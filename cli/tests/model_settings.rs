//! Settings persistence through real CLI processes, using only a fresh profile.
use anyhow::{Context, Result};
use serde_json::Value;
use respire_commands::net_rpc::{self, Health};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::Duration;
use std::process::{Command, Output};

mod support;

#[test]
fn model_weights_persist_read_back_and_drive_the_next_load() -> Result<()> {
    let runtime = std::path::PathBuf::from(
        std::env::var_os("RSRS_RUNTIME_BIN")
            .context("supply RSRS_RUNTIME_BIN with the official standalone Runtime fixture")?,
    )
    .canonicalize()?;
    anyhow::ensure!(runtime.is_file(), "standalone Runtime fixture missing");
    anyhow::ensure!(
        runtime != std::path::Path::new(env!("CARGO_BIN_EXE_rsrs")).canonicalize()?,
        "CLI shim cannot substitute for the standalone Runtime fixture"
    );
    let profile = tempfile::tempdir()?;
    let profile_path = profile.path().to_path_buf();
    let root = profile_path.as_path().join("data");
    let bin_directory = profile_path.as_path().join("bin");
    support::install_host_fixture(&root, &bin_directory)?;
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
        .local_addr()?
        .port();
    let run = |args: &[&str]| -> Result<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| {
                ["RSRS_", "RESPIRE_", "ONEMEMORY_"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
            }) {
                command.env_remove(name);
            }
        }
        command
            .args(["--json", "--direct"])
            .args(args)
            .current_dir(profile_path.as_path())
            .env("HOME", profile_path.as_path())
            .env("USERPROFILE", profile_path.as_path())
            .env("XDG_CONFIG_HOME", profile_path.as_path().join("config"))
            .env("XDG_DATA_HOME", profile_path.as_path().join("share"))
            .env("RSRS_DATA_DIR", &root)
            .env("RSRS_BIN_DIR", &bin_directory)
            .env("RSRS_M3_DIR", profile_path.as_path().join("models"))
            .env("RSRS_RPC_PORT", port.to_string())
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_LANG", "en")
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        let output = command.output()?;
        // Keep the actual JSON even when status checks or parsing fail below.
        eprintln!(
            "model settings {args:?}: status={}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    };
    let mut cleanup = RuntimeCleanup { run: &run, profile, port, cleaned: false };
    // Pin the public names independently of the implementation and its response.
    const MODEL_VARIANTS: [&str; 6] = ["quantized", "fp16", "int8", "uint8", "q4", "q4f16"];
    for variant in MODEL_VARIANTS {
        let saved = run(&["model", "engine", "cpu", "--model", variant])?;
        anyhow::ensure!(
            saved.status.success(),
            "{}",
            String::from_utf8_lossy(&saved.stderr)
        );
        // A new process must use the saved variant, including after an engine-only change.
        anyhow::ensure!(run(&["model", "engine", "cpu"])?.status.success());
        let read = run(&["model", "engine"])?;
        anyhow::ensure!(
            read.status.success(),
            "{}",
            String::from_utf8_lossy(&read.stderr)
        );
        let value: Value = serde_json::from_slice(&read.stdout)?;
        assert_eq!(value["summary"]["model"], variant);
        assert_eq!(
            value["summary"]["variants"]
                .as_array()
                .context("inventory missing")?
                .len(),
            MODEL_VARIANTS.len()
        );
    }
    let settings = profile_path.as_path().join("data/inference.json");
    let before = std::fs::read(&settings)?;
    assert!(!run(&["model", "engine", "cpu", "--model", "invalid"])?
        .status
        .success());
    assert_eq!(std::fs::read(&settings)?, before);
    std::fs::write(&settings, br#"{"engine":"cpu","model":"obsolete"}"#)?;
    anyhow::ensure!(run(&["model", "engine", "cpu", "--model", "q4f16"])?
        .status
        .success());
    assert_eq!(std::fs::read(&settings)?, before);
    assert!(
        !profile_path.as_path().join("models").exists(),
        "settings must not download models"
    );
    // Validated loading never saves an unavailable draft or fetches dependencies.
    let failed_load = run(&["model", "load", "cpu", "--model", "fp16"])?;
    assert!(!failed_load.status.success());
    assert_eq!(std::fs::read(&settings)?, before);
    assert!(!profile_path.as_path().join("models").exists());
    assert!(!run(&[
        "model",
        "install",
        "--model",
        "invalid",
        "--for-engine",
        "cpu"
    ])?
    .status
    .success());
    assert!(
        !profile_path.as_path().join("models").exists(),
        "invalid download request must fail before fetching baseline"
    );

    // Tiny baseline fixtures permit directory resolution, but no valid weights
    // are present and no model bytes can be executed.
    let models = profile_path.as_path().join("models");
    std::fs::create_dir_all(models.join("onnx"))?;
    std::fs::write(models.join("tokenizer.json"), b"{}")?;
    std::fs::write(
        models.join("onnx/model_quantized.onnx"),
        b"invalid synthetic weights",
    )?;
    // Missing weights must fail without silently loading the quantized default.
    let probe = run(&["model", "probe", "--model", "m3"])?;
    assert!(!probe.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&probe.stdout),
        String::from_utf8_lossy(&probe.stderr)
    );
    assert!(diagnostic.contains("q4f16"), "{diagnostic}");
    assert_eq!(std::fs::read(settings)?, before);
    assert!(!models.join("onnx/model_q4f16.onnx").exists());
    cleanup.stop()?;
    Ok(())
}

// Stop only a verified owner. Preserve this installation when cleanup is uncertain.
struct RuntimeCleanup<'a> {
    run: &'a dyn Fn(&[&str]) -> Result<Output>,
    profile: tempfile::TempDir,
    port: u16,
    cleaned: bool,
}

impl RuntimeCleanup<'_> {
    fn health(&self) -> Result<Health> {
        let root = self.profile.path().join("data").canonicalize()?;
        let health: Health = ureq::get(&format!(
            "http://127.0.0.1:{}/api/health",
            self.port
        ))
        .set("X-Respire-Health", "runtime-v1")
        .timeout(Duration::from_secs(3))
        .call()?
        .into_json()?;
        let pin: Value = serde_json::from_str(include_str!("../../runtime-pin.json"))?;
        let version = pin["required"].as_str().context("Runtime pin missing")?;
        let binary = root
            .join("runtime")
            .join(version)
            .join(if cfg!(windows) {
                "rsrs-runtime.exe"
            } else {
                "rsrs-runtime"
            })
            .canonicalize()?;
        anyhow::ensure!(
            health.server == "respire"
                && health.v == 1
                && health.bin == version
                && health.runtime_version == version,
            "unexpected Runtime protocol/version"
        );
        anyhow::ensure!(
            PathBuf::from(&health.installation_root).canonicalize()? == root
                && PathBuf::from(&health.data_dir).canonicalize()? == root,
            "Runtime roots do not match the owned fixture"
        );
        anyhow::ensure!(
            PathBuf::from(&health.exe).canonicalize()? == binary
                && PathBuf::from(&health.image_path).canonicalize()? == binary
                && health.image_sha256 == format!("{:x}", Sha256::digest(std::fs::read(&binary)?)),
            "Runtime image does not match the official installed fixture"
        );
        anyhow::ensure!(
            health.installation_id
                == format!(
                    "{:x}",
                    Sha256::digest(root.display().to_string().as_bytes())
                )
                && health.account_id
                    == format!(
                        "{:x}",
                        Sha256::digest(root.display().to_string().as_bytes())
                    )
                && health.managed_id.is_none()
                && health.pid > 0
                && health.generation > 0
                && !health.instance_id.is_empty(),
            "Runtime scope does not match the anonymous owner"
        );
        let process = net_rpc::runtime_process_identity(health.pid)?;
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        anyhow::ensure!(
            PathBuf::from(&process.executable).canonicalize()? == binary
                && health.process_start_id == format!("{prefix}{}", process.started_at),
            "Runtime OS process identity differs from health"
        );
        Ok(health)
    }

    fn stop(&mut self) -> Result<()> {
        let health = self.health()?;
        let output = (self.run)(&["runtime", "stop"])?;
        anyhow::ensure!(output.status.success(), "owned Runtime stop failed");
        let receipt: Value = serde_json::from_slice(&std::fs::read(
            self.profile.path().join("data/runtime")
                .join(format!("stop-{}.json", health.instance_id)),
        )?)?;
        net_rpc::validate_final_stop_receipt(&health, None, &receipt)?;
        net_rpc::wait_until_exited(health.pid)?;
        anyhow::ensure!(!net_rpc::port_is_open_on(self.port), "Runtime port remains open after stop");
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for RuntimeCleanup<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            if let Err(error) = self.stop() {
                self.profile.disable_cleanup(true);
                eprintln!("model settings Runtime cleanup unconfirmed; preserved {}: {error:#}",
                    self.profile.path().display());
            }
        }
    }
}
