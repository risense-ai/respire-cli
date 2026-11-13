//! Real private control exchanges in isolated, account-free installations.
//! No session material, keyring, remote service, model download or OS registration.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::Digest;
use std::path::PathBuf;
use std::process::{Command, Output};

mod support;

struct Fixture {
    _temporary: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    profile: PathBuf,
    port: u16,
    selection: Vec<u8>,
    client: Vec<u8>,
}

impl Fixture {
    fn new() -> Result<Self> {
        let temporary = tempfile::tempdir()?;
        let base = temporary.path().canonicalize()?;
        let root = base.join("installation");
        let profile = root.join("profiles/synthetic");
        std::fs::create_dir_all(&profile)?;
        support::install_runtime_fixture(&root)?;
        let client = serde_json::to_vec(&json!({"data_dir":profile}))?;
        std::fs::write(root.join("client.json"), &client)?;
        std::fs::write(profile.join("keep.txt"), b"synthetic profile marker")?;
        for directory in ["home", "run", "config", "share", "state", "cache"] {
            std::fs::create_dir(base.join(directory))?;
        }
        let selection = std::fs::read(root.join("bin/runtime.json"))?;
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        Ok(Self {
            _temporary: temporary,
            base,
            root,
            profile,
            port,
            selection,
            client,
        })
    }

    fn run(&self, args: &[&str]) -> Result<(Output, Value)> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        command.env_clear();
        // Same execution/coverage whitelist as the existing model-maintenance tests.
        for name in [
            "PATH",
            "LANG",
            "LC_ALL",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "COMSPEC",
            "PATHEXT",
            "LLVM_PROFILE_FILE",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let output = command
            .arg("--json")
            .args(args)
            .current_dir(&self.base)
            .env("HOME", self.base.join("home"))
            .env("USERPROFILE", self.base.join("home"))
            .env("XDG_CONFIG_HOME", self.base.join("config"))
            .env("XDG_DATA_HOME", self.base.join("share"))
            .env("XDG_STATE_HOME", self.base.join("state"))
            .env("XDG_CACHE_HOME", self.base.join("cache"))
            .env("XDG_RUNTIME_DIR", self.base.join("run"))
            .env("APPDATA", self.base.join("config"))
            .env("LOCALAPPDATA", self.base.join("share"))
            .env("RSRS_DATA_DIR", &self.root)
            .env("RSRS_BIN_DIR", self.base.join("bin"))
            .env("RSRS_M3_DIR", self.root.join("models/bge-m3"))
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_LANG", "en")
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9")
            .output()?;
        let value = serde_json::from_slice(&output.stdout).with_context(|| {
            format!(
                "{args:?}: status={}, stdout={}, stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
        Ok((output, value))
    }

    fn marker(&self) -> PathBuf {
        self.root.join("runtime/autostart/maintenance.json")
    }

    fn assert_unchanged(&self) -> Result<()> {
        assert_eq!(
            std::fs::read(self.root.join("bin/runtime.json"))?,
            self.selection
        );
        assert_eq!(std::fs::read(self.root.join("client.json"))?, self.client);
        assert_eq!(
            std::fs::read(self.profile.join("keep.txt"))?,
            b"synthetic profile marker"
        );
        assert!(!self.profile.join("session.json").exists());
        assert!(!self.root.join("runtime/endpoint.json").exists());
        assert!(!self
            .root
            .join("runtime/autostart/registration.json")
            .exists());
        Ok(())
    }

    fn paused(&self) -> Result<Vec<u8>> {
        let bytes = std::fs::read(self.marker())?;
        let marker: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(marker["phase"], "Paused");
        assert_eq!(marker["expected_profile"], json!(self.profile));
        self.assert_unchanged()?;
        Ok(bytes)
    }
}

#[test]
fn absent_secret_uses_real_private_read_and_finishes_maintenance() -> Result<()> {
    let fixture = Fixture::new()?;
    for _ in 0..2 {
        let (output, result) = fixture.run(&["secret"])?;
        anyhow::ensure!(output.status.success(), "secret read failed: {result}");
        assert_eq!(result["command"], "secret");
        assert_eq!(result["status"], "skip");
        assert_eq!(result["summary"], json!({"session":false}));
        assert_eq!(result["errors"], json!([]));
        assert!(result["details"].is_null());
        assert!(!fixture.marker().exists());
        fixture.assert_unchanged()?;
    }
    Ok(())
}

#[test]
fn absent_session_reads_reject_without_credentials_and_retain_fencing() -> Result<()> {
    for args in [vec!["session", "list"], vec!["keys-export"]] {
        let fixture = Fixture::new()?;
        // Prove the same installed Runtime and private exchange work before the negative.
        let (baseline, baseline_result) = fixture.run(&["secret"])?;
        anyhow::ensure!(
            baseline.status.success(),
            "baseline failed: {baseline_result}"
        );
        assert_eq!(baseline_result["summary"], json!({"session":false}));
        let (output, result) = fixture.run(&args)?;
        assert_eq!(output.status.code(), Some(1), "{result}");
        assert_eq!(result["status"], "fail");
        assert_eq!(result["summary"]["reason"], "runtime_error");
        let error = result["errors"][0]
            .as_str()
            .context("read rejection missing")?;
        assert!(
            error.contains("private Runtime secret read was rejected"),
            "{result}"
        );
        assert!(error.contains("maintenance remains Paused"), "{result}");
        let paused = fixture.paused()?;
        // The global fence also blocks a normal read. Do not retry the failed mutation.
        let (status, status_result) = fixture.run(&["metadata", "status"])?;
        assert_eq!(status.status.code(), Some(1), "{status_result}");
        assert_eq!(status_result["status"], "fail");
        assert_eq!(status_result["summary"]["reason"], "runtime_error");
        assert_eq!(status_result["errors"], json!(["runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library"]));
        assert_eq!(std::fs::read(fixture.marker())?, paused);
        fixture.assert_unchanged()?;
    }
    Ok(())
}

#[test]
fn metadata_enable_without_local_keys_preserves_the_original_failed_operation() -> Result<()> {
    let fixture = Fixture::new()?;
    let (before, before_result) = fixture.run(&["--direct", "metadata", "status"])?;
    anyhow::ensure!(
        before.status.success(),
        "initial metadata status failed: {before_result}"
    );
    assert_eq!(before_result["summary"]["enabled"], false);
    assert_eq!(before_result["summary"]["sdk_supported"], true);
    let (output, result) = fixture.run(&["metadata", "enable", "--mode", "isolated"])?;
    assert_eq!(output.status.code(), Some(1), "{result}");
    assert_eq!(result["status"], "fail");
    let path = fixture
        .root
        .join("runtime/autostart/metadata")
        .join(format!(
            "{}.json",
            hex::encode(sha2::Sha256::digest(
                fixture.profile.display().to_string().as_bytes()
            ))
        ));
    let original_bytes = std::fs::read(&path)?;
    let original: Value = serde_json::from_slice(&original_bytes)?;
    let operation = &original["operation"];
    let id = operation["operation_id"]
        .as_str()
        .context("metadata operation missing")?;
    assert_eq!(uuid::Uuid::parse_str(id)?.get_version_num(), 4);
    assert_eq!(operation["key"], id);
    assert_eq!(operation["profile"], json!(fixture.profile));
    assert_eq!(operation["installation_root"], json!(fixture.root));
    assert_eq!(
        operation["intent"],
        json!({"kind":"enable","mode":"isolated","deployment_review":null})
    );
    assert_eq!(original["sent"], true);
    assert_eq!(original["finished"], false);
    let error = result["errors"][0]
        .as_str()
        .context("metadata rejection missing")?;
    assert!(
        error.contains(&format!("metadata_outcome_unknown operation_id={id}")),
        "{result}"
    );
    let paused = fixture.paused()?;
    let (after, after_result) = fixture.run(&["metadata", "status"])?;
    assert_eq!(after.status.code(), Some(1), "{after_result}");
    assert_eq!(after_result["status"], "fail");
    assert_eq!(after_result["summary"]["reason"], "runtime_error");
    assert_eq!(after_result["errors"], json!(["runtime maintenance is incomplete; use the host runtime restart or the indicated snapshot/login recovery before accessing the library"]));
    assert_eq!(std::fs::read(&path)?, original_bytes);
    assert_eq!(std::fs::read(fixture.marker())?, paused);
    fixture.assert_unchanged()?;
    Ok(())
}
