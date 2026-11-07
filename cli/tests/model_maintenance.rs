//! Real private Runtime exchanges with an owned, account-free managed installation.
//! No model download, inference request, keyring or OS service registration.
use anyhow::{Context, Result};
use respire_commands::net_rpc::{self, Health};
use respire_protocol::model_maintenance::{
    ModelMaintenanceKind, ModelMaintenancePhase, ModelMaintenanceReceipt,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::Duration;

mod support;

struct Fixture {
    _temporary: tempfile::TempDir,
    base: PathBuf,
    root: PathBuf,
    profile: PathBuf,
    model: PathBuf,
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
        std::fs::write(
            root.join("inference.json"),
            br#"{"engine":"gpu","model":"q4","force_cpu":false}"#,
        )?;
        for directory in ["home", "run", "config", "share", "state", "cache"] {
            std::fs::create_dir(base.join(directory))?;
        }
        let selection = std::fs::read(root.join("runtime.json"))?;
        let model = root.join("models/bge-m3");
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        Ok(Self {
            _temporary: temporary,
            base,
            root,
            profile,
            model,
            port,
            selection,
            client,
        })
    }

    fn run(&self, action: &str) -> Result<(Output, Value)> {
        self.command(&["model", action])
    }

    fn command(&self, args: &[&str]) -> Result<(Output, Value)> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        command.env_clear();
        // Preserve execution/coverage plumbing, never account or desktop-session state.
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
            .env("RSRS_M3_DIR", &self.model)
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

    fn receipt(
        &self,
        action: &str,
        kind: ModelMaintenanceKind,
        phase: ModelMaintenancePhase,
    ) -> Result<(Value, ModelMaintenanceReceipt)> {
        let (output, value) = self.run(action)?;
        anyhow::ensure!(
            output.status.success(),
            "model {action} failed: {value}; {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(value["command"], "model");
        assert_eq!(value["errors"], json!([]));
        let receipt: ModelMaintenanceReceipt = serde_json::from_value(value["details"].clone())?;
        assert_eq!(receipt.plan.kind, kind);
        assert_eq!(receipt.phase, phase);
        assert!(receipt.verified);
        assert!(!receipt.npu_ready);
        assert!(receipt.warning.is_none());
        for digest in [
            &receipt.plan.review.selection_sha256,
            &receipt.plan.review.revision_sha256,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
        assert!(
            !self.marker().exists(),
            "completed maintenance must retire its fence"
        );
        self.assert_profile_untouched()?;
        Ok((value, receipt))
    }

    fn marker(&self) -> PathBuf {
        self.root.join("runtime/autostart/maintenance.json")
    }

    fn assert_profile_untouched(&self) -> Result<()> {
        assert_eq!(
            std::fs::read(self.root.join("runtime.json"))?,
            self.selection
        );
        assert_eq!(std::fs::read(self.root.join("client.json"))?, self.client);
        assert_eq!(
            std::fs::read(self.profile.join("keep.txt"))?,
            b"synthetic profile marker"
        );
        for entry in std::fs::read_dir(&self.profile)? {
            let name = entry?.file_name();
            assert!(
                ["keep.txt", "lock.db", "lock.db-shm", "lock.db-wal"]
                    .iter()
                    .any(|allowed| name == *allowed),
                "maintenance created unexpected profile content: {name:?}"
            );
        }
        assert!(!self.root.join("runtime/endpoint.json").exists());
        Ok(())
    }
}

#[test]
fn uninstall_reviews_removes_and_verifies_only_the_owned_model_tree() -> Result<()> {
    let fixture = Fixture::new()?;
    std::fs::create_dir_all(fixture.model.join("onnx/nested"))?;
    std::fs::write(
        fixture.model.join("onnx/nested/model.onnx"),
        b"synthetic non-model bytes",
    )?;
    let sibling = fixture.root.join("models/keep.txt");
    std::fs::write(&sibling, b"unrelated synthetic model")?;
    let before = std::fs::read(fixture.root.join("inference.json"))?;
    for (action, status, removed) in [("uninstall", "ok", true), ("uninstall-m3", "skip", false)] {
        let (value, receipt) = fixture.receipt(
            action,
            ModelMaintenanceKind::UninstallM3,
            ModelMaintenancePhase::Verify,
        )?;
        assert_eq!(value["status"], status);
        assert_eq!(value["summary"]["removed"], removed);
        assert_eq!(value["summary"]["dir"], json!(fixture.model));
        assert_eq!(
            receipt.plan.uninstall_directory.as_ref(),
            Some(&fixture.model)
        );
        assert!(!receipt.config_applied);
        assert!(!fixture.model.exists());
        assert_eq!(std::fs::read(&sibling)?, b"unrelated synthetic model");
        assert_eq!(std::fs::read(fixture.root.join("inference.json"))?, before);
    }
    Ok(())
}

#[test]
fn cpu_reset_applies_the_reviewed_bytes_without_a_model_or_serving_owner() -> Result<()> {
    let fixture = Fixture::new()?;
    for _ in 0..2 {
        let (value, receipt) = fixture.receipt(
            "reset-cpu",
            ModelMaintenanceKind::ResetCpu,
            ModelMaintenancePhase::Apply,
        )?;
        assert_eq!(value["status"], "ok");
        assert_eq!(
            value["summary"],
            json!({"engine":"cpu", "force_cpu":true,
            "runtime_restarted":false, "stopped_pid":null})
        );
        assert!(receipt.config_applied);
        let bytes = std::fs::read(fixture.root.join("inference.json"))?;
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes)?,
            json!({"engine":"cpu","model":"q4","force_cpu":true})
        );
        assert_eq!(
            receipt.plan.cpu_candidate_sha256.as_deref(),
            Some(format!("{:x}", Sha256::digest(&bytes)).as_str())
        );
        assert!(
            !fixture.model.exists(),
            "CPU reset must not download models"
        );
    }
    Ok(())
}

#[cfg(not(windows))]
#[test]
fn provider_maintenance_verifies_an_empty_non_windows_catalog_without_downloads() -> Result<()> {
    let fixture = Fixture::new()?;
    let before = std::fs::read(fixture.root.join("inference.json"))?;
    let (value, receipt) = fixture.receipt(
        "install-engines",
        ModelMaintenanceKind::InstallEngines,
        ModelMaintenancePhase::Verify,
    )?;
    assert_eq!(value["status"], "ok");
    assert_eq!(value["summary"], json!({"providers":[],"npu_ready":false}));
    assert!(receipt.plan.catalog.is_none());
    assert!(!receipt.config_applied);
    assert_eq!(std::fs::read(fixture.root.join("inference.json"))?, before);
    assert!(!fixture.model.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn refused_link_deletion_preserves_data_and_fences_later_mutation() -> Result<()> {
    let fixture = Fixture::new()?;
    std::fs::create_dir_all(&fixture.model)?;
    let outside = fixture.base.join("outside.txt");
    std::fs::write(&outside, b"outside synthetic marker")?;
    let linked = fixture.model.join("linked.onnx");
    std::os::unix::fs::symlink(&outside, &linked)?;
    let before = std::fs::read(fixture.root.join("inference.json"))?;
    let (output, value) = fixture.run("uninstall")?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["status"], "fail");
    assert_eq!(
        value["errors"],
        json!(["model maintenance cannot follow symlinks"])
    );
    assert!(std::fs::symlink_metadata(&linked)?.file_type().is_symlink());
    assert_eq!(std::fs::read(&outside)?, b"outside synthetic marker");
    assert_eq!(std::fs::read(fixture.root.join("inference.json"))?, before);
    let marker = std::fs::read(fixture.marker())?;
    let paused: Value = serde_json::from_slice(&marker)?;
    assert_eq!(paused["phase"], "Paused");
    assert_eq!(paused["expected_profile"], json!(fixture.profile));
    fixture.assert_profile_untouched()?;

    // Fixing the owned fixture's link cannot silently clear incomplete maintenance.
    std::fs::remove_file(&linked)?;
    let (output, value) = fixture.run("reset-cpu")?;
    assert_eq!(output.status.code(), Some(1));
    assert!(value["errors"][0]
        .as_str()
        .context("fence error")?
        .contains("runtime maintenance is incomplete"));
    assert_eq!(std::fs::read(fixture.marker())?, marker);
    assert_eq!(std::fs::read(fixture.root.join("inference.json"))?, before);
    assert_eq!(std::fs::read(&outside)?, b"outside synthetic marker");
    assert!(fixture.model.is_dir());
    fixture.assert_profile_untouched()?;
    Ok(())
}

// Own only this temporary installation. Failed cleanup preserves its files and
// evidence; it never substitutes a forced kill for a verified Runtime drain.
struct OwnedRuntime {
    fixture: Fixture,
    last_owner: Option<Health>,
    cleanup_required: bool,
}

impl OwnedRuntime {
    fn new() -> Result<Self> {
        Ok(Self {
            fixture: Fixture::new()?,
            last_owner: None,
            cleanup_required: false,
        })
    }

    fn health(&self) -> Result<Health> {
        let health: Health = ureq::get(&format!(
            "http://127.0.0.1:{}/api/health",
            self.fixture.port
        ))
        .timeout(Duration::from_secs(3))
        .call()?
        .into_json()?;
        let pin: Value = serde_json::from_str(include_str!("../../runtime-pin.json"))?;
        let version = pin["required"].as_str().context("Runtime pin missing")?;
        let binary = self
            .fixture
            .root
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
            PathBuf::from(&health.installation_root).canonicalize()? == self.fixture.root
                && PathBuf::from(&health.data_dir).canonicalize()? == self.fixture.profile,
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
                    Sha256::digest(self.fixture.root.display().to_string().as_bytes())
                )
                && health.account_id
                    == format!(
                        "{:x}",
                        Sha256::digest(self.fixture.profile.display().to_string().as_bytes())
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

    fn start(&mut self) -> Result<Health> {
        self.cleanup_required = true;
        let (output, result) = self.fixture.command(&["runtime", "start"])?;
        anyhow::ensure!(output.status.success(), "Runtime start failed: {result}");
        assert_eq!(result["command"], "runtime.start");
        assert_eq!(result["summary"]["registered"], false);
        let health = self.health()?;
        self.last_owner = Some(health.clone());
        Ok(health)
    }

    fn verify_drained(&self, health: &Health) -> Result<()> {
        let receipt: Value = serde_json::from_slice(&std::fs::read(
            self.fixture
                .root
                .join("runtime")
                .join(format!("stop-{}.json", health.instance_id)),
        )?)?;
        net_rpc::validate_final_stop_receipt(health, None, &receipt)?;
        // Permission or identity-query failures cannot stand in for OS exit.
        // Reused PIDs conservatively fail rather than bypassing this check.
        net_rpc::wait_until_exited(health.pid)?;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        let health = if net_rpc::port_is_open_on(self.fixture.port) {
            self.health()?
        } else {
            self.last_owner
                .clone()
                .context("no verified owner for cleanup")?
        };
        let (output, result) = self.fixture.command(&["runtime", "stop"])?;
        anyhow::ensure!(output.status.success(), "Runtime stop failed: {result}");
        self.verify_drained(&health)?;
        anyhow::ensure!(
            !net_rpc::port_is_open_on(self.fixture.port),
            "Runtime port remains open after stop"
        );
        self.cleanup_required = false;
        Ok(())
    }
}

impl Drop for OwnedRuntime {
    fn drop(&mut self) {
        if self.cleanup_required {
            if let Err(error) = self.stop() {
                self.fixture._temporary.disable_cleanup(true);
                eprintln!(
                    "owned Runtime cleanup unconfirmed; preserved {}: {error:#}",
                    self.fixture.base.display()
                );
            }
        }
    }
}

#[test]
fn anonymous_owner_cpu_reset_drains_and_restores_verified_runtime() -> Result<()> {
    let mut runtime = OwnedRuntime::new()?;
    let original = runtime.start()?;
    let (output, result) = runtime.fixture.run("reset-cpu")?;
    anyhow::ensure!(output.status.success(), "owned CPU reset failed: {result}");
    assert_eq!(result["command"], "model");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errors"], json!([]));
    // Manual reset intentionally stops, rather than automatically resurrecting,
    // an unregistered owner. Restore explicitly using the public lifecycle API.
    assert_eq!(
        result["summary"],
        json!({"engine":"cpu", "force_cpu":true,
        "runtime_restarted":false, "stopped_pid":original.pid})
    );
    let receipt: ModelMaintenanceReceipt = serde_json::from_value(result["details"].clone())?;
    assert_eq!(receipt.plan.kind, ModelMaintenanceKind::ResetCpu);
    assert_eq!(receipt.phase, ModelMaintenancePhase::Apply);
    assert!(receipt.config_applied && receipt.verified && receipt.warning.is_none());
    let bytes = std::fs::read(runtime.fixture.root.join("inference.json"))?;
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes)?,
        json!({"engine":"cpu","model":"q4","force_cpu":true})
    );
    assert_eq!(
        receipt.plan.cpu_candidate_sha256.as_deref(),
        Some(format!("{:x}", Sha256::digest(&bytes)).as_str())
    );
    assert!(!runtime.fixture.marker().exists());
    assert!(!runtime.fixture.model.exists());
    runtime.verify_drained(&original)?;
    assert!(!net_rpc::port_is_open_on(runtime.fixture.port));
    runtime.cleanup_required = false;

    let restored = runtime.start()?;
    assert_ne!(restored.instance_id, original.instance_id);
    assert_ne!(
        (restored.pid, &restored.process_start_id),
        (original.pid, &original.process_start_id)
    );
    assert_eq!(restored.account_id, original.account_id);
    assert_eq!(restored.installation_id, original.installation_id);
    assert_eq!(restored.image_sha256, original.image_sha256);
    assert!(!original.store_ready || restored.store_ready);
    assert_eq!(
        std::fs::read(runtime.fixture.root.join("inference.json"))?,
        bytes
    );
    assert_eq!(
        std::fs::read(runtime.fixture.root.join("runtime.json"))?,
        runtime.fixture.selection
    );
    assert_eq!(
        std::fs::read(runtime.fixture.root.join("client.json"))?,
        runtime.fixture.client
    );
    assert_eq!(
        std::fs::read(runtime.fixture.profile.join("keep.txt"))?,
        b"synthetic profile marker"
    );
    assert!(!runtime.fixture.profile.join("session.json").exists());
    assert!(!runtime
        .fixture
        .root
        .join("runtime/autostart/registration.json")
        .exists());
    // Uninstall does automatically restore a previously serving manual owner.
    // The owned files are deliberately not loadable models; no backend is claimed.
    std::fs::create_dir_all(&runtime.fixture.model)?;
    std::fs::write(
        runtime.fixture.model.join("owned-marker"),
        b"synthetic removable bytes",
    )?;
    let sibling = runtime.fixture.root.join("models/keep.txt");
    std::fs::write(&sibling, b"unrelated model marker")?;
    let (output, result) = runtime.fixture.run("uninstall-m3")?;
    anyhow::ensure!(
        output.status.success(),
        "owned model uninstall failed: {result}"
    );
    assert_eq!(result["status"], "ok");
    assert_eq!(result["errors"], json!([]));
    assert_eq!(
        result["summary"],
        json!({"dir":runtime.fixture.model,"removed":true,"model":"bge-m3"})
    );
    let receipt: ModelMaintenanceReceipt = serde_json::from_value(result["details"].clone())?;
    assert_eq!(receipt.plan.kind, ModelMaintenanceKind::UninstallM3);
    assert_eq!(receipt.phase, ModelMaintenancePhase::Verify);
    assert!(receipt.verified && !receipt.config_applied && receipt.warning.is_none());
    assert!(!runtime.fixture.model.exists());
    assert_eq!(std::fs::read(&sibling)?, b"unrelated model marker");
    assert_eq!(
        std::fs::read(runtime.fixture.root.join("inference.json"))?,
        bytes
    );
    assert!(!runtime.fixture.marker().exists());
    runtime.verify_drained(&restored)?;
    let automatic = runtime.health()?;
    assert_ne!(automatic.instance_id, restored.instance_id);
    assert_ne!(
        (automatic.pid, &automatic.process_start_id),
        (restored.pid, &restored.process_start_id)
    );
    assert_eq!(automatic.account_id, restored.account_id);
    assert_eq!(automatic.installation_id, restored.installation_id);
    assert_eq!(automatic.image_sha256, restored.image_sha256);
    assert!(!restored.store_ready || automatic.store_ready);
    runtime.last_owner = Some(automatic);
    runtime.stop()?;
    assert!(!runtime.fixture.marker().exists());
    assert!(!runtime.fixture.profile.join("session.json").exists());
    assert!(!runtime
        .fixture
        .root
        .join("runtime/autostart/registration.json")
        .exists());
    Ok(())
}
