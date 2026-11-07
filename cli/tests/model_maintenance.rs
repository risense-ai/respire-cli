//! Real private Runtime exchanges with an owned, account-free managed installation.
//! No model download, inference, keyring, live owner or OS service registration.
use anyhow::{Context, Result};
use respire_protocol::model_maintenance::{
    ModelMaintenanceKind, ModelMaintenancePhase, ModelMaintenanceReceipt,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command, Output};

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
            .args(["--json", "model", action])
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
                "model {action}: status={}, stdout={}, stderr={}",
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
