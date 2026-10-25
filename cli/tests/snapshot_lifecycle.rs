//! Public snapshot commands with an isolated synthetic vault, not user data.
use anyhow::{Context, Result};
use respire::memory::{crypto, search::HashingEmbedder};
use respire::transport::local::LocalStore;
use respire::{MemoryEngine, MemoryEntry, MemoryTransport, SessionKeys};
use serde_json::{json, Value};
use std::{
    io::{Read, Seek, SeekFrom},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    root: tempfile::TempDir,
    port: u16,
    secret: String,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))?
            .local_addr()?
            .port();
        let secret = format!("A3-{}", "07".repeat(18));
        let salt = "08".repeat(16);
        let kek = crypto::derive_rsrs_kek(&secret, &salt)?;
        let (nonce, wrapped) = crypto::wrap_key(&[9; 32], &kek)?;
        std::fs::write(
            root.path().join("session.json"),
            serde_json::to_vec(
                &json!({"user":"snapshot-fixture","vault_version":4,"kdf_salt":salt,"wrapped_urk":format!("{}{wrapped}",crypto::RSRS_PREFIX),"urk_nonce":nonce}),
            )?,
        )?;
        let fixture = Self { root, port, secret };
        let entry = MemoryEntry {
            id: "12345678-1234-4234-8234-123456789abc".into(),
            user: "snapshot-fixture".into(),
            title: "synthetic snapshot".into(),
            content: "synthetic body".into(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            kind: respire::Kind::Context,
            tags: Vec::new(),
            computer: "fixture".into(),
            project: "fixture".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            emotion: 0.0,
            parent_id: String::new(),
            importance: "normal".into(),
            device: "fixture".into(),
            modified_by: "fixture".into(),
        };
        let _defer = respire::core_sdk::defer_indexing();
        let stored = MemoryEngine::seal(
            &SessionKeys::from_urk([9; 32])?,
            &HashingEmbedder::default(),
            &entry,
            "snapshot-fixture",
        )?;
        assert!(LocalStore::open(&fixture.root.path().join("rsrs.db"))?.put(&stored)?);
        Ok(fixture)
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rsrs"));
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|n| {
                n.starts_with("RSRS_") || n.starts_with("ONEMEMORY_") || n.starts_with("RESPIRE_")
            }) {
                command.env_remove(name);
            }
        }
        command
            .args(args)
            .current_dir(self.root.path())
            .env("HOME", self.root.path())
            .env("USERPROFILE", self.root.path())
            .env("RSRS_DATA_DIR", self.root.path())
            .env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_SUPER", &self.secret)
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_LANG", "en")
            .env("RSRS_MIRROR", "http://127.0.0.1:9")
            .env("RSRS_CPU_ORT_MIRROR", "http://127.0.0.1:9");
        command
    }
    fn run(&self, args: &[&str]) -> Result<(bool, Value)> {
        let mut stdout = tempfile::tempfile()?;
        let mut stderr = tempfile::tempfile()?;
        let mut child = self
            .command(args)
            .stdin(Stdio::null())
            .stdout(stdout.try_clone()?)
            .stderr(stderr.try_clone()?)
            .spawn()?;
        let began = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if began.elapsed() > Duration::from_secs(90) {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("snapshot fixture command timed out");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stdout.seek(SeekFrom::Start(0))?;
        stderr.seek(SeekFrom::Start(0))?;
        let mut text = String::new();
        stdout.read_to_string(&mut text)?;
        let value = serde_json::from_str(&text)
            .context("snapshot command did not emit a single JSON envelope")?;
        Ok((status.success(), value))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // The unique port and profile are ours. Check the profile before lifecycle cleanup.
        if let Ok((true, status)) = self.run(&["--json", "--runtime-internal", "--status"]) {
            if status["summary"]["data_dir"]
                .as_str()
                .is_some_and(|root| std::path::Path::new(root) == self.root.path())
            {
                let _ = self.run(&["--json", "--runtime-internal", "--stop"]);
            }
        }
    }
}

#[test]
fn public_snapshot_restore_reopens_runtime_and_keeps_sync_quarantined() -> Result<()> {
    let fixture = Fixture::new()?;
    let (ok, created) = fixture.run(&[
        "--direct",
        "--json",
        "snapshot",
        "create",
        "--note",
        "synthetic regression",
    ])?;
    anyhow::ensure!(ok, "snapshot create failed: {}", created["errors"]);
    let id = created["details"]["id"].as_str().context("snapshot id")?;
    let (ok, listed) = fixture.run(&["--direct", "--json", "snapshot", "list"])?;
    assert!(ok);
    assert_eq!(listed["details"].as_array().context("list")?.len(), 1);
    let (_, before) = fixture.run(&["--json", "status"])?;
    let (ok, _) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "restore",
        id,
        "--confirm",
    ])?;
    assert!(!ok, "sandbox restored database");
    let (ok, restored) = fixture.run(&["--json", "snapshot", "restore", id, "--confirm"])?;
    anyhow::ensure!(ok, "snapshot restore failed: {}", restored["errors"]);
    assert_eq!(restored["summary"]["sync_quarantined"], true);
    assert_eq!(restored["summary"]["cloud_rollback"], false);
    assert!(restored["details"]["before_restore"]
        .as_str()
        .is_some_and(|v| v != id));
    let (ok, status) = fixture.run(&["--client-only", "--json", "status"])?;
    assert!(ok);
    assert_eq!(
        status["summary"]["local_alive"],
        before["summary"]["local_alive"]
    );
    let (ok, failed) = fixture.run(&["--client-only", "--json", "sync"])?;
    assert!(!ok);
    assert!(failed["errors"].to_string().contains("quarantined"));
    let (ok, _) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "resume-sync",
        "--reviewed-revision",
        "stale",
    ])?;
    assert!(!ok);
    let (ok, revision) = fixture.run(&["--client-only", "--json", "memory-revision"])?;
    assert!(ok);
    let token = revision["summary"]["revision"]
        .as_str()
        .context("revision token")?;
    let (ok, resumed) = fixture.run(&[
        "--client-only",
        "--json",
        "snapshot",
        "resume-sync",
        "--reviewed-revision",
        token,
    ])?;
    anyhow::ensure!(ok, "resume failed: {}", resumed["errors"]);
    assert_eq!(resumed["details"]["sync_quarantined"], false);
    Ok(())
}
