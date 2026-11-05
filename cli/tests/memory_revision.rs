//! Revision probes use synthetic profiles only, without keys or model installation.
use std::path::Path;
use std::process::{Command, Output};

use anyhow::Context;
use respire::transport::local::LocalStore;
use serde_json::Value;

// Reuse the official installation prepared for snapshot_lifecycle/runtime_smoke in CI.
// RSRS_RUNTIME_BIN locates that fixture only; product commands cannot use the override.
fn install_runtime_fixture(root: &Path) -> anyhow::Result<()> {
    let binary = std::path::PathBuf::from(
        std::env::var_os("RSRS_RUNTIME_BIN")
            .context("official managed Runtime fixture required")?,
    )
    .canonicalize()?;
    anyhow::ensure!(
        binary != Path::new(env!("CARGO_BIN_EXE_rsrs")).canonicalize()?,
        "CLI shim cannot substitute for the Runtime fixture"
    );
    let version_dir = binary
        .parent()
        .context("Runtime fixture version directory missing")?;
    let source_root = version_dir
        .parent()
        .and_then(Path::parent)
        .context("Runtime fixture installation root missing")?;
    let receipt = source_root.join("runtime.json");
    let selected: Value = serde_json::from_slice(&std::fs::read(&receipt)?)?;
    let pin: Value = serde_json::from_str(include_str!("../../runtime-pin.json"))?;
    let version = pin["required"]
        .as_str()
        .context("Runtime pin required missing")?;
    anyhow::ensure!(
        selected["version"] == version
            && selected["release"]["metadata_json"].is_string()
            && source_root.join("runtime").join(version) == version_dir,
        "Runtime fixture must be the official pinned managed installation"
    );
    let destination = root.join("runtime").join(version);
    let mut pending = vec![(version_dir.to_path_buf(), destination)];
    while let Some((source, target)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&source)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Runtime fixture contains a link"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "Runtime fixture contains a reparse point"
            );
        }
        if metadata.is_dir() {
            std::fs::create_dir_all(&target)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                pending.push((entry.path(), target.join(entry.file_name())));
            }
        } else {
            anyhow::ensure!(metadata.is_file(), "Runtime fixture contains a non-file");
            std::fs::copy(source, target)?;
        }
    }
    // Copy the installer's receipt verbatim; managed_runtime_path verifies its proof/files.
    anyhow::ensure!(
        std::fs::symlink_metadata(&receipt)?.is_file(),
        "Runtime fixture receipt missing"
    );
    std::fs::copy(receipt, root.join("runtime.json"))?;
    Ok(())
}

fn run(root: &Path, args: &[&str]) -> std::io::Result<Output> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(args)
        .env("HOME", root.join("unused-home"))
        .env("RSRS_DATA_DIR", root)
        .env("RSRS_MODEL_DIR", root.join("missing-model"))
        .env("RSRS_JSON", "1")
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("RSRS_RPC_TOKEN")
        .env_remove("RSRS_RUNTIME_BIN")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()
}

fn summary(output: Output) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(envelope["command"], "memory-revision");
    assert_eq!(envelope["status"], "ok");
    assert!(envelope["details"].is_null());
    let value = envelope["summary"].clone();
    assert_eq!(value["revision"].as_str().unwrap_or("").len(), 32);
    Ok(value)
}

#[test]
fn memory_revision_direct_is_model_free_and_follows_resolved_profile(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    drop(LocalStore::open(&root.join("rsrs.db"))?);
    install_runtime_fixture(root)?;
    let initial = summary(run(root, &["--direct", "memory-revision", "--json"])?)?;
    assert_eq!(initial["profile"], root.to_string_lossy().as_ref());
    // RSRS_JSON=1 is exactly the same wire contract as the explicit flag.
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        initial
    );
    assert_eq!(
        summary(run(root, &["memory-revision", "--json"])?)?,
        initial
    );
    let profile = root.join("accounts").join("work");
    drop(LocalStore::open(&profile.join("rsrs.db"))?);
    std::fs::write(
        root.join("client.json"),
        serde_json::to_vec(&serde_json::json!({
            "data_dir": profile.to_string_lossy()
        }))?,
    )?;
    let other = summary(run(root, &["--direct", "memory-revision"])?)?;
    assert_eq!(other["profile"], profile.to_string_lossy().as_ref());
    assert_ne!(other["revision"], initial["revision"]);
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        other
    );
    std::fs::write(root.join("client.json"), "{}")?;
    assert_eq!(
        summary(run(root, &["--direct", "memory-revision"])?)?,
        initial
    );
    assert!(!root.join("runtime/endpoint.json").exists());
    assert!(!root.join("runtime/autostart").exists());
    assert!(!root.join("lock.db").exists());
    assert!(!root.join("missing-model").exists());
    assert!(!root.join("unused-home").exists());
    Ok(())
}

#[test]
fn memory_revision_does_not_initialize_or_autostart() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("absent-profile");
    let direct = run(&root, &["--direct", "memory-revision"])?;
    assert!(!direct.status.success());
    let envelope: Value = serde_json::from_slice(&direct.stdout)?;
    assert_eq!(envelope["status"], "fail");
    assert!(!root.exists());
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let ordinary = Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(["memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env("RSRS_DATA_DIR", &root)
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    assert!(!ordinary.status.success());
    let envelope: Value = serde_json::from_slice(&ordinary.stdout)?;
    assert_eq!(envelope["status"], "fail");
    assert!(!root.exists());
    assert!(!dir.path().join("unused-home").exists());

    std::fs::create_dir(&root)?;
    drop(LocalStore::open(&root.join("rsrs.db"))?);
    let database = std::fs::read(root.join("rsrs.db"))?;
    let journal = root.join(".login-recovery.json");
    let marker = b"synthetic interrupted login must remain untouched";
    std::fs::write(&journal, marker)?;
    for args in [
        vec!["--direct", "memory-revision", "--json"],
        vec!["memory-revision", "--json"],
    ] {
        let result = run(&root, &args)?;
        assert_eq!(result.status.code(), Some(1));
        let envelope: Value = serde_json::from_slice(&result.stdout)?;
        assert_eq!(envelope["command"], "cli");
        assert_eq!(envelope["status"], "fail");
        assert!(envelope["errors"]
            .to_string()
            .contains("host control requires an installed managed Runtime"));
        assert_eq!(std::fs::read(root.join("rsrs.db"))?, database);
        assert_eq!(std::fs::read(&journal)?, marker);
        assert!(!root.join("runtime").exists());
        assert!(!root.join("lock.db").exists());
        assert!(!root.join("session.json").exists());
    }
    Ok(())
}

#[test]
fn memory_revision_direct_respects_client_only_policy() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let result = run(
        dir.path(),
        &["--client-only", "--direct", "memory-revision"],
    )?;
    assert!(!result.status.success());
    let envelope: Value = serde_json::from_slice(&result.stdout)?;
    assert!(envelope["errors"].to_string().contains("client_only"));
    let remote = run(dir.path(), &["--client-only", "memory-revision", "--json"])?;
    assert!(!remote.status.success());
    let envelope: Value = serde_json::from_slice(&remote.stdout)?;
    let errors = envelope["errors"].to_string();
    assert!(!errors.contains("client_only:"));
    assert!(!errors.contains("host control requires an installed managed Runtime"));
    assert!(!dir.path().join("runtime").exists());
    Ok(())
}

#[test]
fn memory_revision_legacy_database_and_ambiguous_names() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    install_runtime_fixture(dir.path())?;
    let legacy = summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(legacy["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    let result = run(dir.path(), &["--direct", "memory-revision"])?;
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("both rsrs.db"));
    Ok(())
}

#[test]
fn memory_revision_does_not_recover_interrupted_login() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("rsrs.db"))?);
    install_runtime_fixture(dir.path())?;
    let journal = dir.path().join(".login-recovery.json");
    let marker = b"synthetic invalid journal must remain untouched";
    std::fs::write(&journal, marker)?;
    summary(run(dir.path(), &["--direct", "memory-revision"])?)?;
    assert_eq!(std::fs::read(&journal)?, marker);
    assert!(!dir.path().join("session.json").exists());
    assert!(!dir.path().join("runtime/endpoint.json").exists());
    assert!(!dir.path().join("runtime/autostart").exists());
    Ok(())
}

#[test]
fn memory_revision_preserves_legacy_environment_alias() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    drop(LocalStore::open(&dir.path().join("onememory.db"))?);
    install_runtime_fixture(dir.path())?;
    let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
        .args(["--direct", "memory-revision", "--json"])
        .env("HOME", dir.path().join("unused-home"))
        .env_remove("RSRS_DATA_DIR")
        .env_remove("RESPIRE_DATA_DIR")
        .env("ONEMEMORY_DATA_DIR", dir.path())
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("ONEMEMORY_CLIENT_ONLY")
        .env_remove("RESPIRE_CLIENT_ONLY")
        .env_remove("RSRS_RUNTIME_BIN")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .output()?;
    let value = summary(output)?;
    assert_eq!(value["profile"], dir.path().to_string_lossy().as_ref());
    assert!(!dir.path().join("rsrs.db").exists());
    Ok(())
}
