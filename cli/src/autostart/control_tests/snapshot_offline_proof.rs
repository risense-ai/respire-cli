//! Local parser/liveness checks only, not proof that any Runtime was stopped.
use super::*;

#[test]
fn snapshot_endpoint_requires_bounded_plain_metadata_and_never_infers_live_exit() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let path = root.join("runtime/endpoint.json");
    fs::create_dir(root.join("runtime"))?;
    let absent = SnapshotOfflineProof::capture(&root, None)?;
    assert!(absent.endpoint_sha256.is_none() && absent.endpoint_pid.is_none());
    absent.verify(&root)?;
    let mut endpoint = json!({"pid":std::process::id(), "padding":""});
    let overhead = serde_json::to_vec(&endpoint)?.len();
    endpoint["padding"] = json!("x".repeat(16 * 1024 - overhead));
    let bounded = serde_json::to_vec(&endpoint)?;
    assert_eq!(bounded.len(), 16 * 1024);
    fs::write(&path, &bounded)?;
    assert_eq!(
        SnapshotOfflineProof::capture(&root, None)
            .unwrap_err()
            .to_string(),
        "snapshot owner is alive but health is unavailable; drain proof required"
    );
    assert_eq!(fs::read(&path)?, bounded);
    assert!(absent.verify(&root).is_err());
    endpoint["padding"] = json!("x".repeat(16 * 1024 - overhead + 1));
    let oversized = serde_json::to_vec(&endpoint)?;
    assert_eq!(oversized.len(), 16 * 1024 + 1);
    fs::write(&path, &oversized)?;
    assert_eq!(
        SnapshotOfflineProof::capture(&root, None)
            .unwrap_err()
            .to_string(),
        "snapshot endpoint is not a bounded regular file"
    );
    assert_eq!(fs::read(&path)?, oversized);
    fs::write(&path, br#"{"pid":0}"#)?;
    assert_eq!(
        SnapshotOfflineProof::capture(&root, None)
            .unwrap_err()
            .to_string(),
        "snapshot endpoint owner PID missing"
    );
    #[cfg(unix)]
    {
        let target = root.join("owned-endpoint.json");
        fs::write(&target, &bounded)?;
        fs::remove_file(&path)?;
        std::os::unix::fs::symlink(&target, &path)?;
        assert_eq!(
            SnapshotOfflineProof::capture(&root, None)
                .unwrap_err()
                .to_string(),
            "snapshot endpoint is not a bounded regular file"
        );
        assert_eq!(fs::read(&target)?, bounded);
    }
    Ok(())
}

#[test]
fn snapshot_prior_process_identity_cannot_be_replaced_by_missing_health() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().canonicalize()?;
    let pid = std::process::id();
    let birth = manager::process_birth(pid)?.context("current test process birth missing")?;
    let mut prior = SnapshotVerifiedRuntime {
        scope: respire_protocol::RuntimeRequestScope {
            account_id: "synthetic".into(),
            instance_id: "synthetic".into(),
            generation: 1,
        },
        pid,
        process_start_id: format!("{}{birth}", snapshot_birth_prefix()),
        image_path: std::env::current_exe()?,
        image_sha256: "synthetic".into(),
        runtime_version: "synthetic".into(),
    };
    assert_eq!(
        SnapshotOfflineProof::capture(&root, Some(prior.clone()))
            .unwrap_err()
            .to_string(),
        "snapshot previous Runtime is alive without health; no offline recovery"
    );
    prior.process_start_id.clear();
    assert_eq!(
        SnapshotOfflineProof::capture(&root, Some(prior))
            .unwrap_err()
            .to_string(),
        "snapshot previous Runtime identity incomplete"
    );
    assert!(!root.join("runtime").exists());
    Ok(())
}
