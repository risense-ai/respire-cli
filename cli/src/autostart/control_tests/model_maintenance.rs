//! File-only model maintenance tests in fresh owned directories. No product is launched.
use super::*;
use std::ffi::OsString;

struct Restore(Vec<(&'static str, Option<OsString>)>);
impl Drop for Restore {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn isolate(root: &Path) -> Restore {
    let names = [
        "HOME",
        "USERPROFILE",
        "RSRS_DATA_DIR",
        "ONEMEMORY_DATA_DIR",
        "RESPIRE_DATA_DIR",
        "RSRS_M3_DIR",
        "ONEMEMORY_M3_DIR",
        "RESPIRE_M3_DIR",
    ];
    let restore = Restore(
        names
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
    );
    for name in names {
        std::env::remove_var(name);
    }
    std::env::set_var("HOME", root);
    std::env::set_var("USERPROFILE", root);
    std::env::set_var("RSRS_DATA_DIR", root.join("installation"));
    restore
}

#[test]
fn model_paths_require_explicit_unambiguous_local_destinations() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    check_path(&root.join("new-model/onnx/model.onnx"))?;
    assert!(check_path(Path::new("relative-model")).is_err());
    for bad in [
        "model.",
        "model ",
        "model:alias",
        "model\\alias",
        "models/../outside",
    ] {
        assert!(
            check_path(&root.join(bad)).is_err(),
            "accepted ambiguous destination {bad}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let invalid = root.join(OsString::from_vec(vec![0xff]));
        assert!(check_path(&invalid).is_err());
        let target = root.join("real-model");
        fs::create_dir(&target)?;
        let linked = root.join("linked-model");
        std::os::unix::fs::symlink(&target, &linked)?;
        assert!(check_path(&linked).is_err());
        assert!(check_path(&linked.join("missing-child")).is_err());
    }
    Ok(())
}

#[test]
fn model_directory_selection_uses_only_the_explicit_owned_environment() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let home = dir.path().canonicalize()?;
    let _restore = isolate(&home);
    let installation = home.join("installation");
    assert!(!installation.exists());
    assert_eq!(roots()?, (installation.clone(), installation.clone()));
    assert!(installation.is_dir());
    assert_eq!(
        local_m3_directory()?,
        home.join("installation/models/bge-m3")
    );
    std::env::set_var("RSRS_M3_DIR", home.join("explicit-model"));
    assert_eq!(local_m3_directory()?, home.join("explicit-model"));
    // Windows dirs::home_dir uses FOLDERID_Profile, not these environment overrides.
    // Compare expansion only; all filesystem mutations above stay under the tempdir.
    let platform_home = dirs::home_dir().context("platform home directory")?;
    std::env::set_var("RSRS_M3_DIR", "~/owned-model");
    assert_eq!(local_m3_directory()?, platform_home.join("owned-model"));
    std::env::set_var("RSRS_M3_DIR", " \t ");
    assert!(local_m3_directory().is_err());
    std::env::remove_var("RSRS_M3_DIR");
    std::env::remove_var("RSRS_DATA_DIR");
    assert_eq!(
        local_m3_directory()?,
        platform_home.join(".rsrs/models/bge-m3")
    );
    Ok(())
}

#[test]
fn uninstall_removes_only_the_exact_model_tree_and_is_idempotent() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let home = dir.path().canonicalize()?;
    let _restore = isolate(&home);
    let root = home.join("installation");
    let profile = root.join("profiles/synthetic");
    fs::create_dir_all(&profile)?;
    let target = root.join("models/bge-m3");
    fs::create_dir_all(target.join("onnx/nested"))?;
    fs::write(
        target.join("onnx/nested/model.onnx"),
        b"synthetic non-executable model",
    )?;
    fs::write(profile.join("keep.txt"), b"synthetic profile marker")?;
    fs::write(root.join("models/keep.txt"), b"unrelated model marker")?;
    assert!(remove_m3(&root, &profile, &root.join("models")).is_err());
    assert!(target.exists());
    assert!(remove_m3(&root, &profile, &target)?);
    assert!(!target.exists());
    assert_eq!(
        fs::read(profile.join("keep.txt"))?,
        b"synthetic profile marker"
    );
    assert_eq!(
        fs::read(root.join("models/keep.txt"))?,
        b"unrelated model marker"
    );
    assert!(!remove_m3(&root, &profile, &target)?);
    fs::write(&target, b"not a directory")?;
    assert!(remove_m3(&root, &profile, &target).is_err());
    assert_eq!(fs::read(&target)?, b"not a directory");
    Ok(())
}

#[test]
fn uninstall_preserves_installation_profile_home_and_linked_content() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let home = dir.path().canonicalize()?;
    let _restore = isolate(&home);
    let root = home.join("installation");
    let profile = root.join("profiles/synthetic");
    fs::create_dir_all(&profile)?;
    for protected in [&home, &root, &profile] {
        std::env::set_var("RSRS_M3_DIR", protected);
        assert!(remove_m3(&root, &profile, protected).is_err());
        assert!(protected.is_dir());
    }
    #[cfg(unix)]
    {
        let target = root.join("models/bge-m3");
        fs::create_dir_all(&target)?;
        let outside = home.join("outside.txt");
        fs::write(&outside, b"outside synthetic marker")?;
        let link = target.join("linked.onnx");
        std::os::unix::fs::symlink(&outside, &link)?;
        std::env::set_var("RSRS_M3_DIR", &target);
        assert!(remove_m3(&root, &profile, &target).is_err());
        assert!(target.is_dir());
        assert_eq!(fs::read(outside)?, b"outside synthetic marker");
    }
    Ok(())
}

#[test]
fn model_account_read_is_metadata_only_and_rejects_invalid_sessions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    assert_eq!(account(&profile)?, None);
    fs::write(
        profile.join("session.json"),
        br#"{"user":"synthetic-model-user"}"#,
    )?;
    assert_eq!(account(&profile)?, Some(hash(b"synthetic-model-user")));
    fs::write(profile.join("session.json"), b"invalid JSON")?;
    assert!(account(&profile).is_err());
    #[cfg(not(windows))]
    {
        assert!(install_catalog(&profile, None)?.is_empty());
        let pin = ModelCatalogPin {
            version: "synthetic".into(),
            package_source: "https://example.invalid".into(),
            package_sha256: "0".repeat(64),
            archive_member: "synthetic".into(),
            destination: profile.join("catalog.dll"),
            dll_size: 1,
            dll_sha256: "0".repeat(64),
        };
        assert!(install_catalog(&profile, Some(&pin)).is_err());
        assert!(!profile.join("catalog.dll").exists());
    }
    Ok(())
}
