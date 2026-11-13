//! Shared Runtime receipts and migration, also implemented independently by Client2.
use super::*;

fn receipt_path(version: &str) -> PathBuf {
    runtime_dir()
        .join(".receipts")
        .join(format!("{version}.json"))
}

pub(super) fn save_receipt(manifest: &ManagedManifest) -> Result<()> {
    let path = receipt_path(&manifest.version);
    let parent = path.parent().context("Runtime receipt has no parent")?;
    create_private_dir(parent)?;
    let temporary = parent.join(format!(".receipt-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
        file.sync_all()?;
        drop(file);
        if path.exists() {
            respire_spawn::durable::replace_file(&temporary, &path)?;
        } else {
            respire_spawn::durable::publish_new_file(&temporary, &path)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn release_manifest(version: &str) -> Result<ManagedManifest> {
    let triple = release_triple()?;
    let bytes = fetch_metadata(&release_asset(
        RELEASE_BASE,
        &format!("v{version}/runtime-build-{triple}.json"),
    ))?;
    let metadata: BuildMetadata = serde_json::from_slice(&bytes)?;
    metadata.validate(version, &triple)?;
    ManagedManifest::from_release(&metadata, &bytes)
}

/// Copy only the authenticated inventory; legacy directories can contain the
/// archive's full-triple image as well as the identical managed image.
fn copy_release(source: &Path, stage: &Path, manifest: &ManagedManifest) -> Result<()> {
    let metadata = manifest.bound_metadata(&release_triple()?)?;
    for entry in &metadata.files {
        let name = if entry.path == metadata.binary_file {
            RUNTIME_BINARY
        } else {
            &entry.path
        };
        let source_name = if source.join(name).is_file() {
            name
        } else {
            &entry.path
        };
        if entry.path.starts_with("core-notices/") {
            continue;
        }
        let input = regular_install_file(source, source_name)?;
        anyhow::ensure!(
            fs::metadata(&input)?.len() == entry.size
                && sha256_file(&input)?.eq_ignore_ascii_case(&entry.sha256),
            "legacy Runtime release file mismatch: {}",
            entry.path
        );
        let output = stage.join(name);
        if let Some(parent) = output.parent() {
            create_private_dir(parent)?;
        }
        fs::copy(&input, &output)?;
    }
    metadata.verify_files(stage)?;
    verify_stage(stage, RUNTIME_BINARY, &release_triple()?, &manifest.sha256)?;
    Ok(())
}

fn publish_directory(source: &Path, manifest: &ManagedManifest, activate: bool) -> Result<PathBuf> {
    let stage = staging_dir()?;
    let result = (|| -> Result<PathBuf> {
        let unpacked = stage.join("unpacked");
        create_private_dir(&unpacked)?;
        copy_release(source, &unpacked, manifest)?;
        let binary = adopt_or_verify_version_dir(&unpacked, manifest)?;
        save_receipt(manifest)?;
        if activate {
            publish_manifest(manifest)?;
        }
        Ok(binary)
    })();
    let cleanup = fs::remove_dir_all(stage);
    match (result, cleanup) {
        (Ok(binary), Ok(())) => Ok(binary),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

/// Migrate installation bytes only. Account data, endpoints and running owners
/// stay untouched; old trees remain available until a verified normal restart.
pub(crate) fn migrate_legacy() -> Result<()> {
    if crate::embedding::selection().is_some() {
        return Ok(());
    }
    if manifest_path().exists() {
        if let Some(manifest) = read_manifest()? {
            if version_dir(&manifest.version)
                .join("core-notices")
                .try_exists()?
            {
                let _lock = install_lock()?;
                compact_version(&manifest)?;
            }
        }
        return Ok(());
    }
    let root = installation_root();
    let mut selected: Option<(ManagedManifest, PathBuf)> = None;
    for base in [root.clone(), root.join("client2")] {
        let path = base.join(MANIFEST_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_MANAGED_MANIFEST_BYTES,
            "legacy Runtime receipt too large"
        );
        let manifest: ManagedManifest = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(
            valid_version(&manifest.version) && valid_sha256(&manifest.sha256),
            "invalid legacy Runtime receipt"
        );
        if let Some((previous, _)) = &selected {
            if previous.version == manifest.version {
                anyhow::ensure!(
                    previous.sha256.eq_ignore_ascii_case(&manifest.sha256),
                    "conflicting legacy Runtime receipts"
                );
            }
            if semver_cmp(&previous.version, &manifest.version) != std::cmp::Ordering::Less {
                continue;
            }
        }
        let source = base.join("runtime").join(&manifest.version);
        selected = Some((manifest, source));
    }
    let Some((legacy, source)) = selected else {
        return Ok(());
    };
    let manifest = if legacy.release.is_some() {
        legacy.clone()
    } else {
        release_manifest(&legacy.version)?
    };
    anyhow::ensure!(
        manifest.sha256.eq_ignore_ascii_case(&legacy.sha256),
        "legacy Runtime receipt differs from the published release"
    );
    let _lock = install_lock()?;
    if manifest_path().exists() {
        return Ok(());
    }
    publish_directory(&source, &manifest, true)?;
    Ok(())
}

// Notices are not loader inputs and are omitted from managed installations.
pub(super) fn compact_version(manifest: &ManagedManifest) -> Result<()> {
    validate_installed(manifest)?;
    let notices = version_dir(&manifest.version).join("core-notices");
    if notices.exists() {
        fs::remove_dir_all(&notices)?;
    }
    Ok(())
}
