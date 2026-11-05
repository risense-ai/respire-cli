//! Read local identity metadata without unlocking keys or opening a store.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

/// Only a missing file is absent; an existing file must be a valid session object.
pub fn read_session_json(path: &Path) -> Result<Option<Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read session {}", path.display()))
        }
    };
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("session {} contains invalid JSON", path.display()))?;
    anyhow::ensure!(
        value.is_object(),
        "session {} must contain a JSON object",
        path.display()
    );
    Ok(Some(value))
}

/// Only an absent session permits the caller's profile-based identity fallback.
pub fn session_user_of_dir(dir: &Path) -> Result<Option<String>> {
    let path = dir.join("session.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let value: Value = serde_json::from_slice(&read_identity_record(&path)?)
                .context("current account identity contains invalid JSON")?;
            let user = value["user"]
                .as_str()
                .filter(|user| !user.is_empty())
                .context("current account identity missing user")?;
            Ok(Some(user.to_owned()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("current account identity is unavailable"),
    }
}

// Keep the launch/recovery record boundary, including checking every ancestor.
fn read_identity_record(path: &Path) -> Result<Vec<u8>> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "recovery path contains a symlink"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "recovery path contains a reparse point"
            );
        }
    }
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 65536,
        "invalid recovery record"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 65536, "recovery record exceeds 64 KiB");
    Ok(bytes)
}
