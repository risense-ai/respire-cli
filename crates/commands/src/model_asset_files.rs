//! Pinned variant file staging and publication without app or Core dependencies.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model_download::{download_with_fallback, DownloadTimeouts};

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-m3";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "4de13258303883538bd53b696b452bf8099f0858";

pub(super) fn install_variant_into(
    variant_name: &str,
    file: &str,
    expected: &str,
    variant_size: u64,
    expected_size: Option<u64>,
    dest: &Path,
    origins: &[String],
) -> Result<()> {
    std::fs::create_dir_all(&dest)?;
    let tmp = variant_staging_dir(&dest);
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let dest_path = dest.join(file);
    let tmp_path = tmp.join(file);
    if !variant_file_valid(&dest_path, expected, variant_size, expected_size)? {
        // A verified leftover from an earlier attempt is published without
        // re-downloading; only an unverified destination downloads.
        if !variant_file_valid(&tmp_path, expected, variant_size, expected_size)? {
            let sources = origins
                .iter()
                .map(|origin| file_url(origin, file))
                .collect::<Vec<_>>();
            download_with_fallback(
                &sources,
                &tmp_path,
                expected,
                true,
                DownloadTimeouts::default(),
                expected_size,
            )?;
        }
        std::fs::create_dir_all(dest.join("onnx"))?;
        anyhow::ensure!(
            variant_file_valid(&tmp_path, expected, variant_size, expected_size)?,
            "downloaded variant size or checksum mismatch"
        );
        replace_file(&tmp_path, &dest_path)?;
    }
    anyhow::ensure!(
        variant_file_valid(&dest_path, expected, variant_size, expected_size)?,
        "BGE-M3 {} install is incomplete",
        variant_name
    );
    Ok(())
}

pub(super) fn file_url(origin: &str, rel: &str) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        origin.trim_end_matches('/'),
        MODEL_REPO,
        MODEL_REVISION,
        rel
    )
}

pub(super) fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        std::fs::remove_file(to)
            .with_context(|| format!("cannot replace invalid file {}", to.display()))?;
    }
    std::fs::rename(from, to).with_context(|| format!("failed to place {}", to.display()))
}

fn variant_staging_dir(dest: &Path) -> PathBuf {
    dest.join(format!(".variants-{MODEL_REVISION}"))
}

fn variant_file_valid(
    path: &Path,
    expected: &str,
    variant_size: u64,
    expected_size: Option<u64>,
) -> Result<bool> {
    if !path.is_file() || path.metadata()?.len() != variant_size {
        return Ok(false);
    }
    crate::model_download::file_valid(path, expected, expected_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn verified_variant_survives_base_cleanup_and_publishes_without_network() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let name = "fp16";
        let file = "onnx/model_fp16.onnx";
        let size = 3;
        let sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let staging = variant_staging_dir(dir.path());
        std::fs::create_dir_all(staging.join("onnx"))?;
        std::fs::write(staging.join("onnx/model_fp16.onnx"), b"abc")?;
        let base_staging = dir.path().join(format!(".download-{MODEL_REVISION}"));
        std::fs::create_dir_all(&base_staging)?;
        std::fs::remove_dir_all(base_staging)?;
        install_variant_into(name, file, sha256, size, None, dir.path(), &[])?;
        install_variant_into(name, file, sha256, size, None, dir.path(), &[])?;
        assert_eq!(
            std::fs::read(dir.path().join("onnx/model_fp16.onnx"))?,
            b"abc"
        );
        assert!(!staging.join("onnx/model_fp16.onnx").exists());
        Ok(())
    }
}
