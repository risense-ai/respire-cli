//! Pinned Granite embedding installs without touching the BGE-M3 layout.
//!
//! The runtime registers the matching built-in profiles; this installer only
//! stages verified bytes under `models/granite-311m-r2` and
//! `models/granite-97m-r2`. It reuses the shared download and verification
//! pipeline and never publishes files the checksum does not match.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::model_asset_files::replace_file;
use crate::model_download::{
    download_with_fallback, file_valid, remove_download_parts, DownloadTimeouts,
};

/// One immutable Granite artifact pin (upstream Hugging Face revision).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GraniteFile {
    /// Destination path relative to the profile directory.
    pub relative: &'static str,
    /// Upstream byte length.
    pub size: u64,
    /// Upstream SHA-256.
    pub sha256: &'static str,
}

/// One selectable Granite profile pin.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GranitePin {
    /// CLI `--model` value.
    pub id: &'static str,
    /// Built-in runtime profile id (aligned with the runtime registry).
    pub profile: &'static str,
    /// Hugging Face repository (`org/name`).
    pub repo: &'static str,
    /// Immutable 40-hex revision.
    pub revision: &'static str,
    /// ONNX weights pin.
    pub weights: GraniteFile,
    /// Tokenizer pin.
    pub tokenizer: GraniteFile,
}

/// Quantized 768-dimension profile for everyday recall (the default).
pub const GRANITE_311M: GranitePin = GranitePin {
    id: "311m",
    profile: "granite-311m-r2",
    repo: "ibm-granite/granite-embedding-311m-multilingual-r2",
    revision: "44399559930365213510b1ee2eb15ded83374f0e",
    weights: GraniteFile {
        relative: "onnx/model_quint8_avx2.onnx",
        size: 313_421_909,
        sha256: "f1fdd44e7e1ac51f12ab7957c7bd092e064d596c288513bf9d326842f669edee",
    },
    tokenizer: GraniteFile {
        relative: "tokenizer.json",
        size: 33_384_821,
        sha256: "0087c868b33bad550a78a08d19798cfd7f713cde4f020803b8f51f405503e15f",
    },
};

/// Non-quantized 384-dimension profile for self-learning.
pub const GRANITE_97M: GranitePin = GranitePin {
    id: "97m",
    profile: "granite-97m-r2",
    repo: "ibm-granite/granite-embedding-97m-multilingual-r2",
    revision: "835ad14087e140460703cf0fae09f97d469d65c2",
    weights: GraniteFile {
        relative: "onnx/model.onnx",
        size: 390_004_608,
        sha256: "68e592b160673d30250824c1116bc6ab33f70efb22b97c9e1d7ce1e69c1c9d70",
    },
    tokenizer: GraniteFile {
        relative: "tokenizer.json",
        size: 25_301_672,
        sha256: "4f2842d568e2724370aec203652a42ac783c7937f8347a1a2cc7506d71f1582f",
    },
};

/// Resolve a CLI `--model` value to its pin.
pub fn pin_for(model: &str) -> Result<GranitePin> {
    match model {
        "311m" => Ok(GRANITE_311M),
        "97m" => Ok(GRANITE_97M),
        _ => anyhow::bail!("unknown granite model {model:?}; expected 311m or 97m"),
    }
}

/// Build the immutable upstream source URL for one pinned file.
///
/// `origin` is a bare mirror origin such as `https://hf-mirror.com`; the path
/// layout stays identical to `https://huggingface.co/{repo}/resolve/{rev}/{rel}`.
pub fn granite_source_url(origin: &str, pin: &GranitePin, file: &GraniteFile) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        origin.trim_end_matches('/'),
        pin.repo,
        pin.revision,
        file.relative
    )
}

/// Profile directory under the shared model root: `models/granite-<id>`.
pub fn granite_model_dir(models_root: &Path, pin: &GranitePin) -> PathBuf {
    models_root.join(pin.profile)
}

/// The shared model root (`main_data_dir()/models`), separate from the M3 root.
pub fn granite_models_root() -> Result<PathBuf> {
    // Same root as the built-in profile registry: main_data_dir()/models.
    // model_install is server-gated, so the CLI path cannot call it.
    Ok(respire_client_host::paths::main_data_dir().join("models"))
}

fn granite_origins(mirror: Option<&str>) -> Result<Vec<String>> {
    let setting = mirror
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto");
    if setting == "auto" {
        return Ok(crate::model_download::MIRRORS[1..]
            .iter()
            .map(|origin| (*origin).to_owned())
            .collect());
    }
    Ok(vec![crate::model_download::origin_from_mirror(setting)?])
}

/// Stage and publish every pinned file for one Granite profile.
///
/// Verified files are reused; only missing or mismatched bytes download. All
/// sources are the same immutable revision, and mirror selection follows the
/// shared `--mirror`/`RSRS_MIRROR` policy (including hf-mirror fallbacks).
pub fn install_granite(model: &str, mirror: Option<&str>) -> Result<InstallGraniteReport> {
    let _operation = crate::model_progress::Operation::begin_download()?;
    let pin = pin_for(model)?;
    let dest = granite_model_dir(&granite_models_root()?, &pin);
    let origins = granite_origins(mirror)?;
    let mut skipped = true;
    for file in [pin.weights, pin.tokenizer] {
        let staged = stage_file(&pin, file, &dest, &origins)?;
        if !staged {
            skipped = false;
        }
    }
    // Prove the published bytes before reporting success.
    for file in [pin.weights, pin.tokenizer] {
        anyhow::ensure!(
            file_valid(&dest.join(file.relative), file.sha256, Some(file.size))?,
            "granite {} {} did not verify after install",
            pin.id,
            file.relative
        );
    }
    Ok(InstallGraniteReport {
        dir: dest,
        skipped,
        profile: pin.profile.to_owned(),
        model: pin.id.to_owned(),
    })
}

/// Receipt for one Granite install.
pub struct InstallGraniteReport {
    pub dir: PathBuf,
    pub skipped: bool,
    pub profile: String,
    pub model: String,
}

/// Download (if needed) and publish a single pinned file.
///
/// Returns `Ok(true)` when the destination already verified and no transfer
/// ran. Staged bytes live under `.download-granite-<revision>` so a partial
/// attempt can resume without exposing an unverified file to the loader.
fn stage_file(
    pin: &GranitePin,
    file: GraniteFile,
    dest: &Path,
    origins: &[String],
) -> Result<bool> {
    std::fs::create_dir_all(dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;
    if file_valid(&dest.join(file.relative), file.sha256, Some(file.size))? {
        return Ok(true);
    }
    let tmp = dest.join(format!(".download-granite-{}", pin.revision));
    std::fs::create_dir_all(tmp.join("onnx"))
        .with_context(|| format!("failed to create {}", tmp.display()))?;
    let staged = tmp.join(file.relative);
    if !file_valid(&staged, file.sha256, Some(file.size))? {
        let sources = origins
            .iter()
            .map(|origin| granite_source_url(origin, pin, &file))
            .collect::<Vec<_>>();
        download_with_fallback(
            &sources,
            &staged,
            file.sha256,
            file.relative.ends_with(".onnx"),
            DownloadTimeouts::default(),
            Some(file.size),
        )?;
        remove_download_parts(&staged)?;
    }
    anyhow::ensure!(
        file_valid(&staged, file.sha256, Some(file.size))?,
        "granite staged file size or checksum mismatch: {}",
        file.relative
    );
    replace_file(&staged, &dest.join(file.relative))?;
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_lookup_rejects_unknown_models() {
        assert_eq!(pin_for("311m").expect("311m pin").profile, "granite-311m-r2");
        assert_eq!(pin_for("97m").expect("97m pin").profile, "granite-97m-r2");
        assert!(pin_for("bge-m3").is_err());
    }

    #[test]
    fn source_url_uses_pinned_repo_revision_and_relative_path() {
        let pin = GRANITE_311M;
        let url = granite_source_url("https://hf-mirror.com", &pin, &pin.weights);
        assert_eq!(
            url,
            "https://hf-mirror.com/ibm-granite/granite-embedding-311m-multilingual-r2/resolve/44399559930365213510b1ee2eb15ded83374f0e/onnx/model_quint8_avx2.onnx"
        );
        let official = granite_source_url("https://huggingface.co", &pin, &pin.tokenizer);
        assert_eq!(
            official,
            "https://huggingface.co/ibm-granite/granite-embedding-311m-multilingual-r2/resolve/44399559930365213510b1ee2eb15ded83374f0e/tokenizer.json"
        );
    }

    #[test]
    fn model_dir_is_the_profile_directory_under_the_shared_root() {
        let pin = GRANITE_97M;
        let dir = granite_model_dir(Path::new("/data/models"), &pin);
        assert_eq!(dir, PathBuf::from("/data/models/granite-97m-r2"));
        assert_eq!(pin.weights.relative, "onnx/model.onnx");
    }

    #[test]
    fn pins_carry_full_upstream_identity() {
        for pin in [GRANITE_311M, GRANITE_97M] {
            assert_eq!(pin.revision.len(), 40);
            assert!(pin.revision.chars().all(|c| c.is_ascii_hexdigit()));
            for file in [pin.weights, pin.tokenizer] {
                assert_eq!(file.sha256.len(), 64);
                assert!(file.sha256.chars().all(|c| c.is_ascii_hexdigit()));
                assert!(file.size > 0);
            }
        }
    }
}
