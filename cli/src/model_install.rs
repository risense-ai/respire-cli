//! Explicitly install the local BGE-M3 model (tokenizer.json + onnx/model_fp16.onnx).
//!
//! Does not touch the session or create a memory store. A failed download leaves
//! no half-file that could be treated as a valid install. A model that already
//! verifies is not overwritten. A mirror only replaces the host.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};

use crate::memory::bge::{expand_home, model_files_present};
use crate::model_progress;

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-m3";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "4de13258303883538bd53b696b452bf8099f0858";
const ONNX_SHA256: &str = "4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9";
const TOKENIZER_SHA256: &str = "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790";

/// Preserve the upstream model card/license separately from the Core SDK license.
fn write_model_notices(dest: &Path, model: &str, repo: &str, revision: &str) -> Result<()> {
    let source = serde_json::json!({"repository":repo,"revision":revision});
    std::fs::write(dest.join("MODEL-SOURCE.json"), serde_json::to_vec_pretty(&source)?)?;
    std::fs::write(dest.join("MODEL-CARD.md"), include_str!("../../docs/model-notices/bge-m3-MODEL-CARD.md"))?;
    std::fs::write(dest.join("LICENSE.txt"), include_str!("../../docs/model-notices/FlagEmbedding-LICENSE.txt"))?;
    std::fs::write(dest.join("NOTICE-SOURCES.json"), include_str!("../../docs/model-notices/sources.json"))?;
    let _ = model;
    Ok(())
}

pub struct InstallReport {
    pub dir: PathBuf,
    pub skipped: bool,
}

/// Download sources all serve the same pinned BGE-M3 files.
pub const MIRRORS: &[&str] = &["auto", "https://hf-mirror.com", "https://hf-mirror.net", "https://huggingface.co"];

pub fn mirror_from_env() -> Option<String> {
    std::env::var("ONEMEMORY_MIRROR").ok().filter(|s| !s.trim().is_empty())
        .or_else(|| crate::service::read_agent_config()["model_mirror"].as_str().map(str::to_owned))
}

pub fn install_target_dir(explicit: Option<&str>) -> PathBuf {
    explicit.filter(|s| !s.trim().is_empty()).map(|s| expand_home(s.trim()))
        .unwrap_or_else(crate::memory::bge::m3_model_dir)
}

pub fn install_m3(mirror: Option<&str>) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin("verify")?;
    install_m3_inner(mirror)
}

/// Called with the background index operation already reserved. Preparing files
/// must not try to reserve that operation a second time or acquire a library lock.
pub fn prepare_m3_for_index() -> Result<()> {
    let user = install_target_dir(None);
    let explicit = std::env::var("ONEMEMORY_M3_DIR").ok().is_some_and(|value| !value.trim().is_empty());
    let mut candidates = vec![user];
    if !explicit {
        if let Some(parent) = std::env::current_exe()?.parent() {
            candidates.push(parent.join("models/bge-m3"));
        }
        candidates.push(PathBuf::from("/usr/lib/respire/models/bge-m3"));
    }
    if !candidates.iter().any(|path| model_files_present(path)) {
        install_m3_inner(None)?;
    }
    Ok(())
}

fn install_m3_inner(mirror: Option<&str>) -> Result<InstallReport> {
    let dest = install_target_dir(None);
    let setting = mirror.map(str::to_owned).or_else(mirror_from_env).unwrap_or_else(|| "auto".to_owned());
    let origins = if setting.trim() == "auto" {
        MIRRORS[1..].iter().map(|s| (*s).to_owned()).collect::<Vec<_>>()
    } else { vec![origin_from_mirror(&setting)?] };
    let files = [("tokenizer.json", TOKENIZER_SHA256), ("onnx/model_fp16.onnx", ONNX_SHA256)];
    std::fs::create_dir_all(&dest)?;
    let tmp = dest.join(format!(".install-tmp-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let _guard = TmpGuard(tmp.clone());
    let mut skipped = true;
    for (name, sha) in files {
        if file_valid(&dest.join(name), sha)? { continue; }
        let mut failures = Vec::new();
        let mut ready = false;
        for origin in &origins {
            model_progress::check()?;
            let url = file_url(origin, name);
            eprintln!("downloading BGE-M3 {name} from {origin}");
            match download_verified(&url, &tmp.join(name), sha) {
                Ok(()) => { ready = true; break; }
                Err(error) => {
                    model_progress::check()?;
                    // Disk failures must not be disguised as a mirror outage.
                    if error.downcast_ref::<std::io::Error>().is_some() { return Err(error); }
                    eprintln!("download source failed: {error:#}");
                    failures.push(format!("{origin}: {error:#}"));
                }
            }
        }
        anyhow::ensure!(ready, "BGE-M3 download failed: {}", failures.join("; "));
        skipped = false;
    }
    // Publish only after every required replacement has passed the pinned checksum.
    std::fs::create_dir_all(dest.join("onnx"))?;
    for (name, _) in files { if tmp.join(name).is_file() { replace_file(&tmp.join(name), &dest.join(name))?; } }
    anyhow::ensure!(model_files_present(&dest), "BGE-M3 install is incomplete");
    write_model_notices(&dest, "m3", MODEL_REPO, MODEL_REVISION)?;
    Ok(InstallReport { dir: dest, skipped })
}

pub struct UninstallReport {
    pub dir: PathBuf,
    pub removed: bool,
}

fn refuse_system_model_dir(path: &Path) -> Result<()> {
    let text = path.to_string_lossy().replace('\\', "/");
    if text.contains("/usr/lib/respire/models") {
        anyhow::bail!(
            "refusing to delete the system model dir: {}",
            path.display()
        );
    }
    Ok(())
}

fn remove_model_dir(path: &Path) -> Result<bool> {
    refuse_system_model_dir(path)?;
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(path)
        .map_err(|e| anyhow!("failed to delete {}: {e}", path.display()))?;
    Ok(true)
}

/// Delete the BGE-M3 files at the install target and drop the in-process session.
pub fn uninstall_m3() -> Result<UninstallReport> {
    crate::memory::onnx::reset_sessions()?;
    let dest = install_target_dir(None);
    let removed = remove_model_dir(&dest)?;
    Ok(UninstallReport { dir: dest, removed })
}

struct TmpGuard(PathBuf);


impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn validate_mirror(value: &str) -> Result<()> {
    if value == "auto" { return Ok(()); }
    origin_from_mirror(value).map(|_| ())
}

fn origin_from_mirror(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("--mirror must not be empty");
    }
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let Some((scheme, rest)) = with_scheme.split_once("://") else {
        anyhow::bail!("--mirror is invalid: {raw}");
    };
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("--mirror only supports http/https");
    }
    let hostport = match rest.split('/').next() {
        Some(h) if !h.is_empty() => h.trim(),
        _ => anyhow::bail!("--mirror is missing a host"),
    };
    anyhow::ensure!(!hostport.contains(['@', '?', '#']) && !hostport.chars().any(char::is_whitespace), "mirror must be a host without credentials, query or fragment");
    Ok(format!("{scheme}://{hostport}"))
}

fn file_url(origin: &str, rel: &str) -> String {
    format!(
        "{}/{}/resolve/{}/{}",
        origin.trim_end_matches('/'),
        MODEL_REPO,
        MODEL_REVISION,
        rel
    )
}

fn replace_file(from: &Path, to: &Path) -> Result<()> {
    if to.exists() {
        std::fs::remove_file(to)
            .map_err(|e| anyhow!("cannot replace invalid file {}: {e}", to.display()))?;
    }
    std::fs::rename(from, to).map_err(|e| anyhow!("failed to place {}: {e}", to.display()))
}

fn file_valid(path: &Path, expected: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    let actual = sha256_file(path)?;
    Ok(actual.eq_ignore_ascii_case(expected))
}

fn sha256_file(path: &Path) -> Result<String> {
    let item = path.file_name().unwrap_or_default().to_string_lossy();
    let total = path.metadata()?.len();
    let mut checked = 0;
    model_progress::update("verify", &item, 0, Some(total))?;
    let mut file =
        File::open(path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        checked += n as u64;
        model_progress::update("verify", &item, checked, Some(total))?;
    }
    Ok(hex::encode(hasher.finalize()))
}

fn download_verified(url: &str, dest: &Path, expected: &str) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("failed to create {}: {e}", parent.display()))?;
    }
    let resp = download_response(url, dest)?;
    let total = resp
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok());
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file =
        File::create(dest).with_context(|| format!("failed to write {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = 0;
    let mut last_mb: u64 = 0;
    loop {
        model_progress::update("download", &item, written, total)?;
        let n = read_download(&mut reader, &mut buf, url)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        hasher.update(&buf[..n]);
        written += n as u64;
        let mb = written / (1024 * 1024);
        if mb >= last_mb + 32 {
            eprintln!("  downloaded {mb} MB");
            last_mb = mb;
        }
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    drop(file);
    model_progress::update("verify", &item, written, Some(written))?;
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(expected) {
        let _ = std::fs::remove_file(dest);
        anyhow::bail!(
            "checksum failed: {} SHA256={actual} (expected {expected})",
            dest.display()
        );
    }
    Ok(())
}

fn download_response(url: &str, dest: &Path) -> Result<ureq::Response> {
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    // Allow CDN body stalls while bounding cancellation latency to one 30-second read.
    let response = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(10))
        .build()
        .get(url)
        .call();
    model_progress::check()?;
    response.map_err(|error| anyhow!("download failed ({url}): {error}"))
}

fn read_download(reader: &mut impl Read, buf: &mut [u8], url: &str) -> Result<usize> {
    let result = reader.read(buf);
    model_progress::check()?;
    result.map_err(|error| anyhow!("download interrupted ({url}): {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn parse_source_and_mirror() -> Result<()> {
        assert_eq!(
            origin_from_mirror("hf-mirror.com")?,
            "https://hf-mirror.com"
        );
        assert_eq!(
            origin_from_mirror("http://127.0.0.1:8080/x")?,
            "http://127.0.0.1:8080"
        );
        assert!(origin_from_mirror("").is_err());
        Ok(())
    }

    #[test]
    fn install_target_and_file_helpers() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let explicit = install_target_dir(Some("D:/models/bge"));
        assert!(explicit.ends_with("bge") || explicit.to_string_lossy().contains("models"));
        let saved = std::env::var("ONEMEMORY_M3_DIR").ok();
        std::env::set_var("ONEMEMORY_M3_DIR", "/tmp/om-model-test");
        let from_env = install_target_dir(None);
        assert!(from_env.to_string_lossy().contains("om-model-test"));
        match saved {
            Some(v) => std::env::set_var("ONEMEMORY_M3_DIR", v),
            None => std::env::remove_var("ONEMEMORY_M3_DIR"),
        }
        let url = file_url("https://huggingface.co", "tokenizer.json");
        assert!(url.contains("tokenizer.json"));
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("a.bin");
        assert!(!file_valid(&p, "deadbeef")?);
        std::fs::write(&p, b"abc")?;
        let hash = sha256_file(&p)?;
        assert_eq!(hash.len(), 64);
        assert!(file_valid(&p, &hash)?);
        let dest = dir.path().join("b.bin");
        replace_file(&p, &dest)?;
        assert!(dest.is_file());
        let tmp = dir.path().join("tmp-guard");
        std::fs::create_dir_all(&tmp)?;
        drop(TmpGuard(tmp.clone()));
        assert!(!tmp.exists());
        Ok(())
    }

    #[test]
    fn uninstall_m3_delete_files() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir()?;
        let bge = root.path().join("bge-m3");
        std::fs::create_dir_all(bge.join("onnx"))?;
        std::fs::write(bge.join("tokenizer.json"), b"{}")?;
        std::fs::write(bge.join("onnx").join("model_fp16.onnx"), b"onnx")?;
        let saved_bge = std::env::var("ONEMEMORY_M3_DIR").ok();
        std::env::set_var("ONEMEMORY_M3_DIR", &bge);

        let gone_bge = uninstall_m3()?;
        assert!(gone_bge.removed);
        assert!(!bge.exists());
        let again_bge = uninstall_m3()?;
        assert!(!again_bge.removed);


        match saved_bge {
            Some(v) => std::env::set_var("ONEMEMORY_M3_DIR", v),
            None => std::env::remove_var("ONEMEMORY_M3_DIR"),
        }
        Ok(())
    }
}
