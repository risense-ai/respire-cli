//! Explicitly install the local BGE model (tokenizer.json + onnx/model.onnx).
//!
//! Does not touch the session or create a memory store. A failed download leaves
//! no half-file that could be treated as a valid install. A model that already
//! verifies is not overwritten. A mirror only replaces the host.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use crate::memory::bge::{default_user_model_dir, expand_home, model_files_present};
use crate::model_progress;

/// HuggingFace repo (where the ONNX actually lives, not the BAAI source repo).
pub const MODEL_REPO: &str = "Xenova/bge-base-zh-v1.5";
/// Verified revision (this commit's tokenizer/onnx hashes match the local read-only model).
pub const MODEL_REVISION: &str = "71e50dc531959f9e04ebf190ea25b00261a0a186";
const DEFAULT_ORIGIN: &str = "https://huggingface.co";
const ONNX_SHA256: &str = "5e5619f7cca7380b824d329c157dba10bee7cc00d0c139e82fdb7906051b8e4f";
const TOKENIZER_SHA256: &str = "7dfbf1966ebf99d471c3796e9b457329d2b2182b817e144f1e904b957745c839";

/// Preserve the upstream model card/license separately from the Core SDK license.
fn write_model_notices(dest: &Path, model: &str, repo: &str, revision: &str) -> Result<()> {
    let source = serde_json::json!({"repository":repo,"revision":revision});
    std::fs::write(dest.join("MODEL-SOURCE.json"), serde_json::to_vec_pretty(&source)?)?;
    let card = match (model, repo) {
        ("legacy", MODEL_REPO) => Some(include_str!("../../docs/model-notices/bge-base-zh-v1.5-MODEL-CARD.md")),
        ("m3", "Xenova/bge-m3") => Some(include_str!("../../docs/model-notices/bge-m3-MODEL-CARD.md")),
        ("reranker", RERANKER_REPO) => Some(include_str!("../../docs/model-notices/bge-reranker-base-MODEL-CARD.md")),
        _ => None,
    };
    if let Some(card) = card {
        std::fs::write(dest.join("MODEL-CARD.md"), card)?;
        std::fs::write(dest.join("LICENSE.txt"), include_str!("../../docs/model-notices/FlagEmbedding-LICENSE.txt"))?;
        std::fs::write(dest.join("NOTICE-SOURCES.json"), include_str!("../../docs/model-notices/sources.json"))?;
    }
    Ok(())
}

pub struct InstallReport {
    pub dir: PathBuf,
    pub skipped: bool,
}

/// Install a pinned M3 artifact without activating it or touching the legacy model/index.
pub fn install_m3(mirror: Option<&str>) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin("verify")?;
    let dest = crate::memory::bge::m3_model_dir();
    let origin = match mirror {
        Some(value) => origin_from_mirror(value)?,
        None => DEFAULT_ORIGIN.to_owned(),
    };
    let files = [
        (
            "tokenizer.json",
            "6710678b12670bc442b99edc952c4d996ae309a7020c1fa0096dd245c2faf790",
        ),
        (
            "onnx/model_fp16.onnx",
            "4f1a646a3d4f39985589e9991a717044ede8278617fe55e3d246838bc05055e9",
        ),
    ];
    std::fs::create_dir_all(&dest)?;
    let tmp = dest.join(format!(".install-tmp-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let _guard = TmpGuard(tmp.clone());
    let mut skipped = true;
    for (name, sha) in files {
        if file_valid(&dest.join(name), sha)? {
            continue;
        }
        let url = format!(
            "{origin}/Xenova/bge-m3/resolve/4de13258303883538bd53b696b452bf8099f0858/{name}"
        );
        eprintln!("downloading BGE-M3 {name} ...");
        download_verified(&url, &tmp.join(name), sha)?;
        std::fs::create_dir_all(dest.join("onnx"))?;
        replace_file(&tmp.join(name), &dest.join(name))?;
        skipped = false;
    }
    write_model_notices(&dest, "m3", "Xenova/bge-m3", "4de13258303883538bd53b696b452bf8099f0858")?;
    Ok(InstallReport { dir: dest, skipped })
}

/// Parameter-less install (doctor auto-install) reads ONEMEMORY_MIRROR; unset -> official origin.
pub fn mirror_from_env() -> Option<String> {
    std::env::var("ONEMEMORY_MIRROR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `--dir` > `ONEMEMORY_MODEL_DIR` > cross-platform user data dir.
pub fn install_target_dir(explicit: Option<&str>) -> PathBuf {
    if let Some(d) = explicit {
        let d = d.trim();
        if !d.is_empty() {
            return expand_home(d);
        }
    }
    if let Ok(d) = std::env::var("ONEMEMORY_MODEL_DIR") {
        let d = d.trim();
        if !d.is_empty() {
            return expand_home(d);
        }
    }
    default_user_model_dir()
}

pub fn install(dir: Option<&str>, mirror: Option<&str>) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin("verify")?;
    let dest = install_target_dir(dir);
    std::fs::create_dir_all(&dest)
        .map_err(|e| anyhow!("failed to create model dir ({}): {e}", dest.display()))?;

    let tok_final = dest.join("tokenizer.json");
    let onnx_final = dest.join("onnx").join("model.onnx");
    let need_tok = !file_valid(&tok_final, TOKENIZER_SHA256)?;
    let need_onnx = !file_valid(&onnx_final, ONNX_SHA256)?;
    if !need_tok && !need_onnx {
        write_model_notices(&dest, "legacy", MODEL_REPO, MODEL_REVISION)?;
        eprintln!(
            "model already ready (verified, not overwritten): {}",
            dest.display()
        );
        return Ok(InstallReport {
            dir: dest,
            skipped: true,
        });
    }

    let origin = match mirror {
        Some(m) => origin_from_mirror(m)?,
        None => DEFAULT_ORIGIN.to_string(),
    };

    let tmp = dest.join(format!(".install-tmp-{}", uuid::Uuid::new_v4()));
    if let Err(e) = std::fs::create_dir_all(tmp.join("onnx")) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(anyhow!(
            "failed to create temp dir ({}): {e}",
            tmp.display()
        ));
    }
    let tmp_guard = TmpGuard(tmp.clone());

    if need_tok {
        let url = file_url(&origin, "tokenizer.json");
        eprintln!("downloading tokenizer.json ...");
        download_verified(&url, &tmp.join("tokenizer.json"), TOKENIZER_SHA256)?;
    }
    if need_onnx {
        let url = file_url(&origin, "onnx/model.onnx");
        eprintln!("downloading onnx/model.onnx ...");
        download_verified(&url, &tmp.join("onnx").join("model.onnx"), ONNX_SHA256)?;
    }

    if need_tok {
        replace_file(&tmp.join("tokenizer.json"), &tok_final)?;
    }
    if need_onnx {
        std::fs::create_dir_all(dest.join("onnx"))
            .map_err(|e| anyhow!("failed to create onnx dir: {e}"))?;
        replace_file(&tmp.join("onnx").join("model.onnx"), &onnx_final)?;
    }
    drop(tmp_guard);

    if !model_files_present(&dest)
        || !file_valid(&tok_final, TOKENIZER_SHA256)?
        || !file_valid(&onnx_final, ONNX_SHA256)?
    {
        anyhow::bail!(
            "post-install verify failed: {} (need tokenizer.json and onnx/model.onnx with matching hashes)",
            dest.display()
        );
    }
    eprintln!("installed BGE model: {}", dest.display());
    write_model_notices(&dest, "legacy", MODEL_REPO, MODEL_REVISION)?;
    Ok(InstallReport {
        dir: dest,
        skipped: false,
    })
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

/// Delete the BGE files at the install target and drop the in-process session.
pub fn uninstall_bge() -> Result<UninstallReport> {
    crate::memory::onnx::reset_sessions()?;
    let dest = install_target_dir(None);
    let removed = remove_model_dir(&dest)?;
    Ok(UninstallReport { dir: dest, removed })
}

pub fn rerank_target_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("ONEMEMORY_RERANKER_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return expand_home(trimmed);
        }
    }
    let bge = default_user_model_dir();
    match bge.parent() {
        Some(models_dir) => models_dir.join("bge-reranker-base"),
        None => bge.with_file_name("bge-reranker-base"),
    }
}

/// Delete the rerank files at the install target and drop the in-process session.
pub fn uninstall_rerank() -> Result<UninstallReport> {
    crate::memory::onnx::reset_sessions()?;
    let dest = rerank_target_dir();
    let removed = remove_model_dir(&dest)?;
    Ok(UninstallReport { dir: dest, removed })
}

/// Reranker model repo (Xenova ONNX build) and verified revision.
pub const RERANKER_REPO: &str = "Xenova/bge-reranker-base";
pub const RERANKER_REVISION: &str = "280bcc27a84e0b898c251e06fddb25171bd9b101";

/// Install the cross-encoder rerank model (quantized bge-reranker-base, ~280MB).
///
/// Unlike the BGE embedder this is **optional** - recall still works without it
/// (just no rerank), so doctor does not auto-download; run `rsrs model install-rerank`.
/// Only three required files are fetched; upstream files inside a revision can change,
/// so there is no hard hash, only a non-empty check.
///
/// `source`: user-supplied model origin - paste the full URL of any file in the repo
/// (resolve/blob both work); origin/repo/revision are parsed and the three files assembled.
/// If that revision 404s, the user pastes a current URL. Without source, RERANKER_REPO+RERANKER_REVISION
/// are used (mirror only swaps the host).
pub fn install_rerank(
    dir: Option<&str>,
    mirror: Option<&str>,
    source: Option<&str>,
) -> Result<InstallReport> {
    let _operation = model_progress::Operation::begin("verify")?;
    let dest = match dir {
        Some(d) if !d.trim().is_empty() => expand_home(d.trim()),
        _ => {
            // Next to BGE: under the **parent** of the user model dir (.../models/bge-base-zh-v1.5)
            let bge = default_user_model_dir();
            match bge.parent() {
                Some(models_dir) => models_dir.join("bge-reranker-base"),
                None => bge.with_file_name("bge-reranker-base"),
            }
        }
    };
    std::fs::create_dir_all(dest.join("onnx"))
        .map_err(|e| anyhow!("failed to create reranker dir ({}): {e}", dest.display()))?;

    let (origin, repo, revision) = match source {
        Some(s) if !s.trim().is_empty() => parse_source(s)?,
        _ => {
            let origin = match mirror {
                Some(m) => origin_from_mirror(m)?,
                None => DEFAULT_ORIGIN.to_string(),
            };
            (
                origin,
                RERANKER_REPO.to_string(),
                RERANKER_REVISION.to_string(),
            )
        }
    };
    let files: [(&str, &str); 3] = [
        ("tokenizer.json", "tokenizer.json"),
        ("config.json", "config.json"),
        ("onnx/model_quantized.onnx", "onnx/model_quantized.onnx"),
    ];
    let mut installed = 0;
    for (rel, name) in files {
        let target = dest.join(name);
        if target.is_file()
            && std::fs::metadata(&target)
                .map(|m| m.len() > 0)
                .unwrap_or(false)
        {
            continue; // idempotent: skip if a non-empty file is already in place
        }
        let url = format!(
            "{}/{}/resolve/{}/{}",
            origin.trim_end_matches('/'),
            repo,
            revision,
            rel
        );
        eprintln!("downloading {rel} ...");
        download_plain(&url, &target)?;
        installed += 1;
    }
    write_model_notices(&dest, "reranker", &repo, &revision)?;
    if installed == 0 {
        eprintln!(
            "rerank model already ready (not overwritten): {}",
            dest.display()
        );
        return Ok(InstallReport {
            dir: dest,
            skipped: true,
        });
    }
    if !dest.join("tokenizer.json").is_file()
        || !dest.join("onnx").join("model_quantized.onnx").is_file()
    {
        anyhow::bail!("post-install verify failed: {}", dest.display());
    }
    eprintln!("installed rerank model: {}", dest.display());
    Ok(InstallReport {
        dir: dest,
        skipped: false,
    })
}

/// Parse (origin, repo, revision) from a user-pasted model-file URL.
/// Shape: `{origin}/{owner}/{repo}/(resolve|blob)/{rev}/{file...}`;
/// no resolve/blob segment -> revision=main; strip query/fragment; extra slashes are ok.
fn parse_source(src: &str) -> Result<(String, String, String)> {
    let trimmed = src.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        anyhow::bail!("--source needs an http(s):// prefix: {src}");
    };
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("--source only supports http/https: {src}");
    }
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h, p),
        None => (rest, ""),
    };
    if host.is_empty() {
        anyhow::bail!("--source is missing a host: {src}");
    }
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let anchor = segs.iter().position(|s| *s == "resolve" || *s == "blob");
    let (repo_segs, revision) = match anchor {
        Some(i) => {
            if segs.len() < i + 2 {
                anyhow::bail!("--source is missing a revision segment: {src}");
            }
            (segs[..i].to_vec(), segs[i + 1].to_string())
        }
        None => (segs.clone(), "main".to_string()),
    };
    if repo_segs.len() < 2 {
        anyhow::bail!("--source needs owner/repo two segments: {src}");
    }
    Ok((format!("{scheme}://{host}"), repo_segs.join("/"), revision))
}

/// Download without a hash (optional piece: only check non-empty; land as .part then rename so a half-file is not treated as installed).
fn download_plain(url: &str, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow!("failed to create {}: {e}", parent.display()))?;
    }
    let tmp = dest.with_extension("part");
    let _partial = PartialFile(tmp.clone());
    let resp = download_response(url, dest)?;
    let total = resp
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok());
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file =
        File::create(&tmp).map_err(|e| anyhow!("failed to write {}: {e}", tmp.display()))?;
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
            .map_err(|e| anyhow!("failed to write {}: {e}", tmp.display()))?;
        written += n as u64;
        let mb = written / (1024 * 1024);
        if mb >= last_mb + 32 {
            eprintln!("  downloaded {mb} MB");
            last_mb = mb;
        }
    }
    file.flush()
        .map_err(|e| anyhow!("failed to write {}: {e}", tmp.display()))?;
    drop(file);
    model_progress::check()?;
    if written == 0 {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("download was empty: {url}");
    }
    std::fs::rename(&tmp, dest).map_err(|e| anyhow!("failed to place {}: {e}", dest.display()))?;
    Ok(())
}

struct TmpGuard(PathBuf);

struct PartialFile(PathBuf);
impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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
        File::create(dest).map_err(|e| anyhow!("failed to write {}: {e}", dest.display()))?;
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
            .map_err(|e| anyhow!("failed to write {}: {e}", dest.display()))?;
        hasher.update(&buf[..n]);
        written += n as u64;
        let mb = written / (1024 * 1024);
        if mb >= last_mb + 32 {
            eprintln!("  downloaded {mb} MB");
            last_mb = mb;
        }
    }
    file.flush()
        .map_err(|e| anyhow!("failed to write {}: {e}", dest.display()))?;
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
    // Bound each blocking network read so cancellation cannot wait for the entire download.
    let response = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(10))
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
        let (origin, repo, rev) = parse_source(
            "https://huggingface.co/Xenova/bge-base-zh-v1.5/resolve/abc123/onnx/model.onnx",
        )?;
        assert_eq!(origin, "https://huggingface.co");
        assert_eq!(repo, "Xenova/bge-base-zh-v1.5");
        assert_eq!(rev, "abc123");
        let (_, _, main) = parse_source("https://hf.co/owner/repo/file.bin")?;
        assert_eq!(main, "main");
        assert!(parse_source("ftp://x/y").is_err());
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
        let saved = std::env::var("ONEMEMORY_MODEL_DIR").ok();
        std::env::set_var("ONEMEMORY_MODEL_DIR", "/tmp/om-model-test");
        let from_env = install_target_dir(None);
        assert!(from_env.to_string_lossy().contains("om-model-test"));
        match saved {
            Some(v) => std::env::set_var("ONEMEMORY_MODEL_DIR", v),
            None => std::env::remove_var("ONEMEMORY_MODEL_DIR"),
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
    fn uninstall_bge_and_rerank_delete_files() -> Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = tempfile::tempdir()?;
        let bge = root.path().join("bge-base-zh-v1.5");
        std::fs::create_dir_all(bge.join("onnx"))?;
        std::fs::write(bge.join("tokenizer.json"), b"{}")?;
        std::fs::write(bge.join("onnx").join("model.onnx"), b"onnx")?;
        let rerank = root.path().join("bge-reranker-base");
        std::fs::create_dir_all(rerank.join("onnx"))?;
        std::fs::write(rerank.join("tokenizer.json"), b"{}")?;
        std::fs::write(rerank.join("onnx").join("model_quantized.onnx"), b"onnx")?;

        let saved_bge = std::env::var("ONEMEMORY_MODEL_DIR").ok();
        let saved_rr = std::env::var("ONEMEMORY_RERANKER_DIR").ok();
        std::env::set_var("ONEMEMORY_MODEL_DIR", &bge);
        std::env::set_var("ONEMEMORY_RERANKER_DIR", &rerank);

        let gone_bge = uninstall_bge()?;
        assert!(gone_bge.removed);
        assert!(!bge.exists());
        let again_bge = uninstall_bge()?;
        assert!(!again_bge.removed);

        let gone_rr = uninstall_rerank()?;
        assert!(gone_rr.removed);
        assert!(!rerank.exists());

        match saved_bge {
            Some(v) => std::env::set_var("ONEMEMORY_MODEL_DIR", v),
            None => std::env::remove_var("ONEMEMORY_MODEL_DIR"),
        }
        match saved_rr {
            Some(v) => std::env::set_var("ONEMEMORY_RERANKER_DIR", v),
            None => std::env::remove_var("ONEMEMORY_RERANKER_DIR"),
        }
        Ok(())
    }
}
