//! Explicitly install the local BGE-M3 model (tokenizer.json + onnx/model_fp16.onnx).
//!
//! Does not touch the session or create a memory store. A failed download leaves
//! partial files outside the loader's paths. A model that already
//! verifies is not overwritten. A mirror only replaces the host.

use std::fs::{File, OpenOptions};
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
    let _operation = model_progress::Operation::begin_download()?;
    install_m3_inner(mirror)
}

/// Used by the runtime's reserved background operation after a source change.
pub fn prepare_m3_from_mirror(mirror: &str) -> Result<()> {
    install_m3_inner(Some(mirror)).map(|_| ())
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
    for path in candidates {
        if file_valid(&path.join("tokenizer.json"), TOKENIZER_SHA256)?
            && file_valid(&path.join("onnx/model_fp16.onnx"), ONNX_SHA256)? {
            return Ok(());
        }
    }
    install_m3_inner(None)?;
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
    // A pinned revision allows cancellation, restart and mirror changes to reuse
    // partial bytes without exposing an incomplete file to the model loader.
    let tmp = dest.join(format!(".download-{MODEL_REVISION}"));
    std::fs::create_dir_all(tmp.join("onnx"))?;
    let mut skipped = true;
    for (name, sha) in files {
        if file_valid(&dest.join(name), sha)? { continue; }
        if file_valid(&tmp.join(name), sha)? { skipped = false; continue; }
        let mut failures = Vec::new();
        let mut ready = false;
        for origin in &origins {
            model_progress::check()?;
            let url = file_url(origin, name);
            let partial = tmp.join(name);
            let result = if name.ends_with(".onnx") && !partial.exists() {
                download_parallel(&url, &partial, sha, 16 * 1024 * 1024)
                    .and_then(|used| if used { Ok(()) } else { download_verified(&url, &partial, sha) })
            } else { download_verified(&url, &partial, sha) };
            match result {
                Ok(()) => { ready = true; break; }
                Err(error) => {
                    model_progress::check()?;
                    // Disk failures must not be disguised as a mirror outage.
                    if error.downcast_ref::<std::io::Error>().is_some() { return Err(error); }
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
    std::fs::remove_dir_all(&tmp)?;
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

#[cfg(test)]
struct TmpGuard(PathBuf);


#[cfg(test)]
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
    let offset = if dest.is_file() { dest.metadata()?.len() } else { 0 };
    let resp = match download_response(url, dest, offset) {
        Ok(response) => response,
        Err(error) if offset > 0 && error.downcast_ref::<ureq::Error>().is_some_and(|error| matches!(error, ureq::Error::Status(416, _))) => {
            std::fs::remove_file(dest)?;
            download_response(url, dest, 0)?
        }
        Err(error) => return Err(error),
    };
    let resumed = resp.status() == 206;
    let total = if resumed {
        let range = resp.header("Content-Range").ok_or_else(|| anyhow!("partial response has no Content-Range"))?;
        let (start, total) = parse_content_range(range)?;
        anyhow::ensure!(start == offset, "partial response starts at {start}, expected {offset}");
        Some(total)
    } else {
        anyhow::ensure!(resp.status() == 200, "unexpected download status {}", resp.status());
        resp.header("Content-Length").and_then(|v| v.parse::<u64>().ok())
    };
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut reader = resp.into_reader();
    let mut file =
        OpenOptions::new().create(true).write(true).append(resumed).truncate(!resumed)
            .open(dest).with_context(|| format!("failed to write {}", dest.display()))?;
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = if resumed { offset } else { 0 };
    loop {
        model_progress::update("download", &item, written, total)?;
        let n = read_download(&mut reader, &mut buf, url)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])
            .with_context(|| format!("failed to write {}", dest.display()))?;
        written += n as u64;
    }
    file.flush()
        .with_context(|| format!("failed to write {}", dest.display()))?;
    drop(file);
    if let Some(total) = total {
        anyhow::ensure!(written == total, "download incomplete: {written}/{total} bytes; partial file retained");
    }
    model_progress::update("verify", &item, written, Some(written))?;
    let actual = sha256_file(dest)?;
    if !actual.eq_ignore_ascii_case(expected) {
        // Unknown-length EOF may be a truncated response. Preserve resumable bytes.
        if total.is_some() { let _ = std::fs::remove_file(dest); }
        anyhow::bail!(
            "checksum failed: {} SHA256={actual} (expected {expected})",
            dest.display()
        );
    }
    Ok(())
}

fn parse_content_range(value: &str) -> Result<(u64, u64)> {
    let value = value.strip_prefix("bytes ").ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (range, total) = value.split_once('/').ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let (start, end) = range.split_once('-').ok_or_else(|| anyhow!("invalid Content-Range"))?;
    let start = start.parse::<u64>()?;
    let end = end.parse::<u64>()?;
    let total = total.parse::<u64>()?;
    anyhow::ensure!(start <= end && end < total, "invalid Content-Range bounds");
    Ok((start, total))
}

/// Four persistent ranges. Only the coordinator updates task state; workers
/// receive cancellation through a shared flag and retain their partial files.
fn download_parallel(url: &str, dest: &Path, expected: &str, minimum: u64) -> Result<bool> {
    use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc};
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, 0, None)?;
    let response = download_agent().get(url).set("Accept-Encoding", "identity").set("Range", "bytes=0-0").call()
        .with_context(|| format!("download probe failed ({url})"))?;
    model_progress::check()?;
    if response.status() == 200 { return Ok(false); }
    anyhow::ensure!(response.status() == 206, "unexpected range probe status");
    let range = response.header("Content-Range").ok_or_else(|| anyhow!("range probe has no Content-Range"))?;
    let (start, total) = parse_content_range(range)?;
    anyhow::ensure!(start == 0, "range probe starts at {start}");
    drop(response);
    if total < minimum || total < 4 { return Ok(false); }
    let parts = dest.with_extension("onnx.parts");
    std::fs::create_dir_all(&parts)?;
    let counts: [AtomicU64; 4] = std::array::from_fn(|_| AtomicU64::new(0));
    let stop = AtomicBool::new(false);
    let (sender, receiver) = mpsc::channel();
    let result = std::thread::scope(|scope| -> Result<()> {
        for (index, count) in counts.iter().enumerate() {
            let begin = total * index as u64 / 4;
            let end = total * (index + 1) as u64 / 4;
            let path = parts.join(index.to_string());
            let sender = sender.clone();
            let stop = &stop;
            scope.spawn(move || {
                let result = download_part(url, &path, begin, end, total, count, stop);
                let failed = result.is_err();
                let _ = sender.send(result);
                if failed { stop.store(true, Ordering::Relaxed); }
            });
        }
        drop(sender);
        let mut finished = 0;
        let mut failure = None;
        while finished < 4 {
            let done = counts.iter().map(|count| count.load(Ordering::Relaxed)).sum();
            if let Err(error) = model_progress::update("download", &item, done, Some(total)) {
                stop.store(true, Ordering::Relaxed);
                if failure.is_none() { failure = Some(error); }
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => {
                    finished += 1;
                    if let Err(error) = result { if failure.is_none() { failure = Some(error); } }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("download workers disconnected"),
            }
        }
        if let Some(error) = failure { return Err(error); }
        Ok(())
    });
    result?;
    let mut merged = File::create(dest)?;
    for index in 0..4 {
        model_progress::check()?;
        std::io::copy(&mut File::open(parts.join(index.to_string()))?, &mut merged)?;
    }
    merged.flush()?;
    drop(merged);
    if !file_valid(dest, expected)? {
        std::fs::remove_file(dest)?;
        std::fs::remove_dir_all(&parts)?;
        anyhow::bail!("parallel download checksum failed; rejected all segments");
    }
    std::fs::remove_dir_all(parts)?;
    Ok(true)
}

fn download_part(url: &str, path: &Path, begin: u64, end: u64, total: u64,
    count: &std::sync::atomic::AtomicU64, stop: &std::sync::atomic::AtomicBool) -> Result<()> {
    use std::sync::atomic::Ordering;
    let length = end - begin;
    let mut offset = if path.is_file() { path.metadata()?.len() } else { 0 };
    anyhow::ensure!(offset <= length, "saved download segment is too long");
    count.store(offset, Ordering::Relaxed);
    if offset == length { return Ok(()); }
    anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
    let start = begin + offset;
    let response = download_agent().get(url).set("Accept-Encoding", "identity").set("Range", &format!("bytes={start}-{}", end - 1)).call()
        .with_context(|| format!("segment download failed ({url})"))?;
    anyhow::ensure!(response.status() == 206, "source did not honor the segment range");
    let expected_range = format!("bytes {start}-{}/{total}", end - 1);
    anyhow::ensure!(response.header("Content-Range") == Some(expected_range.as_str()), "source returned an incorrect segment range");
    let mut reader = response.into_reader();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    while offset < length {
        anyhow::ensure!(!stop.load(Ordering::Relaxed), "download segment stopped");
        let limit = buffer.len().min((length - offset) as usize);
        let received = reader.read(&mut buffer[..limit]).map_err(|error| anyhow!("segment interrupted ({url}): {error}"))?;
        anyhow::ensure!(received > 0, "segment download incomplete; partial bytes retained");
        file.write_all(&buffer[..received])?;
        offset += received as u64;
        count.store(offset, Ordering::Relaxed);
    }
    file.flush()?;
    Ok(())
}

fn download_agent() -> ureq::Agent {
    use std::time::Duration;
    ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30)).timeout_write(Duration::from_secs(10)).build()
}

fn download_response(url: &str, dest: &Path, offset: u64) -> Result<ureq::Response> {
    use std::time::Duration;
    let item = dest.file_name().unwrap_or_default().to_string_lossy();
    model_progress::update("connect", &item, offset, None)?;
    // Allow CDN body stalls while bounding cancellation latency to one 30-second read.
    let request = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(10))
        .build()
        .get(url).set("Accept-Encoding", "identity");
    let request = if offset > 0 { request.set("Range", &format!("bytes={offset}-")) } else { request };
    let response = request.call();
    model_progress::check()?;
    response.with_context(|| format!("download failed ({url})"))
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
    fn partial_download_resumes_across_sources_and_ignoring_range_restarts_safely() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let body = b"pinned model contents";
        let expected = hex::encode(Sha256::digest(body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial.bin");
        for supports_range in [true, false] {
            std::fs::write(&target, &body[..7])?;
            let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
            let url = format!("http://{}/model", server.server_addr());
            let worker = std::thread::spawn(move || -> Result<()> {
                let request = server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("download not requested"))?;
                assert!(request.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=7-"));
                let response = if supports_range {
                    tiny_http::Response::from_data(body[7..].to_vec()).with_status_code(206)
                        .with_header(tiny_http::Header::from_bytes("Content-Range", format!("bytes 7-{}/{}", body.len() - 1, body.len())).map_err(|_| anyhow!("invalid test header"))?)
                } else { tiny_http::Response::from_data(body.to_vec()) };
                request.respond(response)?;
                Ok(())
            });
            download_verified(&url, &target, &expected)?;
            worker.join().map_err(|_| anyhow!("server panicked"))??;
            assert_eq!(std::fs::read(&target)?, body);
        }
        assert!(parse_content_range("bytes 8-9/9").is_err());
        assert!(parse_content_range("bytes 8-7/10").is_err());
        Ok(())
    }

    #[test]
    fn four_parallel_ranges_resume_saved_segments_and_verify_the_merged_file() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let body: Vec<u8> = (0..128 * 1024).map(|index| (index % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&body));
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("model_fp16.onnx");
        let parts = target.with_extension("onnx.parts");
        std::fs::create_dir(&parts)?;
        for index in 0..4 {
            let begin = body.len() * index / 4;
            std::fs::write(parts.join(index.to_string()), &body[begin..begin + 3])?;
        }
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let source = body.clone();
        let worker = std::thread::spawn(move || -> Result<()> {
            let header = |value: String| tiny_http::Header::from_bytes("Content-Range", value).map_err(|_| anyhow!("invalid test header"));
            let probe = server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("probe missing"))?;
            probe.respond(tiny_http::Response::from_data(vec![source[0]]).with_status_code(206)
                .with_header(header(format!("bytes 0-0/{}", source.len()))?))?;
            // Hold all four responses until all requests arrive. A sequential
            // implementation times out here instead of passing this test.
            let mut requests = Vec::new();
            for _ in 0..4 {
                requests.push(server.recv_timeout(std::time::Duration::from_secs(10))?.ok_or_else(|| anyhow!("four concurrent requests did not arrive"))?);
            }
            for request in requests {
                let range = request.headers().iter().find(|header| header.field.equiv("Range"))
                    .ok_or_else(|| anyhow!("segment Range missing"))?.value.as_str();
                let (start, end) = range.strip_prefix("bytes=").and_then(|value| value.split_once('-')).ok_or_else(|| anyhow!("bad range"))?;
                let start = start.parse::<usize>()?;
                let end = end.parse::<usize>()?;
                assert_eq!(start % (source.len() / 4), 3);
                request.respond(tiny_http::Response::from_data(source[start..=end].to_vec()).with_status_code(206)
                    .with_header(header(format!("bytes {start}-{end}/{}", source.len()))?))?;
            }
            Ok(())
        });
        assert!(download_parallel(&url, &target, &expected, 0)?);
        worker.join().map_err(|_| anyhow!("source panicked"))??;
        assert_eq!(std::fs::read(target)?, body);
        assert!(!parts.exists());
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
    fn cancelling_a_download_releases_the_slot_and_restart_uses_the_new_source() -> Result<()> {
        use std::sync::mpsc;
        use std::time::Duration;
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let verified = dir.path().join("verified.bin");
        std::fs::write(&verified, b"keep verified file")?;
        let temporary = dir.path().join("partial");
        std::fs::create_dir(&temporary)?;
        let first = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let first_url = file_url(&format!("http://{}", first.server_addr()), "tokenizer.json");
        let (started, waiting) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let server = std::thread::spawn(move || -> Result<()> {
            let request = first.recv_timeout(Duration::from_secs(10))?.ok_or_else(|| anyhow!("first source was not used"))?;
            started.send(())?;
            resume.recv_timeout(Duration::from_secs(10))?;
            request.respond(tiny_http::Response::from_string("cancelled body"))?;
            Ok(())
        });
        let download_dir = temporary.clone();
        let download = std::thread::spawn(move || -> Result<()> {
            let _operation = model_progress::Operation::begin("connect")?;
            download_verified(&first_url, &download_dir.join("tokenizer.json"), "unused-on-cancel")
        });
        waiting.recv_timeout(Duration::from_secs(10))?;
        let status = model_progress::status()?;
        let id = status["id"].as_str().ok_or_else(|| anyhow!("task id missing"))?;
        assert_eq!(model_progress::control("stale-task", true)?["stale"], true);
        assert_eq!(model_progress::status()?["cancelled"], false);
        assert_eq!(model_progress::control(id, true)?["cancelled"], true);
        release.send(())?;
        server.join().map_err(|_| anyhow!("download server panicked"))??;
        let error = download.join().map_err(|_| anyhow!("download worker panicked"))?.err().ok_or_else(|| anyhow!("cancelled download succeeded"))?;
        assert!(matches!(error.downcast_ref::<model_progress::OperationStopped>(), Some(model_progress::OperationStopped::Cancelled)));
        assert_eq!(model_progress::status()?["active"], false);
        assert!(temporary.exists());
        assert_eq!(std::fs::read(&verified)?, b"keep verified file");
        let second = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let second_url = file_url(&format!("http://{}", second.server_addr()), "tokenizer.json");
        let server = std::thread::spawn(move || -> Result<()> {
            let request = second.recv_timeout(Duration::from_secs(10))?.ok_or_else(|| anyhow!("replacement source was not used"))?;
            assert!(request.url().contains(MODEL_REVISION));
            request.respond(tiny_http::Response::from_string("replacement body"))?;
            Ok(())
        });
        let _operation = model_progress::Operation::begin("connect")?;
        let expected = hex::encode(Sha256::digest(b"replacement body"));
        let target = dir.path().join("tokenizer.json");
        download_verified(&second_url, &target, &expected)?;
        server.join().map_err(|_| anyhow!("replacement server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"replacement body");
        assert_eq!(std::fs::read(verified)?, b"keep verified file");
        Ok(())
    }

    #[test]
    fn unknown_length_partial_is_retained_and_resumed_after_checksum_failure() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let target = dir.path().join("partial");
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| anyhow!("{error}"))?;
        let url = format!("http://{}/model", server.server_addr());
        let handler = std::thread::spawn(move || -> Result<()> {
            let request = server.recv()?;
            request.respond(tiny_http::Response::new(tiny_http::StatusCode(200), vec![],
                std::io::Cursor::new(b"abc"), None, None))?;
            let request = server.recv()?;
            assert!(request.headers().iter().any(|header| header.field.equiv("Range") && header.value.as_str() == "bytes=3-"));
            let range = tiny_http::Header::from_bytes("Content-Range", "bytes 3-5/6").map_err(|_| anyhow!("range header"))?;
            request.respond(tiny_http::Response::from_string("def").with_status_code(206).with_header(range))?;
            Ok(())
        });
        let expected = hex::encode(Sha256::digest(b"abcdef"));
        assert!(download_verified(&url, &target, &expected).is_err());
        assert_eq!(std::fs::read(&target)?, b"abc");
        download_verified(&url, &target, &expected)?;
        handler.join().map_err(|_| anyhow!("test server panicked"))??;
        assert_eq!(std::fs::read(target)?, b"abcdef");
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
