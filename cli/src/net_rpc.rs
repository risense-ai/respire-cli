//! Loopback HTTP client for the local runtime (`127.0.0.1:15169`).
//! Named pipes are not the product path. Token: `ONEMEMORY_RPC_TOKEN` then
//! `<data_dir>/runtime/token`.

use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use crate::runtime_error::RuntimeError;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 15169;
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const STOP_POLLS: usize = 40;
const STOP_WAIT: Duration = Duration::from_millis(250);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Health {
    pub server: String,
    pub bin: String,
    pub pid: u32,
    pub v: u32,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub data_dir: String,
}

pub fn rpc_port() -> u16 {
    if let Ok(raw) = std::env::var("ONEMEMORY_RPC_PORT") {
        let trimmed = raw.trim();
        if let Ok(port) = trimmed.parse::<u16>() {
            if port != 0 {
                return port;
            }
        }
    }
    DEFAULT_RPC_PORT
}

pub fn rpc_base_url() -> String {
    format!("http://{DEFAULT_RPC_HOST}:{}", rpc_port())
}

pub fn no_autostart() -> bool {
    crate::runtime_policy::client_only()
}

pub fn token_path() -> PathBuf {
    crate::rpc::runtime_dir_path().join("token")
}

#[cfg(test)]
fn load_token() -> Option<String> {
    read_token().ok().flatten()
}

fn read_token() -> Result<Option<String>> {
    if let Ok(raw) = std::env::var("ONEMEMORY_RPC_TOKEN") {
        let trimmed = raw.trim().to_owned();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed));
        }
    }
    if let Some(token) = read_token_file(&token_path())? {
        return Ok(Some(token));
    }
    read_token_file(
        &respire::service::data_dir()
            .join("runtime")
            .join("token"),
    )
}

fn read_token_file(path: &std::path::Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
        Ok(_) => Err(RuntimeError::TokenUnreadable(format!("{} is empty", path.display())).into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(RuntimeError::TokenUnreadable(format!("{}: {error}", path.display())).into())
        }
    }
}

fn require_token() -> Result<String> {
    read_token()?.ok_or_else(|| RuntimeError::TokenMissing.into())
}

fn check_connection() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], rpc_port()));
    // Windows may take slightly over two seconds to report loopback refusal.
    // A shorter deadline misclassifies a stopped service as a network timeout.
    match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Err(RuntimeError::Unavailable.into())
        }
        Err(error) => Err(RuntimeError::Transport(error.to_string()).into()),
    }
}

pub fn port_is_open() -> bool {
    port_is_open_on(rpc_port())
}

pub fn port_is_open_on(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

pub fn pid_listening_on(port: u16) -> Option<u32> {
    #[cfg(windows)]
    {
        let out = std::process::Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let needle = format!(":{}", port);
        for line in text.lines() {
            let line = line.trim();
            if !line.contains("LISTENING")
                || !line
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|address| address.ends_with(&needle))
            {
                continue;
            }
            let pid = line.split_whitespace().last()?.parse().ok()?;
            if pid != 0 {
                return Some(pid);
            }
        }
        None
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|line| line.trim().parse().ok())
    }
}

pub fn pid_is_respire(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    #[cfg(windows)]
    {
        let out = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output();
        let Ok(out) = out else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        text.contains("rsrs.exe")
    }
    #[cfg(unix)]
    {
        let out = std::process::Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output();
        let Ok(out) = out else {
            return false;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let name = text.trim();
        name == "rsrs" || name.ends_with("/rsrs")
    }
}

pub fn load_or_create_token() -> Result<String> {
    crate::runtime_policy::require_host("creating runtime credentials")?;
    if let Some(existing) = read_token()? {
        if std::env::var("ONEMEMORY_RPC_TOKEN").is_ok() {
            return Ok(existing);
        }
        return Ok(existing);
    }
    let generated = respire::memory::crypto::random_hex(32);
    persist_token(&generated)?;
    Ok(generated)
}

pub fn persist_token(token: &str) -> Result<()> {
    let path = token_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut file =
        fs::File::create(&path).with_context(|| format!("cannot write {}", path.display()))?;
    file.write_all(token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn origin_ok(origin: &str, bound_origin: &str) -> bool {
    let origin = origin.trim();
    if origin.is_empty() {
        return true;
    }
    let bound = bound_origin.trim_end_matches('/');
    origin == bound
        || origin == format!("http://{DEFAULT_RPC_HOST}:{}", rpc_port())
        || origin == format!("http://localhost:{}", rpc_port())
}

pub fn is_our_health(value: &Value) -> bool {
    value.get("server").and_then(|v| v.as_str()) == Some("respire")
        && value.get("bin").and_then(|v| v.as_str()).is_some()
}

pub fn version_cmp(ours: &str, theirs: &str) -> std::cmp::Ordering {
    fn nums(s: &str) -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .map(|p| p.parse().unwrap_or(0))
            .collect()
    }
    let a = nums(ours);
    let b = nums(theirs);
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(2))
        .timeout(HTTP_TIMEOUT)
        .build()
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

pub fn health() -> Result<Health> {
    check_connection()?;
    let token = require_token()?;
    let url = format!("{}/api/health", rpc_base_url());
    let resp = agent()
        .get(&url)
        .timeout(Duration::from_secs(2))
        .set("Authorization", &auth_header(&token))
        .call()
        .map_err(crate::runtime_error::http)?;
    let parsed: Value = resp.into_json().context("runtime health is not JSON")?;
    if !is_our_health(&parsed) {
        bail!("port is not a rsrs runtime");
    }
    serde_json::from_value(parsed).context("runtime health shape mismatch")
}

pub fn request_stop() -> Result<()> {
    crate::runtime_policy::require_host("runtime shutdown")?;
    let token = require_token()?;
    let url = format!("{}/api/runtime/stop", rpc_base_url());
    agent()
        .post(&url)
        .set("Authorization", &auth_header(&token))
        .send_string("{}")
        .map_err(crate::runtime_error::http)?;
    Ok(())
}

pub fn rpc_exec(args: Vec<String>) -> Result<Value> {
    rpc_method("cli.exec", args)
}

pub fn rpc_method(method: &str, args: Vec<String>) -> Result<Value> {
    check_connection()?;
    let token = require_token()?;
    let url = format!("{}/api/rpc", rpc_base_url());
    let body = json!({
        "v": crate::rpc::PROTOCOL_V,
        "id": uuid::Uuid::new_v4().to_string(),
        "method": method,
        "args": args,
    });
    // Downloading M3 or rebuilding a library can legitimately exceed the normal RPC budget.
    // Inference workers retain their own short deadlines; a request is never replayed here.
    let command: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|s| !s.starts_with('-'))
        .take(2)
        .collect();
    let timeout = if method == "model.control" {
        Duration::from_secs(3)
    } else if matches!(
        command.as_slice(),
        [
            "model",
            "install-m3" | "install-bge" | "install-rerank" | "activate"
        ]
    ) {
        Duration::from_secs(30 * 60)
    } else {
        HTTP_TIMEOUT
    };
    let resp = agent()
        .post(&url)
        .timeout(timeout)
        .set("Authorization", &auth_header(&token))
        .send_json(body)
        .map_err(crate::runtime_error::http)?;
    let parsed: Value = resp.into_json().context("runtime rpc is not JSON")?;
    Ok(parsed)
}

pub fn wait_until_down() -> Result<()> {
    for _ in 0..STOP_POLLS {
        if !port_is_open() {
            return Ok(());
        }
        std::thread::sleep(STOP_WAIT);
    }
    bail!("runtime did not exit after stop")
}

pub(crate) fn kill_pid(pid: u32) {
    if pid == 0 || pid == std::process::id() {
        return;
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
}

/// Used by tests and doctor: ensure the token file exists without starting HTTP.
pub fn ensure_token_file() -> Result<PathBuf> {
    let token = load_or_create_token()?;
    let _ = token;
    Ok(token_path())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_is_open_sees_local_listener() -> Result<(), String> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
        let port = listener.local_addr().map_err(|err| err.to_string())?.port();
        if !port_is_open_on(port) {
            return Err(format!("listener on {port} should be open"));
        }
        Ok(())
    }

    #[test]
    fn default_port_is_15169() -> Result<(), String> {
        if DEFAULT_RPC_PORT != 15169 {
            return Err(format!("port {}", DEFAULT_RPC_PORT));
        }
        Ok(())
    }

    #[test]
    fn rpc_port_reads_env() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var("ONEMEMORY_RPC_PORT").ok();
        std::env::set_var("ONEMEMORY_RPC_PORT", "26111");
        let got = rpc_port();
        match prev {
            Some(v) => std::env::set_var("ONEMEMORY_RPC_PORT", v),
            None => std::env::remove_var("ONEMEMORY_RPC_PORT"),
        }
        if got != 26111 {
            return Err(format!("got {got}"));
        }
        Ok(())
    }

    #[test]
    fn origin_empty_is_cli() -> Result<(), String> {
        if !origin_ok("", "http://127.0.0.1:15169") {
            return Err("empty origin should pass".into());
        }
        if origin_ok("https://evil.example", "http://127.0.0.1:15169") {
            return Err("evil origin should fail".into());
        }
        if !origin_ok("http://127.0.0.1:15169", "http://127.0.0.1:15169") {
            return Err("same origin should pass".into());
        }
        Ok(())
    }

    #[test]
    fn health_shape() -> Result<(), String> {
        let ours = json!({"server":"respire","bin":"1.0.6-dev.2","pid":1,"v":1,"exe":""});
        if !is_our_health(&ours) {
            return Err("ours".into());
        }
        if is_our_health(&json!({"server":"nginx"})) {
            return Err("nginx".into());
        }
        Ok(())
    }

    #[test]
    fn version_newer_dev() -> Result<(), String> {
        if version_cmp("1.0.6-dev.2", "1.0.6-dev.1") != std::cmp::Ordering::Greater {
            return Err("dev.2 should be newer".into());
        }
        if version_cmp("1.0.6-dev.1", "1.0.6-dev.1") != std::cmp::Ordering::Equal {
            return Err("equal".into());
        }
        Ok(())
    }

    #[test]
    fn token_env_beats_file() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let prev_data = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let prev_tok = std::env::var("ONEMEMORY_RPC_TOKEN").ok();
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        std::env::set_var("ONEMEMORY_RPC_TOKEN", "from-env");
        let got = load_token();
        match prev_data {
            Some(v) => std::env::set_var("ONEMEMORY_DATA_DIR", v),
            None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
        }
        match prev_tok {
            Some(v) => std::env::set_var("ONEMEMORY_RPC_TOKEN", v),
            None => std::env::remove_var("ONEMEMORY_RPC_TOKEN"),
        }
        if got.as_deref() != Some("from-env") {
            return Err(format!("{got:?}"));
        }
        Ok(())
    }

    #[test]
    fn persist_and_load_token_file() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let prev_data = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let prev_tok = std::env::var("ONEMEMORY_RPC_TOKEN").ok();
        std::env::remove_var("ONEMEMORY_RPC_TOKEN");
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        persist_token("file-token").map_err(|e| e.to_string())?;
        let got = load_token();
        match prev_data {
            Some(v) => std::env::set_var("ONEMEMORY_DATA_DIR", v),
            None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
        }
        match prev_tok {
            Some(v) => std::env::set_var("ONEMEMORY_RPC_TOKEN", v),
            None => std::env::remove_var("ONEMEMORY_RPC_TOKEN"),
        }
        if got.as_deref() != Some("file-token") {
            return Err(format!("{got:?}"));
        }
        Ok(())
    }
}
