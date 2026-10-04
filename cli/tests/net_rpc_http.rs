//! HTTP RPC against the hidden `rsrs --runtime-internal` host entry.
//! Isolated DATA_DIR + ephemeral port. Safe for GitHub Actions.
//! Do not bind the developer machine's default 15169.

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn pick_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    Ok(listener.local_addr().map_err(|err| err.to_string())?.port())
}

struct Runtime {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
    token: String,
    stderr_path: std::path::PathBuf,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_file(path: &std::path::Path, timeout: Duration) -> Result<String, String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(raw) = fs::read_to_string(path) {
            let trimmed = raw.trim().to_owned();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(format!("timed out waiting for {}", path.display()))
}

fn start_internal_runtime() -> Result<Runtime, String> {
    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    let port = pick_port()?;
    let stderr_path = dir.path().join("stderr.log");
    let stderr_file = fs::File::create(&stderr_path).map_err(|err| err.to_string())?;
    let mut child = Command::new(bin())
        .args([
            "--runtime-internal",
            "--no-open",
            "--port",
            &port.to_string(),
        ])
        .env("ONEMEMORY_DATA_DIR", dir.path())
        .env("ONEMEMORY_RPC_PORT", port.to_string())
        .env("ONEMEMORY_BIN_DIR", dir.path().join("bin"))
        .env_remove("ONEMEMORY_NO_AUTOSTART")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|err| err.to_string())?;
    let token_path = dir.path().join("runtime").join("token");
    let token = match wait_file(&token_path, Duration::from_secs(20)) {
        Ok(token) => token,
        Err(err) => {
            let mut extra = String::new();
            if let Ok(mut file) = fs::File::open(&stderr_path) {
                let _ = file.read_to_string(&mut extra);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{err}; stderr={extra}"));
        }
    };
    let health_url = format!("http://127.0.0.1:{port}/api/health");
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(20) {
        match ureq::get(&health_url)
            .set("Authorization", &format!("Bearer {token}"))
            .call()
        {
            Ok(resp) if resp.status() == 200 => {
                return Ok(Runtime {
                    child,
                    dir,
                    port,
                    token,
                    stderr_path,
                });
            }
            Ok(resp) => last = format!("status {}", resp.status()),
            Err(err) => last = err.to_string(),
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    Err(format!(
        "health not ready: {last}; stderr={}",
        fs::read_to_string(&stderr_path).unwrap_or_default()
    ))
}

#[test]
fn health_requires_bearer_and_reports_bin() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/health", rt.port);
    let denied = ureq::get(&url).call();
    match denied {
        Err(ureq::Error::Status(401, _)) => {}
        other => return Err(format!("expected 401 without token, got {other:?}")),
    }
    let ok = ureq::get(&url)
        .set("Authorization", &format!("Bearer {}", rt.token))
        .call()
        .map_err(|err| err.to_string())?;
    let body: serde_json::Value = ok.into_json().map_err(|err| err.to_string())?;
    if body["server"] != "respire" {
        return Err(format!("server {body}"));
    }
    if body["bin"] != env!("CARGO_PKG_VERSION") {
        return Err(format!("bin {body}"));
    }
    if body["pid"].as_u64().unwrap_or(0) == 0 {
        return Err(format!("pid {body}"));
    }
    let _ = rt.stderr_path.as_path();
    let _ = rt.dir.path();
    Ok(())
}

#[test]
fn rpc_cli_exec_status_returns_envelope() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/rpc", rt.port);
    let body = serde_json::json!({
        "v": 1,
        "id": "ci-status",
        "method": "cli.exec",
        "args": ["--json", "status"]
    });
    let resp = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", rt.token))
        .send_json(body)
        .map_err(|err| err.to_string())?;
    let parsed: serde_json::Value = resp.into_json().map_err(|err| err.to_string())?;
    if parsed["ok"] != true {
        return Err(format!("rpc {parsed}"));
    }
    if parsed["envelope"]["command"] != "status" {
        return Err(format!("envelope {parsed}"));
    }
    Ok(())
}

#[test]
fn parallel_status_requests_all_complete() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/rpc", rt.port);
    let token = rt.token.clone();
    let mut handles = Vec::new();
    for index in 0..8 {
        let url = url.clone();
        let token = token.clone();
        handles.push(thread::spawn(move || {
            let body = serde_json::json!({
                "v": 1,
                "id": format!("queue-{index}"),
                "method": "cli.exec",
                "args": ["--json", "status"]
            });
            let resp = ureq::post(&url)
                .set("Authorization", &format!("Bearer {token}"))
                .timeout(Duration::from_secs(20))
                .send_json(body)
                .map_err(|err| err.to_string())?;
            let parsed: serde_json::Value = resp.into_json().map_err(|err| err.to_string())?;
            if parsed["ok"] != true {
                return Err(format!("rpc {parsed}"));
            }
            if parsed["envelope"]["command"] != "status" {
                return Err(format!("envelope {parsed}"));
            }
            Ok(())
        }));
    }
    for handle in handles {
        handle.join().map_err(|_| "status worker panicked".to_string())??;
    }
    Ok(())
}

#[test]
fn stop_closes_listen_port() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/runtime/stop", rt.port);
    let _ = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", rt.token))
        .send_string("{}")
        .map_err(|err| err.to_string())?;
    let start = Instant::now();
    let addr = format!("127.0.0.1:{}", rt.port);
    while start.elapsed() < Duration::from_secs(12) {
        if std::net::TcpStream::connect(&addr).is_err() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("port still open after stop".into())
}
