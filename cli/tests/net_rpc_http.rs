//! HTTP RPC against the hidden `rsrs --runtime-internal` host entry.
//! Isolated DATA_DIR + ephemeral port. Safe for GitHub Actions.
//! Do not bind the developer machine's default 15169.

use std::fs;
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
    stderr_path: std::path::PathBuf,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_internal_runtime() -> Result<Runtime, String> {
    start_internal_runtime_with_mode("normal")
}

fn start_internal_runtime_with_mode(mode: &str) -> Result<Runtime, String> {
    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    fs::write(dir.path().join("client.json"), serde_json::json!({"service_mode":mode}).to_string())
        .map_err(|err| err.to_string())?;
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
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_RPC_PORT", port.to_string())
        .env("RSRS_BIN_DIR", dir.path().join("bin"))
        .env("RSRS_CORE_TEST_MODE", "1")
        .env("RSRS_NO_AUTOSYNC", "1")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_RPC_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|err| err.to_string())?;
    let health_url = format!("http://127.0.0.1:{port}/api/health");
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(20) {
        match ureq::get(&health_url).call() {
            Ok(resp) if resp.status() == 200 => {
                return Ok(Runtime {
                    child,
                    dir,
                    port,
                    stderr_path,
                });
            }
            Ok(resp) => last = format!("status {}", resp.status()),
            Err(err) => last = err.to_string(),
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(format!(
        "health not ready: {last}; stderr={}",
        fs::read_to_string(&stderr_path).unwrap_or_default()
    ))
}

#[test]
fn device_modes_gate_rpc_and_disabled_startup_never_opens_memory() -> Result<(), String> {
    let rt = start_internal_runtime_with_mode("off")?;
    let execute = |args: &[&str]| -> Result<serde_json::Value, String> {
        ureq::post(&format!("http://127.0.0.1:{}/api/rpc", rt.port))
            .timeout(Duration::from_secs(20))
            .send_json(serde_json::json!({"v":1,"id":uuid::Uuid::new_v4().to_string(),"method":"cli.exec","args":args}))
            .map_err(|err| err.to_string())?
            .into_json().map_err(|err| err.to_string())
    };
    for args in [vec!["--json", "recall", "synthetic query"], vec!["--json", "remember", "synthetic memory"],
        vec!["--json", "list"], vec!["--json", "sync"], vec!["--json", "doctor", "--fix"],
        vec!["--json", "migrate", "--source", "/missing-synthetic-library", "--account", "fixture"]] {
        let response = execute(&args)?;
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["envelope"]["summary"]["skipped"], true);
        assert_eq!(response["envelope"]["items"], serde_json::json!([]));
    }
    let status = execute(&["--json", "status"])?;
    assert_eq!(status["envelope"]["summary"]["workspace"], "off", "{status}");
    assert!(status["envelope"]["summary"]["local_total"].is_null());
    assert!(!rt.dir.path().join("rsrs.db").exists());
    assert!(!rt.dir.path().join("onememory.db").exists());
    let plain = Command::new(bin()).args(["--client-only", "recall", "synthetic query"])
        .env("RSRS_DATA_DIR", rt.dir.path()).env("RSRS_RPC_PORT", rt.port.to_string())
        .output().map_err(|err| err.to_string())?;
    assert!(plain.status.success(), "{}", String::from_utf8_lossy(&plain.stderr));
    assert!(plain.stdout.is_empty(), "disabled human output must be empty");
    let restore = execute(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    assert_eq!(restore["ok"], true, "{restore}");
    let normal = execute(&["--json", "agent-config", "--set", "workspace_mode=normal"])?;
    assert_eq!(normal["ok"], true, "{normal}");
    let initialized = execute(&["--json", "status"])?;
    assert_eq!(initialized["ok"], true, "{initialized}");
    assert!(rt.dir.path().join("rsrs.db").exists());
    let readonly = execute(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    assert_eq!(readonly["ok"], true, "{readonly}");
    for args in [vec!["--json", "remember", "synthetic memory"], vec!["--json", "sync"],
        vec!["--json", "sync-reset"], vec!["--json", "doctor", "--fix"],
        vec!["--json", "sync-conflicts", "--refresh"], vec!["--json", "sync-history", "--remote"],
        vec!["--json", "migrate", "--source", "/missing-synthetic-library", "--account", "fixture"]] {
        let response = execute(&args)?;
        assert_eq!(response["ok"], false, "read-only accepted {args:?}: {response}");
    }
    let normal = execute(&["--json", "agent-config", "--set", "workspace_mode=normal"])?;
    assert_eq!(normal["ok"], true, "{normal}");
    let status = execute(&["--json", "status"])?;
    assert_eq!(status["ok"], true, "{status}");
    assert_ne!(status["envelope"]["summary"]["workspace"], "off");
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&fs::read(rt.dir.path().join("client.json")).map_err(|err|err.to_string())?)
        .map_err(|err|err.to_string())?["service_mode"], "normal");
    Ok(())
}

#[test]
fn client_sends_existing_token_on_initial_health_and_rpc_requests() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("runtime"))?;
    fs::write(dir.path().join("runtime/token"), "synthetic-upgrade-token")?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = server.server_addr().to_ip().ok_or("no server port")?.port();
    let done = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&done);
    let worker = thread::spawn(move || -> Result<Vec<String>, String> {
        let mut paths = Vec::new();
        while !finished.load(Ordering::Acquire) {
            let Some(mut request) = server.recv_timeout(Duration::from_millis(100)).map_err(|error| error.to_string())? else { continue; };
            if !request.headers().iter().any(|header| header.field.equiv("Authorization") && header.value.as_str() == "Bearer synthetic-upgrade-token") {
                return Err("initial request omitted the existing runtime token".into());
            }
            paths.push(request.url().to_owned());
            let response = if request.url() == "/api/health" {
                serde_json::json!({"server":"respire","bin":"1.0.9","pid":1,"v":1})
            } else {
                let body: serde_json::Value = serde_json::from_reader(request.as_reader()).map_err(|error| error.to_string())?;
                serde_json::json!({"v":1,"id":body["id"],"ok":true,"exit":0,"bin":"1.0.9",
                    "envelope":{"command":"status","status":"ok","summary":{},"items":[],"actions":[],"errors":[],"details":null,"related":[]}})
            };
            request.respond(tiny_http::Response::from_string(response.to_string())).map_err(|error| error.to_string())?;
        }
        Ok(paths)
    });
    let output = Command::new(bin()).args(["--client-only", "status", "--json"])
        .env("RSRS_DATA_DIR", dir.path()).env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN").output()?;
    let health = Command::new(bin()).args(["--client-only", "--runtime-internal", "--status", "--json"])
        .env("RSRS_DATA_DIR", dir.path()).env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN").output()?;
    done.store(true, Ordering::Release);
    let paths = worker.join().map_err(|_| "HTTP fixture panicked")??;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    assert!(health.status.success(), "{}", String::from_utf8_lossy(&health.stdout));
    assert!(paths.iter().any(|path| path == "/api/health"));
    assert!(paths.iter().any(|path| path == "/api/rpc"));
    Ok(())
}

#[test]
fn client_only_rejects_stalled_inference_before_submitting_a_write() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = server.server_addr().to_ip().ok_or("no server port")?.port();
    let worker = thread::spawn(move || -> Result<String, String> {
        let request = server.recv_timeout(Duration::from_secs(10)).map_err(|error| error.to_string())?
            .ok_or("client did not inspect health")?;
        let path = request.url().to_owned();
        let body = serde_json::json!({"server":"respire","bin":env!("CARGO_PKG_VERSION"),"pid":1,"v":1,
            "inference":{"host_recovery_required":true}});
        request.respond(tiny_http::Response::from_string(body.to_string())).map_err(|error| error.to_string())?;
        Ok(path)
    });
    let output = Command::new(bin()).args(["--client-only","remember","synthetic pending write","--force","--json"])
        .env("RSRS_DATA_DIR",dir.path()).env("RSRS_RPC_PORT",port.to_string())
        .env_remove("RSRS_RPC_TOKEN").output()?;
    assert_eq!(worker.join().map_err(|_| "HTTP fixture panicked")??, "/api/health");
    assert!(!output.status.success());
    let message = format!("{}{}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
    assert!(message.contains("request was not submitted"), "{message}");
    assert!(!dir.path().join("onememory.db").exists(), "rejected client created a local store");
    Ok(())
}

#[test]
fn health_without_token_reports_bin() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/health", rt.port);
    if rt.dir.path().join("runtime").join("token").exists() {
        return Err("loopback runtime created a token file".into());
    }
    let ok = ureq::get(&url).call().map_err(|err| err.to_string())?;
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
    for path in ["/api/health", "/mcp", "/sse"] {
        for (header, value, error) in [
            ("Host", "example.invalid", "forbidden host"),
            ("Origin", "https://example.invalid", "forbidden origin"),
        ] {
            match ureq::get(&format!("http://127.0.0.1:{}{path}", rt.port))
                .set(header, value)
                .call()
            {
                Err(ureq::Error::Status(403, response)) => {
                    let denied: serde_json::Value =
                        response.into_json().map_err(|err| err.to_string())?;
                    if denied["error"] != error {
                        return Err(format!("unexpected {path} {header} rejection: {denied}"));
                    }
                }
                other => return Err(format!("expected 403 for {path} {header}, got {other:?}")),
            }
        }
    }
    let local = ureq::get(&url)
        .set("Host", &format!("localhost:{}", rt.port))
        .set("Authorization", "Bearer invalid-local-token")
        .call()
        .map_err(|err| err.to_string())?;
    if local.status() != 200 {
        return Err("loopback alias or ignored local token was rejected".into());
    }
    let endpoint = ureq::get(&format!("http://127.0.0.1:{}/mcp", rt.port))
        .set("Host", &format!("localhost:{}", rt.port))
        .call()
        .map_err(|err| err.to_string())?
        .into_string()
        .map_err(|err| err.to_string())?;
    if !endpoint.contains(&format!("http://127.0.0.1:{}/mcp", rt.port)) {
        return Err("MCP endpoint did not use the actual bound address".into());
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
        .send_json(body)
        .map_err(|err| err.to_string())?;
    let parsed: serde_json::Value = resp.into_json().map_err(|err| err.to_string())?;
    if parsed["ok"] != true {
        return Err(format!("rpc {parsed}"));
    }
    if parsed["envelope"]["command"] != "status" {
        return Err(format!("envelope {parsed}"));
    }
    // Existing host credentials remain usable; the new runtime ignores the header.
    fs::write(rt.dir.path().join("runtime").join("token"), "synthetic-old-runtime-token")
        .map_err(|err| err.to_string())?;
    let output = Command::new(bin())
        .args(["--client-only", "status", "--json"])
        .env("RSRS_DATA_DIR", rt.dir.path())
        .env("RSRS_RPC_PORT", rt.port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "client-only status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
    if envelope["command"] != "status" {
        return Err(format!("client-only envelope {envelope}"));
    }
    Ok(())
}

#[test]
fn parallel_status_requests_all_complete() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/rpc", rt.port);
    let mut handles = Vec::new();
    for index in 0..8 {
        let url = url.clone();
        handles.push(thread::spawn(move || {
            let body = serde_json::json!({
                "v": 1,
                "id": format!("queue-{index}"),
                "method": "cli.exec",
                "args": ["--json", "status"]
            });
            let resp = ureq::post(&url)
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
        handle
            .join()
            .map_err(|_| "status worker panicked".to_string())??;
    }
    Ok(())
}

#[test]
fn stop_closes_listen_port() -> Result<(), String> {
    let rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/runtime/stop", rt.port);
    let _ = ureq::post(&url)
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
