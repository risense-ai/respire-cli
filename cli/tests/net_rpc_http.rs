//! HTTP RPC against the official standalone `rsrs-runtime` fixture.
//! The CLI remains a client; neither fixture substitutes for Runtime G1 acceptance.
//! Isolated DATA_DIR + ephemeral port. Safe for GitHub Actions.
//! Do not bind the developer machine's default 15169.

use std::fs;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod support;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn runtime_bin() -> Result<std::path::PathBuf, String> {
    let runtime = std::env::var_os("RSRS_RUNTIME_BIN")
        .ok_or("supply RSRS_RUNTIME_BIN with the official standalone Runtime fixture")?;
    let runtime = std::path::PathBuf::from(runtime)
        .canonicalize()
        .map_err(|err| err.to_string())?;
    if runtime == std::path::Path::new(bin()).canonicalize().map_err(|err| err.to_string())? {
        return Err("CLI shim cannot substitute for the standalone Runtime fixture".into());
    }
    Ok(runtime)
}

fn pick_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    Ok(listener.local_addr().map_err(|err| err.to_string())?.port())
}

fn fixture_health(root: &std::path::Path) -> serde_json::Value {
    serde_json::json!({"server":"respire","bin":"http-fixture","pid":1,"v":1,
        "installation_root":root,"account_id":"fixture-account",
        "instance_id":"fixture-instance","generation":1})
}

fn check_fixture_operation(body: &serde_json::Value) -> Result<(), String> {
    if body["scope"] != serde_json::json!({"account_id":"fixture-account",
        "instance_id":"fixture-instance","generation":1})
        || body["operation_id"].as_str().is_none_or(str::is_empty)
        || body["operation_id"] != body["idempotency_key"]
        || body["operation_id"] == body["id"]
    {
        return Err(format!("unbound fixture request: {body}"));
    }
    Ok(())
}

struct Runtime {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
    stderr_path: std::path::PathBuf,
    identity: serde_json::Value,
}

impl Runtime {
    fn check_health(&self, health: &serde_json::Value) {
        for field in ["pid", "bin", "runtime_version", "installation_id", "installation_root",
            "account_id", "instance_id", "generation", "process_start_id", "image_path", "image_sha256"] {
            assert_eq!(health[field], self.identity[field], "Runtime identity changed: {field}");
        }
        assert_eq!(health["pid"], self.child.id());
    }

    fn rpc_body(&self, id: &str, args: &[&str]) -> serde_json::Value {
        let operation = uuid::Uuid::new_v4().to_string();
        serde_json::json!({"v":1,"id":id,"method":"cli.exec","args":args,
            "operation_id":operation,"idempotency_key":operation,
            "scope":{"account_id":self.identity["account_id"],
                "instance_id":self.identity["instance_id"],"generation":self.identity["generation"]}})
    }

    fn rpc(&self, id: &str, args: &[&str], timeout: Duration) -> Result<serde_json::Value, String> {
        let body = self.rpc_body(id, args);
        let reply: serde_json::Value = ureq::post(&format!("http://127.0.0.1:{}/api/rpc", self.port))
            .timeout(timeout).send_json(body.clone()).map_err(|err| err.to_string())?
            .into_json().map_err(|err| err.to_string())?;
        for field in ["id", "operation_id", "idempotency_key", "scope"] {
            assert_eq!(reply[field], body[field], "unbound RPC reply: {field}");
        }
        assert_ne!(reply["code"], "scope_required", "{reply}");
        assert_ne!(reply["code"], "scope_mismatch", "{reply}");
        assert_eq!(reply["pid"], self.identity["pid"]);
        assert_eq!(reply["bin"], self.identity["bin"]);
        Ok(reply)
    }

    fn verify_stop_receipt(&self, operation: Option<&str>) -> Result<(), String> {
        let instance = self.identity["instance_id"].as_str().ok_or("Runtime instance missing")?;
        let receipt = fs::read(self.dir.path().join("runtime").join(format!("stop-{instance}.json")))
            .map_err(|err| err.to_string())?;
        let receipt = serde_json::from_slice(&receipt).map_err(|err| err.to_string())?;
        let health = serde_json::from_value(self.identity.clone()).map_err(|err| err.to_string())?;
        respire_commands::net_rpc::validate_final_stop_receipt(&health, operation, &receipt)
            .map_err(|err| err.to_string())
    }

    fn stop(&self) -> Result<String, String> {
        let expected = serde_json::json!({"installation_id":self.identity["installation_id"],
            "account_id":self.identity["account_id"],"instance_id":self.identity["instance_id"],
            "generation":self.identity["generation"]});
        let receipt: serde_json::Value = ureq::post(&format!("http://127.0.0.1:{}/api/runtime/stop", self.port))
            .timeout(Duration::from_secs(2)).set("X-Respire-Lifecycle", "coordinator-v1")
            .send_json(expected).map_err(|err| err.to_string())?
            .into_json().map_err(|err| err.to_string())?;
        assert_eq!(receipt["ok"], true, "{receipt}");
        assert_eq!(receipt["state"], "accepted", "{receipt}");
        assert!(receipt["request_id"].as_str().is_some_and(|id| !id.is_empty()));
        receipt["operation_id"].as_str().filter(|id| !id.is_empty())
            .map(str::to_owned).ok_or_else(|| "stop operation ID missing".into())
    }
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
    start_internal_runtime_with_legacy_path(mode, false)
}

fn start_internal_runtime_with_legacy_path(
    mode: &str,
    legacy_path: bool,
) -> Result<Runtime, String> {
    start_runtime(mode, legacy_path)
}

fn start_scoped_runtime() -> Result<Runtime, String> {
    start_runtime("normal", false)
}

fn start_runtime(mode: &str, legacy_path: bool) -> Result<Runtime, String> {
    let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
    fs::write(
        dir.path().join("client.json"),
        serde_json::json!({"service_mode":mode}).to_string(),
    )
    .map_err(|err| err.to_string())?;
    if legacy_path {
        // A directory at the former socket path cannot be unlinked as a stale
        // socket or bound by the old listener. TCP startup must leave it alone.
        fs::create_dir_all(dir.path().join("runtime/rpc.sock")).map_err(|err| err.to_string())?;
        fs::write(
            dir.path().join("runtime/rpc.sock/owned-marker"),
            b"preserve",
        )
        .map_err(|err| err.to_string())?;
    }
    let port = pick_port()?;
    let stderr_path = dir.path().join("stderr.log");
    let stderr_file = fs::File::create(&stderr_path).map_err(|err| err.to_string())?;
    let runtime = runtime_bin()?;
    let version = Command::new(&runtime).arg("--version").output().map_err(|err| err.to_string())?;
    if !version.status.success() {
        return Err("standalone Runtime version query failed".into());
    }
    let version_text = String::from_utf8(version.stdout).map_err(|err| err.to_string())?;
    let version = version_text.trim().strip_prefix("rsrs-runtime ")
        .filter(|version| !version.is_empty()).ok_or("unexpected standalone Runtime version identity")?;
    use sha2::Digest;
    use std::io::Read;
    let mut image = fs::File::open(&runtime).map_err(|err| err.to_string())?;
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = image.read(&mut buffer).map_err(|err| err.to_string())?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    let image_sha256 = format!("{:x}", digest.finalize());
    let mut child = Command::new(&runtime)
        .arg("serve")
        .args(["--port", &port.to_string()])
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
                let identity = match resp.into_json::<serde_json::Value>() {
                    Ok(identity) => identity,
                    Err(err) => { last = err.to_string(); continue; }
                };
                let rt = Runtime { child, dir, port, stderr_path, identity };
                let health = &rt.identity;
                if health["server"] != "respire" || health["v"] != 1
                    || health["pid"] != rt.child.id() || health["bin"] != version
                    || health["runtime_version"] != version || health["image_sha256"] != image_sha256
                    || health["generation"].as_u64().is_none_or(|generation| generation == 0)
                    || ["installation_id", "account_id", "instance_id", "process_start_id"].iter()
                        .any(|field| health[*field].as_str().is_none_or(str::is_empty))
                {
                    return Err("standalone Runtime health identity does not match the owned fixture".into());
                }
                for field in ["exe", "image_path"] {
                    let path = health[field].as_str().ok_or("Runtime image path missing")?;
                    assert_eq!(fs::canonicalize(path).map_err(|err| err.to_string())?, runtime);
                }
                let root = health["installation_root"].as_str().ok_or("Runtime installation root missing")?;
                assert_eq!(fs::canonicalize(root).map_err(|err| err.to_string())?,
                    fs::canonicalize(rt.dir.path()).map_err(|err| err.to_string())?);
                return Ok(rt);
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
fn runtime_uses_only_tcp_and_preserves_owner() -> Result<(), String> {
    let mut rt = start_runtime("normal", true)?;
    let health = || -> Result<serde_json::Value, String> {
        ureq::get(&format!("http://127.0.0.1:{}/api/health", rt.port))
            .timeout(Duration::from_secs(3))
            .call()
            .map_err(|err| err.to_string())?
            .into_json()
            .map_err(|err| err.to_string())
    };
    let owner = health()?["pid"].as_u64().ok_or("runtime pid missing")?;
    assert_eq!(owner, u64::from(rt.child.id()));
    assert_eq!(
        fs::read(rt.dir.path().join("runtime/rpc.sock/owned-marker"))
            .map_err(|err| err.to_string())?,
        b"preserve"
    );
    // Starting another host for the same profile must retain the TCP owner.
    let mut duplicate = Command::new(runtime_bin()?)
        .args([
            "serve",
            "--port",
            &rt.port.to_string(),
        ])
        .env("RSRS_DATA_DIR", rt.dir.path())
        .env("RSRS_RPC_PORT", rt.port.to_string())
        .env("RSRS_CORE_TEST_MODE", "1")
        .env("RSRS_NO_AUTOSYNC", "1")
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| err.to_string())?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = duplicate.try_wait().map_err(|err| err.to_string())? {
            break status;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = duplicate.kill();
            let _ = duplicate.wait();
            return Err("duplicate runtime did not return to its existing owner".into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    assert!(status.success());
    assert_eq!(health()?["pid"].as_u64(), Some(owner));
    // A different port must not bypass installation ownership. In particular,
    // do not publish a healthy second host whose dispatcher is still locked.
    let endpoint =
        fs::read(rt.dir.path().join("runtime/endpoint.json")).map_err(|err| err.to_string())?;
    let original_config =
        fs::read(rt.dir.path().join("client.json")).map_err(|err| err.to_string())?;
    for alternate_profile in [false, true] {
        if alternate_profile {
            // The endpoint belongs to the installation root, while its library
            // lock belongs to the selected account. Both ownership scopes matter.
            let alternate = rt.dir.path().join("accounts/other");
            fs::create_dir_all(&alternate).map_err(|err| err.to_string())?;
            let mut config: serde_json::Value =
                serde_json::from_slice(&original_config).map_err(|err| err.to_string())?;
            config["data_dir"] = serde_json::json!(alternate);
            fs::write(rt.dir.path().join("client.json"), config.to_string())
                .map_err(|err| err.to_string())?;
        }
        let other_port = pick_port()?;
        let mut other = Command::new(runtime_bin()?)
            .args([
                "serve",
                "--port",
                &other_port.to_string(),
            ])
            .env("RSRS_DATA_DIR", rt.dir.path())
            .env("RSRS_RPC_PORT", other_port.to_string())
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_NO_AUTOSYNC", "1")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|err| err.to_string())?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = other.try_wait().map_err(|err| err.to_string())? {
                break status;
            }
            // Windows connection refusal can block for seconds and consume the startup deadline.
            if std::net::TcpStream::connect_timeout(
                &std::net::SocketAddr::from(([127, 0, 0, 1], other_port)),
                Duration::from_millis(50),
            )
            .is_ok()
                || started.elapsed() > Duration::from_secs(20)
            {
                let _ = other.kill();
                let _ = other.wait();
                return Err(
                    "another port bypassed runtime ownership or did not reject startup".into(),
                );
            }
            thread::sleep(Duration::from_millis(25));
        };
        assert!(!status.success());
        assert_eq!(
            fs::read(rt.dir.path().join("runtime/endpoint.json")).map_err(|err| err.to_string())?,
            endpoint
        );
        fs::write(rt.dir.path().join("client.json"), &original_config)
            .map_err(|err| err.to_string())?;
        assert_eq!(health()?["pid"].as_u64(), Some(owner));
    }
    rt.check_health(&health()?);
    let response = rt.rpc("tcp-only-status", &["status", "--json"], Duration::from_secs(10))?;
    assert_eq!(response["ok"], true, "{response}");
    let stop = Command::new(bin())
        .args(["--runtime-internal", "--stop", "--json"])
        .env("RSRS_DATA_DIR", rt.dir.path())
        .env("RSRS_RPC_PORT", rt.port.to_string())
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .output()
        .map_err(|err| err.to_string())?;
    assert!(
        stop.status.success(),
        "{} {}",
        String::from_utf8_lossy(&stop.stdout),
        String::from_utf8_lossy(&stop.stderr)
    );
    let started = Instant::now();
    while rt
        .child
        .try_wait()
        .map_err(|err| err.to_string())?
        .is_none()
    {
        if started.elapsed() > Duration::from_secs(10) {
            return Err("TCP runtime did not stop".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(std::net::TcpStream::connect(("127.0.0.1", rt.port)).is_err());
    assert_eq!(
        fs::read(rt.dir.path().join("runtime/rpc.sock/owned-marker"))
            .map_err(|err| err.to_string())?,
        b"preserve"
    );
    Ok(())
}

#[test]
fn device_modes_gate_rpc_and_disabled_startup_never_opens_memory() -> Result<(), String> {
    let rt = start_internal_runtime_with_mode("off")?;
    let execute = |args: &[&str]| {
        rt.rpc(&uuid::Uuid::new_v4().to_string(), args, Duration::from_secs(20))
    };
    for args in [
        vec!["--json", "recall", "synthetic query"],
        vec!["--json", "remember", "synthetic memory"],
        vec!["--json", "list"],
        vec!["--json", "sync"],
        vec!["--json", "doctor", "--fix"],
        vec![
            "--json",
            "migrate",
            "--source",
            "/missing-synthetic-library",
            "--account",
            "fixture",
        ],
    ] {
        let response = execute(&args)?;
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["envelope"]["summary"]["skipped"], true);
        assert_eq!(response["envelope"]["items"], serde_json::json!([]));
    }
    let status = execute(&["--json", "status"])?;
    assert_eq!(
        status["envelope"]["summary"]["workspace"], "off",
        "{status}"
    );
    assert!(status["envelope"]["summary"]["local_total"].is_null());
    assert!(!rt.dir.path().join("rsrs.db").exists());
    assert!(!rt.dir.path().join("onememory.db").exists());
    let config = execute(&["--json", "agent-config"])?;
    assert_eq!(
        config["envelope"]["summary"]["memory_off"], true,
        "{config}"
    );
    assert_eq!(config["envelope"]["summary"]["workspace_mode"], "off");
    let plain = Command::new(bin())
        .args(["--client-only", "recall", "synthetic query"])
        .env("RSRS_DATA_DIR", rt.dir.path())
        .env("RSRS_RPC_PORT", rt.port.to_string())
        .output()
        .map_err(|err| err.to_string())?;
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(
        plain.stdout.is_empty(),
        "disabled human output must be empty"
    );
    let restore = execute(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    assert_eq!(restore["ok"], true, "{restore}");
    let normal = execute(&["--json", "agent-config", "--set", "workspace_mode=normal"])?;
    assert_eq!(normal["ok"], true, "{normal}");
    let initialized = execute(&["--json", "status"])?;
    assert_eq!(initialized["ok"], true, "{initialized}");
    assert!(rt.dir.path().join("rsrs.db").exists());
    let readonly = execute(&["--json", "agent-config", "--set", "workspace_mode=readonly"])?;
    assert_eq!(readonly["ok"], true, "{readonly}");
    let config = execute(&["--json", "agent-config"])?;
    assert_eq!(config["envelope"]["summary"]["readonly"], true, "{config}");
    for args in [
        vec!["--json", "remember", "synthetic memory"],
        vec!["--json", "sync"],
        vec!["--json", "sync-reset"],
        vec!["--json", "doctor", "--fix"],
        vec!["--json", "sync-conflicts", "--refresh"],
        vec!["--json", "sync-history", "--remote"],
        vec![
            "--json",
            "migrate",
            "--source",
            "/missing-synthetic-library",
            "--account",
            "fixture",
        ],
    ] {
        let response = execute(&args)?;
        assert_eq!(
            response["ok"], false,
            "read-only accepted {args:?}: {response}"
        );
    }
    let normal = execute(&["--json", "agent-config", "--set", "workspace_mode=normal"])?;
    assert_eq!(normal["ok"], true, "{normal}");
    let status = execute(&["--json", "status"])?;
    assert_eq!(status["ok"], true, "{status}");
    assert_ne!(status["envelope"]["summary"]["workspace"], "off");
    let config = execute(&["--json", "agent-config"])?;
    assert_eq!(config["envelope"]["summary"]["readonly"], false, "{config}");
    assert_eq!(config["envelope"]["summary"]["memory_off"], false);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(rt.dir.path().join("client.json")).map_err(|err| err.to_string())?
        )
        .map_err(|err| err.to_string())?["service_mode"],
        "normal"
    );
    Ok(())
}

#[test]
fn client_sends_existing_token_on_initial_health_and_rpc_requests(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("runtime"))?;
    fs::write(dir.path().join("runtime/token"), "synthetic-upgrade-token")?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = server.server_addr().to_ip().ok_or("no server port")?.port();
    let done = Arc::new(AtomicBool::new(false));
    let finished = Arc::clone(&done);
    let health_body = fixture_health(dir.path());
    let worker = thread::spawn(move || -> Result<Vec<String>, String> {
        let mut paths = Vec::new();
        while !finished.load(Ordering::Acquire) {
            let Some(mut request) = server
                .recv_timeout(Duration::from_millis(100))
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            if !request.headers().iter().any(|header| {
                header.field.equiv("Authorization")
                    && header.value.as_str() == "Bearer synthetic-upgrade-token"
            }) {
                return Err("initial request omitted the existing runtime token".into());
            }
            paths.push(request.url().to_owned());
            let response = if request.url() == "/api/health" {
                health_body.clone()
            } else {
                let body: serde_json::Value = serde_json::from_reader(request.as_reader())
                    .map_err(|error| error.to_string())?;
                if body["method"] == "cli.exec" {
                    check_fixture_operation(&body)?;
                }
                serde_json::json!({"v":1,"id":body["id"],"ok":true,"exit":0,"bin":"http-fixture",
                    "operation_id":body["operation_id"],"idempotency_key":body["idempotency_key"],"scope":body["scope"],
                    "envelope":{"command":"status","status":"ok","summary":{},"items":[],"actions":[],"errors":[],"details":null,"related":[]}})
            };
            request
                .respond(tiny_http::Response::from_string(response.to_string()))
                .map_err(|error| error.to_string())?;
        }
        Ok(paths)
    });
    let output = Command::new(bin())
        .args(["--client-only", "status", "--json"])
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    let health = Command::new(bin())
        .args(["--client-only", "--runtime-internal", "--status", "--json"])
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    done.store(true, Ordering::Release);
    let paths = worker.join().map_err(|_| "HTTP fixture panicked")??;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        health.status.success(),
        "{}",
        String::from_utf8_lossy(&health.stdout)
    );
    assert!(paths.iter().any(|path| path == "/api/health"));
    assert!(paths.iter().any(|path| path == "/api/rpc"));
    Ok(())
}

/// Legacy display envelopes still normalize under the current scoped transport.
#[test]
fn client_normalizes_legacy_failure_envelopes_and_preserves_remote_semantics(
) -> Result<(), Box<dyn std::error::Error>> {
    for (status, exit, reason, errors) in [
        ("fail", 1, "legacy_missing", serde_json::json!([])),
        (
            "fail",
            2,
            "invalid_input",
            serde_json::json!(["original remote diagnostic"]),
        ),
        ("pending", 2, "decision_required", serde_json::json!([])),
    ] {
        let dir = tempfile::tempdir()?;
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
        let port = server
            .server_addr()
            .to_ip()
            .ok_or("no fixture port")?
            .port();
        let original_errors = errors.clone();
        let health_body = fixture_health(dir.path());
        let worker = thread::spawn(move || -> Result<(), String> {
            let mut request = loop {
                let request = server
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|error| error.to_string())?
                    .ok_or("legacy fixture received no request")?;
                if request.url() != "/api/health" {
                    break request;
                }
                request.respond(tiny_http::Response::from_string(health_body.to_string()))
                    .map_err(|error| error.to_string())?;
            };
            if request.url() != "/api/rpc" {
                return Err("unexpected legacy fixture request".into());
            }
            let body: serde_json::Value =
                serde_json::from_reader(request.as_reader()).map_err(|error| error.to_string())?;
            if body["method"] != "cli.exec" {
                return Err("unexpected legacy fixture method".into());
            }
            check_fixture_operation(&body)?;
            let response = serde_json::json!({"v":1,"id":body["id"],"ok":exit==0,"exit":exit,"bin":"http-fixture",
                "operation_id":body["operation_id"],"idempotency_key":body["idempotency_key"],"scope":body["scope"],
                "envelope":{"command":"show","status":status,"summary":{"reason":reason},
                    "items":[{"name":"entry","status":"fail","value":"not found"}],
                    "actions":[],"errors":errors,"details":{"error_type":"legacy_fixture"},"related":[]}});
            request
                .respond(tiny_http::Response::from_string(response.to_string()))
                .map_err(|error| error.to_string())
        });
        let output = Command::new(bin())
            .args(["--client-only", "show", "synthetic-missing", "--json"])
            .env("RSRS_DATA_DIR", dir.path())
            .env("RSRS_RPC_PORT", port.to_string())
            .env_remove("RSRS_RPC_TOKEN")
            .output()?;
        worker.join().map_err(|_| "legacy fixture panicked")??;
        assert_eq!(output.status.code(), Some(exit));
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(envelope["status"], status);
        assert_eq!(envelope["summary"]["reason"], reason);
        assert_eq!(envelope["details"]["error_type"], "legacy_fixture");
        if status == "fail" && original_errors == serde_json::json!([]) {
            assert_eq!(envelope["errors"], serde_json::json!(["entry: not found"]));
        } else {
            assert_eq!(envelope["errors"], original_errors);
        }
    }
    Ok(())
}

#[test]
fn client_only_rejects_stalled_inference_before_submitting_a_write(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = server.server_addr().to_ip().ok_or("no server port")?.port();
    let worker = thread::spawn(move || -> Result<String, String> {
        let request = server
            .recv_timeout(Duration::from_secs(10))
            .map_err(|error| error.to_string())?
            .ok_or("client did not inspect health")?;
        let path = request.url().to_owned();
        let body = serde_json::json!({"server":"respire","bin":env!("CARGO_PKG_VERSION"),"pid":1,"v":1,
            "inference":{"host_recovery_required":true}});
        request
            .respond(tiny_http::Response::from_string(body.to_string()))
            .map_err(|error| error.to_string())?;
        Ok(path)
    });
    let output = Command::new(bin())
        .args([
            "--client-only",
            "remember",
            "synthetic pending write",
            "--force",
            "--json",
        ])
        .env("RSRS_DATA_DIR", dir.path())
        .env("RSRS_RPC_PORT", port.to_string())
        .env_remove("RSRS_RPC_TOKEN")
        .output()?;
    assert_eq!(
        worker.join().map_err(|_| "HTTP fixture panicked")??,
        "/api/health"
    );
    assert!(!output.status.success());
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(message.contains("request was not submitted"), "{message}");
    assert!(
        !dir.path().join("onememory.db").exists(),
        "rejected client created a local store"
    );
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
    rt.check_health(&body);
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
    let rt = start_scoped_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/rpc", rt.port);
    for code in ["scope_required", "scope_mismatch"] {
        let mut invalid = rt.rpc_body(code, &["--json", "status"]);
        if code == "scope_required" {
            invalid["scope"] = serde_json::Value::Null;
        } else {
            invalid["scope"]["instance_id"] = serde_json::json!("foreign-runtime-instance");
        }
        let rejected: serde_json::Value = ureq::post(&url)
            .send_json(invalid.clone()).map_err(|err| err.to_string())?
            .into_json().map_err(|err| err.to_string())?;
        assert_eq!(rejected["ok"], false, "{rejected}");
        assert_eq!(rejected["code"], code, "{rejected}");
        assert_eq!(rejected["id"], invalid["id"]);
        assert_eq!(rejected["pid"], rt.identity["pid"]);
    }
    let body = rt.rpc_body("ci-status", &["--json", "status"]);
    let resp = ureq::post(&format!("http://127.0.0.1:{}/api/rpc", rt.port))
        .send_json(body.clone()).map_err(|err| err.to_string())?;
    let parsed: serde_json::Value = resp.into_json().map_err(|err| err.to_string())?;
    if parsed["ok"] != true {
        return Err(format!("rpc {parsed}"));
    }
    assert_eq!(parsed["id"], body["id"]);
    assert_eq!(parsed["operation_id"], body["operation_id"]);
    assert_eq!(parsed["idempotency_key"], body["idempotency_key"]);
    assert_eq!(parsed["scope"], body["scope"]);
    if parsed["envelope"]["command"] != "status" {
        return Err(format!("envelope {parsed}"));
    }
    // Existing host credentials remain usable; the new runtime ignores the header.
    fs::write(
        rt.dir.path().join("runtime").join("token"),
        "synthetic-old-runtime-token",
    )
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
            "client-only status failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
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
        let body = rt.rpc_body(&format!("queue-{index}"), &["--json", "status"]);
        handles.push(thread::spawn(move || {

            let resp = ureq::post(&url)
                .timeout(Duration::from_secs(20))
                .send_json(body.clone())
                .map_err(|err| err.to_string())?;
            let parsed: serde_json::Value = resp.into_json().map_err(|err| err.to_string())?;
            for field in ["id", "operation_id", "idempotency_key", "scope"] {
                assert_eq!(parsed[field], body[field], "unbound parallel reply: {field}");
            }
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
    let mut rt = start_internal_runtime()?;
    let url = format!("http://127.0.0.1:{}/api/runtime/stop", rt.port);
    let mut foreign = serde_json::json!({"installation_id":rt.identity["installation_id"],
        "account_id":rt.identity["account_id"],"instance_id":rt.identity["instance_id"],
        "generation":rt.identity["generation"]});
    foreign["instance_id"] = serde_json::json!("foreign-runtime-instance");
    for invalid in [serde_json::json!({}), foreign] {
        match ureq::post(&url).set("X-Respire-Lifecycle", "coordinator-v1").send_json(invalid) {
            Err(ureq::Error::Status(409, response)) => {
                let rejected: serde_json::Value = response.into_json().map_err(|err| err.to_string())?;
                assert_eq!(rejected["error"], "stop_identity_mismatch");
            }
            other => return Err(format!("unbound stop was not rejected: {other:?}")),
        }
        let health: serde_json::Value = ureq::get(&format!("http://127.0.0.1:{}/api/health", rt.port))
            .call().map_err(|err| err.to_string())?.into_json().map_err(|err| err.to_string())?;
        rt.check_health(&health);
        assert!(rt.child.try_wait().map_err(|err| err.to_string())?.is_none());
    }
    let operation = rt.stop()?;
    let start = Instant::now();
    let addr = format!("127.0.0.1:{}", rt.port);
    while start.elapsed() < Duration::from_secs(12) {
        if rt.child.try_wait().map_err(|err| err.to_string())?.is_some()
            && std::net::TcpStream::connect(&addr).is_err() {
            return rt.verify_stop_receipt(Some(&operation));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("runtime process or listen port remained after stop".into())
}

#[test]
fn incomplete_control_body_does_not_block_health_rpc_or_stop(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut rt = start_internal_runtime()?;
    let mut incomplete = std::net::TcpStream::connect(("127.0.0.1", rt.port))?;
    write!(
        incomplete,
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: 4096\r\n\r\nx",
        rt.port
    )?;
    thread::sleep(Duration::from_millis(100));
    let base = format!("http://127.0.0.1:{}", rt.port);
    let health: serde_json::Value = ureq::get(&format!("{base}/api/health"))
        .timeout(Duration::from_secs(2))
        .call()?
        .into_json()?;
    rt.check_health(&health);
    let reply = rt.rpc("incomplete-body-next", &["--json", "status"], Duration::from_secs(2))?;
    assert_eq!(reply["ok"], true, "{reply}");
    let operation = rt.stop()?;
    let until = Instant::now() + Duration::from_secs(12);
    while rt.child.try_wait()?.is_none() {
        assert!(
            Instant::now() < until,
            "owned runtime did not stop with incomplete peer connected"
        );
        thread::sleep(Duration::from_millis(50));
    }
    assert!(std::net::TcpStream::connect(("127.0.0.1", rt.port)).is_err());
    rt.verify_stop_receipt(Some(&operation))?;
    Ok(())
}

#[test]
fn non_reading_peer_and_pipelined_responses_do_not_block_other_connections(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{Read, Write};
    let rt = start_internal_runtime()?;
    let mut stalled = std::net::TcpStream::connect(("127.0.0.1", rt.port))?;
    stalled.set_write_timeout(Some(Duration::from_secs(5)))?;
    let body = serde_json::json!({"v":1,"id":"non-reading-peer","method":"x".repeat(8*1024*1024),"args":[]}).to_string();
    write!(stalled, "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", rt.port, body.len(), body)?;
    // Queue a control request behind the large response on the same connection.
    write!(
        stalled,
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        rt.port
    )?;
    thread::sleep(Duration::from_millis(250));
    let base = format!("http://127.0.0.1:{}", rt.port);
    for _ in 0..3 {
        let health: serde_json::Value = ureq::get(&format!("{base}/api/health"))
            .timeout(Duration::from_secs(2))
            .call()?
            .into_json()?;
        rt.check_health(&health);
    }
    let reply = rt.rpc("non-reading-next", &["--json", "status"], Duration::from_secs(2))?;
    assert_eq!(reply["ok"], true, "{reply}");
    drop(stalled);
    let mut pipeline = std::net::TcpStream::connect(("127.0.0.1", rt.port))?;
    pipeline.set_read_timeout(Some(Duration::from_secs(5)))?;
    for (id, deadline) in [("pipeline-a", None), ("pipeline-b", Some(0u64))] {
        let mut body = rt.rpc_body(id, &["--json", "status"]);
        if let Some(deadline) = deadline {
            body["queue_wait_ms"] = serde_json::json!(deadline);
        }
        let body = body.to_string();
        write!(pipeline, "POST /api/rpc HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", rt.port, body.len(), body)?;
    }
    write!(
        pipeline,
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        rt.port
    )?;
    let mut wire = String::new();
    pipeline.read_to_string(&mut wire)?;
    let first = wire
        .find("\"id\":\"pipeline-a\"")
        .ok_or("first pipeline reply missing")?;
    let second = wire
        .find("\"id\":\"pipeline-b\"")
        .ok_or("second pipeline reply missing")?;
    assert!(first < second, "responses were reordered");
    assert!(
        wire.contains("command was not started"),
        "zero-deadline pipeline write/read was executed: {wire}"
    );
    assert!(
        wire[second..].contains("\"server\":\"respire\""),
        "pipelined health reply missing"
    );
    Ok(())
}

#[test]
fn rpc_memory_revision_is_read_only_and_model_free() -> Result<(), String> {
    let rt = start_scoped_runtime()?;
    support::install_runtime_fixture(rt.dir.path()).map_err(|err| format!("{err:#}"))?;
    let mut baseline = None;
    for args in [
        vec!["memory-revision", "--json"],
        vec!["--client-only", "memory-revision", "--json"],
        vec!["memory-revision"],
    ] {
        let output = Command::new(bin())
            .args(args)
            .env("RSRS_DATA_DIR", rt.dir.path())
            .env("RSRS_RPC_PORT", rt.port.to_string())
            .env_remove("RSRS_RPC_TOKEN")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_RUNTIME_BIN")
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .env("RSRS_JSON", "1")
            .output()
            .map_err(|err| err.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "revision failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).map_err(|err| err.to_string())?;
        assert_eq!(envelope["command"], "memory-revision");
        assert_eq!(envelope["status"], "ok");
        assert_eq!(
            envelope["summary"]["profile"],
            rt.dir.path().to_string_lossy().as_ref()
        );
        assert_eq!(
            envelope["summary"]["revision"].as_str().unwrap_or("").len(),
            32
        );
        if let Some(expected) = &baseline {
            assert_eq!(&envelope["summary"], expected);
        } else {
            baseline = Some(envelope["summary"].clone());
        }
    }
    assert!(!rt.dir.path().join("session.json").exists());
    assert!(!rt.dir.path().join("model").exists());
    Ok(())
}

#[test]
fn rpc_memory_revision_does_not_initialize_after_off_start(
) -> Result<(), Box<dyn std::error::Error>> {
    let rt = start_internal_runtime_with_mode("off")?;
    let db = rt.dir.path().join("rsrs.db");
    assert!(!db.exists());
    fs::write(
        rt.dir.path().join("client.json"),
        r#"{"service_mode":"normal"}"#,
    )?;
    for index in 0..3 {
        let reply = rt.rpc(&format!("revision-off-start-{index}"), &["--json", "memory-revision"], Duration::from_secs(3))?;
        assert_eq!(
            reply["ok"], false,
            "probe created an absent library: {reply}"
        );
        assert!(!db.exists());
        assert!(!rt.dir.path().join("onememory.db").exists());
        assert!(!rt.dir.path().join("session.json").exists());
    }
    Ok(())
}

#[test]
fn rpc_memory_revision_does_not_schedule_background_work() -> Result<(), Box<dyn std::error::Error>>
{
    let rt = start_internal_runtime()?;
    let base = format!("http://127.0.0.1:{}", rt.port);
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let health: serde_json::Value = ureq::get(&format!("{base}/api/health"))
            .call()?
            .into_json()?;
        if health["retrieval_index"]["state"] == "ready"
            && health["retrieval_index"]["scheduled"] == false
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "initial empty index did not settle: {health}"
        );
        thread::sleep(Duration::from_millis(20));
    }
    // A later unsolicited index kick would now fail on the deliberate ambiguity.
    // This synthetic file is never opened as a database and contains no user data.
    fs::write(
        rt.dir.path().join("onememory.db"),
        b"synthetic ambiguous path",
    )?;
    for index in 0..3 {
        let reply = rt.rpc(&format!("revision-no-index-{index}"), &["--json", "memory-revision"], Duration::from_secs(3))?;
        assert_eq!(reply["ok"], false);
        thread::sleep(Duration::from_millis(100));
        let health: serde_json::Value = ureq::get(&format!("{base}/api/health"))
            .call()?
            .into_json()?;
        assert_eq!(
            health["retrieval_index"]["state"], "ready",
            "probe scheduled indexing: {health}"
        );
        assert_eq!(health["retrieval_index"]["scheduled"], false);
        assert_eq!(health["retrieval_index"]["running"], false);
        assert!(!rt.dir.path().join("session.json").exists());
    }
    Ok(())
}
