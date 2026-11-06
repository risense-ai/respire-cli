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
    host_control: bool,
}

impl Runtime {
    fn host_command(&self, args: &[&str]) -> Result<std::process::Output, String> {
        let host = self.dir.path().join("host");
        let home = host.join("home");
        Command::new(self.dir.path().join("bin").join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" }))
            .args(args).current_dir(host.join("work"))
            .env("HOME", &home).env("USERPROFILE", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("XDG_CACHE_HOME", home.join(".cache"))
            .env("XDG_RUNTIME_DIR", host.join("run"))
            .env("APPDATA", home.join("AppData/Roaming"))
            .env("LOCALAPPDATA", home.join("AppData/Local"))
            .env("RSRS_DATA_DIR", self.dir.path()).env("RSRS_RPC_PORT", self.port.to_string())
            .env("RSRS_BIN_DIR", self.dir.path().join("bin"))
            .env_remove("RSRS_RUNTIME_BIN").env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART").env_remove("RSRS_RPC_TOKEN")
            .env_remove("GH_TOKEN").env_remove("GITHUB_TOKEN")
            .output().map_err(|err| err.to_string())
    }

    fn refresh_controlled_identity(&mut self) -> Result<(), String> {
        self.verify_stop_receipt(None)?;
        let health: serde_json::Value = ureq::get(&format!("http://127.0.0.1:{}/api/health", self.port))
            .timeout(Duration::from_secs(3)).call().map_err(|err| err.to_string())?
            .into_json().map_err(|err| err.to_string())?;
        for field in ["server", "v", "installation_id", "account_id", "bin", "runtime_version", "image_sha256"] {
            assert_eq!(health[field], self.identity[field], "replacement Runtime changed {field}");
        }
        for field in ["installation_root", "data_dir", "exe", "image_path"] {
            let actual = health[field].as_str().ok_or("replacement Runtime path missing")?;
            let expected = self.identity[field].as_str().ok_or("original Runtime path missing")?;
            assert_eq!(fs::canonicalize(actual).map_err(|err| err.to_string())?,
                fs::canonicalize(expected).map_err(|err| err.to_string())?);
        }
        assert_ne!(health["instance_id"], self.identity["instance_id"]);
        assert!(health["generation"].as_u64().is_some_and(|generation| generation > 0));
        for field in ["account_id", "instance_id", "process_start_id"] {
            assert!(health[field].as_str().is_some_and(|value| !value.is_empty()));
        }
        let pid = health["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
            .ok_or("replacement Runtime PID missing")?;
        let process = respire_commands::net_rpc::runtime_process_identity(pid).map_err(|err| err.to_string())?;
        let prefix = if cfg!(windows) { "windows-filetime-" }
            else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
        assert_eq!(health["process_start_id"], format!("{prefix}{}", process.started_at));
        assert_eq!(fs::canonicalize(&process.executable).map_err(|err| err.to_string())?,
            fs::canonicalize(health["image_path"].as_str().ok_or("Runtime image missing")?)
                .map_err(|err| err.to_string())?);
        self.identity = health;
        Ok(())
    }

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
        if self.host_control {
            // Private setters replace the original child. CLI stop verifies roots and OS birth
            // before draining the current owner, rather than killing a PID found by port.
            match self.host_command(&["--runtime-internal", "--stop", "--json"]) {
                Ok(output) if output.status.success() => {}
                _ => {
                    self.dir.disable_cleanup(true);
                    eprintln!("owned mode-test Runtime cleanup was not confirmed; retained {}", self.dir.path().display());
                }
            }
        }
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
    start_runtime(mode, legacy_path, false)
}

fn start_scoped_runtime() -> Result<Runtime, String> {
    start_runtime("normal", false, false)
}

fn start_runtime(mode: &str, legacy_path: bool, host_control: bool) -> Result<Runtime, String> {
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
    let mut runtime = runtime_bin()?;
    if host_control {
        let cli = dir.path().join("bin").join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
        fs::create_dir_all(cli.parent().ok_or("CLI fixture bin directory missing")?)
            .map_err(|err| err.to_string())?;
        fs::copy(bin(), &cli).map_err(|err| err.to_string())?;
        use sha2::Digest;
        let source_hash = sha2::Sha256::digest(fs::read(bin()).map_err(|err| err.to_string())?);
        let installed_hash = sha2::Sha256::digest(fs::read(&cli).map_err(|err| err.to_string())?);
        assert_eq!(installed_hash, source_hash, "installed CLI fixture differs from the tested binary");
        for path in ["host/work", "host/run", "host/home/.config", "host/home/.local/share",
            "host/home/.local/state", "host/home/.cache", "host/home/AppData/Roaming", "host/home/AppData/Local"] {
            fs::create_dir_all(dir.path().join(path)).map_err(|err| err.to_string())?;
        }
        support::install_runtime_fixture(dir.path()).map_err(|err| format!("{err:#}"))?;
        let version = runtime.parent().and_then(std::path::Path::file_name)
            .ok_or("Runtime fixture version directory missing")?;
        let filename = runtime.file_name().ok_or("Runtime fixture binary name missing")?;
        runtime = dir.path().join("runtime").join(version).join(filename)
            .canonicalize().map_err(|err| err.to_string())?;
    }
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
                let rt = Runtime { child, dir, port, stderr_path, identity, host_control };
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
    let mut rt = start_runtime("normal", true, false)?;
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
        let other_stderr_path = rt.dir.path().join(format!(
            "alternate-runtime-{alternate_profile}.stderr.log"
        ));
        let other_stderr = fs::File::create(&other_stderr_path).map_err(|err| err.to_string())?;
        let read_other_stderr = || match fs::read_to_string(&other_stderr_path) {
            Ok(stderr) => stderr,
            Err(err) => format!("failed to read private stderr: {err}"),
        };
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
            .stderr(Stdio::from(other_stderr))
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
            {
                let kill = other.kill();
                let wait = other.wait();
                return Err(format!(
                    "another port became listening: alternate_profile={alternate_profile}; kill={kill:?}; wait={wait:?}; stderr={}",
                    read_other_stderr()
                ));
            }
            // Allow both 5s probes and the 15s installation-lock wait, plus margin.
            if started.elapsed() > Duration::from_secs(40) {
                if let Some(status) = other.try_wait().map_err(|err| err.to_string())? {
                    break status;
                }
                let kill = other.kill();
                let wait = other.wait();
                return Err(format!(
                    "alternate runtime startup rejection timed out after 40s: alternate_profile={alternate_profile}; kill={kill:?}; wait={wait:?}; stderr={}",
                    read_other_stderr()
                ));
            }
            thread::sleep(Duration::from_millis(25));
        };
        assert!(
            !status.success(),
            "alternate runtime exited successfully instead of rejecting startup: alternate_profile={alternate_profile}; status={status}; stderr={}",
            read_other_stderr()
        );
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
    let mut rt = start_runtime("off", false, true)?;
    eprintln!("device-stage=off-rpc-probes");
    let execute = |rt: &Runtime, args: &[&str]| {
        rt.rpc(&uuid::Uuid::new_v4().to_string(), args, Duration::from_secs(20))
    };
    let host = |rt: &Runtime, args: &[&str]| -> Result<(bool, serde_json::Value), String> {
        let output = rt.host_command(args)?;
        let envelope = serde_json::from_slice(&output.stdout).map_err(|err|
            format!("host command {args:?} returned no envelope: {err}; {}", String::from_utf8_lossy(&output.stderr)))?;
        Ok((output.status.success(), envelope))
    };
    let set_mode = |rt: &mut Runtime, mode: &str| -> Result<(), String> {
        let intent = format!("workspace_mode={mode}");
        let (ok, result) = host(rt, &["--json", "agent-config", "--set", &intent])?;
        assert!(ok, "{result}");
        assert_eq!(result["command"], "agent-config");
        assert_eq!(result["summary"]["action"], "updated");
        assert_eq!(result["summary"]["key"], "workspace_mode");
        assert_eq!(result["summary"]["value"], mode);
        eprintln!("device-stage=mode-owner-refresh");
        rt.refresh_controlled_identity()?;
        eprintln!("device-stage=mode-config-read");
        let (ok, config) = host(rt, &["--json", "agent-config"])?;
        assert!(ok, "{config}");
        assert_eq!(config["summary"]["workspace_mode"], mode, "{config}");
        Ok(())
    };
    for args in [
        vec!["--json", "recall", "synthetic query"],
        vec!["--json", "remember", "synthetic memory"],
        vec!["--json", "list"],
        vec!["--json", "sync"],
    ] {
        let response = execute(&rt, &args)?;
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["envelope"]["summary"]["skipped"], true);
        assert_eq!(response["envelope"]["items"], serde_json::json!([]));
    }
    // Doctor always checks the generic prompt, even when no IDE is installed.
    eprintln!("device-stage=off-host-inject");
    let (ok, injected) = host(&rt, &["--json", "inject", "--id", "generic"])?;
    assert!(ok, "{injected}");
    assert_eq!(injected["command"], "inject");
    assert!(rt.dir.path().join("host/home/AGENTS.md").is_file());
    // Repairs and migrations belong to the host, not the business RPC allowlist.
    eprintln!("device-stage=off-host-doctor");
    let doctor_output = rt.host_command(&["--json", "doctor", "--fix"])?;
    let doctor: serde_json::Value = serde_json::from_slice(&doctor_output.stdout).map_err(|err|
        format!("doctor returned no envelope: {err}"))?;
    // Off diagnostics are an explicit warning (exit 2), not a failed host check.
    assert_eq!(doctor_output.status.code(), Some(2), "off doctor must exit with warning status");
    assert_eq!(doctor["command"], "doctor");
    assert_eq!(doctor["status"], "warn");
    assert_eq!(doctor["errors"], serde_json::json!([]));
    assert_eq!(doctor["summary"]["mode"], "off");
    assert_eq!(doctor["summary"]["fail"], 0);
    assert_eq!(doctor["summary"]["warn"], 1);
    assert_eq!(doctor["summary"]["skipped"], true);
    assert!(doctor["items"].as_array().is_some_and(|items| items.iter()
        .any(|item| item["name"] == "Runtime diagnostics" && item["status"] == "warn"
            && item["value"] == "Memory is off; Runtime diagnostics were not executed")));
    assert!(doctor["items"].as_array().is_some_and(|items| items.iter()
        .any(|item| item["name"] == "inject" && item["status"] == "ok"
            && item["value"] == "1/1 injected and fresh (1 detected)")));
    assert!(doctor["items"].as_array().is_some_and(|items| items.iter()
        .any(|item| item["name"] == "host repair" && item["status"] == "skip")));
    let migration = ["--json", "migrate", "--source", "/missing-synthetic-library", "--account", "fixture"];
    eprintln!("device-stage=off-host-migration");
    let (ok, rejected) = host(&rt, &migration)?;
    assert!(!ok, "invalid legacy source was accepted: {rejected}");
    assert!(rejected["errors"].as_array().is_some_and(|errors| errors.iter()
        .any(|error| error.as_str().is_some_and(|message| message.contains("invalid migration source or account")))));
    eprintln!("device-stage=off-status-rpc");
    let status = execute(&rt, &["--json", "status"])?;
    assert_eq!(status["envelope"]["summary"]["workspace"], "off", "{status}");
    assert!(status["envelope"]["summary"]["local_total"].is_null());
    assert!(!rt.dir.path().join("rsrs.db").exists());
    assert!(!rt.dir.path().join("onememory.db").exists());
    let (ok, config) = host(&rt, &["--json", "agent-config"])?;
    assert!(ok, "{config}");
    assert_eq!(config["summary"]["memory_off"], true, "{config}");
    assert_eq!(config["summary"]["workspace_mode"], "off");
    let plain = rt.host_command(&["--client-only", "recall", "synthetic query"])?;
    assert!(plain.status.success(), "{}", String::from_utf8_lossy(&plain.stderr));
    assert!(plain.stdout.is_empty(), "disabled human output must be empty");
    eprintln!("device-stage=enter-readonly");
    set_mode(&mut rt, "readonly")?;
    eprintln!("device-stage=enter-normal");
    set_mode(&mut rt, "normal")?;
    eprintln!("device-stage=normal-initial-status-rpc");
    let initialized = execute(&rt, &["--json", "status"])?;
    assert_eq!(initialized["ok"], true, "{initialized}");
    assert!(rt.dir.path().join("rsrs.db").exists());
    eprintln!("device-stage=enter-readonly");
    set_mode(&mut rt, "readonly")?;
    let (ok, config) = host(&rt, &["--json", "agent-config"])?;
    assert!(ok, "{config}");
    assert_eq!(config["summary"]["readonly"], true, "{config}");
    for args in [
        vec!["--json", "remember", "synthetic memory"],
        vec!["--json", "sync"],
        vec!["--json", "sync-reset"],
        vec!["--json", "doctor", "--fix"],
        vec!["--json", "sync-conflicts", "--refresh"],
        vec!["--json", "sync-history", "--remote"],
        migration.to_vec(),
    ] {
        if matches!(args.get(1), Some(&"doctor" | &"migrate")) {
            let (ok, result) = host(&rt, &args)?;
            assert!(!ok, "read-only host accepted {args:?}: {result}");
            assert_ne!(result["details"]["error_type"], "host_boundary");
            let expected = if args[1] == "doctor" { "read-only" } else { "invalid migration source or account" };
            assert!(result["errors"].as_array().is_some_and(|errors| errors.iter()
                .any(|error| error.as_str().is_some_and(|message| message.contains(expected)))),
                "host rejection was not the intended guard: {result}");
        } else {
            eprintln!("device-stage=readonly-reject-write-rpc");
            let response = execute(&rt, &args)?;
            assert_eq!(response["ok"], false, "read-only accepted {args:?}: {response}");
        }
    }
    eprintln!("device-stage=enter-normal");
    set_mode(&mut rt, "normal")?;
    eprintln!("device-stage=normal-final-status-rpc");
    let status = execute(&rt, &["--json", "status"])?;
    assert_eq!(status["ok"], true, "{status}");
    assert_ne!(status["envelope"]["summary"]["workspace"], "off");
    let (ok, config) = host(&rt, &["--json", "agent-config"])?;
    assert!(ok, "{config}");
    assert_eq!(config["summary"]["readonly"], false, "{config}");
    assert_eq!(config["summary"]["memory_off"], false);
    assert_eq!(serde_json::from_slice::<serde_json::Value>(
        &fs::read(rt.dir.path().join("client.json")).map_err(|err| err.to_string())?
    ).map_err(|err| err.to_string())?["service_mode"], "normal");
    let cleanup = rt.host_command(&["--runtime-internal", "--stop", "--json"])?;
    assert!(cleanup.status.success(), "{}", String::from_utf8_lossy(&cleanup.stderr));
    rt.verify_stop_receipt(None)?;
    assert!(std::net::TcpStream::connect(("127.0.0.1", rt.port)).is_err());
    rt.host_control = false;
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
