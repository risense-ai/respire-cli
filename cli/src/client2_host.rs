//! Transport-only compatibility host for the unchanged Client2 launcher.
//! The independent Runtime owns legacy admission, scope binding and execution.
//! The health selector is representation negotiation, never authorization.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex};
use std::time::{Duration, Instant};

const LIMIT: u64 = 32 * 1024 * 1024;
const READY_LIMIT: u64 = 64 * 1024;

fn visible_path(path: PathBuf) -> Result<PathBuf> {
    // Client2 compares QueryFullProcessImageName's DOS/UNC spelling literally.
    // Retain canonical comparisons for authority; expose the same actual image
    // without Rust's extended-path namespace in the legacy representation.
    #[cfg(windows)]
    return Ok(crate::autostart::windows_task_path(path.to_str()
        .context("host executable path is not UTF-8")?)?.into());
    #[cfg(not(windows))]
    Ok(path)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).timeout_connect(Duration::from_secs(2))
        .timeout(Duration::from_secs(120)).build()
}

fn health_at(port: u16) -> Result<Value> {
    let response = agent().get(&format!("http://127.0.0.1:{port}/api/health"))
        .timeout(Duration::from_secs(2)).call()?;
    let mut bytes = Vec::new();
    response.into_reader().take(READY_LIMIT + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= READY_LIMIT as usize, "oversized health response");
    serde_json::from_slice(&bytes).context("invalid health response")
}

fn read_ready(reader: impl Read) -> Result<Value> {
    let mut bytes = Vec::new();
    BufReader::new(reader.take(READY_LIMIT + 1)).read_until(b'\n', &mut bytes)?;
    anyhow::ensure!(bytes.len() <= READY_LIMIT as usize && bytes.last() == Some(&b'\n'),
        "incomplete Runtime readiness frame");
    let ready: Value = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(ready["startup_complete"] == true, "Runtime startup is incomplete");
    Ok(ready)
}

struct Backend {
    port: u16,
    health: crate::net_rpc::Health,
    executable: PathBuf,
    public_port: u16,
    host_executable: PathBuf,
    last_health: Mutex<crate::net_rpc::Health>,
}

impl Backend {
    fn verify(&self, current: &crate::net_rpc::Health) -> Result<()> {
        anyhow::ensure!(current.server == "respire" && current.v == 1
            && current.pid == self.health.pid && current.instance_id == self.health.instance_id
            && current.process_start_id == self.health.process_start_id
            && current.image_sha256 == self.health.image_sha256
            && current.account_id == self.health.account_id && current.generation >= self.health.generation
            && current.managed_id.is_none() && current.runtime_version == self.health.runtime_version
            && Path::new(&current.exe).canonicalize()? == self.executable
            && Path::new(&current.image_path).canonicalize()? == self.executable
            && Path::new(&current.installation_root).canonicalize()? == Path::new(&self.health.installation_root).canonicalize()?
            && Path::new(&current.data_dir).canonicalize()? == Path::new(&self.health.data_dir).canonicalize()?,
            "compatibility backend identity changed");
        let actual = crate::net_rpc::runtime_process_identity(current.pid)?;
        let prefix = if cfg!(windows) { "windows-filetime-" }
            else if cfg!(target_os = "linux") { "linux-starttime-" } else { "darwin-lstart-" };
        anyhow::ensure!(current.process_start_id == format!("{prefix}{}", actual.started_at)
            && Path::new(&actual.executable).canonicalize()? == self.executable,
            "compatibility backend OS process changed");
        Ok(())
    }

    fn request(&self, request: &mut tiny_http::Request) -> Result<(u16, String, Vec<u8>)> {
        let headers: Vec<_> = request.headers().iter().map(|header|
            (header.field.to_string(), header.value.to_string())).collect();
        validate_request(request.method().as_str(), request.url(),
            request.remote_addr().is_some_and(|address| address.ip().is_loopback()),
            &headers, self.public_port)?;
        let live = health_at(self.port)?;
        let health: crate::net_rpc::Health = serde_json::from_value(live.clone())?;
        self.verify(&health)?;
        *self.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))? = health.clone();
        if request.url() == "/api/health" {
            let modern = headers.iter().any(|(name, value)|
                name.eq_ignore_ascii_case("X-Respire-Health") && value == "runtime-v1");
            let response = if modern { live } else {
                // Old Client2 verifies and waits for this actual CLI process.
                // Do not present the backend PID with a CLI image or version.
                json!({"server":"respire", "v":health.v, "bin":crate::VERSION,
                    "pid":std::process::id(), "exe":self.host_executable,
                    "data_dir":health.data_dir, "installation_root":health.installation_root,
                    "inference":health.inference, "rpc":health.rpc, "store_ready":health.store_ready,
                    "compatibility_host":"client2-v0256", "backend_instance_id":health.instance_id})
            };
            return Ok((200, "application/json".into(), serde_json::to_vec(&response)?));
        }
        anyhow::ensure!(request.body_length().is_none_or(|length| length as u64 <= LIMIT),
            "request body is too large");
        let mut bytes = Vec::new();
        request.as_reader().take(LIMIT + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() as u64 <= LIMIT, "request body is too large");
        anyhow::ensure!(request.method() != &tiny_http::Method::Get || bytes.is_empty(),
            "GET compatibility requests cannot carry a body");
        let mut outgoing = agent().request(request.method().as_str(), &format!("http://127.0.0.1:{}{}", self.port, request.url()))
            .set("Content-Type", "application/json");
        if let Some((_, accept)) = headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("Accept")) {
            outgoing = outgoing.set("Accept", accept);
        }
        if headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("X-Respire-Lifecycle")
            && value == "coordinator-v1") {
            outgoing = outgoing.set("X-Respire-Lifecycle", "coordinator-v1");
        }
        // Original Host/Origin are validated above. No caller credential or
        // forwarding header is copied, and no scope or operation ID is added.
        let response = match if request.method() == &tiny_http::Method::Get {
            outgoing.call()
        } else { outgoing.send_bytes(&bytes) } {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => return Err(error.into()), // Never replay an uncertain write.
        };
        let status = response.status();
        let content_type = response.header("Content-Type").unwrap_or("application/octet-stream").to_owned();
        let mut body = Vec::new();
        response.into_reader().take(LIMIT + 1).read_to_end(&mut body)?;
        anyhow::ensure!(body.len() as u64 <= LIMIT, "Runtime response is too large");
        if status == 200 && request.method() == &tiny_http::Method::Get
            && matches!(request.url(), "/mcp" | "/sse") {
            // This transport owns the public address. Rewrite only the exact
            // verified backend's endpoint announcement, never arbitrary data.
            anyhow::ensure!(body == format!("event: endpoint\ndata: http://127.0.0.1:{}/mcp\n\n", self.port).as_bytes(),
                "unexpected backend SSE endpoint announcement");
            body = format!("event: endpoint\ndata: http://127.0.0.1:{}/mcp\n\n", self.public_port).into_bytes();
        }
        Ok((status, content_type, body))
    }
}

fn validate_request(method: &str, path: &str, loopback: bool,
    headers: &[(String, String)], port: u16) -> Result<()> {
    anyhow::ensure!(loopback, "non-loopback peer rejected");
    anyhow::ensure!(matches!((method, path), ("GET", "/api/health")
        | ("POST", "/api/rpc" | "/api/runtime/stop")
        | ("GET" | "POST", "/mcp" | "/sse")), "unsupported compatibility route");
    for name in ["Host", "Origin", "Accept", "X-Respire-Health", "X-Respire-Lifecycle"] {
        let values: Vec<_> = headers.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str()).collect();
        anyhow::ensure!(values.len() <= 1, "duplicate compatibility header");
        if name == "Host" {
            anyhow::ensure!(values.len() == 1 && (values[0] == format!("127.0.0.1:{port}")
                || values[0] == format!("localhost:{port}")), "foreign Host rejected");
        } else if name == "Origin" {
            anyhow::ensure!(values.is_empty() || (!values[0].is_empty()
                && crate::net_rpc::origin_ok(values[0], &format!("http://127.0.0.1:{port}"))),
                "foreign Origin rejected");
        }
    }
    Ok(())
}

pub(crate) fn serve() -> Result<()> {
    anyhow::ensure!(std::env::args_os().count() == 2, "compatibility host accepts no extra arguments");
    respire_client_host::roots::validate_client_environment()?;
    crate::runtime_policy::require_host("Client2 compatibility startup")?;
    crate::autostart::check_direct_access()?;
    let root = respire_client_host::paths::main_data_dir();
    anyhow::ensure!(!root.join("runtime/autostart/registration.json").exists(),
        "compatibility host cannot replace a registered service");
    let public_port = crate::net_rpc::rpc_port();
    let listener = TcpListener::bind(("127.0.0.1", public_port))?;
    let reservation = TcpListener::bind(("127.0.0.1", 0))?;
    let port = reservation.local_addr()?.port();
    let executable = crate::rpc::resolve_runtime_executable()?.canonicalize()?;
    let digest = hex::encode(Sha256::digest(std::fs::read(&executable)?));
    let mut command = Command::new(&executable);
    command.args(["--runtime-internal", "--runtime-background-internal", "--port", &port.to_string()])
        .env("RSRS_RPC_PORT", port.to_string()).env_remove("RSRS_RUNTIME_BOOT_TOKEN")
        .env_remove("GH_TOKEN").env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    drop(reservation);
    let mut child = respire_spawn::spawn_host_control(&mut command)?;
    let pid = child.id();
    let reader = child.stdout.take().context("Runtime readiness pipe is missing")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || { let _ = sender.send(read_ready(reader)); });
    let ready = receiver.recv_timeout(Duration::from_secs(30))
        .with_context(|| format!("Runtime readiness is uncertain for child {pid}; inspect before retry"))??;
    let health: crate::net_rpc::Health = serde_json::from_value(ready)?;
    let (installation, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(child.try_wait()?.is_none() && health.pid == pid && health.image_sha256 == digest
        && !health.instance_id.is_empty() && !health.account_id.is_empty() && health.generation > 0
        && crate::runtime_fetch::version_in_accept(&health.runtime_version)
        && Path::new(&health.installation_root).canonicalize()? == installation.canonicalize()?
        && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?,
        "Runtime readiness does not match the selected child and installation");
    let backend = Arc::new(Backend { port, health, executable, public_port,
        host_executable: visible_path(std::env::current_exe()?)?,
        last_health: Mutex::new(serde_json::from_value(health_at(port)?)?) });
    backend.verify(&serde_json::from_value(health_at(port)?)?)?;
    let server = tiny_http::Server::from_listener(listener, None)
        .map_err(|error| anyhow::anyhow!("cannot create compatibility listener: {error}"))?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut exited = None;
    loop {
        if exited.is_none() { exited = child.try_wait()?; }
        if let Some(status) = exited {
            if active.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            let final_health = backend.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))?;
            crate::net_rpc::final_stop_receipt(&final_health, None)?;
            anyhow::ensure!(status.success(), "Runtime exited unsuccessfully after drain");
            return Ok(());
        }
        let Some(mut request) = server.recv_timeout(Duration::from_millis(50))? else { continue; };
        let headers: Vec<_> = request.headers().iter().map(|header|
            (header.field.to_string(), header.value.to_string())).collect();
        if validate_request(request.method().as_str(), request.url(),
            request.remote_addr().is_some_and(|address| address.ip().is_loopback()),
            &headers, public_port).is_err() {
            request.respond(tiny_http::Response::from_string("request boundary rejected").with_status_code(403))?;
            continue;
        }
        if active.load(Ordering::Acquire) >= 64 {
            request.respond(tiny_http::Response::from_string("busy").with_status_code(503))?;
            continue;
        }
        active.fetch_add(1, Ordering::AcqRel);
        let backend = Arc::clone(&backend);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            let (status, content_type, body) = backend.request(&mut request).unwrap_or_else(|_| (502, "application/json".into(),
                br#"{"error":"compatibility request failed; outcome may be unknown; do not replay"}"#.to_vec()));
            let mut response = tiny_http::Response::from_data(body).with_status_code(status);
            if let Ok(header) = tiny_http::Header::from_bytes("Content-Type", content_type.as_bytes()) {
                response.add_header(header);
            }
            let _ = request.respond(response);
            active.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

/// Caller retains the existing takeover lock. This never takes over a healthy
/// strict or managed owner, and never retries an uncertain spawn.
pub(crate) fn start_locked() -> Result<()> {
    if crate::rpc::probe_runtime()?.is_some() {
        let public = health_at(crate::net_rpc::rpc_port())?;
        anyhow::ensure!(public["compatibility_host"] == "client2-v0256",
            "existing Runtime is not a Client2 compatibility host; stop it explicitly before changing mode");
        return Ok(());
    }
    crate::runtime_policy::require_host("Client2 compatibility startup")?;
    anyhow::ensure!(crate::autostart::lifecycle_boot_token().is_none(),
        "compatibility startup cannot inherit account maintenance");
    let executable = visible_path(crate::net_rpc::stable_bin_path().canonicalize()?)?;
    anyhow::ensure!(Sha256::digest(std::fs::read(&executable)?)
        == Sha256::digest(std::fs::read(std::env::current_exe()?)?),
        "Client2 requires the same verified CLI bytes at the stable bin path");
    let mut child = respire_spawn::spawn_binary_with_boot_token(&executable,
        &["--client2-host-internal".into()], None)?;
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        anyhow::ensure!(child.try_wait()?.is_none(), "compatibility host exited before readiness");
        if let Ok(public) = health_at(crate::net_rpc::rpc_port()) {
            anyhow::ensure!(public["compatibility_host"] == "client2-v0256"
                && public["pid"] == child.id() && public["bin"] == crate::VERSION
                && public["exe"].as_str().is_some_and(|path| Path::new(path) == executable),
                "compatibility host readiness identity mismatch");
            anyhow::ensure!(crate::rpc::runtime_acceptable(&crate::net_rpc::health()?)?,
                "compatibility host backend is not the selected Runtime");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("compatibility startup is uncertain for child {}; inspect before retry", child.id())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatibility_boundary_rejects_foreign_and_ambiguous_requests() {
        let base = vec![("Host".into(), "127.0.0.1:15169".into())];
        assert!(validate_request("POST", "/api/rpc", true, &base, 15169).is_ok());
        for path in ["//other/api/rpc", "/api/rpc?target=other", "http://other/api/rpc", "/admin"] {
            assert!(validate_request("POST", path, true, &base, 15169).is_err());
        }
        assert!(validate_request("POST", "/api/rpc", false, &base, 15169).is_err());
        assert!(validate_request("GET", "/api/runtime/stop", true, &base, 15169).is_err());
        assert!(validate_request("GET", "/mcp", true, &base, 15169).is_ok());
        assert!(validate_request("POST", "/mcp", true, &base, 15169).is_ok());
        for extra in [("Host", "127.0.0.1:15169"), ("Origin", "null"),
            ("Origin", "http://evil.example"), ("Origin", "http://127.0.0.1:15170")] {
            let mut headers = base.clone(); headers.push((extra.0.into(), extra.1.into()));
            assert!(validate_request("POST", "/api/rpc", true, &headers, 15169).is_err());
        }
        assert!(read_ready(&b"{}\n"[..]).is_err());
        assert!(read_ready(&b"{\"startup_complete\":true}"[..]).is_err());
    }
}
