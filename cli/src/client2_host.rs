//! Transport-only compatibility host for the unchanged Client2 launcher.
//! The independent Runtime owns legacy admission, scope binding and execution.
//! The health selector is representation negotiation, never authorization.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "macos")]
use std::process::Stdio;
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
    anyhow::ensure!(ready["startup_complete"] == true
        || (ready["startup_complete"] == false && ready["error"].is_string()),
        "Runtime startup is incomplete");
    Ok(ready)
}

fn receive_ready(child: &mut std::process::Child) -> Result<Value> {
    let pid = child.id();
    let reader = child.stdout.take().context("private readiness pipe is missing")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || { let _ = sender.send(read_ready(reader)); });
    let ready = receiver.recv_timeout(Duration::from_secs(40))
        .with_context(|| format!("startup is uncertain for child {pid}; inspect before retry"))?;
    match ready {
        Err(error) => match child.try_wait()? {
            Some(status) => Err(error).with_context(|| format!("compatibility startup pipe failed; child exit status: {status}")),
            None => Err(error),
        },
        Ok(ready) => Ok(ready),
    }
}

fn publish_ready(ready: &Value) -> Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, ready)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

// Never forward Display/source strings: they can contain credentials or responses.
pub(crate) fn report_failure(stage: &'static str, error: &anyhow::Error) -> Result<()> {
    let stage = error.downcast_ref::<&'static str>().copied().unwrap_or(stage);
    let category = if let Some(error) = error.downcast_ref::<std::io::Error>() {
        format!("io::{:?}; os_error={:?}", error.kind(), error.raw_os_error())
    } else if let Some(error) = error.downcast_ref::<respire_commands::runtime_error::RuntimeError>() {
        use respire_commands::runtime_error::RuntimeError;
        match error {
            RuntimeError::Unavailable => "runtime_unavailable",
            RuntimeError::TokenUnreadable(_) => "runtime_token_unreadable",
            RuntimeError::Unauthorized => "runtime_unauthorized",
            RuntimeError::Transport(_) => "runtime_transport",
            RuntimeError::OutcomeUnknown { .. } => "request_outcome_unknown",
        }.into()
    } else { "internal_error".into() };
    let status = error.downcast_ref::<std::process::ExitStatus>();
    let message = format!("compatibility startup failed at {stage} ({category}; exit_status={status:?})");
    eprintln!("{message}");
    publish_ready(&json!({"startup_complete":false, "error":message}))
}

#[cfg(any(test, target_os = "macos"))]
fn guarded_host_pid(ready: &Value, guardian: u32, executable: &Path, root: &Path, port: u16) -> Result<u32> {
    let pid = ready["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0 && *pid != guardian).context("invalid guarded host PID")?;
    anyhow::ensure!(ready["guardian_pid"] == guardian && ready["startup_complete"] == true
        && ready["bin"] == crate::VERSION && ready["port"] == port
        && Path::new(ready["exe"].as_str().context("guarded host image missing")?).canonicalize()? == executable.canonicalize()?
        && Path::new(ready["installation_root"].as_str().context("guarded host root missing")?).canonicalize()? == root.canonicalize()?,
        "guarded host readiness does not match this launch");
    Ok(pid)
}

/// Old Client2 polls kinfo_proc every 100 ms for up to 30 seconds, accepting
/// SZOMB but turning an already reaped (zero-length) record into EIO. Keep the
/// actual exited child waitable through that window; no live process, socket,
/// library lock, or fabricated identity is retained for it.
#[cfg(target_os = "macos")]
pub(crate) fn supervise() -> Result<()> {
    let expectation = startup_expectation(std::env::args_os().skip(2))
        .context("startup arguments")?;
    respire_client_host::roots::validate_client_environment()
        .context("client environment")?;
    crate::runtime_policy::require_host("Client2 exit observation")?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let mut command = Command::new(&executable);
    command.arg("--client2-host-internal");
    match expectation {
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::Unlock => { command.arg("--require-unlocked"); }
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::LockedAfterFullLogout => { command.arg("--locked-after-full-logout"); }
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::Startup => {}
    }
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    let mut child = respire_spawn::spawn_host_control(&mut command)?;
    let mut ready = receive_ready(&mut child)?;
    if ready["startup_complete"] == false {
        publish_ready(&ready)?;
        anyhow::bail!("owned compatibility host startup failed");
    }
    anyhow::ensure!(ready["pid"] == child.id(), "readiness does not identify the owned host child");
    ready["guardian_pid"] = json!(std::process::id());
    guarded_host_pid(&ready, std::process::id(), &executable,
        &respire_client_host::paths::main_data_dir(), crate::net_rpc::rpc_port())?;
    let health: crate::net_rpc::Health = serde_json::from_value(ready["backend_health"].clone())?;
    let port = ready["backend_port"].as_u64().and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0).context("guarded backend port missing")?;
    let backend = Backend { port, health: health.clone(),
        executable: crate::rpc::resolve_runtime_executable()?.canonicalize()?,
        public_port: crate::net_rpc::rpc_port(), host_executable: visible_path(executable.clone())?,
        host_image_sha256: hex::encode(Sha256::digest(std::fs::read(&executable)?)),
        last_health: Mutex::new(health) };
    backend.verify(&serde_json::from_value(health_at(port)?)?)?;
    expectation.confirm_credentials(&backend.health)?;
    // A disconnected launcher must not orphan a running host by making its
    // observer exit. Keep ownership and reap normally even if readiness is lost.
    let readiness = publish_ready(&ready);
    // process_birth inspects Darwin's process state without reaping this child.
    // Unknown/denied inspection remains an error, never evidence of an exit.
    while crate::autostart::process_birth(child.id())?.is_some() {
        std::thread::sleep(Duration::from_millis(50));
    }
    // The host can die before it drains its independently running Runtime.
    // Stop only the backend authenticated through this owned child's pipe.
    let operation = if crate::autostart::process_birth(backend.health.pid)?.is_some() {
        let operation = backend.stop_owned()?;
        while let Some(birth) = crate::autostart::process_birth(backend.health.pid)? {
            anyhow::ensure!(backend.health.process_start_id == format!("darwin-lstart-{birth}"),
                "guarded backend process identity changed during shutdown");
            std::thread::sleep(Duration::from_millis(50));
        }
        Some(operation)
    } else { None };
    let final_health = backend.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))?;
    crate::net_rpc::final_stop_receipt(&final_health, operation.as_deref())?;
    std::thread::sleep(Duration::from_secs(35));
    let status = child.wait()?;
    readiness?;
    anyhow::ensure!(status.success(), "compatibility host did not exit successfully");
    Ok(())
}

struct Backend {
    port: u16,
    health: crate::net_rpc::Health,
    executable: PathBuf,
    public_port: u16,
    host_executable: PathBuf,
    host_image_sha256: String,
    last_health: Mutex<crate::net_rpc::Health>,
}

impl Backend {
    fn stop_owned(&self) -> Result<String> {
        crate::runtime_policy::require_host("compatibility host shutdown")?;
        let health: crate::net_rpc::Health = serde_json::from_value(health_at(self.port)?)?;
        self.verify(&health)?;
        *self.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))? = health.clone();
        let expected = json!({"installation_id":health.installation_id,
            "instance_id":health.instance_id, "account_id":health.account_id, "generation":health.generation});
        let response = agent().post(&format!("http://127.0.0.1:{}/api/runtime/stop", self.port))
            .set("Content-Type", "application/json").set("X-Respire-Lifecycle", "coordinator-v1")
            .send_string(&expected.to_string())?;
        let mut bytes = Vec::new();
        response.into_reader().take(64 * 1024 + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 64 * 1024, "oversized stop acknowledgement");
        let reply: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(reply["ok"] == true && reply["state"] == "accepted"
            && reply["request_id"].as_str().is_some_and(|id| !id.is_empty()),
            "owned Runtime did not acknowledge shutdown");
        reply["operation_id"].as_str().filter(|id| !id.is_empty()).map(str::to_owned)
            .context("owned Runtime stop operation ID missing")
    }

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
        let coordinator_stop = request.method() == &tiny_http::Method::Post
            && request.url() == "/api/runtime/stop"
            && headers.iter().any(|(name, value)| name.eq_ignore_ascii_case("X-Respire-Lifecycle")
                && value == "coordinator-v1");
        if coordinator_stop {
            // Paused maintenance deliberately revokes legacy health. The stop
            // target must instead identify this previously observed, OS-verified
            // owned Runtime; the backend still validates its current generation.
            anyhow::ensure!(request.body_length().is_none_or(|length| length <= 4096),
                "coordinator stop body is too large");
            let mut bytes = Vec::new();
            request.as_reader().take(4097).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 4096, "coordinator stop body is too large");
            if !bytes.is_empty() {
                let target: Value = serde_json::from_slice(&bytes)?;
                let health = self.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))?.clone();
                self.verify(&health)?;
                anyhow::ensure!(!health.installation_id.is_empty() && !health.instance_id.is_empty()
                    && !health.account_id.is_empty() && health.generation > 0
                    && target["installation_id"] == health.installation_id
                    && target["instance_id"] == health.instance_id
                    && target["account_id"] == health.account_id
                    && target["generation"].as_u64() == Some(health.generation),
                    "coordinator stop target differs from the verified owned Runtime");
                return self.forward(request, &headers, &bytes);
            }
        }
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
                    "compatibility_host":"client2-v0256", "backend_instance_id":health.instance_id,
                    "host_birth":crate::autostart::process_birth(std::process::id())?
                        .context("compatibility host process birth is unavailable")?,
                    "host_image_sha256":self.host_image_sha256,
                    "public_port":self.public_port, "backend_pid":health.pid,
                    "backend_process_start_id":health.process_start_id})
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
        if request.url() == "/api/rpc" {
            let (outgoing, original) = match prepare_legacy_rpc(&bytes, &health) {
                Ok(value) => value,
                Err(_) => return Ok((400, "application/json".into(), br#"{"error":"invalid_rpc_identity"}"#.to_vec())),
            };
            let (status, content_type, body) = self.forward(request, &headers, &outgoing)?;
            let body = match original {
                Some(original) if status == 200 => project_legacy_rpc(&body, &original, &health)?,
                _ => body,
            };
            return Ok((status, content_type, body));
        }
        if request.url() == "/api/runtime/stop" && bytes.is_empty() {
            bytes = serde_json::to_vec(&json!({"installation_id":health.installation_id,
                "instance_id":health.instance_id,"account_id":health.account_id,"generation":health.generation}))?;
        }
        self.forward(request, &headers, &bytes)
    }

    fn forward(&self, request: &tiny_http::Request, headers: &[(String, String)],
        bytes: &[u8]) -> Result<(u16, String, Vec<u8>)> {
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
        // forwarding header is copied. Legacy RPC identity is supplied by this host.
        let response = match if request.method() == &tiny_http::Method::Get {
            outgoing.call()
        } else { outgoing.send_bytes(bytes) } {
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

fn prepare_legacy_rpc(body: &[u8], health: &crate::net_rpc::Health)
    -> Result<(Vec<u8>, Option<respire_protocol::RpcRequest>)>
{
    let original: respire_protocol::RpcRequest = serde_json::from_slice(body)?;
    if original.scope.is_some() { return Ok((body.to_vec(), None)); }
    anyhow::ensure!(original.operation_id.is_none() && original.idempotency_key.is_none()
        && original.parent_operation_id.is_none(), "scope_required");
    let mut request = original.clone();
    request.scope = Some(crate::net_rpc::request_scope(health)?);
    if request.method != "runtime.result" {
        request.operation_id = Some(request.id.clone());
        request.idempotency_key = Some(request.id.clone());
    }
    Ok((serde_json::to_vec(&request)?, Some(original)))
}

fn project_legacy_rpc(body: &[u8], original: &respire_protocol::RpcRequest,
    health: &crate::net_rpc::Health) -> Result<Vec<u8>>
{
    type Reply = respire_protocol::RpcResponse<Value>;
    let same_actor = |reply: &Reply| reply.v == 1 && reply.scope.as_ref().is_some_and(|scope|
        scope.account_id == health.account_id && scope.instance_id == health.instance_id);
    let strip = |reply: &mut Reply| {
        reply.scope = None; reply.operation_id = None; reply.idempotency_key = None;
    };
    let mut reply: Reply = serde_json::from_slice(body)?;
    anyhow::ensure!(reply.id == original.id && same_actor(&reply),
        "legacy result identity differs from the owned Runtime");
    if original.method == "runtime.result" {
        if let Some(summary) = reply.envelope.as_mut().and_then(|envelope| envelope.get_mut("summary"))
            .and_then(Value::as_object_mut) {
            if summary.get("state").and_then(Value::as_str) == Some("failed") {
                summary.insert("state".into(), json!("completed"));
            }
            if let Some(value) = summary.get_mut("response").filter(|value| !value.is_null()) {
                let mut child: Reply = serde_json::from_value(value.clone())?;
                anyhow::ensure!(original.args.first() == Some(&child.id) && same_actor(&child),
                    "legacy cached result identity differs from the original request");
                strip(&mut child);
                *value = serde_json::to_value(child)?;
            }
            for field in ["scope", "operation_id", "idempotency_key"] { summary.remove(field); }
            summary.insert("request_id".into(), json!(original.args.first()));
            summary.insert("retention".into(), json!("last 64 completed requests in this runtime; unknown is not proof of non-commit; never replay a write automatically"));
        }
    }
    strip(&mut reply);
    Ok(serde_json::to_vec(&reply)?)
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

pub(crate) fn startup_expectation(arguments: impl Iterator<Item = std::ffi::OsString>)
    -> Result<respire_host_control::lifecycle_io::AccountRuntimeExpectation> {
    use respire_host_control::lifecycle_io::AccountRuntimeExpectation;
    let arguments: Vec<_> = arguments.collect();
    match arguments.as_slice() {
        [] => Ok(AccountRuntimeExpectation::Startup),
        [flag] if flag == "--require-unlocked" => Ok(AccountRuntimeExpectation::Unlock),
        [flag] if flag == "--locked-after-full-logout" => Ok(AccountRuntimeExpectation::LockedAfterFullLogout),
        _ => anyhow::bail!("unsupported compatibility startup credential expectation"),
    }
}

pub(crate) fn serve() -> Result<()> {
    let expectation = startup_expectation(std::env::args_os().skip(2))
        .context("startup arguments")?;
    respire_client_host::roots::validate_client_environment()
        .context("client environment")?;
    crate::runtime_policy::require_host("Client2 compatibility startup")
        .context("host policy")?;
    crate::autostart::check_direct_access()
        .context("direct access policy")?;
    #[cfg(windows)]
    respire_spawn::confine_supervisor_tree()
        .context("owned process confinement")?;
    let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(unix)]
    {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, interrupted.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, interrupted.clone())?;
    }
    #[cfg(target_os = "macos")]
    {
        let interrupted = Arc::clone(&interrupted);
        // Only the guardian holds the write end; EOF also covers its SIGKILL.
        std::thread::spawn(move || {
            let mut byte = [0];
            if let Err(error) = std::io::stdin().read(&mut byte) {
                eprintln!("compatibility guardian pipe failed: {error}");
            }
            interrupted.store(true, Ordering::Release);
        });
    }
    let root = respire_client_host::paths::main_data_dir();
    anyhow::ensure!(!root.join("runtime/autostart/registration.json").exists(),
        "compatibility host cannot replace a registered service");
    let public_port = crate::net_rpc::rpc_port();
    let listener = TcpListener::bind(("127.0.0.1", public_port))
        .context("public listener bind")?;
    let reservation = TcpListener::bind(("127.0.0.1", 0))
        .context("Runtime port reservation")?;
    let port = reservation.local_addr()?.port();
    let executable = crate::rpc::resolve_runtime_executable()
        .context("Runtime executable resolution")?
        .canonicalize().context("Runtime executable path")?;
    let digest = hex::encode(Sha256::digest(std::fs::read(&executable)
        .context("Runtime image read")?));
    let arguments = vec![std::ffi::OsString::from("serve"), "--port".into(), port.to_string().into()];
    drop(reservation);
    // Keep authorization and plugin/credential exchange in this resident host, not its launcher.
    let (mut child, instance_id) = crate::autostart::spawn_authorized_runtime(&executable, &arguments, None)
        .context("Runtime spawn")?;
    let pid = child.id();
    let mut stage = "Runtime readiness";
    let startup = (|| -> Result<_> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let health: crate::net_rpc::Health = loop {
            if let Some(status) = child.try_wait()? {
                stage = "owned Runtime exited before readiness";
                return Err(anyhow::anyhow!("owned Runtime exited before readiness").context(status));
            }
            if let Ok(ready) = health_at(port) {
                if ready["startup_complete"] == true {
                    break serde_json::from_value(ready)?;
                }
            }
            anyhow::ensure!(Instant::now() < deadline,
                "Runtime readiness is uncertain for child {pid}; inspect before retry");
            std::thread::sleep(Duration::from_millis(100));
        };
        stage = "Runtime identity verification";
        let (installation, profile) = respire_client_host::config::control_roots()?;
        anyhow::ensure!(child.try_wait()?.is_none() && health.pid == pid && health.image_sha256 == digest
            && health.instance_id == instance_id && !health.account_id.is_empty() && health.generation > 0
            && crate::runtime_fetch::version_in_accept(&health.runtime_version)
            && Path::new(&health.installation_root).canonicalize()? == installation.canonicalize()?
            && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?,
            "Runtime readiness does not match the selected child and installation");
        let backend = Arc::new(Backend { port, health, executable, public_port,
            host_executable: visible_path(std::env::current_exe()?)?,
            host_image_sha256: hex::encode(Sha256::digest(std::fs::read(std::env::current_exe()?)?)),
            last_health: Mutex::new(serde_json::from_value(health_at(port)?)?) });
        backend.verify(&serde_json::from_value(health_at(port)?)?)?;
        stage = "Runtime credential confirmation";
        expectation.confirm_credentials(&backend.health)?;
        stage = "compatibility listener creation";
        let server = tiny_http::Server::from_listener(listener, None)
            .map_err(|error| anyhow::anyhow!("cannot create compatibility listener: {error}"))?;
        Ok((backend, server))
    })();
    let (backend, server) = match startup {
        Ok(ready) => ready,
        Err(error) => {
            let error = error.context(stage);
            // Stop only the child we spawned; a delayed startup must not race the next owner.
            let cleanup = (|| -> Result<()> {
                if child.try_wait().context("could not inspect unready Runtime child")?.is_none() {
                    child.kill().context("could not stop unready Runtime child")?;
                }
                child.wait().context("could not reap unready Runtime child")?;
                Ok(())
            })();
            return match cleanup {
                Ok(()) => Err(error).with_context(||
                    "Runtime startup failed; original data and recovery records retained".to_owned()),
                Err(cleanup_error) => Err(cleanup_error).context(error)
                    .context("owned Runtime cleanup failed after startup failure")
                    .with_context(|| format!(
                        "Runtime startup failed; original data and recovery records retained; owned child {pid} cleanup failed")),
            };
        }
    };
    if let Err(error) = publish_ready(&json!({"startup_complete":true, "pid":std::process::id(),
        "exe":backend.host_executable, "bin":crate::VERSION, "port":public_port,
        "installation_root":backend.health.installation_root,
        "backend_port":backend.port, "backend_health":backend.health})) {
        // The verified host remains available for inspection and normal drain;
        // losing a startup pipe must not abandon its live Runtime child.
        eprintln!("compatibility startup response unavailable: {error}");
    }
    let active = Arc::new(AtomicUsize::new(0));
    let mut exited = None;
    let mut shutdown_requested = false;
    let mut stop_operation = None;
    let mut shutdown_error = None;
    loop {
        if exited.is_none() { exited = child.try_wait()?; }
        if let Some(status) = exited {
            if active.load(Ordering::Acquire) != 0 {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            let final_health = backend.last_health.lock().map_err(|_| anyhow::anyhow!("health state poisoned"))?;
            crate::net_rpc::final_stop_receipt(&final_health, stop_operation.as_deref())?;
            anyhow::ensure!(status.success(), "Runtime exited unsuccessfully after drain");
            if let Some(error) = shutdown_error { return Err(error); }
            return Ok(());
        }
        if interrupted.load(Ordering::Acquire) && !shutdown_requested {
            // One signal-driven stop request only. Unknown outcomes remain
            // inspectable; never replay or abandon the still-owned child.
            shutdown_requested = true;
            match backend.stop_owned() {
                Ok(operation) => stop_operation = Some(operation),
                Err(error) => {
                    eprintln!("compatibility shutdown is unconfirmed; inspect before retry: {error:#}");
                    shutdown_error = Some(error);
                }
            }
        }
        let Some(mut request) = server.recv_timeout(Duration::from_millis(50))? else { continue; };
        if shutdown_requested && !matches!(request.url(), "/api/health" | "/api/runtime/stop") {
            let _ = request.respond(tiny_http::Response::from_string("host is draining").with_status_code(503));
            continue;
        }
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

// Unlike runtime_process_identity, this inspects a CLI host without requiring
// the Runtime role. The caller separately proves that it owns the public socket.
fn host_process(pid: u32) -> Result<(PathBuf, String)> {
    let before = crate::autostart::process_birth(pid)?
        .context("compatibility host process is not running")?;
    #[cfg(windows)]
    let executable = respire_spawn::process_identity(pid)?
        .context("compatibility host process disappeared")?.executable;
    #[cfg(target_os = "linux")]
    let executable = std::fs::read_link(format!("/proc/{pid}/exe"))?;
    #[cfg(all(unix, not(target_os = "linux")))]
    let executable = {
        let output = Command::new("/bin/ps").args(["-ww", "-p", &pid.to_string(), "-o", "comm="])
            .env("LC_ALL", "C").output()?;
        anyhow::ensure!(output.status.success(), "cannot inspect compatibility host image");
        PathBuf::from(String::from_utf8(output.stdout)?.trim())
    };
    anyhow::ensure!(crate::autostart::process_birth(pid)?.as_deref() == Some(before.as_str()),
        "compatibility host changed during OS identity inspection");
    Ok((executable.canonicalize()?, before))
}

// Bind the exact IPv4 loopback endpoint, not an unrelated interface with the
// same port. Missing OS tooling and ambiguous ownership both fail closed.
#[cfg(target_os = "linux")]
fn loopback_listener(port: u16, pid: u32) -> Result<u32> {
    let loopback = format!("0100007F:{port:04X}");
    let wildcard = format!("00000000:{port:04X}");
    let mut inodes = std::collections::BTreeSet::new();
    for line in std::fs::read_to_string("/proc/net/tcp")?.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        anyhow::ensure!(fields.len() >= 10, "invalid OS TCP listener record");
        if fields[3] == "0A" && (fields[1] == loopback || fields[1] == wildcard) {
            anyhow::ensure!(fields[9] != "0", "OS listener inode is missing");
            inodes.insert(fields[9].to_owned());
        }
    }
    anyhow::ensure!(inodes.len() == 1, "compatibility loopback listener is unavailable or ambiguous");
    let inode = inodes.into_iter().next().context("compatibility listener is missing")?;
    let socket = format!("socket:[{inode}]");
    // Inspect only the claimed process: the kernel socket inode, not the health
    // response, must prove its ownership. No scan of inaccessible foreign PIDs.
    for entry in std::fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        match std::fs::read_link(entry.path()) {
            Ok(target) if target.as_os_str() == std::ffi::OsStr::new(&socket) => return Ok(pid),
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("claimed compatibility host does not own the OS listener")
}

#[cfg(windows)]
fn windows_listener_owner(output: &[u8], port: u16) -> Result<u32> {
    let local = format!("127.0.0.1:{port}");
    let wildcard = format!("0.0.0.0:{port}");
    let mut owners = std::collections::BTreeSet::new();
    for line in output.split(|byte| *byte == b'\n') {
        let fields: Vec<_> = line.split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty()).collect();
        // netstat headers use the system code page; TCP records must be ASCII.
        if fields.first().copied() != Some(b"TCP".as_slice()) { continue; }
        anyhow::ensure!(line.is_ascii() && fields.len() == 5, "invalid OS TCP listener record");
        if fields[3] == b"LISTENING" && (fields[1] == local.as_bytes() || fields[1] == wildcard.as_bytes()) {
            anyhow::ensure!(fields[4].iter().all(u8::is_ascii_digit), "invalid OS TCP listener PID");
            owners.insert(std::str::from_utf8(fields[4])?.parse::<u32>()?);
        }
    }
    anyhow::ensure!(owners.len() == 1 && !owners.contains(&0),
        "compatibility loopback listener ownership is unavailable or ambiguous");
    owners.into_iter().next().context("compatibility listener is missing")
}

#[cfg(not(target_os = "linux"))]
fn loopback_listener(port: u16, _pid: u32) -> Result<u32> {
    #[cfg(unix)]
    let mut owners = std::collections::BTreeSet::new();
    #[cfg(windows)]
    {
        let output = Command::new("netstat").args(["-ano", "-p", "tcp"]).output()?;
        anyhow::ensure!(output.status.success(), "cannot inspect compatibility listener");
        return windows_listener_owner(&output.stdout, port);
    }
    #[cfg(unix)]
    {
        let output = Command::new("/usr/sbin/lsof")
            .args(["-nP", &format!("-i4TCP:{port}"), "-sTCP:LISTEN", "-Fpn"]).output()?;
        anyhow::ensure!(output.status.success(), "cannot inspect compatibility listener");
        let local = format!("127.0.0.1:{port}");
        let wildcard = format!("*:{port}");
        let mut pid = None;
        for line in String::from_utf8(output.stdout)?.lines() {
            if let Some(value) = line.strip_prefix('p') { pid = Some(value.parse::<u32>()?); }
            if let Some(value) = line.strip_prefix('n') {
                if value == local || value == wildcard {
                    owners.insert(pid.context("listener process identity is missing")?);
                }
            }
        }
    }
    #[cfg(unix)]
    {
        anyhow::ensure!(owners.len() == 1 && !owners.contains(&0),
            "compatibility loopback listener ownership is unavailable or ambiguous");
        owners.into_iter().next().context("compatibility listener is missing")
    }
}

fn listener_matches(public: &Value, port: u16, listener: Option<u32>) -> Result<u32> {
    let pid = public["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0).context("compatibility host PID is invalid")?;
    anyhow::ensure!(listener == Some(pid),
        "compatibility host is not the verified OS listener; inspect before retry");
    anyhow::ensure!(public["public_port"] == port, "compatibility host port changed");
    Ok(pid)
}

fn verify_host(public: &Value, executable: &Path, expected_pid: Option<u32>) -> Result<()> {
    let port = crate::net_rpc::rpc_port();
    let claimed = public["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 0).context("compatibility host PID is invalid")?;
    let pid = listener_matches(public, port, Some(loopback_listener(port, claimed)?))?;
    anyhow::ensure!(expected_pid.is_none_or(|expected| expected == pid),
        "compatibility listener is not the launched child");
    let (image, birth) = host_process(pid)?;
    let canonical = executable.canonicalize()?;
    anyhow::ensure!(image == canonical && Sha256::digest(std::fs::read(&image)?)
        == Sha256::digest(std::fs::read(std::env::current_exe()?)?),
        "compatibility listener is not the stable CLI image");
    let (root, profile) = respire_client_host::config::control_roots()?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    // Only the same-byte CLI image actually owning the socket can supply these
    // role/root declarations. A foreign listener cannot borrow a real CLI PID.
    anyhow::ensure!(public["compatibility_host"] == "client2-v0256"
        && public["bin"] == crate::VERSION && public["host_birth"] == birth
        && public["host_image_sha256"] == hex::encode(Sha256::digest(std::fs::read(&image)?))
        && public["exe"].as_str().is_some_and(|value| Path::new(value).canonicalize().ok().as_ref() == Some(&canonical))
        && public["installation_root"].as_str().is_some_and(|value| Path::new(value).canonicalize().ok().as_ref() == Some(&root))
        && public["data_dir"].as_str().is_some_and(|value| Path::new(value).canonicalize().ok().as_ref() == Some(&profile)),
        "compatibility host identity does not match this installation");
    let health = crate::net_rpc::health()?;
    anyhow::ensure!(crate::rpc::runtime_acceptable(&health)?
        && public["backend_pid"] == health.pid
        && public["backend_instance_id"] == health.instance_id
        && public["backend_process_start_id"] == health.process_start_id,
        "compatibility host backend binding changed");
    let runtime = crate::rpc::resolve_runtime_executable()?.canonicalize()?;
    anyhow::ensure!(health.image_sha256 == hex::encode(Sha256::digest(std::fs::read(&runtime)?))
        && Path::new(&health.installation_root).canonicalize()? == root.canonicalize()?,
        "compatibility backend image or installation changed");
    let backend = Backend { port: 0, health: health.clone(), executable: runtime,
        public_port: port, host_executable: canonical,
        host_image_sha256: String::new(), last_health: Mutex::new(health.clone()) };
    backend.verify(&health)?;
    anyhow::ensure!(host_process(pid)? == (image, birth)
        && loopback_listener(port, pid)? == pid,
        "compatibility listener changed during verification");
    Ok(())
}

pub(crate) fn checked_executable() -> Result<PathBuf> {
    let executable = visible_path(crate::net_rpc::stable_bin_path().canonicalize()?)?;
    anyhow::ensure!(Sha256::digest(std::fs::read(&executable)?)
        == Sha256::digest(std::fs::read(std::env::current_exe()?)?),
        "Client2 requires the same verified CLI bytes at the stable bin path");
    Ok(executable)
}

/// Caller retains the existing takeover lock. This never takes over a healthy
/// strict or managed owner, and never retries an uncertain spawn.
pub(crate) fn start_locked_with_expectation(
    expectation: respire_host_control::lifecycle_io::AccountRuntimeExpectation) -> Result<()> {
    crate::runtime_policy::require_host("Client2 compatibility startup")?;
    anyhow::ensure!(crate::autostart::lifecycle_boot_token().is_none(),
        "compatibility startup cannot inherit account maintenance");
    let executable = checked_executable()?;
    if crate::rpc::probe_runtime()?.is_some() {
        return verify_host(&health_at(crate::net_rpc::rpc_port())?, &executable, None);
    }
    let mut arguments = Vec::new();
    #[cfg(target_os = "macos")]
    arguments.push(std::ffi::OsString::from("--client2-host-supervisor-internal"));
    #[cfg(not(target_os = "macos"))]
    arguments.push(std::ffi::OsString::from("--client2-host-internal"));
    match expectation {
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::Unlock => arguments.push("--require-unlocked".into()),
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::LockedAfterFullLogout => arguments.push("--locked-after-full-logout".into()),
        respire_host_control::lifecycle_io::AccountRuntimeExpectation::Startup => {}
    }
    let mut child = respire_spawn::spawn_binary_with_readiness(&executable, &arguments)?;
    let ready = receive_ready(&mut child)?;
    anyhow::ensure!(ready["startup_complete"] == true, "{}", ready["error"].as_str().context("startup error missing")?);
    #[cfg(target_os = "macos")]
    let host_pid = guarded_host_pid(&ready, child.id(), &executable,
        &respire_client_host::paths::main_data_dir(), crate::net_rpc::rpc_port())?;
    #[cfg(not(target_os = "macos"))]
    let host_pid = {
        anyhow::ensure!(ready["pid"] == child.id(), "readiness does not identify the owned host child");
        child.id()
    };
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline {
        anyhow::ensure!(child.try_wait()?.is_none(), "compatibility host exited before readiness");
        if let Ok(public) = health_at(crate::net_rpc::rpc_port()) {
            return verify_host(&public, &executable, Some(host_pid));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("compatibility startup is uncertain for child {}; inspect before retry", child.id())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn guardian_readiness_is_bound_to_the_owned_launch() -> Result<()> {
        let executable = std::env::current_exe()?.canonicalize()?;
        let root = std::env::temp_dir().canonicalize()?;
        let ready = json!({"startup_complete":true, "pid":123, "guardian_pid":456,
            "exe":executable, "installation_root":root, "bin":crate::VERSION, "port":15169});
        assert_eq!(guarded_host_pid(&ready, 456, &executable, &root, 15169)?, 123);
        let frame = format!("{ready}\n");
        assert_eq!(read_ready(frame.as_bytes())?, ready);
        assert!(read_ready(b"".as_slice()).is_err());
        let failed = json!({"startup_complete":false, "error":"public listener bind (io::AddrInUse)"});
        let frame = format!("{failed}\n");
        assert_eq!(read_ready(frame.as_bytes())?, failed);
        for (key, value) in [("pid", json!(0)), ("pid", json!(456)),
            ("pid", json!(u64::MAX)), ("guardian_pid", json!(789)),
            ("startup_complete", json!(false)), ("bin", json!("foreign")),
            ("port", json!(15170)), ("exe", json!(root)),
            ("installation_root", json!(executable))] {
            let mut wrong = ready.clone();
            wrong[key] = value;
            assert!(guarded_host_pid(&wrong, 456, &executable, &root, 15169).is_err(), "{key}");
        }
        Ok(())
    }

    #[test]
    fn legacy_rpc_identity_is_supplied_and_projected_by_the_host() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let root = tempfile::tempdir()?;
        let previous = std::env::var_os("RSRS_DATA_DIR");
        std::env::set_var("RSRS_DATA_DIR", root.path());
        let result = (|| -> Result<()> {
        let health: crate::net_rpc::Health = serde_json::from_value(json!({
            "server":"respire","bin":"fixture","v":1,"pid":42,"account_id":"account",
            "instance_id":"instance","generation":7,"installation_root":root.path()
        }))?;
        let raw = serde_json::to_vec(&json!({"v":1,"id":"original","method":"cli.exec","args":["--json","status"]}))?;
        let (bound, original) = prepare_legacy_rpc(&raw, &health)?;
        let bound: respire_protocol::RpcRequest = serde_json::from_slice(&bound)?;
        assert_eq!(bound.scope, Some(crate::net_rpc::request_scope(&health)?));
        assert_eq!(bound.operation_id.as_deref(), Some("original"));
        let original = original.context("missing legacy projection")?;
        let response = json!({"v":1,"id":"original","ok":true,"exit":0,"bin":"fixture",
            "scope":bound.scope,"operation_id":"original","idempotency_key":"original"});
        let projected: Value = serde_json::from_slice(&project_legacy_rpc(&serde_json::to_vec(&response)?, &original, &health)?)?;
        for field in ["scope","operation_id","idempotency_key"] { assert!(projected.get(field).is_none()); }
        let mut changed = response; changed["scope"]["instance_id"] = json!("foreign");
        assert!(project_legacy_rpc(&serde_json::to_vec(&changed)?, &original, &health).is_err());
        let mut mixed = original; mixed.operation_id = Some("foreign".into());
        assert!(prepare_legacy_rpc(&serde_json::to_vec(&mixed)?, &health).is_err());
        Ok(())
        })();
        match previous {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        result
    }

    #[test]
    fn compatibility_boundary_rejects_foreign_and_ambiguous_requests() -> Result<()> {
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
        // An untrusted endpoint cannot borrow the identity of this real process.
        // OS listener ownership must independently match, even with a valid PID.
        let pid = std::process::id();
        let (image, birth) = host_process(pid)?;
        assert_eq!(image, std::env::current_exe()?.canonicalize()?);
        assert!(!birth.is_empty());
        assert_eq!(host_process(pid)?, (image, birth));
        assert!(host_process(0).is_err());
        #[cfg(target_os = "linux")]
        {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let port = listener.local_addr()?.port();
            assert_eq!(loopback_listener(port, pid)?, pid);
            assert!(loopback_listener(port, 0).is_err());
            // A genuine socket in this process on another loopback address
            // cannot prove ownership of the public 127.0.0.1 endpoint.
            let other = TcpListener::bind(("127.0.0.2", port))?;
            drop(listener);
            assert!(loopback_listener(port, pid).is_err());
            drop(other);
        }
        #[cfg(windows)]
        {
            let header = b"\r\n\xbb\xee\xb6\xaf\xc1\xac\xbd\xd3\r\n";
            let row = b"  TCP  127.0.0.1:15169  0.0.0.0:0  LISTENING  123\r\n";
            let mut output = header.to_vec(); output.extend_from_slice(row);
            assert_eq!(windows_listener_owner(&output, 15169)?, 123);
            assert_eq!(windows_listener_owner(&[output.as_slice(), row].concat(), 15169)?, 123);
            assert_eq!(windows_listener_owner(b"TCP 0.0.0.0:15169 0.0.0.0:0 LISTENING 123\n", 15169)?, 123);
            for invalid in [
                b"TCP 127.0.0.2:15169 0.0.0.0:0 LISTENING 123\n".as_slice(),
                b"TCP 127.0.0.1:151690 0.0.0.0:0 LISTENING 123\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 ESTABLISHED 123\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING 0\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING +123\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING 4294967296\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING \xff\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING\n",
                b"TCP 127.0.0.1:15169 0.0.0.0:0 LISTENING 123 extra\n",
            ] { assert!(windows_listener_owner(invalid, 15169).is_err()); }
            let other = b"TCP 0.0.0.0:15169 0.0.0.0:0 LISTENING 456\n";
            assert!(windows_listener_owner(&[row.as_slice(), other].concat(), 15169).is_err());
            assert!(windows_listener_owner(header, 15169).is_err());
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            assert_eq!(loopback_listener(listener.local_addr()?.port(), pid)?, pid);
        }
        let claimed = json!({"pid":pid, "public_port":15169,
            "compatibility_host":"client2-v0256"});
        assert!(listener_matches(&claimed, 15169, None).is_err());
        assert!(listener_matches(&claimed, 15169, Some(pid.saturating_add(1))).is_err());
        assert!(listener_matches(&claimed, 15170, Some(pid)).is_err());
        assert!(listener_matches(&json!({"pid":0,"public_port":15169}), 15169, Some(0)).is_err());
        assert!(read_ready(&b"{}\n"[..]).is_err());
        assert!(read_ready(&b"{\"startup_complete\":true}"[..]).is_err());
        Ok(())
    }
}
