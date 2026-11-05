//! Local launch-grant producer. The inherited token identifies one private grant.
use super::super::{
    lifecycle, private_write, read_registration, recovery::account_identity_source,
};
use anyhow::{Context, Result};
use respire_commands::output::{ResultEnvelope, Status};
use respire_protocol::{
    ControlBinding, HostControlLaunchGrant, HostControlOperation, HostControlParams, RpcRequest,
    RpcResponse, HOST_CONTROL_MAX_FRAME_BYTES, HOST_CONTROL_SCHEMA_V,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(super) fn spawn(
    binary: &Path,
    arguments: &[OsString],
    managed_id: Option<&str>,
) -> Result<(Child, String)> {
    let binary = binary.canonicalize()?;
    let (root, profile) = prepare_launch_roots()?;
    let (grant, nonce) = prepare_grant(
        &binary,
        &root,
        &profile,
        managed_id,
        launch_port(arguments)?,
    )?;
    let path = root
        .join("runtime")
        .join("autostart")
        .join("launch")
        .join(format!("launch-{nonce}.json"));
    private_write(&path, &serde_json::to_vec(&grant)?, None)?;
    let token = format!("launch-v1:{nonce}");
    match respire_spawn::spawn_binary_with_boot_token(&binary, arguments, Some(&token)) {
        Ok(child) => Ok((child, nonce)),
        Err(error) => {
            fs::remove_file(&path).with_context(|| {
                format!("unused launch grant cleanup failed after spawn error: {error}")
            })?;
            Err(error).context("authorized runtime could not be spawned")
        }
    }
}

fn prepare_grant(
    binary: &Path,
    root: &Path,
    profile: &Path,
    managed_id: Option<&str>,
    port: u16,
) -> Result<(serde_json::Value, String)> {
    let maintenance = lifecycle::launch_maintenance_binding(profile, managed_id)?;
    let registration = read_registration(root)?;
    if let Some(config) = &registration {
        lifecycle::owned(config)?;
        if managed_id.is_some() {
            anyhow::ensure!(
                std::env::current_exe()?.canonicalize()? == config.executable.canonicalize()?,
                "managed supervisor differs from the registered CLI"
            );
        }
        anyhow::ensure!(
            !config.maintenance || maintenance.is_some(),
            "registration maintenance lacks an active launch controller"
        );
        match managed_id {
            Some(id) => anyhow::ensure!(
                config.id == id && config.enabled && !config.manually_stopped,
                "managed launch does not match an enabled registration"
            ),
            None => anyhow::ensure!(
                (!config.enabled && !config.manually_stopped) || maintenance.is_some(),
                "registered runtime requires its host lifecycle coordinator"
            ),
        }
    } else {
        anyhow::ensure!(
            managed_id.is_none(),
            "managed launch registration is missing"
        );
    }
    let supervisor_pid = std::process::id();
    let supervisor_birth = super::super::manager::process_birth(supervisor_pid)?
        .context("launch supervisor process identity is unavailable")?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let issued_at_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("launch clock overflow")?;
    let expires_at_ms = issued_at_ms
        .checked_add(60_000)
        .context("launch expiry overflow")?;
    let account_source = account_identity_source(profile)?;
    let grant = json!({
        "schema_version": 1,
        "protocol_version": respire_commands::rpc_worker::PROTOCOL_V,
        "nonce": nonce,
        "instance_id": nonce,
        "installation_root": root,
        "installation_id": hash(root.display().to_string().as_bytes()),
        "profile": profile,
        "account_id": hash(account_source.as_bytes()),
        // Phase one starts a fresh worker; this is not a persistent owner generation.
        "sync_generation": 0,
        "image_path": binary,
        "image_sha256": hash_file(binary)?,
        "supervisor_pid": supervisor_pid,
        "supervisor_birth": supervisor_birth,
        "managed_id": managed_id,
        "registration_sha256": registration.as_ref().and_then(|config| config.digest.as_deref()),
        "maintenance": maintenance,
        "port": port,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    });
    Ok((grant, nonce))
}

/// One private read against an authenticated installed image; never starts serving.
pub(super) fn control_memory_revision() -> Result<ResultEnvelope> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let binary = crate::runtime_fetch::managed_runtime_path()?
        .context("host control requires an installed managed Runtime")?
        .canonicalize()?;
    let manifest = crate::runtime_fetch::read_manifest()?
        .context("host control Runtime manifest is missing")?;
    anyhow::ensure!(
        crate::runtime_fetch::version_in_accept(&manifest.version)
            && hash_file(&binary)?.eq_ignore_ascii_case(&manifest.sha256),
        "host control Runtime version or image does not match the managed manifest"
    );
    let roots = respire::service::resolved_roots()?;
    let root = roots.installation_root.canonicalize()?;
    let profile = roots.account_data_root.canonicalize()?;
    let registration = read_registration(&root)?;
    let managed_id = registration
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped)
        .map(|config| config.id.as_str());
    let (grant, _) = prepare_grant(
        &binary,
        &root,
        &profile,
        managed_id,
        crate::net_rpc::rpc_port(),
    )?;
    let grant: HostControlLaunchGrant = serde_json::from_value(grant)?;
    anyhow::ensure!(
        grant.image_path == binary && grant.image_sha256.eq_ignore_ascii_case(&manifest.sha256),
        "host control image changed while preparing authorization"
    );
    let expected_account_id = respire_client_host::identity::session_user_of_dir(&profile)?
        .map(|user| hash(user.as_bytes()));
    anyhow::ensure!(
        grant.account_id
            == expected_account_id
                .clone()
                .unwrap_or_else(|| hash(profile.display().to_string().as_bytes())),
        "host control account changed while preparing authorization"
    );
    let params = HostControlParams {
        schema_version: HOST_CONTROL_SCHEMA_V,
        binding: ControlBinding {
            installation_root: root,
            profile: profile.clone(),
            launch_id: grant.instance_id.clone(),
            expected_account_id,
        },
    };
    let request = RpcRequest {
        v: respire_commands::rpc_worker::PROTOCOL_V,
        id: uuid::Uuid::new_v4().to_string(),
        method: HostControlOperation::MemoryRevision.method().to_owned(),
        args: vec![serde_json::to_string(&params)?],
        scope: None,
        operation_id: None,
        idempotency_key: None,
        parent_operation_id: None,
        queue_wait_ms: None,
        lifecycle: None,
    };
    let mut frames = Vec::new();
    for bytes in [serde_json::to_vec(&grant)?, serde_json::to_vec(&request)?] {
        anyhow::ensure!(
            !bytes.is_empty() && bytes.len() <= HOST_CONTROL_MAX_FRAME_BYTES,
            "host control request frame exceeds the protocol limit"
        );
        frames.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
        frames.extend_from_slice(&bytes);
    }
    anyhow::ensure!(Instant::now() < deadline, "host control deadline exceeded");
    let mut command = Command::new(&binary);
    command
        .arg("--host-control-internal")
        .env_remove("GH_TOKEN")
        .env_remove("GITHUB_TOKEN")
        .env_remove("RSRS_RUNTIME_BOOT_TOKEN");
    let mut child = respire_spawn::spawn_control_helper(&mut command)
        .context("cannot start owned host control Runtime")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let (input_sender, input_receiver) = std::sync::mpsc::channel();
    let mut worker = None;
    let outcome = (|| -> Result<ResultEnvelope> {
        let mut input = child
            .stdin
            .take()
            .context("missing host control input pipe")?;
        let mut output = child
            .stdout
            .take()
            .context("missing host control output pipe")?;
        worker = Some(
            std::thread::Builder::new()
                .name("host-control-io".into())
                .spawn(move || {
                    let response = (|| -> Result<RpcResponse<ResultEnvelope>> {
                        let written = input.write_all(&frames).and_then(|()| input.flush());
                        // Return the writer before blocking on stdout so the owner can revoke it.
                        input_sender.send(input).map_err(|_| {
                            anyhow::anyhow!("host control input owner was released")
                        })?;
                        written.context("host control request write failed")?;
                        let mut length = [0u8; 4];
                        output
                            .read_exact(&mut length)
                            .context("missing host control response frame")?;
                        let length = u32::from_be_bytes(length) as usize;
                        anyhow::ensure!(
                            length > 0 && length <= HOST_CONTROL_MAX_FRAME_BYTES,
                            "invalid host control response frame size"
                        );
                        let mut bytes = vec![0u8; length];
                        output
                            .read_exact(&mut bytes)
                            .context("incomplete host control response frame")?;
                        let response = serde_json::from_slice(&bytes)
                            .map_err(|_| anyhow::anyhow!("invalid host control response JSON"))?;
                        let mut extra = [0u8; 1];
                        anyhow::ensure!(
                            output.read(&mut extra)? == 0,
                            "extra host control response bytes"
                        );
                        Ok(response)
                    })();
                    let _ = sender.send(response);
                })?,
        );
        let response = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .context("host control response deadline or channel failure")?;
        anyhow::ensure!(
            Instant::now() < deadline,
            "host control response deadline exceeded"
        );
        let envelope = validate_control_response(response?, &request, &profile, child.id())?;
        loop {
            anyhow::ensure!(
                Instant::now() < deadline,
                "host control exit deadline exceeded"
            );
            if let Some(status) = child.try_wait()? {
                anyhow::ensure!(
                    status.success(),
                    "host control Runtime exited unsuccessfully"
                );
                return Ok(envelope);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    let cleanup = if outcome.is_err() {
        stop_control_child(&mut child)
    } else {
        Ok(())
    };
    // Keep stdin until exit confirmation; on failure release it to revoke the channel.
    drop(input_receiver);
    drop(receiver);
    cleanup?;
    if let Some(worker) = worker {
        let until = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() {
            anyhow::ensure!(
                Instant::now() < until,
                "cleanup_failed owned_pid={}: host control I/O worker did not finish",
                child.id()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        worker.join().map_err(|_| {
            anyhow::anyhow!(
                "cleanup_failed owned_pid={}: host control I/O worker panicked",
                child.id()
            )
        })?;
    }
    outcome
}

fn stop_control_child(child: &mut Child) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(2);
    let kill_error = child.kill().err();
    loop {
        if control_exit_confirmed(
            child.id(),
            child.try_wait().map(|status| status.is_some()),
            Instant::now() >= until,
            kill_error.as_ref(),
        )? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn control_exit_confirmed(
    pid: u32,
    observation: std::io::Result<bool>,
    expired: bool,
    kill_error: Option<&std::io::Error>,
) -> Result<bool> {
    let reason = match observation {
        // try_wait(Some) has reaped the owned child, even if kill lost an exit race.
        Ok(true) => return Ok(true),
        Ok(false) if !expired => return Ok(false),
        Ok(false) => "exit confirmation deadline exceeded".to_owned(),
        Err(error) => format!("exit confirmation failed: {error}"),
    };
    match kill_error {
        Some(error) => {
            anyhow::bail!("cleanup_failed owned_pid={pid}: {reason}; kill failed: {error}")
        }
        None => anyhow::bail!("cleanup_failed owned_pid={pid}: {reason}"),
    }
}

fn validate_control_response(
    response: RpcResponse<ResultEnvelope>,
    request: &RpcRequest,
    profile: &Path,
    pid: u32,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        response.v == request.v
            && response.id == request.id
            && response.bin == "rsrs-runtime"
            && response.pid == Some(pid)
            && response.scope.is_none()
            && response.operation_id.is_none()
            && response.idempotency_key.is_none()
            && response.web_url.is_none(),
        "host control response identity mismatch"
    );
    anyhow::ensure!(
        response.ok && response.exit == 0 && response.error.is_none() && response.code.is_none(),
        "host control memory revision failed"
    );
    let envelope = response
        .envelope
        .context("missing host control result envelope")?;
    anyhow::ensure!(
        envelope.command == "memory-revision"
            && matches!(envelope.status, Status::Ok)
            && envelope.errors.is_empty(),
        "invalid host control result envelope"
    );
    let mut ready = envelope
        .items
        .iter()
        .filter(|item| item.name == "control_ready");
    anyhow::ensure!(
        ready
            .next()
            .is_some_and(|item| matches!(item.status, Status::Ok) && item.value == "true")
            && ready.next().is_none(),
        "host control authorization was not confirmed"
    );
    let actual_profile = envelope.summary["profile"]
        .as_str()
        .context("missing host control profile")?;
    anyhow::ensure!(
        Path::new(actual_profile).canonicalize()? == profile
            && envelope.summary["revision"]
                .as_str()
                .is_some_and(|value| !value.is_empty()),
        "host control revision profile or value is invalid"
    );
    if let Some(data_dir) = response.data_dir {
        anyhow::ensure!(
            Path::new(&data_dir).canonicalize()? == profile,
            "host control data directory mismatch"
        );
    }
    Ok(envelope)
}

fn prepare_launch_roots() -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    // Resolve strict configuration and reject parent traversal before creating roots.
    let roots = respire::service::resolved_roots()?;
    fs::create_dir_all(&roots.installation_root)?;
    fs::create_dir_all(&roots.account_data_root)?;
    Ok((
        roots.installation_root.canonicalize()?,
        roots.account_data_root.canonicalize()?,
    ))
}

fn launch_port(arguments: &[OsString]) -> Result<u16> {
    let mut found = None;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--port" {
            anyhow::ensure!(found.is_none(), "duplicate launch port");
            let port = arguments
                .next()
                .and_then(|value| value.to_str())
                .context("launch port is missing")?
                .parse::<u16>()?;
            anyhow::ensure!(port != 0, "launch port cannot be zero");
            found = Some(port);
        }
    }
    Ok(found.unwrap_or_else(crate::net_rpc::rpc_port))
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_roots_validate_before_creating_fresh_profiles() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Vec<(&'static str, Option<OsString>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
        let keys = ["RSRS_DATA_DIR", "RSRS_M3_DIR"];
        let _restore = Restore(
            keys.into_iter()
                .map(|key| (key, std::env::var_os(key)))
                .collect(),
        );
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().join("fresh installation");
        std::env::set_var("RSRS_DATA_DIR", &root);
        std::env::set_var("RSRS_M3_DIR", temporary.path().join("models"));
        assert!(!root.exists());
        let (installation, profile) = prepare_launch_roots()?;
        assert_eq!(installation, root.canonicalize()?);
        assert_eq!(profile, installation);
        assert!(!root.join("runtime").exists());

        let account = root.join("accounts/fresh profile");
        let config = root.join("client.json");
        fs::write(&config, serde_json::to_vec(&json!({"data_dir": account}))?)?;
        let (_, profile) = prepare_launch_roots()?;
        assert_eq!(profile, account.canonicalize()?);

        assert_eq!(
            account_identity_source(&profile)?,
            profile.display().to_string()
        );
        let session = profile.join("session.json");
        fs::write(&session, br#"{"user":"Fixture-Account"}"#)?;
        assert_eq!(account_identity_source(&profile)?, "Fixture-Account");
        for invalid in ["{", "{}", r#"{"user":42}"#, r#"{"user":""}"#] {
            fs::write(&session, invalid)?;
            assert!(account_identity_source(&profile).is_err());
            assert_eq!(fs::read_to_string(&session)?, invalid);
        }
        fs::remove_file(&session)?;
        fs::create_dir(&session)?;
        assert!(account_identity_source(&profile).is_err());
        fs::remove_dir(&session)?;

        let request: RpcRequest = serde_json::from_value(json!({
            "v": respire_commands::rpc_worker::PROTOCOL_V,
            "id": uuid::Uuid::new_v4().to_string(),
            "method": HostControlOperation::MemoryRevision.method(),
        }))?;
        let pid = 4242;
        let revision = "0123456789abcdef0123456789abcdef";
        let response: RpcResponse<ResultEnvelope> = serde_json::from_value(json!({
            "v": request.v,
            "id": request.id,
            "bin": "rsrs-runtime",
            "pid": pid,
            "ok": true,
            "exit": 0,
            "envelope": ResultEnvelope::new(
                "memory-revision",
                Status::Ok,
                json!({"profile": profile, "revision": revision}),
                vec![respire_commands::output::Item::new("control_ready", Status::Ok, "true")],
            ),
        }))?;
        assert_eq!(
            validate_control_response(response.clone(), &request, &profile, pid)?.summary
                ["revision"],
            revision
        );

        let mut wrong_id = response.clone();
        wrong_id.id = uuid::Uuid::new_v4().to_string();
        assert!(validate_control_response(wrong_id, &request, &profile, pid).is_err());
        let mut wrong_pid = response.clone();
        wrong_pid.pid = Some(pid + 1);
        assert!(validate_control_response(wrong_pid, &request, &profile, pid).is_err());
        let mut wrong_profile = response.clone();
        wrong_profile
            .envelope
            .as_mut()
            .context("fixture envelope missing")?
            .summary["profile"] = json!(installation);
        assert!(validate_control_response(wrong_profile, &request, &profile, pid).is_err());
        let mut duplicate_ready = response.clone();
        duplicate_ready
            .envelope
            .as_mut()
            .context("fixture envelope missing")?
            .items
            .push(respire_commands::output::Item::new(
                "control_ready",
                Status::Ok,
                "true",
            ));
        assert!(validate_control_response(duplicate_ready, &request, &profile, pid).is_err());
        let mut scoped = response;
        scoped.scope = Some(respire_protocol::RuntimeRequestScope {
            account_id: "foreign-account".to_owned(),
            instance_id: "foreign-instance".to_owned(),
            generation: 0,
        });
        assert!(validate_control_response(scoped, &request, &profile, pid).is_err());

        assert!(!control_exit_confirmed(pid, Ok(false), false, None)?);
        assert!(control_exit_confirmed(pid, Ok(true), false, None)?);
        let kill_error = std::io::Error::other("fixture kill failed");
        assert!(control_exit_confirmed(
            pid,
            Ok(true),
            true,
            Some(&kill_error)
        )?);
        let timeout = control_exit_confirmed(pid, Ok(false), true, Some(&kill_error))
            .err()
            .context("cleanup deadline must fail closed")?
            .to_string();
        assert!(timeout.contains("cleanup_failed owned_pid=4242"));
        assert!(timeout.contains("exit confirmation deadline exceeded"));
        assert!(timeout.contains("fixture kill failed"));
        let observation_error = control_exit_confirmed(
            pid,
            Err(std::io::Error::other("fixture observation failed")),
            false,
            None,
        )
        .err()
        .context("cleanup observation error must fail closed")?
        .to_string();
        assert!(observation_error.contains("cleanup_failed owned_pid=4242"));
        assert!(observation_error.contains("fixture observation failed"));

        for invalid in ["{", r#"{"data_dir":42}"#] {
            fs::write(&config, invalid)?;
            assert!(prepare_launch_roots().is_err());
            assert_eq!(fs::read_to_string(&config)?, invalid);
        }
        let missing_account = root.join("must remain absent");
        fs::write(
            &config,
            serde_json::to_vec(&json!({"data_dir": missing_account.join("../escape")}))?,
        )?;
        assert!(prepare_launch_roots().is_err());
        assert!(!missing_account.exists() && !root.join("escape").exists());
        let missing = temporary.path().join("must remain absent");
        let unsafe_root = missing.join("..").join("escape");
        std::env::set_var("RSRS_DATA_DIR", &unsafe_root);
        assert!(prepare_launch_roots().is_err());
        assert!(!missing.exists() && !temporary.path().join("escape").exists());
        for invalid in ["", " "] {
            std::env::set_var("RSRS_DATA_DIR", invalid);
            assert!(prepare_launch_roots().is_err());
        }
        Ok(())
    }

    #[test]
    fn explicit_launch_port_is_exact_and_unambiguous() -> Result<()> {
        assert_eq!(
            launch_port(&["serve".into(), "--port".into(), "19169".into()])?,
            19169
        );
        for arguments in [
            vec!["--port".into()],
            vec!["--port".into(), "0".into()],
            vec![
                "--port".into(),
                "19169".into(),
                "--port".into(),
                "19170".into(),
            ],
        ] {
            assert!(launch_port(&arguments).is_err());
        }
        Ok(())
    }
}
