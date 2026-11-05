//! Local launch-grant producer. The inherited token identifies one private grant.
use super::super::{lifecycle, private_write, read_registration};
use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Child;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn spawn(
    binary: &Path,
    arguments: &[OsString],
    managed_id: Option<&str>,
) -> Result<(Child, String)> {
    let root = respire::service::main_data_dir().canonicalize()?;
    let profile = respire::service::data_dir().canonicalize()?;
    let binary = binary.canonicalize()?;
    let maintenance = lifecycle::launch_maintenance_binding(&profile, managed_id)?;
    let registration = read_registration(&root)?;
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
    let port = launch_port(arguments)?;
    let nonce = uuid::Uuid::new_v4().to_string();
    let issued_at_ms = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
        .context("launch clock overflow")?;
    let expires_at_ms = issued_at_ms
        .checked_add(60_000)
        .context("launch expiry overflow")?;
    let account = respire::service::session_user_of_dir(&profile);
    let account_source = if account.is_empty() {
        profile.display().to_string()
    } else {
        account
    };
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
        "image_sha256": hash_file(&binary)?,
        "supervisor_pid": supervisor_pid,
        "supervisor_birth": supervisor_birth,
        "managed_id": managed_id,
        "registration_sha256": registration.as_ref().and_then(|config| config.digest.as_deref()),
        "maintenance": maintenance,
        "port": port,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
    });
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
