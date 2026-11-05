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
    let binary = binary.canonicalize()?;
    let (root, profile) = prepare_launch_roots()?;
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
