//! Native login custody, owned exclusively by the host account coordinator.
use super::*;

fn login_entry(account: &str, backend: &str, slot: &str) -> Result<keyring::Entry> {
    anyhow::ensure!(account.starts_with("login-") && account.len() <= 128
        && account.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid login custody account");
    anyhow::ensure!(matches!(slot, "login-control" | "super" | "pass" | "legacy-secret"),
        "invalid login custody slot");
    #[cfg(target_os = "linux")]
    anyhow::ensure!(backend == "secret_service", "login custody requires persistent host storage");
    #[cfg(not(target_os = "linux"))]
    anyhow::ensure!(backend == "native", "login custody requires native host storage");
    entry("rsrs", &format!("{slot}:{account}"), backend)
        .map_err(|error| anyhow::anyhow!("login custody storage unavailable ({error:?})"))
}

pub fn read(account: &str, backend: &str, slot: &str) -> Result<Option<String>> {
    match login_entry(account, backend, slot)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => anyhow::bail!("login custody read failed ({:?})", credential_error(error)),
    }
}

/// The caller holds installation takeover; compare before replacement and read back.
pub fn write(account: &str, backend: &str, slot: &str, expected: Option<&str>, value: &str) -> Result<()> {
    let original = read(account, backend, slot)?;
    anyhow::ensure!(original.as_deref() == expected || original.as_deref() == Some(value),
        "login custody write conflicts with existing material; original retained");
    login_entry(account, backend, slot)?.set_password(value)
        .map_err(|error| anyhow::anyhow!("login custody write failed ({:?})", credential_error(error)))?;
    anyhow::ensure!(read(account, backend, slot)?.as_deref() == Some(value),
        "login custody readback mismatch; retain the original operation");
    Ok(())
}

pub fn remove(account: &str, backend: &str, slot: &str, expected: &str) -> Result<()> {
    let original = read(account, backend, slot)?;
    anyhow::ensure!(original.as_deref().is_none_or(|value| value == expected),
        "login custody cleanup conflicts with existing material; original retained");
    if original.is_some() {
        match login_entry(account, backend, slot)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {},
            Err(error) => anyhow::bail!("login custody cleanup failed ({:?})", credential_error(error)),
        }
    }
    anyhow::ensure!(read(account, backend, slot)?.is_none(), "login custody cleanup readback failed");
    Ok(())
}

/// Original session factors use the recorded backend, without process overrides.
pub fn session_material(bytes: &[u8], primary: Option<&str>)
    -> Result<respire_protocol::host_control::HostAuthSessionMaterial> {
    use respire_protocol::host_control::{HostAuthSessionMaterial, HostAuthVaultFactors as Factors};
    use sha2::{Digest, Sha256};
    let session: serde_json::Value = serde_json::from_slice(bytes)?;
    let version = session["vault_version"].as_u64().context("original session vault version missing")?;
    let (super_password, secret) = read_export_factors(&session)?;
    let factors = match version {
        1 => {
            let password = match primary {
                Some(value) => value.to_owned(),
                None => read_session_slot(&format!("pass:{}", session["keyring_account"].as_str()
                    .context("original v1 credential account missing")?), session["keyring_backend"].as_str()
                    .context("original v1 credential backend missing")?)?.context("original v1 password missing")?,
            };
            Factors::V1 { password, account_secret: secret.context("original Account Secret missing")? }
        },
        2 => Factors::V2 { super_password: primary.map(str::to_owned).or(super_password).context("original super key missing")? },
        3 => Factors::V3 { super_password: primary.map(str::to_owned).or(super_password).context("original super key missing")?,
            secret_key: secret.context("original Secret Key missing")? },
        4 => Factors::V4 { super_password: primary.map(str::to_owned).or(super_password).context("original super key missing")? },
        _ => anyhow::bail!("unsupported original session vault version"),
    };
    Ok(HostAuthSessionMaterial { session_sha256: hex::encode(Sha256::digest(bytes)), factors })
}
