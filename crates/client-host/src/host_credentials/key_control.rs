//! Exact slot custody for the host's durable key-operation owner.
use super::*;

fn slot(account: &str, backend: &str, name: &str) -> Result<keyring::Entry> {
    anyhow::ensure!(account.starts_with("login-") && account.len() <= 128
        && account.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && credential_backends().contains(&backend) && backend != "kernel"
        && matches!(name, "super" | "pass" | "legacy-secret" | "totp" | "key-control"),
        "invalid host key credential binding");
    entry("rsrs", &format!("{name}:{account}"), backend)
        .map_err(|error| anyhow::anyhow!("host key credential unavailable ({error:?})"))
}

pub fn read(account: &str, backend: &str, name: &str) -> Result<Option<String>> {
    match slot(account, backend, name)?.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(error) => anyhow::bail!("host key credential read failed ({:?})", credential_error(error)),
    }
}

/// The caller durably records ownership before the first write, including empty v1 passwords.
pub fn persist(account: &str, backend: &str, name: &str, value: &str) -> Result<()> {
    anyhow::ensure!(name == "pass" || !value.is_empty(), "empty host key credential");
    match read(account, backend, name)? {
        Some(existing) => anyhow::ensure!(existing == value, "host key credential conflict; original retained"),
        None => slot(account, backend, name)?.set_password(value)
            .map_err(|error| anyhow::anyhow!("host key credential write failed ({:?})", credential_error(error)))?,
    }
    anyhow::ensure!(read(account, backend, name)?.as_deref() == Some(value), "host key credential readback failed");
    Ok(())
}

/// Update only the private continuation already held by this takeover owner.
pub fn replace(account: &str, backend: &str, expected: &str, value: &str) -> Result<()> {
    anyhow::ensure!(read(account, backend, "key-control")?.as_deref() == Some(expected),
        "host key continuation changed; original retained");
    slot(account, backend, "key-control")?.set_password(value)
        .map_err(|error| anyhow::anyhow!("host key continuation write failed ({:?})", credential_error(error)))?;
    anyhow::ensure!(read(account, backend, "key-control")?.as_deref() == Some(value),
        "host key continuation readback failed");
    Ok(())
}

/// Source lookup uses only the recorded session backend and never environment overrides.
pub fn source(session: &serde_json::Value, input: &mut respire_protocol::key_control::HostKeyInput) -> Result<()> {
    let account = session["keyring_account"].as_str().context("source credential account missing")?;
    let backend = session["keyring_backend"].as_str().context("source credential backend missing")?;
    let version = session["vault_version"].as_i64().unwrap_or(1);
    if input.password.is_none() { input.password = read_session_slot(&format!("pass:{account}"), backend)?; }
    if version >= 2 && input.super_password.is_none() {
        input.super_password = read_session_slot(&format!("super:{account}"), backend)?;
    }
    if matches!(version, 1 | 3) && input.account_secret.is_none() {
        input.account_secret = read_session_legacy_secret(session)?;
    }
    Ok(())
}

/// Compare the receipt-owned value before deletion; never remove a conflicting slot.
pub fn remove(account: &str, backend: &str, name: &str, expected: &str) -> Result<()> {
    if let Some(value) = read(account, backend, name)? {
        anyhow::ensure!(value == expected, "host key cleanup conflict; original retained");
        match slot(account, backend, name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {},
            Err(error) => anyhow::bail!("host key credential cleanup failed ({:?})", credential_error(error)),
        }
        anyhow::ensure!(read(account, backend, name)?.is_none(), "host key cleanup readback failed");
    }
    Ok(())
}
