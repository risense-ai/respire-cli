//! Host-owned credential retirement for space admissions.
use super::*;

/// Retire only the legacy slot owned by a rejected space admission.
pub fn remove_legacy(account: &str, backend: &str, expected: &str) -> Result<()> {
    anyhow::ensure!(account.starts_with("login-") && account.len() <= 128
        && account.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && credential_backends().contains(&backend) && backend != "kernel", "invalid space legacy credential binding");
    let name = format!("legacy-secret:{account}");
    if let Some(value) = read_session_slot(&name, backend)? {
        anyhow::ensure!(value == expected, "space legacy credential conflict; original slot retained");
        let slot = entry("rsrs", &name, backend)
            .map_err(|error| anyhow::anyhow!("space legacy credential unavailable ({error:?})"))?;
        match slot.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {},
            Err(error) => anyhow::bail!("space legacy cleanup failed ({:?})", credential_error(error)),
        }
        anyhow::ensure!(read_session_slot(&name, backend)?.is_none(), "space legacy cleanup readback failed");
    }
    Ok(())
}
