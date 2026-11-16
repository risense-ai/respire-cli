//! Host-owned v4 generation and credential custody for keygen and registration.
use anyhow::{ensure, Context, Result};
use respire_client_host::host_credentials::{read_auth_super, write_auth_super};
use respire_crypto::crypto;
use respire_protocol::HostAuthKeygenMaterial;
use serde_json::Value;

/// Generate only for a newly admitted operation, never when reconnecting to an existing one.
pub fn generate() -> Result<HostAuthKeygenMaterial> {
    let super_password = crypto::generate_secret_key();
    let urk = crypto::generate_key();
    let kdf_salt = crypto::random_hex(16);
    let kek = crypto::derive_rsrs_kek(&super_password, &kdf_salt)?;
    let (urk_nonce, wrapped) = crypto::wrap_key(&urk, &kek)?;
    #[cfg(target_os = "linux")]
    let backend = "secret_service";
    #[cfg(not(target_os = "linux"))]
    let backend = "native";
    Ok(HostAuthKeygenMaterial { kdf_salt, wrapped_urk: format!("{}{wrapped}", crypto::RSRS_PREFIX),
        urk_nonce, super_password, keyring_account: format!("login-{}", uuid::Uuid::new_v4().simple()),
        keyring_backend: backend.to_owned() })
}

/// The caller holds operation ownership and durably records public material before the write.
/// Never serialize the entire material into that record: it contains the plaintext Super Key.
pub fn checkpoint(material: &HostAuthKeygenMaterial, before_write: impl FnOnce() -> Result<()>) -> Result<()> {
    validate(material)?;
    before_write()?;
    write_auth_super(&material.keyring_account, &material.keyring_backend, &material.super_password)
}

/// Reconnect using the exact public candidate and credential slot; never generate a replacement.
pub fn load(candidate: &Value) -> Result<HostAuthKeygenMaterial> {
    let field = |name: &str| -> Result<String> {
        Ok(candidate[name].as_str().filter(|value| !value.is_empty())
            .with_context(|| format!("host auth candidate is missing {name}"))?.to_owned())
    };
    let keyring_account = field("keyring_account")?;
    let keyring_backend = field("keyring_backend")?;
    let super_password = read_auth_super(&keyring_account, &keyring_backend)?
        .context("host auth candidate credential is missing; retain the original operation")?;
    let material = HostAuthKeygenMaterial { kdf_salt: field("kdf_salt")?, wrapped_urk: field("wrapped_urk")?,
        urk_nonce: field("urk_nonce")?, super_password, keyring_account, keyring_backend };
    validate(&material)?;
    Ok(material)
}

fn validate(material: &HostAuthKeygenMaterial) -> Result<()> {
    ensure!(material.keyring_account.starts_with("login-") && material.keyring_account.len() <= 128
        && material.keyring_account.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid host auth credential account");
    #[cfg(target_os = "linux")]
    ensure!(material.keyring_backend == "secret_service", "host auth requires persistent credentials");
    #[cfg(not(target_os = "linux"))]
    ensure!(material.keyring_backend == "native", "host auth requires persistent credentials");
    ensure!(!material.super_password.is_empty(), "host auth material is missing its Super Key");
    let wrapped = material.wrapped_urk.strip_prefix(crypto::RSRS_PREFIX)
        .context("new host auth material requires the current crypto namespace")?;
    let kek = crypto::derive_rsrs_kek(&material.super_password, &material.kdf_salt)?;
    crypto::unwrap_key(wrapped, &material.urk_nonce, &kek)
        .context("host auth credential does not unlock its candidate")?;
    Ok(())
}
