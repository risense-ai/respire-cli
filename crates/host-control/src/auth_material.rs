//! Host-owned v4 generation and credential custody for keygen and registration.
use anyhow::{ensure, Context, Result};
use respire_client_host::host_credentials::{read_auth_super, write_auth_super, write_auth_password, remove_auth_material};
use respire_crypto::crypto;
use respire_protocol::HostAuthKeygenMaterial;
use serde_json::Value;

/// Normalize only a new auth source, before freezing any operation identity.
/// Interrupted operations retain their original session and journal for explicit recovery.
pub fn prepare_source(takeover: &respire_client_host::lock::LibraryLock) -> Result<bool> {
    use respire_client_host::lock::LibraryLock;
    use std::time::Duration;
    let (root, profile) = respire_client_host::config::control_roots()?;
    ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "host_preparation_required: auth source requires installation takeover ownership");
    let path = profile.join("session.json");
    let Some(original) = crate::maintenance::private_io::bounded_bytes(&path, 65536)? else { return Ok(false); };
    let session: Value = serde_json::from_slice(&original).context("invalid auth source session")?;
    let factor_free = |value: &Value| ["pass", "super", "secret", "secret_key"]
        .iter().all(|field| value.get(*field).is_none());
    if factor_free(&session) { return Ok(false); }
    let journal = respire_client_host::paths::client_config_path().with_file_name(".login-recovery.json");
    ensure!(!journal.try_exists()?,
        "host_recovery_required: source factors and an existing login journal require explicit recovery; originals retained");
    ensure!(respire_client_host::host_credentials::legacy_session_needs_migration(&session),
        "host_preparation_required: this inline source format has no host canonicalization path; original session retained");
    ensure!(crate::lifecycle_io::probe_runtime()?.is_none() && !crate::lifecycle_io::endpoint_path().try_exists()?,
        "host_preparation_required: release the source Runtime owner before canonicalizing inline factors");
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let _root_lock = LibraryLock::acquire(&root, Duration::from_secs(1))?;
    let _profile_lock = if root == profile { None } else {
        Some(LibraryLock::acquire(&profile, Duration::from_secs(1))?)
    };
    ensure!(crate::maintenance::private_io::bounded_bytes(&path, 65536)?.as_deref() == Some(original.as_slice()),
        "host_preparation_required: auth source changed before exclusive preparation");
    let migrated = crate::lifecycle_io::migrate_legacy_session_under_takeover(takeover)?;
    let bytes = crate::maintenance::private_io::bounded_bytes(&path, 65536)?
        .context("host_preparation_required: canonical auth source is missing")?;
    let canonical: Value = serde_json::from_slice(&bytes)?;
    ensure!(migrated && factor_free(&canonical)
        && ["vault_version", "kdf_salt", "wrapped_urk", "urk_nonce"].iter()
            .all(|field| canonical[*field] == session[*field]),
        "host_preparation_required: source canonicalization did not preserve the original vault");
    Ok(true)
}

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
pub fn persist(material: &HostAuthKeygenMaterial, before_write: impl FnOnce() -> Result<()>) -> Result<()> {
    validate(material)?;
    before_write()?;
    write_auth_super(&material.keyring_account, &material.keyring_backend, &material.super_password)
}

/// Registration has already recorded its password-slot intent under the same operation owner.
pub fn persist_password(material: &HostAuthKeygenMaterial, password: &str) -> Result<()> {
    validate(material)?;
    ensure!(read_auth_super(&material.keyring_account, &material.keyring_backend)?.as_deref()
        == Some(material.super_password.as_str()), "host registration Super Key persist is missing");
    write_auth_password(&material.keyring_account, &material.keyring_backend, password)
}

/// Retire only newly generated, receipt-owned slots, never a reused source vault.
/// Supply the expected registration password to preserve any conflicting password slot.
pub fn remove(material: &HostAuthKeygenMaterial, password: Option<&str>) -> Result<()> {
    validate(material)?;
    remove_auth_material(&material.keyring_account, &material.keyring_backend,
        &material.super_password, password)
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
