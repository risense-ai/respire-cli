//! Host-only recovery document rendering. No Runtime or database access.
use anyhow::{Context, Result};
use respire_protocol::secret_control::{HostKeysExportReadResult, HostSecretReadResult, HostSecretSession};

pub fn keys_export(
    data: &serde_json::Value,
    super_password: Option<&str>,
    legacy_secret: Option<&str>,
) -> Result<HostKeysExportReadResult> {
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let addr = data["addr"].as_str().unwrap_or("").to_owned();
    let version = match data.get("vault_version") {
        None => 1,
        Some(value) => value.as_i64().context("invalid vault version")?,
    };
    anyhow::ensure!(version >= 1, "unsupported vault version");
    let kdf_salt = data["kdf_salt"].as_str().unwrap_or("").to_owned();
    let wrapped_urk = data["wrapped_urk"].as_str().unwrap_or("").to_owned();
    let urk_nonce = data["urk_nonce"].as_str().unwrap_or("").to_owned();
    if wrapped_urk.is_empty() {
        anyhow::bail!("no local key material (session.json missing wrapped_urk) - this machine never ran register/keys");
    }
    let is_v4 = version >= 4;
    let super_key = match version {
        3 => legacy_secret.filter(|value| !value.is_empty()).context("original Secret Key is unavailable")?,
        4.. => super_password.filter(|value| !value.is_empty()).context("super password is unavailable")?,
        _ => "",
    };
    let legacy_super = if matches!(version, 2 | 3) {
        super_password.filter(|value| !value.is_empty()).context("original super password is unavailable")?
    } else { "" };
    if is_v4 { verify_v4(data, super_key)?; }
    let is_v3 = version == 3;
    let body = if version == 1 {
        let account_secret = legacy_secret
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "v1 Account Secret is missing; retain the original device and library"
                )
            })?;
        format!(
            "rsrs v1 key-recovery notes (keep private; losing the original factors makes data unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original v1 decrypt factors (no independent super password) --\n\
             original login password: required, not included in this export\n\
             Account Secret: {account_secret}\n\n\
             -- unchanged vault wrap material --\n\
             vault_version: 1\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- new device, after explicit full-library and cloud migration --\n\
             rsrs login --interactive --user {user} --pass <original-login-password>\n\
             Enter the original Account Secret when prompted; do not use --super or ordinary --secret-key.\n\n\
             -- select the explicitly migrated library and publish the same v1 factors --\n\
             rsrs migrate --vault --user {user} --pass <original-login-password> --secret-key <original-account-secret>\n"
        )
    } else if is_v4 {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- super password (decrypt depends on this; v4 single factor) --\n\
             super password: {super_key}\n\n\
             -- vault wrap material (a new machine login fetches this; listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- import on a new machine --\n\
             rsrs login --interactive --user {user} --pass <login-password> --super {super_key}\n\
             (or fill the same super password on the website Keys & Recovery page after login)\n"
        )
    } else {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- original decrypt factors (migration retains the vault version and factors) --\n\
             super password (passphrase): {legacy_super}\n\
             Secret Key (recovery code): {super_key}\n\n\
             -- vault wrap material (listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- explicitly migrate the full library, select it, then publish its unchanged-factor vault --\n\
             rsrs migrate --vault --user {user} --pass <login-password> --super \"{legacy_super}\" --secret-key {super_key}\n"
        )
    };
    Ok(HostKeysExportReadResult { version, user, body, legacy_warning: !(is_v4 || is_v3) })
}

/// Render metadata without keyring access; reveal receives only host-selected original factors.
pub fn secret_read(
    data: Option<&serde_json::Value>,
    reveal: bool,
    super_password: Option<&str>,
    legacy_secret: Option<&str>,
) -> Result<HostSecretReadResult> {
    let Some(data) = data else {
        return Ok(HostSecretReadResult {
            session: HostSecretSession { has_session: false, user: String::new(), addr: String::new(),
                has_token: false, secret_masked: String::new(), has_local_keys: false },
            secret: None, five: None,
        });
    };
    anyhow::ensure!(data.is_object(), "invalid secret read session");
    let inline = data["secret_key"].as_str().filter(|value| !value.is_empty())
        .or_else(|| data["secret"].as_str()).unwrap_or("");
    let chars: Vec<_> = inline.chars().collect();
    let masked = if chars.len() <= 8 { "****".to_owned() } else {
        format!("{}\u{2026}{}", chars[..4].iter().collect::<String>(), chars[chars.len()-4..].iter().collect::<String>())
    };
    let session = HostSecretSession {
        has_session: true,
        user: data["user"].as_str().unwrap_or("").to_owned(),
        addr: data["addr"].as_str().unwrap_or("").to_owned(),
        has_token: data["token"].as_str().is_some_and(|value| !value.is_empty()),
        secret_masked: masked,
        has_local_keys: data["wrapped_urk"].as_str().is_some_and(|value| !value.is_empty()) || !inline.is_empty(),
    };
    if !reveal { return Ok(HostSecretReadResult { session, secret: None, five: None }); }
    let version = match data.get("vault_version") {
        None => 1,
        Some(value) => value.as_u64().context("invalid reveal vault version")?,
    };
    anyhow::ensure!(version >= 1, "unsupported reveal vault version");
    let secret = if matches!(version, 1 | 3) { legacy_secret } else { super_password }
        .filter(|value| !value.is_empty()).context("session recovery secret is unavailable")?;
    if version >= 4 { verify_v4(data, secret)?; }
    let mut five = serde_json::json!({
        "pass":data["pass"], "super":data["super"], "secret":data["secret"], "secret_key":data["secret_key"],
        "kdf_salt":data["kdf_salt"], "wrapped_urk":data["wrapped_urk"], "urk_nonce":data["urk_nonce"],
        "vault_version":data["vault_version"],
    });
    if let Some(value) = super_password {
        five[if version >= 4 { "secret_key" } else { "super" }] = serde_json::json!(value);
    }
    if let Some(value) = legacy_secret {
        five[if version == 1 { "secret" } else { "secret_key" }] = serde_json::json!(value);
    }
    Ok(HostSecretReadResult { session, secret: Some(secret.to_owned()), five: Some(five) })
}

fn verify_v4(data: &serde_json::Value, secret: &str) -> Result<()> {
    use respire_crypto::crypto;
    let salt = data["kdf_salt"].as_str().context("session KDF salt is missing")?;
    let wrap = data["wrapped_urk"].as_str().context("session wrapped URK is missing")?;
    let nonce = data["urk_nonce"].as_str().context("session URK nonce is missing")?;
    let current = wrap.strip_prefix(crypto::RSRS_PREFIX);
    let kek = if current.is_some() { crypto::derive_rsrs_kek(secret, salt)? }
        else { crypto::derive_kek_v4(secret, salt)? };
    crypto::unwrap_key(current.unwrap_or(wrap), nonce, &kek)
        .context("recovery credential does not unlock the selected session")?;
    Ok(())
}
