//! Private factors stay in native custody; the host journal contains only the public wrap.
use super::*;
use anyhow::ensure;
use respire_client_host::host_credentials::key_control as slots;
use respire_crypto::crypto;
use serde_json::Value;

fn backend() -> &'static str {
    if cfg!(target_os = "linux") { "secret_service" } else { "native" }
}

fn alias(original: &Original) -> String {
    format!("login-{}", original.operation_id.replace('-', ""))
}

pub(super) fn validate_public(original: &Original) -> Result<()> {
    let Some(candidate) = original.candidate.as_ref() else { return Ok(()); };
    let object = candidate.as_object().context("host key candidate must be an object")?;
    ensure!(object.len() == 6 && object.keys().all(|field| matches!(field.as_str(),
        "vault_version" | "kdf_salt" | "wrapped_urk" | "urk_nonce" | "keyring_account" | "keyring_backend"))
        && candidate["keyring_account"].as_str() == Some(alias(original).as_str())
        && candidate["keyring_backend"].as_str() == Some(backend()), "invalid public host key candidate");
    for field in ["kdf_salt", "wrapped_urk", "urk_nonce"] {
        ensure!(candidate[field].as_str().is_some_and(|value| !value.is_empty()), "incomplete host key candidate");
    }
    match &original.operation {
        HostKeyOperation::SuperReset { .. } => ensure!(candidate["vault_version"] == 4, "reset candidate must be v4"),
        HostKeyOperation::Fivekeys { kdf_salt, wrapped_urk, urk_nonce, use_super, .. } => {
            ensure!(candidate["kdf_salt"].as_str() == Some(kdf_salt.as_str())
                && candidate["wrapped_urk"].as_str() == Some(wrapped_urk.as_str())
                && candidate["urk_nonce"].as_str() == Some(urk_nonce.as_str())
                && if *use_super { matches!(candidate["vault_version"].as_i64(), Some(2 | 4)) }
                    else { candidate["vault_version"] == 1 }, "host key candidate differs from its admitted kit");
        }
    }
    Ok(())
}

fn copy(input: &HostKeyInput) -> Result<HostKeyInput> {
    Ok(serde_json::from_value(serde_json::to_value(input)?)?)
}

fn unlock(session: &Value, input: &HostKeyInput) -> Result<[u8; 32]> {
    let field = |name: &str| session[name].as_str().with_context(|| format!("key vault missing {name}"));
    let salt = field("kdf_salt")?;
    let wrapped = field("wrapped_urk")?;
    let current = wrapped.strip_prefix(crypto::RSRS_PREFIX);
    let secret = || input.super_password.as_deref().context("explicit Super Key required");
    let legacy = || input.account_secret.as_deref().context("explicit legacy factor required");
    let version = match session.get("vault_version") {
        None => 1,
        Some(value) => value.as_i64().context("invalid host key vault version")?,
    };
    let kek = match version {
        1 if current.is_some() => crypto::derive_rsrs_password_kek(input.password.as_deref().context("password required")?, legacy()?, salt)?,
        1 => crypto::derive_kek(input.password.as_deref().context("password required")?, legacy()?, salt)?,
        2 => crypto::derive_super_kek(secret()?, salt)?,
        3 if current.is_some() => crypto::derive_rsrs_vault_kek(secret()?, legacy()?, salt)?,
        3 => crypto::derive_vault_kek(secret()?, legacy()?, salt)?,
        4 if current.is_some() => crypto::derive_rsrs_kek(secret()?, salt)?,
        4 => crypto::derive_kek_v4(secret()?, salt)?,
        _ => anyhow::bail!("unsupported host key vault version"),
    };
    crypto::unwrap_key(current.unwrap_or(wrapped), field("urk_nonce")?, &kek)
}

/// Compute once for a new candidate. The caller checkpoints `public` before storing `input`.
pub(super) fn prepare(original: &Original, input: &HostKeyInput) -> Result<(Option<Value>, HostKeyInput)> {
    ensure!(input.material.is_none(), "key material is supplied only by the owning host");
    if original.candidate.is_some() { return Ok((None, load(original, Some(input), true)?)); }
    let mut input = copy(input)?;
    let account = alias(original);
    let (session, reset) = match &original.operation {
        HostKeyOperation::SuperReset { .. } => {
            let source = crate::maintenance::private_io::bounded_bytes(&original.profile.join("session.json"), 65536)?
                .context("super-reset source session missing")?;
            let source: Value = serde_json::from_slice(&source)?;
            slots::source(&source, &mut input)?;
            let version = source["vault_version"].as_i64().unwrap_or(1);
            if (version == 1 && input.password.is_none()) || (version >= 2 && input.super_password.is_none()) {
                return Ok((None, input));
            }
            let urk = unlock(&source, &input)?;
            let mut reset = crate::auth_material::generate()?;
            reset.keyring_account = account.clone();
            let current = source["wrapped_urk"].as_str().is_some_and(|value| value.starts_with(crypto::RSRS_PREFIX))
                || source["crypto_namespace"].as_str() == Some(crypto::RSRS_PREFIX);
            let kek = if current { crypto::derive_rsrs_kek(&reset.super_password, &reset.kdf_salt)? }
                else { crypto::derive_kek_v4(&reset.super_password, &reset.kdf_salt)? };
            let (nonce, wrapped) = crypto::wrap_key(&urk, &kek)?;
            reset.wrapped_urk = if current { format!("{}{wrapped}", crypto::RSRS_PREFIX) } else { wrapped };
            reset.urk_nonce = nonce;
            (json!({"vault_version":4,"kdf_salt":reset.kdf_salt,"wrapped_urk":reset.wrapped_urk,
                "urk_nonce":reset.urk_nonce,"keyring_account":account,"keyring_backend":backend()}), Some(reset))
        }
        HostKeyOperation::Fivekeys { kdf_salt, wrapped_urk, urk_nonce, use_super, .. } => {
            if input.password.is_none() || (*use_super && input.super_password.is_none())
                || (!*use_super && input.account_secret.is_none()) { return Ok((None, input)); }
            let mut session = json!({"vault_version":if *use_super { 4 } else { 1 },
                "kdf_salt":kdf_salt,"wrapped_urk":wrapped_urk,"urk_nonce":urk_nonce,
                "keyring_account":account,"keyring_backend":backend()});
            if *use_super && unlock(&session, &input).is_err() { session["vault_version"] = json!(2); }
            unlock(&session, &input)?;
            (session, None)
        }
    };
    input.material = Some(HostKeyMaterial { keyring_account: account, keyring_backend: backend().to_owned(),
        reset, challenge: None });
    Ok((Some(session), input))
}

fn validate(original: &Original, input: &HostKeyInput) -> Result<()> {
    validate_public(original)?;
    let public = original.candidate.as_ref().context("host key custody intent missing")?;
    let material = input.material.as_ref().context("host key custody material missing")?;
    ensure!(material.keyring_account == alias(original) && material.keyring_backend == backend()
        && public["keyring_account"].as_str() == Some(material.keyring_account.as_str())
        && public["keyring_backend"].as_str() == Some(material.keyring_backend.as_str()), "host key custody owner changed");
    if let Some(reset) = material.reset.as_ref() {
        ensure!(matches!(original.operation, HostKeyOperation::SuperReset { .. })
            && reset.keyring_account == material.keyring_account && reset.keyring_backend == material.keyring_backend
            && public["kdf_salt"].as_str() == Some(reset.kdf_salt.as_str())
            && public["wrapped_urk"].as_str() == Some(reset.wrapped_urk.as_str())
            && public["urk_nonce"].as_str() == Some(reset.urk_nonce.as_str()), "host reset custody candidate changed");
        unlock(public, &HostKeyInput { super_password: Some(reset.super_password.clone()), ..HostKeyInput::default() })?;
    } else {
        ensure!(matches!(original.operation, HostKeyOperation::Fivekeys { .. }), "host reset custody is incomplete");
        unlock(public, input)?;
    }
    Ok(())
}

pub(super) fn persist(original: &Original, input: &HostKeyInput) -> Result<()> {
    if original.candidate.is_none() { return Ok(()); }
    validate(original, input)?;
    let material = input.material.as_ref().context("key material missing")?;
    let mut saved = copy(input)?;
    saved.totp = None;
    slots::persist(&material.keyring_account, &material.keyring_backend, "key-control", &serde_json::to_string(&saved)?)?;
    // The private continuation is durable before any slot consumed by a serving Runtime.
    let super_password = material.reset.as_ref().map(|reset| reset.super_password.as_str()).or(input.super_password.as_deref());
    if let Some(secret) = super_password { slots::persist(&material.keyring_account, &material.keyring_backend, "super", secret)?; }
    if let Some(password) = input.password.as_deref() { slots::persist(&material.keyring_account, &material.keyring_backend, "pass", password)?; }
    if matches!(original.operation, HostKeyOperation::Fivekeys { use_super:false, .. }) {
        slots::persist(&material.keyring_account, &material.keyring_backend, "legacy-secret",
            input.account_secret.as_deref().context("Account Secret missing")?)?;
    }
    Ok(())
}

pub(super) fn load(original: &Original, supplied: Option<&HostKeyInput>, verify_slots: bool) -> Result<HostKeyInput> {
    let Some(_) = original.candidate else { return supplied.map(copy).unwrap_or_else(|| Ok(HostKeyInput::default())); };
    let account = alias(original);
    let Some(payload) = slots::read(&account, backend(), "key-control")? else {
        ensure!(!verify_slots, "host key custody missing; retain the original operation without regenerating material");
        // Explicit rollback may precede the first private write; no candidate slot may exist.
        for name in ["super", "pass", "legacy-secret"] {
            ensure!(slots::read(&account, backend(), name)?.is_none(), "host key custody missing for existing slot");
        }
        return Ok(HostKeyInput::default());
    };
    let mut input: HostKeyInput = serde_json::from_str(&payload).map_err(|_| anyhow::anyhow!("invalid host key custody"))?;
    validate(original, &input)?;
    if original.sent && verify_slots {
        let material = input.material.as_ref().context("host key material missing")?;
        let secret = material.reset.as_ref().map(|reset| reset.super_password.as_str()).or(input.super_password.as_deref());
        let legacy = if matches!(original.operation, HostKeyOperation::Fivekeys { use_super:false, .. }) { input.account_secret.as_deref() } else { None };
        for (name, expected) in [("super", secret), ("pass", input.password.as_deref()), ("legacy-secret", legacy)] {
            ensure!(slots::read(&material.keyring_account, &material.keyring_backend, name)?.as_deref() == expected,
                "host key candidate credential changed; retain the original operation");
        }
    }
    if let Some(supplied) = supplied {
        ensure!(supplied.material.is_none(), "caller cannot replace host key custody");
        for (new, old) in [(&supplied.password, &input.password), (&supplied.super_password, &input.super_password),
            (&supplied.account_secret, &input.account_secret)] {
            ensure!(new.is_none() || new == old, "key continuation changed its original factors");
        }
        input.totp = supplied.totp.clone();
    }
    Ok(input)
}

pub(super) fn checkpoint_challenge(original: &Original, receipt: &mut HostKeyResult) -> Result<()> {
    let Some(challenge) = receipt.challenge.take() else { return Ok(()); };
    ensure!(matches!(original.operation, HostKeyOperation::Fivekeys { .. })
        && receipt.outcome == HostKeyOutcome::AwaitingInput && receipt.required_inputs == ["totp"],
        "unexpected private key challenge");
    let account = alias(original);
    let payload = slots::read(&account, backend(), "key-control")?.context("host key custody missing")?;
    let mut input: HostKeyInput = serde_json::from_str(&payload).map_err(|_| anyhow::anyhow!("invalid host key custody"))?;
    validate(original, &input)?;
    let material = input.material.as_mut().context("host key material missing")?;
    ensure!(material.challenge.as_deref().is_none_or(|old| old == challenge), "host fivekeys challenge changed");
    material.challenge = Some(challenge);
    slots::replace(&account, backend(), &payload, &serde_json::to_string(&input)?)
}

pub(super) fn complete(original: &Original) -> Result<()> {
    let account = alias(original);
    let payload = slots::read(&account, backend(), "key-control")?.context("host key custody missing")?;
    let mut input: HostKeyInput = serde_json::from_str(&payload).map_err(|_| anyhow::anyhow!("invalid host key custody"))?;
    validate(original, &input)?;
    let material = input.material.as_mut().context("host key material missing")?;
    material.challenge = None;
    input.totp = None;
    if let Some(reset) = material.reset.as_ref() {
        input.super_password = Some(reset.super_password.clone());
        input.account_secret = None;
    }
    let sanitized = serde_json::to_string(&input)?;
    if sanitized != payload { slots::replace(&account, backend(), &payload, &sanitized)?; }
    Ok(())
}

/// Runtime has already restored files; the host now compensates only its own candidate slots.
pub(super) fn rollback(original: &Original) -> Result<()> {
    if original.candidate.is_none() { return Ok(()); }
    let account = alias(original);
    let Some(payload) = slots::read(&account, backend(), "key-control")? else {
        for name in ["super", "pass", "legacy-secret"] {
            ensure!(slots::read(&account, backend(), name)?.is_none(), "host key custody missing for existing slot");
        }
        return Ok(());
    };
    let input: HostKeyInput = serde_json::from_str(&payload).map_err(|_| anyhow::anyhow!("invalid host key custody"))?;
    validate(original, &input)?;
    let material = input.material.as_ref().context("host key material missing")?;
    let secret = material.reset.as_ref().map(|reset| reset.super_password.as_str()).or(input.super_password.as_deref());
    let legacy = if matches!(original.operation, HostKeyOperation::Fivekeys { use_super:false, .. }) { input.account_secret.as_deref() } else { None };
    let owned = [("super", secret), ("pass", input.password.as_deref()), ("legacy-secret", legacy)];
    for (name, expected) in owned {
        let found = slots::read(&account, backend(), name)?;
        ensure!(found.as_deref().is_none_or(|value| Some(value) == expected),
            "host key cleanup conflict; original slots retained");
    }
    for (name, expected) in owned {
        if let Some(value) = expected { slots::remove(&account, backend(), name, value)?; }
    }
    slots::remove(&account, backend(), "key-control", &payload)
}
