//! Native credential custody belongs to the host, including private control helpers.
use anyhow::{Context, Result};
use respire_protocol::credentials::{
    CredentialError, CredentialOperation, CredentialReply, CredentialRequest, CREDENTIAL_SCHEMA_V,
    ProviderCredentialStatus, ProviderCredentialUpdate, ProviderUnavailableCode,
    RuntimeUnlockReceipt, RuntimeUnlockV2, RUNTIME_UNLOCK_SCHEMA_V2,
};
use std::io::{Read, Write};

fn entry(service: &str, account: &str, backend: &str) -> Result<keyring::Entry, CredentialError> {
    let result = match backend {
        "native" => keyring::Entry::new(service, account),
        #[cfg(target_os = "linux")]
        "secret_service" => keyring::secret_service::default_credential_builder()
            .build(None, service, account).map(keyring::Entry::new_with_credential),
        #[cfg(target_os = "linux")]
        "kernel" => keyring::keyutils::default_credential_builder()
            .build(None, service, account).map(keyring::Entry::new_with_credential),
        _ => return Err(CredentialError::Unavailable),
    };
    result.map_err(credential_error)
}

fn credential_error(error: keyring::Error) -> CredentialError {
    match error {
        keyring::Error::NoEntry => CredentialError::NoEntry,
        keyring::Error::Ambiguous(_) => CredentialError::Ambiguous,
        keyring::Error::BadEncoding(_) => CredentialError::BadEncoding,
        keyring::Error::Invalid(_, _) => CredentialError::Invalid,
        _ => CredentialError::Unavailable,
    }
}

fn execute(request: &CredentialRequest) -> Result<Option<String>, CredentialError> {
    if request.credential_request != CREDENTIAL_SCHEMA_V
        || request.id.len() != 36 || uuid::Uuid::parse_str(&request.id).is_err()
        || request.service.is_empty() || request.service.len() > 512
        || request.service.contains(['\0', '\r', '\n'])
        || request.account.is_empty() || request.account.len() > 512
        || request.account.contains(['\0', '\r', '\n'])
    {
        return Err(CredentialError::Invalid);
    }
    if matches!(request.operation, CredentialOperation::ReadConfigured) {
            if request.service != "rsrs" || !(request.account.starts_with("super:") || request.account.starts_with("pass:")) {
                return Err(CredentialError::Invalid);
            }
            let name = if request.account.starts_with("super:") { "RSRS_SUPER" } else { "RSRS_PASS" };
            if let Some(value) = crate::env::var(name).ok().filter(|value| !value.is_empty()) {
                return Ok(Some(value));
            }
        }
    let entry = entry(&request.service, &request.account, &request.backend)?;
    match &request.operation {
        CredentialOperation::Read | CredentialOperation::ReadConfigured => entry.get_password().map(Some).map_err(credential_error),
        CredentialOperation::Write(value) => {
            if request.service != "rsrs" || value.len() > 65536 {
                return Err(CredentialError::Invalid);
            }
            entry.set_password(value).map_err(credential_error)?;
            Ok(None)
        }
        CredentialOperation::Delete => {
            if request.service != "rsrs" { return Err(CredentialError::Invalid); }
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(credential_error(error)),
            }
        }
    }
}

/// Consume private credential frames until the original Runtime response arrives.
/// Credentials are never attached to that response, written to files, or logged.
pub fn read_control_response<T: serde::de::DeserializeOwned>(
    input: &mut impl Write, output: &mut impl Read,
) -> Result<T> {
    loop {
        let mut length = [0u8; 4];
        output.read_exact(&mut length).context("missing host control response frame")?;
        let length = u32::from_be_bytes(length) as usize;
        anyhow::ensure!(length > 0 && length <= respire_protocol::HOST_CONTROL_MAX_FRAME_BYTES,
            "invalid host control response frame size");
        let mut bytes = vec![0; length];
        output.read_exact(&mut bytes).context("incomplete host control response frame")?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid host control response JSON"))?;
        if value.get("credential_request").is_none() {
            return serde_json::from_value(value)
                .map_err(|_| anyhow::anyhow!("invalid host control response JSON"));
        }
        let request: CredentialRequest = serde_json::from_value(value)
            .map_err(|_| anyhow::anyhow!("invalid private credential request"))?;
        let reply = CredentialReply {
            credential_reply: CREDENTIAL_SCHEMA_V, id: request.id.clone(), result: execute(&request),
        };
        let bytes = serde_json::to_vec(&reply)?;
        input.write_all(&u32::try_from(bytes.len())?.to_be_bytes())?;
        input.write_all(&bytes)?;
        input.flush()?;
    }
}

pub fn read_session_credentials(session: &serde_json::Value) -> Result<(Option<String>, Option<String>)> {
    let account = session["keyring_account"].as_str().filter(|alias|
        (alias.starts_with("legacy-") || alias.starts_with("login-"))
            && alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'))
        .or_else(|| session["user"].as_str().map(str::trim).filter(|user| !user.is_empty()))
        .unwrap_or("local");
    anyhow::ensure!(account.len() <= 512 && !account.contains(['\0', '\r', '\n']), "invalid credential account");
    let backend = match session.get("keyring_backend") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(backend)) => {
            anyhow::ensure!(credential_backends().contains(&backend.as_str()),
                "unsupported session credential backend");
            Some(backend.as_str())
        }
        Some(_) => anyhow::bail!("invalid session credential backend metadata"),
    };
    let read = |slot: &str| {
        // Login credentials can use a different backend from the recorded super credential.
        let backends: Vec<_> = match backend {
            Some(selected) if slot == "super" => vec![selected],
            Some(selected) => std::iter::once(selected).chain(credential_backends().iter().copied()
                .filter(|candidate| *candidate != selected)).collect(),
            None => credential_backends().to_vec(),
        };
        read_provider_credential("rsrs", &format!("{slot}:{account}"), &backends)
            .map_err(|code| anyhow::anyhow!("host session credential read failed ({code:?})"))
    };
    let version = session["vault_version"].as_u64().unwrap_or(1);
    let session_super = session["super"].as_str().filter(|value| !value.is_empty()).map(str::to_owned);
    let super_password = match crate::env::var("RSRS_SUPER").ok().filter(|value| !value.is_empty()) {
        Some(value) => Some(value),
        None if version < 2 => None,
        None if version < 4 && session_super.is_some() => session_super,
        None => read("super")?
            .or_else(|| (version >= 4).then(|| session["secret_key"].as_str().map(str::to_owned)).flatten()),
    };
    let login_password = if version < 2 {
        match crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty())
            .or_else(|| session["pass"].as_str().map(str::to_owned)) {
            Some(value) => Some(value),
            None => read("pass")?,
        }
    } else {
        None
    };
    Ok((super_password, login_password))
}

/// The caller verifies the Runtime process/image and profile before delivering any key.
/// Missing credentials leave the library locked; they never authorize another keygen.
pub fn unlock_runtime(
    base: &str, installation: &std::path::Path, profile: &std::path::Path,
    instance_id: &str, generation: u64,
) -> Result<RuntimeUnlockReceipt> {
    use sha2::{Digest, Sha256};
    let url = url::Url::parse(base)?;
    anyhow::ensure!(url.scheme() == "http" && url.username().is_empty() && url.password().is_none()
        && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
        && url.host_str().is_some_and(|host| host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())), "unlock requires a literal loopback Runtime URL");
    let path = profile.join("session.json");
    let bytes = std::fs::read(path).context("Runtime session credentials are unavailable; library remains locked")?;
    let session: serde_json::Value = serde_json::from_slice(&bytes)?;
    let (super_password, login_password) = read_session_credentials(&session)?;
    let version = session["vault_version"].as_u64().unwrap_or(1);
    anyhow::ensure!(!((version < 2 && login_password.is_none())
        || (version >= 2 && super_password.is_none())),
        "Runtime session key is unavailable; library remains locked");
    let token_path = installation.join("runtime/token");
    let token = match crate::env::var("RSRS_RPC_TOKEN").ok().filter(|value| !value.trim().is_empty()) {
        Some(value) => value.trim().to_owned(),
        None => match crate::credential::read_token_file(&token_path)? {
            Some(value) => value,
            None => {
                let value = crate::credential::generate_runtime_token()?;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
                match options.open(&token_path) {
                    Ok(mut file) => { file.write_all(value.as_bytes())?; file.sync_all()?; value }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists =>
                        crate::credential::read_token_file(&token_path)?.context("host token disappeared")?,
                    Err(error) => return Err(error.into()),
                }
            }
        },
    };
    let provider_update = match provider_credentials(installation, profile) {
        Ok(credentials) => ProviderCredentialUpdate::Replace { credentials },
        Err(code) => ProviderCredentialUpdate::Unavailable { code },
    };
    let expected_provider_status = match &provider_update {
        ProviderCredentialUpdate::Replace { .. } => ProviderCredentialStatus::Ready,
        ProviderCredentialUpdate::Unavailable { code } => ProviderCredentialStatus::Unavailable { code: *code },
    };
    let input = RuntimeUnlockV2 {
        schema_version: RUNTIME_UNLOCK_SCHEMA_V2, profile: profile.canonicalize()?,
        session_sha256: format!("{:x}", Sha256::digest(&bytes)),
        instance_id: instance_id.into(), generation, super_password, login_password,
        legacy_secret: if session["vault_version"] == 3 {
            session["secret_key"].as_str().map(str::to_owned)
        } else { session["secret"].as_str().map(str::to_owned) },
        provider_update,
    };
    let bytes = serde_json::to_vec(&input)?;
    anyhow::ensure!(bytes.len() <= 65536, "Runtime unlock input exceeds the private frame limit");
    let reply = ureq::AgentBuilder::new().redirects(0)
        .timeout(std::time::Duration::from_secs(15)).build()
        .post(&format!("{}/api/runtime/unlock", base.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json").send_bytes(&bytes)
        .map_err(|error| match error {
            ureq::Error::Status(status, _) => anyhow::anyhow!(
                "Runtime V2 unlock rejected (HTTP {status}); inspect Runtime health before retrying"),
            ureq::Error::Transport(error) => anyhow::anyhow!(
                "Runtime V2 unlock transport failed ({:?}); delivery is unconfirmed; inspect Runtime health before retrying",
                error.kind()),
        })?;
    let receipt: RuntimeUnlockReceipt = reply.into_json()
        .map_err(|_| anyhow::anyhow!("invalid Runtime V2 unlock receipt"))?;
    anyhow::ensure!(receipt.schema_version == RUNTIME_UNLOCK_SCHEMA_V2,
        "Runtime unlock receipt schema mismatch: expected {RUNTIME_UNLOCK_SCHEMA_V2}, received {}",
        receipt.schema_version);
    anyhow::ensure!(receipt.store_ready, "Runtime V2 unlock receipt reports a locked library");
    anyhow::ensure!(receipt.provider_status == expected_provider_status,
        "Runtime provider credential receipt mismatch: expected {expected_provider_status:?}, received {:?}",
        receipt.provider_status);
    if let ProviderCredentialStatus::Unavailable { code } = receipt.provider_status {
        eprintln!("Runtime library unlocked; provider credentials unavailable ({code:?}); provider operations remain disabled");
    }
    Ok(receipt)
}

fn credential_backends() -> &'static [&'static str] {
    #[cfg(target_os = "linux")]
    { &["secret_service", "kernel"] }
    #[cfg(not(target_os = "linux"))]
    { &["native"] }
}

// Only missing or empty entries permit trying another backend; failures carry public codes only.
fn read_provider_credential(service: &str, account: &str, backends: &[&str])
    -> Result<Option<String>, ProviderUnavailableCode> {
    for backend in backends {
        let credential = match entry(service, account, backend) {
            Ok(credential) => credential,
            Err(CredentialError::NoEntry) => continue,
            Err(error) => return Err(match error {
                CredentialError::Ambiguous => ProviderUnavailableCode::Ambiguous,
                CredentialError::BadEncoding => ProviderUnavailableCode::BadEncoding,
                CredentialError::Invalid => ProviderUnavailableCode::InvalidConfiguration,
                _ => ProviderUnavailableCode::BackendUnavailable,
            }),
        };
        match credential.get_password() {
            Ok(value) if value.is_empty() => {},
            Ok(value) => return Ok(Some(value)),
            Err(keyring::Error::NoEntry) => {},
            Err(error) => return Err(match error {
                keyring::Error::NoStorageAccess(_) => ProviderUnavailableCode::AccessDenied,
                keyring::Error::PlatformFailure(_) => ProviderUnavailableCode::PlatformFailure,
                keyring::Error::Ambiguous(_) => ProviderUnavailableCode::Ambiguous,
                keyring::Error::BadEncoding(_) => ProviderUnavailableCode::BadEncoding,
                keyring::Error::Invalid(_, _) => ProviderUnavailableCode::InvalidConfiguration,
                _ => ProviderUnavailableCode::BackendUnavailable,
            }),
        }
    }
    Ok(None)
}

fn provider_io_error(error: std::io::Error) -> ProviderUnavailableCode {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        ProviderUnavailableCode::AccessDenied
    } else {
        ProviderUnavailableCode::PlatformFailure
    }
}

fn provider_credentials(root: &std::path::Path, profile: &std::path::Path)
    -> Result<Vec<respire_protocol::credentials::ProvidedCredential>, ProviderUnavailableCode> {
    fn collect(value: &serde_json::Value, result: &mut Vec<respire_protocol::credentials::ProvidedCredential>)
        -> Result<(), ProviderUnavailableCode> {
        match value {
            serde_json::Value::Object(fields) => {
                if fields.contains_key("keyring_service") || fields.contains_key("keyring_account") {
                    let service = fields.get("keyring_service").and_then(|v| v.as_str())
                        .ok_or(ProviderUnavailableCode::InvalidConfiguration)?;
                    let account = fields.get("keyring_account").and_then(|v| v.as_str())
                        .ok_or(ProviderUnavailableCode::InvalidConfiguration)?;
                    if service.is_empty() || account.is_empty() || service.len() > 512 || account.len() > 512
                        || service.contains(['\0', '\r', '\n']) || account.contains(['\0', '\r', '\n']) {
                        return Err(ProviderUnavailableCode::InvalidConfiguration);
                    }
                    if !result.iter().any(|item| item.service == service && item.account == account) {
                        if let Some(value) = read_provider_credential(service, account, credential_backends())? {
                            result.push(respire_protocol::credentials::ProvidedCredential {
                                service: service.into(), account: account.into(), value,
                            });
                        }
                    }
                }
                for value in fields.values() { collect(value, result)?; }
            }
            serde_json::Value::Array(values) => for value in values { collect(value, result)?; },
            _ => {},
        }
        Ok(())
    }
    let mut result = Vec::new();
    // Classification settings live in fixed OS slots, independently of embedding profiles.
    for slot in ["typesafe", "ds", "last-backend", "ds-last-base"] {
        collect(&serde_json::json!({"keyring_service": "rsrs", "keyring_account": format!("classify:{slot}")}), &mut result)?;
    }
    let mut hosts = vec!["api.deepseek.com".to_owned()];
    if let Some(base) = result.iter().find(|item| item.service == "rsrs" && item.account == "classify:ds-last-base") {
        hosts.push(crate::classification::host_of(&base.value));
    }
    let agent = match std::fs::read(profile.join("agent.json")) {
        Ok(bytes) => Some(serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|_| ProviderUnavailableCode::InvalidConfiguration)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(provider_io_error(error)),
    };
    if let Some(base) = agent.as_ref().and_then(|agent| agent["recall_api_base"].as_str()) {
        hosts.push(crate::classification::host_of(base));
    }
    hosts.sort();
    hosts.dedup();
    for host in hosts.into_iter().filter(|host| !host.is_empty()) {
        for slot in [format!("ds@{host}"), format!("ds-model@{host}")] {
            collect(&serde_json::json!({"keyring_service": "rsrs", "keyring_account": format!("classify:{slot}")}), &mut result)?;
        }
    }
    let bytes = match std::fs::read(root.join("embedding-profiles-v1.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
        Err(error) => return Err(provider_io_error(error)),
    };
    if bytes.len() > 1024 * 1024 {
        return Err(ProviderUnavailableCode::InvalidConfiguration);
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| ProviderUnavailableCode::InvalidConfiguration)?;
    collect(&value, &mut result)?;
    Ok(result)
}
