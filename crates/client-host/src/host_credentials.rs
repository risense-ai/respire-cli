//! Native credential custody belongs to the host, including private control helpers.
use anyhow::{Context, Result};
use respire_protocol::credentials::{
    CredentialError, CredentialOperation, CredentialReply, CredentialRequest, CREDENTIAL_SCHEMA_V,
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
    #[cfg(target_os = "linux")]
    let backends = ["secret_service", "kernel"];
    #[cfg(not(target_os = "linux"))]
    let backends = ["native"];
    let read = |slot: &str| -> Option<String> {
        backends.iter().find_map(|backend| entry("rsrs", &format!("{slot}:{account}"), backend)
            .ok()?.get_password().ok().filter(|value| !value.is_empty()))
    };
    let super_password = crate::env::var("RSRS_SUPER").ok().filter(|value| !value.is_empty())
        .or_else(|| read("super"))
        .or_else(|| session["super"].as_str().filter(|value| !value.is_empty()).map(str::to_owned))
        .or_else(|| (session["vault_version"].as_u64().unwrap_or(1) >= 4)
            .then(|| session["secret_key"].as_str().map(str::to_owned)).flatten());
    let login_password = crate::env::var("RSRS_PASS").ok().filter(|value| !value.is_empty())
        .or_else(|| read("pass")).or_else(|| session["pass"].as_str().map(str::to_owned));
    Ok((super_password, login_password))
}

/// The caller verifies the Runtime process/image and profile before delivering any key.
/// Missing credentials are a normal locked state; they do not authorize another keygen.
pub fn unlock_runtime(
    base: &str, installation: &std::path::Path, profile: &std::path::Path,
    instance_id: &str, generation: u64,
) -> Result<bool> {
    use sha2::{Digest, Sha256};
    let url = url::Url::parse(base)?;
    anyhow::ensure!(url.scheme() == "http" && url.username().is_empty() && url.password().is_none()
        && url.path() == "/" && url.query().is_none() && url.fragment().is_none()
        && url.host_str().is_some_and(|host| host.parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())), "unlock requires a literal loopback Runtime URL");
    let path = profile.join("session.json");
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let session: serde_json::Value = serde_json::from_slice(&bytes)?;
    let (super_password, login_password) = read_session_credentials(&session)?;
    if session["vault_version"].as_u64().unwrap_or(1) >= 2 && super_password.is_none()
        && session["secret_key"].as_str().is_none() && session["super"].as_str().is_none()
    {
        return Ok(false);
    }
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
    let input = respire_protocol::credentials::RuntimeUnlock {
        schema_version: CREDENTIAL_SCHEMA_V, profile: profile.canonicalize()?,
        session_sha256: format!("{:x}", Sha256::digest(&bytes)),
        instance_id: instance_id.into(), generation, super_password, login_password,
        legacy_secret: if session["vault_version"] == 3 {
            session["secret_key"].as_str().map(str::to_owned)
        } else { session["secret"].as_str().map(str::to_owned) },
        provider_credentials: provider_credentials(installation)?,
    };
    let bytes = serde_json::to_vec(&input)?;
    anyhow::ensure!(bytes.len() <= 65536, "Runtime unlock input exceeds the private frame limit");
    let reply = ureq::AgentBuilder::new().redirects(0)
        .timeout(std::time::Duration::from_secs(15)).build()
        .post(&format!("{}/api/runtime/unlock", base.trim_end_matches('/')))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json").send_bytes(&bytes)
        .map_err(|_| anyhow::anyhow!("host key delivery was not confirmed; inspect Runtime health before retrying"))?;
    let value: serde_json::Value = reply.into_json()
        .map_err(|_| anyhow::anyhow!("invalid Runtime unlock receipt"))?;
    anyhow::ensure!(value["store_ready"] == true, "Runtime library remains locked");
    Ok(true)
}

fn provider_credentials(root: &std::path::Path) -> Result<Vec<respire_protocol::credentials::ProvidedCredential>> {
    let bytes = match std::fs::read(root.join("embedding-profiles-v1.json")) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(bytes.len() <= 1024 * 1024, "embedding profiles exceed the configuration limit");
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    fn collect(value: &serde_json::Value, result: &mut Vec<respire_protocol::credentials::ProvidedCredential>) {
        match value {
            serde_json::Value::Object(fields) => {
                if let (Some(service), Some(account)) = (fields.get("keyring_service").and_then(|v| v.as_str()),
                    fields.get("keyring_account").and_then(|v| v.as_str())) {
                    if !result.iter().any(|item| item.service == service && item.account == account) {
                        #[cfg(target_os = "linux")]
                        let backends = ["secret_service", "kernel"];
                        #[cfg(not(target_os = "linux"))]
                        let backends = ["native"];
                        if let Some(value) = backends.iter().find_map(|backend|
                            entry(service, account, backend).ok()?.get_password().ok()) {
                            result.push(respire_protocol::credentials::ProvidedCredential {
                                service: service.into(), account: account.into(), value,
                            });
                        }
                    }
                }
                for value in fields.values() { collect(value, result); }
            }
            serde_json::Value::Array(values) => for value in values { collect(value, result); },
            _ => {},
        }
    }
    let mut result = Vec::new();
    collect(&value, &mut result);
    Ok(result)
}
