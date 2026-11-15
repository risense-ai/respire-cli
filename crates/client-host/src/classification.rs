//! Host provider settings in the existing rsrs/classify:* credential namespace.
//! No account credentials or arbitrary service/label access are exposed.

use anyhow::{anyhow, Result};

const SERVICE: &str = "rsrs";

#[derive(Clone, Copy)]
enum Backend {
    #[cfg(any(not(target_os = "linux"), test))]
    Native,
    #[cfg(all(target_os = "linux", not(test)))]
    SecretService,
    #[cfg(all(target_os = "linux", not(test)))]
    Kernel,
}

impl Backend {
    fn name(self) -> &'static str {
        match self {
            #[cfg(any(not(target_os = "linux"), test))]
            Self::Native => "native",
            #[cfg(all(target_os = "linux", not(test)))]
            Self::SecretService => "secret_service",
            #[cfg(all(target_os = "linux", not(test)))]
            Self::Kernel => "kernel",
        }
    }
}

fn backends() -> &'static [Backend] {
    #[cfg(all(target_os = "linux", not(test)))]
    {
        &[Backend::SecretService, Backend::Kernel]
    }
    #[cfg(any(not(target_os = "linux"), test))]
    {
        &[Backend::Native]
    }
}

fn credential_entry(label: &str, backend: Backend) -> std::result::Result<keyring::Entry, keyring::Error> {
    match backend {
        #[cfg(any(not(target_os = "linux"), test))]
        Backend::Native => keyring::Entry::new(SERVICE, label),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::SecretService => keyring::secret_service::default_credential_builder()
            .build(None, SERVICE, label)
            .map(keyring::Entry::new_with_credential),
        #[cfg(all(target_os = "linux", not(test)))]
        Backend::Kernel => keyring::keyutils::default_credential_builder()
            .build(None, SERVICE, label)
            .map(keyring::Entry::new_with_credential),
    }
}

fn credential_error(operation: &str, backend: Backend, error: keyring::Error) -> anyhow::Error {
    let category = match error {
        keyring::Error::NoEntry => "missing",
        keyring::Error::NoStorageAccess(_) => "access_denied",
        keyring::Error::PlatformFailure(_) => "platform_failure",
        keyring::Error::Ambiguous(_) => "ambiguous",
        keyring::Error::BadEncoding(_) => "bad_encoding",
        keyring::Error::Invalid(_, _) => "invalid",
        _ => "unavailable",
    };
    anyhow!("classification credential {operation} failed ({}, {category})", backend.name())
}

// Only absence permits checking the next legacy backend; an existing slot keeps its backend.
fn find_credential(label: &str) -> Result<Option<(Backend, String)>> {
    for &backend in backends() {
        let entry = match credential_entry(label, backend) {
            Ok(entry) => entry,
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => return Err(credential_error("initialization", backend, error)),
        };
        match entry.get_password() {
            Ok(value) => return Ok(Some((backend, value))),
            Err(keyring::Error::NoEntry) => continue,
            Err(error) => return Err(credential_error("read", backend, error)),
        }
    }
    Ok(None)
}

fn read_label(label: &str) -> Result<Option<String>> {
    match find_credential(label)? {
        Some((backend, value)) => {
            anyhow::ensure!(!value.is_empty(), "classification credential is empty ({})", backend.name());
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

fn save_label(label: &str, value: &str) -> Result<()> {
    let backend = match find_credential(label)? {
        Some((backend, _)) => backend,
        None => *backends().first().ok_or_else(|| anyhow!("no classification credential backend configured"))?,
    };
    let entry = credential_entry(label, backend)
        .map_err(|error| credential_error("initialization", backend, error))?;
    entry.set_password(value)
        .map_err(|error| credential_error("write", backend, error))?;
    let stored = entry.get_password()
        .map_err(|error| credential_error("readback", backend, error))?;
    anyhow::ensure!(stored == value, "classification credential readback mismatch ({})", backend.name());
    if backend.name() == "kernel" {
        eprintln!("warning: Linux credentials are in the volatile kernel keyring; enabling Secret Service alone does not preserve existing keys across reboot; restore or re-import them into the persistent store");
    }
    Ok(())
}

/// classify backend slot (separate account under the same OS keyring service).
/// DS backends are keyed by **endpoint host** — official deepseek.com and b.ai relay keys
/// are not interchangeable; sharing one slot overwrites the other (hit 2026-09-20).
/// Host from an endpoint URL, used as the DS key-slot suffix (e.g. api.deepseek.com / api.b.ai).
pub fn host_of(base: &str) -> String {
    let b = base.trim();
    let rest = b.split_once("://").map(|(_, r)| r).unwrap_or(b);
    rest.split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_owned()
}

/// Save a classify backend key (backend ∈ "ds" | "typesafe").
pub fn save_classify_key(backend: &str, key: &str) -> Result<()> {
    save_label(&format!("classify:{backend}"), key)
}

/// Load a classify backend key: OS keyring → env (DS_API_KEY / TYPESAFE_API_KEY) → None.
pub fn load_classify_key(backend: &str) -> Result<Option<String>> {
    if let Some(value) = read_label(&format!("classify:{backend}"))? {
        return Ok(Some(value));
    }
    let var = if backend.starts_with("ds") {
        "DS_API_KEY"
    } else {
        "TYPESAFE_API_KEY"
    };
    match crate::env::var(var) {
        Ok(value) => Ok((!value.is_empty()).then_some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{var} is not valid Unicode"),
    }
}

/// Remember the last DS endpoint used (including path, e.g. https://api.b.ai/v1)
/// so a stored key is not paired with a host that dropped the path.
pub fn save_ds_last_base(base: &str) -> Result<()> {
    save_label("classify:ds-last-base", base)
}

/// Load the last DS endpoint used (full base).
pub fn load_ds_last_base() -> Result<Option<String>> {
    read_label("classify:ds-last-base")
}

/// Remember the last model used for an endpoint (relay names differ: official deepseek-chat, b.ai deepseek-v4.1-flash).
pub fn save_ds_model(host: &str, model: &str) -> Result<()> {
    save_label(&format!("classify:ds-model@{host}"), model)
}

/// Load the last model used for an endpoint.
pub fn load_ds_model(host: &str) -> Result<Option<String>> {
    read_label(&format!("classify:ds-model@{host}"))
}

/// Remember the classify backend choice (GUI "AI backend" dropdown; "jev" | "ds").
pub fn save_classify_backend(backend: &str) -> Result<()> {
    save_label("classify:last-backend", backend)
}

/// Load the last classify backend (None if unset; caller picks the default).
pub fn load_classify_backend() -> Result<Option<String>> {
    match read_label("classify:last-backend")? {
        Some(value) if value == "jev" || value == "ds" => Ok(Some(value)),
        Some(_) => anyhow::bail!("stored classification backend is invalid"),
        None => Ok(None),
    }
}
