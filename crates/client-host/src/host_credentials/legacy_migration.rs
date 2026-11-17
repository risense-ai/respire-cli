//! Legacy profile credential custody, performed only by the installation host.
use super::*;
use std::path::{Path, PathBuf};
use sha2::{Digest, Sha256};
use serde_json::Value;
use respire_protocol::host_control::{HostAuthSessionMaterial, HostAuthVaultFactors};
use respire_protocol::migration_control::{HostMigrationCustody, HostMigrationMaterial};

/// Secrets are deliberately neither serializable as recovery metadata nor printable.
pub struct LegacyMigration {
    source: PathBuf,
    source_id: String,
    session: Option<Vec<u8>>,
    password: Option<String>,
    material: HostMigrationMaterial,
}

fn no_links(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(!metadata.file_type().is_symlink(), "legacy source contains a symlink");
        #[cfg(windows)] {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "legacy source contains a reparse point");
        }
    }
    Ok(())
}

fn source_identity(path: &Path) -> Result<String> {
    let mut value = path.canonicalize()?.to_string_lossy().replace('\\', "/");
    if cfg!(windows) { value.make_ascii_lowercase(); }
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}

fn session_bytes(source: &Path) -> Result<Option<Vec<u8>>> {
    let path = source.join("session.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => { no_links(&path)?; Ok(Some(std::fs::read(path)?)) }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_candidates(session: &Value, services: &[&str], slot: &str, fields: &[&str]) -> Result<Vec<String>> {
    let mut values = Vec::new();
    for field in fields {
        if let Some(value) = session[*field].as_str() {
            if slot == "pass" || !value.is_empty() { values.push(value.to_owned()); }
        }
    }
    let user = session["user"].as_str().unwrap_or("").trim();
    let account = session["keyring_account"].as_str().filter(|value| !value.is_empty())
        .unwrap_or(if user.is_empty() { "local" } else { user });
    for service in services {
        for backend in credential_backends() {
            let request = CredentialRequest { credential_request: CREDENTIAL_SCHEMA_V,
                id: uuid::Uuid::new_v4().to_string(), service: (*service).into(),
                account: format!("{slot}:{account}"), backend: (*backend).into(), operation: CredentialOperation::Read };
            match execute(&request) {
                Ok(Some(value)) if slot == "pass" || !value.is_empty() => values.push(value),
                Ok(Some(_)) | Err(CredentialError::NoEntry) => {},
                Ok(None) => anyhow::bail!("legacy credential read returned no result"),
                Err(error) => anyhow::bail!("legacy credential source read failed ({error:?})"),
            }
        }
    }
    if slot == "super" {
        if let Ok(value) = crate::env::var("RSRS_SUPER") {
            if !value.is_empty() { values.push(value); }
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
    Ok(values)
}

impl LegacyMigration {
    /// Read candidates only. No credential writes precede Runtime's DB verification/fence.
    pub fn collect(source_id: &str) -> Result<Self> {
        anyhow::ensure!(source_id.len() == 64 && source_id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid legacy source identity");
        let home = crate::paths::home_dir().context("cannot locate host home for legacy migration")?;
        let mut selected = None;
        for (label, services) in [("respire", ["respire", "memocap", "1memory"]),
            ("onememory", ["1memory", "memocap", "respire"]), ("rsrs", ["rsrs", "respire", "1memory"])] {
            let root = home.join(format!(".{label}"));
            if !root.try_exists()? { continue; }
            no_links(&root)?;
            let mut paths = vec![root.clone()];
            let accounts = root.join("accounts");
            if accounts.try_exists()? {
                no_links(&accounts)?;
                for entry in std::fs::read_dir(accounts)? { paths.push(entry?.path()); }
            }
            for path in paths {
                no_links(&path)?;
                if source_identity(&path)? == source_id {
                    anyhow::ensure!(selected.is_none(), "legacy source identity is ambiguous");
                    selected = Some((path, services));
                }
            }
        }
        let (source, services) = selected.context("legacy source is no longer available")?;
        let bytes = session_bytes(&source)?;
        let mut material = HostMigrationMaterial { candidates: Vec::new(), custody: None };
        let mut password = None;
        if let Some(bytes) = &bytes {
            let session: Value = serde_json::from_slice(bytes).context("legacy session is invalid")?;
            let wrapped = session["wrapped_urk"].as_str().is_some_and(|value| !value.is_empty());
            let inline = ["pass", "super", "secret", "secret_key"].iter().any(|field| session.get(*field).is_some());
            if wrapped || inline {
                let version = session["vault_version"].as_u64().unwrap_or(1);
                anyhow::ensure!((1..=4).contains(&version), "unsupported legacy vault version");
                let passes = read_candidates(&session, &services, "pass", &["pass"])?;
                password = passes.first().cloned();
                let primaries = if version == 1 { passes } else {
                    read_candidates(&session, &services, "super", if version == 4 { &["secret_key", "super"] } else { &["super"] })?
                };
                let legacy = if matches!(version, 1 | 3) {
                    if session.get("legacy_secret_backend").is_some() {
                        read_session_legacy_secret(&session)?
                    } else {
                        Some(session[if version == 1 { "secret" } else { "secret_key" }].as_str()
                            .filter(|value| !value.is_empty()).context("original legacy factor is missing")?.to_owned())
                    }
                } else { None };
                for primary in primaries {
                    let factors = match version {
                        1 => HostAuthVaultFactors::V1 { password: primary, account_secret: legacy.clone().context("legacy account factor missing")? },
                        2 => HostAuthVaultFactors::V2 { super_password: primary },
                        3 => HostAuthVaultFactors::V3 { super_password: primary, secret_key: legacy.clone().context("legacy vault factor missing")? },
                        4 => HostAuthVaultFactors::V4 { super_password: primary },
                        _ => anyhow::bail!("unsupported legacy vault version"),
                    };
                    material.candidates.push(HostAuthSessionMaterial { session_sha256: hex::encode(Sha256::digest(bytes)), factors });
                }
                anyhow::ensure!(!material.candidates.is_empty(), "original legacy credentials are unavailable");
            }
        }
        Ok(Self { source, source_id: source_id.into(), session: bytes, password, material })
    }

    pub fn material(&self) -> &HostMigrationMaterial { &self.material }

    /// Called only after the matching private credentials_required response.
    /// Conflicts and interrupted writes retain source data and every staged slot.
    pub fn retain_selected(&mut self, details: &Value) -> Result<()> {
        anyhow::ensure!(details.as_object().is_some_and(|value| value.len() == 3)
            && details["state"] == "credentials_required", "invalid host custody requirement");
        no_links(&self.source)?;
        anyhow::ensure!(source_identity(&self.source)? == self.source_id && session_bytes(&self.source)? == self.session,
            "legacy source changed before host custody");
        let index = details["candidate_index"].as_u64().context("missing selected migration candidate")?;
        let candidate = self.material.candidates.get(usize::try_from(index)?).context("selected migration candidate is out of range")?.clone();
        anyhow::ensure!(details["session_sha256"].as_str() == Some(candidate.session_sha256.as_str()),
            "host custody requirement changed the source session");
        let alias = format!("legacy-{}", &self.source_id[..16]);
        let backend = credential_backends().iter().copied().find(|backend| *backend != "kernel")
            .context("legacy migration requires a persistent credential backend")?;
        let (primary_slot, primary, legacy) = match &candidate.factors {
            HostAuthVaultFactors::V1 { password, account_secret } => ("pass", password.as_str(), Some(account_secret.as_str())),
            HostAuthVaultFactors::V2 { super_password } | HostAuthVaultFactors::V4 { super_password } => ("super", super_password.as_str(), None),
            HostAuthVaultFactors::V3 { super_password, secret_key } => ("super", super_password.as_str(), Some(secret_key.as_str())),
        };
        ensure_legacy_slot(&alias, primary_slot, primary, backend, &mut execute)?;
        if let Some(factor) = legacy { ensure_legacy_slot(&alias, "legacy-secret", factor, backend, &mut execute)?; }
        let retained_password = if primary_slot == "pass" { true } else {
            if let Some(password) = &self.password { ensure_legacy_slot(&alias, "pass", password, backend, &mut execute)?; }
            self.password.is_some()
        };
        let legacy_backend = legacy.map(|_| backend.to_owned());
        self.material = HostMigrationMaterial { candidates: vec![candidate], custody: Some(HostMigrationCustody {
            keyring_account: alias, keyring_backend: backend.into(),
            legacy_secret_backend: legacy_backend, login_password_retained: retained_password,
        }) };
        Ok(())
    }
}
