//! Public registration custody intent. Plaintext factors stay in the host credential store.
use super::*;
use respire_protocol::HostAuthKeygenMaterial;
use respire_client_host::host_credentials as credentials;
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    operation_id: String,
    root: PathBuf,
    source: PathBuf,
    identity: HostAuthIdentity,
    reused: bool,
    candidate: Value,
    password_commitment: String,
}

fn password_commitment(material: &HostAuthKeygenMaterial, password: &str) -> Result<String> {
    // The random Super Key prevents offline guessing from this public intent record.
    Ok(hash(&serde_json::to_vec(&(&material.super_password, password))?))
}

impl Maintenance {
    fn registration_path(&self) -> Result<PathBuf> {
        Ok(self.account_record.as_ref().context("registration account owner is missing")?
            .path.with_extension("registration.json"))
    }

    fn registration(&self, operation_id: &str, source: &Path,
        identity: &HostAuthIdentity) -> Result<Option<Registration>> {
        self.check_owner()?;
        let bytes = private_io::bounded_bytes(&self.registration_path()?, MAINTENANCE_MARKER_MAX_BYTES)?;
        let Some(bytes) = bytes else { return Ok(None); };
        let record: Registration = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(record.operation_id == operation_id && record.root == self.root
            && record.source == source && record.identity == *identity,
            "registration custody intent changed its original owner");
        Ok(Some(record))
    }

    pub(crate) fn prepare_registration(&mut self, operation_id: &str, source: &Path,
        identity: &HostAuthIdentity, password: &str, supplied_super: Option<&str>)
        -> Result<HostAuthKeygenMaterial> {
        let existing = self.registration(operation_id, source, identity)?;
        let (material, record) = if let Some(record) = existing {
            let material = crate::auth_material::load(&record.candidate)?;
            anyhow::ensure!(password_commitment(&material, password)? == record.password_commitment,
                "registration password differs from the original custody intent");
            (material, record)
        } else {
            let reused = matches!(identity, HostAuthIdentity::Unbound { .. });
            let material = if reused {
                let bytes = private_io::bounded_bytes(&source.join("session.json"), MAINTENANCE_MARKER_MAX_BYTES)?
                    .context("unbound registration source is missing")?;
                crate::auth_material::load(&serde_json::from_slice(&bytes)?)?
            } else { crate::auth_material::generate()? };
            if let Some(expected) = supplied_super {
                anyhow::ensure!(expected == material.super_password,
                    "recovery code does not match the host registration vault");
            }
            let candidate = json!({"vault_version":4,"kdf_salt":material.kdf_salt,
                "wrapped_urk":material.wrapped_urk,"urk_nonce":material.urk_nonce,
                "keyring_account":material.keyring_account,"keyring_backend":material.keyring_backend});
            let record = Registration { operation_id: operation_id.to_owned(), root: self.root.clone(),
                source: source.to_owned(), identity: identity.clone(), reused, candidate,
                password_commitment: password_commitment(&material, password)? };
            crate::auth_material::persist(&material, || {
                private_write(&self.registration_path()?, &serde_json::to_vec(&record)?, None)
            })?;
            (material, record)
        };
        if let Some(expected) = supplied_super {
            anyhow::ensure!(expected == material.super_password,
                "recovery code does not match the original host registration vault");
        }
        if let Err(error) = crate::auth_material::persist_password(&material, password) {
            if !record.reused {
                crate::auth_material::remove(&material, Some(password))
                    .context("registration custody failed; retain the original intent until cleanup succeeds")?;
            }
            return Err(error.context("host registration custody did not complete; no request was sent"));
        }
        Ok(material)
    }

    pub(crate) fn rollback_registration(&mut self, operation_id: &str, source: &Path,
        identity: &HostAuthIdentity) -> Result<()> {
        let Some(record) = self.registration(operation_id, source, identity)? else { return Ok(()); };
        if record.reused { return Ok(()); }
        let account = record.candidate["keyring_account"].as_str().context("registration slot is missing")?;
        let backend = record.candidate["keyring_backend"].as_str().context("registration backend is missing")?;
        let super_password = credentials::read_auth_super(account, backend)?;
        let password = credentials::read_auth_password(account, backend)?;
        if super_password.is_none() && password.is_none() { return Ok(()); }
        let material = crate::auth_material::load(&record.candidate)?;
        if let Some(password) = password.as_deref() {
            anyhow::ensure!(password_commitment(&material, password)? == record.password_commitment,
                "registration password slot changed; preserve both credentials and the original intent");
        }
        crate::auth_material::remove(&material, password.as_deref())
    }

    pub(crate) fn registration_super(&self, operation_id: &str, source: &Path,
        identity: &HostAuthIdentity, target: &Path) -> Result<String> {
        let record = self.registration(operation_id, source, identity)?
            .context("committed registration custody intent is missing")?;
        let bytes = private_io::bounded_bytes(&target.join("session.json"), MAINTENANCE_MARKER_MAX_BYTES)?
            .context("committed registration session is missing")?;
        let session: Value = serde_json::from_slice(&bytes)?;
        anyhow::ensure!(record.candidate.as_object().context("invalid registration candidate")?
            .iter().all(|(field, value)| session.get(field) == Some(value)),
            "committed registration vault differs from host custody intent");
        Ok(crate::auth_material::load(&record.candidate)?.super_password)
    }
}
