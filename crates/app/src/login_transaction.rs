//! Prepare login without changing the active account; commit only after vault verification.
use std::path::{Path, PathBuf};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use std::io::Write;

#[derive(Serialize, Deserialize)]
struct Recovery {
    directory: PathBuf,
    original: Option<Vec<u8>>,
    config: Option<Vec<u8>>,
    alias: String,
    backends: Vec<String>,
    directory_existed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_login_restores_existing_and_new_profiles() -> Result<()> {
        let root = tempfile::tempdir()?;
        let previous_root = std::env::var_os("ONEMEMORY_DATA_DIR");
        let previous_super = std::env::var_os("ONEMEMORY_SUPER");
        std::env::set_var("ONEMEMORY_DATA_DIR", root.path());
        let code = crate::memory::crypto::generate_secret_key();
        std::env::set_var("ONEMEMORY_SUPER", &code);
        let result = (|| -> Result<()> {
            let config = br#"{"custom":"preserve","api_base":"https://previous.invalid"}"#;
            let old = br#"{"user":"existing","token":"old-token"}"#;
            std::fs::write(crate::service::client_config_path(), config)?;
            let existing = crate::service::account_dir("existing")?;
            std::fs::create_dir_all(&existing)?;
            std::fs::write(existing.join("session.json"), old)?;
            let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&code, &[42; 32])?;
            let vault = json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
            for user in ["existing", "new-account"] {
                let mut prepared = PreparedLogin::prepare_with_vault("https://fixture.invalid", &json!({"user":user,"token":"new-token"}), code.clone(), vault.clone(), None)?;
                let directory = prepared.directory.clone();
                prepared.commit()?;
                ensure!(recovery_pending(), "commit did not retain recovery state");
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    ensure!(std::fs::metadata(recovery_path())?.permissions().mode() & 0o777 == 0o600, "recovery is not private");
                }
                let record = std::fs::read_to_string(recovery_path())?;
                ensure!(!record.contains(&code), "recovery persisted the super password");
                drop(prepared); // Simulate process loss: only the durable record remains.
                recover_interrupted()?;
                recover_interrupted()?; // Recovery must be idempotent.
                ensure!(std::fs::read(crate::service::client_config_path())? == config, "configuration changed");
                ensure!(std::fs::read(existing.join("session.json"))? == old, "existing session changed");
                if user == "new-account" { ensure!(!directory.exists(), "failed new account remained selectable"); }
                ensure!(!recovery_pending(), "completed recovery retained its journal");
            }
            Ok(())
        })();
        match previous_root { Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value), None => std::env::remove_var("ONEMEMORY_DATA_DIR") }
        match previous_super { Some(value) => std::env::set_var("ONEMEMORY_SUPER", value), None => std::env::remove_var("ONEMEMORY_SUPER") }
        result
    }
}

fn recovery_path() -> PathBuf {
    crate::service::client_config_path().with_file_name(".login-recovery.json")
}

fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let temporary = path.with_file_name(format!(".login-write-{}", uuid::Uuid::new_v4().simple()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() && temporary.exists() { std::fs::remove_file(&temporary)?; }
    result
}

fn restore(path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    match bytes {
        Some(bytes) => private_write(path, bytes),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

pub fn recovery_pending() -> bool { recovery_path().exists() }

/// Called by the host under its takeover lock, after stopping the interrupted runtime.
/// Roll back local state only. A published cloud v4 wrap is resumed by the existing
/// migration path, which proves that the old and new wraps contain the same URK.
pub fn recover_interrupted() -> Result<()> {
    crate::service::require_profile_change_host()?;
    let path = recovery_path();
    ensure!(!std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()), "login recovery record must not be a symbolic link");
    let record: Recovery = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("invalid login recovery record; retain it for recovery")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(record.alias.starts_with("login-") && record.alias.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-'), "invalid recovery credential alias");
    ensure!(record.directory.exists() || record.original.is_none(), "original account directory is missing; retain the recovery record");
    if record.directory.exists() {
        read_original(&record.directory)?;
        restore(&record.directory.join("session.json"), record.original.as_deref())?;
    }
    restore(&crate::service::client_config_path(), record.config.as_deref())?;
    for backend in &record.backends {
        crate::keystore::remove_imported(&record.alias, "super", backend)?;
    }
    if !record.directory_existed && record.directory.exists() {
        let parent = record.directory.parent().context("recovery directory has no parent")?;
        std::fs::rename(&record.directory, parent.join(format!(".failed-{}", record.alias)))?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

pub struct PreparedLogin {
    pub user: String,
    pub directory: PathBuf,
    original: Option<Vec<u8>>,
    session: Value,
    super_password: String,
    alias: String,
    recovery_written: bool,
    migration_cloud: Option<Value>,
}

fn read_original(directory: &Path) -> Result<Option<Vec<u8>>> {
    let path = directory.join("session.json");
    if std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.file_type().is_symlink())
        || std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        anyhow::bail!("login destination must not be a symbolic link");
    }
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

impl PreparedLogin {
    pub fn prepare(addr: &str, authorized: &Value, super_password: String) -> Result<Self> {
        let vault = Self::fetch_vault(addr, authorized)?;
        Self::prepare_with_vault(addr, authorized, super_password, vault, None)
    }

    fn fetch_vault(addr: &str, authorized: &Value) -> Result<Value> {
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .get(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}")).call()
            .context("could not fetch the account vault")?.into_json().map_err(Into::into)
    }

    /// Only the explicitly selected legacy profile can be upgraded; raw memory rows are untouched.
    pub fn prepare_migration(addr: &str, authorized: &Value, password: &str, legacy_super: Option<&str>, secret_key: Option<&str>, new_super: Option<&str>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let mut local = crate::auth::read_session_json()?;
        ensure!(local["user"] == authorized["user"], "select the copied legacy account before migrating its vault");
        let version = local["vault_version"].as_i64().unwrap_or(1);
        ensure!((1..=4).contains(&version), "selected account has an unsupported vault version");
        let original = local.clone();
        if let Some(secret) = secret_key { local["secret_key"] = json!(secret); }
        let user = authorized["user"].as_str().context("authorization did not return a user")?;
        let unlock = if version == 4 { Some(new_super.filter(|code| !code.is_empty())
            .context("interrupted v4 migration requires --new-super <saved-recovery-code>")?) } else { legacy_super };
        let keys = crate::auth::unlock_session_keys(&local, password, unlock, user)?;
        let cloud = Self::fetch_vault(addr, authorized)?;
        if cloud["version"].as_i64() == Some(4) {
            // A prior publication can have committed even when both its response
            // and the confirmation fetch were lost. Resume only with the saved
            // recovery code and proof that both wraps contain the same data key.
            let recovery = new_super.filter(|code| !code.is_empty())
                .context("cloud vault is already v4; resume with --new-super <displayed-recovery-code>")?;
            return Self::prepare_with_vault(addr, authorized, recovery.to_owned(), cloud, Some((original, keys.urk)));
        }
        ensure!(cloud["version"].as_i64().is_some_and(|version| (2..=3).contains(&version)),
            "cloud vault differs from the selected legacy library; original keys and data were preserved");
        if version == 4 {
            // Repair pre-journal DEV interruptions only after proving the cloud
            // legacy wrap and the saved local v4 wrap hold the same data key.
            let mut legacy_cloud = cloud.clone();
            legacy_cloud["vault_version"] = cloud["version"].clone();
            if let Some(secret) = secret_key { legacy_cloud["secret_key"] = json!(secret); }
            let cloud_keys = crate::auth::unlock_session_keys(&legacy_cloud, password, legacy_super, user)?;
            ensure!(cloud_keys.urk == keys.urk, "cloud and local vault data keys differ; original data was preserved");
        } else {
            ensure!(["kdf_salt", "wrapped_urk", "urk_nonce"].iter().all(|field| cloud[*field] == local[*field]),
                "cloud vault differs from the selected legacy library; original keys and data were preserved");
        }
        let super_password = if let Some(code) = new_super.filter(|code| !code.is_empty()) { code.to_owned() } else if version == 3 {
            local["secret_key"].as_str().context("legacy Secret Key is required")?.to_owned()
        } else { crate::memory::crypto::generate_secret_key() };
        let (salt, wrapped, nonce) = crate::auth::wrap_with_v4(&super_password, &keys.urk)?;
        let vault = json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        let mut prepared = Self::prepare_with_vault(addr, authorized, super_password, vault, Some((original, keys.urk)))?;
        prepared.migration_cloud = Some(cloud);
        Ok(prepared)
    }

    pub fn migration_super_password(&self) -> Option<&str> {
        self.migration_cloud.as_ref().map(|_| self.super_password.as_str())
    }

    /// Publish the unchanged URK's new wrap only after host/runtime verification.
    pub fn finish_migration(&self, addr: &str, authorized: &Value) -> Result<()> {
        let Some(original) = self.migration_cloud.as_ref() else { return Ok(()); };
        ensure!(Self::fetch_vault(addr, authorized)? == *original, "cloud vault changed during migration; original local session was restored");
        let vault = json!({"version":4,"kdf_salt":self.session["kdf_salt"],"wrapped_urk":self.session["wrapped_urk"],"urk_nonce":self.session["urk_nonce"]});
        let token = authorized["token"].as_str().context("authorization did not return a token")?;
        let result = ureq::AgentBuilder::new().redirects(0).timeout(std::time::Duration::from_secs(30)).build()
            .post(&format!("{}/api/self/vault", addr.trim().trim_end_matches('/')))
            .set("Authorization", &format!("Bearer {token}")).send_json(vault.clone());
        if let Err(error) = result {
            // A lost HTTP response can follow a committed write; inspect that exact wrap once.
            if Self::fetch_vault(addr, authorized).is_ok_and(|current| current == vault) { return Ok(()); }
            return Err(anyhow!("legacy vault publication failed: {error}; retain the displayed recovery code and the original library"));
        }
        Ok(())
    }

    fn prepare_with_vault(addr: &str, authorized: &Value, super_password: String, vault: Value, legacy: Option<(Value, [u8; 32])>) -> Result<Self> {
        crate::service::require_profile_change_host()?;
        let user = authorized["user"].as_str().filter(|user| !user.is_empty()).context("authorization did not return a user")?.to_owned();
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        let base = addr.trim().trim_end_matches('/');
        ensure!(vault["version"].as_i64() == Some(4), "this account uses a legacy vault; migrate the old account explicitly before normal login");
        let salt = vault["kdf_salt"].as_str().context("vault missing kdf_salt")?;
        let wrapped = vault["wrapped_urk"].as_str().context("vault missing wrapped_urk")?;
        let nonce = vault["urk_nonce"].as_str().context("vault missing urk_nonce")?;
        let verified = crate::memory::SessionKeys::unlock_v4(&super_password, salt, wrapped, nonce)
            .context("super password does not unlock this account; the original account was preserved")?;
        let current = crate::service::data_dir();
        let main = crate::service::main_data_dir();
        let directory = if crate::service::session_user_of_dir(&current) == user { current }
            else if crate::service::session_user_of_dir(&main) == user { main }
            else { crate::service::account_dir(&user)? };
        let original = read_original(&directory)?;
        let mut session: Value = match original.as_deref() {
            Some(bytes) => serde_json::from_slice(bytes).context("target account session is invalid; original files were preserved")?,
            None => json!({}),
        };
        ensure!(session.is_object(), "target account session must be an object");
        ensure!(session["user"].as_str().is_none_or(|owner| owner.is_empty() || owner == user), "destination belongs to another account");
        if let Some((original, urk)) = legacy.as_ref() {
            ensure!(session == *original && verified.urk == *urk, "legacy session changed or migration would replace its data key");
        }
        let database = directory.join("onememory.db");
        if database.is_file() {
            let database = rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
            if has_memories {
                let count: i64 = database.query_row("SELECT count(*) FROM memories WHERE ciphertext <> ''", [], |row| row.get(0))?;
                if count > 0 {
                    let same_wrap = session["kdf_salt"] == vault["kdf_salt"] && session["wrapped_urk"] == vault["wrapped_urk"] && session["urk_nonce"] == vault["urk_nonce"];
                    if legacy.is_none() && !same_wrap {
                        // Full logout removes the wrap, and a super-password change can
                        // rewrap the same URK. Prove compatibility against local data.
                        let mut statement = database.prepare("SELECT ciphertext,nonce FROM memories WHERE ciphertext <> '' AND COALESCE(deleted,0)=0")?;
                        let mut rows = statement.query([])?;
                        let mut verified_rows = 0;
                        while let Some(row) = rows.next()? {
                            let mut stored = crate::memory::model::StoredMemory::new_pending(String::new(), String::new());
                            stored.ciphertext = row.get(0)?;
                            stored.nonce = row.get(1)?;
                            crate::memory::MemoryEngine::open(&verified, &stored)
                                .context("local library uses different key material; original data was preserved")?;
                            verified_rows += 1;
                        }
                        ensure!(verified_rows > 0, "local library key compatibility could not be verified; original data was preserved");
                    }
                }
            }
        }
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        for field in ["pass", "super", "secret", "secret_key"] { session.as_object_mut().map(|object| object.remove(field)); }
        session["user"] = json!(user);
        session["addr"] = json!(base);
        session["token"] = json!(token);
        session["session_id"] = authorized["session_id"].clone();
        session["vault_version"] = json!(4);
        session["kdf_salt"] = vault["kdf_salt"].clone();
        session["wrapped_urk"] = vault["wrapped_urk"].clone();
        session["urk_nonce"] = vault["urk_nonce"].clone();
        session["keyring_account"] = json!(alias);
        Ok(Self { user, directory, original, session, super_password, alias, recovery_written: false, migration_cloud: None })
    }

    pub fn commit(&mut self) -> Result<()> {
        ensure!(read_original(&self.directory)? == self.original, "target session changed during login; original account was preserved");
        let result = self.commit_inner();
        if let Err(error) = result {
            return match self.rollback() { Ok(()) => Err(error), Err(rollback) => Err(error.context(format!("login rollback failed: {rollback:#}"))) };
        }
        Ok(())
    }

    fn commit_inner(&mut self) -> Result<()> {
        let path = recovery_path();
        ensure!(!path.exists(), "interrupted login must be recovered before another commit");
        let config = match std::fs::read(crate::service::client_config_path()) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let mut recovery = Recovery { directory: self.directory.clone(), original: self.original.clone(), config,
            alias: self.alias.clone(), backends: Vec::new(), directory_existed: self.directory.exists() };
        std::fs::create_dir_all(path.parent().context("recovery root is missing")?)?;
        private_write(&path, &serde_json::to_vec(&recovery)?)?;
        self.recovery_written = true;
        if std::env::var("ONEMEMORY_SUPER").is_ok_and(|value| value == self.super_password) {
            // Headless hosts explicitly supply the same verified key to their runtime.
            self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
        } else {
            let backend = crate::keystore::import_credential_checkpoint(&self.alias, "super", &self.super_password, |backend| {
                recovery.backends.push(backend.to_owned());
                private_write(&path, &serde_json::to_vec(&recovery)?)
            })?;
            self.session["keyring_backend"] = json!(backend);
        }
        if !self.directory.exists() {
            let parent = self.directory.parent().context("account directory has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::create_dir(&self.directory)?;
        }
        private_write(&self.directory.join("session.json"), &serde_json::to_vec_pretty(&self.session)?)?;
        crate::service::set_data_dir(&self.directory.to_string_lossy())?;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        if self.recovery_written {
            recover_interrupted()?;
            self.recovery_written = false;
        }
        Ok(())
    }

    pub fn complete(&self) -> Result<()> {
        std::fs::remove_file(recovery_path()).context("login verified but recovery record could not be retired")
    }
}
