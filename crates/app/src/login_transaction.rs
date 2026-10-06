//! Prepare login without changing the active account; commit only after vault verification.
use std::path::{Path, PathBuf};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};

pub struct PreparedLogin {
    pub user: String,
    pub directory: PathBuf,
    original: Option<Vec<u8>>,
    session: Value,
    super_password: String,
    alias: String,
    backend: Option<String>,
    directory_created: bool,
    session_written: bool,
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
        ensure!((1..=3).contains(&version), "selected account does not use a legacy vault");
        let original = local.clone();
        if let Some(secret) = secret_key { local["secret_key"] = json!(secret); }
        let user = authorized["user"].as_str().context("authorization did not return a user")?;
        let keys = crate::auth::unlock_session_keys(&local, password, legacy_super, user)?;
        let cloud = Self::fetch_vault(addr, authorized)?;
        if cloud["version"].as_i64() == Some(4) {
            // A prior publication can have committed even when both its response
            // and the confirmation fetch were lost. Resume only with the saved
            // recovery code and proof that both wraps contain the same data key.
            let recovery = new_super.filter(|code| !code.is_empty())
                .context("cloud vault is already v4; resume with --new-super <displayed-recovery-code>")?;
            return Self::prepare_with_vault(addr, authorized, recovery.to_owned(), cloud, Some((original, keys.urk)));
        }
        ensure!(cloud["version"].as_i64().is_some_and(|version| (2..=3).contains(&version))
            && ["kdf_salt", "wrapped_urk", "urk_nonce"].iter().all(|field| cloud[*field] == local[*field]),
            "cloud vault differs from the selected legacy library; original keys and data were preserved");
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
        Ok(Self { user, directory, original, session, super_password, alias, backend: None, directory_created: false, session_written: false, migration_cloud: None })
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
        if std::env::var("ONEMEMORY_SUPER").is_ok_and(|value| value == self.super_password) {
            // Headless hosts explicitly supply the same verified key to their runtime.
            self.session.as_object_mut().map(|object| { object.remove("keyring_account"); object.remove("keyring_backend"); });
        } else {
            self.backend = Some(crate::keystore::import_credential(&self.alias, "super", &self.super_password)?.to_owned());
            self.session["keyring_backend"] = json!(self.backend);
        }
        if !self.directory.exists() {
            let parent = self.directory.parent().context("account directory has no parent")?;
            std::fs::create_dir_all(parent)?;
            std::fs::create_dir(&self.directory)?;
            self.directory_created = true;
        }
        // Keep the original bytes in memory until runtime startup is verified.
        self.session_written = true;
        std::fs::write(self.directory.join("session.json"), serde_json::to_vec_pretty(&self.session)?)?;
        crate::service::set_data_dir(&self.directory.to_string_lossy())?;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        if self.session_written {
            let restored = match &self.original {
                Some(bytes) => std::fs::write(self.directory.join("session.json"), bytes),
                None => match std::fs::remove_file(self.directory.join("session.json")) {
                    Ok(()) => Ok(()), Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()), Err(error) => Err(error),
                },
            };
            if let Err(error) = restored { errors.push(format!("session restoration: {error}")); }
            else { self.session_written = false; }
        }
        if let Some(backend) = self.backend.as_deref() {
            if let Err(error) = crate::keystore::remove_imported(&self.alias, "super", backend) { errors.push(error.to_string()); }
            else { self.backend = None; }
        }
        if self.directory_created && !self.session_written {
            // A failed runtime can have written files: retain them outside the selectable account path.
            match crate::service::accounts_root().parent() {
                None => errors.push("profile recovery root is unavailable".to_owned()),
                Some(root) => {
                    let recovered = root.join(format!(".failed-{}", self.alias));
                    if let Err(error) = std::fs::rename(&self.directory, recovered) { errors.push(format!("account rollback: {error}")); }
                    else { self.directory_created = false; }
                }
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(anyhow!(errors.join("; "))) }
    }
}
