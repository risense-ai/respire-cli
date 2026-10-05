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
        crate::service::require_profile_change_host()?;
        let user = authorized["user"].as_str().filter(|user| !user.is_empty()).context("authorization did not return a user")?.to_owned();
        let token = authorized["token"].as_str().filter(|token| !token.is_empty()).context("authorization did not return a token")?;
        let base = addr.trim().trim_end_matches('/');
        let vault: Value = ureq::get(&format!("{base}/api/self/vault"))
            .set("Authorization", &format!("Bearer {token}")).call()
            .context("could not fetch the account vault")?.into_json()?;
        ensure!(vault["version"].as_i64() == Some(4), "this account uses a legacy vault; migrate the old account explicitly before normal login");
        let salt = vault["kdf_salt"].as_str().context("vault missing kdf_salt")?;
        let wrapped = vault["wrapped_urk"].as_str().context("vault missing wrapped_urk")?;
        let nonce = vault["urk_nonce"].as_str().context("vault missing urk_nonce")?;
        crate::memory::SessionKeys::unlock_v4(&super_password, salt, wrapped, nonce)
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
        let database = directory.join("onememory.db");
        if database.is_file() {
            let database = rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let has_memories: bool = database.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories')", [], |row| row.get(0))?;
            if has_memories {
                let count: i64 = database.query_row("SELECT count(*) FROM memories WHERE ciphertext <> ''", [], |row| row.get(0))?;
                if count > 0 {
                    ensure!(session["kdf_salt"] == vault["kdf_salt"] && session["wrapped_urk"] == vault["wrapped_urk"] && session["urk_nonce"] == vault["urk_nonce"],
                        "local library uses different key material; migrate or export it before login; original data was preserved");
                }
            }
        }
        let alias = format!("login-{}", uuid::Uuid::new_v4().simple());
        for field in ["pass", "super", "secret_key"] { session.as_object_mut().map(|object| object.remove(field)); }
        session["user"] = json!(user);
        session["addr"] = json!(base);
        session["token"] = json!(token);
        session["session_id"] = authorized["session_id"].clone();
        session["vault_version"] = json!(4);
        session["kdf_salt"] = vault["kdf_salt"].clone();
        session["wrapped_urk"] = vault["wrapped_urk"].clone();
        session["urk_nonce"] = vault["urk_nonce"].clone();
        session["keyring_account"] = json!(alias);
        Ok(Self { user, directory, original, session, super_password, alias, backend: None, directory_created: false, session_written: false })
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
        self.backend = Some(crate::keystore::import_credential(&self.alias, "super", &self.super_password)?.to_owned());
        self.session["keyring_backend"] = json!(self.backend);
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
            let recovered = crate::service::accounts_root().parent().context("profile recovery root is unavailable")?
                .join(format!(".failed-{}", self.alias));
            if let Err(error) = std::fs::rename(&self.directory, recovered) { errors.push(format!("account rollback: {error}")); }
            else { self.directory_created = false; }
        }
        if errors.is_empty() { Ok(()) } else { Err(anyhow!(errors.join("; "))) }
    }
}
