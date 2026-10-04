//! Copy legacy default homes without modifying the original libraries or credentials.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RECEIPT: &str = ".rsrs-migration.json";
const DEFAULT_ENV: &str = "RESPIRE_DEFAULT_DATA_DIR";

struct Profile {
    source: PathBuf,
    destination: PathBuf,
    identity: String,
    services: [&'static str; 3],
}

/// The SDK accepts the original data-root environment variable. This marker lets
/// app configuration retain its default-home and active-profile semantics.
pub(crate) fn internally_configured_root(value: &str) -> bool {
    std::env::var(DEFAULT_ENV).ok().is_some_and(|marker| {
        equivalent_path(
            &crate::service::expand_tilde(&marker),
            &crate::service::expand_tilde(value),
        ) && equivalent_path(
            &crate::service::expand_tilde(value),
            &crate::service::default_data_dir(),
        )
    })
}

fn equivalent_path(left: &Path, right: &Path) -> bool {
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|root| root.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    };
    let normalize = |path: PathBuf| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    };
    let left = normalize(absolute(left));
    let right = normalize(absolute(right));
    if cfg!(windows) {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    } else {
        left == right
    }
}

/// Run before command parsing or runtime creation. Explicit isolated roots never
/// import default-home state. A failed attempt leaves source and staging intact.
pub fn ensure_default_home() -> Result<()> {
    if ["ONEMEMORY_CLIENT_ONLY", "ONEMEMORY_NO_AUTOSTART"]
        .iter()
        .any(|name| {
            std::env::var(name).ok().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "on" | "yes"
                )
            })
        })
    {
        return Ok(());
    }
    if let Ok(value) = std::env::var("ONEMEMORY_DATA_DIR") {
        if !value.trim().is_empty() && !internally_configured_root(value.trim()) {
            return Ok(());
        }
    }
    let home = crate::service::home_dir().context("cannot locate the user home for migration")?;
    migrate_home(&home)?;
    let root = home.join(".rsrs");
    // This occurs at single-threaded startup, before Core or runtime workers exist.
    std::env::set_var("ONEMEMORY_DATA_DIR", &root);
    std::env::set_var(DEFAULT_ENV, &root);
    Ok(())
}

fn meaningful(path: &Path) -> Result<bool> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("migration root is a symbolic link; no external data was copied");
        }
    }
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(path)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if !excluded(&name) && name != RECEIPT {
            return Ok(true);
        }
    }
    Ok(false)
}

fn excluded(name: &str) -> bool {
    matches!(
        name,
        "runtime" | "bin" | "lock.db" | "lock.db-wal" | "lock.db-shm"
    ) || name.ends_with("-wal")
        || name.ends_with("-shm")
        || name.ends_with(".pid")
        || name.starts_with("runtime.")
        || name == "runtime.json"
        || name == "runtime-token"
}

fn identity(path: &Path) -> Result<String> {
    let canonical = path.canonicalize()?;
    let mut value = canonical.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        value.make_ascii_lowercase();
    }
    Ok(hex::encode(Sha256::digest(value.as_bytes())))
}

fn receipt_matches(destination: &Path, source_id: &str) -> Result<bool> {
    let path = destination.join(RECEIPT);
    if !path.is_file() {
        return Ok(false);
    }
    let receipt: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(receipt["source_identity"].as_str() == Some(source_id) && receipt["complete"] == true)
}

fn safe_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn destination_for(base: PathBuf, id: &str, reserved: &mut BTreeSet<PathBuf>) -> Result<PathBuf> {
    if (!base.exists() || !meaningful(&base)? || receipt_matches(&base, id)?)
        && reserved.insert(base.clone())
    {
        return Ok(base);
    }
    let name = base
        .file_name()
        .ok_or_else(|| anyhow!("invalid migration destination"))?
        .to_string_lossy();
    let alternate = base.with_file_name(format!("{name}-{}", &id[..16]));
    if alternate.exists() && !receipt_matches(&alternate, id)? {
        bail!("legacy migration destination conflict; original libraries were preserved");
    }
    if !reserved.insert(alternate.clone()) {
        bail!("duplicate legacy migration destination");
    }
    Ok(alternate)
}

/// Also used by fixture-only tests; it does not replace HOME or access runtime services.
fn migrate_home(home: &Path) -> Result<()> {
    let target = home.join(".rsrs");
    if let Ok(metadata) = std::fs::symlink_metadata(target.join("accounts")) {
        if metadata.file_type().is_symlink() {
            bail!("new account root is a symbolic link; no external data was written");
        }
    }
    let sources = [
        ("respire", ["respire", "memocap", "1memory"]),
        ("onememory", ["1memory", "memocap", "respire"]),
    ];
    let mut roots = Vec::new();
    for (label, services) in sources {
        let path = home.join(format!(".{label}"));
        if meaningful(&path)? {
            roots.push((label, path, services));
        }
    }
    if roots.is_empty() {
        return Ok(());
    }
    let lock_root = home.join(".rsrs-migration-lock");
    private_directory(&lock_root)?;
    let _lock = crate::lock::LibraryLock::acquire(&lock_root, Duration::from_secs(30))?;
    let fresh = !meaningful(&target)?;
    let mut reserved = BTreeSet::new();
    let mut profiles = Vec::new();
    for (index, (label, source, services)) in roots.iter().enumerate() {
        let id = identity(source)?;
        let main = if fresh && index == 0 || receipt_matches(&target, &id)? {
            reserved.insert(target.clone());
            target.clone()
        } else {
            destination_for(
                target.join("accounts").join(format!("legacy-{label}")),
                &id,
                &mut reserved,
            )?
        };
        profiles.push(Profile {
            source: source.clone(),
            destination: main,
            identity: id,
            services: *services,
        });
        let accounts = source.join("accounts");
        if accounts.is_dir() {
            let mut entries = std::fs::read_dir(accounts)?.collect::<std::io::Result<Vec<_>>>()?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                if !meaningful(&entry.path())? {
                    continue;
                }
                let id = identity(&entry.path())?;
                let original = safe_name(&entry.file_name().to_string_lossy());
                let name = if index == 0 && (fresh || profiles[0].destination == target) {
                    original
                } else {
                    format!("legacy-{label}-{original}")
                };
                let destination =
                    destination_for(target.join("accounts").join(name), &id, &mut reserved)?;
                profiles.push(Profile {
                    source: entry.path(),
                    destination,
                    identity: id,
                    services: *services,
                });
            }
        }
    }
    let pending = profiles
        .iter()
        .filter_map(
            |profile| match receipt_matches(&profile.destination, &profile.identity) {
                Ok(true) => None,
                result => Some(result.map(|_| profile)),
            },
        )
        .collect::<Result<Vec<_>>>()?;
    if pending.is_empty() {
        return Ok(());
    }
    let staging_root = home.join(".rsrs-migration-staging");
    private_directory(&staging_root)?;
    let staging = staging_root.join(uuid::Uuid::new_v4().to_string());
    private_directory(&staging)?;
    let mut completed = Vec::new();
    // Provider settings belong to the user's selected global source, not to
    // every account. Existing new provider entries always retain precedence.
    crate::keystore::import_classification(&roots[0].2)?;
    for (index, profile) in pending.iter().enumerate() {
        let stage = staging.join(format!("profile-{index}"));
        snapshot_profile(profile, &stage, &profiles)?;
        completed.push((profile, stage));
    }
    // A new default home is published in one rename, including every account.
    if fresh {
        let (_, main_stage) = completed
            .iter()
            .find(|(profile, _)| profile.destination == target)
            .ok_or_else(|| anyhow!("missing main migration snapshot"))?;
        for (profile, stage) in &completed {
            if profile.destination == target {
                continue;
            }
            let relative = profile.destination.strip_prefix(&target)?;
            let destination = main_stage.join(relative);
            if let Some(parent) = destination.parent() {
                private_directory(parent)?;
            }
            std::fs::rename(stage, destination)?;
        }
        if target.exists() {
            // Only an empty directory may be replaced; never remove existing state.
            std::fs::remove_dir(&target)
                .context("new home is no longer empty; migration was not published")?;
        }
        std::fs::rename(main_stage, &target)?;
    } else {
        for (profile, stage) in completed {
            if profile.destination.exists() {
                std::fs::remove_dir(&profile.destination)
                    .context("migration destination changed; no state was overwritten")?;
            }
            if let Some(parent) = profile.destination.parent() {
                private_directory(&target)?;
                private_directory(parent)?;
            }
            std::fs::rename(stage, &profile.destination)?;
        }
    }
    eprintln!("legacy library copied safely to ~/.rsrs; original directories and credentials were retained");
    Ok(())
}

fn snapshot_profile(profile: &Profile, stage: &Path, profiles: &[Profile]) -> Result<()> {
    // Reading a held SQLite library lock detects an active original writer without
    // stopping it or modifying its lock file.
    let old_lock = profile.source.join("lock.db");
    let mut legacy_active = false;
    if old_lock.is_file() {
        let connection = Connection::open_with_flags(old_lock, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_millis(100))?;
        match connection.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0)) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                legacy_active = true;
                eprintln!("legacy runtime is active: migration captures committed data at the snapshot; use rsrs after upgrading; later unsynced old writes remain in the original library");
            }
            Err(error) => return Err(error.into()),
        }
    }
    let session_path = profile.source.join("session.json");
    let original_session = if session_path.is_file() {
        Some(std::fs::read(&session_path)?)
    } else {
        None
    };
    copy_tree(&profile.source, stage, true)?;
    let database = stage.join("onememory.db");
    if database.is_file() {
        private_file(&database)?;
    }
    let mut keyring_backend = None;
    if let Some(bytes) = original_session.as_ref() {
        let mut session: Value = serde_json::from_slice(bytes)
            .context("legacy session is invalid; source was preserved")?;
        migrate_credentials(profile, &mut session)?;
        keyring_backend = session.get("keyring_backend").cloned();
        rewrite_address(&mut session);
        write_json(&stage.join("session.json"), &session)?;
    }
    for name in ["client.json", "agent.json"] {
        let path = stage.join(name);
        if path.is_file() {
            let mut config: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            rewrite_address(&mut config);
            if let Some(value) = config["data_dir"]
                .as_str()
                .filter(|value| !value.is_empty())
            {
                let old = crate::service::expand_tilde(value);
                if old
                    .components()
                    .any(|component| matches!(component, std::path::Component::ParentDir))
                {
                    bail!("legacy configuration contains a parent-directory path; originals were preserved");
                }
                if let Some(found) = profiles
                    .iter()
                    .filter(|candidate| old.starts_with(&candidate.source))
                    .max_by_key(|candidate| candidate.source.components().count())
                {
                    config["data_dir"] =
                        json!(found.destination.join(old.strip_prefix(&found.source)?));
                } else {
                    bail!("legacy configuration uses an external data directory; originals were preserved; set ONEMEMORY_DATA_DIR explicitly to open it");
                }
            }
            write_json(&path, &config)?;
        }
    }
    if let Some(bytes) = original_session {
        if std::fs::read(session_path)? != bytes {
            bail!("legacy identity changed during migration; retry after closing the old runtime");
        }
    }
    write_json(
        &stage.join(RECEIPT),
        &json!({"schema":1,"complete":true,"source_identity":profile.identity,
        "source":profile.source,"destination":profile.destination,
            "api_default":crate::service::DEFAULT_SERVER_ADDR,"original_preserved":true,
            "keyring_backend":keyring_backend,
        "snapshot_at":chrono::Utc::now().to_rfc3339(),"legacy_runtime_active":legacy_active,
        "snapshot_only":true}),
    )?;
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path, root: bool) -> Result<()> {
    private_directory(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let text = name.to_string_lossy();
        if excluded(&text) || text == RECEIPT || root && text == "accounts" {
            continue;
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("legacy library contains a symbolic link; no external data was copied");
        }
        let target = destination.join(&name);
        if kind.is_dir() {
            copy_tree(&entry.path(), &target, false)?;
        } else if kind.is_file() {
            if text.ends_with(".db") || text.ends_with(".sqlite") || text.ends_with(".sqlite3") {
                snapshot_database(&entry.path(), &target)?;
            } else {
                std::fs::copy(entry.path(), &target)?;
                private_file(&target)?;
            }
        }
    }
    Ok(())
}

fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    let source = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.busy_timeout(Duration::from_millis(200))?;
    let mut destination = Connection::open(destination)?;
    let backup = Backup::new(&source, &mut destination)?;
    let began = Instant::now();
    loop {
        match backup.step(256)? {
            StepResult::Done => break,
            _ if began.elapsed() >= Duration::from_secs(60) => {
                bail!("legacy SQLite snapshot remained busy; migration was not published")
            }
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    drop(backup);
    let result: String = destination.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if result != "ok" {
        bail!("legacy SQLite snapshot failed integrity validation");
    }
    if let Some(path) = destination.path() {
        private_file(Path::new(path))?;
    }
    Ok(())
}

fn candidate_values(
    profile: &Profile,
    user: &str,
    slot: &str,
    fields: &[&str],
    session: &Value,
) -> Vec<String> {
    let mut values = Vec::new();
    for field in fields {
        if let Some(value) = session[field].as_str().filter(|value| !value.is_empty()) {
            values.push(value.to_owned());
        }
    }
    let account = if user.trim().is_empty() {
        "local"
    } else {
        user.trim()
    };
    for service in profile.services {
        values.extend(crate::keystore::read_credentials(
            service,
            &format!("{slot}:{account}"),
        ));
    }
    if slot == "super" {
        if let Ok(value) = std::env::var("ONEMEMORY_SUPER") {
            if !value.is_empty() {
                values.push(value);
            }
        }
    }
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
    values
}

fn migrate_credentials(profile: &Profile, session: &mut Value) -> Result<()> {
    if session["wrapped_urk"].as_str().is_none() {
        return Ok(());
    }
    let user = session["user"].as_str().unwrap_or("").to_owned();
    let passes = candidate_values(profile, &user, "pass", &["pass"], session);
    let supers = candidate_values(
        profile,
        &user,
        "super",
        if session["vault_version"].as_i64().unwrap_or(1) >= 4 {
            &["secret_key", "super"]
        } else {
            &["super"]
        },
        session,
    );
    let version = session["vault_version"].as_i64().unwrap_or(1);
    let mut unlocked = None;
    if version >= 2 {
        for super_pass in &supers {
            if let Ok(keys) = crate::auth::unlock_session_keys(session, "", Some(super_pass), &user)
            {
                unlocked = Some((keys, Some(super_pass.clone()), None));
                break;
            }
        }
    } else {
        for pass in &passes {
            if let Ok(keys) = crate::auth::unlock_session_keys(session, pass, None, &user) {
                unlocked = Some((keys, None, Some(pass.clone())));
                break;
            }
        }
    }
    let (_, super_pass, legacy_pass) = unlocked.ok_or_else(|| anyhow!("legacy vault could not be unlocked; supply its original recovery key/password; no new vault was created"))?;
    let alias = format!("legacy-{}", &profile.identity[..16]);
    if let Some(value) = super_pass {
        let backend = crate::keystore::import_credential(&alias, "super", &value)?;
        session["keyring_backend"] = json!(backend);
    }
    if let Some(value) = legacy_pass.as_ref().or_else(|| passes.first()) {
        let backend = crate::keystore::import_credential(&alias, "pass", value)?;
        if legacy_pass.is_some() {
            session["keyring_backend"] = json!(backend);
        }
    }
    session["keyring_account"] = json!(alias);
    Ok(())
}

fn rewrite_address(value: &mut Value) {
    let Some(address) = value["addr"].as_str() else {
        return;
    };
    let host = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))
        .and_then(|value| value.split('/').next())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(
        host.as_str(),
        "1memory.ai"
            | "api.1memory.ai"
            | "memocap.ai"
            | "api.memocap.ai"
            | "respire.ai"
            | "api.respire.ai"
    ) {
        value["addr"] = json!(crate::service::DEFAULT_SERVER_ADDR);
    }
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    private_file(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            bail!("migration destination is a symbolic link; no external data was written");
        }
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(0o600 | (mode & 0o100)),
        )?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_only_never_creates_a_migration_home() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        plaintext_profile(&home.path().join(".onememory"), "client-fixture")?;
        let variables = [
            "HOME",
            "ONEMEMORY_DATA_DIR",
            "ONEMEMORY_CLIENT_ONLY",
            DEFAULT_ENV,
        ];
        let saved = variables.map(|name| (name, std::env::var_os(name)));
        std::env::set_var("HOME", home.path());
        std::env::remove_var("ONEMEMORY_DATA_DIR");
        std::env::remove_var(DEFAULT_ENV);
        std::env::set_var("ONEMEMORY_CLIENT_ONLY", "yes");
        let result = ensure_default_home();
        let root_changed = std::env::var_os("ONEMEMORY_DATA_DIR").is_some();
        for (name, value) in saved {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        result?;
        assert!(!root_changed);
        assert!(!home.path().join(".rsrs").exists());
        assert!(!home.path().join(".rsrs-migration-lock").exists());
        assert!(!home.path().join(".rsrs-migration-staging").exists());
        Ok(())
    }

    fn plaintext_profile(path: &Path, user: &str) -> Result<()> {
        std::fs::create_dir_all(path)?;
        write_json(
            &path.join("session.json"),
            &json!({"user":user,"addr":"https://1memory.ai","token":"fixture-token"}),
        )?;
        Ok(())
    }

    #[test]
    fn committed_wal_and_original_files_survive() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        let source = home.path().join(".onememory");
        plaintext_profile(&source, "wal-owner")?;
        let urk = crate::memory::crypto::generate_key();
        let db = Connection::open(source.join("onememory.db"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
                    CREATE TABLE memories (id TEXT PRIMARY KEY,user TEXT,ciphertext TEXT,nonce TEXT,created_at TEXT,updated_at TEXT,deleted INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO memories VALUES ('committed','wal-owner','','','created','updated',0);")?;
        let data_key = crate::memory::crypto::derive_subkey(&urk, b"onememory:data:v1")?;
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&data_key, "committed fixture")?;
        db.execute(
            "UPDATE memories SET ciphertext=?1,nonce=?2 WHERE id='committed'",
            rusqlite::params![ciphertext, nonce],
        )?;
        let foreign_key = crate::memory::crypto::generate_key();
        let (foreign_nonce, foreign_ciphertext) =
            crate::memory::crypto::encrypt_item(&foreign_key, "old local fixture")?;
        db.execute(
            "INSERT INTO memories VALUES ('old-local','local',?1,?2,'created','updated',0)",
            rusqlite::params![foreign_ciphertext, foreign_nonce],
        )?;
        db.execute("UPDATE memories SET deleted=1 WHERE id='old-local'", [])?;
        // Migration copies opaque data, including undecodable live rows.
        db.execute("INSERT INTO memories VALUES ('undecodable','wal-owner','broken','broken','created','updated',0)", [])?;
        std::fs::create_dir_all(source.join("runtime"))?;
        std::fs::write(source.join("runtime/token"), "must-not-copy")?;
        std::fs::create_dir_all(source.join("models"))?;
        std::fs::write(source.join("models/model.fixture"), "model")?;
        let original_session = std::fs::read(source.join("session.json"))?;
        migrate_home(home.path())?;
        let target = home.path().join(".rsrs");
        let snapshot = Connection::open(target.join("onememory.db"))?;
        assert_eq!(
            snapshot.query_row("SELECT id FROM memories WHERE id='committed'", [], |row| {
                row.get::<_, String>(0)
            })?,
            "committed"
        );
        assert_eq!(
            snapshot.query_row(
                "SELECT ciphertext,nonce,deleted FROM memories WHERE id='old-local'",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?
                ))
            )?,
            (foreign_ciphertext, foreign_nonce, 1)
        );
        assert_eq!(
            snapshot.query_row(
                "SELECT ciphertext,nonce FROM memories WHERE id='undecodable'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            )?,
            ("broken".to_owned(), "broken".to_owned())
        );
        assert_eq!(
            snapshot.query_row(
                "SELECT ciphertext,nonce FROM memories WHERE id='committed'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            )?,
            (ciphertext, nonce)
        );
        assert_eq!(
            std::fs::read(source.join("session.json"))?,
            original_session
        );
        assert!(source.join("runtime/token").is_file());
        assert!(!target.join("runtime").exists());
        assert_eq!(
            std::fs::read_to_string(target.join("models/model.fixture"))?,
            "model"
        );
        let session: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        assert_eq!(session["addr"], crate::service::DEFAULT_SERVER_ADDR);
        assert_eq!(session["token"], "fixture-token");
        migrate_home(home.path())?;
        assert!(!target.join("accounts/legacy-onememory").exists());
        Ok(())
    }

    #[test]
    fn both_homes_and_conflicting_profiles_are_retained() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        let recent = home.path().join(".respire");
        let old = home.path().join(".onememory");
        plaintext_profile(&recent, "recent")?;
        plaintext_profile(&old, "old")?;
        plaintext_profile(&recent.join("accounts/work"), "recent-work")?;
        plaintext_profile(&old.join("accounts/work"), "old-work")?;
        write_json(
            &recent.join("client.json"),
            &json!({"data_dir":recent.join("accounts/work"),"addr":"https://dev.rsrs.rs"}),
        )?;
        migrate_home(home.path())?;
        let target = home.path().join(".rsrs");
        assert!(target.join("session.json").is_file());
        assert!(target.join("accounts/work/session.json").is_file());
        assert!(target
            .join("accounts/legacy-onememory/session.json")
            .is_file());
        assert!(target
            .join("accounts/legacy-onememory-work/session.json")
            .is_file());
        let config: Value = serde_json::from_slice(&std::fs::read(target.join("client.json"))?)?;
        let active_profile = config["data_dir"]
            .as_str()
            .ok_or_else(|| anyhow!("migrated active profile path is missing"))?;
        assert_eq!(Path::new(active_profile), target.join("accounts/work"));
        assert_eq!(config["addr"], "https://dev.rsrs.rs");
        let session_before = std::fs::read(target.join("session.json"))?;
        migrate_home(home.path())?;
        assert_eq!(std::fs::read(target.join("session.json"))?, session_before);
        assert!(old.join("accounts/work/session.json").is_file());
        Ok(())
    }

    #[test]
    fn historical_schema_is_copied_without_conversion() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let home = tempfile::tempdir()?;
        let source = home.path().join(".onememory");
        plaintext_profile(&source, "old-demo")?;
        let db = Connection::open(source.join("onememory.db"))?;
        db.execute_batch(
            "CREATE TABLE memories (id INTEGER PRIMARY KEY,tag_hashes TEXT,content TEXT);
                INSERT INTO memories VALUES (1,'legacy','preserved');",
        )?;
        migrate_home(home.path())?;
        let snapshot = Connection::open(home.path().join(".rsrs/onememory.db"))?;
        assert_eq!(
            snapshot.query_row("SELECT content FROM memories WHERE id=1", [], |row| row
                .get::<_, String>(
                0
            ))?,
            "preserved"
        );
        assert_eq!(
            db.query_row("SELECT content FROM memories", [], |row| row
                .get::<_, String>(0))?,
            "preserved"
        );
        assert!(home.path().join(".rsrs-migration-staging").is_dir());
        Ok(())
    }

}
