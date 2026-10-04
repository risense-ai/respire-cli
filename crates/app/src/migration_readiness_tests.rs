//! Migration readiness regressions: synthetic data, process-memory credentials, no network.
use super::*;
use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

type Slot = (Option<String>, String, String);
type MemorySlots = Arc<Mutex<HashMap<Slot, Arc<keyring::mock::MockCredential>>>>;
#[derive(Default)]
struct MemoryKeyring(MemorySlots);
struct SharedCredential(Arc<keyring::mock::MockCredential>);
impl CredentialApi for SharedCredential {
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        self.0.set_secret(secret)
    }
    fn get_secret(&self) -> keyring::Result<Vec<u8>> {
        self.0.get_secret()
    }
    fn delete_credential(&self) -> keyring::Result<()> {
        self.0.delete_credential()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
impl CredentialBuilderApi for MemoryKeyring {
    fn build(
        &self,
        target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        let slot = (
            target.map(str::to_owned),
            service.to_owned(),
            user.to_owned(),
        );
        let credential = self
            .0
            .lock()
            .map_err(|_| {
                keyring::Error::PlatformFailure(Box::new(std::io::Error::other(
                    "migration test credential store lock was poisoned",
                )))
            })?
            .entry(slot)
            .or_default()
            .clone();
        Ok(Box::new(SharedCredential(credential)))
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }
}
pub(super) struct RestoreMock(MemorySlots);
impl Drop for RestoreMock {
    fn drop(&mut self) {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    }
}

pub(super) fn memory_keyring() -> RestoreMock {
    let store = MemorySlots::default();
    keyring::set_default_credential_builder(Box::new(MemoryKeyring(store.clone())));
    RestoreMock(store)
}

struct Fixture {
    home: tempfile::TempDir,
    source: PathBuf,
    database: Connection,
    keys: crate::memory::SessionKeys,
    good: (String, String),
    bad: (String, String),
}

impl Fixture {
    fn new(rows: &[(&str, bool, bool)]) -> Result<Self> {
        let home = tempfile::tempdir()?;
        let source = home.path().join(".onememory");
        private_directory(&source)?;
        let user = "synthetic-migration-readiness";
        let urk = crate::memory::crypto::generate_key();
        let secret = crate::memory::crypto::generate_secret_key();
        let salt = crate::memory::crypto::random_hex(16);
        let kek = crate::memory::crypto::derive_kek_v4(&secret, &salt)?;
        let (urk_nonce, wrapped_urk) = crate::memory::crypto::wrap_key(&urk, &kek)?;
        write_json(
            &source.join("session.json"),
            &json!({
                "user":user,"addr":"https://invalid.example","vault_version":4,
                "secret_key":secret,"kdf_salt":salt,"urk_nonce":urk_nonce,"wrapped_urk":wrapped_urk
            }),
        )?;
        let keys = crate::memory::SessionKeys::from_urk(urk)?;
        let data_key = crate::memory::crypto::derive_subkey(&keys.urk, b"onememory:data:v1")?;
        let payload = json!({"kind":"context","tags":"","title":"readiness",
            "content":"synthetic readiness fixture","user":user,"computer":"fixture",
            "project":"","created_at":"2026-10-04T00:00:00Z","updated_at":"2026-10-04T00:00:00Z"})
        .to_string();
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&data_key, &payload)?;
        let good = (ciphertext, nonce);
        let foreign_key = crate::memory::crypto::generate_key();
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&foreign_key, &payload)?;
        let bad = (ciphertext, nonce);
        let database = Connection::open(source.join("onememory.db"))?;
        database.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
            CREATE TABLE memories (id TEXT PRIMARY KEY,user TEXT,ciphertext TEXT,nonce TEXT,
                created_at TEXT,updated_at TEXT,deleted INTEGER DEFAULT 0)",
        )?;
        for (id, deleted, readable) in rows {
            let pair = if *readable { &good } else { &bad };
            database.execute(
                "INSERT INTO memories VALUES (?1,?2,?3,?4,'created','updated',?5)",
                rusqlite::params![id, user, pair.0, pair.1, *deleted as i64],
            )?;
        }
        Ok(Self {
            home,
            source,
            database,
            keys,
            good,
            bad,
        })
    }

    fn target(&self) -> PathBuf {
        self.home.path().join(".rsrs")
    }

    fn migrate(&self) -> Result<()> {
        migrate_home(self.home.path())
    }

    fn assert_rejected(&self) -> Result<()> {
        let error = self
            .migrate()
            .expect_err("unreadable live ciphertext must block publication");
        assert!(error.to_string().contains("live ciphertext"), "{error:#}");
        assert!(!self.target().exists());
        Ok(())
    }

    fn copied_rows(&self) -> Result<Vec<(String, String, String, i64)>> {
        let database = Connection::open_with_flags(
            self.target().join("onememory.db"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut statement =
            database.prepare("SELECT id,ciphertext,nonce,deleted FROM memories ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[test]
fn mismatched_live_row_rejects_without_publication_and_source_repair_can_retry() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let fixture = Fixture::new(&[("live", false, false)])?;
    let session = std::fs::read(fixture.source.join("session.json"))?;
    fixture.assert_rejected()?;
    assert!(
        _keyring
            .0
            .lock()
            .map_err(|_| anyhow!("migration test credential store lock was poisoned"))?
            .values()
            .all(|credential| credential.get_secret().is_err()),
        "failed readiness must not persist imported credentials"
    );
    assert_eq!(
        fixture
            .database
            .query_row("SELECT ciphertext,nonce FROM memories", [], |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?
            )))?,
        fixture.bad
    );
    assert_eq!(std::fs::read(fixture.source.join("session.json"))?, session);
    fixture.database.execute(
        "UPDATE memories SET ciphertext=?1,nonce=?2 WHERE id='live'",
        rusqlite::params![fixture.good.0, fixture.good.1],
    )?;
    fixture.migrate()?;
    assert!(receipt_matches(
        &fixture.target(),
        &identity(&fixture.source)?
    )?);
    assert_eq!(
        fixture.copied_rows()?,
        vec![(
            "live".into(),
            fixture.good.0.clone(),
            fixture.good.1.clone(),
            0
        )]
    );
    Ok(())
}

#[test]
fn every_live_row_must_decrypt_even_after_a_readable_row() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    Fixture::new(&[("first-good", false, true), ("second-bad", false, false)])?.assert_rejected()
}

#[test]
fn readable_live_rows_and_unreadable_tombstones_are_copied_unchanged() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let fixture = Fixture::new(&[("live", false, true), ("old-local", true, false)])?;
    fixture.migrate()?;
    assert_eq!(
        fixture.copied_rows()?,
        vec![
            (
                "live".into(),
                fixture.good.0.clone(),
                fixture.good.1.clone(),
                0
            ),
            (
                "old-local".into(),
                fixture.bad.0.clone(),
                fixture.bad.1.clone(),
                1
            ),
        ]
    );
    let store = crate::transport::local::LocalStore::open(&fixture.target().join("onememory.db"))?;
    let embedder = crate::memory::search::HashingEmbedder::default();
    assert_eq!(store.rebuild_index(&fixture.keys, &embedder, "legacy")?, 1);
    assert!(!store.index_pending("legacy")?);
    Ok(())
}

#[test]
fn all_deleted_rows_remain_opaque_but_existing_session_requirements_remain() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let fixture = Fixture::new(&[("old-local", true, false)])?;
    fixture.migrate()?;
    assert_eq!(
        fixture.copied_rows()?,
        vec![("old-local".into(), fixture.bad.0, fixture.bad.1, 1)]
    );
    for missing_session in [false, true] {
        let fixture = Fixture::new(&[("old-local", true, false)])?;
        let session_path = fixture.source.join("session.json");
        if missing_session {
            std::fs::remove_file(session_path)?;
        } else {
            write_json(&session_path, &json!({"user":"synthetic"}))?;
        }
        assert!(fixture.migrate().is_err());
        assert!(!fixture.target().exists());
    }
    Ok(())
}

#[test]
fn legacy_rows_without_deleted_column_and_null_deleted_rows_are_checked() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let readable = Fixture::new(&[("live", false, true)])?;
    readable
        .database
        .execute_batch("ALTER TABLE memories DROP COLUMN deleted")?;
    readable.migrate()?;
    assert!(receipt_matches(
        &readable.target(),
        &identity(&readable.source)?
    )?);
    for missing_column in [false, true] {
        let fixture = Fixture::new(&[("live", false, false)])?;
        if missing_column {
            fixture
                .database
                .execute_batch("ALTER TABLE memories DROP COLUMN deleted")?;
        } else {
            fixture
                .database
                .execute("UPDATE memories SET deleted=NULL", [])?;
        }
        fixture.assert_rejected()?;
    }
    Ok(())
}

#[test]
fn blank_or_null_live_ciphertext_and_nonce_cannot_bypass_readiness() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    for change in ["ciphertext=''", "ciphertext=NULL", "nonce=''", "nonce=NULL"] {
        let fixture = Fixture::new(&[("live", false, true)])?;
        fixture
            .database
            .execute(&format!("UPDATE memories SET {change}"), [])?;
        fixture.assert_rejected()?;
    }
    for missing_session in [false, true] {
        let fixture = Fixture::new(&[("live", false, true)])?;
        fixture
            .database
            .execute("UPDATE memories SET ciphertext='',nonce=''", [])?;
        let path = fixture.source.join("session.json");
        if missing_session {
            std::fs::remove_file(path)?;
        } else {
            write_json(&path, &json!({"user":"synthetic"}))?;
        }
        fixture.assert_rejected()?;
    }
    Ok(())
}

#[test]
fn invalid_decrypted_payload_is_rejected_without_disclosing_its_contents() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    for plaintext in ["not-json-private-sentinel", "{}"] {
        let fixture = Fixture::new(&[("live", false, true)])?;
        let data_key =
            crate::memory::crypto::derive_subkey(&fixture.keys.urk, b"onememory:data:v1")?;
        let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&data_key, plaintext)?;
        fixture.database.execute(
            "UPDATE memories SET ciphertext=?1,nonce=?2",
            rusqlite::params![ciphertext, nonce],
        )?;
        let error = fixture
            .migrate()
            .expect_err("invalid payload must not be published");
        assert!(!format!("{error:#}").contains(plaintext));
        assert!(!fixture.target().exists());
    }
    let fixture = Fixture::new(&[("live", false, true)])?;
    let data_key = crate::memory::crypto::derive_subkey(&fixture.keys.urk, b"onememory:data:v1")?;
    let mut payload: Value = serde_json::from_str(&crate::memory::crypto::decrypt_item(
        &data_key,
        &fixture.good.0,
        &fixture.good.1,
    )?)?;
    payload["emotion"] = json!("private-emotion-sentinel");
    let (nonce, ciphertext) = crate::memory::crypto::encrypt_item(&data_key, &payload.to_string())?;
    fixture.database.execute(
        "UPDATE memories SET ciphertext=?1,nonce=?2",
        rusqlite::params![ciphertext, nonce],
    )?;
    let error = fixture
        .migrate()
        .expect_err("invalid payload field must not be published");
    assert!(!format!("{error:#}").contains("private-emotion-sentinel"));
    assert!(!fixture.target().exists());
    Ok(())
}

#[test]
fn empty_library_without_session_still_migrates() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let fixture = Fixture::new(&[])?;
    std::fs::remove_file(fixture.source.join("session.json"))?;
    fixture.migrate()?;
    assert!(receipt_matches(
        &fixture.target(),
        &identity(&fixture.source)?
    )?);
    assert!(fixture.copied_rows()?.is_empty());
    Ok(())
}

#[test]
fn existing_completed_receipts_never_recopy_or_overwrite_destination_edits() -> Result<()> {
    let _isolate = crate::test_lock::Isolate::new()?;
    let _keyring = memory_keyring();
    let fixture = Fixture::new(&[("live", false, true)])?;
    fixture.migrate()?;
    let receipt_path = fixture.target().join(RECEIPT);
    let receipt = std::fs::read(&receipt_path)?;
    let target = Connection::open(fixture.target().join("onememory.db"))?;
    target.execute("UPDATE memories SET updated_at='destination-edited'", [])?;
    fixture.database.execute(
        "UPDATE memories SET ciphertext=?1,nonce=?2",
        rusqlite::params![fixture.bad.0, fixture.bad.1],
    )?;
    fixture.migrate()?;
    assert_eq!(std::fs::read(receipt_path)?, receipt);
    assert_eq!(
        target.query_row("SELECT updated_at FROM memories", [], |row| row
            .get::<_, String>(0))?,
        "destination-edited"
    );
    assert_eq!(
        fixture.copied_rows()?,
        vec![(
            "live".into(),
            fixture.good.0.clone(),
            fixture.good.1.clone(),
            0
        )]
    );
    assert!(!fixture.target().join("accounts/legacy-onememory").exists());
    Ok(())
}
