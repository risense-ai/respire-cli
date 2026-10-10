use super::*;
use respire_protocol::{MemoryEntry, MemoryQuery};
use respire_storage::transport::MemoryTransport;

fn seal_pending(keys: &SessionKeys, id: &str, title: &str, stamp: &str) -> Result<StoredMemory> {
    let entry: MemoryEntry = serde_json::from_value(serde_json::json!({
        "id":id,"kind":"Context","tags":[],"title":title,"content":"resident regression keyword",
        "user":"test","computer":"test","project":"","created_at":stamp,"updated_at":stamp,
        "emotion":0,"parent_id":"","importance":"important"
    }))?;
    let _defer = respire_core_sdk::defer_indexing();
    MemoryEngine::seal(keys, &respire_core_sdk::search::HashingEmbedder::new(1024), &entry, "test")
}

fn recall(lease: &respire_core_sdk::ResidentLease) -> Result<Vec<MemoryEntry>> {
    let _scope = lease.enter();
    let provider = respire_core_sdk::bge::BgeEmbedder::load_model("m3")?;
    respire_core_sdk::query(&provider, &[], &MemoryQuery::new("resident regression keyword").limit(5), "plain")
}

#[test]
fn unchanged_catalog_reuses_arcs_and_old_readers_survive_updates_and_deletes() -> Result<()> {
    let _guard = crate::test_lock::guard();
    clear()?;
    let dir = tempfile::tempdir()?;
    let store = LocalStore::open(&dir.path().join("resident.db"))?;
    let keys = SessionKeys::from_urk([7; 32])?;
    let original = seal_pending(&keys, "one", "before", "2026-10-10T00:00:00Z")?;
    store.put_checked(&original, None)?;
    let (first, pending, old_lease) = recall_catalog(&keys, &store)?;
    assert_eq!(pending, 1);
    assert!(first[0].ciphertext.is_empty());
    let (same, _, same_lease) = recall_catalog(&keys, &store)?;
    assert!(Arc::ptr_eq(&first, &same));
    assert!(Arc::ptr_eq(&old_lease, &same_lease));
    let newer = seal_pending(&keys, "one", "after", &store.edit_stamp("one")?)?;
    store.put_checked(&newer, Some(&original.ciphertext))?;
    let (_, _, new_lease) = recall_catalog(&keys, &store)?;
    assert_eq!(recall(&old_lease)?.first().context("retained pending snapshot was not recalled")?.title, "before");
    assert_eq!(recall(&new_lease)?.first().context("updated pending snapshot was not recalled")?.title, "after");
    store.forget("one")?;
    let (empty, pending, empty_lease) = recall_catalog(&keys, &store)?;
    assert!(empty.is_empty());
    assert_eq!(pending, 0);
    assert!(recall(&empty_lease)?.is_empty());
    assert_eq!(recall(&old_lease)?.first().context("retained pending snapshot was not recalled")?.title, "before");
    clear()?;
    Ok(())
}
