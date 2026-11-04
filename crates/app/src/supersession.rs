//! Current/former recall channels over the local supersession projection.
//!
//! The frozen Core ranking never reads `superseded_by` or `valid_until`; instead
//! the host drops non-current rows from the resident view before Core scores
//! them, so the frozen weights stay untouched while old statements stop
//! occupying the recall limit. Ciphertext remains authoritative — the local
//! column exists only to filter without decrypting the whole library.

use anyhow::Result;
use respire_crypto::SessionKeys;
use respire_protocol::{MemoryEntry, PayloadV2, StoredMemory};
use respire_storage::transport::{local::LocalStore, MemoryTransport};

/// Set once the `superseded_by` column has been backfilled from ciphertext.
/// After this flag is written, an empty column means "no live replacement".
const PROJECTION_FLAG: &str = "superseded_projection_v1";

/// Former-channel lexical cues in both library languages; these select the
/// `auto` channel in the query text. Matched case-insensitively.
const FORMER_CUES: [&str; 12] = [
    "\u{4ee5}\u{524d}", // yi qian: in the past
    "\u{66fe}\u{7ecf}", // ceng jing: once, at some point
    "\u{8fc7}\u{53bb}", // guo qu: the past
    "\u{5f53}\u{65f6}", // dang shi: at that time
    "\u{4e3a}\u{4ec0}\u{4e48}\u{53d8}\u{6210}", // why it turned into
    "\u{539f}\u{5148}", // yuan xian: originally
    "used to",
    "previously",
    "formerly",
    "in the past",
    "no longer",
    "back then",
];

/// True when the query text explicitly reaches into the past (auto channel).
pub fn former_cue(query: &str) -> bool {
    let lowered = query.to_lowercase();
    FORMER_CUES.iter().any(|cue| lowered.contains(cue))
}

/// A stored row is current until it has a live replacement or its validity
/// window closes. Timestamps are fixed-width UTC (protocol::metadata::
/// validate_timestamp), so a lexicographic compare is chronological.
pub fn is_current(row: &StoredMemory, now: &str) -> bool {
    if !row.local_superseded_by.is_empty() {
        return false;
    }
    validity_open(&row.local_meta.valid_until, now)
}

/// A decrypted entry is current under the same rule (payload truth; used to
/// anchor the former-channel chain on the top live hit).
pub fn entry_is_current(entry: &MemoryEntry, now: &str) -> bool {
    if !entry.superseded_by.is_empty() {
        return false;
    }
    validity_open(&entry.metadata.valid_until, now)
}

/// Absent or empty validity means the statement never expires.
fn validity_open(valid_until: &Option<String>, now: &str) -> bool {
    match valid_until.as_deref() {
        None => true,
        Some(value) => value.is_empty() || value > now,
    }
}

/// Ids the current channel drops from the Core view. Deleted rows are never
/// dropped here: tombstones stay in the view so Core can tell a deleted source
/// from a live one.
pub fn removed_ids(rows: &[StoredMemory], now: &str) -> Vec<String> {
    rows.iter()
        .filter(|row| !row.deleted && !is_current(row, now))
        .map(|row| row.id.clone())
        .collect()
}

/// Walk replacements backwards from a live record: rows whose `superseded_by`
/// points at the current head, nearest hop first, at most `steps` hops.
pub fn supersession_chain<'a>(rows: &'a [StoredMemory], start: &str, steps: usize) -> Vec<&'a StoredMemory> {
    let mut out: Vec<&StoredMemory> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::iter::once(start.to_owned()).collect();
    let mut heads = vec![start.to_owned()];
    for _ in 0..steps {
        let mut next = Vec::new();
        for row in rows {
            if seen.contains(&row.id) || !heads.iter().any(|head| *head == row.local_superseded_by) {
                continue;
            }
            seen.insert(row.id.clone());
            next.push(row.id.clone());
            out.push(row);
        }
        if next.is_empty() {
            break;
        }
        heads = next;
    }
    out
}

/// Titles of the records `id` replaced (reverse index over the projection),
/// used for the current channel's `supersedes <title>` line.
pub fn replaced_titles<'a>(rows: &'a [StoredMemory], id: &str) -> Vec<&'a str> {
    rows.iter()
        .filter(|row| row.local_superseded_by == id)
        .map(|row| row.local_title.as_str())
        .collect()
}

/// One-time decrypt-and-project of supersession edges written before the column
/// existed. Only normal writable mode refreshes local index state; a read-only
/// space keeps the projection it already has, so its filter behaves exactly as
/// it did before the column existed (fail-open, never silently drops rows).
pub fn ensure_projection(keys: &SessionKeys, store: &LocalStore) -> Result<()> {
    if crate::service::workspace_mode() != "normal" {
        return Ok(());
    }
    if store.meta_get(PROJECTION_FLAG)?.as_deref() == Some("1") {
        return Ok(());
    }
    let rows = store.all(true)?;
    store.write_transaction(|| {
        for row in &rows {
            if row.deleted || row.ciphertext.is_empty() {
                continue;
            }
            let plaintext = keys.decrypt_content(&row.ciphertext, &row.nonce)?;
            let payload: PayloadV2 = serde_json::from_str(&plaintext)?;
            if row.local_superseded_by != payload.superseded_by {
                store.project_superseded(&row.id, &payload.superseded_by)?;
            }
        }
        store.meta_set(PROJECTION_FLAG, "1")?;
        Ok(())
    })
}
