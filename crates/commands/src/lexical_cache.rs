//! Stage-1 resident lexical index cache (design A, fast path only).
//!
//! Why a process-local cache is the right shape: `recall` executes inside the
//! long-resident runtime. `engine` (and therefore `learn`/`lexical`) is only
//! compiled under the `server` feature, and the CLI dependency never enables
//! that feature, so a one-shot CLI process cannot build this index at all —
//! every recall runs in the serving process, where this cache persists across
//! requests.
//!
//! Cache key — every one of these participates in `PartialEq`, so a mismatch
//! rebuilds instead of reusing a stale index:
//! * content token — `meta.memory_revision_v1`, bumped by the P0 revision
//!   triggers on every content write;
//! * [`INDEX_FORMAT_VERSION`] — bump when field weights or the index layout
//!   change (stored in [`CacheKey::format`], part of `==`);
//! * [`TOKENIZER_ID`] — identity of [`crate::lexical::tokenize`] (stored in
//!   [`CacheKey::tokenizer`], part of `==`);
//! * scope — `(project, kind)`. `df`/`avg_len` are statistics of the *filtered*
//!   document set, so an index built for one scope must never answer another.
//!
//! `library_identity` is deliberately not a separate key item: a replaced or
//! copied library carries a fresh random 32-hex `memory_revision_v1`, so the
//! token already forces a mismatch, while a rewritten-but-equal library stays
//! safe to reuse.
//!
//! Failure policy (design §3 兜底): a failed token probe or a missing P0
//! revision trigger never fails the recall and never reuses a stale index —
//! the request just rebuilds without touching the cache.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;

use respire_app::transport::local::LocalStore;

use crate::lexical::Bm25Index;

/// Bump when tokenizer rules, field weights or the index layout change.
pub const INDEX_FORMAT_VERSION: u32 = 1;
/// Identity of [`crate::lexical::tokenize`]: CJK character bigrams plus
/// lowercase ASCII runs. Change the rules, change this string.
pub const TOKENIZER_ID: &str = "cjk-bigram+ascii-run-v1";
/// Diagnostic switch: `RSRS_LEXICAL_CACHE=off` (process environment) or the
/// presence of `<data_dir>/lexical-cache.off` forces the uncached path, so the
/// same serving process can run both arms of an interleaved latency comparison.
pub const CACHE_ENV: &str = "RSRS_LEXICAL_CACHE";
/// Data-root marker read per request; one `stat` keeps the arms switchable
/// without restarting the runtime.
pub const CACHE_MARKER: &str = "lexical-cache.off";

/// Identity of one cached index. Cheap to clone, compared by value; every field
/// below is part of `==`, so changing the tokenizer or the index format
/// invalidates the cache in-code rather than only after a restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    pub token: String,
    pub format: u32,
    pub tokenizer: &'static str,
    pub scope: String,
}

impl CacheKey {
    pub fn new(token: String, project: Option<&str>, kind: Option<&str>) -> Self {
        Self {
            token,
            format: INDEX_FORMAT_VERSION,
            tokenizer: TOKENIZER_ID,
            scope: scope_key(project, kind),
        }
    }

    /// Stable, unambiguous rendering for diagnostics.
    pub fn render(&self) -> String {
        format!(
            "token={};format={};tokenizer={};{}",
            self.token, self.format, self.tokenizer, self.scope
        )
    }
}

pub fn scope_key(project: Option<&str>, kind: Option<&str>) -> String {
    format!("project={};kind={}", project.unwrap_or(""), kind.unwrap_or(""))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheState {
    /// Index reused as-is; no database scan, no tokenization, no build.
    Hit,
    /// Key changed (or the cache was empty); the index was rebuilt and stored.
    Miss,
    /// Cache deliberately not used and not populated (probe/P0 gate/env off).
    Bypass,
}

struct Entry {
    key: CacheKey,
    index: Arc<Bm25Index>,
    bytes: usize,
}

static CACHE: OnceLock<Mutex<Option<Entry>>> = OnceLock::new();
static BUILDS: AtomicUsize = AtomicUsize::new(0);
static GATE_WARNED: AtomicBool = AtomicBool::new(false);

fn cache() -> &'static Mutex<Option<Entry>> {
    CACHE.get_or_init(|| Mutex::new(None))
}

pub fn disabled_by_env() -> bool {
    if std::env::var(CACHE_ENV).is_ok_and(|value| {
        let value = value.trim();
        value.eq_ignore_ascii_case("off") || value == "0"
    }) {
        return true;
    }
    respire_app::service::main_data_dir().join(CACHE_MARKER).is_file()
}

/// Key for this request, or `None` when the cache must be bypassed.
fn key_for(store: &LocalStore, project: Option<&str>, kind: Option<&str>, bypass: bool) -> Option<CacheKey> {
    if bypass {
        return None;
    }
    // P0: a library whose revision triggers are absent cannot vouch for the
    // token, so the cache stays off and every request rebuilds.
    match store.revision_triggers_missing() {
        Ok(missing) if !missing.is_empty() => {
            if !GATE_WARNED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "warning: revision triggers missing {missing:?}; lexical index cache disabled, rebuilding per request"
                );
            }
            return None;
        }
        Ok(_) => {}
        Err(_) => return None,
    }
    match store.memory_revision() {
        Ok(token) => Some(CacheKey::new(token, project, kind)),
        Err(_) => None,
    }
}

/// Return the index for this request, building it only when the key changed.
pub fn index_for<F>(
    store: &LocalStore,
    project: Option<&str>,
    kind: Option<&str>,
    build: F,
) -> Result<(Arc<Bm25Index>, CacheState)>
where
    F: FnOnce() -> Result<Bm25Index>,
{
    index_for_with(store, project, kind, disabled_by_env(), build)
}

/// Same decision with the environment switch passed explicitly, so tests can
/// exercise the bypass arm without mutating process-global state.
pub(crate) fn index_for_with<F>(
    store: &LocalStore,
    project: Option<&str>,
    kind: Option<&str>,
    bypass: bool,
    build: F,
) -> Result<(Arc<Bm25Index>, CacheState)>
where
    F: FnOnce() -> Result<Bm25Index>,
{
    let key = key_for(store, project, kind, bypass);
    if let Some(key) = key.as_ref() {
        if let Ok(guard) = cache().lock() {
            if let Some(entry) = guard.as_ref() {
                if &entry.key == key {
                    return Ok((entry.index.clone(), CacheState::Hit));
                }
            }
        }
    }
    let index = Arc::new(build()?);
    BUILDS.fetch_add(1, Ordering::Relaxed);
    let state = if key.is_some() { CacheState::Miss } else { CacheState::Bypass };
    if let Some(key) = key {
        if let Ok(mut guard) = cache().lock() {
            *guard = Some(Entry { key, index: index.clone(), bytes: index.approx_bytes() });
        }
    }
    Ok((index, state))
}

/// Load (or reuse) the index for one `(project, kind)` scope.
///
/// This is the whole fast path: on a hit the store is never scanned for rows,
/// and no token is re-tokenized.
pub fn load(
    store: &LocalStore,
    project: Option<&str>,
    kind: Option<&str>,
) -> Result<(Arc<Bm25Index>, CacheState)> {
    index_for(store, project, kind, || {
        let docs: Vec<crate::lexical::RowDoc> = crate::lexical::docs_from_store(store)?
            .into_iter()
            .filter(|doc| project.is_none_or(|p| p.is_empty() || doc.project == p))
            .filter(|doc| kind.is_none_or(|k| k.is_empty() || doc.kind.eq_ignore_ascii_case(k)))
            .collect();
        Ok(Bm25Index::build(docs))
    })
}

/// Drop the cached index (tests and diagnostics).
pub fn clear() {
    if let Ok(mut guard) = cache().lock() {
        *guard = None;
    }
}

/// Number of index builds performed by this process.
pub fn builds() -> usize {
    BUILDS.load(Ordering::Relaxed)
}

/// Approximate resident size of the cached index, 0 when empty.
pub fn cached_bytes() -> usize {
    cache()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|entry| entry.bytes))
        .unwrap_or(0)
}

/// Key currently held, rendered for diagnostics.
pub fn cached_key() -> Option<String> {
    cache()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|entry| entry.key.render()))
}

