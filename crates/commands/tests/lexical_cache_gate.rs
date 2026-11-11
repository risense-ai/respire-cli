//! Stage-1 lexical index cache: correctness gates.
//!
//! These run as an integration test on purpose: the crate's in-crate test
//! module has a pre-existing unresolved import (`crate::capture_tests`, left
//! over from the task-12 port; that module only exists in the CLI crate), so
//! `--lib` tests do not compile. The gates themselves only need the public
//! cache API plus a real `LocalStore`.

#![cfg(feature = "server")]

use anyhow::Result;
use respire_app::memory::StoredMemory;
use respire_app::transport::local::LocalStore;
use respire_app::MemoryTransport;
use respire_commands::lexical::Bm25Index;
use respire_commands::lexical_cache::{self, CacheKey, CacheState};

/// The cache is process-global; keep these tests from interleaving.
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

fn memory(id: &str, title: &str, head: &str, project: &str) -> StoredMemory {
    let mut memory = StoredMemory::new_pending(id.to_owned(), "account".to_owned());
    memory.updated_at = "2026-01-01T00:00:00Z".to_owned();
    memory.local_title = title.to_owned();
    memory.local_content_head = head.to_owned();
    memory.local_project = project.to_owned();
    memory.local_kind = "knowledge".to_owned();
    memory.local_created_at = "2026-01-01T00:00:00Z".to_owned();
    memory
}

fn seeded(project: &str) -> Result<(tempfile::TempDir, LocalStore)> {
    let dir = tempfile::tempdir()?;
    let store = LocalStore::open(&dir.path().join("memory.db"))?;
    for index in 0..5 {
        store.put(&memory(
            &format!("{project}id-{index}"),
            &format!("部署脚本位置 {index}"),
            "scripts/build-core-sdk.mjs 构建入口",
            project,
        ))?;
    }
    Ok((dir, store))
}

fn hits(index: &Bm25Index, query: &str) -> Vec<(String, f32)> {
    index
        .search(query, 10)
        .into_iter()
        .filter_map(|(position, score)| index.doc(position).map(|doc| (doc.id.clone(), score)))
        .collect()
}

#[test]
fn cached_hit_matches_cold_rebuild_exactly() -> Result<()> {
    let _guard = lock();
    let (_dir, store) = seeded("")?;
    lexical_cache::clear();
    let builds_before = lexical_cache::builds();
    let (first, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Miss);
    assert_eq!(first.len(), 5);
    let (second, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Hit);
    assert_eq!(lexical_cache::builds(), builds_before + 1, "a hit must not rebuild the index");
    let cached = hits(&second, "部署脚本");
    assert!(!cached.is_empty());
    // 召回行为零变化：命中缓存的索引与清缓存后全建，同一查询的 (id, score) 必须逐条全等。
    lexical_cache::clear();
    let (cold, _) = lexical_cache::load(&store, None, None)?;
    assert_eq!(cached, hits(&cold, "部署脚本"));
    assert_eq!(lexical_cache::builds(), builds_before + 2);
    Ok(())
}

#[test]
fn write_after_cache_hit_is_visible() -> Result<()> {
    let _guard = lock();
    let (_dir, store) = seeded("")?;
    lexical_cache::clear();
    let _ = lexical_cache::load(&store, None, None)?;
    let (_, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Hit);
    // 写一条新记忆：content token 必须变，缓存失配，新条目立即可召回。
    store.put(&memory("fresh-id", "缓存写后可见标记 7777", "刚写入的内容必须立即可召回", ""))?;
    let (fresh, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Miss);
    let fresh_hits = hits(&fresh, "写后可见标记");
    assert_eq!(
        fresh_hits.first().map(|hit| hit.0.as_str()),
        Some("fresh-id"),
        "hits={fresh_hits:?}"
    );
    Ok(())
}

#[test]
fn scope_is_part_of_the_key() -> Result<()> {
    let _guard = lock();
    let (_dir, store) = seeded("demo-")?;
    lexical_cache::clear();
    let (_, state) = lexical_cache::load(&store, Some("demo-"), None)?;
    assert_eq!(state, CacheState::Miss);
    let (_, state) = lexical_cache::load(&store, Some("demo-"), None)?;
    assert_eq!(state, CacheState::Hit);
    // 不同 scope 的 df/avg_len 不同，必须另建而不是复用。
    let (_, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Miss);
    Ok(())
}

#[test]
fn key_fields_all_participate_in_equality() {
    // 格式版本与分词器标识必须进 `==`：改任一常量都应让旧索引失配，而不是
    // 只在 render() 诊断串里"看起来在键里"。
    let base = CacheKey::new("token-abc".to_owned(), Some("demo"), Some("knowledge"));
    let same = CacheKey::new("token-abc".to_owned(), Some("demo"), Some("knowledge"));
    assert_eq!(base, same);
    let other_token = CacheKey::new("token-xyz".to_owned(), Some("demo"), Some("knowledge"));
    assert_ne!(base, other_token);
    let other_scope = CacheKey::new("token-abc".to_owned(), None, Some("knowledge"));
    assert_ne!(base, other_scope);
    let other_format = CacheKey { format: base.format + 1, ..base.clone() };
    assert_ne!(base, other_format, "INDEX_FORMAT_VERSION must invalidate the cache");
    let other_tokenizer = CacheKey { tokenizer: "some-future-tokenizer-v2", ..base.clone() };
    assert_ne!(base, other_tokenizer, "TOKENIZER_ID must invalidate the cache");
    assert!(base.render().contains("format=1"));
    assert!(base.render().contains("tokenizer=cjk-bigram+ascii-run-v1"));
}

#[test]
fn bypass_switch_never_populates_the_cache() -> Result<()> {
    let _guard = lock();
    let (_dir, store) = seeded("")?;
    lexical_cache::clear();
    let builds_before = lexical_cache::builds();
    // 走公开路径：进程环境开关（与数据根 lexical-cache.off 标记同一条判定）。
    std::env::set_var(lexical_cache::CACHE_ENV, "off");
    let bypassed = lexical_cache::load(&store, None, None);
    std::env::remove_var(lexical_cache::CACHE_ENV);
    let (bypass_index, state) = bypassed?;
    assert_eq!(state, CacheState::Bypass);
    assert!(lexical_cache::cached_key().is_none(), "bypass must not store an index");
    assert_eq!(lexical_cache::builds(), builds_before + 1);
    // 再跑一次仍是 Bypass（缓存没被写进去）
    std::env::set_var(lexical_cache::CACHE_ENV, "off");
    let again = lexical_cache::load(&store, None, None);
    std::env::remove_var(lexical_cache::CACHE_ENV);
    assert_eq!(again?.1, CacheState::Bypass);
    // 结果与冷建一致
    lexical_cache::clear();
    let (cold, cold_state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(cold_state, CacheState::Miss);
    assert_eq!(hits(&bypass_index, "部署脚本"), hits(&cold, "部署脚本"));
    Ok(())
}

/// Design C (task-28): the startup prewarm must leave a resident index behind,
/// so the first recall of a fresh process is a hit instead of a build.
#[test]
fn prewarm_leaves_a_resident_index_for_the_first_recall() -> Result<()> {
    let _guard = lock();
    let (dir, store) = seeded("")?;
    lexical_cache::clear();
    let builds_before = lexical_cache::builds();
    let warmed = lexical_cache::prewarm_once(&dir.path().join("memory.db"));
    assert_eq!(
        warmed,
        Some(CacheState::Miss),
        "prewarm must build and store the unscoped index"
    );
    assert_eq!(lexical_cache::builds(), builds_before + 1);
    assert!(lexical_cache::cached_key().is_some(), "prewarm must populate the cache");
    // 预热之后，首个召回直接命中，不再重建。
    let builds_after_warm = lexical_cache::builds();
    let (index, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Hit);
    assert_eq!(lexical_cache::builds(), builds_after_warm, "hit must not rebuild");
    assert!(!hits(&index, "部署脚本").is_empty());
    Ok(())
}

/// `RSRS_LEXICAL_PREWARM=off` must disable prewarm entirely: no build, no cache.
#[test]
fn prewarm_switch_off_does_nothing() -> Result<()> {
    let _guard = lock();
    let (dir, store) = seeded("")?;
    lexical_cache::clear();
    let builds_before = lexical_cache::builds();
    std::env::set_var(lexical_cache::PREWARM_ENV, "off");
    let warmed = lexical_cache::prewarm_once(&dir.path().join("memory.db"));
    std::env::remove_var(lexical_cache::PREWARM_ENV);
    assert_eq!(warmed, None, "prewarm must be a no-op when switched off");
    assert_eq!(lexical_cache::builds(), builds_before, "off must not build");
    assert!(lexical_cache::cached_key().is_none(), "off must not populate the cache");
    // 关掉预热不影响正常召回（仍走懒建）。
    let (_, state) = lexical_cache::load(&store, None, None)?;
    assert_eq!(state, CacheState::Miss);
    Ok(())
}
