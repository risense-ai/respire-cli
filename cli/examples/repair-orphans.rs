//! One-time repair of legacy orphan parent links.
//!
//! Older versions stored unresolved short prefixes as parent IDs. Resolve an
//! unambiguous live parent and reject cycles; otherwise promote the entry to a root.
//! Reseal changed parent links so synchronization can propagate the correction.
//!
//! Usage:
//!   cargo run --release -p respire --example repair-orphans
//!   cargo run --release -p respire --example repair-orphans -- --dry

use anyhow::Result;
use respire::auth;
use respire::memory::bge::BgeEmbedder;
use respire::memory::engine::MemoryEngine;
use respire::service::{now_stamp, open_store, resolve_prefix};
use respire::sync::{build_remote_from_env, remote_configured, sync_all};
use respire::MemoryTransport;

fn main() -> Result<()> {
    let dry = std::env::args().any(|a| a == "--dry");
    let keys = respire::auth::load_local_session()?;
    let store = open_store()?;
    let embedder = BgeEmbedder::load()?;
    let all = store.all(true)?;

    let orphans: Vec<_> = all
        .iter()
        .filter(|s| !s.deleted && !s.local_parent_id.is_empty())
        .filter(|s| !all.iter().any(|p| p.id == s.local_parent_id && !p.deleted))
        .collect();

    println!("🌐 孤儿对账：活跃父缺失 {} 条{}", orphans.len(), if dry { "（dry 只看不动）" } else { "" });
    if orphans.is_empty() {
        println!("✓ 无孤儿——因果树健全");
        return Ok(());
    }

    let mut reattached = 0usize;
    let mut promoted = 0usize;
    for s in &orphans {
        let title = if s.local_title.is_empty() { &s.id[..8] } else { &s.local_title };
        let entry = MemoryEngine::open(&keys, s)?;
        // Reject cycles: the target ancestor chain must not contain this entry.
        let chain = store.ancestor_chain(&s.id)?;
        let decide = match resolve_prefix(&all, &s.local_parent_id) {
            Ok(full) if full != s.id && !chain.contains(&full) => ("reattach", full),
            _ => ("promote", String::new()),
        };
        match decide {
            ("reattach", full) => {
                println!("  🔗 {} {}  假父 {} → 真父 {}", &s.id[..8], title, &s.local_parent_id[..8], &full[..8]);
                if !dry {
                    let mut e = entry;
                    e.parent_id = full;
                    e.updated_at = now_stamp();
                    let user = e.user.clone();
                    let stored = MemoryEngine::seal(&keys, &embedder, &e, &user)?;
                    store.put(&stored)?;
                }
                reattached += 1;
            }
            _ => {
                println!("  ⬆️ {} {}  父 {} 真不存在 → 升根（自为因）", &s.id[..8], title, &s.local_parent_id[..8]);
                if !dry {
                    let mut e = entry;
                    e.parent_id = String::new();
                    e.updated_at = now_stamp();
                    let user = e.user.clone();
                    let stored = MemoryEngine::seal(&keys, &embedder, &e, &user)?;
                    store.put(&stored)?;
                }
                promoted += 1;
            }
        }
    }

    println!("—— 账单：挂真父 {}，升根 {}，共 {}", reattached, promoted, reattached + promoted);
    if dry {
        println!("（dry 未动库——去掉 --dry 实修）");
        return Ok(());
    }
    if remote_configured() {
        match build_remote_from_env().and_then(|remote| sync_all(&keys, &store, &remote)) {
            Ok(stats) => println!("🔁 已同步：拉 {} 条，推 {} 条", stats.pulled, stats.pushed),
            Err(e) => eprintln!("⚠️ 同步失败（本地已修，稍后 rsrs sync）: {e}"),
        }
    }
    Ok(())
}
