//! One-time backfill of local plaintext metadata indexes.
//!
//! Older sync hydration omitted the local importance column. Rehydrate live
//! entries from the encrypted payload without changing ciphertext or dirty flags.
//!
//! Usage:
//!   cargo run --release -p respire --example repair-locals
//!   cargo run --release -p respire --example repair-locals -- --dry

use anyhow::Result;
use respire::auth;
use respire::memory::engine::hydrate_local;
use respire::service::open_store;
use respire::MemoryTransport;

fn main() -> Result<()> {
    let dry = std::env::args().any(|a| a == "--dry");
    let keys = auth::load_local_session()?;
    let store = open_store()?;
    let all = store.all(true)?;

    let broken: Vec<_> = all
        .iter()
        .filter(|s| !s.deleted && s.local_importance.is_empty())
        .collect();

    println!(
        "🌐 索引对账：importance 列空串 {} 条{}",
        broken.len(),
        if dry { "（dry 只看不动）" } else { "" }
    );
    if broken.is_empty() {
        println!("✓ 无空串——索引列健全");
        return Ok(());
    }

    let mut fixed = 0usize;
    let mut failed = 0usize;
    for s in &broken {
        let title = if s.local_title.is_empty() { &s.id[..8] } else { &s.local_title };
        let mut st = (*s).clone();
        match hydrate_local(&keys, &mut st) {
            Ok(()) => {
                if !dry {
                    store.put_synced(&st)?;
                }
                fixed += 1;
                println!("  🔧 {} {}  importance → {}", &s.id[..8], title, st.local_importance);
            }
            Err(e) => {
                failed += 1;
                println!("  ⚠️ {} 解密失败：{e}", &s.id[..8]);
            }
        }
    }
    println!(
        "{} 回填 {} 条，失败 {failed} 条",
        if dry { "🔎 试运行" } else { "✅" },
        fixed
    );
    Ok(())
}
