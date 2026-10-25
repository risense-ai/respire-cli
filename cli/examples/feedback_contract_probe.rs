//! Isolated real-model feedback contract probe. No account, keyring or network.
//! Requires the paired SDK and an explicitly prepared model via RSRS_M3_DIR.
use anyhow::{Context, Result};
use respire::memory::engine::RecalledWithContext;
use respire::{MemoryEngine, MemoryEntry, MemoryQuery, MemoryTransport, SessionKeys};
use respire_app as respire;
use serde_json::{json, Value};

fn score(rows: &[RecalledWithContext], id: &str) -> Result<f32> {
    rows.iter()
        .find(|row| row.entry.id == id)
        .map(|row| row.score)
        .context("probe candidate unexpectedly absent")
}
fn recall(
    store: &respire::transport::local::LocalStore,
    keys: &SessionKeys,
    query: &MemoryQuery,
) -> Result<Vec<RecalledWithContext>> {
    let candidates = store.all(false)?;
    let output: Value = respire::core_sdk::execute(
        "query_business",
        json!({
            "model":"m3","snapshots":respire::memory::engine::snapshots(keys,&candidates),
            "query":query,"mode":"fast","provider":null,
            "query_settings":respire::feedback::query_settings(store,query,&candidates)?
        }),
    )?;
    serde_json::from_value(output["items"].clone()).map_err(Into::into)
}
fn main() -> Result<()> {
    anyhow::ensure!(
        respire::core_sdk::FEEDBACK_CONTRACT == 1,
        "paired real SDK with feedback contract 1 is required"
    );
    anyhow::ensure!(
        respire::env::var_os("RSRS_M3_DIR").is_some(),
        "provide the prepared real model with RSRS_M3_DIR"
    );
    anyhow::ensure!(
        respire::env::var_os("RSRS_CORE_TEST_MODE").is_none(),
        "real-model probe rejects the synthetic test provider"
    );
    let root = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", root.path());
    std::env::set_var("RSRS_NO_AUTOSYNC", "1");
    std::env::set_var("RSRS_ENGINE", "cpu");
    std::env::set_var("RSRS_FEEDBACK", "0");
    std::env::set_var("RSRS_ABLATE", "");
    std::env::set_var("RSRS_MARK_SIM", "0.5");
    std::env::set_var("RSRS_BAD_PENALTY", "1");
    let store = respire::transport::local::LocalStore::open(&root.path().join("rsrs.db"))?;
    let keys = SessionKeys::from_urk([11; 32])?;
    let embedder = respire::memory::bge::BgeEmbedder::load_model("m3")?;
    let text = "Rust ownership and borrowing keep memory access safe";
    for (index, (title, body)) in [
        ("Rust memory ownership", text),
        (
            "Python exception handling",
            "Python raises and catches exceptions using try and except",
        ),
        ("中文记忆检索", "中文记忆检索和数据同步使用明确的库边界"),
    ]
    .iter()
    .enumerate()
    {
        let now = chrono::Utc::now().to_rfc3339();
        let entry = MemoryEntry {
            id: format!("00000000-0000-4000-8000-{index:012}"),
            user: "synthetic-probe".into(),
            title: (*title).into(),
            content: (*body).into(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            kind: respire::Kind::Context,
            tags: Vec::new(),
            computer: "fixture".into(),
            project: "probe".into(),
            created_at: now.clone(),
            updated_at: now,
            emotion: 0.0,
            parent_id: String::new(),
            importance: "normal".into(),
            device: "fixture".into(),
            modified_by: "fixture".into(),
        };
        let memory = MemoryEngine::seal(&keys, &embedder, &entry, "synthetic-probe")?;
        anyhow::ensure!(store.put(&memory)?, "fixture insertion rejected");
    }
    let query = MemoryQuery::new(text).of_project("probe").limit(20);
    let baseline = recall(&store, &keys, &query)?;
    let target = baseline
        .first()
        .context("real model returned no synthetic candidate")?
        .entry
        .id
        .clone();
    let neutral = score(&baseline, &target)?;
    std::env::set_var("RSRS_FEEDBACK", "1");
    let clean = recall(&store, &keys, &query)?;
    anyhow::ensure!(
        (score(&clean, &target)? - neutral).abs() < 1e-6,
        "unmarked zero-read baseline differs"
    );
    for _ in 0..15 {
        store.bump_recall_count(&target)?;
    }
    anyhow::ensure!(
        (score(&recall(&store, &keys, &query)?, &target)? - neutral).abs() < 1e-6,
        "enabled feedback retained read heat"
    );
    std::env::set_var("RSRS_FEEDBACK", "0");
    let read_hot = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (read_hot - neutral - 0.10).abs() < 1e-5,
        "legacy heat control did not exercise the original axis"
    );
    let request = uuid::Uuid::new_v4().to_string();
    store.log_query_request(&request, text, "probe", "", &[target.clone()], &[neutral])?;
    store.mark_query_feedback(&request, &[target.clone()], true, "human")?;
    let disabled_after = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        disabled_after == read_hot,
        "disabled experiment changed after a grade"
    );
    std::env::set_var("RSRS_FEEDBACK", "1");
    let good = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (good - neutral - 0.025).abs() < 1e-5,
        "real scorer did not consume refreshed good heat"
    );
    store.mark_query_feedback(&request, &[target.clone()], false, "human")?;
    let bad = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (bad - neutral * 0.92).abs() < 1e-5,
        "real scorer did not consume latest bad penalty"
    );
    std::env::set_var("RSRS_BAD_PENALTY", "0");
    let bad_off = score(&recall(&store, &keys, &query)?, &target)?;
    anyhow::ensure!(
        (bad_off - neutral).abs() < 1e-6,
        "bad penalty disable did not restore neutral score"
    );
    let context = respire::feedback::query_settings(
        &store,
        &MemoryQuery::new("unrelated query").of_project("probe"),
        &store.all(false)?,
    )?;
    anyhow::ensure!(
        context["feedback"]["bad"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
        "unrelated query received a penalty"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"provider":"real-m3","feedback_contract":respire::core_sdk::FEEDBACK_CONTRACT,"synthetic_entries":3,"target":target,"neutral":neutral,"legacy_read_hot":read_hot,"good":good,"bad":bad,"bad_off":bad_off,"checks":"PASS","original_benchmark_replicated":false})
        )?
    );
    Ok(())
}
