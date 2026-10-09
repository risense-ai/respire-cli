//! Explicit user mode and provider configuration; Core returns final recall results.
use anyhow::Result;
use respire::memory::engine::RecalledWithContext;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct RecallResult {
    items: Vec<RecalledWithContext>,
    mode: String,
    warning: Option<String>,
    routing: respire::memory::model::RecallRouting,
}

pub fn recall<E: respire::memory::search::Embedder>(
    keys: &respire::memory::SessionKeys,
    embedder: &E,
    candidates: &[respire::StoredMemory],
    query: &respire::MemoryQuery,
) -> Result<(Vec<RecalledWithContext>, String, Option<String>, respire::memory::model::RecallRouting)> {
    let mode = respire::service::read_agent_config()["recall_mode"]
        .as_str()
        .unwrap_or("fast")
        .to_owned();
    recall_with_mode(keys, embedder, candidates, query, &mode)
}

pub fn recall_with_mode<E: respire::memory::search::Embedder>(
    keys: &respire::memory::SessionKeys,
    embedder: &E,
    candidates: &[respire::StoredMemory],
    query: &respire::MemoryQuery,
    mode: &str,
) -> Result<(Vec<RecalledWithContext>, String, Option<String>, respire::memory::model::RecallRouting)> {
    anyhow::ensure!(matches!(mode, "fast" | "quality"), "unknown recall mode");
    let provider = if mode == "quality" {
        configured_provider()
    } else {
        None
    };
    let mut transport = |request: &Value| -> Result<Value> {
        let backend = provider.as_ref().ok_or_else(|| anyhow::anyhow!("model provider is not configured"))?;
        crate::classify::call_api(backend, request)
    };
    let result: RecallResult = respire::core_sdk::execute_with_transport(
        "query_business",
        json!({
            "model": embedder.model_name(),
            "snapshots": respire::memory::engine::snapshots(keys, candidates),
            "query": query,
            "mode": mode,
            "provider": provider.as_ref().map(|backend| json!({"name":backend.name,"model":backend.model})),
        }),
        &mut transport,
    )?;
    Ok((result.items, result.mode, result.warning, result.routing))
}

fn configured_provider() -> Option<crate::classify::Backend> {
    let config = respire::service::read_agent_config();
    let base = config["recall_api_base"]
        .as_str()
        .map(str::to_owned)
        .or_else(respire::keystore::load_ds_last_base)
        .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned());
    let slot = format!("ds@{}", respire::keystore::host_of(&base));
    let key = respire::env::var("RSRS_RECALL_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .or_else(|| respire::keystore::load_classify_key(&slot))?;
    let model = config["recall_model"]
        .as_str()
        .unwrap_or(crate::classify::DEFAULT_DS_MODEL);
    Some(crate::classify::Backend { name: "ds", endpoint: crate::classify::ds_endpoint(&base),
        key, model: model.to_owned(), base_shown: base })
}
