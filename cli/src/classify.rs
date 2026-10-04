//! Provider configuration and final business results. Core owns model execution.
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DEFAULT_API_BASE: &str = "https://api.typesafe.ai/v1/systemone";
pub const DEFAULT_MODEL: &str = "jev-latest";
pub const DEFAULT_DS_BASE: &str = "https://api.deepseek.com/v1";
pub const DEFAULT_DS_MODEL: &str = "deepseek-flash";

pub struct Backend {
    pub name: &'static str,
    pub key: String,
    pub model: String,
    pub endpoint: String,
    pub base_shown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub choice: String,
    pub confidence: f32,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    pub id: String,
    pub title: String,
    pub current_root: String,
    pub verdict: Option<Verdict>,
    pub error: Option<String>,
    pub suggest_parent: Option<(String, String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifyReport {
    pub command: String,
    pub status: String,
    pub summary: ReportSummary,
    pub items: Vec<ReportItem>,
    pub actions: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub matched: usize,
    pub mismatch: usize,
    pub unrooted: usize,
    pub low_confidence: usize,
    pub failed: usize,
    pub min_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub id: String,
    pub class: String,
    pub status: String,
    pub current: String,
    pub choice: String,
    pub confidence: Option<f32>,
    pub title: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub parent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessResult {
    pub report: Option<ClassifyReport>,
    pub actions: Vec<Action>,
    pub warnings: Vec<String>,
    pub summary: Value,
    pub items: Vec<ItemResult>,
}

pub fn execute(
    memories: &[respire::StoredMemory],
    backend: Option<&Backend>,
    options: Value,
) -> Result<BusinessResult> {
    let backend = backend.map(|backend| {
        json!({
            "name": backend.name,
            "endpoint": backend.endpoint,
            "key": backend.key,
            "model": backend.model,
        })
    });
    respire::core_sdk::execute(
        "classify_business",
        json!({
            "snapshots": respire::core_sdk::metadata_snapshots(memories),
            "backend": backend,
            "options": options,
        }),
    )
}

pub fn ds_endpoint(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/chat/completions") {
        base.to_owned()
    } else {
        format!("{base}/chat/completions")
    }
}
