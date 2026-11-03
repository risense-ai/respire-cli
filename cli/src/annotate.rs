//! annotate - lexical (BM25) candidate recall + LLM judgement + local label store.
//!
//! Why: recall quality should improve while the system is used. This module
//! takes a query, builds a **BGE-free** lexical index over the plaintext
//! `title`/`tags`/`content_head` columns, takes the BM25 top-N, asks the
//! configured chat backend which candidates a careful assistant would actually
//! read, and stores both the judgement and every candidate score. Rows are
//! directly replayable as listwise / pairwise training samples, so the label
//! set grows just by using the product.
//!
//! Design constraints:
//! - No model download, no embedding, no network unless an LLM label is requested.
//! - LLM labels are **weak** labels (`source=model`); human labels outrank them
//!   and training exports keep the provenance field intact.
//! - Credentials only come from the existing classify backend/keyring path; the
//!   key never enters a prompt, a log, or the database.
//! - Only candidate ids/titles/snippets are sent to the provider (never bodies).
//!
//! Usage: `rsrs annotate --query "..." [--topk 10] [--dry-run] [--json]`
//!        `rsrs annotate --file evalset.jsonl [--topk 10]`
//!        `rsrs annotate --from-query-log --limit 5`
//!        `rsrs annotate --export-training out.jsonl [--export-format pairwise]`

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use respire::transport::local::{AnnotationCandidate, AnnotationRow, LocalStore, NewAnnotation};
use respire::MemoryTransport;

use crate::output::{Item as OutputItem, ResultEnvelope, Status as OutputStatus};

const K1: f32 = 1.2;
const B: f32 = 0.75;
/// Field weights: a title hit is worth more than a body hit.
const W_TITLE: f32 = 3.0;
const W_TAGS: f32 = 2.0;
const W_HEAD: f32 = 1.0;
const SNIPPET_CHARS: usize = 120;

// ───────────────────────────── tokenization ─────────────────────────────

fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF)
}

fn flush_ascii(buffer: &mut String, out: &mut Vec<String>) {
    // Identifier punctuation is kept inside a token, not at its edges.
    let trimmed = buffer.trim_matches(|c| c == '_' || c == '-');
    if trimmed.chars().count() >= 2 {
        out.push(trimmed.to_owned());
    }
    buffer.clear();
}

fn flush_cjk(buffer: &mut Vec<char>, out: &mut Vec<String>) {
    match buffer.len() {
        0 => {}
        1 => out.push(buffer[0].to_string()),
        _ => {
            for pair in buffer.windows(2) {
                out.push(pair.iter().collect());
            }
        }
    }
    buffer.clear();
}

/// Chinese: overlapping character bigrams (single leftover char kept).
/// English/digits/identifiers: one lowercase token per run, length ≥ 2;
/// `_` and `-` stay inside the run so `query_log` / `core-sdk` are searchable.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut ascii = String::new();
    let mut cjk: Vec<char> = Vec::new();
    for c in text.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
            if !cjk.is_empty() {
                flush_cjk(&mut cjk, &mut out);
            }
            ascii.push(c);
        } else if is_cjk(c) {
            if !ascii.is_empty() {
                flush_ascii(&mut ascii, &mut out);
            }
            cjk.push(c);
        } else {
            if !ascii.is_empty() {
                flush_ascii(&mut ascii, &mut out);
            }
            if !cjk.is_empty() {
                flush_cjk(&mut cjk, &mut out);
            }
        }
    }
    if !ascii.is_empty() {
        flush_ascii(&mut ascii, &mut out);
    }
    if !cjk.is_empty() {
        flush_cjk(&mut cjk, &mut out);
    }
    out
}

// ───────────────────────────── BM25 index ─────────────────────────────

/// One indexed entry: only the plaintext lexical columns.
#[derive(Debug, Clone)]
pub struct RowDoc {
    pub id: String,
    pub title: String,
    pub tags: String,
    pub head: String,
    pub project: String,
    pub created_at: String,
    pub kind: String,
}

#[derive(Debug, Clone, Default)]
struct FieldVector {
    tf: HashMap<String, f32>,
    len: f32,
}

impl FieldVector {
    fn add(&mut self, tokens: &[String], weight: f32) {
        for token in tokens {
            *self.tf.entry(token.clone()).or_insert(0.0) += weight;
            self.len += weight;
        }
    }
}

/// Lexical ranker over title/tags/content_head. Pure function of the rows, so
/// the same store snapshot always produces the same candidate list (replayable).
pub struct Bm25Index {
    docs: Vec<RowDoc>,
    fields: Vec<[FieldVector; 3]>,
    /// Per-field average length (BM25F normalizes each field separately).
    avg_len: [f32; 3],
    df: HashMap<String, u32>,
}

const FIELD_WEIGHTS: [f32; 3] = [W_TITLE, W_TAGS, W_HEAD];

impl Bm25Index {
    /// BM25F: per-field tf saturation and length normalization, field weight as a
    /// multiplier on that field's contribution. Summing fields (instead of mixing
    /// their term counts) keeps a title hit from being outvoted by several
    /// coincidental body bigrams.
    pub fn build(docs: Vec<RowDoc>) -> Self {
        let mut fields = Vec::with_capacity(docs.len());
        let mut df: HashMap<String, u32> = HashMap::new();
        let mut total_len = [0.0_f32; 3];
        for doc in &docs {
            let mut title = FieldVector::default();
            title.add(&tokenize(&doc.title), 1.0);
            let mut tags = FieldVector::default();
            tags.add(&tokenize(&doc.tags), 1.0);
            let mut head = FieldVector::default();
            head.add(&tokenize(&doc.head), 1.0);
            total_len[0] += title.len;
            total_len[1] += tags.len;
            total_len[2] += head.len;
            let mut seen: HashSet<&str> = HashSet::new();
            for token in title.tf.keys().chain(tags.tf.keys()).chain(head.tf.keys()) {
                if seen.insert(token.as_str()) {
                    *df.entry(token.clone()).or_insert(0) += 1;
                }
            }
            fields.push([title, tags, head]);
        }
        let n = docs.len().max(1) as f32;
        let avg_len = [
            (total_len[0] / n).max(1.0),
            (total_len[1] / n).max(1.0),
            (total_len[2] / n).max(1.0),
        ];
        Self {
            docs,
            fields,
            avg_len,
            df,
        }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    pub fn doc(&self, index: usize) -> Option<&RowDoc> {
        self.docs.get(index)
    }

    fn idf(&self, token: &str) -> f32 {
        let n = self.docs.len() as f32;
        let df = self.df.get(token).copied().unwrap_or(0) as f32;
        // Lucene-style idf: always positive, no negative scores for common terms.
        (1.0 + (n - df + 0.5) / (df + 0.5)).ln()
    }

    /// Top-K candidates with a positive score (stable: score desc, then id asc).
    pub fn search(&self, query: &str, topk: usize) -> Vec<(usize, f32)> {
        let mut terms: Vec<String> = tokenize(query);
        terms.sort();
        terms.dedup();
        if terms.is_empty() || self.docs.is_empty() {
            return Vec::new();
        }
        let idf: Vec<f32> = terms.iter().map(|term| self.idf(term)).collect();
        let mut scored: Vec<(usize, f32)> = Vec::new();
        for (index, fields) in self.fields.iter().enumerate() {
            let mut score = 0.0_f32;
            let mut matched = false;
            for (field_index, field) in fields.iter().enumerate() {
                let normalizer = K1 * (1.0 - B + B * field.len / self.avg_len[field_index]);
                for (term_index, term) in terms.iter().enumerate() {
                    let tf = field.tf.get(term).copied().unwrap_or(0.0);
                    if tf <= 0.0 {
                        continue;
                    }
                    matched = true;
                    score += FIELD_WEIGHTS[field_index] * idf[term_index] * tf * (K1 + 1.0)
                        / (tf + normalizer);
                }
            }
            if matched && score > 0.0 {
                scored.push((index, score));
            }
        }
        scored.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| self.docs[left.0].id.cmp(&self.docs[right.0].id))
        });
        scored.truncate(topk);
        scored
    }

    pub fn candidates(&self, query: &str, topk: usize) -> Vec<AnnotationCandidate> {
        self.search(query, topk)
            .into_iter()
            .map(|(index, score)| {
                let doc = &self.docs[index];
                AnnotationCandidate {
                    id: doc.id.clone(),
                    title: if doc.title.trim().is_empty() {
                        doc.head.chars().take(40).collect()
                    } else {
                        doc.title.clone()
                    },
                    score,
                    snippet: snippet(&doc.head, &doc.title),
                }
            })
            .collect()
    }
}

fn snippet(head: &str, title: &str) -> String {
    let text: String = head.split_whitespace().collect::<Vec<_>>().join(" ");
    let text = text.trim();
    if text.is_empty() {
        return title.chars().take(SNIPPET_CHARS).collect();
    }
    let mut out: String = text.chars().take(SNIPPET_CHARS).collect();
    if text.chars().count() > SNIPPET_CHARS {
        out.push('…');
    }
    out
}

// ───────────────────────────── LLM judgement ─────────────────────────────

pub const SYSTEM_PROMPT: &str = "You label retrieval results for a personal memory system.\n\
Input: one user query, and N candidate memory entries retrieved by BM25 (id, title, lexical score, snippet).\n\
Task: select the candidates that a careful assistant would actually open to answer the query.\n\
Rules:\n\
- Judge usefulness for the query's intent, not surface keyword overlap.\n\
- Prefer precision: if no candidate is clearly useful, return an empty array.\n\
- Only use ids that appear in the candidate list; never invent or reformat ids.\n\
- 1-3 ids is typical; more only when several entries are independently needed.\n\
- Do not quote memory text verbatim in the reason.\n\
Reply with exactly ONE JSON object, no prose, no code fence:\n\
{\"selected\":[\"<id>\"],\"confidence\":0.0,\"reason\":\"<one short sentence>\"}\n\
confidence is 0..1 for the whole judgement.";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmVerdict {
    #[serde(default)]
    pub selected: Vec<String>,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub reason: String,
}

pub fn request_body(model: &str, query: &str, candidates: &[AnnotationCandidate]) -> Value {
    let payload = json!({
        "query": query,
        "candidates": candidates.iter().map(|c| json!({
            "id": c.id,
            "title": c.title,
            "score": (c.score * 1000.0).round() / 1000.0,
            "snippet": c.snippet,
        })).collect::<Vec<_>>(),
    });
    json!({
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": payload.to_string()},
        ],
    })
}

/// Keep only what is safe to store/surface: no provider bodies, no keys.
pub fn summarize_raw(content: &str) -> String {
    let flat: String = content.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = flat.chars().take(240).collect();
    if flat.chars().count() > 240 {
        out.push('…');
    }
    out
}

/// First balanced JSON object in the text (tolerates ``` fences and stray prose).
fn extract_json_object(content: &str) -> Option<&str> {
    let start = content.find('{')?;
    let bytes = content.as_bytes();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        let c = *byte;
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return content.get(start..=offset);
                }
            }
            _ => {}
        }
    }
    None
}

pub fn parse_verdict(content: &str) -> Result<LlmVerdict> {
    let object = extract_json_object(content).ok_or_else(|| {
        anyhow::anyhow!(
            "model response has no JSON object (raw: {})",
            summarize_raw(content)
        )
    })?;
    let verdict: LlmVerdict = serde_json::from_str(object).map_err(|error| {
        anyhow::anyhow!(
            "model JSON does not match the annotation schema ({error}); raw: {}",
            summarize_raw(content)
        )
    })?;
    anyhow::ensure!(
        (0.0..=1.0).contains(&verdict.confidence),
        "model confidence {} is outside 0..1; raw: {}",
        verdict.confidence,
        summarize_raw(content)
    );
    Ok(verdict)
}

/// Map model output ids onto real candidate ids (exact or unique prefix ≥ 4 chars).
pub fn resolve_selected(ids: &[String], candidates: &[AnnotationCandidate]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for raw in ids {
        let id = raw.trim().trim_start_matches('#');
        anyhow::ensure!(!id.is_empty(), "model returned an empty candidate id");
        let hit = candidates.iter().find(|c| c.id == id).map(|c| c.id.clone()).or_else(|| {
            if id.chars().count() < 4 {
                return None;
            }
            let matches: Vec<&AnnotationCandidate> = candidates
                .iter()
                .filter(|c| c.id.starts_with(id) || id.starts_with(c.id.as_str()))
                .collect();
            if matches.len() == 1 {
                Some(matches[0].id.clone())
            } else {
                None
            }
        });
        let hit = hit.ok_or_else(|| {
            anyhow::anyhow!(
                "model selected id \"{id}\" which is not a unique candidate of this query"
            )
        })?;
        if !out.contains(&hit) {
            out.push(hit);
        }
    }
    Ok(out)
}

// ───────────────────────────── options / run ─────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct Options {
    pub query: Option<String>,
    pub file: Option<String>,
    pub from_query_log: bool,
    pub limit: usize,
    pub topk: usize,
    /// BM25 pool stored as hard negatives; the LLM only sees `topk`.
    pub candidate_topk: usize,
    pub dry_run: bool,
    pub project: Option<String>,
    pub api_base: Option<String>,
    pub model: String,
    pub ds: Option<String>,
    pub backend: Option<String>,
    pub export_training: Option<String>,
    pub export_format: String,
    pub export_limit: usize,
    pub include_failed: bool,
    pub request_id: Option<String>,
    /// Recall hook: never print, never fail the caller.
    pub quiet: bool,
}

fn parse_queries(file: &str) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("cannot read query file {file}"))?;
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let query = match serde_json::from_str::<Value>(line) {
            Ok(value) => value
                .get("query")
                .and_then(|q| q.as_str())
                .map(str::to_owned)
                .with_context(|| format!("{} line {} has no \"query\" field", file, index + 1))?,
            Err(_) => line.to_owned(),
        };
        if !query.trim().is_empty() {
            out.push(query);
        }
    }
    Ok(out)
}

pub(crate) fn docs_from_store(store: &LocalStore) -> Result<Vec<RowDoc>> {
    let memories = store.all(false)?;
    Ok(memories
        .iter()
        .filter(|m| !(m.local_title.trim().is_empty() && m.local_content_head.trim().is_empty()))
        .map(|m| RowDoc {
            id: m.id.clone(),
            title: m.local_title.clone(),
            tags: m.local_tags.clone(),
            head: m.local_content_head.clone(),
            project: m.local_project.clone(),
            created_at: if m.local_created_at.is_empty() { m.updated_at.clone() } else { m.local_created_at.clone() },
            kind: m.local_kind.clone(),
        })
        .collect())
}

fn annotated_queries(store: &LocalStore) -> Result<HashSet<String>> {
    Ok(store
        .annotation_rows(100_000)?
        .into_iter()
        .filter(|row| row.status == "ok" || row.status == "dry_run")
        .map(|row| row.query)
        .collect())
}

fn export_training(
    store: &LocalStore,
    path: &str,
    format: &str,
    limit: usize,
    include_failed: bool,
) -> Result<Value> {
    let rows = store.annotation_training_rows(include_failed, limit)?;
    let pairwise = format.eq_ignore_ascii_case("pairwise");
    let mut out = String::new();
    let mut samples = 0_usize;
    let mut skipped = 0_usize;
    // Oldest first: append-only training files keep read order stable.
    for row in rows.iter().rev() {
        if row.status != "ok" && !include_failed {
            continue;
        }
        if row.selected.is_empty() {
            // Empty selection is a valid negative, but it has no positive to pair with.
            if pairwise {
                skipped += 1;
                continue;
            }
        }
        if pairwise {
            let negative_pool: Vec<&AnnotationCandidate> = row
                .candidates
                .iter()
                .filter(|c| !row.selected.contains(&c.id))
                .collect();
            if negative_pool.is_empty() {
                skipped += 1;
                continue;
            }
            for positive_id in &row.selected {
                let positive = match row.candidates.iter().find(|c| &c.id == positive_id) {
                    Some(candidate) => candidate,
                    None => continue,
                };
                for negative in &negative_pool {
                    let sample = json!({
                        "format": "pairwise",
                        "query": row.query,
                        "positive": {"id": positive.id, "title": positive.title, "score": positive.score, "snippet": positive.snippet},
                        "negative": {"id": negative.id, "title": negative.title, "score": negative.score, "snippet": negative.snippet},
                        "label_source": row.source,
                        "weak_label": row.source == "model",
                        "confidence": row.confidence,
                        "model": row.model,
                        "annotation_id": row.id,
                        "created_at": row.ts,
                        "status": row.status,
                    });
                    out.push_str(&serde_json::to_string(&sample)?);
                    out.push('\n');
                    samples += 1;
                }
            }
        } else {
            out.push_str(&serde_json::to_string(&listwise_sample(row))?);
            out.push('\n');
            samples += 1;
        }
    }
    let path_ref = Path::new(path);
    if let Some(parent) = path_ref.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut file = std::fs::File::create(path_ref)
        .with_context(|| format!("cannot create training file {path}"))?;
    file.write_all(out.as_bytes())?;
    Ok(json!({
        "format": if pairwise { "pairwise" } else { "listwise" },
        "path": std::fs::canonicalize(path_ref).unwrap_or_else(|_| path_ref.to_path_buf()),
        "samples": samples,
        "skipped_no_positive": skipped,
        "human_labels": rows.iter().filter(|r| r.source == "human" && r.status == "ok").count(),
        "model_labels": rows.iter().filter(|r| r.source == "model" && r.status == "ok").count(),
    }))
}

/// Backend selection. `RSRS_ANNOTATE_KEY` (CI / local OpenAI-compatible
/// endpoints) bypasses the keyring entirely so a throwaway key is never stored;
/// otherwise the normal classify backend/keyring/config path is used.
fn build_backend(options: &Options) -> Result<crate::classify::Backend> {
    if let Ok(key) = respire::env::var("RSRS_ANNOTATE_KEY") {
        let key = key.trim().to_owned();
        if !key.is_empty() {
            let base = options
                .api_base
                .clone()
                .or_else(respire::keystore::load_ds_last_base)
                .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned());
            let model = if options.model == crate::classify::DEFAULT_MODEL {
                respire::keystore::load_ds_model(&respire::keystore::host_of(&base))
                    .unwrap_or_else(|| crate::classify::DEFAULT_DS_MODEL.to_owned())
            } else {
                options.model.clone()
            };
            return Ok(crate::classify::Backend {
                name: "ds",
                key,
                model,
                endpoint: crate::classify::ds_endpoint(&base),
                base_shown: base,
            });
        }
    }
    crate::build_classify_backend(
        options.api_base.as_deref(),
        &options.model,
        false,
        options.ds.as_deref(),
        options.backend.as_deref(),
    )
}

/// Run the annotate command (CLI entry).
pub fn run(options: Options) -> Result<()> {
    let store = crate::build_local()?;

    if let Some(path) = options.export_training.as_deref() {
        let summary = export_training(
            &store,
            path,
            &options.export_format,
            options.export_limit,
            options.include_failed,
        )?;
        let mut result = ResultEnvelope::new(
            "annotate",
            OutputStatus::Ok,
            summary.clone(),
            vec![OutputItem::new(
                "training_export",
                OutputStatus::Ok,
                summary["samples"].to_string(),
            )],
        );
        result.details = summary;
        return crate::emit_result(result);
    }

    let mut queries: Vec<String> = Vec::new();
    if let Some(query) = options.query.as_deref() {
        if !query.trim().is_empty() {
            queries.push(query.trim().to_owned());
        }
    }
    if let Some(file) = options.file.as_deref() {
        queries.extend(parse_queries(file)?);
    }
    if options.from_query_log {
        let seen = annotated_queries(&store)?;
        for (query, _ts) in store.recent_queries(options.limit.max(1))? {
            if !seen.contains(&query) {
                queries.push(query);
            }
        }
    }
    let mut deduped: Vec<String> = Vec::new();
    for query in queries {
        if !deduped.contains(&query) {
            deduped.push(query);
        }
    }
    anyhow::ensure!(
        !deduped.is_empty(),
        "nothing to annotate: pass --query, --file, --from-query-log or --export-training"
    );

    let docs = docs_from_store(&store)?;
    let index = Bm25Index::build(docs);
    anyhow::ensure!(
        !index.is_empty(),
        "the local library has no plaintext title/content_head to index; nothing to rank"
    );

    // Backend: only built when a real LLM judgement is requested.
    let backend = if options.dry_run {
        None
    } else {
        Some(build_backend(&options)?)
    };

    let mut details: Vec<Value> = Vec::new();
    let mut ok = 0_usize;
    let mut failed = 0_usize;
    let mut dry = 0_usize;
    let mut items: Vec<OutputItem> = Vec::new();

    for (position, query) in deduped.iter().enumerate() {
        let label = format!("query#{}", position + 1);
        let recalled = index.candidates(query, options.candidate_topk.max(options.topk).max(1));
        let llm_candidates: Vec<AnnotationCandidate> = recalled.iter().take(options.topk.max(1)).cloned().collect();
        let project = options.project.clone().unwrap_or_default();

        let mut verdict = LlmVerdict::default();
        let mut status = "dry_run".to_owned();
        let mut raw = String::new();
        let mut error: Option<String> = None;

        if !options.dry_run {
            if llm_candidates.is_empty() {
                // No lexical candidate: nothing to ask, record an honest empty sample.
                status = "ok".to_owned();
                verdict.reason = "no lexical candidate above zero for this query".to_owned();
                verdict.confidence = 0.0;
            } else {
                let backend = backend.as_ref().ok_or_else(|| anyhow::anyhow!("model backend missing"))?;
                let body = request_body(&backend.model, query, &llm_candidates);
                let request = json!({
                    "provider": backend.name,
                    "body": body,
                    "timeout": 60,
                    "retries": 2,
                });
                match crate::classify::call_api(backend, &request) {
                    Err(request_error) => {
                        status = "llm_error".to_owned();
                        error = Some(format!("{request_error:#}"));
                    }
                    Ok(response) => {
                        let content = response["choices"]
                            .get(0)
                            .and_then(|choice| choice["message"]["content"].as_str())
                            .unwrap_or_default()
                            .to_owned();
                        raw = summarize_raw(&content);
                        match parse_verdict(&content)
                            .and_then(|parsed| {
                                let selected = resolve_selected(&parsed.selected, &llm_candidates)?;
                                Ok((parsed, selected))
                            }) {
                            Ok((parsed, selected)) => {
                                verdict = LlmVerdict {
                                    selected,
                                    confidence: parsed.confidence,
                                    reason: parsed.reason.trim().chars().take(400).collect(),
                                };
                                status = "ok".to_owned();
                            }
                            Err(parse_error) => {
                                status = "parse_error".to_owned();
                                error = Some(format!("{parse_error:#}"));
                            }
                        }
                    }
                }
            }
        }

        let model_label = backend.as_ref().map(|b| b.model.clone()).unwrap_or_default();
        let annotation_id = store.insert_annotation(&NewAnnotation {
            query,
            project: &project,
            scope: "",
            topk: recalled.len(),
            candidates: &recalled,
            selected: &verdict.selected,
            confidence: verdict.confidence,
            reason: &verdict.reason,
            model: &model_label,
            source: "model",
            status: &status,
            raw: &raw,
            request_id: options.request_id.as_deref().filter(|_| deduped.len() == 1 || position == 0),
        })?;

        // Flywheel: one real LLM label immediately trains one SGD step.
        let learned = if status == "ok" && !verdict.selected.is_empty() {
            match store.annotation_row(annotation_id)
                .and_then(|row| row.ok_or_else(|| anyhow::anyhow!("annotation row {annotation_id} vanished")))
                .and_then(|row| crate::learn::train_row(&store, &row))
            {
                Ok(step) => json!({"updates": step.updates, "pairs": step.pairs, "loss": step.loss}),
                Err(error) => json!({"error": format!("{error:#}")}),
            }
        } else { Value::Null };

        match status.as_str() {
            "ok" => ok += 1,
            "dry_run" => dry += 1,
            _ => failed += 1,
        }
        if let Some(message) = error.as_deref() {
            items.push(OutputItem::new(format!("{label} {query}"), OutputStatus::Fail, message));
        } else {
            let picked = if verdict.selected.is_empty() {
                "none".to_owned()
            } else {
                verdict
                    .selected
                    .iter()
                    .map(|id| id.chars().take(8).collect::<String>())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            items.push(OutputItem::new(
                format!("{label} {query}"),
                OutputStatus::Ok,
                format!(
                    "{} candidates stored, {} sent to LLM, selected {picked}, confidence {:.2}, annotation #{annotation_id}",
                    recalled.len(),
                    llm_candidates.len(),
                    verdict.confidence
                ),
            ));
        }
        details.push(json!({
            "query": query,
            "status": status,
            "annotation_id": annotation_id,
            "candidates": recalled.iter().map(|c| json!({
                "id": c.id, "title": c.title, "score": (c.score * 1000.0).round() / 1000.0, "snippet": c.snippet,
            })).collect::<Vec<_>>(),
            "selected": verdict.selected,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
            "model": backend.as_ref().map(|b| b.model.clone()).unwrap_or_default(),
            "error": error,
            "learned": learned,
        }));
    }

    let status = if failed > 0 {
        OutputStatus::Warn
    } else {
        OutputStatus::Ok
    };
    let summary = json!({
        "queries": deduped.len(),
        "ok": ok,
        "dry_run": dry,
        "failed": failed,
        "topk": options.topk,
        "indexed_entries": index.len(),
        "stored_annotations": store.annotation_count()?,
        "db": respire::service::database_path(&respire::service::data_dir()).ok(),
    });
    let mut result = ResultEnvelope::new("annotate", status, summary, items);
    result.details = Value::Array(details);
    if failed > 0 {
        result
            .actions
            .push("fix the model backend, or run --dry-run to inspect BM25 candidates only".into());
    }
    // Recall-hook mode: the caller already replied; only the stored row matters.
    if options.quiet {
        return Ok(());
    }
    crate::emit_result(result)
}

/// Recall hook: after a real recall, annotate in a **detached** process so the
/// reply path never waits for (or pays for) an LLM call. Off unless
/// `RSRS_ANNOTATE=1`. Failures land in annotation_log, never in the reply.
pub fn spawn_after_recall(query: &str, project: &str, request_id: Option<&str>) {
    if !matches!(respire::env::var("RSRS_ANNOTATE"), Ok(value) if value.trim() == "1") {
        return;
    }
    if query.trim().is_empty() {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("annotate hook skipped: current executable unknown ({error})");
            return;
        }
    };
    let topk = respire::env::var("RSRS_ANNOTATE_TOPK")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(10);
    let mut command = std::process::Command::new(exe);
    command
        .arg("annotate")
        .arg("--query")
        .arg(query)
        .arg("--topk")
        .arg(topk.to_string())
        .arg("--candidate-topk")
        .arg(respire::env::var("RSRS_ANNOTATE_CANDIDATES").ok().and_then(|value| value.trim().parse::<usize>().ok()).filter(|value| *value > 0).unwrap_or(50).to_string())
        .arg("--quiet")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if !project.trim().is_empty() {
        command.arg("--project").arg(project);
    }
    if let Some(request_id) = request_id {
        command.arg("--request-id").arg(request_id);
    }
    // The hook runs without flags, so provider/model routing must come from the
    // runtime environment (the same environment the daemon was started with).
    if let Ok(base) = respire::env::var("RSRS_ANNOTATE_API_BASE") {
        if !base.trim().is_empty() {
            command.arg("--api-base").arg(base.trim());
        }
    }
    if let Ok(model) = respire::env::var("RSRS_ANNOTATE_MODEL") {
        if !model.trim().is_empty() {
            command.arg("--model").arg(model.trim());
        }
    }
    if let Err(error) = command.spawn() {
        eprintln!("annotate hook spawn failed: {error}");
    }
}

/// Export helper reused by tests: build the listwise sample for one row.
pub fn listwise_sample(row: &AnnotationRow) -> Value {

    let labeled: Vec<Value> = row
        .candidates
        .iter()
        .map(|c| {
            json!({
                "id": c.id, "title": c.title, "score": c.score, "snippet": c.snippet,
                "label": if row.selected.contains(&c.id) { 1 } else { 0 },
            })
        })
        .collect();
    json!({
        "format": "listwise",
        "query": row.query,
        "candidates": labeled,
        "positives": row.selected,
        "negatives": row.candidates.iter()
            .filter(|c| !row.selected.contains(&c.id))
            .map(|c| c.id.clone()).collect::<Vec<_>>(),
        "label_source": row.source,
        "weak_label": row.source == "model",
        "confidence": row.confidence,
        "model": row.model,
        "annotation_id": row.id,
        "created_at": row.ts,
        "status": row.status,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: &str, title: &str, score: f32) -> AnnotationCandidate {
        AnnotationCandidate {
            id: id.to_owned(),
            title: title.to_owned(),
            score,
            snippet: format!("snippet for {title}"),
        }
    }

    #[test]
    fn chinese_bigrams_and_ascii_tokens() {
        assert_eq!(tokenize("部署脚本"), vec!["部署", "署脚", "脚本"]);
        assert_eq!(tokenize("BM25 召回"), vec!["bm25", "召回"]);
        // identifiers survive as one token; single CJK char survives; single ASCII letter is dropped
        assert_eq!(tokenize("query_log 表"), vec!["query_log", "表"]);
        assert_eq!(tokenize("  ,. -x- "), Vec::<String>::new());
        assert!(tokenize("  ,. ").is_empty());
    }

    #[test]
    fn bm25_ranks_the_intent_match_first() {
        let docs = vec![
            RowDoc {
                id: "d1".into(),
                title: "KMeans 聚类超参数".into(),
                tags: "ml,cluster".into(),
                head: "聚类数量 k 的选择与肘部法".into(),
                project: "demo".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                kind: "context".into(),
            },
            RowDoc {
                id: "d2".into(),
                title: "部署脚本位置".into(),
                tags: "ops".into(),
                head: "scripts/build-core-sdk.mjs 构建入口".into(),
                project: "demo".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                kind: "context".into(),
            },
            RowDoc {
                id: "d3".into(),
                title: "周报模板".into(),
                tags: "doc".into(),
                head: "每周进展与风险".into(),
                project: "demo".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                kind: "context".into(),
            },
        ];
        let index = Bm25Index::build(docs);
        let hits = index.candidates("聚类算法怎么选 k", 3);
        assert_eq!(hits[0].id, "d1");
        assert!(hits[0].score > 0.0);
        // field weight: title hit beats body-only hit
        let hits = index.candidates("部署脚本", 3);
        assert_eq!(hits[0].id, "d2");
        let empty = index.candidates("量子纠缠", 3);
        assert!(empty.is_empty(), "no overlap must not invent candidates");
    }

    #[test]
    fn bm25_scores_are_replayable() {
        let docs: Vec<RowDoc> = (0..5)
            .map(|i| RowDoc {
                id: format!("id{i}"),
                title: format!("memory {i}"),
                tags: String::new(),
                head: "alpha beta gamma".into(),
                project: "demo".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                kind: "context".into(),
            })
            .collect();
        let first = Bm25Index::build(docs.clone()).candidates("alpha", 3);
        let second = Bm25Index::build(docs).candidates("alpha", 3);
        assert_eq!(first.len(), 3);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(first[0].score, second[0].score);
    }

    #[test]
    fn verdict_parsing_accepts_fences_and_rejects_garbage() {
        let ok = parse_verdict("```json\n{\"selected\":[\"a\"],\"confidence\":0.7,\"reason\":\"r\"}\n```")
            .expect("fenced JSON must parse");
        assert_eq!(ok.selected, vec!["a".to_owned()]);
        assert!((ok.confidence - 0.7).abs() < 1e-9);

        let empty = parse_verdict("{\"selected\":[],\"confidence\":0.2,\"reason\":\"none\"}")
            .expect("empty selection is valid");
        assert!(empty.selected.is_empty());

        let error = parse_verdict("I think entry a is best").unwrap_err().to_string();
        assert!(error.contains("raw:"), "error must keep a raw summary: {error}");
        assert!(error.contains("I think entry a is best"));

        let error = parse_verdict("{\"selected\":[\"a\"],\"confidence\":1.7,\"reason\":\"r\"}")
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside 0..1"));
    }

    #[test]
    fn selected_ids_resolve_to_real_candidates() {
        let candidates = vec![
            candidate("aaaaaaaa-1111", "t1", 3.0),
            candidate("bbbbbbbb-2222", "t2", 2.0),
        ];
        let resolved = resolve_selected(&["aaaaaaaa".into(), "aaaaaaaa-1111".into()], &candidates)
            .expect("prefix and full id resolve");
        assert_eq!(resolved, vec!["aaaaaaaa-1111".to_owned()]);
        assert!(resolve_selected(&["cccccccc".into()], &candidates).is_err());
        assert!(resolve_selected(&["aa".into()], &candidates).is_err());
    }

    #[test]
    fn listwise_sample_marks_positives_and_negatives() {
        let row = AnnotationRow {
            id: 7,
            created_at: 0,
            ts: "2026-01-01T00:00:00Z".into(),
            query: "q".into(),
            project: String::new(),
            scope: String::new(),
            topk: 2,
            candidates: vec![candidate("a", "t1", 3.0), candidate("b", "t2", 1.0)],
            selected: vec!["a".to_owned()],
            confidence: 0.9,
            reason: "r".into(),
            model: "m".into(),
            source: "model".into(),
            status: "ok".into(),
            raw: String::new(),
            request_id: None,
        };
        let sample = listwise_sample(&row);
        assert_eq!(sample["candidates"][0]["label"], 1);
        assert_eq!(sample["candidates"][1]["label"], 0);
        assert_eq!(sample["positives"][0], "a");
        assert_eq!(sample["negatives"][0], "b");
        assert_eq!(sample["label_source"], "model");
        assert_eq!(sample["weak_label"], true);
        assert!(!row.selected.is_empty());
    }

    #[test]
    fn request_body_sends_only_candidate_metadata() {
        let body = request_body("m", "q", &[candidate("a", "title", 2.5)]);
        let content = body["messages"][1]["content"].as_str().expect("user message is text");
        let payload: Value = serde_json::from_str(content).expect("payload is JSON");
        assert_eq!(payload["query"], "q");
        assert_eq!(payload["candidates"][0]["id"], "a");
        assert!(payload["candidates"][0]["snippet"].is_string());
        assert!(!content.contains("api_key"));
        assert!(!content.contains("ciphertext"));
        assert_eq!(body["temperature"], 0);
    }
}
