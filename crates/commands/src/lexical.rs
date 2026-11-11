//! Model-free lexical index primitives used by the cache correctness gates.
//!
//! The index reads local title, tags and content-head fields. Production
//! retrieval and cache integration remain in the independent Runtime and Core.

use std::collections::{HashMap, HashSet};

use anyhow::Result;

use respire_app::transport::local::LocalStore;
use respire_app::MemoryTransport;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LexicalCandidate {
    pub id: String,
    pub title: String,
    pub score: f32,
    pub snippet: String,
}

const K1: f32 = 1.2;
const B: f32 = 0.75;
/// Field weights: a title hit is worth more than a body hit.
const W_TITLE: f32 = 3.0;
const W_TAGS: f32 = 2.0;
const W_HEAD: f32 = 1.0;
const SNIPPET_CHARS: usize = 120;

fn is_cjk(c: char) -> bool {
    matches!(c as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF)
}

fn flush_ascii(buffer: &mut String, out: &mut Vec<String>) {
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
    avg_len: [f32; 3],
    df: HashMap<String, u32>,
}

const FIELD_WEIGHTS: [f32; 3] = [W_TITLE, W_TAGS, W_HEAD];

impl Bm25Index {
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
        Self { docs, fields, avg_len, df }
    }

    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// Rough resident size, for cache diagnostics only (not a precise allocator
    /// figure): document text plus one entry per indexed token.
    pub fn approx_bytes(&self) -> usize {
        let docs: usize = self.docs.iter().map(|doc| 96 + doc.title.len() + doc.tags.len() + doc.head.len() + doc.project.len() + doc.kind.len() + doc.created_at.len()).sum();
        let fields: usize = self.fields.iter().flatten()
            .map(|vector| vector.tf.iter().map(|(token, _)| 48 + token.len()).sum::<usize>())
            .sum();
        let df: usize = self.df.keys().map(|token| 48 + token.len()).sum();
        docs + fields + df + std::mem::size_of::<Self>()
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

    pub fn candidates(&self, query: &str, topk: usize) -> Vec<LexicalCandidate> {
        self.search(query, topk)
            .into_iter()
            .map(|(index, score)| {
                let doc = &self.docs[index];
                LexicalCandidate {
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
            created_at: if m.local_created_at.is_empty() {
                m.updated_at.clone()
            } else {
                m.local_created_at.clone()
            },
            kind: m.local_kind.clone(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str, title: &str, tags: &str, head: &str) -> RowDoc {
        RowDoc {
            id: id.into(),
            title: title.into(),
            tags: tags.into(),
            head: head.into(),
            project: "demo".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            kind: "context".into(),
        }
    }

    #[test]
    fn chinese_bigrams_and_ascii_tokens() {
        assert_eq!(tokenize("部署脚本"), vec!["部署", "署脚", "脚本"]);
        assert_eq!(tokenize("BM25 召回"), vec!["bm25", "召回"]);
        assert_eq!(tokenize("query_log 表"), vec!["query_log", "表"]);
        assert_eq!(tokenize("  ,. -x- "), Vec::<String>::new());
        assert!(tokenize("  ,. ").is_empty());
    }

    #[test]
    fn bm25_ranks_the_intent_match_first() {
        let docs = vec![
            doc("d1", "KMeans 聚类超参数", "ml,cluster", "聚类数量 k 的选择与肘部法"),
            doc("d2", "部署脚本位置", "ops", "scripts/build-core-sdk.mjs 构建入口"),
            doc("d3", "周报模板", "doc", "每周进展与风险"),
        ];
        let index = Bm25Index::build(docs);
        assert_eq!(index.len(), 3);
        assert!(!index.is_empty());
        assert_eq!(index.doc(0).map(|d| d.id.as_str()), Some("d1"));
        assert!(index.doc(9).is_none());
        let hits = index.candidates("聚类算法怎么选 k", 3);
        assert_eq!(hits[0].id, "d1");
        assert!(hits[0].score > 0.0);
        let hits = index.candidates("部署脚本", 3);
        assert_eq!(hits[0].id, "d2");
        assert!(index.candidates("量子纠缠", 3).is_empty());
    }

    #[test]
    fn bm25_scores_are_replayable() {
        let docs: Vec<RowDoc> = (0..5)
            .map(|i| doc(&format!("id{i}"), &format!("memory {i}"), "", "alpha beta gamma"))
            .collect();
        let first = Bm25Index::build(docs.clone()).candidates("alpha", 3);
        let second = Bm25Index::build(docs).candidates("alpha", 3);
        assert_eq!(first.len(), 3);
        assert_eq!(first[0].id, second[0].id);
        assert_eq!(first[0].score, second[0].score);
    }

    #[test]
    fn empty_query_and_empty_index_return_nothing() {
        let index = Bm25Index::build(Vec::new());
        assert!(index.is_empty());
        assert!(index.search("alpha", 5).is_empty());
        let index = Bm25Index::build(vec![doc("d", "标题", "", "正文")]);
        assert!(index.search(" ,. ", 5).is_empty());
    }

    #[test]
    fn candidate_title_falls_back_to_head_and_snippet_truncates() {
        let head = "很长的正文".repeat(40);
        let index = Bm25Index::build(vec![doc("d", "   ", "", &head)]);
        let hits = index.candidates("很长", 1);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title.chars().count(), 40);
        assert!(hits[0].snippet.ends_with('…'));
    }
}
