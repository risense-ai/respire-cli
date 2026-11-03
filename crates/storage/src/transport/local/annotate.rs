//! annotation_log — LLM-in-the-loop retrieval annotation (query → BM25 candidates → LLM pick).
//!
//! Local-only, never synced. One row is directly replayable as a training sample:
//! the query, every candidate with its lexical score and snippet, the selected
//! (positive) ids, the model, the label source and the confidence. `status`
//! distinguishes a real LLM label (`ok`) from a dry-run candidate dump
//! (`dry_run`) and from failures (`llm_error` / `parse_error`) so weak labels
//! never mix with evidence of a broken call.
use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnnotationCandidate {
    pub id: String,
    pub title: String,
    pub score: f32,
    pub snippet: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnnotationRow {
    pub id: i64,
    pub created_at: i64,
    pub ts: String,
    pub query: String,
    pub project: String,
    pub scope: String,
    pub topk: usize,
    pub candidates: Vec<AnnotationCandidate>,
    pub selected: Vec<String>,
    pub confidence: f64,
    pub reason: String,
    pub model: String,
    /// human | model | task_outcome — human labels outrank model labels.
    pub source: String,
    /// ok | dry_run | llm_error | parse_error
    pub status: String,
    pub raw: String,
    pub request_id: Option<String>,
}

/// Real user adoption from query_log: the ids the caller actually opened or
/// marked good. This is the strongest label the product produces without an LLM.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LabeledQuery {
    pub ts_unix: i64,
    pub query: String,
    pub project: String,
    pub positives: Vec<String>,
}

/// Singleton learned reranker state; local-only, never synced.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LearnedModelRow {
    pub weights: Vec<f32>,
    pub bias: f32,
    pub updates: u64,
    pub updated_at: i64,
}

/// Insert payload; borrowed so callers keep ownership of the candidate list.
pub struct NewAnnotation<'a> {
    pub query: &'a str,
    pub project: &'a str,
    pub scope: &'a str,
    pub topk: usize,
    pub candidates: &'a [AnnotationCandidate],
    pub selected: &'a [String],
    pub confidence: f64,
    pub reason: &'a str,
    pub model: &'a str,
    pub source: &'a str,
    pub status: &'a str,
    pub raw: &'a str,
    pub request_id: Option<&'a str>,
}

impl LocalStore {
    pub fn insert_annotation(&self, row: &NewAnnotation<'_>) -> Result<i64> {
        anyhow::ensure!(
            matches!(row.source, "human" | "model" | "task_outcome"),
            "annotation source must be human, model, or task_outcome"
        );
        anyhow::ensure!(
            matches!(row.status, "ok" | "dry_run" | "llm_error" | "parse_error"),
            "annotation status must be ok, dry_run, llm_error or parse_error"
        );
        let now = chrono::Utc::now();
        self.connection.execute(
            "INSERT INTO annotation_log(created_at,ts,query,project,scope,topk,candidates,selected,confidence,reason,model,source,status,raw,request_id)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                now.timestamp(),
                now.to_rfc3339(),
                row.query,
                row.project,
                row.scope,
                row.topk as i64,
                serde_json::to_string(row.candidates)?,
                serde_json::to_string(row.selected)?,
                row.confidence,
                row.reason,
                row.model,
                row.source,
                row.status,
                row.raw,
                row.request_id
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn annotation_exists_request(&self, request_id: &str) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM annotation_log WHERE request_id=?1)",
            params![request_id],
            |row| row.get::<_, bool>(0),
        )?)
    }

    pub fn annotation_rows(&self, limit: usize) -> Result<Vec<AnnotationRow>> {
        self.annotation_rows_where("", &[], limit)
    }

    /// Training export: only real labels (status ok) unless `include_failed`.
    pub fn annotation_training_rows(&self, include_failed: bool, limit: usize) -> Result<Vec<AnnotationRow>> {
        let (clause, args): (&str, Vec<String>) = if include_failed {
            ("", Vec::new())
        } else {
            ("WHERE status='ok'", Vec::new())
        };
        self.annotation_rows_where(clause, &args, limit)
    }

    fn annotation_rows_where(
        &self,
        clause: &str,
        args: &[String],
        limit: usize,
    ) -> Result<Vec<AnnotationRow>> {
        let sql = format!(
            "SELECT id,created_at,ts,query,project,scope,topk,candidates,selected,confidence,reason,model,source,status,raw,request_id
             FROM annotation_log {clause} ORDER BY id DESC LIMIT {}",
            limit.max(1) as i64
        );
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement.query_map(rusqlite::params_from_iter(args.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, f64>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, String>(12)?,
                row.get::<_, String>(13)?,
                row.get::<_, String>(14)?,
                row.get::<_, Option<String>>(15)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                id,
                created_at,
                ts,
                query,
                project,
                scope,
                topk,
                candidates,
                selected,
                confidence,
                reason,
                model,
                source,
                status,
                raw,
                request_id,
            ) = row?;
            out.push(AnnotationRow {
                id,
                created_at,
                ts,
                query,
                project,
                scope,
                topk: topk.max(0) as usize,
                candidates: serde_json::from_str(&candidates).unwrap_or_default(),
                selected: serde_json::from_str(&selected).unwrap_or_default(),
                confidence,
                reason,
                model,
                source,
                status,
                raw,
                request_id,
            });
        }
        Ok(out)
    }

    pub fn annotation_count(&self) -> Result<i64> {
        Ok(self
            .connection
            .query_row("SELECT COUNT(*) FROM annotation_log", [], |row| row.get(0))?)
    }

    pub fn annotation_row(&self, id: i64) -> Result<Option<AnnotationRow>> {
        Ok(self.annotation_rows_where("WHERE id=?1", &[id.to_string()], 1)?.into_iter().next())
    }

    pub fn load_learned_model(&self) -> Result<Option<LearnedModelRow>> {
        self.connection
            .query_row(
                "SELECT weights,bias,updates,updated_at FROM learned_reranker WHERE id=1",
                [],
                |row| {
                    let raw: String = row.get(0)?;
                    Ok(LearnedModelRow {
                        weights: serde_json::from_str(&raw).unwrap_or_default(),
                        bias: row.get(1)?,
                        updates: row.get::<_, i64>(2)?.max(0) as u64,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn save_learned_model(&self, weights: &[f32], bias: f32, updates: u64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO learned_reranker(id,weights,bias,updates,updated_at) VALUES(1,?1,?2,?3,?4)
             ON CONFLICT(id) DO UPDATE SET weights=excluded.weights,bias=excluded.bias,updates=excluded.updates,updated_at=excluded.updated_at",
            params![serde_json::to_string(weights)?, bias, updates as i64, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    }

    pub fn clear_learned_model(&self) -> Result<()> {
        self.connection.execute("DELETE FROM learned_reranker WHERE id=1", [])?;
        Ok(())
    }

    /// Rows mined from query-log need their original query text only.
    pub fn recent_queries(&self, limit: usize) -> Result<Vec<(String, String)>> {
        let mut statement = self
            .connection
            .prepare("SELECT query, MAX(ts) FROM query_log GROUP BY query ORDER BY MAX(id) DESC LIMIT ?1")?;
        let rows = statement.query_map(params![limit.max(1) as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Oldest-first labeled queries with their adopted + explicitly-good ids.
    /// Same query text is merged so repeated asks do not multiply its weight.
    pub fn labeled_queries(&self, limit: usize) -> Result<Vec<LabeledQuery>> {
        let mut statement = self.connection.prepare(
            "SELECT ts_unix, query, project, adopted, good_ids FROM query_log
             WHERE adopted!='[]' OR good_ids!='[]' ORDER BY ts_unix ASC, id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        let mut merged: std::collections::BTreeMap<String, LabeledQuery> = Default::default();
        for row in rows {
            let (ts_unix, query, project, adopted, good) = row?;
            let parse = |text: &str| -> Vec<String> {
                serde_json::from_str::<Vec<String>>(text).unwrap_or_default()
            };
            let mut positives = parse(&adopted);
            positives.extend(parse(&good));
            positives.sort();
            positives.dedup();
            if positives.is_empty() { continue; }
            let entry = merged.entry(query.clone()).or_insert_with(|| LabeledQuery {
                ts_unix,
                query,
                project,
                positives: Vec::new(),
            });
            for id in positives {
                if !entry.positives.contains(&id) { entry.positives.push(id); }
            }
        }
        let mut out: Vec<LabeledQuery> = merged.into_values().collect();
        out.sort_by(|a, b| b.ts_unix.cmp(&a.ts_unix));
        out.truncate(limit.max(1));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Result<(tempfile::TempDir, LocalStore)> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("mem.db"))?;
        Ok((dir, store))
    }

    fn candidate(id: &str, score: f32) -> AnnotationCandidate {
        AnnotationCandidate {
            id: id.to_owned(),
            title: format!("title {id}"),
            score,
            snippet: format!("snippet {id}"),
        }
    }

    #[test]
    fn learned_model_roundtrip_and_clear() -> Result<()> {
        let (_dir, store) = store()?;
        assert!(store.load_learned_model()?.is_none());
        store.save_learned_model(&[1.0, 0.25, -0.5], 0.125, 7)?;
        let model = store.load_learned_model()?.context("saved model missing")?;
        assert_eq!(model.weights, vec![1.0, 0.25, -0.5]);
        assert_eq!(model.bias, 0.125);
        assert_eq!(model.updates, 7);
        store.clear_learned_model()?;
        assert!(store.load_learned_model()?.is_none());
        Ok(())
    }

    #[test]
    fn annotation_roundtrip_keeps_scores_and_labels() -> Result<()> {
        let (_dir, store) = store()?;
        let candidates = vec![candidate("a1", 3.5), candidate("b2", 1.25)];
        let selected = vec!["a1".to_owned()];
        let id = store.insert_annotation(&NewAnnotation {
            query: "部署脚本在哪",
            project: "respire",
            scope: "",
            topk: 2,
            candidates: &candidates,
            selected: &selected,
            confidence: 0.87,
            reason: "only a1 mentions the deploy script",
            model: "test-model",
            source: "model",
            status: "ok",
            raw: "",
            request_id: Some("11111111-1111-4111-8111-111111111111"),
        })?;
        assert!(id > 0);
        assert_eq!(store.annotation_count()?, 1);
        assert!(store.annotation_exists_request("11111111-1111-4111-8111-111111111111")?);
        let rows = store.annotation_rows(10)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].candidates.len(), 2);
        assert!((rows[0].candidates[0].score - 3.5).abs() < 1e-6);
        assert_eq!(rows[0].candidates[0].snippet, "snippet a1");
        assert_eq!(rows[0].selected, vec!["a1".to_owned()]);
        assert!((rows[0].confidence - 0.87).abs() < 1e-6);
        assert_eq!(rows[0].source, "model");
        Ok(())
    }

    #[test]
    fn training_export_skips_dry_run_rows() -> Result<()> {
        let (_dir, store) = store()?;
        let candidates = vec![candidate("a1", 1.0)];
        for status in ["dry_run", "ok"] {
            store.insert_annotation(&NewAnnotation {
                query: "q",
                project: "",
                scope: "",
                topk: 1,
                candidates: &candidates,
                selected: if status == "ok" { &[] as &[String] } else { &[] },
                confidence: 0.0,
                reason: "",
                model: "",
                source: "model",
                status,
                raw: "",
                request_id: None,
            })?;
        }
        assert_eq!(store.annotation_training_rows(false, 10)?.len(), 1);
        assert_eq!(store.annotation_training_rows(true, 10)?.len(), 2);
        Ok(())
    }

    #[test]
    fn invalid_source_and_status_are_rejected() -> Result<()> {
        let (_dir, store) = store()?;
        let empty: Vec<String> = Vec::new();
        let base = NewAnnotation {
            query: "q",
            project: "",
            scope: "",
            topk: 0,
            candidates: &[],
            selected: &empty,
            confidence: 0.0,
            reason: "",
            model: "",
            source: "robot",
            status: "ok",
            raw: "",
            request_id: None,
        };
        assert!(store.insert_annotation(&base).is_err());
        let bad_status = NewAnnotation { source: "model", status: "good", ..base };
        assert!(store.insert_annotation(&bad_status).is_err());
        Ok(())
    }
}
