//! Opt-in per-domain similarity thresholds for judge-then-store (agent.json `sim_thresholds`).
//!
//! Judge-then-store splits ranked recall candidates inside Core on hard lines
//! (`remember_candidates`: merge ≥ 0.45, parent ≥ 0.30 — core-ffi `business.rs`,
//! `remember_candidates` arm). This module exposes those lines as a per-taxonomy-root
//! override without touching the Core contract:
//!
//! ```json
//! {"sim_thresholds": {"default": {"merge": 0.45, "parent": 0.30},
//!                     "编程开发": {"merge": 0.90, "parent": 0.60}}}
//! ```
//!
//! - Key absent (or not an object) → caller keeps the legacy Core FFI path, byte-for-byte.
//! - Key present → the caller ranks once via `query` mode `scored` (the same
//!   `recall_local_scored`, same payload) and splits here with the configured bands.
//! - Domain = the taxonomy root title reached by walking `local_parent_id` from a
//!   candidate. Unknown domains, broken chains and cycles fall back to `default`,
//!   then to the legacy lines (0.45 / 0.30).

use crate::{MemoryEntry, StoredMemory};
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;

/// Hard lines inside Core `remember_candidates` (merge ≥ 0.45, parent ≥ 0.30).
pub const LEGACY_MERGE: f32 = 0.45;
pub const LEGACY_PARENT: f32 = 0.30;

/// One split band: `score >= merge` → merge candidate, `parent <= score < merge` →
/// attach candidate, below `parent` → not a candidate at all.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Band {
    pub merge: f32,
    pub parent: f32,
}

impl Band {
    /// The exact lines Core applies today (`>= 0.45` / `>= 0.30`).
    pub const fn legacy() -> Self {
        Self {
            merge: LEGACY_MERGE,
            parent: LEGACY_PARENT,
        }
    }
}

/// Parsed `sim_thresholds`; `None` from [`SimThresholds::parse`] means "unconfigured".
#[derive(Debug, Default, PartialEq)]
pub struct SimThresholds {
    default: Option<Band>,
    domains: HashMap<String, Band>,
}

/// Parse one band entry; `None` for anything not shaped like `{"merge":x,"parent":y}`
/// with `0 <= parent <= merge <= 1`. Hand-edited invalid entries are ignored by
/// [`SimThresholds::parse`] (never crash a store) and rejected by [`validate`].
fn band_of(value: &Value) -> Option<Band> {
    let object = value.as_object()?;
    let merge = object.get("merge")?.as_f64()? as f32;
    let parent = object.get("parent")?.as_f64()? as f32;
    if !merge.is_finite()
        || !parent.is_finite()
        || !(0.0..=1.0).contains(&merge)
        || !(0.0..=1.0).contains(&parent)
        || parent > merge
    {
        return None;
    }
    Some(Band { merge, parent })
}

impl SimThresholds {
    /// `None` when the `sim_thresholds` key is absent or not an object: the caller
    /// then keeps the legacy Core `remember_candidates` path unchanged.
    pub fn parse(config: &Value) -> Option<Self> {
        let object = config.get("sim_thresholds")?.as_object()?;
        let mut parsed = SimThresholds::default();
        for (domain, value) in object {
            let Some(band) = band_of(value) else {
                continue; // invalid hand-edited band: ignore, fall back toward default/legacy
            };
            if domain == "default" {
                parsed.default = Some(band);
            } else if !domain.trim().is_empty() {
                parsed.domains.insert(domain.clone(), band);
            }
        }
        Some(parsed)
    }

    /// Domain band → `default` band → legacy lines.
    pub fn band(&self, domain: Option<&str>) -> Band {
        domain
            .and_then(|name| self.domains.get(name).copied())
            .or(self.default)
            .unwrap_or_else(Band::legacy)
    }

    /// Split ranked candidates exactly like Core `remember_candidates`, but with a
    /// per-domain band per candidate. Order inside each list follows `ranked` — the
    /// same order the Core filters preserve — so with every band set to the legacy
    /// lines the output equals the Core split element for element.
    pub fn split(
        &self,
        ranked: &[(f32, MemoryEntry)],
        domains: &DomainIndex<'_>,
    ) -> (Vec<(f32, MemoryEntry)>, Vec<(f32, MemoryEntry)>) {
        let mut merge = Vec::new();
        let mut parent = Vec::new();
        for (score, entry) in ranked {
            let band = self.band(domains.root_title(&entry.id));
            if *score >= band.merge {
                merge.push((*score, entry.clone()));
            } else if *score >= band.parent {
                parent.push((*score, entry.clone()));
            }
        }
        (merge, parent)
    }
}

/// Taxonomy-root lookup over the recall catalog: id → (parent_id, title).
pub struct DomainIndex<'a> {
    nodes: HashMap<&'a str, (&'a str, &'a str)>,
}

impl<'a> DomainIndex<'a> {
    pub fn new(catalog: &'a [StoredMemory]) -> Self {
        Self {
            nodes: catalog
                .iter()
                .map(|row| {
                    (
                        row.id.as_str(),
                        (row.local_parent_id.as_str(), row.local_title.as_str()),
                    )
                })
                .collect(),
        }
    }

    /// Root title of `id`; `None` when the entry or an ancestor is missing from the
    /// catalog (broken chain) or the chain cycles — callers then fall back to the
    /// `default` band instead of guessing a domain.
    pub fn root_title(&self, id: &str) -> Option<&'a str> {
        let mut current = id;
        let mut steps = 0usize;
        loop {
            let (parent, title) = self.nodes.get(current)?;
            if parent.is_empty() || *parent == current {
                return Some(*title);
            }
            steps += 1;
            if steps > self.nodes.len() {
                return None; // cycle guard
            }
            current = *parent;
        }
    }
}

/// `agent-config --set sim_thresholds=<json>` validation (see `write_agent_config_key`).
pub fn validate(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .context("sim_thresholds must be an object")?;
    for (domain, band) in object {
        anyhow::ensure!(!domain.trim().is_empty(), "sim_thresholds domain must not be empty");
        let fields = band.as_object().with_context(|| {
            format!("sim_thresholds.{domain} must be an object with merge and parent")
        })?;
        for key in fields.keys() {
            anyhow::ensure!(
                key == "merge" || key == "parent",
                "unknown sim_thresholds.{domain} key {key}"
            );
        }
        for key in ["merge", "parent"] {
            anyhow::ensure!(
                fields.contains_key(key),
                "sim_thresholds.{domain} needs {key}"
            );
        }
        band_of(band).with_context(|| {
            format!("sim_thresholds.{domain} needs 0 <= parent <= merge <= 1")
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Kind, MemoryEntry};

    fn entry(id: &str) -> MemoryEntry {
        MemoryEntry {
            metadata: Default::default(),
            unknown_fields: Default::default(),
            supersedes: String::new(),
            superseded_by: String::new(),
            see_also: Vec::new(),
            id: id.into(),
            kind: Kind::Context,
            tags: vec![],
            title: format!("title-{id}"),
            content: format!("content-{id}"),
            user: "test".into(),
            computer: "test".into(),
            project: "test".into(),
            created_at: "2026-11-06T00:00:00Z".into(),
            updated_at: "2026-11-06T00:00:00Z".into(),
            emotion: -1.0,
            parent_id: String::new(),
            importance: "important".into(),
            device: "test".into(),
            modified_by: "test".into(),
        }
    }

    fn row(id: &str, parent: &str, title: &str) -> StoredMemory {
        StoredMemory {
            id: id.into(),
            user: "test".into(),
            ciphertext: String::new(),
            nonce: String::new(),
            embedding_enc: String::new(),
            updated_at: "2026-11-06T00:00:00.000Z".into(),
            deleted: false,
            local_kind: String::new(),
            local_tags: String::new(),
            local_title: title.into(),
            local_project: String::new(),
            local_computer: String::new(),
            local_embedding: None,
            local_parent_id: parent.into(),
            local_created_at: String::new(),
            local_content_head: String::new(),
            local_recall_count: 0,
            local_importance: String::new(),
            local_device: String::new(),
            local_modified_by: String::new(),
            local_chunks: vec![],
            local_artifact: vec![],
            local_meta: Default::default(),
        }
    }

    /// The exact filter Core applies in `remember_candidates` (core-ffi business.rs).
    fn core_split(ranked: &[(f32, MemoryEntry)]) -> (Vec<(f32, MemoryEntry)>, Vec<(f32, MemoryEntry)>) {
        let merge: Vec<_> = ranked.iter().filter(|(s, _)| *s >= 0.45).cloned().collect();
        let parent: Vec<_> = ranked
            .iter()
            .filter(|(s, _)| *s >= 0.30 && *s < 0.45)
            .cloned()
            .collect();
        (merge, parent)
    }

    fn config(json: serde_json::Value) -> SimThresholds {
        SimThresholds::parse(&json).expect("sim_thresholds configured")
    }

    #[test]
    fn absent_key_is_unconfigured() {
        assert!(SimThresholds::parse(&serde_json::json!({})).is_none());
        assert!(SimThresholds::parse(&serde_json::json!({"memory_off": false})).is_none());
        assert!(SimThresholds::parse(&serde_json::Value::Null).is_none());
        // Wrong type under the key: not an object → still unconfigured, legacy path.
        assert!(SimThresholds::parse(&serde_json::json!({"sim_thresholds": 3})).is_none());
    }

    #[test]
    fn legacy_band_matches_core_lines() {
        assert_eq!(Band::legacy(), Band { merge: 0.45, parent: 0.30 });
        assert_eq!(Band::legacy().merge, LEGACY_MERGE);
        assert_eq!(Band::legacy().parent, LEGACY_PARENT);
    }

    #[test]
    fn default_band_applies_without_domain() {
        let thresholds = config(serde_json::json!({
            "sim_thresholds": {"default": {"merge": 0.9, "parent": 0.5}}
        }));
        assert_eq!(thresholds.band(None), Band { merge: 0.9, parent: 0.5 });
    }

    #[test]
    fn domain_band_overrides_default() {
        let thresholds = config(serde_json::json!({
            "sim_thresholds": {
                "default": {"merge": 0.45, "parent": 0.30},
                "编程开发": {"merge": 0.9, "parent": 0.6}
            }
        }));
        assert_eq!(
            thresholds.band(Some("编程开发")),
            Band { merge: 0.9, parent: 0.6 }
        );
        assert_eq!(
            thresholds.band(Some("家庭")),
            Band { merge: 0.45, parent: 0.30 },
            "unknown domain falls back to default"
        );
    }

    #[test]
    fn unknown_domain_falls_back_to_default_then_legacy() {
        let with_default = config(serde_json::json!({
            "sim_thresholds": {
                "default": {"merge": 0.7, "parent": 0.4},
                "编程开发": {"merge": 0.9, "parent": 0.6}
            }
        }));
        assert_eq!(with_default.band(Some("不存在的域")), Band { merge: 0.7, parent: 0.4 });
        assert_eq!(with_default.band(None), Band { merge: 0.7, parent: 0.4 });

        let without_default = config(serde_json::json!({
            "sim_thresholds": {"编程开发": {"merge": 0.9, "parent": 0.6}}
        }));
        assert_eq!(
            without_default.band(Some("家庭")),
            Band::legacy(),
            "no default configured → legacy lines"
        );
        assert_eq!(without_default.band(None), Band::legacy());
    }

    #[test]
    fn boundary_scores_classify_exactly_like_core() {
        let band = Band::legacy();
        // merge edge: exactly 0.45 is merge; the next f32 below it is parent.
        assert_eq!(band.merge, 0.45);
        assert!(0.45f32 >= band.merge);
        let just_below_merge = f32::from_bits(0.45f32.to_bits() - 1);
        assert!(just_below_merge < band.merge && just_below_merge >= band.parent);
        // parent edge: exactly 0.30 is parent; the next f32 below it is dropped.
        assert!(0.30f32 >= band.parent);
        let just_below_parent = f32::from_bits(0.30f32.to_bits() - 1);
        assert!(just_below_parent < band.parent);
        // configured band edges
        let strict = Band { merge: 0.9, parent: 0.6 };
        assert!(0.9f32 >= strict.merge);
        let just_below_strict_merge = f32::from_bits(0.9f32.to_bits() - 1);
        assert!(just_below_strict_merge < strict.merge && just_below_strict_merge >= strict.parent);
        let just_below_strict_parent = f32::from_bits(0.6f32.to_bits() - 1);
        assert!(just_below_strict_parent < strict.parent);
    }

    #[test]
    fn split_matches_core_remember_candidates_filter() {
        let ranked: Vec<(f32, MemoryEntry)> = [
            (0.92f32, entry("a")),
            (0.45, entry("b")),
            (0.44999997, entry("c")),
            (0.30, entry("d")),
            (0.29999998, entry("e")),
            (0.0, entry("f")),
        ]
        .into_iter()
        .collect();
        let domains = DomainIndex::new(&[]);
        // Legacy bands must reproduce Core's split element for element, order included.
        let thresholds = config(serde_json::json!({
            "sim_thresholds": {"default": {"merge": 0.45, "parent": 0.30}}
        }));
        let (merge, parent) = thresholds.split(&ranked, &domains);
        let (core_merge, core_parent) = core_split(&ranked);
        assert_eq!(
            merge.iter().map(|(s, e)| (*s, e.id.clone())).collect::<Vec<_>>(),
            core_merge.iter().map(|(s, e)| (*s, e.id.clone())).collect::<Vec<_>>(),
            "merge list (ids and scores, in order) must equal Core's filter"
        );
        assert_eq!(
            parent.iter().map(|(s, e)| (*s, e.id.clone())).collect::<Vec<_>>(),
            core_parent.iter().map(|(s, e)| (*s, e.id.clone())).collect::<Vec<_>>(),
            "parent list (ids and scores, in order) must equal Core's filter"
        );
        // And unconfigured callers keep the literal Core path (parse returns None).
        assert!(SimThresholds::parse(&serde_json::json!({})).is_none());
    }

    #[test]
    fn split_uses_per_domain_bands() {
        let ranked: Vec<(f32, MemoryEntry)> = [
            (0.85f32, entry("code-child")),
            (0.85, entry("home-child")),
            (0.85, entry("orphan")),
        ]
        .into_iter()
        .collect();
        let catalog = vec![
            row("code-child", "code-root", "编程开发"),
            row("code-root", "", "编程开发"),
            row("home-child", "home-root", "家庭"),
            row("home-root", "", "家庭"),
            row("orphan", "missing-root", "编程开发"), // broken chain → default
        ];
        let domains = DomainIndex::new(&catalog);
        let thresholds = config(serde_json::json!({
            "sim_thresholds": {
                "default": {"merge": 0.9, "parent": 0.3},
                "编程开发": {"merge": 0.8, "parent": 0.7}
            }
        }));
        let (merge, parent) = thresholds.split(&ranked, &domains);
        let ids = |list: &[(f32, MemoryEntry)]| list.iter().map(|(_, e)| e.id.clone()).collect::<Vec<_>>();
        // 编程开发 band (merge 0.8): 0.85 → merge candidate.
        assert_eq!(ids(&merge), vec!["code-child".to_string()]);
        // 家庭 keeps the default band (merge 0.9): 0.85 → parent, not merge.
        // Broken chain (orphan) also falls back to default — not to the 编程开发 band,
        // which would have pushed 0.85 into merge.
        assert_eq!(ids(&parent), vec!["home-child".to_string(), "orphan".to_string()]);
    }

    #[test]
    fn domain_index_resolves_root_and_guards() {
        let catalog = vec![
            row("leaf", "mid", "叶子"),
            row("mid", "root", "中间"),
            row("root", "", "编程开发"),
            row("loop-a", "loop-b", "循环A"),
            row("loop-b", "loop-a", "循环B"),
            row("dangling", "gone", "断链"),
        ];
        let domains = DomainIndex::new(&catalog);
        assert_eq!(domains.root_title("leaf"), Some("编程开发"));
        assert_eq!(domains.root_title("root"), Some("编程开发"));
        assert_eq!(domains.root_title("loop-a"), None, "cyclic chain → no domain");
        assert_eq!(domains.root_title("dangling"), None, "broken chain → no domain");
        assert_eq!(domains.root_title("unknown-id"), None);
        // A self-parented node is its own root, not an infinite walk.
        let self_parented = vec![row("self", "self", "自根")];
        assert_eq!(DomainIndex::new(&self_parented).root_title("self"), Some("自根"));
    }

    #[test]
    fn validate_accepts_well_formed_and_rejects_bad_shapes() {
        assert!(validate(&serde_json::json!({})).is_ok());
        assert!(validate(&serde_json::json!({
            "default": {"merge": 0.45, "parent": 0.30},
            "编程开发": {"merge": 0.9, "parent": 0.6}
        }))
        .is_ok());

        assert!(validate(&serde_json::json!([1])).is_err(), "not an object");
        assert!(
            validate(&serde_json::json!({"": {"merge": 0.5, "parent": 0.3}})).is_err(),
            "empty domain"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": 0.5}})).is_err(),
            "missing parent"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": "0.5", "parent": 0.3}})).is_err(),
            "non-number"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": 0.3, "parent": 0.5}})).is_err(),
            "parent above merge"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": 1.5, "parent": 0.3}})).is_err(),
            "merge above 1"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": 0.5, "parent": -0.1}})).is_err(),
            "parent below 0"
        );
        assert!(
            validate(&serde_json::json!({"d": {"merge": 0.5, "parent": 0.3, "x": 1.0}}))
                .is_err(),
            "unknown key"
        );
    }

    #[test]
    fn parse_ignores_invalid_bands_instead_of_crashing() {
        let thresholds = config(serde_json::json!({
            "sim_thresholds": {
                "default": {"merge": 0.7, "parent": 0.4},
                "bad": {"merge": 0.3, "parent": 0.5},
                "": {"merge": 0.9, "parent": 0.1}
            }
        }));
        assert_eq!(thresholds.band(Some("bad")), Band { merge: 0.7, parent: 0.4 });
        assert_eq!(thresholds.band(Some("")), Band { merge: 0.7, parent: 0.4 });
        assert_eq!(thresholds.band(None), Band { merge: 0.7, parent: 0.4 });
    }

    #[test]
    fn agent_config_round_trips_sim_thresholds_and_rejects_bad_shapes() -> Result<()> {
        let _isolate = crate::test_lock::Isolate::new()?;
        let band = serde_json::json!({
            "default": {"merge": 0.45, "parent": 0.30},
            "编程开发": {"merge": 0.9, "parent": 0.6}
        });
        // Write through the same `agent-config --set sim_thresholds=<json>` path.
        crate::service::write_agent_config_key("sim_thresholds", &band)?;
        let read = crate::service::read_agent_config();
        assert_eq!(
            read.get("sim_thresholds"),
            Some(&band),
            "agent.json must round-trip the bands unchanged"
        );
        let parsed = SimThresholds::parse(&read).expect("key present after write");
        assert_eq!(parsed.band(Some("编程开发")), Band { merge: 0.9, parent: 0.6 });
        assert_eq!(parsed.band(None), Band { merge: 0.45, parent: 0.30 });

        // Malformed shapes are refused before any write; agent.json stays untouched.
        let before = crate::service::read_agent_config();
        for bad in [
            serde_json::json!({"d": {"merge": 0.3, "parent": 0.5}}),
            serde_json::json!({"d": {"merge": 0.5}}),
            serde_json::json!([1.0]),
        ] {
            assert!(
                crate::service::write_agent_config_key("sim_thresholds", &bad).is_err(),
                "must reject {bad}"
            );
            assert_eq!(crate::service::read_agent_config(), before, "no partial write");
        }
        Ok(())
    }

    /// Restores one environment variable on drop (the Core test provider switch is
    /// process-wide; tests run multi-threaded, so keep the window as small as the
    /// test body and never leak it into later tests).
    struct EnvGuard(&'static str, Option<String>);
    impl EnvGuard {
        fn set(name: &'static str, value: &str) -> Self {
            let previous = std::env::var(name).ok();
            std::env::set_var(name, value);
            Self(name, previous)
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.1 {
                Some(value) => std::env::set_var(self.0, value),
                None => std::env::remove_var(self.0),
            }
        }
    }

    /// Equivalence against the live Core FFI path: with the same payload, the legacy
    /// `remember_candidates` operation and `query` mode `scored` + local split on the
    /// legacy bands must return the same candidates — ids, scores and order.
    #[test]
    fn live_scored_split_matches_core_remember_candidates() -> Result<()> {
        use crate::core_sdk::{
            self,
            search::{Embedder, HashingEmbedder},
        };
        use crate::{MemoryEngine, MemoryQuery, SessionKeys};

        let _isolate = crate::test_lock::Isolate::new()?;
        // Opening the store registers the thread's Core index root (business.rs
        // refuses every request without a selected profile index root).
        let _store = crate::transport::local::LocalStore::open(&_isolate.path().join("judge-eq.db"))?;
        // The Core test-hash provider refuses to run without the explicit switch.
        let _provider = EnvGuard::set("RESPIRE_CORE_TEST_MODE", "1");
        let _handle = EnvGuard::set("RSRS_CORE_TEST_MODE", "1");

        let keys = SessionKeys::from_urk([37; 32])?;
        let embedder = HashingEmbedder::new(8);
        let mut memories = Vec::new();
        for id in ["judge-eq-a", "judge-eq-b", "judge-eq-c"] {
            let entry = MemoryEntry {
                metadata: Default::default(),
                unknown_fields: Default::default(),
                supersedes: String::new(),
                superseded_by: String::new(),
                see_also: Vec::new(),
                id: id.into(),
                kind: Kind::Context,
                tags: vec![],
                title: format!("title-{id}"),
                content: "quantum bamboo flange dedup needle".into(),
                user: "test".into(),
                computer: "test".into(),
                project: "test".into(),
                created_at: "2026-11-06T00:00:00Z".into(),
                updated_at: format!("2026-11-06T00:00:0{id}Z"),
                emotion: -1.0,
                parent_id: String::new(),
                importance: "important".into(),
                device: "test".into(),
                modified_by: "test".into(),
            };
            memories.push(MemoryEngine::seal(&keys, &embedder, &entry, "synthetic")?);
        }
        let snapshots = crate::memory::engine::snapshots(&keys, &memories)?;
        let query = MemoryQuery::new("quantum bamboo flange dedup needle").limit(5);
        let base = serde_json::json!({
            "model": embedder.model_name(),
            "snapshots": snapshots,
            "query": query,
        });

        // Path 1: the untouched legacy Core operation.
        let legacy: core_sdk::RememberCandidates =
            core_sdk::execute("remember_candidates", base.clone())?;

        // Path 2: rank via query mode `scored`, split locally on the legacy bands.
        let mut scored_payload = base;
        scored_payload["mode"] = serde_json::json!("scored");
        let ranked: Vec<(f32, MemoryEntry)> = core_sdk::execute("query", scored_payload)?;
        assert!(!ranked.is_empty(), "fixture must be recalled at all");

        let thresholds = SimThresholds::parse(&serde_json::json!({
            "sim_thresholds": {"default": {"merge": 0.45, "parent": 0.30}}
        }))
        .expect("configured");
        let domains = DomainIndex::new(&memories);
        let (merge, parent) = thresholds.split(&ranked, &domains);

        let shape = |list: &[(f32, MemoryEntry)]| {
            list.iter()
                .map(|(score, entry)| (entry.id.clone(), *score))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            shape(&legacy.merge),
            shape(&merge),
            "merge candidates (ids, scores, order) must equal the live Core split"
        );
        assert_eq!(
            shape(&legacy.parent),
            shape(&parent),
            "parent candidates (ids, scores, order) must equal the live Core split"
        );
        Ok(())
    }
}
