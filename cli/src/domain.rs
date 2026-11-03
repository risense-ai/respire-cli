//! Domain/effect: read-time projection of the taxonomy tree onto four effect axes.
//!
//! A record's **domain** is where it hangs: walk `parent_id` up to a taxonomy
//! root (`taxonomy::CATALOG`) and fold the 23 built-in roots into five
//! behaviour domains. Its **effect** is what the record is *for*: a norm
//! (rule to obey), a procedure (how-to), material (fact/reference) or stream
//! (running context).
//!
//! The projection is deliberately inert:
//!
//! * computed at read time — never stored, exported, synced or used as a tag;
//! * never filters, never reorders, never gates a candidate;
//! * surfaces only as JSON labels (`details[].domain` / `details[].effect` and
//!   `summary.slices`), so domain names never reach injected prompt text.
//!
//! Why labels only: on a 62-query slice of a real library, re-slicing the
//! ranked list by domain collapsed hit@5 from 0.710 to 0.306, while an additive
//! "reserve one seat for a missing effect" gained norm visibility 0.806 → 1.000
//! for a single lost hit (respire-benchmark `tests/28-domain-effect-slicing-
//! 20261103.md`). Sorting belongs to Core; seat reservation belongs to the
//! emission layer; this module only reports the projection.

use std::collections::HashMap;

use crate::taxonomy::find_by_title;
use crate::StoredMemory;

/// Maximum parent hops when resolving a domain — same cap as
/// `LocalStore::ancestor_chain`, so a pathological chain degrades instead of looping.
const MAX_PARENT_HOPS: usize = 64;

/// Five behaviour domains folded from the 23 catalog roots, plus
/// `Unassigned` for anything outside the catalog (user-created roots, orphans,
/// rows whose parent chain is not in the catalog).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// 编程开发 / 职业工作 / 任务计划
    Work,
    /// 技能库 — repeatable AI procedures
    AiFlow,
    /// 经验库 / 踩坑录 — distilled norms and pitfalls
    AiNorm,
    /// 财务理财
    Finance,
    /// 灵感创意 / 学习成长
    Learn,
    /// The remaining 14 human roots (life, health, home, travel, …)
    Life,
    /// Not under any built-in root
    Unassigned,
}

impl Domain {
    /// Stable machine name for JSON. Never injected into prompt text.
    pub fn as_str(self) -> &'static str {
        match self {
            Domain::Work => "work",
            Domain::AiFlow => "ai_flow",
            Domain::AiNorm => "ai_norm",
            Domain::Finance => "finance",
            Domain::Learn => "learn",
            Domain::Life => "life",
            Domain::Unassigned => "unassigned",
        }
    }
}

/// What a record is served as when the hook renders an injection block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Rule to obey — how the agent must behave.
    Norm,
    /// Repeatable procedure — how to do the thing.
    Procedure,
    /// Fact/reference material — what is true.
    Material,
    /// Running context — background that is cheap to show and cheap to drop.
    Stream,
}

impl Effect {
    /// Stable machine name for JSON. Never injected into prompt text.
    pub fn as_str(self) -> &'static str {
        match self {
            Effect::Norm => "norm",
            Effect::Procedure => "procedure",
            Effect::Material => "material",
            Effect::Stream => "stream",
        }
    }
}

/// Fold one catalog root title into its behaviour domain.
///
/// Only built-in roots receive a domain: a title outside `CATALOG` is
/// `Unassigned` even if it hangs at the top of its own tree.
pub fn domain_of_root(title: &str) -> Domain {
    if find_by_title(title).is_none() {
        return Domain::Unassigned;
    }
    match title {
        // work
        "\u{7f16}\u{7a0b}\u{5f00}\u{53d1}" | "\u{804c}\u{4e1a}\u{5de5}\u{4f5c}"
        | "\u{4efb}\u{52a1}\u{8ba1}\u{5212}" => Domain::Work,
        // ai_flow
        "\u{6280}\u{80fd}\u{5e93}" => Domain::AiFlow,
        // ai_norm
        "\u{7ecf}\u{9a8c}\u{5e93}" | "\u{8e29}\u{5751}\u{5f55}" => Domain::AiNorm,
        // finance
        "\u{8d22}\u{52a1}\u{7406}\u{8d22}" => Domain::Finance,
        // learn
        "\u{7075}\u{611f}\u{521b}\u{610f}" | "\u{5b66}\u{4e60}\u{6210}\u{957f}" => Domain::Learn,
        // every other catalog root is one of the 14 human life outlines
        _ => Domain::Life,
    }
}

/// Domain default: what a record becomes when its kind carries no role.
pub fn default_effect(domain: Domain) -> Effect {
    match domain {
        Domain::AiFlow => Effect::Procedure,
        Domain::AiNorm => Effect::Norm,
        Domain::Work | Domain::Finance | Domain::Learn => Effect::Material,
        Domain::Life | Domain::Unassigned => Effect::Stream,
    }
}

/// S1 effect proxy: `kind` carries the role until a stored role field exists.
///
/// `kind` is the canonical lowercase form (`Kind::as_str`): `skill`,
/// `decision`, `preference`, … A future `role` override plugs in here as
/// `role ?? default_effect(domain)` without touching callers.
pub fn effect(kind: &str, domain: Domain) -> Effect {
    match kind {
        "skill" => Effect::Procedure,
        "decision" | "preference" => Effect::Norm,
        _ => default_effect(domain),
    }
}

/// Parent/title index over the resident catalog.
///
/// Domain resolution is a pure in-memory walk: one pass over rows the recall
/// command already holds, then O(depth) map lookups per hit — no store reads,
/// no decryption, no network.
pub struct Index<'a> {
    parent: HashMap<&'a str, &'a str>,
    title: HashMap<&'a str, &'a str>,
}

impl<'a> Index<'a> {
    /// Index the catalog rows recall already loaded (deleted rows are skipped).
    pub fn new(rows: &'a [StoredMemory]) -> Self {
        let mut parent = HashMap::with_capacity(rows.len());
        let mut title = HashMap::with_capacity(rows.len());
        for row in rows {
            if row.deleted {
                continue;
            }
            parent.insert(row.id.as_str(), row.local_parent_id.as_str());
            title.insert(row.id.as_str(), row.local_title.as_str());
        }
        Self { parent, title }
    }

    /// Resolve an entry's domain by walking `parent_id` to the root.
    ///
    /// A missing row, an empty index and a parent cycle all resolve to
    /// `Unassigned` — labels degrade, they never panic and never block recall.
    pub fn domain(&self, id: &str) -> Domain {
        let mut cur = id;
        for _ in 0..MAX_PARENT_HOPS {
            let (Some(parent), Some(title)) = (
                self.parent.get(cur).copied(),
                self.title.get(cur).copied(),
            ) else {
                return Domain::Unassigned;
            };
            if parent.is_empty() {
                return domain_of_root(title);
            }
            cur = parent;
        }
        Domain::Unassigned
    }
}
