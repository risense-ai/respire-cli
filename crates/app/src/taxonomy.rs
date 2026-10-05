//! taxonomy — built-in class lexicon (compile-time include, travels with the binary) + auto-classify + trivia diary
//!
//! Classes like an IME lexicon: on store the AI classifies first; a hit hangs under that outline (outline = tree root),
//! only when the lexicon cannot tell do we create a new subtree (root-create, user must agree; the AI must not overstep).
//! Trivia stays out of the tree: trivial is always diary flow (the serialized diary marker plus body); the time-ordered archive is its own chain.

use anyhow::Result;
use chrono::Local;

use crate::memory::engine::MemoryEngine;
use crate::memory::model::{Kind, MemoryEntry};
use crate::memory::search::Embedder;
use crate::memory::SessionKeys;
use crate::transport::local::LocalStore;
use crate::transport::MemoryTransport;

/// One built-in class.
pub struct Category {
    /// Outline name (the root entry title)
    pub title: &'static str,
    /// Domain: human / AI
    pub ai: bool,
    /// One-sentence gist (body when creating the outline; also the classify semantic anchor)
    pub gist: &'static str,
}

/// Built-in lexicon: 20 human-domain + 3 AI-domain.
pub const CATALOG: &[Category] = &[
    Category { title: "家庭亲友", ai: false, gist: "家人亲戚朋友之事：相处往来、婚恋家庭、红白喜事、重要日子。" },
    Category { title: "健康医疗", ai: false, gist: "身体健康之事：病症就医、用药体检、睡眠心理、康复保健。" },
    Category { title: "财务理财", ai: false, gist: "钱财之事：收支储蓄、投资理财、借贷税务、保险账单。" },
    Category { title: "饮食烹饪", ai: false, gist: "吃喝之事：做饭菜谱、外卖餐厅、口味偏好、饮食安排。" },
    Category { title: "住房家居", ai: false, gist: "居住之事：租房买房、装修改造、家具家电、维修保洁。" },
    Category { title: "出行交通", ai: false, gist: "出行之事：通勤路线、驾车骑车、票务车务、交通规则。" },
    Category { title: "购物消费", ai: false, gist: "购物之事：买什么、比价优惠、快递退换、二手转卖。" },
    Category { title: "职业工作", ai: false, gist: "职业之事：岗位事务、职场人际、求职离职、工作安排。" },
    Category { title: "任务计划", ai: false, gist: "任务计划之事：待办任务、项目规划、工程拆解、进度跟进。" },
    Category { title: "编程开发", ai: false, gist: "编程开发之事：代码项目、技术栈、环境部署、开发流程。" },
    Category { title: "学习成长", ai: false, gist: "求知之事：读书上课、考试考证、学习方法、成长记录。" },
    Category { title: "兴趣娱乐", ai: false, gist: "消遣之事：影音娱乐、爱好收藏、文艺创作性消遣。" },
    Category { title: "电子游戏", ai: false, gist: "游戏之事：进度存档、版本攻略、平台外设、联机赛事。" },
    Category { title: "运动健身", ai: false, gist: "运动之事：锻炼健身、球类赛事、装备场地、体能记录。" },
    Category { title: "社交网络", ai: false, gist: "社交之事：线上平台账号、群聊动态、人情往来礼数。" },
    Category { title: "旅行游历", ai: false, gist: "旅行之事：行程攻略、景点住宿、证件票务、游记见闻。" },
    Category { title: "宠物植物", ai: false, gist: "养宠种栽之事：喂养照料、健康驯导、花草养护。" },
    Category { title: "情感心境", ai: false, gist: "心绪之事：情绪起伏、压力心结、感悟释怀。" },
    Category { title: "习惯养成", ai: false, gist: "自我管理之事：作息习惯、戒断坚持、计划目标、复盘。" },
    Category { title: "灵感创意", ai: false, gist: "创造之事：点子灵感、创作构思、作品构想。" },
    Category { title: "技能库", ai: true, gist: "给 AI 用：可重复的操作序列——下次遇同类事照做即可的步骤、命令、流程。" },
    Category { title: "经验库", ai: true, gist: "给 AI 用：总结出的规律做法——以后做同类事该参照的经验沉淀。" },
    Category { title: "踩坑录", ai: true, gist: "给 AI 用：踩坑记录——症状、原因、解法俱全，同一坑不踩第二次。" },
];

pub fn category(idx: usize) -> &'static Category {
    &CATALOG[idx]
}

pub fn find_by_title(title: &str) -> Option<usize> {
    CATALOG.iter().position(|c| c.title == title)
}

/// Outline entry id (deterministic uuid-v5-like: sha1(domain + name) formatted as 16 bytes).
/// Same outline, same id across devices; re-running the same lexicon does not recreate.
pub fn root_id(title: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    Digest::update(&mut h, b"respire-taxonomy-v1:");
    Digest::update(&mut h, title.as_bytes());
    let d = h.finalize();
    let b: [u8; 16] = d[..16].try_into().unwrap_or([0u8; 16]);
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Classify semantic-anchor text (same source as the outline body).
pub fn anchor_text(c: &Category) -> String {
    format!("{}：{}", c.title, c.gist)
}

/// Outline entry (Kind::Knowledge, importance=important, hangs at root).
fn category_entry(c: &Category) -> MemoryEntry {
    let now = Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    MemoryEntry {
        supersedes: String::new(),
        superseded_by: String::new(),
        see_also: Vec::new(),
        id: root_id(c.title),
        kind: Kind::Knowledge,
        tags: vec!["词库纲".to_owned(), if c.ai { "AI域" } else { "人域" }.to_owned()],
        title: c.title.to_owned(),
        content: anchor_text(c),
        user: crate::service::current_user(),
        computer: String::new(),
        device: crate::service::device_tag(),
        modified_by: crate::service::device_tag(),
        project: String::new(),
        created_at: now.clone(),
        updated_at: now,
        emotion: -1.0,
        parent_id: String::new(),
        importance: "important".to_owned(),
    }
}

/// Create outline (idempotent): exists → take it; missing → store. Returns root id. Does not auto-sync (caller auto_sync).
pub fn ensure_category_root<E: Embedder>(
    session: &SessionKeys,
    embedder: &E,
    store: &LocalStore,
    idx: usize,
) -> Result<String> {
    let c = category(idx);
    let rid = root_id(c.title);
    if store.all(false)?.iter().any(|m| m.id == rid && !m.deleted) {
        return Ok(rid);
    }
    let stored = MemoryEngine::seal(session, embedder, &category_entry(c), &category_entry(c).user)?;
    store.put(&stored)?;
    Ok(rid)
}

/// Lexical classify: lowercase body (including title) and count keyword hits.


/// Auto-classify: lexical hits (if tied, take the class with more keyword hits) → compare to the semantic anchor.
/// Returns (class index, anchor similarity). Lexical and semantic both use the hit class; semantic only rejects a false attach.
/// Decision: lexical hits ≥1 and anchor sim ≥0.42 → hit; no lexical hits → None (do not guess).
pub fn classify<E: Embedder>(
    embedder: &E,
    text: &str,
) -> Result<Option<(usize, f32)>> {
    respire_core_sdk::execute("taxonomy_classify", serde_json::json!({"model":embedder.model_name(), "text":text}))
}

/// Build a diary body from the serialized marker, date/time and original content.
pub fn diary_content(content: &str) -> String {
    format!("【日记】{} {}", Local::now().format("%Y-%m-%d %H:%M"), content)
}

/// Orphan root: a live root with no parent and no children (the object of create-outline ask).
pub fn lone_roots(store: &LocalStore) -> Result<Vec<(String, String)>> {
    let all = store.all(false)?;
    let mut out = Vec::new();
    for m in &all {
        if !m.local_parent_id.is_empty() {
            continue;
        }
        let has_child = all.iter().any(|x| x.local_parent_id == m.id);
        if !has_child {
            out.push((m.id.clone(), if m.local_title.is_empty() { m.local_content_head.chars().take(24).collect() } else { m.local_title.clone() }));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_id_is_deterministic_uuid_like() {
        let a = root_id("家庭亲友");
        let b = root_id("家庭亲友");
        assert_eq!(a, b);
        assert_eq!(a.len(), 36);
        assert_ne!(a, root_id("技能库"));
    }

    #[test]
    fn catalog_has_23_and_no_dup_titles() {
        assert_eq!(CATALOG.len(), 23);
        let mut titles: Vec<_> = CATALOG.iter().map(|c| c.title).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), CATALOG.len(), "duplicate catalog titles");
        assert_eq!(CATALOG.iter().filter(|c| c.ai).count(), 3, "AI domain must have 3 classes");
    }


    #[test]
    fn diary_content_stamps_body() {
        let s = diary_content("hello trail");
        assert!(s.starts_with("【日记】"));
        assert!(s.contains("hello trail"));
    }
    #[test]
    fn lone_roots_skips_parents() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = LocalStore::open(&dir.path().join("t.db"))?;
        let mut root = crate::memory::model::StoredMemory::new_pending(
            "11111111-1111-4111-8111-111111111111".into(),
            "u".into(),
        );
        root.local_title = "root".into();
        let mut child = crate::memory::model::StoredMemory::new_pending(
            "22222222-2222-4222-8222-222222222222".into(),
            "u".into(),
        );
        child.local_parent_id = root.id.clone();
        child.local_title = "child".into();
        let mut lone = crate::memory::model::StoredMemory::new_pending(
            "33333333-3333-4333-8333-333333333333".into(),
            "u".into(),
        );
        lone.local_title = "orphan".into();
        MemoryTransport::put(&store, &root)?;
        MemoryTransport::put(&store, &child)?;
        MemoryTransport::put(&store, &lone)?;
        let roots = lone_roots(&store)?;
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].0, lone.id);
        Ok(())
    }
}
