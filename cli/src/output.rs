use serde::{Deserialize, Serialize};
use serde_json::Value;
use unicode_width::UnicodeWidthStr;

/// Stable command status shared by human and machine output.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Skip,
    Pending,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Pending => "pending",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Item {
    pub name: String,
    pub status: Status,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl Item {
    pub fn new(name: impl Into<String>, status: Status, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status,
            value: value.into(),
            action: None,
        }
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultEnvelope {
    pub command: String,
    pub status: Status,
    pub summary: Value,
    pub items: Vec<Item>,
    pub actions: Vec<String>,
    pub errors: Vec<String>,
    pub details: Value,
}

impl ResultEnvelope {
    pub fn new(
        command: impl Into<String>,
        status: Status,
        summary: Value,
        items: Vec<Item>,
    ) -> Self {
        Self {
            command: command.into(),
            status,
            summary,
            items,
            actions: Vec::new(),
            errors: Vec::new(),
            details: Value::Null,
        }
    }

    /// The caller supplies both business data and display rows. No schema or
    /// status is inferred from legacy JSON or terminal text.
    pub fn render(&self, json: bool) -> anyhow::Result<String> {
        if json {
            return Ok(serde_json::to_string(self)?);
        }
        // The prompt is a Markdown document, not a table cell. Preserve its paragraphs.
        if self.command == "prompt" {
            if let Some(instructions) = self.summary["instructions"].as_str() {
                return Ok(instructions.to_owned());
            }
        }
        let rows = self
            .items
            .iter()
            .map(|item| {
                vec![
                    crate::i18n::field_label(&item.name),
                    status_label(item.status).to_owned(),
                    humanize_value(&item.value),
                    item.action.clone().unwrap_or_default(),
                ]
            })
            .collect::<Vec<_>>();
        let mut sections = Vec::new();
        if !self.summary.is_null() {
            let rows = summary_rows(&self.summary);
            if !rows.is_empty() {
                let table = render_table(
                    &[crate::i18n::chrome("item"), crate::i18n::chrome("value")],
                    &rows,
                );
                sections.push(format!("{}\n{table}", crate::i18n::chrome("summary")));
            }
        }
        if !rows.is_empty() {
            sections.push(render_table(
                &[
                    crate::i18n::chrome("item"),
                    crate::i18n::chrome("status"),
                    crate::i18n::chrome("value"),
                    crate::i18n::chrome("action"),
                ],
                &rows,
            ));
        }
        let mut text = sections.join("\n");
        // `details` is a machine-readable extension point.  It can contain
        // large diagnostic structures and, historically, accidentally exposed
        // sealed storage rows.  Human output is intentionally limited to the
        // declared summary/items/actions/errors table; callers that need
        // details must opt into `--json`.
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&format!(
            "{}: {}",
            crate::i18n::chrome("result"),
            status_label(self.status)
        ));
        for action in &self.actions {
            text.push_str(&format!("\n{}: {action}", crate::i18n::chrome("action")));
        }
        for error in &self.errors {
            text.push_str(&format!("\nERROR: {error}"));
        }
        Ok(text)
    }
}

/// Remove persistence and credential material before a result crosses the
/// CLI boundary. StoredMemory is an internal shape and must never expose its
/// ciphertext, nonce or encrypted embeddings. Plaintext command payloads such
/// as recall/show content remain available; explicit secret/grant/share
/// commands retain the fields that are their declared result.
pub fn sanitize_details(command: &str, value: &Value) -> Value {
    fn sensitive_key(command: &str, key: &str) -> bool {
        let explicit = command.to_ascii_lowercase();
        matches!(
            key.to_ascii_lowercase().as_str(),
            "ciphertext"
                | "nonce"
                | "embedding"
                | "embedding_enc"
                | "local_embedding"
                | "wrapped_urk"
                | "kdf_salt"
                | "blob"
        ) || (matches!(key.to_ascii_lowercase().as_str(), "token" | "password")
            && explicit != "secret"
            && explicit != "grant")
            || (key.eq_ignore_ascii_case("secret") && explicit != "secret")
            || (key.eq_ignore_ascii_case("secret_key") && explicit != "secret")
            || (key.eq_ignore_ascii_case("grant") && explicit != "grant")
            || (key.eq_ignore_ascii_case("code") && explicit != "grant" && explicit != "space")
            || (key.eq_ignore_ascii_case("payload")
                && explicit != "share"
                && explicit != "share-import")
            || (key.eq_ignore_ascii_case("raw") && explicit != "share")
    }

    fn walk(command: &str, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, child) in map {
                    if sensitive_key(command, key) {
                        continue;
                    }
                    out.insert(key.clone(), walk(command, child));
                }
                Value::Object(out)
            }
            Value::Array(values) => Value::Array(values.iter().map(|v| walk(command, v)).collect()),
            other => other.clone(),
        }
    }

    walk(command, value)
}

fn summary_rows(value: &Value) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    flatten_summary("", value, &mut rows, 0);
    rows
}

fn humanize_value(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(text) = json_as_text(trimmed) {
        return text;
    }
    if let Some(text) = known_phrase(trimmed) {
        return text;
    }
    if let Some((total, active)) = split_ends(trimmed, " total / ", " active") {
        return if crate::i18n::lang() == crate::i18n::Lang::Zh {
            format!("总数 {total} / 有效 {active}")
        } else {
            format!("total {total} / active {active}")
        };
    }
    if let Some(rest) = trimmed.strip_prefix("pulled ") {
        if let Some((pulled, pushed)) = rest.split_once(" / pushed ") {
            return if crate::i18n::lang() == crate::i18n::Lang::Zh {
                format!("下载 {pulled} / 上传 {pushed}")
            } else {
                format!("pulled {pulled} / pushed {pushed}")
            };
        }
    }
    if let Some(rest) = trimmed.strip_prefix("send ") {
        let parts: Vec<&str> = rest.split(" / ").collect();
        if parts.len() == 4 {
            let conflicts = parts[1].strip_prefix("conflicts ").unwrap_or(parts[1]);
            let decrypt = parts[2].strip_prefix("decrypt ").unwrap_or(parts[2]);
            let index = parts[3].strip_prefix("index ").unwrap_or(parts[3]);
            return if crate::i18n::lang() == crate::i18n::Lang::Zh {
                format!(
                    "待推送 {} / 冲突 {conflicts} / 解密 {decrypt} / 嵌入 {index}",
                    parts[0]
                )
            } else {
                format!(
                    "send {} / conflicts {conflicts} / decrypt {decrypt} / index {index}",
                    parts[0]
                )
            };
        }
    }
    raw.to_owned()
}

fn split_ends<'a>(text: &'a str, mid: &str, end: &str) -> Option<(&'a str, &'a str)> {
    let text = text.strip_suffix(end)?;
    text.split_once(mid)
}

fn json_as_text(text: &str) -> Option<String> {
    let object = text.starts_with('{') && text.ends_with('}');
    let array = text.starts_with('[') && text.ends_with(']');
    if !object && !array {
        return None;
    }
    let value: Value = serde_json::from_str(text).ok()?;
    Some(compact_human(&value))
}

fn compact_human(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            keys.iter()
                .map(|key| {
                    format!(
                        "{}={}",
                        crate::i18n::field_label(key),
                        scalar_text(&map[*key])
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        }
        Value::Array(items) => items
            .iter()
            .map(compact_human)
            .collect::<Vec<_>>()
            .join("; "),
        other => scalar_text(other),
    }
}

fn known_phrase(text: &str) -> Option<String> {
    let zh = crate::i18n::lang() == crate::i18n::Lang::Zh;
    Some(
        match text {
            "converged" => {
                if zh {
                    "已对齐"
                } else {
                    "converged"
                }
            }
            "not-converged" => {
                if zh {
                    "未对齐"
                } else {
                    "not converged"
                }
            }
            "active-count-diff" => {
                if zh {
                    "有效条数不一致"
                } else {
                    "active count differs"
                }
            }
            "cloud sync (auto)" => {
                if zh {
                    "云同步（自动）"
                } else {
                    "cloud sync (auto)"
                }
            }
            "cloud sync (manual)" => {
                if zh {
                    "云同步（手动）"
                } else {
                    "cloud sync (manual)"
                }
            }
            "local authority store (offline)" => {
                if zh {
                    "本地库（离线）"
                } else {
                    "local store (offline)"
                }
            }
            "reset" => {
                if zh {
                    "已重置"
                } else {
                    "reset"
                }
            }
            "kept" => {
                if zh {
                    "保留"
                } else {
                    "kept"
                }
            }
            "true" => crate::i18n::yes_no(true),
            "false" => crate::i18n::yes_no(false),
            _ => return None,
        }
        .to_owned(),
    )
}

fn flatten_summary(name: &str, value: &Value, rows: &mut Vec<Vec<String>>, depth: usize) {
    match value {
        Value::Object(map) if depth < 2 => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let child = &map[key];
                let next = if name.is_empty() {
                    crate::i18n::field_label(key)
                } else {
                    format!("{name}.{}", crate::i18n::field_label(key))
                };
                flatten_summary(&next, child, rows, depth + 1);
            }
        }
        Value::Array(items) => {
            rows.push(vec![label_or_value(name), items.len().to_string()]);
        }
        other => {
            rows.push(vec![label_or_value(name), compact_human(other)]);
        }
    }
}

fn label_or_value(name: &str) -> String {
    if name.is_empty() {
        "value".to_owned()
    } else {
        name.to_owned()
    }
}

fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(flag) => crate::i18n::yes_no(*flag).to_owned(),
        other => other.to_string(),
    }
}

/// Render a compact, dependency-free table for TTY and redirected text output.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if headers.is_empty() {
        return String::new();
    }
    let rows = rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| {
                    cell.chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mut widths: Vec<usize> = headers.iter().map(|h| UnicodeWidthStr::width(*h)).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate().take(widths.len()) {
            widths[i] = widths[i].max(UnicodeWidthStr::width(cell.as_str()));
        }
    }
    let line = |row: &[String]| {
        row.iter()
            .enumerate()
            .take(widths.len())
            .map(|(i, cell)| {
                format!(
                    "{cell}{}",
                    " ".repeat(widths[i].saturating_sub(UnicodeWidthStr::width(cell.as_str())))
                )
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let head = headers.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let mut out = vec![
        line(&head),
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  "),
    ];
    out.extend(rows.iter().map(|row| line(row)));
    out.join("\n")
}

pub fn status_from_items(items: &[Item]) -> Status {
    if items.iter().any(|i| matches!(i.status, Status::Fail)) {
        Status::Fail
    } else if items
        .iter()
        .any(|i| matches!(i.status, Status::Warn | Status::Pending))
    {
        Status::Warn
    } else {
        Status::Ok
    }
}

pub fn status_label(status: Status) -> &'static str {
    crate::i18n::chrome(match status {
        Status::Ok => "pass",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Skip => "skip",
        Status::Pending => "pending",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_aligned_and_compact() {
        assert_eq!(
            render_table(&["NAME", "STATUS"], &[vec!["store".into(), "PASS".into()]]),
            "NAME   STATUS\n-----  ------\nstore  PASS"
        );
    }

    #[test]
    fn status_prioritizes_fail_then_warn() {
        assert!(matches!(
            status_from_items(&[Item::new("a", Status::Warn, "")]),
            Status::Warn
        ));
        assert!(matches!(
            status_from_items(&[Item::new("a", Status::Fail, "")]),
            Status::Fail
        ));
    }

    #[test]
    fn table_handles_cjk_and_control_characters() {
        let table = render_table(
            &["NAME", "VALUE"],
            &[
                vec!["中文".into(), "one\ntwo".into()],
                vec!["a".into(), "plain".into()],
            ],
        );
        assert!(table.contains("中文  one two"));
        assert!(table.contains("a     plain"));
        assert_eq!(table.lines().count(), 4);
    }

    fn pin_english() -> (std::sync::MutexGuard<'static, ()>, Option<String>) {
        let guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let prev = std::env::var("ONEMEMORY_LANG").ok();
        std::env::set_var("ONEMEMORY_LANG", "en");
        (guard, prev)
    }

    fn restore_lang(prev: Option<String>) {
        match prev {
            Some(value) => std::env::set_var("ONEMEMORY_LANG", value),
            None => std::env::remove_var("ONEMEMORY_LANG"),
        }
    }

    #[test]
    fn explicit_pending_result_is_not_replaced_with_success() -> anyhow::Result<()> {
        let (_lock, prev) = pin_english();
        let result = ResultEnvelope::new(
            "sync-restore",
            Status::Pending,
            serde_json::json!({"pending_sync":true}),
            vec![Item::new("sync", Status::Pending, "queued")],
        );
        let value: Value = serde_json::from_str(&result.render(true)?)?;
        assert_eq!(value["status"], "pending");
        assert!(value["errors"].is_array());
        assert!(value["actions"].is_array());
        let text = result.render(false)?;
        restore_lang(prev);
        assert!(text.contains("RESULT: PENDING"), "{text}");
        Ok(())
    }

    #[test]
    fn text_render_omits_details() -> anyhow::Result<()> {
        let (_lock, prev) = pin_english();
        let mut result = ResultEnvelope::new(
            "doctor",
            Status::Warn,
            serde_json::json!({"pass": 1, "warn": 1}),
            vec![Item::new("session", Status::Warn, "missing")],
        );
        result.details = serde_json::json!({"source":"local"});
        let text = result.render(false)?;
        restore_lang(prev);
        assert!(text.contains("SUMMARY"));
        assert!(text.contains("Pass"));
        assert!(text.contains("1"));
        assert!(!text.contains('{'), "{text}");
        assert!(!text.contains("DETAILS:"));
        assert!(text.contains("RESULT: WARN"), "{text}");
        Ok(())
    }

    #[test]
    fn human_summary_is_a_table_not_json() -> anyhow::Result<()> {
        let (_lock, prev) = pin_english();
        let result = ResultEnvelope::new(
            "sync",
            Status::Warn,
            serde_json::json!({
                "conflicts": 10,
                "local_alive": 3190,
                "converged": true
            }),
            vec![Item::new("state", Status::Warn, "converged")],
        );
        let text = result.render(false)?;
        restore_lang(prev);
        assert!(text.contains("Conflicts"), "{text}");
        assert!(text.contains("3190"), "{text}");
        assert!(text.contains("yes"), "{text}");
        assert!(!text.contains('{'), "{text}");
        assert!(!text.contains('}'), "{text}");
        Ok(())
    }

    #[test]
    fn humanize_covers_json_phrases_and_sync_lines() -> anyhow::Result<()> {
        let (_lock, prev) = pin_english();
        let phrases = [
            "converged",
            "not-converged",
            "active-count-diff",
            "cloud sync (auto)",
            "cloud sync (manual)",
            "local authority store (offline)",
            "reset",
            "kept",
            "true",
            "false",
        ];
        for phrase in phrases {
            anyhow::ensure!(!humanize_value(phrase).is_empty(), "{phrase}");
        }
        anyhow::ensure!(humanize_value("12 total / 3 active").contains("total"));
        anyhow::ensure!(humanize_value("pulled 1 / pushed 2").contains("pushed"));
        anyhow::ensure!(
            humanize_value("send 0 / conflicts 1 / decrypt 2 / index 3").contains("index")
        );
        anyhow::ensure!(humanize_value("plain text") == "plain text");
        anyhow::ensure!(humanize_value("{not json") == "{not json");
        let object = humanize_value(r#"{"conflicts":1,"note":null}"#);
        anyhow::ensure!(
            object.contains("Conflicts") && object.contains("note"),
            "{object}"
        );
        anyhow::ensure!(humanize_value("[1,true]").contains("yes"));
        let nested = summary_rows(&serde_json::json!({"outer":{"inner":{"a":1}},"ids":[1,2]}));
        anyhow::ensure!(
            nested.iter().any(|row| row[0].contains("inner")),
            "{nested:?}"
        );
        anyhow::ensure!(nested.iter().any(|row| row[1] == "2"), "{nested:?}");
        std::env::set_var("ONEMEMORY_LANG", "zh");
        anyhow::ensure!(humanize_value("converged") == "已对齐");
        anyhow::ensure!(humanize_value("12 total / 3 active").contains("总数"));
        anyhow::ensure!(humanize_value("pulled 1 / pushed 2").contains("下载"));
        anyhow::ensure!(
            humanize_value("send 0 / conflicts 1 / decrypt 2 / index 3").contains("待推送")
        );
        anyhow::ensure!(humanize_value("not-converged") == "未对齐");
        anyhow::ensure!(humanize_value("active-count-diff").contains("不一致"));
        anyhow::ensure!(humanize_value("cloud sync (auto)").contains("自动"));
        anyhow::ensure!(humanize_value("cloud sync (manual)").contains("手动"));
        anyhow::ensure!(humanize_value("local authority store (offline)").contains("离线"));
        anyhow::ensure!(humanize_value("reset") == "已重置");
        anyhow::ensure!(humanize_value("kept") == "保留");
        let mut result = ResultEnvelope::new("sync", Status::Ok, serde_json::json!({}), vec![]);
        result.actions.push("reembed".into());
        let text = result.render(false)?;
        anyhow::ensure!(text.contains("动作"), "{text}");
        anyhow::ensure!(!text.contains('{'), "{text}");
        std::env::set_var("ONEMEMORY_LANG", "en");
        let text = result.render(false)?;
        anyhow::ensure!(text.contains("ACTION"), "{text}");
        restore_lang(prev);
        Ok(())
    }

    #[test]
    fn sanitize_details_removes_sealed_storage_and_credentials() {
        let value = serde_json::json!({
            "entry": {
                "id": "id",
                "title": "title",
                "content": "plaintext body",
                "ciphertext": "deadbeef",
                "nonce": "cafebabe",
                "embedding_enc": "0011"
            },
            "token": "access-token",
            "safe": "ok"
        });
        let clean = sanitize_details("show", &value);
        assert_eq!(clean["entry"]["id"], "id");
        assert_eq!(clean["entry"]["content"], "plaintext body");
        assert!(clean["entry"].get("ciphertext").is_none());
        assert!(clean.get("token").is_none());
        assert_eq!(clean["safe"], "ok");

        let secret = sanitize_details(
            "secret",
            &serde_json::json!({
                "secret": "revealed",
                "secret_key": "key"
            }),
        );
        assert_eq!(secret["secret"], "revealed");
        assert_eq!(secret["secret_key"], "key");

        let share = sanitize_details(
            "share",
            &serde_json::json!({
                "payload": "1MEMSHARE1:encoded"
            }),
        );
        assert_eq!(share["payload"], "1MEMSHARE1:encoded");
    }
}
