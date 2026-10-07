//! CLI display language. `client.json` key `lang` is `zh` or `en`.
//! Machine JSON keeps English field names; only human chrome is translated.

use std::path::PathBuf;

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

pub fn lang() -> Lang {
    if let Ok(raw) = respire::env::var("RSRS_LANG") {
        if let Some(lang) = parse_lang(&raw) {
            return lang;
        }
    }
    read_lang_file().unwrap_or(Lang::En)
}

pub fn parse_lang(raw: &str) -> Option<Lang> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "zh" | "zh-cn" | "cn" | "chinese" => Some(Lang::Zh),
        "en" | "en-us" | "english" => Some(Lang::En),
        _ => None,
    }
}

pub fn set_lang(lang: Lang) -> anyhow::Result<()> {
    let path = client_config_path();
    let mut data = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let obj = data
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("client.json is not an object"))?;
    obj.insert(
        "lang".to_owned(),
        Value::String(match lang {
            Lang::Zh => "zh",
            Lang::En => "en",
        }.to_owned()),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

pub fn chrome(key: &str) -> &'static str {
    chrome_for(lang(), key)
}

/// Human label for a summary or table field. Unknown keys keep their words, with underscores turned into spaces.
pub fn field_label(key: &str) -> String {
    if let Some(label) = known_field(lang(), key) {
        return label.to_owned();
    }
    key.replace('_', " ")
}

fn known_field(lang: Lang, key: &str) -> Option<&'static str> {
    let zh = matches!(lang, Lang::Zh);
    Some(match key {
        "conflict_history" => {
            if zh {
                "冲突历史"
            } else {
                "Conflict history"
            }
        }
        "conflicts" => {
            if zh {
                "冲突"
            } else {
                "Conflicts"
            }
        }
        "converged" => {
            if zh {
                "已对齐"
            } else {
                "Converged"
            }
        }
        "historical_conflicts" => {
            if zh {
                "历史冲突"
            } else {
                "Historical conflicts"
            }
        }
        "index_pending" => {
            if zh {
                "待嵌入"
            } else {
                "Index pending"
            }
        }
        "local_alive" => {
            if zh {
                "本地有效"
            } else {
                "Local active"
            }
        }
        "local_total" => {
            if zh {
                "本地总数"
            } else {
                "Local total"
            }
        }
        "pending" => {
            if zh {
                "待推送"
            } else {
                "Pending"
            }
        }
        "processed_conflicts" => {
            if zh {
                "已处理冲突"
            } else {
                "Processed conflicts"
            }
        }
        "protocol" => {
            if zh {
                "协议"
            } else {
                "Protocol"
            }
        }
        "pulled" => {
            if zh {
                "下载"
            } else {
                "Pulled"
            }
        }
        "purged" => {
            if zh {
                "已清除"
            } else {
                "Purged"
            }
        }
        "pushed" => {
            if zh {
                "上传"
            } else {
                "Pushed"
            }
        }
        "remote_alive" => {
            if zh {
                "云端有效"
            } else {
                "Remote active"
            }
        }
        "remote_total" => {
            if zh {
                "云端总数"
            } else {
                "Remote total"
            }
        }
        "resolution_supported" => {
            if zh {
                "可解决冲突"
            } else {
                "Resolution supported"
            }
        }
        "resolving_conflicts" => {
            if zh {
                "解决中"
            } else {
                "Resolving"
            }
        }
        "total_matched" => {
            if zh {
                "总数一致"
            } else {
                "Totals match"
            }
        }
        "undecodable" => {
            if zh {
                "无法解码"
            } else {
                "Undecodable"
            }
        }
        "remote" => {
            if zh {
                "云端"
            } else {
                "Remote"
            }
        }
        "local" => {
            if zh {
                "本地"
            } else {
                "Local"
            }
        }
        "changes" => {
            if zh {
                "变更"
            } else {
                "Changes"
            }
        }
        "state" => {
            if zh {
                "状态"
            } else {
                "State"
            }
        }
        "user" => {
            if zh {
                "用户"
            } else {
                "User"
            }
        }
        "server" | "server_addr" | "addr" => {
            if zh {
                "服务器"
            } else {
                "Server"
            }
        }
        "mode" => {
            if zh {
                "模式"
            } else {
                "Mode"
            }
        }
        "memories" => {
            if zh {
                "记忆"
            } else {
                "Memories"
            }
        }
        "max_updated_at" => {
            if zh {
                "最近更新"
            } else {
                "Last update"
            }
        }
        "remote_configured" => {
            if zh {
                "已配置远程"
            } else {
                "Remote configured"
            }
        }
        "autosync" => {
            if zh {
                "自动同步"
            } else {
                "Auto-sync"
            }
        }
        "workspace" => {
            if zh {
                "工作区"
            } else {
                "Workspace"
            }
        }
        "pass" => {
            if zh {
                "通过数"
            } else {
                "Pass"
            }
        }
        "warn" => {
            if zh {
                "警告数"
            } else {
                "Warn"
            }
        }
        "reembedded" => {
            if zh {
                "已重嵌入"
            } else {
                "Re-embedded"
            }
        }
        "dimensions" => {
            if zh {
                "维度"
            } else {
                "Dimensions"
            }
        }
        _ => return None,
    })
}

pub fn yes_no(flag: bool) -> &'static str {
    match (lang(), flag) {
        (Lang::Zh, true) => "是",
        (Lang::Zh, false) => "否",
        (_, true) => "yes",
        (_, false) => "no",
    }
}

pub fn chrome_for(lang: Lang, key: &str) -> &'static str {
    match (lang, key) {
        (Lang::Zh, "summary") => "摘要",
        (Lang::Zh, "result") => "结果",
        (Lang::Zh, "item") => "项",
        (Lang::Zh, "status") => "状态",
        (Lang::Zh, "value") => "值",
        (Lang::Zh, "action") => "动作",
        (Lang::Zh, "pass") => "通过",
        (Lang::Zh, "warn") => "警告",
        (Lang::Zh, "fail") => "失败",
        (Lang::Zh, "skip") => "跳过",
        (Lang::Zh, "pending") => "等待",
        (_, "summary") => "SUMMARY",
        (_, "result") => "RESULT",
        (_, "item") => "ITEM",
        (_, "status") => "STATUS",
        (_, "value") => "VALUE",
        (_, "action") => "ACTION",
        (_, "pass") => "PASS",
        (_, "warn") => "WARN",
        (_, "fail") => "FAIL",
        (_, "skip") => "SKIP",
        (_, "pending") => "PENDING",
        _ => "?",
    }
}

pub fn text(key: &str) -> &'static str {
    match (lang(), key) {
        (Lang::Zh, "need_tty") => {
            "无参数启动需要终端。查看状态请运行 rsrs status。"
        }
        (_, "need_tty") => "A terminal is required when no command is given. Use `rsrs status`.",
        (Lang::Zh, "direct") => "警告：--direct 绕过本机 runtime，直接打开本地库。",
        (_, "direct") => "WARN: --direct bypasses the local runtime and opens the library itself.",
        (Lang::Zh, "web_down") => "本机 runtime 没有在运行。",
        (_, "web_down") => "The local runtime is not running.",
        (Lang::Zh, "busy") => "有长任务在运行，status 先返回。",
        (_, "busy") => "A long task is running; status returns without waiting.",
        _ => "",
    }
}

fn read_lang_file() -> Option<Lang> {
    let text = std::fs::read_to_string(client_config_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    parse_lang(data.get("lang")?.as_str()?)
}

/// Same path rule as app-core: `RSRS_DATA_DIR/client.json`, else `~/.rsrs/client.json`.
pub fn client_config_path() -> PathBuf {
    if let Some(root) = respire::service::env_root_dir() {
        return root.join("client.json");
    }
    respire::service::home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
        .join("client.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        crate::TEST_ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn chinese_chrome_is_translated() {
        for (key, zh, en) in [
            ("summary", "摘要", "SUMMARY"),
            ("result", "结果", "RESULT"),
            ("item", "项", "ITEM"),
            ("status", "状态", "STATUS"),
            ("value", "值", "VALUE"),
            ("action", "动作", "ACTION"),
            ("pass", "通过", "PASS"),
            ("warn", "警告", "WARN"),
            ("fail", "失败", "FAIL"),
            ("skip", "跳过", "SKIP"),
            ("pending", "等待", "PENDING"),
        ] {
            assert_eq!(chrome_for(Lang::Zh, key), zh);
            assert_eq!(chrome_for(Lang::En, key), en);
        }
        assert_eq!(chrome_for(Lang::En, "missing"), "?");
    }

    #[test]
    fn field_labels_follow_the_configured_language() -> anyhow::Result<()> {
        let _guard = lock_env();
        let prev = respire::env::var("RSRS_LANG").ok();
        let keys = [
            "conflict_history",
            "conflicts",
            "converged",
            "historical_conflicts",
            "index_pending",
            "local_alive",
            "local_total",
            "pending",
            "processed_conflicts",
            "protocol",
            "pulled",
            "purged",
            "pushed",
            "remote_alive",
            "remote_total",
            "resolution_supported",
            "resolving_conflicts",
            "total_matched",
            "undecodable",
            "remote",
            "local",
            "changes",
            "state",
            "user",
            "server",
            "server_addr",
            "addr",
            "mode",
            "memories",
            "max_updated_at",
            "remote_configured",
            "autosync",
            "workspace",
            "pass",
            "warn",
            "reembedded",
            "dimensions",
        ];
        std::env::set_var("RSRS_LANG", "zh");
        for key in keys {
            let label = field_label(key);
            anyhow::ensure!(!label.is_empty() && label != key, "{key} -> {label}");
        }
        anyhow::ensure!(yes_no(true) == "是" && yes_no(false) == "否");
        std::env::set_var("RSRS_LANG", "en");
        for key in keys {
            anyhow::ensure!(!field_label(key).is_empty(), "{key}");
        }
        anyhow::ensure!(field_label("not_a_known_field") == "not a known field");
        anyhow::ensure!(yes_no(true) == "yes" && yes_no(false) == "no");
        match prev {
            Some(value) => std::env::set_var("RSRS_LANG", value),
            None => std::env::remove_var("RSRS_LANG"),
        }
        Ok(())
    }

    #[test]
    fn parse_lang_accepts_aliases() {
        assert_eq!(parse_lang("zh-CN"), Some(Lang::Zh));
        assert_eq!(parse_lang(" chinese "), Some(Lang::Zh));
        assert_eq!(parse_lang("en-US"), Some(Lang::En));
        assert_eq!(parse_lang("fr"), None);
        assert_eq!(parse_lang("  "), None);
    }

    #[test]
    fn lang_file_and_text_follow_isolated_config() -> anyhow::Result<()> {
        let _guard = lock_env();
        let previous_dir = respire::env::var("RSRS_DATA_DIR").ok();
        let previous_lang = respire::env::var("RSRS_LANG").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        std::env::remove_var("RSRS_LANG");
        assert!(client_config_path().starts_with(dir.path()));
        assert_eq!(lang(), Lang::En);
        set_lang(Lang::Zh)?;
        assert_eq!(read_lang_file(), Some(Lang::Zh));
        assert_eq!(lang(), Lang::Zh);
        assert_eq!(chrome("summary"), "摘要");
        assert!(text("need_tty").contains("终端"));
        assert!(text("direct").contains("警告"));
        assert!(text("web_down").contains("没有"));
        assert!(text("busy").contains("长任务"));
        set_lang(Lang::En)?;
        assert_eq!(lang(), Lang::En);
        assert!(text("need_tty").contains("terminal"));
        assert!(text("direct").contains("WARN"));
        assert!(text("web_down").contains("not running"));
        assert!(text("busy").contains("long task"));
        assert!(text("missing").is_empty());
        std::fs::write(client_config_path(), "[]")?;
        assert!(set_lang(Lang::Zh).is_err());
        std::env::set_var("RSRS_LANG", "zh-cn");
        assert_eq!(lang(), Lang::Zh);
        std::env::set_var("RSRS_LANG", "nope");
        assert_eq!(lang(), Lang::En);
        match previous_dir {
            Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
            None => std::env::remove_var("RSRS_DATA_DIR"),
        }
        match previous_lang {
            Some(value) => std::env::set_var("RSRS_LANG", value),
            None => std::env::remove_var("RSRS_LANG"),
        }
        Ok(())
    }
}
