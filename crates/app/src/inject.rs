//! inject — adapter that distributes the memory-injection source (CLI install and the client inject page share this)
//!
//! Embeds docs/respire.md (compile-time include, the only source) into each AI tool's system prompt / memory file.
//! Two modes: cover (the target file IS the source) and block (markers wrap the insert, user content stays).
//! Idempotent: skip when content matches; uninstall supported (strip block, or delete a cover file that is exactly the source).
//!
//! | target | path | mode |
//! |------|------|----|
//! | dsh | ~/.dsh/AGENTS.md | cover |
//! | opencode | ~/.local/share/respire/docs/respire.md (opencode.json instructions reference) | reference |
//! | codex | ~/.codex/AGENTS.md | block |
//! | claude code | ~/.claude/CLAUDE.md | block |
//! | codebuddy | ~/.codebuddy/AGENTS.md | block |
//! | workbuddy | ~/.workbuddy/MEMORY.md (user-level long-term memory, injected each turn as <user_memory>; write a reference block) | ref-block |
//! | grok build | ~/.grok/AGENTS.md | block |
//! | generic fallback | ~/AGENTS.md | block |

use anyhow::{anyhow, Result};
use serde::Serialize;

/// Compile-time include of docs/respire.md (the only source travels with the binary; rebuild after editing).
pub const INSTRUCTIONS_MD: &str = include_str!("../../../docs/respire.md");
pub const INSTRUCTIONS_LITE_MD: &str = include_str!("../../../docs/respire-lite.md");

/// Compile-time include of docs/respire-readonly.md — inject source for **read-only spaces**.
pub const INSTRUCTIONS_READONLY_MD: &str = include_str!("../../../docs/respire-readonly.md");

/// Compile-time include of docs/respire-off.md — inject source for **temporarily off**.
pub const INSTRUCTIONS_OFF_MD: &str = include_str!("../../../docs/respire-off.md");

/// Pick the inject source from local mode: temporarily off (agent.json `memory_off=true`) uses the off edition;
/// a read-only space (agent.json `readonly=true`) uses the read-only edition.
///
/// Why (2026-09-20): team read-only members should only recall; their AI must be told "do not write",
/// or it keeps trying and hits HTTP 403 with no explanation. So the inject source follows the mode.
/// (2026-09-21: personal space can be temporarily off — even recall is forbidden; the AI should just answer.)
pub fn instructions_md() -> &'static str {
    if crate::service::off_mode() {
        INSTRUCTIONS_OFF_MD
    } else if crate::service::readonly_mode() {
        INSTRUCTIONS_READONLY_MD
    } else {
        INSTRUCTIONS_LITE_MD
    }
}

/// Inject-block markers (block mode: bound user content vs injected content).
pub const BLOCK_BEGIN: &str = "<!-- respire:begin -->";
pub const BLOCK_END: &str = "<!-- respire:end -->";
const LEGACY_BLOCK_BEGIN: &str = "<!-- 1memory:begin -->";
const LEGACY_BLOCK_END: &str = "<!-- 1memory:end -->";

/// Path of the inject entity file: Unix `~/.local/share/respire/docs/respire.md`;
/// Windows `%LOCALAPPDATA%\respire\docs\respire.md` (do not force an XDG path).
fn entity_path() -> Result<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let base = dirs::data_local_dir()
            .ok_or_else(|| anyhow!("cannot determine local app data directory"))?;
        Ok(base.join("respire").join("docs").join("respire.md"))
    }
    #[cfg(not(windows))]
    {
        Ok(home()?.join(".local/share/respire/docs/respire.md"))
    }
}

/// Absolute path of the entity file — written into config and inject text (`~` does not expand in Windows cmd or some loaders).
fn entity_abs() -> Result<String> {
    Ok(entity_path()?.to_string_lossy().into_owned())
}

/// Display path (Unix abbreviated as `~/…`).
fn entity_display() -> String {
    let abs = entity_path()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    match dirs::home_dir().and_then(|h| {
        abs.strip_prefix(&h.to_string_lossy().into_owned())
            .map(|r| r.to_owned())
    }) {
        Some(rest) => format!("~{rest}"),
        None => abs,
    }
}

/// Whether a config instructions entry is this inject path (`~` form and absolute form are the same item).
fn same_entry(raw: &str) -> bool {
    expand(raw) == entity_path().unwrap_or_default()
}

/// Inject target list (same order for the client and the CLI).
#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub id: &'static str,
    pub name: &'static str,
    /// Display path (`~` abbreviated; real path via expand)
    pub path: String,
    /// inject | block | reference
    pub mode: &'static str,
    /// Probe: the software looks installed (dir/file exists) — hint only, does not block inject
    pub likely_installed: bool,
    /// State: not injected / injected / stale; manual means the config needs a hand check.
    pub state: &'static str,
}

fn home() -> Result<std::path::PathBuf> {
    dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))
}

fn expand(p: &str) -> std::path::PathBuf {
    if let Some(rest) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    std::path::PathBuf::from(p)
}

/// workbuddy reference block: MEMORY.md is injected each turn as <user_memory> (4000-char cap),
/// Keep explicit mandatory gates below the cap and load the complete policy after the first recall each turn.
fn wb_ref_md(entity: &str) -> String {
    format!(
        r#"## Respire memory workflow

首工具 recall 后、其他工作前，读取本轮完整规则：`{entity}`。摘要不替代全文；只读禁止写入，暂停模式禁止查存；查存失败明确报告，不得绕过用户授权或服务权限。

**三行铁锚**（上下文愈长、工具输出愈多，愈须回读）：**答前必查 ｜ 收尾必存 ｜ 遇障先翻忆**。

Core rules (follow each item):

1. **首工具查闸**：本回合第一次工具调用只能是 `rsrs recall "<项目名+关键词>" --titles --json`，每条用户新消息重置，禁先读码后补查；失败须明确报告。按标题选中后 `show <id> --json` 读全文，空则换 2–3 组词；读库必 JSON，答中说明查询词与命中依据。
2. **遇障查闸**：报错/异常后的下一次工具调用必须是 `rsrs recall "<项目名+组件+症状>" --json`，禁先读码试错；未命中先读现场、立假设、最小验证。两试无进展停手再查；仍无果报告卡点、已试方法、当前假设，每败必录。
3. **判重与挂点硬闸**：候选全文必读，严格改＞并＞挂＞存；禁候选悬空、裸 force、同题平级。important 新条先判 taxonomy，换 2–3 组词树内深搜，再 `tree --from <id> --depth 3 --json` 定最贴切挂点，必带 `--parent`；trivial 日记免挂点。长文修改和合并先持久备份验非空，合并查子孙，改后立即 show 复验。
4. **正文三段（硬）**：正文必以 `【前因】`、`【行为】`、`【后果】` 三标分段——展示层按此切段，无标记则 recall 时整段截断 200 字、看不全。前因＝缘何而起；行为＝做了何事；后果＝成何状态（含验证与教训）。琐事轨迹条免此规。
5. **每回合至少存一条**：过程流水 → `--importance trivial`（日记链）；经验/决策/教训 → `--importance important` 判类挂纲。
6. **存必告**：存了就在答末注明「已存（类型）」；翻旧账用 `rsrs diary --date YYYY-MM-DD`（支持 today/yesterday；区间 `--from/--to`；关键词 `--contains`——日记本=全库时间链，不分主区琐事）。
7. **读忆首看设备**：recall/show/diary 每条皆标 `🖥记录于=<主机/平台>`、`✎改于=<最后改的设备>`。他机之忆只取结论，**命令与路径不得照搬**；标「未知设备（旧数据，勿跨机照搬）」者更须当场核实。存忆时若内容特定于本机（路径/端口/硬件），正文须明写设备名。
8. **禁偷懒**：以上各条皆下限非上限——禁以「条文没写」为由省事、禁取字面最省力之解、禁以「做完了」充作「做到位」；**干活宁慢勿快**——有依赖者必串行（如多图上传有序，逐件传毕验毕再传次件），无关联者方可并行；干活三纲（认真·勤勉·周全 ①–⑫＋反偷懒总则）见全文。
9. **回合三闸**：查闸核首工具 recall、全文与设备、查询证据；存闸核每轮必存、过程和结论归位、一事一条、important 新条 parent，禁「无可存」；障闸核报错下一工具查忆、两试再查与阻塞报告。未通过先补再答；只读/暂停按模式豁免，失败不得伪称已存。
10. **Credential references**: inspect content before writing or sharing. Omit plaintext passwords, API tokens and private keys; record only a safe purpose/location reference. Keep secrets out of recall queries. This is an agent rule, not an automatic CLI scanner.
11. **Task conditions**: include a `【触发】` line with a confirmed date (and time zone if needed) or verifiable prerequisite. Ask if unclear; verify dates and prerequisite evidence when recalling the task, then mention due conditions. This is a conversational check, not automatic validation or a background reminder. Keep `important`/`trivial` importance inputs.
12. **标题与验收**：标题写主语＋动作＋关键结果，改正文同给 `--title`，合并重拟标题；禁降档逃判树。论断锚实据，实际验证相关主路径及失败路径，没跑明说；禁吞错、删失败测试、硬编码凑绿。逐项回对需求，依赖串行、独立读取可并行、委派须自验；禁字面最省力之解，做到位才算完。
"#
    )
}

/// Probe all targets (shown in the UI before inject).
pub fn targets() -> Result<Vec<Target>> {
    let h = home()?;
    let probe = [
        ("dsh", h.join(".dsh").is_dir()),
        ("opencode", h.join(".config/opencode").is_dir()),
        ("codex", h.join(".codex").is_dir()),
        ("claude", h.join(".claude").is_dir()),
        ("codebuddy", h.join(".codebuddy").is_dir()),
        ("workbuddy", h.join(".workbuddy").is_dir()),
        ("kylinbot", h.join(".kylinbot").is_dir()),
        ("pi", h.join(".pi").is_dir()),
        (
            "zigcode",
            h.join(".zcode").is_dir() || h.join(".zigcode").is_dir(),
        ),
        ("deepseek", h.join(".deepseek").is_dir()),
        (
            "qwen",
            h.join(".qwen").is_dir() || h.join(".config/qwen").is_dir(),
        ),
        (
            "doubao",
            h.join(".doubao").is_dir() || h.join(".config/doubao").is_dir(),
        ),
        ("grok", h.join(".grok").is_dir()),
        ("generic", true),
    ];
    let mut out = Vec::new();
    for (id, likely) in probe {
        let name: &'static str;
        let path: String;
        let mode: &'static str;
        match id {
            "dsh" => {
                name = "dsh";
                path = "~/.dsh/AGENTS.md".to_owned();
                mode = "inject";
            }
            "opencode" => {
                name = "opencode";
                path = entity_display();
                mode = "reference";
            }
            "codex" => {
                name = "codex";
                path = "~/.codex/AGENTS.md".to_owned();
                mode = "block";
            }
            "claude" => {
                name = "claude code";
                path = "~/.claude/CLAUDE.md".to_owned();
                mode = "block";
            }
            "codebuddy" => {
                name = "codebuddy";
                path = "~/.codebuddy/AGENTS.md".to_owned();
                mode = "block";
            }
            "workbuddy" => {
                name = "workbuddy";
                path = "~/.workbuddy/MEMORY.md".to_owned();
                mode = "ref-block";
            }
            "pi" => {
                name = "pi agent";
                path = "~/.pi/AGENTS.md".to_owned();
                mode = "block";
            }
            "zigcode" => {
                name = "zig code";
                path = "~/.zcode/AGENTS.md".to_owned();
                mode = "block";
            }
            "deepseek" => {
                name = "deepseek harness";
                path = "~/.deepseek/AGENTS.md".to_owned();
                mode = "block";
            }
            "qwen" => {
                name = "Qwen assistant";
                path = "~/.qwen/AGENTS.md".to_owned();
                mode = "block";
            }
            "doubao" => {
                name = "Doubao office";
                path = "~/.doubao/AGENTS.md".to_owned();
                mode = "block";
            }
            "grok" => {
                name = "grok build";
                path = "~/.grok/AGENTS.md".to_owned();
                mode = "block";
            }
            "kylinbot" => {
                name = "kylinbot";
                path = "~/.kylinbot/workspace/AGENTS.md".to_owned();
                mode = "block";
            }
            _ => {
                name = "generic AGENTS.md";
                path = "~/AGENTS.md".to_owned();
                mode = "block";
            }
        }
        let state = if id == "opencode" {
            opencode_state()?
        } else {
            let state = check_state(expand(&path), mode);
            if mode == "ref-block"
                && state == "fresh"
                && check_state(entity_path()?, "reference") != "fresh"
            {
                "stale"
            } else {
                state
            }
        };
        out.push(Target {
            id,
            name,
            path,
            mode,
            likely_installed: likely,
            state,
        });
    }
    Ok(out)
}

/// Current state: absent (no file) / fresh (up to date) / stale (injected but not current) / none (file exists, not injected).
fn check_state(path: std::path::PathBuf, mode: &str) -> &'static str {
    match std::fs::read_to_string(&path) {
        Err(_) => "absent",
        Ok(text) => match mode {
            // Cover/reference: the target file IS the inject source; compare the whole text
            "inject" | "reference" => {
                if text.trim_end() == instructions_md().trim_end() {
                    "fresh"
                } else {
                    "stale"
                }
            }
            // Block: no markers → not injected; markers present → compare inner content
            _ => {
                if text.contains(LEGACY_BLOCK_BEGIN) || text.contains(LEGACY_BLOCK_END) {
                    return "stale";
                }
                let ref_md = wb_ref_md(&entity_abs().unwrap_or_default());
                let expected = match mode {
                    "ref-block" => ref_md.trim_end(),
                    _ => instructions_md().trim_end(),
                };
                match extract_block(&text) {
                    None => "none",
                    Some(inner) => {
                        if inner == expected.replace("\r\n", "\n") {
                            "fresh"
                        } else {
                            "stale"
                        }
                    }
                }
            }
        },
    }
}

fn extract_block(text: &str) -> Option<String> {
    let start = text.find(BLOCK_BEGIN)? + BLOCK_BEGIN.len();
    let end = text.find(BLOCK_END)?;
    if end < start {
        return None;
    }
    Some(text[start..end].trim().replace("\r\n", "\n"))
}

/// Inject one target. Returns whether a write actually happened.
pub fn inject_one(id: &str) -> Result<bool> {
    match id {
        "dsh" => write_cover(expand("~/.dsh/AGENTS.md")),
        "opencode" => inject_opencode(),
        "codex" => write_block(expand("~/.codex/AGENTS.md")),
        "claude" => write_block(expand("~/.claude/CLAUDE.md")),
        "codebuddy" => write_block(expand("~/.codebuddy/AGENTS.md")),
        "workbuddy" => inject_workbuddy(),
        "pi" => write_block(expand("~/.pi/AGENTS.md")),
        "zigcode" => write_block(expand("~/.zcode/AGENTS.md")),
        "deepseek" => write_block(expand("~/.deepseek/AGENTS.md")),
        "qwen" => write_block(expand("~/.qwen/AGENTS.md")),
        "doubao" => write_block(expand("~/.doubao/AGENTS.md")),
        "grok" => write_block(expand("~/.grok/AGENTS.md")),
        "kylinbot" => write_block(expand("~/.kylinbot/workspace/AGENTS.md")),
        "generic" => write_block(expand("~/AGENTS.md")),
        other => anyhow::bail!("unknown inject target: {other}"),
    }
}

/// Uninstall one target. Returns whether a write actually happened.
pub fn remove_one(id: &str) -> Result<bool> {
    match id {
        "dsh" => remove_cover(expand("~/.dsh/AGENTS.md")),
        "opencode" => remove_opencode(),
        "codex" => remove_block(expand("~/.codex/AGENTS.md")),
        "claude" => remove_block(expand("~/.claude/CLAUDE.md")),
        "codebuddy" => remove_block(expand("~/.codebuddy/AGENTS.md")),
        "workbuddy" => remove_block(expand("~/.workbuddy/MEMORY.md")),
        "pi" => remove_block(expand("~/.pi/AGENTS.md")),
        "zigcode" => remove_block(expand("~/.zcode/AGENTS.md")),
        "deepseek" => remove_block(expand("~/.deepseek/AGENTS.md")),
        "qwen" => remove_block(expand("~/.qwen/AGENTS.md")),
        "doubao" => remove_block(expand("~/.doubao/AGENTS.md")),
        "grok" => remove_block(expand("~/.grok/AGENTS.md")),
        "kylinbot" => remove_block(expand("~/.kylinbot/workspace/AGENTS.md")),
        "generic" => remove_block(expand("~/AGENTS.md")),
        other => anyhow::bail!("unknown inject target: {other}"),
    }
}

// ── cover mode (dsh): target file = inject source ──

fn write_cover(path: std::path::PathBuf) -> Result<bool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Drop a symlink first — fs::write would follow it and overwrite the repo source
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            std::fs::remove_file(&path)?;
        }
    }
    let changed = match std::fs::read_to_string(&path) {
        Ok(old) if old == instructions_md() => false,
        _ => {
            std::fs::write(&path, instructions_md())?;
            true
        }
    };
    Ok(changed)
}

fn remove_cover(path: std::path::PathBuf) -> Result<bool> {
    match std::fs::read_to_string(&path) {
        // Identical to the inject source → treat as a pure inject file and delete it
        Ok(text) if text == instructions_md() || text == INSTRUCTIONS_MD => {
            std::fs::remove_file(&path)?;
            Ok(true)
        }
        // User-owned content → strip the block only
        Ok(_) => remove_block(path),
        Err(_) => Ok(false),
    }
}

// ── reference mode (opencode): entity file + opencode.json instructions ──

fn opencode_state() -> Result<&'static str> {
    let dir = home()?.join(".config/opencode");
    let mut referenced = false;
    for name in ["opencode.json", "opencode.jsonc"] {
        let text = match std::fs::read_to_string(dir.join(name)) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Ok("manual"),
        };
        let cfg: serde_json::Value = match serde_json::from_str(&text) {
            Ok(cfg) => cfg,
            Err(_) => return Ok("manual"),
        };
        // A later jsonc overrides the former only when it declares instructions.
        if let Some(entries) = cfg.get("instructions") {
            referenced = entries.as_array().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.as_str().is_some_and(same_entry))
            });
        }
    }
    if !referenced {
        return Ok("none");
    }
    Ok(check_state(entity_path()?, "reference"))
}

fn inject_opencode() -> Result<bool> {
    let entity = entity_path()?;
    let mut changed = write_cover(entity)?;
    // Both opencode.json and opencode.jsonc are loaded (jsonc later can override instructions) — write both if present
    let dir = home()?.join(".config/opencode");
    for name in ["opencode.json", "opencode.jsonc"] {
        let path = dir.join(name);
        if name.ends_with(".jsonc") && !path.exists() {
            continue;
        }
        changed |= patch_instructions(&path, true)?;
    }
    // oh-my-openagent prompt_append (touch only if the field exists; idempotent)
    let oma = dir.join("oh-my-openagent.json");
    if oma.exists() {
        changed |= patch_prompt_append(&oma, true)?;
    }
    Ok(changed)
}

fn remove_opencode() -> Result<bool> {
    // The entity file is shared by OpenCode and WorkBuddy; uninstall only drops this target's reference.
    let mut changed = false;
    let dir = home()?.join(".config/opencode");
    for name in ["opencode.json", "opencode.jsonc"] {
        let path = dir.join(name);
        if path.exists() {
            changed |= patch_instructions(&path, false)?;
        }
    }
    let oma = dir.join("oh-my-openagent.json");
    if oma.exists() {
        changed |= patch_prompt_append(&oma, false)?;
    }
    Ok(changed)
}

/// Add/remove the inject path in the instructions array; keep other entries (the old impl replaced the whole list and deleted extras; fixed 2026-09-09).
fn patch_instructions(path: &std::path::Path, add: bool) -> Result<bool> {
    let entry_str = entity_abs()?;
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !add {
                return Ok(false);
            }
            let mut obj = serde_json::Map::new();
            obj.insert(
                "$schema".to_owned(),
                serde_json::json!("https://opencode.ai/config.json"),
            );
            obj.insert("instructions".to_owned(), serde_json::json!([entry_str]));
            if let Some(p) = path.parent() {
                std::fs::create_dir_all(p)?;
            }
            std::fs::write(
                path,
                serde_json::to_string_pretty(&serde_json::Value::Object(obj))?,
            )?;
            return Ok(true);
        }
        Err(e) => return Err(anyhow!("failed to read {}: {e}", path.display())),
    };
    let mut cfg: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
        anyhow!("{} parse failed (for jsonc with comments, edit by hand: add/remove {} in the instructions array): {e}", path.display(), entry_str)
    })?;
    let obj = cfg.as_object_mut().ok_or_else(|| {
        anyhow!(
            "{} top-level value is not an object; inspect by hand",
            path.display()
        )
    })?;
    let entry = serde_json::Value::String(entry_str.clone());
    match obj.get_mut("instructions") {
        Some(serde_json::Value::Array(arr)) => {
            // Normalize: `~` form and absolute form are the same item; drop the old form then add the new (no duplicates)
            arr.retain(|x| !x.as_str().is_some_and(same_entry));
            let has = arr.iter().any(|x| x == &entry);
            if add && !has {
                arr.insert(0, entry);
            }
        }
        Some(_) => {
            return Err(anyhow!(
                "{} instructions is not an array; inspect by hand",
                path.display()
            ))
        }
        None if add => {
            obj.insert("instructions".to_owned(), serde_json::json!([entry_str]));
        }
        None => {}
    }
    let new_text = serde_json::to_string_pretty(&cfg)?;
    if new_text == text {
        return Ok(false);
    }
    std::fs::write(path, new_text)?;
    Ok(true)
}

/// Add/remove the inject path in each agent's prompt_append in oh-my-openagent.json (no-op if the field is missing).
fn patch_prompt_append(path: &std::path::Path, add: bool) -> Result<bool> {
    let text = std::fs::read_to_string(path)?;
    let mut cfg: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| anyhow!("{} parse failed: {e}", path.display()))?;
    let abs = entity_abs()?;
    let line = format!("- 记忆铁律（respire）：{abs}");
    let mut changed = 0usize;
    walk_prompt_append(&mut cfg, add, &line, &abs, &mut changed);
    if changed == 0 {
        return Ok(false);
    }
    let new_text = serde_json::to_string_pretty(&cfg)?;
    if new_text == text {
        return Ok(false);
    }
    std::fs::write(path, new_text)?;
    Ok(true)
}

fn walk_prompt_append(
    v: &mut serde_json::Value,
    add: bool,
    line: &str,
    path_ref: &str,
    changed: &mut usize,
) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(s)) = map.get_mut("prompt_append") {
                if add && !s.contains(&path_ref) {
                    if !s.is_empty() && !s.ends_with('\n') {
                        s.push('\n');
                    }
                    s.push_str(line);
                    *changed += 1;
                } else if !add && s.lines().any(|l| l == line) {
                    let kept: Vec<&str> = s.lines().filter(|l| *l != line).collect();
                    *s = kept.join("\n");
                    *changed += 1;
                }
            }
            for (_, child) in map.iter_mut() {
                walk_prompt_append(child, add, line, path_ref, changed);
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr.iter_mut() {
                walk_prompt_append(child, add, line, path_ref, changed);
            }
        }
        _ => {}
    }
}

// ── block mode (codex/claude/codebuddy/generic): markers wrap the insert ──

fn write_block(path: std::path::PathBuf) -> Result<bool> {
    apply_block(&path, false, None)
}

/// Custom block content (workbuddy uses a reference block, not the full text).
fn write_block_with(path: &std::path::Path, content: &str) -> Result<bool> {
    apply_block_with(path, false, None, content)
}

/// workbuddy reference mode: entity file (shared with opencode) + MEMORY.md reference block.
fn inject_workbuddy() -> Result<bool> {
    let mut changed = write_cover(entity_path()?)?;
    let ref_md = wb_ref_md(&entity_abs()?);
    changed |= write_block_with(&expand("~/.workbuddy/MEMORY.md"), &ref_md)?;
    Ok(changed)
}

#[derive(Debug, Serialize)]
pub struct BlockPreview {
    pub path: String,
    pub before: String,
    pub after: String,
    pub revision: String,
    pub changed: bool,
}

fn block_preview(path: &std::path::Path, remove: bool) -> Result<BlockPreview> {
    block_preview_with(path, remove, instructions_md())
}

fn block_preview_with(path: &std::path::Path, remove: bool, content: &str) -> Result<BlockPreview> {
    use sha2::{Digest, Sha256};
    let before = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(anyhow!("failed to read {}: {e}", path.display())),
    };
    let mut bounds = Vec::new();
    for (begin, end_marker) in [
        (BLOCK_BEGIN, BLOCK_END),
        (LEGACY_BLOCK_BEGIN, LEGACY_BLOCK_END),
    ] {
        let starts: Vec<_> = before.match_indices(begin).map(|(i, _)| i).collect();
        let ends: Vec<_> = before.match_indices(end_marker).map(|(i, _)| i).collect();
        match (starts.as_slice(), ends.as_slice()) {
            ([], []) => {}
            ([start], [end]) if start < end => bounds.push((*start, end + end_marker.len())),
            _ => anyhow::bail!(
                "inject markers incomplete or duplicated; fix {} first",
                path.display()
            ),
        }
    }
    bounds.sort_unstable();
    anyhow::ensure!(
        bounds.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "inject markers overlap; fix {} first", path.display()
    );
    let newline = if before
        .find('\n')
        .is_some_and(|i| i > 0 && before.as_bytes()[i - 1] == b'\r')
    {
        "\r\n"
    } else {
        "\n"
    };
    let block = format!(
        "{BLOCK_BEGIN}{newline}{}{newline}{BLOCK_END}",
        content.trim_end()
    );
    let after = if bounds.is_empty() {
        if remove { before.clone() } else {
            let sep = if before.is_empty() {
                String::new()
            } else if before.ends_with("\n\n") {
                String::new()
            } else if before.ends_with('\n') {
                newline.to_owned()
            } else {
                format!("{newline}{newline}")
            };
            format!("{before}{sep}{block}{newline}")
        }
    } else {
        let mut after = String::new();
        let mut cursor = 0;
        for (index, (start, end)) in bounds.iter().copied().enumerate() {
            after.push_str(&before[cursor..start]);
            if index == 0 && !remove { after.push_str(&block); }
            cursor = end;
        }
        after.push_str(&before[cursor..]);
        after
    };
    let revision = hex::encode(Sha256::digest(before.as_bytes()));
    let changed = before != after;
    Ok(BlockPreview {
        path: path.display().to_string(),
        before,
        after,
        revision,
        changed,
    })
}

fn apply_block(path: &std::path::Path, remove: bool, expected: Option<&str>) -> Result<bool> {
    apply_block_with(path, remove, expected, instructions_md())
}

fn apply_block_with(
    path: &std::path::Path,
    remove: bool,
    expected: Option<&str>,
    content: &str,
) -> Result<bool> {
    let preview = block_preview_with(path, remove, content)?;
    if expected.is_some_and(|value| value != preview.revision) {
        anyhow::bail!("target file changed; preview again before applying");
    }
    if !preview.changed {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, preview.after)?;
    Ok(true)
}

/// First desktop preview target: Codex. Reads config only; does not write.
pub fn preview_codex(remove: bool) -> Result<BlockPreview> {
    block_preview(&home()?.join(".codex/AGENTS.md"), remove)
}

pub fn apply_codex(remove: bool, expected: &str) -> Result<bool> {
    apply_block(&home()?.join(".codex/AGENTS.md"), remove, Some(expected))
}

fn remove_block(path: std::path::PathBuf) -> Result<bool> {
    apply_block(&path, true, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_roundtrip_preserves_user_content() -> anyhow::Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("AGENTS.md");
        std::fs::write(&path, "# 用户自有内容\n\n自定义规则。\n")?;
        assert!(write_block(path.clone())?);
        let text = std::fs::read_to_string(&path)?;
        assert!(text.starts_with("# 用户自有内容"));
        assert!(text.contains(BLOCK_BEGIN) && text.contains(BLOCK_END));
        assert!(text.contains("respire"));
        // Idempotent: injecting again must not duplicate
        assert!(!write_block(path.clone())?);
        // Strip the block and restore
        assert!(remove_block(path.clone())?);
        let after = std::fs::read_to_string(&path)?;
        assert_eq!(after.trim(), "# 用户自有内容\n\n自定义规则。");
        assert!(!after.contains("respire"));
        Ok(())
    }

    #[test]
    fn block_replace_updates_stale() -> anyhow::Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("CLAUDE.md");
        std::fs::write(&path, format!(" mine\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\n"))?;
        assert!(write_block(path.clone())?);
        let text = std::fs::read_to_string(&path)?;
        assert!(text.contains("mine"));
        assert!(text.contains("respire"));
        assert!(!text.contains("old\n#"));
        assert_eq!(text.matches(BLOCK_BEGIN).count(), 1);
        for old in [
            format!("mine\n{LEGACY_BLOCK_BEGIN}\nlegacy\n{LEGACY_BLOCK_END}\n"),
            format!("mine\n{LEGACY_BLOCK_BEGIN}\nlegacy\n{LEGACY_BLOCK_END}\nbetween\n{BLOCK_BEGIN}\nold\n{BLOCK_END}\ntail\n"),
        ] {
            std::fs::write(&path, old)?;
            assert_eq!(check_state(path.clone(), "block"), "stale");
            assert!(write_block(path.clone())?);
            let migrated = std::fs::read_to_string(&path)?;
            assert!(migrated.starts_with("mine\n"));
            assert_eq!(migrated.matches(BLOCK_BEGIN).count(), 1);
            assert!(!migrated.contains(LEGACY_BLOCK_BEGIN));
            assert!(!migrated.contains("legacy\n"));
            assert!(!write_block(path.clone())?);
            assert!(remove_block(path.clone())?);
            assert!(!std::fs::read_to_string(&path)?.contains(BLOCK_BEGIN));
        }
        let incomplete = format!("mine\n{LEGACY_BLOCK_BEGIN}\nlegacy\n");
        std::fs::write(&path, &incomplete)?;
        assert!(write_block(path.clone()).is_err());
        assert_eq!(std::fs::read_to_string(&path)?, incomplete);
        Ok(())
    }

    #[test]
    fn cover_remove_keeps_user_file() -> anyhow::Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("AGENTS.md");
        std::fs::write(&path, "自有")?;
        // Not an inject-source file → strip the block only (no-op if none)
        assert!(!remove_cover(path.clone())?);
        assert_eq!(std::fs::read_to_string(&path)?, "自有");
        // Pure inject file → delete the whole file
        std::fs::write(&path, INSTRUCTIONS_MD)?;
        assert!(remove_cover(path.clone())?);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn targets_include_all_thirteen() -> anyhow::Result<()> {
        let ts = targets()?;
        let ids: Vec<_> = ts.iter().map(|t| t.id).collect();
        for want in [
            "dsh",
            "opencode",
            "codex",
            "claude",
            "codebuddy",
            "workbuddy",
            "kylinbot",
            "pi",
            "zigcode",
            "deepseek",
            "qwen",
            "doubao",
            "generic",
        ] {
            assert!(ids.contains(&want), "missing target {want}");
        }
        Ok(())
    }

    /// Reference mode (opencode): the target file is the full inject source — no block markers, still counts as fresh (fixed 2026-09-06).
    #[test]
    fn reference_mode_pure_source_is_fresh() -> anyhow::Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("respire.md");
        std::fs::write(&path, instructions_md())?;
        assert_eq!(check_state(path, "reference"), "fresh");
        Ok(())
    }

    #[test]
    fn cover_mode_stale_when_drifted() -> anyhow::Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("AGENTS.md");
        std::fs::write(&path, format!("{INSTRUCTIONS_MD}\n<!-- 别人加的一行 -->\n"))?;
        assert_eq!(check_state(path, "inject"), "stale");
        Ok(())
    }

    /// opencode instructions: keep other entries, normalize `~` vs absolute, idempotent, uninstall drops only this item.
    #[test]
    fn opencode_instructions_preserve_entries_and_normalize() -> Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("opencode.json");
        std::fs::write(
            &path,
            serde_json::to_string(&serde_json::json!({
                "instructions": ["~/other.md", entity_display()], "model": "x"
            }))?,
        )?;
        let abs = entity_abs()?;
        assert!(patch_instructions(&path, true)?);
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let arr = v["instructions"]
            .as_array()
            .ok_or_else(|| anyhow!("instructions is not an array"))?;
        assert!(
            arr.iter().any(|x| x.as_str() == Some("~/other.md")),
            "other entries were deleted by mistake"
        );
        assert_eq!(
            arr.iter()
                .filter(|x| x.as_str() == Some(abs.as_str()))
                .count(),
            1,
            "normalized form has duplicates"
        );
        assert_eq!(v["model"], "x");
        assert!(!patch_instructions(&path, true)?, "not idempotent");
        assert!(patch_instructions(&path, false)?);
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        assert_eq!(
            v["instructions"]
                .as_array()
                .ok_or_else(|| anyhow!("instructions is not an array"))?
                .len(),
            1
        );
        Ok(())
    }

    /// workbuddy reference block: write without touching user content, idempotent, removable, state is fresh.
    #[test]
    fn workbuddy_ref_block_roundtrip() -> Result<()> {
        let _iso = crate::test_lock::Isolate::new()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("MEMORY.md");
        std::fs::write(&path, "# 长期规则\n\n自有内容\n")?;
        let abs = entity_abs()?;
        let ref_md = wb_ref_md(&abs);
        assert!(write_block_with(&path, &ref_md)?);
        let text = std::fs::read_to_string(&path)?;
        assert!(text.contains("自有内容"));
        assert!(text.contains(&abs), "reference block missing entity path");
        assert_eq!(check_state(path.clone(), "ref-block"), "fresh");
        assert!(!write_block_with(&path, &ref_md)?, "not idempotent");
        assert!(remove_block(path.clone())?);
        let after = std::fs::read_to_string(&path)?;
        assert!(!after.contains(BLOCK_BEGIN) && after.contains("自有内容"));
        Ok(())
    }
}
