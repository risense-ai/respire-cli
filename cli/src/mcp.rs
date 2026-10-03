//! MCP server: stdio JSON-RPC and HTTP/SSE helpers used by the authenticated runtime.
//!
//! Tool calls go through the resident runtime (`rpc::query_json`). This process
//! never `spawn`s another `rsrs` to re-invoke the CLI. `current_exe` is only
//! used to copy the native binary into `<data_dir>/bin`. Spec: 2025-03-26.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::rpc;

const PROTOCOL_VERSION: &str = "2025-03-26";
const TOOL_COUNT: usize = 15;

/// Incoming HTTP fields for `/mcp` and `/sse`.
pub struct HttpIn {
    pub method: String,
    pub path: String,
    pub origin: String,
    pub accept: String,
    pub body: String,
}

/// Native daemon directory. Default: `~/.respire/bin` (profile root, not the
/// current account `data_dir()`). Isolation: `ONEMEMORY_DATA_DIR` / `ONEMEMORY_BIN_DIR`.
pub fn bin_dir() -> PathBuf {
    if let Ok(raw) = std::env::var("ONEMEMORY_BIN_DIR") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    respire::service::main_data_dir().join("bin")
}

pub fn stable_bin_path() -> PathBuf {
    let name = if cfg!(windows) { "rsrs.exe" } else { "rsrs" };
    bin_dir().join(name)
}

pub fn mcp_http_url(web_url: &str) -> String {
    format!("{}/mcp", web_url.trim_end_matches('/'))
}

/// Copy this process's native binary to `stable_bin_path()` when missing or stale.
pub fn materialize_bin() -> Result<PathBuf, String> {
    crate::runtime_policy::require_host("runtime binary installation")
        .map_err(|error| error.to_string())?;
    let dest = stable_bin_path();
    let src = std::env::current_exe().map_err(|err| format!("cannot locate this binary: {err}"))?;
    if same_path(&src, &dest) {
        return Ok(dest);
    }
    // cargo test binaries live under target/*/deps. Never overwrite the user
    // ~/.respire/bin with a test harness. Sweep and unit tests isolate data_dir.
    if std::env::var("ONEMEMORY_BIN_DIR")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_none()
        && is_cargo_test_bin(&src)
    {
        return Ok(src);
    }
    if !bin_needs_refresh(&src, &dest)? {
        return Ok(dest);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
    }
    std::fs::copy(&src, &dest)
        .map_err(|err| format!("cannot copy {} -> {}: {err}", src.display(), dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("cannot set execute bit on {}: {err}", dest.display()))?;
    }
    Ok(dest)
}

pub fn exe_matches_dest(exe: &str, dest: &Path) -> bool {
    if exe.trim().is_empty() {
        return false;
    }
    same_path(Path::new(exe), dest)
}

pub fn bin_needs_refresh(src: &Path, dest: &Path) -> Result<bool, String> {
    if !dest.try_exists().map_err(|error| error.to_string())? {
        return Ok(true);
    }
    Ok(file_sha256(src)? != file_sha256(dest)?)
}

fn is_cargo_test_bin(path: &Path) -> bool {
    let text = path.to_string_lossy().replace('\\', "/");
    text.contains("/deps/") || text.contains("/incremental/")
}

fn same_path(a: &Path, b: &Path) -> bool {
    fn canon(path: &Path) -> PathBuf {
        path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
    }
    canon(a) == canon(b)
}

fn file_sha256(path: &Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher.finalize().into())
}

fn tools() -> Vec<(&'static str, &'static str, serde_json::Value)> {
    vec![
        (
            "memory_status",
            "Local store status (data dir, session, counts). Use to check that rsrs is ready.",
            serde_json::json!({"type":"object","properties":{}}),
        ),
        (
            "memory_remember",
            "Store a memory (judge-then-store; --force writes immediately; merge_ids deletes the listed ids)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "content":{"type":"string","description":"Memory body; prefer cause, action, and effect sections"},
                    "title":{"type":"string"},
                    "importance":{"type":"string","enum":["important","trivial"]},
                    "parent":{"type":"string","description":"Parent id or catalog title"},
                    "force":{"type":"boolean"},
                    "merge_ids":{"type":"string","description":"Comma-separated ids to merge into this content"},
                    "type":{"type":"string","description":"Memory kind; default context"}
                },
                "required":["content"]
            }),
        ),
        (
            "memory_recall",
            "Semantic recall (local BGE + keyword fusion, no network)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "query":{"type":"string"},
                    "limit":{"type":"integer","description":"Default 3"}
                },
                "required":["query"]
            }),
        ),
        (
            "memory_list",
            "List recent memories",
            serde_json::json!({
                "type":"object",
                "properties":{"limit":{"type":"integer","description":"Default 10"}}
            }),
        ),
        (
            "memory_show",
            "Show one memory in full (including causal-chain context)",
            serde_json::json!({
                "type":"object",
                "properties":{"id":{"type":"string"}},
                "required":["id"]
            }),
        ),
        (
            "memory_update",
            "Update title/body/tags/kind/importance of an existing memory",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "id":{"type":"string"},
                    "title":{"type":"string"},
                    "content":{"type":"string"},
                    "tags":{"type":"string"},
                    "kind":{"type":"string"},
                    "importance":{"type":"string","enum":["important","trivial"]}
                },
                "required":["id"]
            }),
        ),
        (
            "memory_attach",
            "Attach a child under a parent (explicit reparent)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "id":{"type":"string","description":"Child id"},
                    "parent":{"type":"string"}
                },
                "required":["id","parent"]
            }),
        ),
        (
            "memory_tree",
            "Causal tree: forest / subtree / outline",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "from":{"type":"string"},
                    "outline":{"type":"boolean"},
                    "depth":{"type":"integer"}
                }
            }),
        ),
        (
            "memory_history",
            "Entry change audit (create/update/delete/restore)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "id":{"type":"string"},
                    "limit":{"type":"integer"}
                }
            }),
        ),
        (
            "memory_diary",
            "Diary time chain (trivial zone included)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "limit":{"type":"integer"},
                    "date":{"type":"string"},
                    "from":{"type":"string"},
                    "to":{"type":"string"},
                    "contains":{"type":"string"}
                }
            }),
        ),
        (
            "memory_chain",
            "Causal chain: ancestors + this entry + descendants",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "id":{"type":"string"},
                    "depth":{"type":"integer","description":"Default 3"}
                },
                "required":["id"]
            }),
        ),
        (
            "memory_query_log_mark",
            "Self-grade recall candidates: --good (chosen) or --bad (rejected)",
            serde_json::json!({
                "type":"object",
                "properties":{
                    "ids":{"type":"string","description":"Comma-separated ids; 8-char prefixes ok"},
                    "good":{"type":"boolean"},
                    "bad":{"type":"boolean"}
                },
                "required":["ids"]
            }),
        ),
        (
            "memory_forget",
            "Tombstone a memory (propagates with sync)",
            serde_json::json!({
                "type":"object",
                "properties":{"id":{"type":"string"}},
                "required":["id"]
            }),
        ),
        (
            "memory_restore",
            "Restore a tombstoned memory by full id",
            serde_json::json!({
                "type":"object",
                "properties":{"id":{"type":"string"}},
                "required":["id"]
            }),
        ),
        (
            "memory_taxonomy",
            "List the 23 built-in catalog roots",
            serde_json::json!({"type":"object","properties":{}}),
        ),
    ]
}

fn tool_argv(name: &str, args: &serde_json::Value) -> Result<Vec<String>, String> {
    let opt_str = |key: &str| {
        args.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    };
    let opt_u64 = |key: &str| args.get(key).and_then(|v| v.as_u64());
    let opt_bool = |key: &str| args.get(key).and_then(|v| v.as_bool());
    match name {
        "memory_status" => Ok(vec!["status".to_owned()]),
        "memory_remember" => {
            let content = opt_str("content").ok_or("missing content")?;
            let mut cmd = vec!["remember".to_owned(), content.to_owned()];
            if let Some(title) = opt_str("title") {
                cmd.extend(["--title".to_owned(), title.to_owned()]);
            }
            if let Some(importance) = opt_str("importance") {
                cmd.extend(["--importance".to_owned(), importance.to_owned()]);
            }
            if let Some(parent) = opt_str("parent") {
                cmd.extend(["--parent".to_owned(), parent.to_owned()]);
            }
            if let Some(kind) = opt_str("type") {
                cmd.extend(["--type".to_owned(), kind.to_owned()]);
            }
            if let Some(merge_ids) = opt_str("merge_ids") {
                cmd.extend(["--merge-ids".to_owned(), merge_ids.to_owned()]);
            }
            if opt_bool("force") == Some(true) {
                cmd.push("--force".to_owned());
            }
            Ok(cmd)
        }
        "memory_recall" => {
            let query = opt_str("query").ok_or("missing query")?;
            let mut cmd = vec!["recall".to_owned(), query.to_owned()];
            if let Some(limit) = opt_u64("limit") {
                cmd.extend(["--limit".to_owned(), limit.to_string()]);
            }
            Ok(cmd)
        }
        "memory_list" => {
            let mut cmd = vec!["list".to_owned()];
            cmd.extend([
                "--limit".to_owned(),
                opt_u64("limit").unwrap_or(10).to_string(),
            ]);
            Ok(cmd)
        }
        "memory_show" => {
            let id = opt_str("id").ok_or("missing id")?;
            Ok(vec!["show".to_owned(), id.to_owned()])
        }
        "memory_update" => {
            let id = opt_str("id").ok_or("missing id")?;
            let mut cmd = vec!["update".to_owned(), id.to_owned()];
            if let Some(title) = opt_str("title") {
                cmd.extend(["--title".to_owned(), title.to_owned()]);
            }
            if let Some(content) = opt_str("content") {
                cmd.extend(["--content".to_owned(), content.to_owned()]);
            }
            if let Some(tags) = opt_str("tags") {
                cmd.extend(["--tags".to_owned(), tags.to_owned()]);
            }
            if let Some(kind) = opt_str("kind") {
                cmd.extend(["--kind".to_owned(), kind.to_owned()]);
            }
            if let Some(importance) = opt_str("importance") {
                cmd.extend(["--importance".to_owned(), importance.to_owned()]);
            }
            Ok(cmd)
        }
        "memory_attach" => {
            let id = opt_str("id").ok_or("missing id")?;
            let parent = opt_str("parent").ok_or("missing parent")?;
            Ok(vec![
                "attach".to_owned(),
                id.to_owned(),
                "--parent".to_owned(),
                parent.to_owned(),
            ])
        }
        "memory_tree" => {
            let mut cmd = vec!["tree".to_owned()];
            if let Some(from) = opt_str("from") {
                cmd.extend(["--from".to_owned(), from.to_owned()]);
            }
            if opt_bool("outline") == Some(true) {
                cmd.push("--outline".to_owned());
            }
            if let Some(depth) = opt_u64("depth") {
                cmd.extend(["--depth".to_owned(), depth.to_string()]);
            }
            Ok(cmd)
        }
        "memory_history" => {
            let mut cmd = vec!["history".to_owned()];
            if let Some(id) = opt_str("id") {
                cmd.push(id.to_owned());
            }
            if let Some(limit) = opt_u64("limit") {
                cmd.extend(["--limit".to_owned(), limit.to_string()]);
            }
            Ok(cmd)
        }
        "memory_diary" => {
            let mut cmd = vec!["diary".to_owned()];
            if let Some(limit) = opt_u64("limit") {
                cmd.extend(["--limit".to_owned(), limit.to_string()]);
            }
            if let Some(date) = opt_str("date") {
                cmd.extend(["--date".to_owned(), date.to_owned()]);
            }
            if let Some(from) = opt_str("from") {
                cmd.extend(["--from".to_owned(), from.to_owned()]);
            }
            if let Some(to) = opt_str("to") {
                cmd.extend(["--to".to_owned(), to.to_owned()]);
            }
            if let Some(contains) = opt_str("contains") {
                cmd.extend(["--contains".to_owned(), contains.to_owned()]);
            }
            Ok(cmd)
        }
        "memory_chain" => {
            let id = opt_str("id").ok_or("missing id")?;
            let mut cmd = vec!["chain".to_owned(), id.to_owned()];
            if let Some(depth) = opt_u64("depth") {
                cmd.extend(["--depth".to_owned(), depth.to_string()]);
            }
            Ok(cmd)
        }
        "memory_query_log_mark" => {
            let ids = opt_str("ids").ok_or("missing ids")?;
            let mut cmd = vec!["query-log".to_owned(), "mark".to_owned(), ids.to_owned()];
            match (opt_bool("good"), opt_bool("bad")) {
                (Some(true), Some(true)) => return Err("set only one of good or bad".to_owned()),
                (Some(true), _) => cmd.push("--good".to_owned()),
                (_, Some(true)) => cmd.push("--bad".to_owned()),
                _ => return Err("set good or bad".to_owned()),
            }
            Ok(cmd)
        }
        "memory_forget" => {
            let id = opt_str("id").ok_or("missing id")?;
            Ok(vec!["forget".to_owned(), id.to_owned()])
        }
        "memory_restore" => {
            let id = opt_str("id").ok_or("missing id")?;
            Ok(vec!["restore".to_owned(), id.to_owned()])
        }
        "memory_taxonomy" => Ok(vec!["taxonomy".to_owned(), "--list".to_owned()]),
        other => Err(format!("unknown tool {other}")),
    }
}

fn ensure_envelope(value: &serde_json::Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "CLI output is not a ResultEnvelope object".to_owned())?;
    for key in [
        "command", "status", "summary", "items", "actions", "errors", "details",
    ] {
        if !object.contains_key(key) {
            return Err(format!("CLI output is missing ResultEnvelope field: {key}"));
        }
    }
    let status = object["status"]
        .as_str()
        .ok_or_else(|| "CLI ResultEnvelope status must be a string".to_owned())?;
    if !matches!(status, "ok" | "warn" | "fail" | "skip" | "pending") {
        return Err(format!("CLI ResultEnvelope has invalid status: {status}"));
    }
    if !object["items"].is_array() || !object["actions"].is_array() || !object["errors"].is_array()
    {
        return Err("CLI ResultEnvelope items/actions/errors must be arrays".to_owned());
    }
    Ok(())
}

fn invoke_cli(args: Vec<String>) -> Result<serde_json::Value, String> {
    rpc::query_json(args).map_err(|err| err.to_string())
}

fn call_tool(
    params: &serde_json::Value,
    invoke: &dyn Fn(Vec<String>) -> Result<serde_json::Value, String>,
) -> Result<String, String> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("missing name")?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let argv = tool_argv(name, &arguments)?;
    let envelope = invoke(argv)?;
    ensure_envelope(&envelope)?;
    serde_json::to_string(&envelope)
        .map_err(|err| format!("cannot serialize ResultEnvelope: {err}"))
}

fn initialize_result() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {
            "name": "respire",
            "version": env!("CARGO_PKG_VERSION"),
            "title": "respire"
        }
    })
}

fn tools_list_result() -> serde_json::Value {
    debug_assert_eq!(tools().len(), TOOL_COUNT);
    serde_json::json!({
        "tools": tools().iter().map(|(name, desc, schema)| serde_json::json!({
            "name": name, "description": desc, "inputSchema": schema,
        })).collect::<Vec<_>>()
    })
}

/// Handle one JSON-RPC object. Notifications (no id) return Null.
fn handle_rpc(
    req: &serde_json::Value,
    invoke: &dyn Fn(Vec<String>) -> Result<serde_json::Value, String>,
) -> Option<serde_json::Value> {
    let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
    if req.get("id").is_none() {
        return None;
    }
    let id = req["id"].clone();
    let result = match method {
        "initialize" => initialize_result(),
        "tools/list" => tools_list_result(),
        "tools/call" => match call_tool(&req["params"], invoke) {
            Ok(text) => serde_json::json!({
                "content": [{"type": "text", "text": text}],
                "isError": false
            }),
            Err(err) => serde_json::json!({
                "content": [{"type": "text", "text": format!("tool failed: {err}")}],
                "isError": true
            }),
        },
        "ping" => serde_json::json!({}),
        other => {
            return Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("unknown method {other}")}
            }));
        }
    };
    Some(serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn handle_rpc_live(req: &serde_json::Value) -> Option<serde_json::Value> {
    handle_rpc(req, &invoke_cli)
}

fn encode_sse(event: &str, data: &str) -> Vec<u8> {
    format!("event: {event}\ndata: {data}\n\n").into_bytes()
}

/// HTTP adapter for `/mcp` (Streamable HTTP) and `/sse` (legacy SSE endpoint event).
pub fn http_response(req: HttpIn) -> (u16, &'static str, Vec<u8>) {
    let method = req.method.to_ascii_uppercase();
    let path = req.path.split('?').next().unwrap_or(req.path.as_str());
    let wants_sse = req
        .accept
        .to_ascii_lowercase()
        .contains("text/event-stream");
    if method == "GET" && (path == "/mcp" || path == "/sse") {
        let endpoint = mcp_http_url(&req.origin);
        return (
            200,
            "text/event-stream; charset=utf-8",
            encode_sse("endpoint", &endpoint),
        );
    }
    if method != "POST" || (path != "/mcp" && path != "/sse") {
        return (
            405,
            "text/plain; charset=utf-8",
            b"method not allowed".to_vec(),
        );
    }
    let parsed: serde_json::Value = match serde_json::from_str(req.body.trim()) {
        Ok(value) => value,
        Err(err) => {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error": format!("request body is not JSON: {err}")})
                    .to_string()
                    .into_bytes(),
            );
        }
    };
    let payload = if parsed.is_array() {
        let items: Vec<serde_json::Value> = parsed
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .filter_map(handle_rpc_live)
            .collect();
        serde_json::Value::Array(items)
    } else {
        handle_rpc_live(&parsed).unwrap_or(serde_json::json!({"jsonrpc":"2.0","result":{}}))
    };
    let body = match serde_json::to_vec(&payload) {
        Ok(bytes) => bytes,
        Err(_) => b"{\"error\":\"cannot encode response\"}".to_vec(),
    };
    if wants_sse {
        let data = String::from_utf8_lossy(&body).into_owned();
        return (
            200,
            "text/event-stream; charset=utf-8",
            encode_sse("message", &data),
        );
    }
    (200, "application/json; charset=utf-8", body)
}

/// stdio loop: one JSON-RPC object per line. Exit when stdin closes.
pub fn serve() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(frame) = handle_rpc_live(&req) {
            writeln!(out, "{frame}")?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_ok(args: Vec<String>) -> Result<serde_json::Value, String> {
        Ok(serde_json::json!({
            "command": args.first().cloned().unwrap_or_else(|| "cli".to_owned()),
            "status": "ok",
            "summary": {"ok": true},
            "items": [],
            "actions": [],
            "errors": [],
            "details": {}
        }))
    }

    #[test]
    fn tools_have_unique_names_and_schema() -> Result<(), String> {
        let mut seen = std::collections::HashSet::<String>::new();
        for (name, desc, schema) in tools() {
            if !seen.insert(name.to_string()) {
                return Err(format!("duplicate tool {name}"));
            }
            if desc.is_empty() {
                return Err(format!("empty description for {name}"));
            }
            if schema["type"] != "object" {
                return Err(format!("schema for {name} is not an object"));
            }
        }
        if tools().len() != TOOL_COUNT {
            return Err(format!(
                "expected {TOOL_COUNT} tools, got {}",
                tools().len()
            ));
        }
        Ok(())
    }

    #[test]
    fn source_does_not_reinvoke_cli_binary() -> Result<(), String> {
        let src = include_str!("mcp.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        if prod.contains("spawnSync") || prod.contains("std::process::Command") {
            return Err("production mcp.rs must not spawn a CLI process".to_owned());
        }
        Ok(())
    }

    #[test]
    fn tool_argv_covers_required_fields() -> Result<(), String> {
        if tool_argv("memory_remember", &serde_json::json!({})).is_ok() {
            return Err("remember without content should fail".to_owned());
        }
        if tool_argv("memory_recall", &serde_json::json!({})).is_ok() {
            return Err("recall without query should fail".to_owned());
        }
        if tool_argv("memory_show", &serde_json::json!({})).is_ok() {
            return Err("show without id should fail".to_owned());
        }
        if tool_argv("nope", &serde_json::json!({})).is_ok() {
            return Err("unknown tool should fail".to_owned());
        }
        let remember = tool_argv(
            "memory_remember",
            &serde_json::json!({"content":"x","title":"t","force":true,"parent":"p"}),
        )?;
        if remember[0] != "remember" || !remember.contains(&"--force".to_owned()) {
            return Err(format!("remember argv {remember:?}"));
        }
        let mark = tool_argv(
            "memory_query_log_mark",
            &serde_json::json!({"ids":"abc","good":true}),
        )?;
        if !mark.contains(&"--good".to_owned()) {
            return Err(format!("mark argv {mark:?}"));
        }
        let cases: Vec<(&str, serde_json::Value, &str)> = vec![
            ("memory_status", serde_json::json!({}), "status"),
            (
                "memory_remember",
                serde_json::json!({"content":"c","importance":"important","type":"decision","merge_ids":"a,b"}),
                "remember",
            ),
            (
                "memory_recall",
                serde_json::json!({"query":"q","limit":5}),
                "recall",
            ),
            ("memory_list", serde_json::json!({"limit":2}), "list"),
            ("memory_show", serde_json::json!({"id":"ab"}), "show"),
            (
                "memory_update",
                serde_json::json!({"id":"ab","title":"t","content":"c","tags":"a","kind":"context","importance":"trivial"}),
                "update",
            ),
            (
                "memory_attach",
                serde_json::json!({"id":"c","parent":"p"}),
                "attach",
            ),
            (
                "memory_tree",
                serde_json::json!({"from":"r","outline":true,"depth":2}),
                "tree",
            ),
            (
                "memory_history",
                serde_json::json!({"id":"ab","limit":4}),
                "history",
            ),
            (
                "memory_diary",
                serde_json::json!({"limit":3,"date":"today","from":"a","to":"b","contains":"x"}),
                "diary",
            ),
            (
                "memory_chain",
                serde_json::json!({"id":"ab","depth":1}),
                "chain",
            ),
            (
                "memory_query_log_mark",
                serde_json::json!({"ids":"ab","bad":true}),
                "query-log",
            ),
            ("memory_forget", serde_json::json!({"id":"ab"}), "forget"),
            ("memory_restore", serde_json::json!({"id":"ab"}), "restore"),
            ("memory_taxonomy", serde_json::json!({}), "taxonomy"),
        ];
        for (name, args, first) in cases {
            let argv = tool_argv(name, &args)?;
            if argv.first().map(String::as_str) != Some(first) {
                return Err(format!("{name} argv {argv:?}"));
            }
        }
        if tool_argv(
            "memory_query_log_mark",
            &serde_json::json!({"ids":"ab","good":true,"bad":true}),
        )
        .is_ok()
        {
            return Err("good and bad together should fail".to_owned());
        }
        if tool_argv("memory_query_log_mark", &serde_json::json!({"ids":"ab"})).is_ok() {
            return Err("mark without good/bad should fail".to_owned());
        }
        if tool_argv("memory_attach", &serde_json::json!({"id":"c"})).is_ok() {
            return Err("attach without parent should fail".to_owned());
        }
        Ok(())
    }

    #[test]
    fn handle_rpc_initialize_and_list() -> Result<(), String> {
        let init = handle_rpc(
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
            &fake_ok,
        )
        .ok_or("initialize should reply")?;
        if init["result"]["protocolVersion"] != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_owned());
        }
        let listed = handle_rpc(
            &serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            &fake_ok,
        )
        .ok_or("tools/list should reply")?;
        let tools = listed["result"]["tools"]
            .as_array()
            .ok_or("tools array missing")?;
        if tools.len() != TOOL_COUNT {
            return Err(format!("tools/list returned {}", tools.len()));
        }
        let notify = handle_rpc(
            &serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &fake_ok,
        );
        if notify.is_some() {
            return Err("notification must not reply".to_owned());
        }
        let unknown = handle_rpc(
            &serde_json::json!({"jsonrpc":"2.0","id":3,"method":"nope"}),
            &fake_ok,
        )
        .ok_or("unknown method should reply")?;
        if unknown["error"]["code"] != -32601 {
            return Err("unknown method should be -32601".to_owned());
        }
        Ok(())
    }

    #[test]
    fn tools_call_returns_envelope_even_when_status_fail() -> Result<(), String> {
        let invoke = |args: Vec<String>| {
            Ok(serde_json::json!({
                "command": args.first().cloned().unwrap_or_else(|| "remember".to_owned()),
                "status": "fail",
                "summary": {"dropped": 0},
                "items": [],
                "actions": ["remember --force"],
                "errors": ["similar"],
                "details": {}
            }))
        };
        let frame = handle_rpc(
            &serde_json::json!({
                "jsonrpc":"2.0","id":9,"method":"tools/call",
                "params":{"name":"memory_remember","arguments":{"content":"x","force":true}}
            }),
            &invoke,
        )
        .ok_or("tools/call should reply")?;
        if frame["result"]["isError"] != false {
            return Err("judge-then-store fail must not set isError".to_owned());
        }
        Ok(())
    }

    #[test]
    fn http_get_sse_endpoint_and_post_json() -> Result<(), String> {
        let get = http_response(HttpIn {
            method: "GET".into(),
            path: "/sse".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "text/event-stream".into(),
            body: String::new(),
        });
        if get.0 != 200 || !get.1.contains("event-stream") {
            return Err("GET /sse should be 200 event-stream".to_owned());
        }
        let text = String::from_utf8_lossy(&get.2);
        if !text.contains("http://127.0.0.1:15169/mcp") {
            return Err(format!("sse endpoint missing: {text}"));
        }
        let post = http_response(HttpIn {
            method: "POST".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "application/json".into(),
            body: r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.into(),
        });
        if post.0 != 200 || !post.1.contains("json") {
            return Err("POST /mcp ping should be JSON".to_owned());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&post.2).map_err(|err| err.to_string())?;
        if value["id"] != 1 {
            return Err("ping id mismatch".to_owned());
        }
        let bad = http_response(HttpIn {
            method: "POST".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "application/json".into(),
            body: "not-json".into(),
        });
        if bad.0 != 400 {
            return Err("bad JSON should be 400".to_owned());
        }
        let deny = http_response(HttpIn {
            method: "PUT".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "*/*".into(),
            body: String::new(),
        });
        if deny.0 != 405 {
            return Err("PUT should be 405".to_owned());
        }
        let sse_post = http_response(HttpIn {
            method: "POST".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "text/event-stream".into(),
            body: r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.into(),
        });
        if sse_post.0 != 200 || !sse_post.1.contains("event-stream") {
            return Err("POST /mcp with SSE accept should stream".to_owned());
        }
        let sse_text = String::from_utf8_lossy(&sse_post.2);
        if !sse_text.contains("event: message") {
            return Err(format!("missing SSE message event: {sse_text}"));
        }
        let get_mcp = http_response(HttpIn {
            method: "GET".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "text/event-stream".into(),
            body: String::new(),
        });
        if get_mcp.0 != 200 {
            return Err("GET /mcp should be 200".to_owned());
        }
        let batch = http_response(HttpIn {
            method: "POST".into(),
            path: "/mcp".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "application/json".into(),
            body: r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]"#.into(),
        });
        if batch.0 != 200 {
            return Err("batch POST should be 200".to_owned());
        }
        let batch_value: serde_json::Value =
            serde_json::from_slice(&batch.2).map_err(|err| err.to_string())?;
        if !batch_value.is_array() {
            return Err("batch response should be an array".to_owned());
        }
        let sse_post_alias = http_response(HttpIn {
            method: "POST".into(),
            path: "/sse".into(),
            origin: "http://127.0.0.1:15169".into(),
            accept: "application/json".into(),
            body: r#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#.into(),
        });
        if sse_post_alias.0 != 200 {
            return Err("POST /sse should accept JSON-RPC".to_owned());
        }
        Ok(())
    }

    #[test]
    fn exe_matches_dest_rejects_empty() -> Result<(), String> {
        let dest = std::path::PathBuf::from("C:/x/rsrs.exe");
        if exe_matches_dest("", &dest) {
            return Err("empty exe should not match".into());
        }
        Ok(())
    }

    #[test]
    fn default_bin_dir_is_under_data_dir() -> Result<(), String> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let prev_data = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let prev_bin = std::env::var("ONEMEMORY_BIN_DIR").ok();
        std::env::remove_var("ONEMEMORY_BIN_DIR");
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        let got = bin_dir();
        let want = dir.path().join("bin");
        let restore = || {
            match prev_data {
                Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value),
                None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
            }
            match prev_bin {
                Some(value) => std::env::set_var("ONEMEMORY_BIN_DIR", value),
                None => std::env::remove_var("ONEMEMORY_BIN_DIR"),
            }
        };
        if got != want {
            restore();
            return Err(format!("bin_dir {} != {}", got.display(), want.display()));
        }
        restore();
        Ok(())
    }

    #[test]
    fn materialize_bin_honors_override_dir() -> Result<(), String> {
        static BIN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = BIN_LOCK.lock().unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let prev = std::env::var("ONEMEMORY_BIN_DIR").ok();
        std::env::set_var("ONEMEMORY_BIN_DIR", dir.path());
        let path = materialize_bin()?;
        if !path.starts_with(dir.path()) {
            if let Some(value) = prev {
                std::env::set_var("ONEMEMORY_BIN_DIR", value);
            } else {
                std::env::remove_var("ONEMEMORY_BIN_DIR");
            }
            return Err(format!("bin path {} not under override", path.display()));
        }
        if !path.exists() {
            if let Some(value) = prev {
                std::env::set_var("ONEMEMORY_BIN_DIR", value);
            } else {
                std::env::remove_var("ONEMEMORY_BIN_DIR");
            }
            return Err("materialized bin missing".to_owned());
        }
        let again = materialize_bin()?;
        if again != path {
            if let Some(value) = prev {
                std::env::set_var("ONEMEMORY_BIN_DIR", value);
            } else {
                std::env::remove_var("ONEMEMORY_BIN_DIR");
            }
            return Err("second materialize changed path".to_owned());
        }
        if let Some(value) = prev {
            std::env::set_var("ONEMEMORY_BIN_DIR", value);
        } else {
            std::env::remove_var("ONEMEMORY_BIN_DIR");
        }
        Ok(())
    }

    #[test]
    fn ensure_envelope_rejects_legacy() -> Result<(), String> {
        if ensure_envelope(&serde_json::json!({"ok":true})).is_ok() {
            return Err("legacy object should fail".to_owned());
        }
        ensure_envelope(&serde_json::json!({
            "command":"status","status":"ok","summary":{},"items":[],"actions":[],"errors":[],"details":{}
        }))
        .map_err(|err| err)?;
        Ok(())
    }
}
