//! `rsrs web` - local Web client: host tree-ui (the Tauri desktop frontend) over HTTP,
//! and turn frontend invoke into a `rsrs` CLI child - same shape as the Tauri shell;
//! business truth still lives in the CLI.
//!
//! Design (2026-09-18): the Windows desktop client stalled, so Windows/Linux/macOS all
//! go through `rsrs web`: the browser is the client. API is POST /api/invoke {cmd,args};
//! the server maps commands with the same table as the Tauri shell, forces ONEMEMORY_JSON=1,
//! and returns the last stdout line parsed as JSON. Serial gate matches Tauri: CLI
//! subcommands fight over lock.db, so queue on the server instead of waiting on each other.
//!
//! The tree-ui build in `npm/web-dist` is compiled into this binary (`include_dir`).
//! `rsrs web` does not look on disk and does not need `ONEMEMORY_WEB_DIST`.
//! Refresh the page by rebuilding the CLI after replacing `npm/web-dist`.

use include_dir::{include_dir, Dir};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

static WEB_DIST: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../npm/web-dist");

fn ensure_embedded_frontend() -> Result<(), String> {
    match WEB_DIST.get_file("index.html") {
        Some(file) if !file.contents().is_empty() => Ok(()),
        _ => Err(
            "frontend artifact index.html is not embedded in this binary; rebuild with npm/web-dist present"
                .to_owned(),
        ),
    }
}

/// Read one embedded frontend file. Rejects `..` and absolute paths.
fn read_dist_file(rel: &str) -> Option<Vec<u8>> {
    if rel.is_empty()
        || rel.contains("..")
        || rel.contains('\\')
        || rel.starts_with('/')
        || Path::new(rel).is_absolute()
    {
        return None;
    }
    WEB_DIST.get_file(rel).map(|file| file.contents().to_vec())
}

/// Client-side serial gate kept only for the fallback child path.
static CLI_GATE: Mutex<()> = Mutex::new(());

static IN_PROCESS: std::sync::OnceLock<fn(Vec<String>) -> Result<Value, String>> =
    std::sync::OnceLock::new();

pub(crate) fn install_executor(f: fn(Vec<String>) -> Result<Value, String>) {
    let _ = IN_PROCESS.set(f);
}

fn in_process(args: &[&str]) -> Option<Result<Value, String>> {
    IN_PROCESS
        .get()
        .map(|exec| exec(args.iter().map(|arg| (*arg).to_owned()).collect()))
}

/// Long-task progress table (async jobs): task_id -> progress snapshot.
/// Why: reparents like `causal_reorder` take minutes. A sync HTTP wait would freeze the UI
/// and CLI_GATE would lock every other call (the page would not even refresh).
/// So the request returns a task_id immediately, a background thread runs, the UI polls /api/task?id=.
static TASKS: Mutex<Option<std::collections::HashMap<String, Value>>> = Mutex::new(None);

fn tasks_insert(id: &str, v: Value) {
    let mut g = TASKS.lock().unwrap_or_else(|e| e.into_inner());
    g.get_or_insert_with(std::collections::HashMap::new)
        .insert(id.to_owned(), v);
}

fn tasks_get(id: &str) -> Option<Value> {
    let g = TASKS.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref().and_then(|m| m.get(id).cloned())
}

/// Patch task progress (keep id/kind/started; overwrite status/progress/message...).
fn tasks_patch(id: &str, patch: Value) {
    let mut g = TASKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = g.as_mut() {
        if let Some(entry) = m.get_mut(id) {
            if let (Some(dst), Some(src)) = (entry.as_object_mut(), patch.as_object()) {
                for (k, v) in src {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
    }
}

/// Append one log line to a task (the frontend scrolls this).
fn tasks_log(id: &str, line: &str) {
    let mut g = TASKS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(m) = g.as_mut() {
        if let Some(entry) = m.get_mut(id) {
            if let Some(logs) = entry.get_mut("logs").and_then(|v| v.as_array_mut()) {
                logs.push(json!(line));
                // Keep the last 400 lines so memory cannot grow without bound.
                let n = logs.len();
                if n > 400 {
                    logs.drain(0..n - 400);
                }
            }
        }
    }
}

fn last_nonempty_line(s: &str) -> &str {
    s.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .map(str::trim)
        .unwrap_or("")
}

/// Parse the CLI JSON contract and expose the command payload to the web API.
/// Every child invocation must return a complete ResultEnvelope; legacy bare
/// JSON is rejected so a command migration cannot be hidden by the bridge.
fn parse_cli_envelope(line: &str) -> Result<Value, String> {
    let value: Value = serde_json::from_str(line).map_err(|e| {
        format!(
            "CLI output failed to parse ({e}): {}",
            line.chars().take(200).collect::<String>()
        )
    })?;
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
    match object.get("details") {
        Some(details) if !details.is_null() => Ok(details.clone()),
        _ => Ok(object["summary"].clone()),
    }
}

/// Locate this CLI binary for spawning a child.
///
/// `current_exe()` has two traps (hit 2026-09-20):
/// 1. **The path was deleted/replaced** (a rebuild overwrote the file; the old process still holds a deleted inode)
///    -> the child fails with `No such file or directory (os error 2)`;
/// 2. Under the npm wrapper (cli.js symlink), `current_exe()` may not be the real binary.
/// Fallback chain: current_exe (must still exist and not be deleted) -> ONEMEMORY_CLI ->
/// rsrs on PATH -> /usr/bin/rsrs.
fn resolve_cli_exe() -> Result<std::path::PathBuf, String> {
    // 1. current_exe: only if the path still exists and is not "(deleted)"
    if let Ok(p) = std::env::current_exe() {
        let real = std::fs::canonicalize(&p).unwrap_or_else(|_| p.clone());
        if real.exists() && !real.to_string_lossy().ends_with(" (deleted)") {
            return Ok(real);
        }
    }
    // 2. explicit override
    if let Ok(p) = std::env::var("ONEMEMORY_CLI") {
        let pb = std::path::PathBuf::from(p.trim());
        if pb.exists() {
            return Ok(pb);
        }
    }
    // 3. PATH lookup
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let cand = dir.join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }
    // 4. last resort
    let sys = std::path::PathBuf::from("/usr/bin/rsrs");
    if sys.exists() {
        return Ok(sys);
    }
    Err(
        "cannot locate the rsrs CLI binary (current_exe is stale, PATH has no rsrs) - \
         set ONEMEMORY_CLI to the binary"
            .to_owned(),
    )
}

fn cli_output(args: &[&str]) -> Result<(bool, String, String), String> {
    let exe = resolve_cli_exe()?;
    let out = Command::new(&exe)
        .args(args)
        .env("ONEMEMORY_JSON", "1")
        .output()
        .map_err(|e| format!("failed to start rsrs CLI child ({}): {e}", exe.display()))?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// Run a command inside the runtime when it is up; otherwise fall back to a CLI child.
fn cli(args: &[&str]) -> Result<Value, String> {
    if let Some(result) = in_process(args) {
        return result;
    }
    let _gate = CLI_GATE.lock().unwrap_or_else(|e| e.into_inner());
    let (ok, stdout, stderr) = cli_output(args)?;
    if !ok {
        let msg = last_nonempty_line(&stderr);
        return Err(if msg.is_empty() {
            "command failed".to_owned()
        } else {
            msg.to_owned()
        });
    }
    parse_cli_envelope(last_nonempty_line(&stdout))
}

/// Stream a CLI run: read stderr (progress) and stdout (last-line JSON) line by line, callback each.
/// For async long jobs - stderr progress is what the frontend "scrolls".
fn cli_streaming(
    args: &[String],
    task_id: &str,
    env_extra: &[(&str, &str)],
) -> Result<Value, String> {
    if let Some(exec) = IN_PROCESS.get() {
        tasks_log(task_id, "running");
        return exec(args.to_vec());
    }
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let exe = resolve_cli_exe()?;
    let mut cmd = Command::new(&exe);
    cmd.args(args)
        .env("ONEMEMORY_JSON", "1")
        .env("ONEMEMORY_PROGRESS", "1") // want stderr progress (frontend scroll)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env_extra {
        cmd.env(k, v);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to start CLI child: {e}"))?;

    let stderr = child.stderr.take().ok_or("cannot read stderr")?;
    let stdout = child.stdout.take().ok_or("cannot read stdout")?;

    // stderr line by line -> task log (progress uses \r, so split on \r again)
    let tid = task_id.to_owned();
    let h_err = std::thread::spawn(move || {
        let mut buf = String::new();
        let mut rd = BufReader::new(stderr);
        loop {
            buf.clear();
            match rd.read_line(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    for seg in buf.split('\r') {
                        let line = seg.trim_matches(['\n', '\r', '\x1b']).trim();
                        // Strip ANSI clear-line sequences.
                        let clean: String = line
                            .replace("\x1b[K", "")
                            .chars()
                            .filter(|c| *c != '\x1b')
                            .collect();
                        let clean = clean.trim();
                        if !clean.is_empty() && clean != "[K" {
                            tasks_log(&tid, clean);
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    let out = std::io::read_to_string(stdout).unwrap_or_default();
    let _ = child.wait();
    let _ = h_err.join();

    let last = out
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    parse_cli_envelope(last)
}

/// Async long job: return task_id immediately, run on a background thread; the UI polls /api/task?id=.
fn spawn_task(kind: &str, args: Vec<String>, env_extra: Vec<(String, String)>) -> String {
    let id = format!("t{}", uuid::Uuid::new_v4().simple());
    tasks_insert(
        &id,
        json!({
            "id": id, "kind": kind, "status": "running",
            "started": chrono::Utc::now().to_rfc3339(),
            "logs": [format!("ACTION task started ({kind})")],
            "result": Value::Null,
        }),
    );
    let tid = id.clone();
    std::thread::spawn(move || {
        let env_ref: Vec<(&str, &str)> = env_extra
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        match cli_streaming(&args, &tid, &env_ref) {
            Ok(v) => {
                let summary = summarize_task_result(&v);
                tasks_patch(
                    &tid,
                    json!({ "status": "done", "result": v, "finished": chrono::Utc::now().to_rfc3339() }),
                );
                tasks_log(&tid, &format!("PASS {summary}"));
            }
            Err(e) => {
                tasks_patch(&tid, json!({ "status": "failed", "error": e }));
                tasks_log(&tid, &format!("FAIL {e}"));
            }
        }
    });
    id
}

/// One-line task result summary for the frontend.
fn summarize_task_result(v: &Value) -> String {
    if let Some(applied) = v.get("applied").and_then(|x| x.as_u64()) {
        return format!("reparent done: applied {applied}");
    }
    "done".to_owned()
}

fn opt_str<'a>(a: &'a Value, k: &str) -> Option<&'a str> {
    a.get(k).and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

fn opt_num<T: std::str::FromStr>(a: &Value, k: &str, default: T) -> T {
    a.get(k)
        .and_then(|v| v.as_u64().or_else(|| v.as_f64().map(|f| f as u64)))
        .and_then(|n| n.to_string().parse::<T>().ok())
        .unwrap_or(default)
}

/// Use the application's profile resolver, including explicit data-dir overrides.
fn data_base_dir() -> std::path::PathBuf {
    respire::service::data_dir()
}

/// Light poll: onememory.db mtime in ms - the frontend refreshes the tree when an external AI writes via CLI.
fn db_stamp() -> Result<Value, String> {
    let db = data_base_dir().join("onememory.db");
    let m = std::fs::metadata(&db).map_err(|e| format!("no store file: {e}"))?;
    let t = m.modified().map_err(|e| e.to_string())?;
    let ms = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Ok(json!(ms))
}

/// Rerank-model dir (same order as CLI rerank.rs: user model dir + bge-reranker-base).
fn rerank_model_dir() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("ONEMEMORY_RERANKER_DIR") {
        let p = p.trim();
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    if let Ok(p) = std::env::var("ONEMEMORY_MODEL_DIR") {
        let p = p.trim();
        if !p.is_empty() {
            let b = std::path::PathBuf::from(p);
            if let Some(parent) = b.parent() {
                return parent.join("bge-reranker-base");
            }
        }
    }
    respire::model_install::rerank_target_dir()
}

fn rerank_model_status() -> Result<Value, String> {
    let dir = rerank_model_dir();
    let tok = dir.join("tokenizer.json");
    let onnx_q = dir.join("onnx").join("model_quantized.onnx");
    let onnx_f = dir.join("onnx").join("model.onnx");
    let installed = tok.is_file() && (onnx_q.is_file() || onnx_f.is_file());
    let size_mb = if installed {
        std::fs::metadata(&onnx_q)
            .or_else(|_| std::fs::metadata(&onnx_f))
            .map(|m| m.len() / 1024 / 1024)
            .unwrap_or(0)
    } else {
        0
    };
    Ok(
        json!({ "installed": installed, "dir": dir.to_string_lossy(), "size_mb": size_mb, "optional": true }),
    )
}

/// Install the optional rerank model: run CLI `model install-rerank` synchronously and return.
/// The web UI has no event channel, so progress is not streamed - the frontend shows "installing...".
fn rerank_model_install(a: &Value) -> Result<Value, String> {
    let mut args: Vec<String> = vec!["model".into(), "install-rerank".into()];
    // Custom source first (the only way out when the upstream revision 404s; added 2026-09-20)
    if let Some(s) = opt_str(a, "source") {
        args.push("--source".into());
        args.push(s.to_owned());
    } else if let Some(m) = opt_str(a, "mirror") {
        args.push("--mirror".into());
        args.push(m.to_owned());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match cli(&refs) {
        Ok(v) => Ok(v),
        Err(e) if e.starts_with("CLI output failed to parse") => Ok(json!({ "installed": true })),
        Err(e) => Err(e),
    }
}

/// Enumerate system font families (appearance settings): Linux/BSD uses fc-list, macOS scans font dirs;
/// if neither works, fall back to built-in candidates. Returns { source, fonts }.
fn list_system_fonts() -> Result<Value, String> {
    let mut raw: Vec<String> = Vec::new();
    let mut source = "fallback";
    #[cfg(unix)]
    {
        if let Ok(out) = Command::new("fc-list").args([":", "family"]).output() {
            if out.status.success() {
                source = "fc-list";
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    for part in line.split(',') {
                        raw.push(part.trim().to_owned());
                    }
                }
            }
        }
        // macOS: if fc-list is missing, scan font-dir filenames (better than nothing; real family names need objc, which CLI does not pull in)
        if source == "fallback" {
            for dir in [
                "/System/Library/Fonts",
                "/Library/Fonts",
                "/System/Library/Fonts/Supplemental",
            ] {
                if let Ok(rd) = std::fs::read_dir(dir) {
                    source = "fonts-dir";
                    for entry in rd.flatten() {
                        if let Some(stem) = entry.path().file_stem().and_then(|s| s.to_str()) {
                            raw.push(stem.to_owned());
                        }
                    }
                }
            }
        }
    }
    // Normalize families: drop empty, case-insensitive unique, dictionary order
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<String> = vec!["System default".to_owned()];
    seen.insert("system default".to_lowercase());
    for name in raw {
        let name = name.trim();
        if name.is_empty() || !seen.insert(name.to_lowercase()) {
            continue;
        }
        out.push(name.to_owned());
    }
    out[1..].sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    Ok(json!({ "source": source, "fonts": out }))
}

/// Isolate a runtime ONEMEMORY_ADDR from the displayed address so the UI does not prefill the global client.json / default public URL.
fn overlay_process_addr(mut v: Value) -> Result<Value, String> {
    let config = v
        .as_object_mut()
        .ok_or("CLI config output must be a JSON object")?;
    if let Ok(addr) = std::env::var("ONEMEMORY_ADDR") {
        let addr = addr.trim();
        if !addr.is_empty() {
            config.insert("addr".to_owned(), Value::String(addr.to_owned()));
        }
    }
    Ok(v)
}

/// Command map: same table as client/src-tauri/src/main.rs (change one, change the other).
fn dispatch(cmd: &str, a: &Value) -> Result<Value, String> {
    match cmd {
        "status" => cli(&["status"]),
        "update_check" => cli(&["update-check", "--force"]),
        "db_stamp" => db_stamp(),
        "list" => {
            let limit = opt_num::<usize>(a, "limit", 20);
            cli(&["list", "--limit", &limit.to_string()])
        }
        "search" => {
            let q = a["q"].as_str().ok_or("search missing q")?;
            let limit = opt_num::<usize>(a, "limit", 20);
            let mut args = vec!["recall".to_owned(), q.to_owned(), "--limit".to_owned(), limit.to_string()];
            if let Some(k) = opt_str(a, "kind") {
                args.push("--type".into());
                args.push(k.to_owned());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "show" => cli(&["show", a["id"].as_str().ok_or("show missing id")?]),
        "tree" => {
            let depth = opt_num::<usize>(a, "depth", 3);
            let mut args = vec!["tree".to_owned(), "--depth".to_owned(), depth.to_string()];
            if let Some(f) = opt_str(a, "from") {
                args.push("--from".into());
                args.push(f.to_owned());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "candidates" => cli(&["candidates", a["content"].as_str().ok_or("candidates missing content")?]),
        "create" => {
            let content = a["content"].as_str().ok_or("create missing content")?;
            let mut args: Vec<String> = vec![
                "remember".into(),
                content.to_owned(),
                "--type".into(),
                opt_str(a, "kind").unwrap_or("context").to_owned(),
            ];
            if let Some(t) = opt_str(a, "title") {
                args.extend(["--title".into(), t.to_owned()]);
            }
            if let Some(tg) = opt_str(a, "tags") {
                args.extend(["--tags".into(), tg.to_owned()]);
            }
            if let Some(p) = opt_str(a, "project") {
                args.extend(["--project".into(), p.to_owned()]);
            }
            if let Some(imp) = opt_str(a, "importance") {
                args.extend(["--importance".into(), imp.to_owned()]);
            }
            if let Some(p) = opt_str(a, "parent") {
                args.extend(["--parent".into(), p.to_owned()]);
            }
            if let Some(ids) = a.get("merge_ids").and_then(|v| v.as_array()).filter(|v| !v.is_empty()) {
                let joined = ids.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(",");
                if !joined.is_empty() {
                    args.extend(["--merge-ids".into(), joined]);
                }
            }
            if a.get("force").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--force".into());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "update" => {
            let mut args: Vec<String> = vec!["update".into(), a["id"].as_str().ok_or("update missing id")?.to_owned()];
            for (k, flag) in [("title", "--title"), ("content", "--content"), ("tags", "--tags"), ("kind", "--kind"), ("importance", "--importance")] {
                if let Some(v) = a.get(k).and_then(|v| v.as_str()) {
                    args.extend([flag.to_owned(), v.to_owned()]);
                }
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "delete" => cli(&["forget", a["id"].as_str().ok_or("delete missing id")?]),
        "purge" => cli(&["purge", a["id"].as_str().ok_or("purge missing id")?]),
        "attach" => cli(&["attach", a["id"].as_str().ok_or("attach missing id")?, "--parent", a["parent"].as_str().ok_or("attach missing parent")?]),
        "restore" => cli(&["restore", a["id"].as_str().ok_or("restore missing id")?]),
        "promote" => cli(&["promote", a["id"].as_str().ok_or("promote missing id")?]),
        "demote" => cli(&["demote", a["id"].as_str().ok_or("demote missing id")?]),
        "sync" => cli(&["sync"]),
        "register" => {
            let mut args: Vec<String> = vec!["register".into(), "--user".into(), a["user"].as_str().ok_or("register missing user")?.to_owned(), "--pass".into(), a["pass"].as_str().ok_or("register missing pass")?.to_owned()];
            if let Some(addr) = opt_str(a, "addr") {
                args.extend(["--addr".to_owned(), addr.to_owned()]);
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "login" => {
            let mut args = vec!["login".to_owned(), "--user".into(), a["user"].as_str().ok_or("login missing user")?.to_owned(), "--pass".into(), a["pass"].as_str().ok_or("login missing pass")?.to_owned()];
            if let Some(s) = opt_str(a, "addr") {
                args.extend(["--addr".to_owned(), s.to_owned()]);
            }
            if let Some(s) = opt_str(a, "super_pass").or_else(|| opt_str(a, "superPass")) {
                args.push("--super".into());
                args.push(s.to_owned());
            }
            if let Some(s) = opt_str(a, "secret_key") {
                args.push("--secret-key".into());
                args.push(s.to_owned());
            }
            if a.get("reset_vault").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--reset-vault".into());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "logout" => {
            let full = a.get("full").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut args = vec!["logout"];
            if full {
                args.push("--full");
            }
            cli(&args)
        }
        "keygen" => {
            if a.get("force").and_then(|v| v.as_bool()).unwrap_or(false) {
                cli(&["keygen", "--force"])
            } else {
                cli(&["keygen"])
            }
        }
        "super_reset" => {
            let mut args: Vec<&str> = vec!["super-reset"];
            if let Some(s) = opt_str(a, "super_pass") {
                args.push("--super");
                args.push(s);
            }
            cli(&args)
        }
        "keys_export" => {
            let owned = opt_str(a, "out").map(ToOwned::to_owned);
            let mut args = vec!["keys-export"];
            if let Some(p) = owned.as_deref() {
                args.push("--out");
                args.push(p);
            }
            cli(&args)
        }
        "config_get" => overlay_process_addr(cli(&["config"])?),
        "server_addr_get" => {
            let v = overlay_process_addr(cli(&["config"])?)?;
            let addr = v
                .get("addr")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(respire::service::DEFAULT_SERVER_ADDR);
            Ok(json!({
                "addr": addr,
                "default": respire::service::DEFAULT_SERVER_ADDR,
                "autosync": v.get("autosync").cloned().unwrap_or(json!(true)),
            }))
        }
        "resume_session" => respire::service::resume_session().map_err(|error| format!("{error:#}")),
        "server_addr_set" => cli(&["config", "--addr", a["addr"].as_str().ok_or("server_addr_set missing addr")?]),
        "sync_config_set" => cli(&["config", "--autosync", if a.get("autosync").and_then(|v| v.as_bool()).unwrap_or(true) { "true" } else { "false" }]),
        "cure_config_set" => cli(&["config", "--cure-auto", if a.get("on").and_then(|v| v.as_bool()).unwrap_or(false) { "true" } else { "false" }]),
        "diary_mode_get" => {
            let v = cli(&["agent-config"])?;
            Ok(json!({ "diary_mode": v.get("diary_mode").cloned().unwrap_or(json!("concise")) }))
        }
        "diary_mode_set" => cli(&["agent-config", "--set", &format!("diary_mode={}", a["mode"].as_str().unwrap_or("concise"))]),
        // -- Personal workspace three-state: normal (read/write) | readonly | off (temporarily closed) --
        "workspace_mode_get" => {
            let v = cli(&["agent-config"])?;
            let off = v.get("memory_off").and_then(|x| x.as_bool()).unwrap_or(false);
            let ro = v.get("readonly").and_then(|x| x.as_bool()).unwrap_or(false);
            Ok(json!({ "mode": if off { "off" } else if ro { "readonly" } else { "normal" } }))
        }
        "workspace_mode_set" => {
            let mode = opt_str(a, "mode").ok_or("workspace_mode_set missing mode")?;
            let _applied: bool = match mode {
                "normal" => {
                    cli(&["agent-config", "--set", "memory_off=false"])?;
                    cli(&["agent-config", "--set", "readonly=false"])?;
                    cli(&["agent-config", "--set", "readonly_team=false"])?;
                    true
                }
                "readonly" => {
                    cli(&["agent-config", "--set", "memory_off=false"])?;
                    cli(&["agent-config", "--set", "readonly=true"])?;
                    true
                }
                "off" => {
                    cli(&["agent-config", "--set", "memory_off=true"])?;
                    true
                }
                other => return Err(format!("unknown mode \"{other}\" - choose: normal | readonly | off")),
            };
            // Switching mode re-injects: the inject source follows the mode (normal/readonly/off), so the target files actually change
            cli(&["inject"])?;
            Ok(json!({ "ok": true, "mode": mode }))
        }
        "data_dir_set" => cli(&["config", "--data-dir", a["dir"].as_str().ok_or("data_dir_set missing dir")?]),
        "list_system_fonts" => list_system_fonts(),
        // Subtree material export: 2026-09-21 moved from scope --material to tree --material (local-subtree feature was dropped)
        "scope_material" => cli(&["tree", "--material", a["root"].as_str().ok_or("scope_material missing root")?]),
        // -- Spaces (virtual accounts) --
        "space_list" => cli(&["space", "list"]),
        "space_create" => cli(&["space", "create", a["name"].as_str().ok_or("space_create missing name")?]),
        "space_use" => cli(&["space", "use", a["name"].as_str().ok_or("space_use missing name")?]),
        "space_invite" => {
            let mut args = vec!["space", "invite"];
            if a.get("readonly").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--readonly");
            }
            if let Some(n) = opt_str(a, "note") {
                args.push("--note");
                args.push(n);
            }
            cli(&args)
        }
        "space_join" => cli(&["space", "join", a["code"].as_str().ok_or("space_join missing code")?]),
        "space_members" => match opt_str(a, "name") {
            Some(n) => cli(&["space", "members", n]),
            None => cli(&["space", "members"]),
        },
        "space_kick" => {
            if a.get("all").and_then(|v| v.as_bool()).unwrap_or(false) {
                cli(&["space", "kick", "--all"])
            } else {
                cli(&["space", "kick", "--session", a["session"].as_str().ok_or("space_kick missing session or all")?])
            }
        }
        "space_remove" => {
            if !a.get("yes").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err("deleting a space profile is unrecoverable - explicit confirm required".to_owned());
            }
            cli(&["space", "remove", a["name"].as_str().ok_or("space_remove missing name")?, "--yes"])
        }
        "doctor" => cli(&["doctor"]),
        "rerank_model_status" => rerank_model_status(),
        "rerank_model_install" => rerank_model_install(a),
        "inject_targets" => cli(&["inject", "--targets"]),
        "inject" => match opt_str(a, "id") {
            Some(id) => cli(&["inject", "--id", id]),
            None => cli(&["inject"]),
        },
        "inject_remove" => cli(&["inject", "--remove", "--id", a["id"].as_str().ok_or("inject_remove missing id")?]),
        "inject_preview" => {
            let mut args = vec!["inject", "--id", "codex", "--preview"];
            if a.get("remove").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--remove");
            }
            cli(&args)
        }
        "inject_apply" => {
            let mut args = vec!["inject", "--id", "codex", "--expected", a["revision"].as_str().ok_or("inject_apply missing revision")?];
            if a.get("remove").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--remove");
            }
            cli(&args)
        }
        // Browser mode has no system file dialog (fixed 2026-09-21): the old build returned "unknown command",
        // so export/snapshot/import buttons were dead under rsrs web. Now -
        //    pick_save_file: land in the Downloads dir (timestamped name so we do not overwrite); path is returned for the UI;
        //    pick_open_file / pick_directory: no browser equivalent; return a clear error with a CLI hint.
        "pick_save_file" => {
            let name = opt_str(a, "defaultName").filter(|s| !s.trim().is_empty()).unwrap_or("respire-export.json");
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let (stem, ext) = match name.rsplit_once('.') {
                Some((s, e)) => (s.to_owned(), format!(".{e}")),
                None => (name.to_owned(), String::new()),
            };
            let dir = dirs::download_dir()
                .or_else(dirs::home_dir)
                .ok_or("cannot locate the Downloads dir; use the CLI: rsrs export <path>")?;
            Ok(serde_json::json!(dir.join(format!("{stem}-{ts}{ext}")).to_string_lossy()))
        }
        "pick_open_file" => Err("browser mode cannot open a system file picker; import with CLI: rsrs import <path>".into()),
        "pick_directory" => Err("browser mode cannot open a system directory picker; type the path in the input (or CLI: rsrs config --data-dir <path>)".into()),
        "export_memories" => cli(&["export", a["path"].as_str().ok_or("export missing path")?]),
        "import_memories" => cli(&["import", a["path"].as_str().ok_or("import missing path")?]),
        "backup_db" => cli(&["backup", a["path"].as_str().ok_or("backup missing path")?]),
        "book_material" => cli(&["book-material", a["root"].as_str().ok_or("book_material missing root")?]),
        // Subtree share: emit a prompt another AI can paste (payload is plaintext; root defaults to this machine's scope root)
        "share_subtree" => {
            let mut args: Vec<String> = vec!["share".to_owned()];
            if let Some(r) = opt_str(a, "root").filter(|s| !s.trim().is_empty()) {
                args.push("--root".to_owned());
                args.push(r.to_owned());
            }
            if let Some(o) = opt_str(a, "out").filter(|s| !s.trim().is_empty()) {
                args.push("--out".to_owned());
                args.push(o.to_owned());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        // Share import: without go, print attach-candidate bill (for the AI to pick a hang point); go writes the store
        "share_import" => {
            let mut args: Vec<String> = vec![
                "share-import".to_owned(),
                a["path"].as_str().ok_or("share_import missing path")?.to_owned(),
            ];
            if let Some(p) = opt_str(a, "parent").filter(|s| !s.trim().is_empty()) {
                args.push("--parent".to_owned());
                args.push(p.to_owned());
            }
            if let Some(t) = opt_str(a, "title").filter(|s| !s.trim().is_empty()) {
                args.push("--title".to_owned());
                args.push(t.to_owned());
            }
            if a.get("go").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--go".to_owned());
            }
            if a.get("force").and_then(|v| v.as_bool()).unwrap_or(false) {
                args.push("--force".to_owned());
            }
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli(&refs)
        }
        "portrait_material" => {
            let limit = opt_num::<usize>(a, "limit", 40);
            cli(&["portrait-material", "--limit", &limit.to_string()])
        }
        "tree_cure" => {
            let top = opt_num::<usize>(a, "top", 20);
            cli(&["tree-cure", "--top", &top.to_string()])
        }
        // Causal reparent (GUI "one-click reparent"): **async** long job - return task_id immediately,
        // run in the background, UI polls /api/task (avoids a sync block + CLI_GATE locking the whole site).
        "causal_reorder" => {
            let apply = a.get("apply").and_then(|v| v.as_bool()).unwrap_or(false);
            let rounds = opt_num::<usize>(a, "rounds", 5);
            let min_kids = opt_num::<usize>(a, "min_kids", 3);
            // Backend: GUI dropdown passes jev|ds; default is last choice, then ds (old behavior)
            let backend = opt_str(a, "backend")
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| s == "jev" || s == "ds")
                .or_else(respire::keystore::load_classify_backend)
                .unwrap_or_else(|| "ds".to_owned());
            let mut args: Vec<String> = vec![
                "classify".to_owned(),
                "--backend".to_owned(),
                backend.clone(),
                "--auto".to_owned(),
                "--rounds".to_owned(),
                rounds.to_string(),
                "--min-kids".to_owned(),
                min_kids.to_string(),
            ];
            if !apply {
                args.push("--dry-run".to_owned());
            }
            // Progress goes to stderr (cli_streaming reads it line by line) - so do not pass --json, which would suppress it
            let tid = spawn_task("causal_reorder", args, vec![]);
            Ok(json!({ "task_id": tid, "async": true, "backend": backend }))
        }
        // Emit a reparent plan (GUI "generate plan"): a copyable prompt (merge+causal+demote) the user can paste into another AI
        "causal_plan" => {
            let segments = opt_num::<usize>(a, "segments", 12);
            let seg_s = segments.to_string();
            let mut v = cli(&["classify", "--plan", "--segments", &seg_s])?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("ok".to_owned(), json!(true));
            }
            Ok(v)
        }
        // DS key config status (for the GUI): whether it is set, endpoint, model
        "ds_key_status" => {
            let base = respire::keystore::load_ds_last_base()
                .unwrap_or_else(|| "https://api.deepseek.com/v1".to_owned());
            let host = respire::keystore::host_of(&base);
            let slot = format!("ds@{host}");
            let has = respire::keystore::load_classify_key(&slot).is_some();
            let model = respire::keystore::load_ds_model(&host)
                .unwrap_or_else(|| "deepseek-flash".to_owned());
            // Jev (TypeSafe): key lives in the typesafe keyring slot (GUI), env, or classify.json (CLI hand-config)
            let jev_has = respire::keystore::load_classify_key("typesafe").is_some()
                || std::env::var("TYPESAFE_API_KEY").map(|v| !v.is_empty()).unwrap_or(false)
                || respire::service::data_dir()
                    .join("classify.json")
                    .exists(); // file present counts as configured (content is checked when CLI actually runs)
            Ok(json!({
                "configured": has,
                "base": base,
                "host": host,
                "slot": slot,
                "model": model,
                "env_fallback": std::env::var("DS_API_KEY").map(|v| !v.is_empty()).unwrap_or(false),
                "jev": {
                    "configured": jev_has,
                    "slot": "typesafe",
                    "base": "https://api.typesafe.ai/v1/systemone",
                    "model": "jev-latest",
                },
                "selected": respire::keystore::load_classify_backend().unwrap_or_else(|| "ds".to_owned()),
            }))
        }
        // Save a DS key (GUI config): write the keyring and remember endpoint + model
        "ds_key_save" => {
            let key = opt_str(a, "key").ok_or("ds_key_save missing key")?;
            let backend = opt_str(a, "backend").unwrap_or("ds").to_owned();
            if backend == "jev" {
                // Jev: endpoint/model are fixed; key goes in the typesafe slot
                respire::keystore::save_classify_key("typesafe", key)
                    .map_err(|e| format!("failed to write keyring: {e}"))?;
                respire::keystore::save_classify_backend("jev");
                return Ok(json!({ "ok": true, "slot": "typesafe", "backend": "jev",
                    "base": "https://api.typesafe.ai/v1/systemone", "model": "jev-latest" }));
            }
            let base = opt_str(a, "base")
                .unwrap_or("https://api.deepseek.com/v1")
                .to_owned();
            let model = opt_str(a, "model").unwrap_or("deepseek-flash").to_owned();
            let host = respire::keystore::host_of(&base);
            let slot = format!("ds@{host}");
            respire::keystore::save_classify_key(&slot, key)
                .map_err(|e| format!("failed to write keyring: {e}"))?;
            respire::keystore::save_ds_last_base(&base);
            respire::keystore::save_ds_model(&host, &model);
            respire::keystore::save_classify_backend("ds");
            Ok(json!({ "ok": true, "slot": slot, "base": base, "model": model, "backend": "ds" }))
        }
        // classify backend choice (GUI "AI backend" dropdown): read / remember
        "classify_backend_get" => Ok(json!({
            "backend": respire::keystore::load_classify_backend().unwrap_or_else(|| "ds".to_owned()),
        })),
        "classify_backend_set" => {
            let b = opt_str(a, "backend").ok_or("classify_backend_set missing backend")?;
            let b = b.trim().to_ascii_lowercase();
            if b != "jev" && b != "ds" {
                return Err(format!("unknown backend \"{b}\" - choose: jev | ds"));
            }
            respire::keystore::save_classify_backend(&b);
            Ok(json!({ "ok": true, "backend": b }))
        }
        // Task progress: GET /api/task?id=xxx (the UI polls every 1–2s)
        "task_status" => {
            let id = opt_str(a, "id").ok_or("task_status missing id")?;
            tasks_get(id).ok_or_else(|| format!("no such task: {id}"))
        }
        "defrag" => {
            let min = a.get("min").and_then(|v| v.as_f64()).unwrap_or(0.8);
            let top = opt_num::<usize>(a, "top", 20);
            cli(&["defrag", "--min", &min.to_string(), "--top", &top.to_string()])
        }
        "reembed" => cli(&["reembed"]),
        other => Err(format!("unknown command: {other}")),
    }
}

fn content_type_of(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Handle one request: returns (status, Content-Type, body).
/// Access token when bound off-loopback (process-level, set by `run_web`; None = this machine only, no check).
static ACCESS_TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

fn set_access_token(t: Option<String>) {
    let _ = ACCESS_TOKEN.set(t);
}

/// Token check: required for every request. Headers first; GET may use `?token=`.
fn token_ok(req: &tiny_http::Request, url: &str, method: &tiny_http::Method) -> bool {
    let Some(Some(expected)) = ACCESS_TOKEN.get() else {
        return false;
    };
    // Header first
    for h in req.headers() {
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("X-respire-Token")
        {
            if h.value.as_str() == expected.as_str() {
                return true;
            }
        }
        if h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("Authorization")
        {
            let value = h.value.as_str();
            let token = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "));
            if token == Some(expected.as_str()) {
                return true;
            }
        }
    }
    // Query param only for GET (first page load). POST APIs must use a header.
    if *method == tiny_http::Method::Get {
        if let Some(q) = url.split_once('?').map(|(_, q)| q) {
            for pair in q.split('&') {
                if let Some(v) = pair.strip_prefix("token=") {
                    if v == expected.as_str() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn header_value(req: &tiny_http::Request, name: &str) -> String {
    for header in req.headers() {
        if header.field.as_str().as_str().eq_ignore_ascii_case(name) {
            return header.value.as_str().to_owned();
        }
    }
    String::new()
}

fn request_origin(req: &tiny_http::Request) -> String {
    let host = header_value(req, "Host");
    if host.is_empty() {
        crate::net_rpc::rpc_base_url()
    } else if host.starts_with("http://") || host.starts_with("https://") {
        host
    } else {
        format!("http://{host}")
    }
}

fn mcp_http(
    req: &mut tiny_http::Request,
    method: &tiny_http::Method,
    path: &str,
) -> (u16, &'static str, Vec<u8>) {
    let method_name = match *method {
        tiny_http::Method::Get => "GET",
        tiny_http::Method::Post => "POST",
        _ => "OTHER",
    };
    let mut body = String::new();
    if *method == tiny_http::Method::Post {
        let _ = req.as_reader().read_to_string(&mut body);
    }
    crate::mcp::http_response(crate::mcp::HttpIn {
        method: method_name.to_owned(),
        path: path.to_owned(),
        origin: request_origin(req),
        accept: header_value(req, "Accept"),
        body,
    })
}

fn handle_request(req: &mut tiny_http::Request) -> (u16, &'static str, Vec<u8>) {
    let url = req.url().to_owned();
    let method = req.method().to_owned();

    // Off-loopback binds force a token check (added in the 2026-09-20 audit) -
    // otherwise anyone on the LAN can keys_export the super password and read every plaintext memory.
    if !token_ok(req, &url, &method) {
        return (
            401,
            "application/json; charset=utf-8",
            serde_json::json!({"error":"unauthorized: send Authorization: Bearer or X-respire-Token"}).to_string().into_bytes(),
        );
    }

    let path = url.split('?').next().unwrap_or(url.as_str());
    if method == tiny_http::Method::Post
        && (path.starts_with("/api/") || path == "/mcp" || path == "/sse")
    {
        let origin = header_value(req, "Origin");
        if !crate::net_rpc::origin_ok(&origin, &crate::net_rpc::rpc_base_url()) {
            return (
                403,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"forbidden origin"})
                    .to_string()
                    .into_bytes(),
            );
        }
    }
    if path == "/api/health" && method == tiny_http::Method::Get {
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::to_vec(&crate::rpc::health_body()).unwrap_or_default(),
        );
    }
    if path == "/api/runtime/stop" && method == tiny_http::Method::Post {
        return (
            200,
            "application/json; charset=utf-8",
            serde_json::json!({"ok": true, "server": "respire"})
                .to_string()
                .into_bytes(),
        );
    }
    if path == "/api/rpc" && method == tiny_http::Method::Post {
        let mut body = String::new();
        if req.as_reader().read_to_string(&mut body).is_err() {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"request body unreadable"})
                    .to_string()
                    .into_bytes(),
            );
        }
        return match crate::rpc::handle_http_rpc(body.as_bytes()) {
            Ok(response) => (
                200,
                "application/json; charset=utf-8",
                serde_json::to_vec(&response).unwrap_or_default(),
            ),
            Err(error) => (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error": error.to_string()})
                    .to_string()
                    .into_bytes(),
            ),
        };
    }
    if path == "/mcp" || path == "/sse" {
        return mcp_http(req, &method, path);
    }

    if method == tiny_http::Method::Post
        && (url == "/api/invoke" || url.starts_with("/api/invoke?"))
    {
        let mut body = String::new();
        if req.as_reader().read_to_string(&mut body).is_err() {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"request body unreadable"})
                    .to_string()
                    .into_bytes(),
            );
        }
        let parsed: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                return (
                    400,
                    "application/json; charset=utf-8",
                    serde_json::json!({"error": format!("request body is not JSON: {e}")})
                        .to_string()
                        .into_bytes(),
                )
            }
        };
        let cmd = parsed.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
        let args = parsed.get("args").cloned().unwrap_or(json!({}));
        if cmd.is_empty() {
            return (
                400,
                "application/json; charset=utf-8",
                serde_json::json!({"error":"missing cmd"})
                    .to_string()
                    .into_bytes(),
            );
        }
        match dispatch(cmd, &args) {
            Ok(v) => (
                200,
                "application/json; charset=utf-8",
                serde_json::to_vec(&v).unwrap_or_default(),
            ),
            Err(e) => (
                500,
                "application/json; charset=utf-8",
                serde_json::to_vec(&json!({ "error": e })).unwrap_or_default(),
            ),
        }
    } else if method == tiny_http::Method::Get {
        // Static files: / -> index.html; /brand/... /fonts/... from the dist dir
        let path = url.split('?').next().unwrap_or("/");
        let path = path.trim_start_matches('/');
        let path = if path.is_empty() { "index.html" } else { path };
        // No path traversal: read_dist_file rejects .. and absolute paths
        match read_dist_file(path) {
            Some(bytes) => (200, content_type_of(path), bytes),
            None => match read_dist_file("index.html") {
                // SPA fallback: unknown paths return index (the frontend has no router besides /; this only covers typos outside brand)
                Some(bytes) if path.starts_with("assets/") => {
                    (200, content_type_of("index.html"), bytes)
                }
                Some(bytes) if path != "index.html" && !path.contains('.') => {
                    (200, content_type_of("index.html"), bytes)
                }
                _ => (
                    404,
                    "text/plain; charset=utf-8",
                    format!("404: {path}").into_bytes(),
                ),
            },
        }
    } else {
        (
            405,
            "text/plain; charset=utf-8",
            b"method not allowed".to_vec(),
        )
    }
}

pub(crate) fn open_browser(url: &str) {
    let (program, args): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("open", &[url])
    } else if cfg!(windows) {
        ("cmd", &["/C", "start", "", url])
    } else {
        ("xdg-open", &[url])
    };
    // L9 (2026-09-20 audit): a silent fail showed "started" with no window and no why.
    if let Err(e) = Command::new(program).args(args).spawn() {
        eprintln!("WARN could not open a browser ({e}) - visit the URL above by hand");
    }
}

/// `rsrs web` entry: start a local server hosting the GUI. Default bind is 127.0.0.1, not public.
///
/// **Security (fixed 2026-09-20 audit)**: `--host` can bind off-loopback (LAN share),
/// but `/api/invoke` had no auth - binding 0.0.0.0 opened plaintext memories and the super password to anyone on the LAN.
/// Now: off-loopback **always mints a random access token**; `/api/invoke` needs `?token=` or
/// `X-respire-Token`, else 401. Startup text prints the real host (it used to hard-code
/// "this machine only", which was a lie).
pub(crate) struct BoundWeb {
    pub server: tiny_http::Server,
    pub url: String,
}

pub(crate) fn bind_error_is_in_use(error: &anyhow::Error) -> bool {
    let text = format!("{error:#}").to_ascii_lowercase();
    text.contains("in use")
        || text.contains("addrinuse")
        || text.contains("only one usage")
        || text.contains("already")
}

pub(crate) fn bind_web(port: Option<u16>, host: &str) -> anyhow::Result<BoundWeb> {
    ensure_embedded_frontend().map_err(|err| anyhow::anyhow!(err))?;
    let actual = port.unwrap_or_else(crate::net_rpc::rpc_port);
    let access_token = crate::net_rpc::load_or_create_token()?;
    set_access_token(Some(access_token.clone()));
    let server = tiny_http::Server::http((host, actual))
        .map_err(|error| anyhow::anyhow!("failed to bind {host}:{actual}: {error}"))?;
    let is_loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    let origin = format!("http://{host}:{actual}");
    let url = format!("{origin}/?token={access_token}");
    if !is_loopback {
        eprintln!("WARN bound {host} - anyone on this LAN can reach it. Open the token URL only.");
    }
    Ok(BoundWeb { server, url })
}

pub(crate) fn serve_loop(server: tiny_http::Server) -> anyhow::Result<()> {
    for request in server.incoming_requests() {
        std::thread::Builder::new()
            .name("runtime-http".into())
            .spawn(move || {
                if let Err(error) = serve_request(request) {
                    eprintln!("runtime HTTP request failed: {error:#}");
                }
            })?;
    }
    Ok(())
}

fn serve_request(mut request: tiny_http::Request) -> anyhow::Result<()> {
    let (status, ctype, body) = handle_request(&mut request);
    let stop = status == 200
        && request.method() == &tiny_http::Method::Post
        && request.url().split('?').next() == Some("/api/runtime/stop");
    let mut resp = tiny_http::Response::from_data(body)
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], ctype)
                .map_err(|_| anyhow::anyhow!("failed to build Content-Type header"))?,
        );
    if ctype.starts_with("text/event-stream") {
        resp = resp.with_header(
            tiny_http::Header::from_bytes(&b"Cache-Control"[..], "no-cache")
                .map_err(|_| anyhow::anyhow!("failed to build Cache-Control header"))?,
        );
    }
    let result = request.respond(resp);
    if stop {
        crate::rpc::request_drain_exit();
    }
    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::read_dist_file;

    #[test]
    fn embedded_index_and_font_are_present() -> Result<(), String> {
        let index = read_dist_file("index.html").ok_or("missing embedded index.html")?;
        if !index.starts_with(b"<!doctype html>") && !index.starts_with(b"<!DOCTYPE html>") {
            return Err("embedded index.html does not start with a doctype".into());
        }
        let font =
            read_dist_file("fonts/LXGWMarkerGothic-Regular.ttf").ok_or("missing embedded font")?;
        if font.len() < 1000 {
            return Err("embedded font is too small".into());
        }
        if read_dist_file("../index.html").is_some() || read_dist_file("/index.html").is_some() {
            return Err("path traversal was accepted".into());
        }
        Ok(())
    }
}
