//! Plugin hook runner.
//!
//! Config is `<data-dir>/plugins.json`:
//! ```jsonc
//! { "hooks": {
//!     "pre-remember":  [{ "cmd": "sensitive-scan", "timeout_ms": 3000, "on_error": "block" }],
//!     "post-remember": [{ "cmd": "auto-tagger", "timeout_ms": 5000, "on_error": "warn" }]
//! } }
//! ```
//! Semantics: event JSON is written to the plugin stdin (`{"event":"...","ts":"...","data":{...}}`);
//! a `pre-*` hook that exits 0 with stdout `{"verdict":"block","reason":"..."}` vetoes the action;
//! a non-zero exit follows `on_error` (block=veto / warn=log and continue / skip=silent);
//! `post-*` failures do not block the main flow. Timeouts attempt cleanup and report failure.
//! Safety: the child is stripped of all ONEMEMORY_* secrets; payloads are summaries, not keys.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Hook event. pre = before the action (can veto); post = after (observe only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookEvent {
    PreRemember,
    PostRemember,
    PostRecall,
    PostForget,
    PostSync,
}

impl HookEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::PreRemember => "pre-remember",
            HookEvent::PostRemember => "post-remember",
            HookEvent::PostRecall => "post-recall",
            HookEvent::PostForget => "post-forget",
            HookEvent::PostSync => "post-sync",
        }
    }
    pub fn parse(s: &str) -> Option<HookEvent> {
        Some(match s {
            "pre-remember" => HookEvent::PreRemember,
            "post-remember" => HookEvent::PostRemember,
            "post-recall" => HookEvent::PostRecall,
            "post-forget" => HookEvent::PostForget,
            "post-sync" => HookEvent::PostSync,
            _ => return None,
        })
    }
    /// Pre events may veto the action; post events only observe.
    pub fn is_pre(&self) -> bool {
        matches!(self, HookEvent::PreRemember)
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct HookSpec {
    /// Plugin command (run via shell; may include args).
    pub cmd: String,
    /// Wait timeout in milliseconds (default 5000; `on_error` applies after cleanup).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Failure policy: block (pre may veto) / warn (stderr warning, action continues) / skip (silent).
    /// Pre defaults to warn; post defaults to skip.
    #[serde(default)]
    pub on_error: String,
}

fn default_timeout_ms() -> u64 {
    5000
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct HooksConfig {
    #[serde(default)]
    pub hooks: BTreeMap<String, Vec<HookSpec>>,
}

#[cfg(feature = "server")]

pub fn config_path() -> std::path::PathBuf {
    respire_app::service::data_dir().join("plugins.json")
}

/// Compatibility entry for Runtime callers using their current data directory.
#[cfg(feature = "server")]
pub fn read_config() -> anyhow::Result<HooksConfig> {
    read_config_at(&config_path())
}

/// A missing config means no plugins; unreadable or invalid config is an error.
pub fn read_config_at(path: &Path) -> anyhow::Result<HooksConfig> {
    use anyhow::Context;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HooksConfig::default()),
        Err(error) => return Err(error).with_context(|| format!("read plugin config {}", path.display())),
    };
    let config: HooksConfig = serde_json::from_str(&text)
        .with_context(|| format!("parse plugin config {}", path.display()))?;
    for (event, specs) in &config.hooks {
        anyhow::ensure!(HookEvent::parse(event).is_some(), "unknown plugin event {event}");
        for spec in specs {
            anyhow::ensure!(!spec.cmd.trim().is_empty(), "empty plugin command for {event}");
            anyhow::ensure!(matches!(spec.on_error.as_str(), "" | "block" | "warn" | "skip"),
                "unknown plugin failure policy {} for {event}", spec.on_error);
        }
    }
    Ok(config)
}

/// Result of one fire() call.
#[derive(Debug, Default)]
pub struct HookVerdict {
    /// Pre events: true = the action was vetoed.
    pub blocked: bool,
    pub reason: String,
    /// Warnings (`on_error=warn` or plugin stderr summary); the caller may display them.
    pub warnings: Vec<String>,
    /// Execution faults remain visible to acknowledged host event delivery, including skip policy.
    pub failures: Vec<String>,
}

impl HookVerdict {
    fn allow() -> HookVerdict {
        HookVerdict::default()
    }
}

/// Single-hook outcome: Ok=success / Blocked=explicit veto / Failed=handled per on_error.
enum HookOutcome {
    Ok(Vec<String>),
    Blocked(String),
    Failed(String),
}

/// Compatibility entry for Runtime callers using their current data directory.
#[cfg(feature = "server")]
pub fn fire(event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    match fire_at(&config_path(), event, payload) {
        Ok(verdict) => verdict,
        Err(error) => HookVerdict {
            blocked: event.is_pre(),
            reason: format!("invalid plugin configuration: {error:#}"),
            warnings: vec![format!("invalid plugin configuration: {error:#}")],
            failures: vec![format!("invalid plugin configuration: {error:#}")],
        },
    }
}

/// Fire one event: run every hook for it in order.
/// payload is a summary-level business payload; combined with event/ts into JSON on plugin stdin.
pub fn fire_at(path: &Path, event: HookEvent, payload: serde_json::Value) -> anyhow::Result<HookVerdict> {
    Ok(fire_config(&read_config_at(path)?, event, payload))
}

/// Execute the validated configuration captured before submitting a core command.
pub fn fire_config(cfg: &HooksConfig, event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    let specs = match cfg.hooks.get(event.as_str()) {
        Some(v) if !v.is_empty() => v,
        _ => return HookVerdict::allow(),
    };
    let mut verdict = HookVerdict::allow();
    let envelope = serde_json::json!({
        "event": event.as_str(),
        "ts": chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string(),
        "data": payload,
    });
    for spec in specs {
        match run_hook(spec, &envelope) {
            HookOutcome::Ok(mut w) => verdict.warnings.append(&mut w),
            HookOutcome::Blocked(reason) => {
                // Explicit veto always applies, regardless of on_error - skip only covers faults, not verdicts.
                if event.is_pre() {
                    verdict.blocked = true;
                    verdict.reason = format!("hook {} blocked: {reason}", spec.cmd);
                } else {
                    verdict.warnings.push(format!("hook {} returned a veto after commit (ignored): {reason}", spec.cmd));
                }
            }
            HookOutcome::Failed(fail) => {
                verdict.failures.push(format!("hook {} failed: {fail}", spec.cmd));
                eprintln!("HOOK event={} command={} failed={fail}", event.as_str(), spec.cmd);
                let policy = if spec.on_error.is_empty() && event.is_pre() {
                    "warn"
                } else if spec.on_error.is_empty() {
                    "skip"
                } else {
                    spec.on_error.as_str()
                };
                match (event.is_pre(), policy) {
                    (true, "block") => {
                        verdict.blocked = true;
                        verdict.reason = format!("hook {} failed: {fail}", spec.cmd);
                    }
                    (true, "warn") | (_, "warn") => {
                        verdict
                            .warnings
                            .push(format!("hook {} failed (continuing): {fail}", spec.cmd));
                    }
                    _ => {} // skip: silent
                }
            }
        }
        if verdict.blocked {
            break; // vetoed; remaining hooks are not run
        }
    }
    verdict
}

/// Run a single plugin.
fn run_hook(spec: &HookSpec, envelope: &serde_json::Value) -> HookOutcome {
    let body = match serde_json::to_string(envelope) {
        Ok(body) => body,
        Err(e) => return HookOutcome::Failed(e.to_string()),
    };
    // Restore PATH/HOME and Windows SystemRoot, but no ONEMEMORY_* secrets.
    // New secret vars are also wiped by env_clear, so there is no "forgot to strip" hole.
    #[cfg(windows)]
    let mut spawn = {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/S", "/C"]);
        command.raw_arg(&spec.cmd);
        command
    };
    #[cfg(not(windows))]
    let mut spawn = {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("sh");
        command.arg("-c").arg(&spec.cmd).process_group(0);
        command
    };
    let spawn = spawn
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", crate::env::var("PATH").unwrap_or_default())
        .env("HOME", crate::env::var("HOME").unwrap_or_default())
        .env("RSRS_HOOK_EVENT", envelope["event"].as_str().unwrap_or(""));
    #[cfg(windows)]
    if let Some(root) = crate::env::var_os("SystemRoot") {
        spawn.env("SystemRoot", root);
    }
    let mut child = match spawn.spawn() {
        Ok(child) => child,
        Err(e) => return HookOutcome::Failed(format!("failed to start ({e})")),
    };
    let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        let mut errors = vec!["hook I/O pipes unavailable".to_owned()];
        errors.extend(stop_hook(&mut child));
        return HookOutcome::Failed(errors.join("; "));
    };
    let writer = std::thread::spawn(move || stdin.write_all(body.as_bytes()));
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });

    let timeout = Duration::from_millis(spec.timeout_ms.max(1));
    let started = Instant::now();
    let mut errors = Vec::new();
    let status = loop {
        if writer.is_finished() && stdout_reader.is_finished() && stderr_reader.is_finished() {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {}
                Err(e) => {
                    errors.push(format!("wait for plugin failed ({e})"));
                    break None;
                }
            }
        }
        if started.elapsed() >= timeout {
            errors.push(format!("timeout (>{}ms)", spec.timeout_ms));
            break None;
        }
        std::thread::sleep(
            Duration::from_millis(10).min(timeout.saturating_sub(started.elapsed())),
        );
    };
    if status.is_none() {
        errors.extend(stop_hook(&mut child));
        let started = Instant::now();
        while !(writer.is_finished() && stdout_reader.is_finished() && stderr_reader.is_finished())
            && started.elapsed() < Duration::from_secs(2)
        {
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    let input = finish_hook_io(writer, "stdin write");
    let stdout = finish_hook_io(stdout_reader, "stdout read");
    let stderr = finish_hook_io(stderr_reader, "stderr read");
    if status.is_some() {
        if let Ok(stderr) = &stderr {
            let stderr = String::from_utf8_lossy(stderr);
            for line in stderr.lines().filter(|l| !l.trim().is_empty()).take(5) {
                eprintln!("HOOK command={} message={}", spec.cmd, line);
            }
        }
    }
    let (status, stdout, input_error) = match (status, input, stdout, stderr) {
        (Some(status), Ok(()), Ok(stdout), Ok(_)) if errors.is_empty() => (status, stdout, None),
        (Some(status), Err(error), Ok(stdout), Ok(_))
            if errors.is_empty()
                && status.success()
                && error.kind() == std::io::ErrorKind::BrokenPipe =>
        {
            // An early veto may close stdin before the full payload is written.
            (status, stdout, Some(error))
        }
        (_, input, stdout, stderr) => {
            if let Err(e) = input {
                errors.push(e.to_string());
            }
            if let Err(e) = stdout {
                errors.push(e.to_string());
            }
            if let Err(e) = stderr {
                errors.push(e.to_string());
            }
            return HookOutcome::Failed(errors.join("; "));
        }
    };
    if !status.success() {
        return HookOutcome::Failed(format!("{}", status));
    }
    let stdout = String::from_utf8_lossy(&stdout);
    // Pre: last stdout JSON line {"verdict":"block","reason":"..."} -> veto
    if let Some(last) = stdout.lines().rev().find(|l| !l.trim().is_empty()) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(last.trim()) {
            if v["verdict"] == "block" {
                return HookOutcome::Blocked(
                    v["reason"].as_str().unwrap_or("no reason given").to_owned(),
                );
            }
        }
    }
    if let Some(error) = input_error {
        return HookOutcome::Failed(error.to_string());
    }
    HookOutcome::Ok(Vec::new())
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            return Ok(None);
        }
        std::thread::sleep(
            Duration::from_millis(10).min(timeout.saturating_sub(started.elapsed())),
        );
    }
}

fn stop_hook(child: &mut std::process::Child) -> Vec<String> {
    let mut errors = Vec::new();
    // shortcut: escaped descendants can survive; use OS-enforced jobs for full tree ownership.
    #[cfg(windows)]
    let mut stop = {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new("taskkill");
        command.args(["/PID", &child.id().to_string(), "/T", "/F"]);
        command.creation_flags(0x0800_0000);
        command
    };
    #[cfg(not(windows))]
    let mut stop = {
        let mut command = Command::new("kill");
        command.args(["-KILL", "--", &format!("-{}", child.id())]);
        command
    };
    match stop
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut stopper) => {
            let unfinished = match wait_for_child(&mut stopper, Duration::from_secs(2)) {
                Ok(Some(status)) if status.success() => false,
                Ok(Some(status)) => {
                    errors.push(format!("process tree termination failed ({status})"));
                    false
                }
                Ok(None) => {
                    errors.push("process tree termination timed out".to_owned());
                    true
                }
                Err(e) => {
                    errors.push(format!("waiting for process tree termination failed ({e})"));
                    true
                }
            };
            if unfinished {
                let kill_error = stopper.kill().err();
                match wait_for_child(&mut stopper, Duration::from_secs(2)) {
                    Ok(Some(_)) => {}
                    Ok(None) => errors.push(format!(
                        "termination helper was not reaped (kill: {kill_error:?})"
                    )),
                    Err(e) => errors.push(format!(
                        "termination helper could not be reaped ({e}; kill: {kill_error:?})"
                    )),
                }
            }
        }
        Err(e) => errors.push(format!("failed to start process tree termination ({e})")),
    }
    let kill_error = child.kill().err();
    match wait_for_child(child, Duration::from_secs(2)) {
        Ok(Some(_)) => {}
        Ok(None) => errors.push(format!("hook child was not reaped (kill: {kill_error:?})")),
        Err(e) => errors.push(format!(
            "hook child could not be reaped ({e}; kill: {kill_error:?})"
        )),
    }
    errors
}

fn finish_hook_io<T>(
    worker: std::thread::JoinHandle<std::io::Result<T>>,
    name: &str,
) -> std::io::Result<T> {
    if !worker.is_finished() {
        return Err(std::io::Error::other(format!("{name} thread did not stop")));
    }
    worker
        .join()
        .map_err(|_| std::io::Error::other(format!("{name} thread panicked")))?
        .map_err(|e| std::io::Error::new(e.kind(), format!("{name} failed ({e})")))
}

#[cfg(feature = "server")]

/// Alias over fire(): public paths all go through fire.
pub fn verdict_of(event: HookEvent, payload: serde_json::Value) -> HookVerdict {
    fire(event, payload)
}

/// Full event-name table (plugin list / docs).
pub const EVENT_NAMES: &[&str] = &[
    "pre-remember",
    "post-remember",
    "post-recall",
    "post-forget",
    "post-sync",
];

// -- Event payload builders (summary-level: the smallest surface a hook needs) --

pub fn remember_payload(
    title: &str,
    importance: &str,
    kind: &str,
    project: &str,
    content: &str,
) -> serde_json::Value {
    serde_json::json!({
        "title": title,
        "importance": importance,
        "kind": kind,
        "project": project,
        "content_head": content.chars().take(200).collect::<String>(),
        "content_chars": content.chars().count(),
    })
}

pub fn remember_done_payload(id: &str, title: &str, importance: &str) -> serde_json::Value {
    serde_json::json!({ "id": id, "title": title, "importance": importance })
}

pub fn recall_payload(query: &str, project: &str, hits: &[(String, f32)]) -> serde_json::Value {
    serde_json::json!({
        "query": query,
        "project": project,
        "hits": hits.iter().map(|(id, s)| serde_json::json!({"id": id, "score": s})).collect::<Vec<_>>(),
    })
}

pub fn forget_payload(id: &str) -> serde_json::Value {
    serde_json::json!({ "id": id })
}

pub fn sync_payload(pulled: usize, pushed: usize) -> serde_json::Value {
    serde_json::json!({ "pulled": pulled, "pushed": pushed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_roundtrip() {
        for e in [
            HookEvent::PreRemember,
            HookEvent::PostRemember,
            HookEvent::PostRecall,
            HookEvent::PostForget,
            HookEvent::PostSync,
        ] {
            assert_eq!(HookEvent::parse(e.as_str()), Some(e));
        }
        assert_eq!(HookEvent::parse("nope"), None);
        assert!(HookEvent::PreRemember.is_pre());
        assert!(!HookEvent::PostSync.is_pre());
    }

    #[test]
    fn test_config_missing_is_empty() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("missing/plugins.json");
        let cfg = read_config_at(&path)?;
        assert!(cfg.hooks.is_empty());
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({}))?;
        assert!(!v.blocked);
        Ok(())
    }

    #[test]
    fn test_payload_summary_only() {
        let p = remember_payload("t", "normal", "context", "proj", "a very long body");
        assert_eq!(p["title"], "t");
        assert!(p["content_head"].is_string());
        assert!(p.get("id").is_none());
    }

    #[test]
    fn fire_runs_shell_hook() -> anyhow::Result<()> {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("plugins.json");
        let cfg = serde_json::json!({
            "hooks": {
                "pre-remember": [{"cmd": "exit 0", "timeout_ms": 2000, "on_error": "warn"}]
            }
        });
        std::fs::write(&path, cfg.to_string())?;
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({"title":"t"}))?;
        assert!(!v.blocked);
        let cfg_block = serde_json::json!({
            "hooks": {
                "pre-remember": [{"cmd": "exit 1", "timeout_ms": 2000, "on_error": "block"}]
            }
        });
        std::fs::write(&path, cfg_block.to_string())?;
        let v = fire_at(&path, HookEvent::PreRemember, serde_json::json!({}))?;
        assert!(v.blocked);
        Ok(())
    }

    #[test]
    fn payload_builders_and_event_names() -> anyhow::Result<()> {
        assert_eq!(EVENT_NAMES.len(), 5);
        let done = remember_done_payload("id", "t", "important");
        assert_eq!(done["id"], "id");
        let rec = recall_payload("q", "p", &[("a".into(), 0.9)]);
        assert_eq!(rec["query"], "q");
        assert_eq!(forget_payload("x")["id"], "x");
        assert_eq!(sync_payload(1, 2)["pulled"], 1);
        let dir = tempfile::tempdir()?;
        let v = fire_at(&dir.path().join("plugins.json"), HookEvent::PostSync, serde_json::json!({}))?;
        assert!(!v.blocked);
        Ok(())
    }

    #[test]
    fn hook_failure_policies_and_explicit_veto() -> anyhow::Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("plugins.json");
        for (event, policy, blocked, warned) in [
            (HookEvent::PreRemember, "", false, true),
            (HookEvent::PreRemember, "warn", false, true),
            (HookEvent::PreRemember, "skip", false, false),
            (HookEvent::PreRemember, "block", true, false),
            (HookEvent::PostSync, "", false, false),
            (HookEvent::PostSync, "block", false, false),
            (HookEvent::PostSync, "warn", false, true),
        ] {
            let cfg = serde_json::json!({"hooks": {event.as_str(): [
                {"cmd": "exit 1", "on_error": policy, "timeout_ms": 2000}
            ]}});
            std::fs::write(&path, cfg.to_string())?;
            let verdict = fire_at(&path, event, serde_json::json!({}))?;
            assert_eq!(
                verdict.blocked,
                blocked,
                "{} policy={policy}",
                event.as_str()
            );
            assert_eq!(!verdict.warnings.is_empty(), warned);
            assert_eq!(verdict.failures.len(), 1, "execution errors must reach host acknowledgements, including skip");
            assert!(!verdict.reason.contains("failed to start"));
            assert!(verdict
                .warnings
                .iter()
                .all(|warning| !warning.contains("failed to start")));
        }
        let veto_command = if cfg!(windows) {
            "echo {\"verdict\":\"block\",\"reason\":\"private data\"}"
        } else {
            "echo '{\"verdict\":\"block\",\"reason\":\"private data\"}'"
        };
        let cfg = serde_json::json!({"hooks": {"pre-remember": [
            {"cmd": veto_command, "on_error": "skip"},
            {"cmd": "exit 1", "on_error": "warn"}
        ]}});
        std::fs::write(&path, cfg.to_string())?;
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"data": "x".repeat(2 * 1024 * 1024)}),
        ] {
            // The echo hook exits without reading stdin, including a payload larger than the pipe.
            let verdict = fire_at(&path, HookEvent::PreRemember, payload)?;
            assert!(verdict.blocked, "{} {:?}", verdict.reason, verdict.warnings);
            assert!(verdict.reason.contains("private data"));
            assert!(verdict.warnings.is_empty(), "a veto must stop later hooks");
        }
        let outcome = run_hook(
            &HookSpec {
                cmd: "exit 0".to_owned(),
                timeout_ms: 2000,
                on_error: "skip".to_owned(),
            },
            &serde_json::json!({"data": "x".repeat(2 * 1024 * 1024)}),
        );
        match outcome {
            HookOutcome::Failed(error) => assert!(error.contains("stdin write failed"), "{error}"),
            _ => panic!("a broken pipe without an explicit veto must still fail"),
        }
        std::fs::write(&path, "invalid json")?;
        assert!(read_config_at(&path).is_err());
        let post = fire_config(&serde_json::from_value(serde_json::json!({"hooks": {"post-sync": [
            {"cmd": veto_command}, {"cmd": "exit 1", "on_error": "warn"}
        ]}}))?, HookEvent::PostSync, serde_json::json!({}));
        assert!(!post.blocked, "post events cannot veto committed work");
        assert_eq!(post.warnings.len(), 2, "post veto must not suppress later hooks");
        Ok(())
    }

    #[test]
    fn timeout_hook_child() -> anyhow::Result<()> {
        let event = std::env::var("RSRS_HOOK_EVENT").unwrap_or_default();
        if let Some(path) = event.strip_prefix("timeout-test:") {
            std::fs::write(path, "running")?;
            std::thread::sleep(Duration::from_secs(4));
            std::fs::write(path, "survived")?;
        }
        Ok(())
    }

    #[test]
    fn timeout_terminates_hook_tree_and_unblocks_writer() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("hook-state");
        let executable = std::env::current_exe()?;
        #[cfg(windows)]
        let cmd = format!(
            "\"\"{}\" --exact hooks::tests::timeout_hook_child --nocapture\"",
            executable.display()
        );
        #[cfg(not(windows))]
        let cmd = format!(
            "'{}' --exact hooks::tests::timeout_hook_child --nocapture",
            executable.display().to_string().replace('\'', "'\\''")
        );
        let spec = HookSpec {
            cmd,
            timeout_ms: 2000,
            on_error: "block".to_owned(),
        };
        let envelope = serde_json::json!({
            "event": format!("timeout-test:{}", marker.display()),
            "data": "x".repeat(2 * 1024 * 1024),
        });
        let started = Instant::now();
        let outcome = run_hook(&spec, &envelope);
        let failure = match outcome {
            HookOutcome::Failed(failure) => failure,
            _ => panic!("expected timeout failure"),
        };
        assert!(started.elapsed() < Duration::from_secs(6), "{failure}");
        assert!(failure.contains("timeout"), "{failure}");
        assert!(failure.contains("stdin write failed"), "{failure}");
        assert!(!failure.contains("did not stop"), "{failure}");
        assert!(!failure.contains("not reaped"), "{failure}");
        assert!(!failure.contains("could not be reaped"), "{failure}");
        assert!(!failure.contains("termination"), "{failure}");
        assert!(!failure.contains("stdout read"), "{failure}");
        assert!(!failure.contains("stderr read"), "{failure}");
        assert_eq!(std::fs::read_to_string(&marker)?, "running");
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(std::fs::read_to_string(&marker)?, "running");
        Ok(())
    }
}
