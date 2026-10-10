//! Human progress is separate from stdout and scoped to one foreground request.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

struct Entry {
    id: String,
    phase: Mutex<String>,
    remote: AtomicBool,
    finished: AtomicBool,
}
static ACTIVE: OnceLock<Mutex<HashMap<String, Arc<Entry>>>> = OnceLock::new();
thread_local! {
    static CURRENT: RefCell<Option<Arc<Entry>>> = const { RefCell::new(None) };
}

pub struct Scope {
    entry: Arc<Entry>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Scope {
    pub fn start(id: Option<String>, display: bool, immediate: bool) -> Option<Self> {
        if id.is_none() && !display { return None; }
        let entry = Arc::new(Entry {
            id: id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            phase: Mutex::new(text("正在准备命令", "Preparing command")),
            remote: AtomicBool::new(false),
            finished: AtomicBool::new(false),
        });
        if let Ok(mut active) = ACTIVE.get_or_init(|| Mutex::new(HashMap::new())).lock() {
            active.insert(entry.id.clone(), entry.clone());
        }
        CURRENT.with(|current| *current.borrow_mut() = Some(entry.clone()));
        let (stop, receiver) = mpsc::channel();
        if display && immediate {
            print(&text("正在准备命令", "Preparing command"), 0, stderr_is_terminal());
        }
        let worker = if display {
            let entry = entry.clone();
            Some(std::thread::spawn(move || {
                let started = Instant::now();
                let mut last = String::new();
                let mut shown = Instant::now();
                while receiver.recv_timeout(Duration::from_millis(250)).is_err() {
                    if entry.finished.load(Ordering::Acquire) { break; }
                    let mut phase = entry.phase.lock().map(|phase| phase.clone()).unwrap_or_default();
                    if entry.remote.load(Ordering::Acquire) {
                        // Poll outside the command worker pool, so saturated workers can report their wait.
                        match crate::rpc::foreground_progress(&entry.id) {
                            Ok(value) => {
                                if let Some(current) = value["phase"].as_str() { phase = current.to_owned(); }
                                else { phase = text("等待 runtime 执行命令", "Waiting for runtime to execute command"); }
                                if value["model_operation"]["active"] == true {
                                    phase = crate::output::model_task_text(&value["model_operation"]);
                                }
                                if let Some(inference) = inference_progress_text(&value["inference"]) {
                                    phase = format!("{phase} · {inference}");
                                }
                            }
                            Err(_) => phase = text("等待 runtime 响应", "Waiting for runtime response"),
                        }
                    }
                    if phase != last || shown.elapsed() >= Duration::from_secs(5) {
                        let mut stderr = std::io::stderr().lock();
                        if entry.finished.load(Ordering::Acquire) { break; }
                        write_line(&mut stderr, &phase, started.elapsed().as_secs(), stderr_is_terminal());
                        last = phase;
                        shown = Instant::now();
                    }
                }
            }))
        } else { None };
        Some(Self { entry, stop, worker })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        finish();
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
        if let Some(active) = ACTIVE.get() {
            if let Ok(mut active) = active.lock() { active.remove(&self.entry.id); }
        }
        CURRENT.with(|current| *current.borrow_mut() = None);
    }
}

fn text(zh: &str, en: &str) -> String {
    if crate::i18n::lang() == crate::i18n::Lang::Zh { zh } else { en }.to_owned()
}

pub(crate) fn inference_progress_text(status: &serde_json::Value) -> Option<String> {
    if status["host_recovery_required"] == true {
        return Some(text("推理无响应，需要宿主恢复", "Inference unresponsive; host recovery required"));
    }
    let queued = status["queued"].as_u64()?;
    if status["active"] == true || queued > 0 {
        let label = if status["phase"] == "loading" {
            text("推理服务（全局）：加载模型；等待任务", "Inference service (global): loading; queued")
        } else {
            text("推理服务（全局）：运行中；等待任务", "Inference service (global): active; queued")
        };
        return Some(format!("{label} {queued}"));
    }
    None
}

pub fn phase(zh: &str, en: &str) {
    CURRENT.with(|current| {
        if let Some(entry) = current.borrow().as_ref() {
            if let Ok(mut phase) = entry.phase.lock() { *phase = text(zh, en); }
        }
    });
}

pub fn remote_id() -> Option<String> {
    CURRENT.with(|current| current.borrow().as_ref().map(|entry| {
        phase("连接 runtime；等待命令结果", "Connecting to runtime; waiting for command result");
        entry.remote.store(true, Ordering::Release);
        entry.id.clone()
    }))
}

pub fn status(id: &str) -> serde_json::Value {
    let mut value = ACTIVE.get().and_then(|active| active.lock().ok())
        .and_then(|active| active.get(id).cloned())
        .and_then(|entry| entry.phase.lock().ok().map(|phase| serde_json::json!({"phase":*phase})))
        .unwrap_or(serde_json::Value::Null);
    if !value.is_null() {
        if let Ok(task) = respire::model_progress::status() {
            if task["id"].as_str() == Some(id) { value["model_operation"] = task; }
        }
    }
    value
}

pub fn finish() {
    CURRENT.with(|current| {
        if let Some(entry) = current.borrow().as_ref() {
            if !entry.finished.swap(true, Ordering::AcqRel) && stderr_is_terminal() {
                let mut stderr = std::io::stderr().lock();
                let _ = write!(stderr, "\r\x1b[2K");
                let _ = stderr.flush();
            }
        }
    });
}

fn stderr_is_terminal() -> bool { std::io::stderr().is_terminal() }
fn print(phase: &str, elapsed: u64, tty: bool) {
    write_line(&mut std::io::stderr().lock(), phase, elapsed, tty);
}
fn write_line(writer: &mut impl Write, phase: &str, elapsed: u64, tty: bool) {
    if tty { let _ = write!(writer, "\r\x1b[2K{phase} ({elapsed}s)"); }
    else { let _ = writeln!(writer, "{phase} ({elapsed}s)"); }
    let _ = writer.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_progress_is_brief_and_reports_stalls() {
        assert!(inference_progress_text(&serde_json::json!({"active":false,"queued":0})).is_none());
        let busy = inference_progress_text(&serde_json::json!({"active":true,"queued":3}));
        assert!(busy.is_some_and(|text| text.ends_with("3") && !text.contains('{')));
        let stalled = inference_progress_text(&serde_json::json!({"host_recovery_required":true}));
        assert!(stalled.is_some_and(|text| !text.contains('{')));
    }

    #[test]
    fn json_is_silent_and_redirected_progress_has_no_terminal_codes() -> anyhow::Result<()> {
        assert!(Scope::start(None, false, false).is_none());
        let mut plain = Vec::new();
        write_line(&mut plain, "Waiting for server", 5, false);
        assert_eq!(String::from_utf8(plain)?, "Waiting for server (5s)\n");
        let mut terminal = Vec::new();
        write_line(&mut terminal, "Downloading 25%", 2, true);
        assert_eq!(String::from_utf8(terminal)?, "\r\x1b[2KDownloading 25% (2s)");
        Ok(())
    }
}
