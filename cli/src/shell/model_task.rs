//! Model task feedback remains responsive even while all command workers are occupied.
use super::{fail_line, line, t, Line, FAST};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub(super) struct Task {
    pub id: String,
    pub cancel: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
    progress: Arc<Mutex<Result<Value, String>>>,
    started: Instant,
}

impl Task {
    pub(super) fn start() -> Self {
        let task = Self {
            id: uuid::Uuid::new_v4().to_string(),
            cancel: Arc::new(AtomicBool::new(false)),
            finished: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(Ok(Value::Null))),
            started: Instant::now(),
        };
        let cancel = Arc::clone(&task.cancel);
        let finished = Arc::clone(&task.finished);
        let progress = Arc::clone(&task.progress);
        let id = task.id.clone();
        std::thread::spawn(move || {
            while !finished.load(Ordering::Acquire) {
                let result = crate::rpc::model_control(&id, cancel.load(Ordering::Acquire))
                    .map_err(|error| error.to_string());
                if let Ok(mut slot) = progress.lock() {
                    *slot = result;
                }
                std::thread::sleep(FAST);
            }
        });
        task
    }

    pub(super) fn lines(&self) -> Vec<Line<'static>> {
        let mut lines = vec![line(t("模型任务", "Model task"))];
        let progress = self
            .progress
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| Err("progress lock poisoned".into()));
        match progress {
            Ok(value) if value["active"] == true => {
                let phase = value["phase"].as_str().unwrap_or("");
                let label = match phase {
                    "connect" => t("连接下载源 / 等待响应", "Connecting / waiting for response"),
                    "download" => t("下载", "Downloading"),
                    "verify" => t("校验文件", "Verifying files"),
                    "load" => t("加载模型", "Loading model"),
                    "index" => t("重建索引", "Rebuilding index"),
                    _ => phase.to_owned(),
                };
                lines.push(line(format!(
                    "{label}: {}",
                    value["item"].as_str().unwrap_or("")
                )));
                let done = value["done"].as_u64().unwrap_or(0);
                let total = value["total"].as_u64().filter(|total| *total > 0);
                if let Some(total) = total {
                    let ratio = (done as f64 / total as f64).min(1.0);
                    let filled = (ratio * 24.0) as usize;
                    lines.push(line(format!(
                        "[{}{}] {:.1}%",
                        "#".repeat(filled),
                        "-".repeat(24 - filled),
                        ratio * 100.0
                    )));
                }
                if phase == "download" || phase == "verify" {
                    lines.push(line(format!(
                        "{:.1} MiB / {}",
                        done as f64 / 1048576.0,
                        total
                            .map(|n| format!("{:.1} MiB", n as f64 / 1048576.0))
                            .unwrap_or_else(|| t("总大小未知", "unknown total"))
                    )));
                } else if phase == "index" {
                    lines.push(line(format!(
                        "{done} / {} {}",
                        total.unwrap_or(0),
                        t("条记忆", "memories")
                    )));
                }
                lines.push(line(format!(
                    "{} {}s",
                    t("距上次进展", "Since last progress"),
                    value["idle"].as_u64().unwrap_or(0)
                )));
            }
            Ok(_) => lines.push(line(t(
                "等待任务启动或切换阶段…",
                "Waiting for task / next phase...",
            ))),
            Err(error) => lines.push(fail_line(format!(
                "{}: {error}",
                t("进度连接失败", "Progress connection failed")
            ))),
        }
        lines.push(line(format!(
            "{} {}s",
            t("已用时", "Elapsed"),
            self.started.elapsed().as_secs()
        )));
        lines.push(line(if self.cancel.load(Ordering::Acquire) {
            t(
                "已请求取消，等待当前网络读取或推理结束…",
                "Cancellation requested; waiting for the current read / inference...",
            )
        } else {
            t(
                "Esc / C 取消任务；完成前保留当前索引",
                "Esc / C cancels; current index stays active until complete",
            )
        }));
        lines
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
    }
}
