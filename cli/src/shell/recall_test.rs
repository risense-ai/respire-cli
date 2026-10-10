//! One-request recall checks; never change the saved recall mode.
use super::text_input::Input;
use super::{fail_line, line, ok_line, retrieval_action, t, warn_line};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use serde_json::Value;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Instant;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub(super) struct Form {
    mode: &'static str,
    query: Input,
    pending: Option<(Instant, Receiver<Result<Value, String>>)>,
    result: Vec<Line<'static>>,
    scroll: u16,
    cancel: Arc<AtomicBool>,
}

impl Form {
    pub fn new(mode: &'static str) -> Self {
        Self {
            mode,
            query: Input::new(String::new()),
            pending: None,
            result: Vec::new(),
            scroll: 0,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn paste(&mut self, text: &str) {
        if self.pending.is_none() {
            self.query.paste(text);
        }
    }

    pub fn key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::PageDown => {
                self.scroll = self
                    .scroll
                    .saturating_add(5)
                    .min(self.result.len().saturating_sub(1) as u16);
                return;
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(5);
                return;
            }
            _ => {}
        }
        if self.pending.is_some() {
            return;
        }
        if key.code != KeyCode::Enter {
            self.query.key(key);
            return;
        }
        let query = self.query.text.trim().to_owned();
        if query.is_empty() {
            self.result = vec![fail_line(t("请输入测试查询", "Enter a query to test"))];
            return;
        }
        let mode = self.mode;
        let cancel = Arc::clone(&self.cancel);
        let (sender, receiver) = mpsc::channel();
        self.pending = Some((Instant::now(), receiver));
        self.result.clear();
        self.scroll = 0;
        std::thread::spawn(move || {
            let result = if mode == "benchmark" {
                run_benchmark(&query, &cancel)
            } else {
                retrieval_action(&[
                    "recall", &query, "--mode", mode, "--titles", "--limit", "20",
                ])
            };
            let _ = sender.send(result);
        });
    }

    pub fn poll(&mut self) {
        let Some((started, receiver)) = &self.pending else {
            return;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err(t("测试线程中断", "Test worker disconnected")),
        };
        let elapsed = started.elapsed().as_secs_f32();
        self.pending = None;
        self.result
            .push(line(format!("{}: {elapsed:.2}s", t("耗时", "Elapsed"))));
        match result {
            Err(error) => self.result.push(fail_line(error)),
            Ok(value) => {
                if self.mode == "benchmark" {
                    if let Some(rows) = value["rows"].as_array() {
                        self.result.extend(rows.iter().filter_map(Value::as_str).map(|row| line(row.to_owned())));
                    }
                    return;
                }
                let count = value["summary"]["count"].as_u64().unwrap_or(0);
                if let Some(reason) = value["summary"]["selection_fallback"].as_str() {
                    self.result.push(warn_line(format!(
                        "{}: {reason}",
                        t(
                            "高质量失败，以下为快速结果",
                            "Quality failed; showing local results"
                        )
                    )));
                } else if count == 0 {
                    self.result.push(warn_line(if self.mode == "quality" {
                        t(
                            "未召回结果；本次未验证高质量 API",
                            "No results; quality API was not exercised",
                        )
                    } else {
                        t(
                            "未召回结果，请换一个查询",
                            "No results; try a different query",
                        )
                    }));
                } else {
                    self.result.push(ok_line(format!(
                        "{} · {count} {}",
                        t("测试成功", "Test passed"),
                        t("条结果", "results")
                    )));
                }
                if let Some(items) = value["items"].as_array() {
                    self.result.extend(
                        items
                            .iter()
                            .filter_map(|item| item["value"].as_str())
                            .map(|text| line(text.to_owned())),
                    );
                }
                if let Some(related) = value.get("related") {
                    match serde_json::from_value::<Vec<respire::memory::model::RelatedMemory>>(
                        related.clone(),
                    ) {
                        Ok(related) => self.result.extend(
                            related
                                .iter()
                                .map(|entry| line(crate::output::related_value(entry))),
                        ),
                        Err(error) => self.result.push(fail_line(error.to_string())),
                    }
                }
            }
        }
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let title = if self.mode == "benchmark" {
            t("推理 / Recall Benchmark", "Inference / Recall Benchmark")
        } else if self.mode == "quality" {
            t("测试高质量召回", "Test high-quality recall")
        } else {
            t("测试快速召回", "Test fast recall")
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let regions = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);
        frame.render_widget(
            Paragraph::new(self.query.line(
                regions[0].width.saturating_sub(2) as usize,
                true,
                false,
            ))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(t("查询", "Query")),
            ),
            regions[0],
        );
        let note = if self.mode == "benchmark" {
            t("回车：首轮 + 8 轮推理验证及快速 Recall。包含 RPC 等待；只访问本地 runtime。", "Enter: first call + 8 inference checks and fast recalls. RPC waits included; local runtime only.")
        } else if self.mode == "quality" {
            t("回车测试：查询与候选标题会发往已配置 API；不改变默认模式。", "Enter tests: query and candidate titles go to the configured API; saved mode is unchanged.")
        } else {
            t(
                "回车测试：仅使用本地召回；不改变默认模式。",
                "Enter tests local recall; saved mode is unchanged.",
            )
        };
        frame.render_widget(Paragraph::new(note).wrap(Wrap { trim: false }), regions[1]);
        let lines = if let Some((started, _)) = &self.pending {
            vec![
                line(format!(
                    "{} {}s",
                    t("正在测试", "Testing"),
                    started.elapsed().as_secs()
                )),
                line(t(
                    "Esc 返回；已发出的请求完成后停止后续轮次。",
                    "Esc returns; the submitted request finishes, then further rounds stop.",
                )),
            ]
        } else {
            self.result.clone()
        };
        frame.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0)),
            regions[2],
        );
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

// The SDK's reported probe time and RPC wall time have distinct scopes.
// Repeated fast Recall measures the current library without calling a selector API.
fn run_benchmark(query: &str, cancel: &AtomicBool) -> Result<Value, String> {
    const ROUNDS: usize = 8;
    let mut inference = Vec::new();
    let mut probe_wall = Vec::new();
    let mut recall_wall = Vec::new();
    let mut selected = String::new();
    let mut indexed_min = u64::MAX;
    let mut indexed_max = 0;
    let mut pending_max = 0;
    let mut first_probe = 0.0;
    let mut first_recall = 0.0;
    for round in 0..=ROUNDS {
        if cancel.load(Ordering::Acquire) { return Err(t("Benchmark 已停止", "Benchmark stopped")); }
        let probe_text = format!("{query} [benchmark {round}]");
        let started = Instant::now();
        let probe = retrieval_action(&["model", "probe", "--text", &probe_text])
            .map_err(|error| format!("Benchmark probe {round}: {error}"))?;
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        let summary = &probe["summary"];
        let elapsed = summary["elapsed_ms"].as_f64()
            .filter(|value| value.is_finite() && *value >= 0.0)
            .ok_or_else(|| "Benchmark: missing probe elapsed_ms".to_owned())?;
        let engine = summary["selected"].as_str()
            .ok_or_else(|| "Benchmark: missing selected engine".to_owned())?;
        if !selected.is_empty() && selected != engine {
            return Err(t("推理引擎在测试期间发生变化，请重新测试", "Inference engine changed during the benchmark; run again"));
        }
        selected = engine.to_owned();
        if round == 0 { first_probe = wall; }
        else { inference.push(elapsed); probe_wall.push(wall); }
        if cancel.load(Ordering::Acquire) { return Err(t("Benchmark 已停止", "Benchmark stopped")); }
        let started = Instant::now();
        let recalled = retrieval_action(&["recall", query, "--mode", "fast", "--titles", "--limit", "20"])
            .map_err(|error| format!("Benchmark recall {round}: {error}"))?;
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        let summary = &recalled["summary"];
        let indexed = summary["indexed_candidates"].as_u64()
            .ok_or_else(|| "Benchmark: runtime does not report indexed_candidates; update the runtime".to_owned())?;
        let pending = summary["index_pending"].as_u64()
            .ok_or_else(|| "Benchmark: runtime does not report index_pending; update the runtime".to_owned())?;
        indexed_min = indexed_min.min(indexed);
        indexed_max = indexed_max.max(indexed);
        pending_max = pending_max.max(pending);
        if round == 0 { first_recall = wall; } else { recall_wall.push(wall); }
    }
    let mut rows = vec![
        format!("{}: {selected}; {ROUNDS} {}", t("实际引擎", "Selected engine"), t("重复轮次", "repeated rounds")),
        format!("{}: {first_probe:.1} ms / {first_recall:.1} ms", t("首轮推理请求 / Recall", "First probe request / Recall")),
        benchmark_row(&t("推理报告耗时", "Reported probe time"), &inference)?,
        benchmark_row(&t("推理请求完整耗时", "Probe RPC wall time"), &probe_wall)?,
        benchmark_row(&t("快速 Recall 完整耗时", "Fast Recall RPC wall time"), &recall_wall)?,
        format!("{}: {indexed_min}–{indexed_max}; {}: {pending_max}", t("有效候选数", "Indexed candidates"), t("最多待索引数", "Maximum pending index")),
        t("首轮不等于冷启动；重复 Recall 可复用查询缓存。", "First call is not a cold start; repeated Recall may reuse query caches."),
        t("SDK 上报耗时与完整请求不同；完整 Recall 含排队、RPC 和检索。", "SDK-reported times differ from full requests; full Recall includes queues, RPC and retrieval."),
        t("Recall 会更新常规查询日志与命中统计；不修改记忆正文或默认模式。", "Recall updates normal query logs and hit statistics; content and saved mode are unchanged."),
    ];
    if indexed_min == 0 {
        rows.push(t("没有有效候选：结果仅代表空候选查询，不代表完整记忆库速度。", "No indexed candidates: timings cover empty-candidate queries, not a populated library."));
    }
    if indexed_min != indexed_max || pending_max > 0 {
        rows.push(t("索引仍有变化：本次为当前负载结果，不适合直接比较引擎。", "Index is changing: these timings reflect current load; avoid direct engine comparisons."));
    }
    Ok(serde_json::json!({"rows": rows}))
}

fn benchmark_row(label: &str, samples: &[f64]) -> Result<String, String> {
    if samples.is_empty() { return Err("Benchmark: no samples".to_owned()); }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let p50 = sorted[(sorted.len() * 50).div_ceil(100) - 1];
    let p95 = sorted[(sorted.len() * 95).div_ceil(100) - 1];
    let rate = if mean > 0.0 { format!("{:.2}", 1000.0 / mean) } else { "n/a".to_owned() };
    Ok(format!("{label}: mean {mean:.1} ms  P50 {p50:.1} ms  P95 {p95:.1} ms  {rate}/s"))
}
