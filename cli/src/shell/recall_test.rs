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

pub(super) struct Form {
    mode: &'static str,
    query: Input,
    pending: Option<(Instant, Receiver<Result<Value, String>>)>,
    result: Vec<Line<'static>>,
    scroll: u16,
}

impl Form {
    pub fn new(mode: &'static str) -> Self {
        Self {
            mode,
            query: Input::new(String::new()),
            pending: None,
            result: Vec::new(),
            scroll: 0,
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
        let (sender, receiver) = mpsc::channel();
        self.pending = Some((Instant::now(), receiver));
        self.result.clear();
        self.scroll = 0;
        std::thread::spawn(move || {
            let result = retrieval_action(&[
                "recall", &query, "--mode", mode, "--titles", "--limit", "20",
            ]);
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
            }
        }
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let title = if self.mode == "quality" {
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
        let note = if self.mode == "quality" {
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
                    "Esc 返回；已发出的请求继续完成。",
                    "Esc returns; the submitted request will finish.",
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
