//! TUI editor for the OpenAI-compatible title-selection service.
use super::text_input::Input;
use super::{choice, line, retrieval_action, t, KeyCode, Line};
use anyhow::{anyhow, Result};
use crossterm::event::{KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Instant;

pub(super) struct Form {
    values: [Input; 3],
    field: usize,
    error: String,
    saving: Option<(Instant, Receiver<Result<(), String>>)>,
}

pub(super) fn base() -> String {
    respire::service::read_agent_config()["recall_api_base"]
        .as_str()
        .map(str::to_owned)
        .or_else(respire::keystore::load_ds_last_base)
        .unwrap_or_else(|| crate::classify::DEFAULT_DS_BASE.to_owned())
}

fn key_for(base: &str) -> Option<String> {
    respire::env::var("RSRS_RECALL_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .or_else(|| {
            respire::keystore::load_classify_key(&format!(
                "ds@{}",
                respire::keystore::host_of(base)
            ))
        })
}

pub(super) fn ready() -> bool {
    key_for(&base()).is_some()
}

impl Form {
    pub(super) fn new() -> Self {
        let config = respire::service::read_agent_config();
        let values = [
            base(),
            config["recall_model"]
                .as_str()
                .unwrap_or(crate::classify::DEFAULT_DS_MODEL)
                .to_owned(),
            String::new(),
        ];
        Self {
            values: values.map(Input::new),
            field: 0,
            error: String::new(),
            saving: None,
        }
    }

    pub(super) fn paste(&mut self, text: &str) {
        if self.field < 3 && !self.saving() {
            self.values[self.field].paste(text);
        }
    }

    pub(super) fn key(&mut self, key: KeyEvent) {
        if self.saving.is_some() {
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('s' | 'S'))
        {
            self.start_save();
            return;
        }
        match key.code {
            KeyCode::Tab | KeyCode::Down => self.field = (self.field + 1) % 4,
            KeyCode::BackTab | KeyCode::Up => self.field = (self.field + 3) % 4,
            KeyCode::Enter if self.field < 3 => self.field += 1,
            KeyCode::Enter => self.start_save(),
            _ if self.field < 3 => self.values[self.field].key(key),
            _ => {}
        }
    }

    fn start_save(&mut self) {
        let values = std::array::from_fn(|index| self.values[index].text.clone());
        let (sender, receiver) = mpsc::channel();
        self.saving = Some((Instant::now(), receiver));
        self.error.clear();
        std::thread::spawn(move || {
            let _ = sender.send(Self::save(&values).map_err(|error| error.to_string()));
        });
    }

    pub(super) fn saving(&self) -> bool {
        self.saving.is_some()
    }

    pub(super) fn poll_saved(&mut self) -> bool {
        let Some((_, receiver)) = &self.saving else {
            return false;
        };
        let result = match receiver.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return false,
            Err(TryRecvError::Disconnected) => Err(t(
                "配置保存线程中断",
                "Configuration save worker disconnected",
            )),
        };
        self.saving = None;
        match result {
            Ok(()) => true,
            Err(error) => {
                self.error = error;
                false
            }
        }
    }

    fn save(values: &[String; 3]) -> Result<()> {
        let base = values[0].trim().trim_end_matches('/');
        let model = values[1].trim();
        let key = values[2].trim();
        let host = base
            .split_once("://")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(""));
        anyhow::ensure!(
            (base.starts_with("https://") || base.starts_with("http://"))
                && host.is_some_and(|host| !host.is_empty() && !host.contains('@'))
                && !base.chars().any(char::is_whitespace)
                && !base.contains(['?', '#']),
            "{}",
            t(
                "请输入有效的 http(s) API 地址，不要在地址中放密钥",
                "Enter an http(s) API base without credentials, query or fragment"
            )
        );
        anyhow::ensure!(
            !model.is_empty(),
            "{}",
            t("模型名不能为空", "Model name is required")
        );
        anyhow::ensure!(
            !key.is_empty() || key_for(base).is_some(),
            "{}",
            t(
                "请输入此地址的 API Key",
                "API key is required for this endpoint"
            )
        );
        if !key.is_empty() {
            respire::keystore::save_classify_key(
                &format!("ds@{}", respire::keystore::host_of(base)),
                key,
            )?;
        }
        for (name, value) in [("recall_api_base", base), ("recall_model", model)] {
            retrieval_action(&["agent-config", "--set", &format!("{name}={value}")])
                .map_err(|e| anyhow!(e))?;
        }
        Ok(())
    }

    pub(super) fn draw(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default().borders(Borders::ALL).title(t(
            "高质量召回 API（OpenAI 兼容）",
            "High-quality recall API (OpenAI compatible)",
        ));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let regions = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .split(inner);
        for (index, label) in ["API Base URL", "Model", "API Key"].iter().enumerate() {
            let active = self.field == index;
            let block = Block::default()
                .borders(Borders::ALL)
                .title(*label)
                .border_style(if active {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default()
                });
            frame.render_widget(
                Paragraph::new(self.values[index].line(
                    regions[index].width.saturating_sub(2) as usize,
                    active,
                    index == 2,
                ))
                .block(block),
                regions[index],
            );
        }
        let mut lines: Vec<Line<'static>> = vec![choice(
            self.field == 3,
            t("[ 保存配置 ]", "[ Save configuration ]"),
        )];
        lines.push(line(t(
            "密钥留空保留该地址已有密钥；新密钥存入系统凭据库。",
            "Leave key blank to retain this endpoint's key; new keys use the OS keyring.",
        )));
        lines.push(line(t(
            "查询和候选标题会发送到此服务。保存后仍需选择高质量模式。",
            "Queries and candidate titles go to this service. Select High quality after saving.",
        )));
        lines.push(line(t(
            "Ctrl+A 全选，Ctrl+U 清空，Ctrl+S 保存；测试入口在模型页。",
            "Ctrl+A selects all, Ctrl+U clears, Ctrl+S saves; test recall from the model page.",
        )));
        if !self.error.is_empty() {
            lines.push(super::fail_line(self.error.clone()));
        }
        if let Some((started, _)) = &self.saving {
            lines.push(line(format!(
                "{} {}s",
                t("正在保存配置", "Saving configuration"),
                started.elapsed().as_secs()
            )));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), regions[3]);
    }
}
