//! Default screen when `rsrs` is started with no command in a terminal.
//!
//! The home page polls the resident runtime. Keys are only arrows, digits,
//! Enter, and Space. Backspace is accepted only while a server address is
//! being typed, because a typo otherwise cannot be corrected.

use std::io::{stdout, Stdout};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
};
use serde_json::Value;

use crate::i18n::{self, Lang};

mod model_task;
mod recall_api;
mod recall_test;
mod text_input;

const FAST: Duration = Duration::from_millis(250);
const SLOW: Duration = Duration::from_secs(5);

enum Page {
    Home,
    Accounts,
    Server,
    Inject,
    Sync,
    Model,
    Workspace,
    Lang,
    Version,
    Web,
}

enum ConfirmKind {
    Switch(String),
    Sync,
    InstallBge,
    UninstallBge,
    InstallRerank,
    UninstallRerank,
    Engine(String),
    InstallEngines,
    ProbeEngine,
    RecallMode(String),
    UpgradeM3,
    LegacyModel,
    Workspace(String),
    Autosync(bool),
    Update(String, String),
}

enum Overlay {
    None,
    RecallApi(recall_api::Form),
    RecallTest(recall_test::Form),
    ModelTask(model_task::Task),
    Confirm {
        text: String,
        cursor: usize,
        kind: ConfirmKind,
    },
    Edit {
        buf: String,
        cursor: usize,
    },
}

struct InjectRow {
    id: String,
    name: String,
    state: String,
    seen: bool,
    checked: bool,
}

struct AccountRow {
    name: String,
    user: String,
    current: bool,
}

struct Live {
    connected: bool,
    error: String,
    notice: String,
    user: String,
    addr: String,
    autosync: bool,
    workspace: String,
    local_alive: u64,
    local_total: u64,
    phase: String,
    pulled: u64,
    pushed: u64,
    remote_alive: u64,
    conflicts: i64,
    pending: i64,
    pid: u32,
    url: String,
    doctor: Vec<(String, String, String)>,
    inject: Vec<InjectRow>,
    accounts: Vec<AccountRow>,
    fresh: usize,
    stale: usize,
    missing: usize,
    ver_line: String,
    update_spec: String,
}

struct App {
    page: Page,
    cursor: usize,
    overlay: Overlay,
    live: Live,
    workspace_draft: usize,
    autosync_draft: bool,
    manager_pick: usize,
    shared: Arc<Mutex<Live>>,
    outcome: Arc<Mutex<Option<String>>>,
}

// Odd revisions mean a write is in flight; changed revisions invalidate old reads.
static INJECT_REVISION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin())
        || !std::io::IsTerminal::is_terminal(&std::io::stdout())
    {
        anyhow::bail!(i18n::text("need_tty"));
    }
    enable_raw_mode()?;
    let mut terminal = match setup() {
        Ok(terminal) => terminal,
        Err(error) => {
            disable_raw_mode()?;
            return Err(error);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Mutex::new(Live::empty()));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_loop(worker_stop, worker_shared));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_details_loop(worker_stop, worker_shared));
    let mut app = App::new(Arc::clone(&shared));
    let result = loop {
        if let Overlay::RecallTest(form) = &mut app.overlay {
            form.poll();
        }
        let api_saved = match &mut app.overlay {
            Overlay::RecallApi(form) => form.poll_saved(),
            _ => false,
        };
        if api_saved {
            app.overlay = Overlay::None;
            app.set_notice(t(
                "API 配置已保存；选择高质量模式后生效",
                "API saved; select High quality to enable it",
            ));
        }
        if let Ok(mut slot) = app.outcome.lock() {
            if let Some(message) = slot.take() {
                app.overlay = Overlay::None;
                app.set_notice(message);
            }
        }
        if let Ok(guard) = shared.lock() {
            app.live = guard.clone();
        }
        if let Err(error) = terminal.draw(|frame| draw(frame, &app)) {
            break Err(error);
        }
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        let event = event::read()?;
        if let Event::Paste(text) = &event {
            match &mut app.overlay {
                Overlay::RecallApi(form) => form.paste(text),
                Overlay::RecallTest(form) => form.paste(text),
                _ => {}
            }
        }
        let Event::Key(key) = event else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Overlay::RecallApi(form) = &mut app.overlay {
            if key.code == KeyCode::Esc && !form.saving() {
                app.overlay = Overlay::None;
            } else {
                form.key(key);
            }
            continue;
        }
        if let Overlay::RecallTest(form) = &mut app.overlay {
            if key.code == KeyCode::Esc {
                app.overlay = Overlay::None;
            } else {
                form.key(key);
            }
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            || key.modifiers.contains(KeyModifiers::ALT)
        {
            continue;
        }
        if handle(&mut app, key.code) {
            break Ok(());
        }
    };
    stop.store(true, Ordering::Relaxed);
    restore(&mut terminal)?;
    disable_raw_mode()?;
    result.map_err(anyhow::Error::from)
}

impl Live {
    fn empty() -> Self {
        Self {
            connected: false,
            error: String::new(),
            notice: String::new(),
            user: String::new(),
            addr: String::new(),
            autosync: true,
            workspace: "normal".to_owned(),
            local_alive: 0,
            local_total: 0,
            phase: "idle".to_owned(),
            pulled: 0,
            pushed: 0,
            remote_alive: 0,
            conflicts: 0,
            pending: 0,
            pid: 0,
            url: String::new(),
            doctor: Vec::new(),
            inject: Vec::new(),
            accounts: Vec::new(),
            fresh: 0,
            stale: 0,
            missing: 0,
            ver_line: String::new(),
            update_spec: String::new(),
        }
    }

    fn clone(&self) -> Self {
        Self {
            connected: self.connected,
            error: self.error.clone(),
            notice: self.notice.clone(),
            user: self.user.clone(),
            addr: self.addr.clone(),
            autosync: self.autosync,
            workspace: self.workspace.clone(),
            local_alive: self.local_alive,
            local_total: self.local_total,
            phase: self.phase.clone(),
            pulled: self.pulled,
            pushed: self.pushed,
            remote_alive: self.remote_alive,
            conflicts: self.conflicts,
            pending: self.pending,
            pid: self.pid,
            url: self.url.clone(),
            doctor: self.doctor.clone(),
            inject: self.inject.iter().map(InjectRow::clone_row).collect(),
            accounts: self.accounts.iter().map(AccountRow::clone_row).collect(),
            fresh: self.fresh,
            stale: self.stale,
            missing: self.missing,
            ver_line: self.ver_line.clone(),
            update_spec: self.update_spec.clone(),
        }
    }
}

impl InjectRow {
    fn clone_row(&self) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            state: self.state.clone(),
            seen: self.seen,
            checked: self.checked,
        }
    }
}

impl AccountRow {
    fn clone_row(&self) -> Self {
        Self {
            name: self.name.clone(),
            user: self.user.clone(),
            current: self.current,
        }
    }
}

impl App {
    fn new(shared: Arc<Mutex<Live>>) -> Self {
        Self {
            page: Page::Home,
            cursor: 0,
            overlay: Overlay::None,
            live: Live::empty(),
            workspace_draft: 0,
            autosync_draft: true,
            manager_pick: 0,
            shared,
            outcome: Arc::new(Mutex::new(None)),
        }
    }

    fn set_notice(&self, text: impl Into<String>) {
        if let Ok(mut guard) = self.shared.lock() {
            guard.notice = text.into();
        }
    }
}

fn zh() -> bool {
    i18n::lang() == Lang::Zh
}

fn t(zh_text: &str, en_text: &str) -> String {
    if zh() {
        zh_text.to_owned()
    } else {
        en_text.to_owned()
    }
}

fn rpc(args: &[&str]) -> Result<Value, String> {
    let owned: Vec<String> = args.iter().copied().map(str::to_owned).collect();
    crate::rpc::query_json(owned).map_err(|err| format!("{err:#}"))
}

fn retrieval_action(args: &[&str]) -> Result<Value, String> {
    let result = rpc(args)?;
    if matches!(result["status"].as_str(), Some("ok" | "skip")) {
        return Ok(result);
    }
    let errors = result["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("; ");
    if errors.contains("model operation cancelled") {
        return Err(t(
            "已取消；当前索引保持不变",
            "Cancelled; current index unchanged",
        ));
    }
    Err(errors)
}

fn refresh_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let mut next = Live::empty();
        if let Some((pid, url)) = crate::rpc::runtime_brief() {
            next.pid = pid;
            next.url = url;
        }
        match rpc(&["status"]) {
            Ok(envelope) if envelope["status"] == "ok" => {
                let summary = &envelope["summary"];
                next.connected = true;
                next.user = summary["session"]["user"].as_str().unwrap_or("").to_owned();
                next.addr = summary["server_addr"].as_str().unwrap_or("").to_owned();
                next.autosync = summary["autosync"].as_bool().unwrap_or(true);
                next.workspace = summary["workspace"].as_str().unwrap_or("normal").to_owned();
                next.local_alive = summary["local_alive"].as_u64().unwrap_or(0);
                next.local_total = summary["local_total"].as_u64().unwrap_or(0);
                let live = &summary["sync_live"];
                next.phase = live["phase"].as_str().unwrap_or("idle").to_owned();
                next.pulled = live["pulled"].as_u64().unwrap_or(0);
                next.pushed = live["pushed"].as_u64().unwrap_or(0);
                next.remote_alive = live["remote_alive"].as_u64().unwrap_or(0);
                next.conflicts = live["conflicts"].as_i64().unwrap_or(0);
                next.pending = live["pending"].as_i64().unwrap_or(0);
                if next.phase == "err" {
                    next.error = live["error"].as_str().unwrap_or("").to_owned();
                }
            }
            Ok(envelope) => next.error = envelope["errors"].to_string(),
            Err(error) => {
                next.connected = false;
                next.error = error;
            }
        }
        if let Ok(mut guard) = shared.lock() {
            next.notice = guard.notice.clone();
            next.ver_line = guard.ver_line.clone();
            next.update_spec = guard.update_spec.clone();
            next.inject = guard.inject.iter().map(InjectRow::clone_row).collect();
            next.accounts = guard.accounts.iter().map(AccountRow::clone_row).collect();
            next.doctor = guard.doctor.clone();
            next.fresh = guard.fresh;
            next.stale = guard.stale;
            next.missing = guard.missing;
            *guard = next;
        }
        std::thread::sleep(FAST.saturating_sub(started.elapsed()));
    }
}

fn refresh_details_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    let mut slow_at = Instant::now() - SLOW;
    while !stop.load(Ordering::Relaxed) {
        let ready = shared.lock().map(|live| live.connected).unwrap_or(false);
        if !ready || slow_at.elapsed() < SLOW {
            std::thread::sleep(FAST);
            continue;
        }
        slow_at = Instant::now();
        let mut next = match shared.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        if let Ok(envelope) = rpc(&["account", "list"]) {
            if let Some(rows) = envelope["details"]["accounts"].as_array() {
                next.accounts.clear();
                for row in rows {
                    next.accounts.push(AccountRow {
                        name: row["name"].as_str().unwrap_or("").to_owned(),
                        user: row["user"].as_str().unwrap_or("").to_owned(),
                        current: row["current"].as_bool().unwrap_or(false),
                    });
                }
            }
        }
        let revision = INJECT_REVISION.load(Ordering::Acquire);
        if revision % 2 == 0 {
            if let Ok(rows) = read_inject_rows() {
                if let Ok(mut guard) = shared.lock() {
                    if INJECT_REVISION.load(Ordering::Acquire) == revision {
                        set_inject_rows(&mut guard, rows);
                    }
                }
            }
        }

        if let Ok(envelope) = rpc(&["doctor"]) {
            next.doctor.clear();
            if let Some(items) = envelope["items"].as_array() {
                for item in items {
                    next.doctor.push((
                        item["name"].as_str().unwrap_or("").to_owned(),
                        item["status"].as_str().unwrap_or("").to_owned(),
                        item["value"].as_str().unwrap_or("").to_owned(),
                    ));
                }
            }
        }
        if let Ok(mut guard) = shared.lock() {
            guard.accounts = next.accounts;
            guard.doctor = next.doctor;
        }
    }
}

fn handle(app: &mut App, code: KeyCode) -> bool {
    if let Overlay::ModelTask(task) = &app.overlay {
        if matches!(code, KeyCode::Esc | KeyCode::Char('c' | 'C')) {
            task.cancel.store(true, Ordering::Release);
        }
        return false;
    }
    if code == KeyCode::Esc {
        if !matches!(app.overlay, Overlay::None) {
            app.overlay = Overlay::None;
            return false;
        }
        return go_back(app);
    }
    if code == KeyCode::Char('7') && !matches!(app.overlay, Overlay::Edit { .. }) {
        toggle_lang(app);
        return false;
    }
    if !app.live.connected {
        return code == KeyCode::Char('0');
    }
    if matches!(app.overlay, Overlay::Edit { .. }) {
        return edit_key(app, code);
    }
    if matches!(app.overlay, Overlay::Confirm { .. }) {
        return confirm_key(app, code);
    }
    match app.page {
        Page::Home => home_key(app, code),
        Page::Accounts => list_key(app, code, app.live.accounts.len(), |app, code| {
            account_key(app, code)
        }),
        Page::Server => server_key(app, code),
        Page::Inject => list_key(app, code, app.live.inject.len() + 2, |app, code| {
            inject_key(app, code)
        }),
        Page::Sync => sync_key(app, code),
        Page::Model => list_key(
            app,
            code,
            12 + model_engines().len() + usize::from(cfg!(windows)),
            |app, code| model_key(app, code),
        ),
        Page::Workspace => workspace_key(app, code),
        Page::Lang => list_key(app, code, 2, |app, code| lang_key(app, code)),
        Page::Version => version_key(app, code),
        Page::Web => web_key(app, code),
    }
}

fn go_back(app: &mut App) -> bool {
    if matches!(app.page, Page::Home) {
        return true;
    }
    app.page = Page::Home;
    false
}

fn toggle_lang(app: &mut App) {
    let next = if zh() { Lang::En } else { Lang::Zh };
    match i18n::set_lang(next) {
        Ok(()) => app.set_notice(t("语言已切换", "Language saved")),
        Err(error) => app.set_notice(error.to_string()),
    }
}

fn home_key(app: &mut App, code: KeyCode) -> bool {
    let n = 10;
    match code {
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(n - 1),
        KeyCode::Char('0') => return true,
        KeyCode::Char(ch) if ch.is_ascii_digit() => {
            let number = (ch as u8 - b'0') as usize;
            if (1..=9).contains(&number) {
                open_home(app, number - 1);
            }
        }
        KeyCode::Enter if app.cursor == 9 => return true,
        KeyCode::Enter => open_home(app, app.cursor),
        _ => {}
    }
    false
}

fn open_home(app: &mut App, index: usize) {
    app.cursor = 0;
    app.workspace_draft = match app.live.workspace.as_str() {
        "readonly" => 1,
        "off" => 2,
        _ => 0,
    };
    app.autosync_draft = app.live.autosync;
    app.page = match index {
        0 => Page::Accounts,
        1 => Page::Server,
        2 => Page::Inject,
        3 => Page::Sync,
        4 => Page::Model,
        5 => Page::Workspace,
        6 => Page::Lang,
        7 => Page::Version,
        _ => Page::Web,
    };
}

fn list_key(
    app: &mut App,
    code: KeyCode,
    content: usize,
    mut on_enter: impl FnMut(&mut App, KeyCode),
) -> bool {
    let total = content + 1;
    match code {
        KeyCode::Char('0') => {
            app.page = Page::Home;
            false
        }
        KeyCode::Up => {
            app.cursor = app.cursor.saturating_sub(1);
            false
        }
        KeyCode::Down => {
            if total > 0 {
                app.cursor = (app.cursor + 1).min(total - 1);
            }
            false
        }
        KeyCode::Enter if app.cursor == content => {
            app.page = Page::Home;
            false
        }
        other if app.cursor < content => {
            on_enter(app, other);
            false
        }
        _ => false,
    }
}

fn account_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Enter {
        return;
    }
    let Some(row) = app.live.accounts.get(app.cursor) else {
        return;
    };
    if row.current {
        app.set_notice(t("已经是当前账户", "Already the active account"));
        return;
    }
    let name = row.name.clone();
    ask(
        app,
        t(
            &format!("切换到账户 {name}？",),
            &format!("Switch to account {name}?"),
        ),
        ConfirmKind::Switch(name),
    );
}

fn server_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            app.overlay = Overlay::Edit {
                buf: app.live.addr.clone(),
                cursor: app.live.addr.chars().count(),
            };
        }
        _ => {}
    }
    false
}

fn inject_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Char(' ') && code != KeyCode::Enter {
        return;
    }
    if INJECT_REVISION.load(Ordering::Acquire) % 2 != 0 {
        return;
    }
    let batch = app.cursor < 2;
    let remove = app.cursor == 1;
    let selected = if batch {
        app.live
            .inject
            .iter()
            .filter(|row| row.checked)
            .collect::<Vec<_>>()
    } else {
        app.live.inject.get(app.cursor - 2).into_iter().collect()
    };
    let ids: Vec<(String, bool)> = selected
        .iter()
        .map(|row| (row.id.clone(), if batch { remove } else { row.checked }))
        .collect();
    if ids.is_empty() {
        app.set_notice(t("没有已安装的提示词", "No installed prompts"));
        return;
    }
    INJECT_REVISION.fetch_add(1, Ordering::AcqRel);
    app.set_notice(t("正在处理提示词", "Updating prompts"));
    let slot = Arc::clone(&app.outcome);
    let shared = Arc::clone(&app.shared);
    std::thread::spawn(move || {
        let mut succeeded = 0;
        let mut errors = Vec::new();
        for (id, remove) in &ids {
            let result = if *remove {
                rpc(&["inject", "--remove", "--id", id])
            } else {
                rpc(&["inject", "--id", id])
            }
            .and_then(inject_result);
            match result {
                Ok(_) => succeeded += 1,
                Err(error) => errors.push(format!("{id}: {error}")),
            }
        }
        match read_inject_rows() {
            Ok(rows) => {
                if let Ok(mut guard) = shared.lock() {
                    set_inject_rows(&mut guard, rows);
                }
            }
            Err(error) => errors.push(error),
        }
        let mut message = t(
            &format!("提示词处理完成：成功 {succeeded}/{}", ids.len()),
            &format!("Prompts finished: {succeeded}/{} succeeded", ids.len()),
        );
        if !errors.is_empty() {
            message.push_str(&format!("; {}", errors.join("; ")));
        }
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
        INJECT_REVISION.fetch_add(1, Ordering::Release);
    });
}

fn inject_result(envelope: Value) -> Result<Value, String> {
    if envelope["status"] != "ok" {
        return Err(envelope["errors"].to_string());
    }
    Ok(envelope)
}

fn read_inject_rows() -> Result<Vec<InjectRow>, String> {
    let envelope = inject_result(rpc(&["inject", "--targets"])?)?;
    let rows = envelope["details"]
        .as_array()
        .ok_or("Missing inject targets")?;
    Ok(rows
        .iter()
        .map(|row| {
            let state = row["state"].as_str().unwrap_or("").to_owned();
            InjectRow {
                checked: state == "fresh" || state == "stale",
                id: row["id"].as_str().unwrap_or("").to_owned(),
                name: row["name"].as_str().unwrap_or("").to_owned(),
                seen: row["likely_installed"].as_bool().unwrap_or(false),
                state,
            }
        })
        .collect())
}

fn set_inject_rows(live: &mut Live, rows: Vec<InjectRow>) {
    live.fresh = rows.iter().filter(|row| row.state == "fresh").count();
    live.stale = rows.iter().filter(|row| row.state == "stale").count();
    live.missing = rows.len() - live.fresh - live.stale;
    live.inject = rows;
}

fn sync_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(2),
        KeyCode::Left | KeyCode::Right if app.cursor == 1 => {
            app.autosync_draft = !app.autosync_draft
        }
        KeyCode::Enter if app.cursor == 2 => app.page = Page::Home,
        KeyCode::Enter if app.cursor == 0 => ask(
            app,
            t("现在同步一次？", "Sync once now?"),
            ConfirmKind::Sync,
        ),
        KeyCode::Enter if app.cursor == 1 => {
            let on = app.autosync_draft;
            ask(
                app,
                t(
                    if on {
                        "打开自动同步？"
                    } else {
                        "关闭自动同步？"
                    },
                    if on {
                        "Turn auto-sync on?"
                    } else {
                        "Turn auto-sync off?"
                    },
                ),
                ConfirmKind::Autosync(on),
            );
        }
        _ => {}
    }
    false
}

fn model_engines() -> &'static [&'static str] {
    if cfg!(any(windows, target_os = "macos")) {
        &["cpu", "gpu", "npu"]
    } else {
        &["cpu"]
    }
}

fn model_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Enter {
        return;
    }
    match app.cursor {
        0 => ask(
            app,
            t(
                "安装或校验 BGE？已存在则跳过。",
                "Install or verify BGE? An existing model is skipped.",
            ),
            ConfirmKind::InstallBge,
        ),
        1 => ask(
            app,
            t(
                "卸载 BGE 并删除模型文件？卸载后 recall 需要重新安装。",
                "Uninstall BGE and delete its files? Recall will need a reinstall.",
            ),
            ConfirmKind::UninstallBge,
        ),
        2 => ask(
            app,
            t(
                "安装可选精排模型？体积大约 280MB。",
                "Install the optional rerank model? About 280MB.",
            ),
            ConfirmKind::InstallRerank,
        ),
        3 => ask(
            app,
            t(
                "卸载精排模型并删除文件？卸载后 recall 仍可用，只是不再精排。",
                "Uninstall the rerank model and delete its files? Recall still works without it.",
            ),
            ConfirmKind::UninstallRerank,
        ),
        cursor => {
            let engines = model_engines();
            if let Some(engine) = cursor.checked_sub(4).and_then(|index| engines.get(index)) {
                run_confirm(app, ConfirmKind::Engine((*engine).to_owned()));
            } else if cfg!(windows) && cursor == 4 + engines.len() {
                ask(
                    app,
                    t(
                        "通过 Windows ML 下载兼容的 NPU 推理引擎？",
                        "Download compatible NPU providers through Windows ML?",
                    ),
                    ConfirmKind::InstallEngines,
                );
            } else if cursor == 4 + engines.len() + usize::from(cfg!(windows)) {
                run_confirm(app, ConfirmKind::ProbeEngine);
            } else {
                let index = 5 + engines.len() + usize::from(cfg!(windows));
                match cursor.checked_sub(index) {
                    Some(0) => run_confirm(app, ConfirmKind::RecallMode("fast".to_owned())),
                    Some(1) if !recall_api::ready() => {
                        app.overlay = Overlay::RecallApi(recall_api::Form::new());
                        app.set_notice(t("请先配置高质量召回 API", "Configure the recall API first"));
                    }
                    Some(1) => ask(
                        app,
                        t(
                            "启用高质量召回？查询和候选标题将发送到已配置的模型服务；失败时退回本地结果。",
                            "Enable high-quality recall? Queries and candidate titles go to your configured model service; failures use local results.",
                        ),
                        ConfirmKind::RecallMode("quality".to_owned()),
                    ),
                    Some(2) => ask(
                        app,
                        t(
                            "下载 BGE-M3 并重建索引？约 1.15GB，完成前保留旧索引。",
                            "Download BGE-M3 and rebuild the index? About 1.15GB. The old index remains until complete.",
                        ),
                        ConfirmKind::UpgradeM3,
                    ),
                    Some(3) => ask(
                        app,
                        t("重建并切回旧版 BGE 索引？", "Rebuild and return to the legacy BGE index?"),
                        ConfirmKind::LegacyModel,
                    ),
                    Some(4) => app.overlay = Overlay::RecallApi(recall_api::Form::new()),
                    Some(5) => app.overlay = Overlay::RecallTest(recall_test::Form::new("fast")),
                    Some(6) => app.overlay = Overlay::RecallTest(recall_test::Form::new("quality")),
                    _ => {}
                }
            }
        }
    }
}

fn workspace_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Left if app.cursor == 0 => {
            app.workspace_draft = app.workspace_draft.saturating_sub(1)
        }
        KeyCode::Right if app.cursor == 0 => app.workspace_draft = (app.workspace_draft + 1).min(2),
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            let mode = ["normal", "readonly", "off"][app.workspace_draft];
            ask(
                app,
                t(
                    &format!("把工作区改成 {mode}？"),
                    &format!("Change the workspace to {mode}?"),
                ),
                ConfirmKind::Workspace(mode.to_owned()),
            );
        }
        _ => {}
    }
    false
}

fn version_key(app: &mut App, code: KeyCode) -> bool {
    let tools = tools_on_path();
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = app.cursor.saturating_sub(1),
        KeyCode::Down => app.cursor = (app.cursor + 1).min(2),
        KeyCode::Left if app.cursor == 1 && !tools.is_empty() => {
            app.manager_pick = app.manager_pick.saturating_sub(1);
        }
        KeyCode::Right if app.cursor == 1 && !tools.is_empty() => {
            app.manager_pick = (app.manager_pick + 1).min(tools.len() - 1);
        }
        KeyCode::Enter if app.cursor == 2 => app.page = Page::Home,
        KeyCode::Enter if app.cursor == 0 => check_versions(app),
        KeyCode::Enter => {
            let Some(manager) = tools.get(app.manager_pick).copied() else {
                app.set_notice(t(
                    "没有找到 npm、pnpm、yarn 或 bun",
                    "npm, pnpm, yarn, and bun were not found",
                ));
                return false;
            };
            if matches!(manager, Manager::Direct) {
                app.set_notice(t(
                    "当前窗口是直接运行的程序，包管理器更新不会换掉这个窗口",
                    "This window is a direct binary. A package-manager update will not replace it",
                ));
                return false;
            }
            let spec = if app.live.update_spec.is_empty() {
                channel_spec()
            } else {
                app.live.update_spec.clone()
            };
            ask(
                app,
                t(
                    &format!("用 {} 更新到 {spec}？", manager_name(manager)),
                    &format!("Update to {spec} with {}?", manager_name(manager)),
                ),
                ConfirmKind::Update(manager_name(manager).to_owned(), spec),
            );
        }
        _ => {}
    }
    false
}

fn lang_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('1') => app.cursor = 0,
        KeyCode::Char('2') => app.cursor = 1,
        KeyCode::Enter => {
            let lang = if app.cursor == 0 { Lang::Zh } else { Lang::En };
            match i18n::set_lang(lang) {
                Ok(()) => app.set_notice(t("语言已切换", "Language saved")),
                Err(error) => app.set_notice(error.to_string()),
            }
        }
        _ => {}
    }
}

fn ask(app: &mut App, text: String, kind: ConfirmKind) {
    app.overlay = Overlay::Confirm {
        text,
        cursor: 1,
        kind,
    };
}

fn confirm_key(app: &mut App, code: KeyCode) -> bool {
    let Overlay::Confirm { cursor, .. } = &mut app.overlay else {
        return false;
    };
    match code {
        KeyCode::Up | KeyCode::Left | KeyCode::Char('1') => *cursor = 0,
        KeyCode::Down | KeyCode::Right | KeyCode::Char('2') => *cursor = 1,
        KeyCode::Enter if *cursor == 1 => app.overlay = Overlay::None,
        KeyCode::Enter => {
            let kind = match std::mem::replace(&mut app.overlay, Overlay::None) {
                Overlay::Confirm { kind, .. } => kind,
                other => {
                    app.overlay = other;
                    return false;
                }
            };
            run_confirm(app, kind);
        }
        KeyCode::Char('0') => app.overlay = Overlay::None,
        _ => {}
    }
    false
}

fn run_confirm(app: &mut App, kind: ConfirmKind) {
    let task = matches!(
        &kind,
        ConfirmKind::InstallBge
            | ConfirmKind::InstallRerank
            | ConfirmKind::UpgradeM3
            | ConfirmKind::LegacyModel
    )
    .then(model_task::Task::start);
    let cancel = task.as_ref().map(|task| Arc::clone(&task.cancel));
    let task_id = task
        .as_ref()
        .map(|task| task.id.clone())
        .unwrap_or_default();
    if let Some(task) = task {
        app.overlay = Overlay::ModelTask(task);
    }
    let label = match &kind {
        ConfirmKind::Switch(name) => t(
            &format!("正在切换到 {name}"),
            &format!("Switching to {name}"),
        ),
        ConfirmKind::Sync => t("正在同步", "Syncing"),
        ConfirmKind::InstallBge => t("正在安装或校验 BGE", "Installing or verifying BGE"),
        ConfirmKind::UninstallBge => t("正在卸载 BGE", "Uninstalling BGE"),
        ConfirmKind::InstallRerank => t("正在安装精排模型", "Installing the rerank model"),
        ConfirmKind::UninstallRerank => t("正在卸载精排模型", "Uninstalling the rerank model"),
        ConfirmKind::Engine(_) => t("正在保存推理引擎", "Saving inference engine"),
        ConfirmKind::InstallEngines => t("正在下载 NPU 推理引擎", "Downloading NPU providers"),
        ConfirmKind::ProbeEngine => t("正在验证推理引擎", "Checking inference engine"),
        ConfirmKind::RecallMode(_) => t("正在保存召回模式", "Saving recall mode"),
        ConfirmKind::UpgradeM3 => t(
            "正在下载 M3 并重建索引，请等待完成",
            "Downloading M3 and rebuilding the index; please wait",
        ),
        ConfirmKind::LegacyModel => t("正在恢复旧版模型索引", "Restoring the legacy model index"),
        ConfirmKind::Workspace(_) => t("正在切换工作区", "Changing workspace"),
        ConfirmKind::Autosync(_) => t("正在保存自动同步", "Saving auto-sync"),
        ConfirmKind::Update(tool, spec) => t(
            &format!("正在用 {tool} 更新 {spec}"),
            &format!("Updating {spec} with {tool}"),
        ),
    };
    app.set_notice(label);
    let slot = Arc::clone(&app.outcome);
    std::thread::spawn(move || {
        let model_action = |action: &[&str]| {
            if cancel
                .as_ref()
                .is_some_and(|flag| flag.load(Ordering::Acquire))
            {
                return Err(t(
                    "已取消，当前索引保持不变",
                    "Cancelled; current index unchanged",
                ));
            }
            let mut args = action.to_vec();
            args.extend(["--model-task-id", &task_id]);
            retrieval_action(&args)
        };
        let result = match kind {
            ConfirmKind::Switch(name) => {
                rpc(&["account", "use", &name]).map(|_| t("已切换账户", "Account switched"))
            }
            ConfirmKind::Sync => rpc(&["sync"]).map(|value| sync_notice(&value)),
            ConfirmKind::InstallBge => model_action(&["model", "install-bge"])
                .map(|_| t("BGE 处理结束", "BGE step finished")),
            ConfirmKind::UninstallBge => {
                rpc(&["model", "uninstall-bge"]).map(|_| t("BGE 已卸载", "BGE uninstalled"))
            }
            ConfirmKind::InstallRerank => model_action(&["model", "install-rerank"])
                .map(|_| t("精排模型处理结束", "Rerank step finished")),
            ConfirmKind::UninstallRerank => rpc(&["model", "uninstall-rerank"])
                .map(|_| t("精排模型已卸载", "Rerank uninstalled")),
            ConfirmKind::Engine(engine) => rpc(&["model", "engine", &engine]).map(|_| {
                t(
                    "推理引擎已保存，下次加载模型生效",
                    "Engine saved; applies on next model load",
                )
            }),
            ConfirmKind::RecallMode(mode) => {
                retrieval_action(&["agent-config", "--set", &format!("recall_mode={mode}")]).map(
                    |_| {
                        t(
                            "召回模式已保存，下次查询生效",
                            "Recall mode saved; applies to the next query",
                        )
                    },
                )
            }
            ConfirmKind::UpgradeM3 => model_action(&["model", "install-m3"])
                .and_then(|_| {
                    if cancel
                        .as_ref()
                        .is_some_and(|flag| flag.load(Ordering::Acquire))
                    {
                        return Err(t(
                            "已取消，当前索引保持不变",
                            "Cancelled; current index unchanged",
                        ));
                    }
                    model_action(&["model", "activate", "m3"])
                })
                .map(|_| {
                    t(
                        "BGE-M3 和分块索引已启用",
                        "BGE-M3 and chunked retrieval are active",
                    )
                }),
            ConfirmKind::LegacyModel => model_action(&["model", "activate", "legacy"])
                .map(|_| t("旧版模型索引已恢复", "Legacy model index restored")),
            ConfirmKind::InstallEngines => rpc(&["model", "install-engines"]).map(|v| {
                format!(
                    "{}: {}",
                    t("推理引擎", "Providers"),
                    v["summary"]["providers"]
                )
            }),
            ConfirmKind::ProbeEngine => rpc(&["model", "probe"]).map(|v| {
                let result = &v["summary"];
                format!(
                    "{}: {}  {} ms",
                    t("验证通过", "Verified"),
                    result["selected"].as_str().unwrap_or("unknown"),
                    result["elapsed_ms"]
                )
            }),
            ConfirmKind::Workspace(mode) => set_workspace(&mode),
            ConfirmKind::Autosync(on) => {
                let flag = if on { "true" } else { "false" };
                rpc(&["config", "--autosync", flag]).map(|_| t("自动同步已保存", "Auto-sync saved"))
            }
            ConfirmKind::Update(tool, spec) => run_package_update(&tool, &spec),
        };
        let message = match result {
            Ok(text) => text,
            Err(error) => error,
        };
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
    });
}

fn set_workspace(mode: &str) -> Result<String, String> {
    match mode {
        "normal" => {
            rpc(&["agent-config", "--set", "memory_off=false"])?;
            rpc(&["agent-config", "--set", "readonly=false"])?;
        }
        "readonly" => {
            rpc(&["agent-config", "--set", "memory_off=false"])?;
            rpc(&["agent-config", "--set", "readonly=true"])?;
        }
        "off" => {
            rpc(&["agent-config", "--set", "memory_off=true"])?;
        }
        _ => return Err(t("未知工作区", "Unknown workspace")),
    }
    Ok(t(
        "工作区已保存。提示词过期时到第 3 项更新。",
        "Workspace saved. Refresh stale prompts from item 3.",
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Direct,
}

fn manager_name(manager: Manager) -> &'static str {
    match manager {
        Manager::Npm => "npm",
        Manager::Pnpm => "pnpm",
        Manager::Yarn => "yarn",
        Manager::Bun => "bun",
        Manager::Direct => "direct",
    }
}

fn tool_on_path(name: &str) -> bool {
    let path = match std::env::var_os("PATH") {
        Some(path) => path,
        None => return false,
    };
    let file = if cfg!(windows) {
        format!("{name}.cmd")
    } else {
        name.to_owned()
    };
    std::env::split_paths(&path).any(|dir| dir.join(&file).is_file() || dir.join(name).is_file())
}

fn tools_on_path() -> Vec<Manager> {
    let mut tools = Vec::new();
    let agent = std::env::var("npm_config_user_agent")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let exe = std::env::current_exe()
        .map(|path| path.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let prefer = if agent.starts_with("pnpm") || exe.contains(".pnpm") || exe.contains("pnpm") {
        Some(Manager::Pnpm)
    } else if agent.starts_with("yarn") || exe.contains("yarn") {
        Some(Manager::Yarn)
    } else if agent.starts_with("bun") || exe.contains("\\bun\\") || exe.contains("/bun/") {
        Some(Manager::Bun)
    } else if agent.starts_with("npm")
        || exe.contains("node_modules")
        || exe.contains("\\npm\\")
        || exe.contains("/npm/")
    {
        Some(Manager::Npm)
    } else {
        None
    };
    for manager in [Manager::Npm, Manager::Pnpm, Manager::Yarn, Manager::Bun] {
        if tool_on_path(manager_name(manager)) {
            tools.push(manager);
        }
    }
    if let Some(prefer) = prefer {
        if let Some(index) = tools.iter().position(|item| *item == prefer) {
            tools.swap(0, index);
        }
    }
    if tools.is_empty() {
        tools.push(Manager::Direct);
    }
    tools
}

fn channel_spec() -> String {
    if env!("CARGO_PKG_VERSION").contains("-dev") {
        "@rsrsai/cli@dev".to_owned()
    } else {
        "@rsrsai/cli@latest".to_owned()
    }
}

fn check_versions(app: &mut App) {
    app.set_notice(t("正在检查 npm 上的版本", "Checking versions on npm"));
    let slot = Arc::clone(&app.outcome);
    let shared = Arc::clone(&app.shared);
    std::thread::spawn(move || {
        let current = env!("CARGO_PKG_VERSION");
        let message = match respire::update_check::fetch_dist_tags() {
            Some((latest, dev)) => {
                let spec = channel_spec();
                let remote = if current.contains("-dev") {
                    dev.as_str()
                } else {
                    latest.as_str()
                };
                let newer =
                    !remote.is_empty() && respire::update_check::is_newer(remote, current);
                let line = format!(
                    "{} {current}    latest {latest}    dev {dev}{}",
                    if zh() { "当前" } else { "current" },
                    if newer {
                        if zh() {
                            format!("    有新版本 {remote}")
                        } else {
                            format!("    update available {remote}")
                        }
                    } else if zh() {
                        "    已是这条通道上的最新版".to_owned()
                    } else {
                        "    already the newest on this channel".to_owned()
                    }
                );
                if let Ok(mut guard) = shared.lock() {
                    guard.ver_line = line.clone();
                    guard.update_spec = spec;
                }
                line
            }
            None => t(
                "没有读到 npm 版本，检查网络后再试",
                "Could not read npm versions. Check the network and try again",
            ),
        };
        if let Ok(mut guard) = slot.lock() {
            *guard = Some(message);
        }
    });
}

fn run_package_update(tool: &str, spec: &str) -> Result<String, String> {
    crate::runtime_policy::require_host("package upgrade").map_err(|error| error.to_string())?;
    let line = match tool {
        "npm" => format!("npm i -g {spec}"),
        "pnpm" => format!("pnpm add -g {spec}"),
        "yarn" => format!("yarn global add {spec}"),
        "bun" => format!("bun add -g {spec}"),
        _ => return Err(t("没有可用的包管理器", "No package manager is available")),
    };
    let mut cmd = if cfg!(windows) {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", &line]);
        cmd
    } else {
        let mut parts = line.split_whitespace();
        let program = parts.next().unwrap_or(tool);
        let mut cmd = std::process::Command::new(program);
        cmd.args(parts);
        cmd
    };
    let output = cmd.output().map_err(|error| format!("{error}"))?;
    if output.status.success() {
        return Ok(t(
            "更新命令已完成。重新打开程序后才会换成新版本。当前这个窗口如果是直接运行的，不会被换掉。",
            "Update command finished. Reopen the program to use the new version. This window is unchanged if it was started as a direct binary.",
        ));
    }
    let err = String::from_utf8_lossy(&output.stderr);
    let out = String::from_utf8_lossy(&output.stdout);
    let text = if err.trim().is_empty() { out } else { err };
    Err(text.chars().take(400).collect())
}

fn sync_notice(value: &Value) -> String {
    let summary = &value["summary"];
    t(
        &format!(
            "同步结束  拉 {}  推 {}  冲突 {}",
            summary["pulled"].as_u64().unwrap_or(0),
            summary["pushed"].as_u64().unwrap_or(0),
            summary["conflicts"].as_i64().unwrap_or(0)
        ),
        &format!(
            "Sync finished  pulled {}  pushed {}  conflicts {}",
            summary["pulled"].as_u64().unwrap_or(0),
            summary["pushed"].as_u64().unwrap_or(0),
            summary["conflicts"].as_i64().unwrap_or(0)
        ),
    )
}

fn edit_key(app: &mut App, code: KeyCode) -> bool {
    let Overlay::Edit { buf, cursor } = &mut app.overlay else {
        return false;
    };
    match code {
        KeyCode::Char(' ') => app.overlay = Overlay::None,
        KeyCode::Enter => {
            let value = buf.trim().to_owned();
            app.overlay = Overlay::None;
            if value.is_empty() || !(value.starts_with("http://") || value.starts_with("https://"))
            {
                app.set_notice(t(
                    "地址必须以 http:// 或 https:// 开头",
                    "Address must start with http:// or https://",
                ));
                return false;
            }
            let slot = Arc::clone(&app.outcome);
            app.set_notice(t("正在保存服务器地址", "Saving the server address"));
            std::thread::spawn(move || {
                let message = match rpc(&["config", "--addr", &value]) {
                    Ok(_) => t("服务器地址已保存", "Server address saved"),
                    Err(error) => error,
                };
                if let Ok(mut guard) = slot.lock() {
                    *guard = Some(message);
                }
            });
        }
        KeyCode::Backspace => {
            if *cursor > 0 {
                let remove_at = *cursor - 1;
                let mut next = String::new();
                for (index, ch) in buf.chars().enumerate() {
                    if index != remove_at {
                        next.push(ch);
                    }
                }
                *buf = next;
                *cursor -= 1;
            }
        }
        KeyCode::Left => *cursor = cursor.saturating_sub(1),
        KeyCode::Right => *cursor = (*cursor + 1).min(buf.chars().count()),
        KeyCode::Char(ch) => {
            let mut next = String::new();
            let mut inserted = false;
            for (index, current) in buf.chars().enumerate() {
                if index == *cursor {
                    next.push(ch);
                    inserted = true;
                }
                next.push(current);
            }
            if !inserted {
                next.push(ch);
            }
            *buf = next;
            *cursor += 1;
        }
        _ => {}
    }
    false
}

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let foot_height = if app.live.notice.is_empty() { 3 } else { 4 };
    let chunks =
        Layout::vertical([Constraint::Min(8), Constraint::Length(foot_height)]).split(area);
    let mut body = if !app.live.connected {
        let mut lines = vec![line(t(
            "正在连接 runtime / 初始化中…",
            "Connecting to runtime / initializing...",
        ))];
        if !app.live.error.is_empty() {
            lines.push(fail_line(app.live.error.clone()));
        }
        lines.push(line(t(
            "推理卡住可在终端运行：rsrs model reset-cpu",
            "If inference is stuck: rsrs model reset-cpu",
        )));
        lines
    } else {
        match app.page {
            Page::Home => home_body(app, chunks[0].width.saturating_sub(2) as usize),
            Page::Accounts => accounts_body(app),
            Page::Server => server_body(app),
            Page::Inject => Vec::new(),
            Page::Sync => sync_body(app),
            Page::Model => model_body(app),
            Page::Workspace => workspace_body(app),
            Page::Lang => lang_body(app),
            Page::Version => version_body(app),
            Page::Web => web_body(app),
        }
    };
    // Keep the selected model option visible as the menu grows or the terminal shrinks.
    if matches!(app.page, Page::Model) {
        let height = chunks[0].height.saturating_sub(3) as usize;
        let selected = body.iter().position(|line| {
            line.spans
                .iter()
                .any(|span| span.style.add_modifier.contains(Modifier::REVERSED))
        });
        if let Some(selected) = selected.filter(|&index| index >= height.saturating_sub(2)) {
            body.drain(..selected.saturating_sub(height / 2));
        }
    }
    let mut lines = vec![banner()];
    if let Some(extra) = overlay_lines(app) {
        // Confirmation and edit controls must not be clipped below a long page body.
        lines.extend(extra);
    } else {
        lines.extend(body);
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(crate::app_version::line()),
            )
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    match &app.overlay {
        Overlay::RecallApi(form) => form.draw(frame, chunks[0]),
        Overlay::RecallTest(form) => form.draw(frame, chunks[0]),
        _ => {}
    }
    if app.live.connected
        && matches!(app.page, Page::Inject)
        && matches!(app.overlay, Overlay::None)
    {
        draw_inject(frame, app, chunks[0]);
    }
    let foot = if matches!(app.overlay, Overlay::ModelTask(_)) {
        t("Esc / C 取消当前模型任务", "Esc / C cancels the model task")
    } else if matches!(app.overlay, Overlay::RecallApi(_)) {
        t(
            "Tab 切字段    Ctrl+A 全选    Ctrl+S 保存    Esc 放弃",
            "Tab changes field    Ctrl+A selects all    Ctrl+S saves    Esc discards",
        )
    } else if matches!(app.overlay, Overlay::RecallTest(_)) {
        t(
            "回车测试    Ctrl+A 全选    PgUp/PgDn 滚动    Esc 返回",
            "Enter tests    Ctrl+A selects all    PgUp/PgDn scroll    Esc returns",
        )
    } else if matches!(app.overlay, Overlay::Edit { .. }) {
        t(
            "回车保存    空格或 Esc 放弃    退格删除",
            "Enter saves    Space or Esc cancels    Backspace deletes",
        )
    } else if zh() {
        "方向键移动    数字进入    回车确认    空格勾选    0 或 Esc 返回    7 切换语言".to_owned()
    } else {
        "Arrows move    digits open    Enter confirms    Space checks    0 or Esc back    7 switches language".to_owned()
    };
    let note = if app.live.notice.is_empty() {
        foot
    } else {
        format!("{foot}\n{}", app.live.notice)
    };
    let foot_lines: Vec<Line<'static>> = note.lines().map(|text| line(text.to_owned())).collect();
    frame.render_widget(
        Paragraph::new(foot_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(t("按键", "Keys")),
        ),
        chunks[1],
    );
}

fn home_body(app: &App, inner: usize) -> Vec<Line<'static>> {
    let live = &app.live;
    let phase = match live.phase.as_str() {
        "running" => t("正在同步", "syncing"),
        "ok" => t("上次成功", "last ok"),
        "err" => t("上次失败", "last failed"),
        _ => t("空闲", "idle"),
    };
    let user = if live.user.is_empty() {
        t("未登录", "signed out")
    } else {
        live.user.clone()
    };
    let addr = if live.addr.is_empty() {
        respire::service::DEFAULT_SERVER_ADDR.to_owned()
    } else {
        live.addr.clone()
    };
    let stamp = chrono::Local::now().format("%H:%M:%S").to_string();
    let mut lines = smi_table(
        &[
            [
                format!("rsrs  {stamp}"),
                format!("pid {}", live.pid),
                if live.connected {
                    t("runtime 在运行", "runtime up")
                } else {
                    t("runtime 未连通", "runtime down")
                },
            ],
            [
                live.url.clone(),
                format!("{}  {user}", t("档案", "Account")),
                format!(
                    "{}  {}",
                    t("工作区", "Workspace"),
                    workspace_label(&live.workspace)
                ),
            ],
            [
                format!("{}  {addr}", t("服务器", "Server")),
                format!("{}  {phase}", t("同步", "Sync")),
                format!(
                    "{} {} / {} {}",
                    t("本地", "Local"),
                    live.local_alive,
                    t("云端", "Remote"),
                    live.remote_alive
                ),
            ],
            [
                format!(
                    "{} {}  {} {}",
                    t("冲突", "Conflicts"),
                    live.conflicts,
                    t("自动", "Auto"),
                    if live.autosync {
                        t("开", "on")
                    } else {
                        t("关", "off")
                    }
                ),
                format!("{} {}", t("待推送", "Pending"), live.pending),
                format!(
                    "{} {}  {} {}",
                    t("上次拉", "Pulled"),
                    live.pulled,
                    t("推", "pushed"),
                    live.pushed
                ),
            ],
            [
                format!(
                    "{} {}  {} {}  {} {}",
                    t("注入新", "fresh"),
                    live.fresh,
                    t("过期", "stale"),
                    live.stale,
                    t("未注入", "missing"),
                    live.missing
                ),
                String::new(),
                String::new(),
            ],
        ],
        inner,
    );
    if !live.error.is_empty() {
        lines.push(fail_line(live.error.clone()));
    }
    let fails: Vec<_> = live
        .doctor
        .iter()
        .filter(|(_, status, _)| status == "fail" || status == "warn")
        .cloned()
        .collect();
    if fails.is_empty() {
        lines.push(ok_line(format!(
            "doctor  {} {}",
            live.doctor.len(),
            t("项已读取", "checks read")
        )));
    } else {
        for (name, status, value) in fails.iter().take(6) {
            let shown = if status == "fail" {
                fail_line(format!("{name}  {value}"))
            } else {
                warn_line(format!("{name}  {value}"))
            };
            lines.push(shown);
        }
    }
    lines.push(line(String::new()));
    let labels = [
        t("1  账户", "1  Accounts"),
        t("2  服务器", "2  Server"),
        t("3  注入与提示词", "3  Inject and prompts"),
        t("4  同步", "4  Sync"),
        t("5  模型", "5  Models"),
        t("6  工作区", "6  Workspace"),
        t("7  语言", "7  Language"),
        t("8  版本", "8  Version"),
        t("9  打开 Web", "9  Open Web"),
    ];
    for (index, label) in labels.iter().enumerate() {
        lines.push(choice(index == app.cursor, label.clone()));
    }
    lines.push(choice(app.cursor == 9, t("0  退出", "0  Quit")));
    lines
}

fn table_metrics(inner: usize) -> (usize, usize, usize) {
    let preferred = 28usize;
    let cols = if inner >= preferred * 3 + 4 {
        3
    } else if inner >= preferred * 2 + 3 {
        2
    } else {
        1
    };
    let gutters = cols + 1;
    let cell = if cols == 3 {
        preferred
    } else {
        inner.saturating_sub(gutters).clamp(12, preferred)
    };
    let width = cols * cell + gutters;
    (cols, cell, width)
}

fn clip_cell(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w > width {
            break;
        }
        out.push(ch);
        used += w;
    }
    while used < width {
        out.push(' ');
        used += 1;
    }
    out
}

fn smi_table(rows: &[[String; 3]], inner: usize) -> Vec<Line<'static>> {
    let (cols, cell, _) = table_metrics(inner);
    let mut flat = Vec::new();
    for row in rows {
        for item in row {
            flat.push(item.clone());
        }
    }
    let mut out = Vec::new();
    let rule = |fill: char| {
        let mut text = String::from("+");
        for _ in 0..cols {
            text.push_str(&fill.to_string().repeat(cell));
            text.push('+');
        }
        line(text)
    };
    out.push(rule('-'));
    for (index, chunk) in flat.chunks(cols).enumerate() {
        let mut text = String::from("|");
        for item in chunk {
            text.push_str(&clip_cell(item, cell));
            text.push('|');
        }
        for _ in 0..(cols - chunk.len()) {
            text.push_str(&clip_cell("", cell));
            text.push('|');
        }
        out.push(line(text));
        out.push(rule(if index == 0 { '=' } else { '-' }));
    }
    out
}

fn web_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('0') => app.page = Page::Home,
        KeyCode::Up => app.cursor = 0,
        KeyCode::Down => app.cursor = 1,
        KeyCode::Enter if app.cursor == 1 => app.page = Page::Home,
        KeyCode::Enter => {
            let url = if app.live.url.is_empty() {
                crate::net_rpc::rpc_base_url()
            } else {
                app.live.url.clone()
            };
            crate::web::open_browser(&url);
            app.set_notice(t(&format!("已打开 {url}"), &format!("Opened {url}")));
        }
        _ => {}
    }
    false
}

fn web_body(app: &App) -> Vec<Line<'static>> {
    let url = if app.live.url.is_empty() {
        crate::net_rpc::rpc_base_url()
    } else {
        app.live.url.clone()
    };
    vec![
        line(format!("{}: {url}", t("本机页面", "Local page"))),
        line(t(
            "回车用系统浏览器打开。",
            "Enter opens it in the system browser.",
        )),
        choice(app.cursor == 0, t("打开 Web", "Open Web")),
        choice(app.cursor == 1, t("0  返回", "0  Back")),
    ]
}

fn banner() -> Line<'static> {
    let zh_on = zh();
    let on = Style::default()
        .fg(Color::Black)
        .bg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let off = Style::default().fg(Color::DarkGray);
    Line::from(vec![
        Span::raw(t("语言  ", "Language  ")),
        Span::styled("中文", if zh_on { on } else { off }),
        Span::raw("  "),
        Span::styled("English", if zh_on { off } else { on }),
        Span::raw(t("      7 立即切换", "      7 switches now")),
    ])
}

fn accounts_body(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![line(t(
        "选择账户后回车。没有钥匙的档案不能在这里登录。",
        "Enter switches account. A profile without keys cannot sign in here.",
    ))];
    if app.live.accounts.is_empty() {
        lines.push(line(t("没有读到账户", "No accounts read")));
    }
    for (index, row) in app.live.accounts.iter().enumerate() {
        let mark = if row.current {
            t("当前", "current")
        } else {
            t("    ", "       ")
        };
        let user = if row.user.is_empty() {
            t("未登录", "signed out")
        } else {
            row.user.clone()
        };
        lines.push(choice(
            index == app.cursor,
            format!("{mark}  {}  {user}", row.name),
        ));
    }
    lines.push(choice(
        app.cursor == app.live.accounts.len(),
        t("0  返回", "0  Back"),
    ));
    lines
}

fn server_body(app: &App) -> Vec<Line<'static>> {
    vec![
        choice(
            app.cursor == 0,
            format!("{}: {}", t("修改地址", "Edit address"), app.live.addr),
        ),
        choice(app.cursor == 1, t("0  返回", "0  Back")),
    ]
}

fn draw_inject(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered().title(t("注入与提示词", "Inject and prompts"));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let sections = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Min(2),
        Constraint::Length(1),
    ])
    .split(inner);
    frame.render_widget(Paragraph::new(banner()), sections[0]);
    frame.render_widget(
        Paragraph::new(vec![
            choice(
                app.cursor == 0,
                t("更新所有已安装提示词", "Update all installed prompts"),
            ),
            choice(
                app.cursor == 1,
                t("卸载所有已安装提示词", "Uninstall all installed prompts"),
            ),
        ]),
        sections[1],
    );
    let rows = app.live.inject.iter().map(|row| {
        let color = match row.state.as_str() {
            "fresh" => Color::Green,
            "stale" => Color::Yellow,
            _ => Color::DarkGray,
        };
        Row::new(vec![
            Cell::from(if row.checked { "[x]" } else { "[ ]" }),
            Cell::from(row.name.clone()),
            Cell::from(state_label(&row.state)).style(Style::default().fg(color)),
            Cell::from(if row.seen {
                t("已检测到", "detected")
            } else {
                t("未检测到", "not detected")
            }),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new([
            t("安装", "On"),
            t("目标", "Target"),
            t("提示词状态", "Prompt status"),
            t("应用检测", "App detected"),
        ])
        .style(Style::default().bold()),
    )
    .block(Block::bordered())
    .column_spacing(2)
    .row_highlight_style(Style::default().bg(Color::DarkGray).bold())
    .highlight_symbol("> ");
    let selected = app
        .cursor
        .checked_sub(2)
        .filter(|index| *index < app.live.inject.len());
    let mut state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, sections[2], &mut state);
    frame.render_widget(
        Paragraph::new(choice(
            app.cursor == app.live.inject.len() + 2,
            t("0  返回", "0  Back"),
        )),
        sections[3],
    );
}

fn state_label(state: &str) -> String {
    match state {
        "fresh" => t("提示词已更新", "prompt fresh"),
        "stale" => t("提示词过期", "prompt stale"),
        "none" | "absent" => t("未注入", "not injected"),
        other => other.to_owned(),
    }
}

fn sync_body(app: &App) -> Vec<Line<'static>> {
    let phase = match app.live.phase.as_str() {
        "running" => t("正在同步", "syncing"),
        "ok" => t("上次成功", "last ok"),
        "err" => t("上次失败", "last failed"),
        _ => t("尚未同步", "not synced yet"),
    };
    vec![
        line(format!(
            "{phase}    {}: {}  {}: {}  {}: {}",
            t("拉", "pulled"),
            app.live.pulled,
            t("推", "pushed"),
            app.live.pushed,
            t("冲突", "conflicts"),
            app.live.conflicts
        )),
        line(if app.live.error.is_empty() {
            t(
                "冲突只在这里查看，合并仍用命令。",
                "Conflicts are listed here. Merging stays a command.",
            )
        } else {
            app.live.error.clone()
        }),
        choice(app.cursor == 0, t("手动同步一次", "Sync once")),
        choice(
            app.cursor == 1,
            format!(
                "{}  {}",
                t("自动同步", "Auto-sync"),
                if app.autosync_draft {
                    t("开", "on")
                } else {
                    t("关", "off")
                }
            ),
        ),
        choice(app.cursor == 2, t("0  返回", "0  Back")),
        line(t(
            "左右键切换自动同步，回车保存。",
            "Left and right change auto-sync. Enter saves.",
        )),
    ]
}

fn model_body(app: &App) -> Vec<Line<'static>> {
    let bge = doctor_value(&app.live, "embedder");
    let rerank = doctor_value(&app.live, "reranker");
    let engine = respire::memory::onnx::configured_engine()
        .map(|e| format!("{e:?}"))
        .unwrap_or_else(|e| e.to_string());
    let mut lines = vec![
        line(format!("BGE  {bge}")),
        choice(
            app.cursor == 0,
            t("安装或校验 BGE", "Install or verify BGE"),
        ),
        choice(
            app.cursor == 1,
            t("卸载 BGE（删除文件）", "Uninstall BGE (delete files)"),
        ),
        line(format!("{}  {rerank}", t("精排", "Rerank"))),
        choice(app.cursor == 2, t("安装精排模型", "Install rerank model")),
        choice(
            app.cursor == 3,
            t(
                "卸载精排模型（删除文件）",
                "Uninstall rerank (delete files)",
            ),
        ),
        line(format!(
            "{}: {engine}",
            t("当前推理设置", "Inference setting")
        )),
    ];
    for (index, engine) in model_engines().iter().enumerate() {
        let label = match *engine {
            "npu" if cfg!(target_os = "macos") => "Apple CoreML (ANE / CPU)".to_owned(),
            "npu" => "NPU (Windows ML)".to_owned(),
            "gpu" => "GPU".to_owned(),
            _ => t("CPU（默认）", "CPU (default)"),
        };
        lines.push(choice(app.cursor == index + 4, label));
    }
    let mut index = 4 + model_engines().len();
    if cfg!(windows) {
        lines.push(choice(
            app.cursor == index,
            t("安装 Windows NPU 推理引擎", "Install Windows NPU providers"),
        ));
        index += 1;
    }
    lines.push(choice(
        app.cursor == index,
        t("运行推理验证", "Check inference"),
    ));
    let mode = respire::service::read_agent_config()["recall_mode"]
        .as_str()
        .unwrap_or("fast")
        .to_owned();
    lines.push(line(format!("{}: {mode}", t("召回模式", "Recall mode"))));
    lines.push(choice(
        app.cursor == index + 1,
        t("快速（本地召回，默认）", "Fast (local retrieval, default)"),
    ));
    lines.push(choice(
        app.cursor == index + 2,
        t(
            "高质量（模型筛选标题，需配置 API）",
            "High quality (model selects titles; API required)",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 3,
        t(
            "升级 BGE-M3 并重建索引",
            "Upgrade to BGE-M3 and rebuild index",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 4,
        t("恢复旧版 BGE 模型索引", "Restore legacy BGE index"),
    ));
    lines.push(line(t(
        "默认 CPU；加载超时 30 秒，推理超时 15 秒；失败报错，不切换引擎。",
        "CPU by default; load timeout 30s, inference 15s; failures report errors without switching engines.",
    )));
    lines.push(line(t(
        "卡住时在终端运行：rsrs model reset-cpu",
        "If stuck, run in terminal: rsrs model reset-cpu",
    )));
    lines.push(choice(
        app.cursor == index + 5,
        t(
            "配置高质量召回 API（地址 / 模型 / 密钥）",
            "Configure recall API (URL / model / key)",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 6,
        t("测试快速召回", "Test fast recall"),
    ));
    lines.push(choice(
        app.cursor == index + 7,
        t("测试高质量召回", "Test high-quality recall"),
    ));
    lines.push(choice(app.cursor == index + 8, t("0  返回", "0  Back")));
    lines
}

fn workspace_body(app: &App) -> Vec<Line<'static>> {
    let labels = [
        t("读写", "read and write"),
        t("只读", "read only"),
        t("暂时关闭", "off"),
    ];
    vec![
        line(format!(
            "{}: {}",
            t("当前", "Current"),
            workspace_label(&app.live.workspace)
        )),
        choice(
            app.cursor == 0,
            format!("{}  {}", t("选择", "Choice"), labels[app.workspace_draft]),
        ),
        choice(app.cursor == 1, t("0  返回", "0  Back")),
        line(t(
            "左右键选择，回车保存。",
            "Left and right choose. Enter saves.",
        )),
    ]
}

fn lang_body(app: &App) -> Vec<Line<'static>> {
    vec![
        choice(app.cursor == 0, t("1  中文", "1  Chinese")),
        choice(app.cursor == 1, t("2  English", "2  English")),
        choice(app.cursor == 2, t("0  返回", "0  Back")),
        line(t(
            "任意界面按 7 也会立即切换。回车在这里选定。",
            "7 also switches immediately from any screen. Enter selects here.",
        )),
    ]
}

fn version_body(app: &App) -> Vec<Line<'static>> {
    let tools = tools_on_path();
    let tool = tools
        .get(app.manager_pick)
        .copied()
        .unwrap_or(Manager::Direct);
    let spec = if app.live.update_spec.is_empty() {
        channel_spec()
    } else {
        app.live.update_spec.clone()
    };
    let status = if app.live.ver_line.is_empty() {
        format!("{} {}", t("当前", "Current"), env!("CARGO_PKG_VERSION"))
    } else {
        app.live.ver_line.clone()
    };
    vec![
        line(status),
        line(format!("{}: {}", t("启动方式", "Started as"), manager_name(detect_preferred()))),
        choice(app.cursor == 0, t("检查最新版", "Check the newest version")),
        choice(app.cursor == 1, format!("{} {}  {spec}", t("更新", "Update"), manager_name(tool))),
        choice(app.cursor == 2, t("0  返回", "0  Back")),
        line(t("左右键选择用哪个包管理器更新。直接运行的程序不会被这次更新替换。", "Left and right choose the package manager. A direct binary is not replaced by the update.")),
    ]
}

fn detect_preferred() -> Manager {
    tools_on_path().first().copied().unwrap_or(Manager::Direct)
}

fn doctor_value(live: &Live, name: &str) -> String {
    live.doctor
        .iter()
        .find(|(item, _, _)| item == name)
        .map(|(_, status, value)| format!("{status}  {value}"))
        .unwrap_or_else(|| t("还没有读到", "not read yet"))
}

fn workspace_label(mode: &str) -> String {
    match mode {
        "readonly" => t("只读", "read only"),
        "off" => t("暂时关闭", "off"),
        _ => t("读写", "read and write"),
    }
}

fn overlay_lines(app: &App) -> Option<Vec<Line<'static>>> {
    match &app.overlay {
        Overlay::None => None,
        Overlay::RecallApi(_) | Overlay::RecallTest(_) => Some(Vec::new()),
        Overlay::ModelTask(task) => Some(task.lines()),
        Overlay::Edit { buf, cursor } => {
            let mut shown = String::new();
            for (index, ch) in buf.chars().enumerate() {
                if index == *cursor {
                    shown.push('|');
                }
                shown.push(ch);
            }
            if *cursor >= buf.chars().count() {
                shown.push('|');
            }
            Some(vec![
                line(String::new()),
                line(t("服务器地址", "Server address")),
                line(shown),
            ])
        }
        Overlay::Confirm { text, cursor, .. } => Some(vec![
            line(String::new()),
            line(text.clone()),
            choice(*cursor == 0, t("1  确认", "1  Confirm")),
            choice(*cursor == 1, t("2  取消", "2  Cancel")),
        ]),
    }
}

fn line(text: String) -> Line<'static> {
    Line::from(text)
}

fn choice(on: bool, text: String) -> Line<'static> {
    let prefix = if on { "> " } else { "  " };
    let style = if on {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(Span::styled(format!("{prefix}{text}"), style))
}

fn ok_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Green)))
}

fn warn_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Yellow)))
}

fn fail_line(text: String) -> Line<'static> {
    Line::from(Span::styled(text, Style::default().fg(Color::Red)))
}

fn setup() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    execute!(stdout(), EnterAlternateScreen, event::EnableBracketedPaste)?;
    Ok(Terminal::new(CrosstermBackend::new(stdout()))?)
}

fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    execute!(
        terminal.backend_mut(),
        event::DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    Ok(terminal.show_cursor()?)
}
