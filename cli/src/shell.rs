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
    Migration,
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
    Migrate(String, String),
    Sync,
    InstallM3,
    UninstallM3,
    CancelModel(String),
    RestartM3(String, String),
    Engine(String),
    InstallEngines,
    ProbeEngine,
    RecallMode(String),
    Workspace(String),
    Autosync(bool),
    Update(String, String),
}

enum Overlay {
    None,
    RecallApi(recall_api::Form),
    ModelMirror(text_input::Input),
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
    inference: Value,
    index: Value,
    model_progress: Value,
    engine: String,
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
    runtime_version: String,
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
    login_requested: bool,
    migration_profiles: Vec<Value>,
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
    // Finish host startup before terminal rendering. Polling never takes over a
    // runtime, and host actions capture their diagnostics instead of drawing them.
    crate::rpc::ensure_daemon()?;
    enable_raw_mode()?;
    let mut terminal = setup()?;
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Mutex::new(Live::empty()));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_loop(worker_stop, worker_shared));
    let worker_stop = Arc::clone(&stop);
    let worker_shared = Arc::clone(&shared);
    std::thread::spawn(move || refresh_details_loop(worker_stop, worker_shared));
    let worker_stop = stop.clone();
    let worker_shared = shared.clone();
    std::thread::spawn(move || refresh_inference_loop(worker_stop, worker_shared));
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
                Overlay::ModelMirror(input) => input.paste(text),
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
        if let Overlay::ModelMirror(input) = &mut app.overlay {
            if key.code == KeyCode::Esc { app.overlay = Overlay::None; }
            else if key.code == KeyCode::Enter {
                let value = input.text.trim().to_owned();
                let result = respire::model_install::validate_mirror(&value)
                    .map_err(|e| e.to_string())
                    .and_then(|_| retrieval_action(&["agent-config", "--set", &format!("model_mirror={value}")]).map(|_| ()));
                match result {
                    Ok(()) => {
                        app.overlay = Overlay::None;
                        app.set_notice(t("下载源已保存", "Download source saved"));
                        if let Some(id) = app.live.model_progress["id"].as_str().filter(|_| app.live.model_progress["active"] == true) {
                            let id = id.to_owned();
                            ask(&mut app, t("取消当前任务，使用所选下载源重新下载？", "Cancel the current task and restart using the selected source?"), ConfirmKind::RestartM3(id, value));
                        }
                    }
                    Err(error) => app.set_notice(error),
                }
            } else if matches!(key.code, KeyCode::Up | KeyCode::Down) {
                let presets = respire::model_install::MIRRORS;
                let index = presets.iter().position(|v| *v == input.text).unwrap_or(0);
                let next = if key.code == KeyCode::Down { (index + 1) % presets.len() } else { (index + presets.len() - 1) % presets.len() };
                *input = text_input::Input::new(presets[next].to_owned());
            } else { input.key(key); }
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
        if app.login_requested {
            app.login_requested = false;
            // Give secret prompts sole ownership of the normal terminal, then redraw the TUI.
            restore(&mut terminal)?;
            disable_raw_mode()?;
            let login = crate::login::run(None, None, None, None, true, false, None, false);
            enable_raw_mode()?;
            terminal = match setup() {
                Ok(terminal) => terminal,
                Err(error) => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(error);
                }
            };
            app.set_notice(match login {
                Ok(()) => t("登录成功；账户已验证", "Signed in; account verified"),
                Err(error) => format!("{error:#}"),
            });
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
            inference: Value::Null,
            index: Value::Null,
            model_progress: Value::Null,
            engine: String::new(),
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
            runtime_version: String::new(),
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
            inference: self.inference.clone(),
            index: self.index.clone(),
            model_progress: self.model_progress.clone(),
            engine: self.engine.clone(),
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
            runtime_version: self.runtime_version.clone(),
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
            login_requested: false,
            migration_profiles: Vec::new(),
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
    crate::rpc::query_existing_json(owned).map_err(|err| format!("{err:#}"))
}

fn retrieval_action(args: &[&str]) -> Result<Value, String> {
    checked_result(rpc(args)?)
}

fn checked_result(result: Value) -> Result<Value, String> {
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
    Err(if errors.is_empty() {
        format!("Command failed: {}", result["status"])
    } else {
        errors
    })
}

fn switch_account(name: &str) -> Result<String, String> {
    let switched = host_command(&["account", "use", name])?;
    let expected_dir = switched["summary"]["dir"].as_str()
        .ok_or_else(|| "Profile switch did not return its directory".to_owned())?;
    let accounts = checked_result(rpc(&["account", "list"])?)?;
    let actual = accounts["details"]["accounts"].as_array()
        .and_then(|rows| rows.iter().find(|row| row["current"] == true))
        .ok_or_else(|| "Runtime did not report its current account".to_owned())?;
    if actual["name"] != name || actual["dir"] != expected_dir {
        return Err("Runtime account does not match the requested profile".to_owned());
    }
    Ok(t("已切换账户", "Account switched"))
}

fn host_command(args: &[&str]) -> Result<Value, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let mut command = std::process::Command::new(executable);
    command.arg("--json").args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().map_err(|error| error.to_string())?;
    if !output.status.success() {
        if let Ok(value) = serde_json::from_slice(&output.stdout) {
            if let Err(error) = checked_result(value) { return Err(error); }
        }
        return Err(format!("Host action failed ({}): {}", output.status,
            String::from_utf8_lossy(&output.stderr).trim()));
    }
    let envelope = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    checked_result(envelope)
}

fn refresh_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let mut next = Live::empty();
        if let Some((pid, url, version)) = crate::rpc::runtime_brief() {
            next.pid = pid;
            next.url = url;
            next.runtime_version = version;
        }
        match rpc(&["status"]) {
            Ok(envelope) if envelope["status"] == "ok" => {
                let summary = &envelope["summary"];
                next.index = summary["retrieval_index"].clone();
                next.model_progress = summary["model_operation"].clone();
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
        if !next.connected {
            next.runtime_version.clear();
        }
        if let Ok(mut guard) = shared.lock() {
            next.inference = guard.inference.clone();
            next.notice = guard.notice.clone();
            next.ver_line = guard.ver_line.clone();
            next.update_spec = guard.update_spec.clone();
            next.inject = guard.inject.iter().map(InjectRow::clone_row).collect();
            next.accounts = guard.accounts.iter().map(AccountRow::clone_row).collect();
            next.doctor = guard.doctor.clone();
            next.engine = guard.engine.clone();
            next.fresh = guard.fresh;
            next.stale = guard.stale;
            next.missing = guard.missing;
            *guard = next;
        }
        std::thread::sleep(FAST.saturating_sub(started.elapsed()));
    }
}

fn refresh_inference_loop(stop: Arc<AtomicBool>, shared: Arc<Mutex<Live>>) {
    while !stop.load(Ordering::Relaxed) {
        let inference = match crate::net_rpc::health() {
            Ok(health) => health.inference,
            Err(error) => serde_json::json!({"phase":"unavailable","error":format!("{error:#}")}),
        };
        if let Ok(mut state) = shared.lock() { state.inference = inference; }
        std::thread::sleep(FAST);
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
            if let Ok(envelope) = serde_json::from_value::<crate::output::ResultEnvelope>(envelope) {
                next.doctor = envelope.items.iter().map(|item| (
                    item.name.clone(), item.status.as_str().to_owned(), envelope.human_item_value(item),
                )).collect();
            }
        }
        if let Ok(envelope) = retrieval_action(&["model", "engine"]) {
            next.engine = envelope["summary"]["engine"].as_str().unwrap_or("").to_owned();
        }
        if let Ok(mut guard) = shared.lock() {
            guard.engine = next.engine;
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
        Page::Accounts => list_key(app, code, app.live.accounts.len() + 2, |app, code| {
            account_key(app, code)
        }),
        Page::Migration => list_key(app, code, app.migration_profiles.len(), migration_key),
        Page::Server => server_key(app, code),
        Page::Inject => list_key(app, code, app.live.inject.len() + 2, |app, code| {
            inject_key(app, code)
        }),
        Page::Sync => sync_key(app, code),
        Page::Model => list_key(
            app,
            code,
            11 + model_engines().len() + usize::from(cfg!(windows)),
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
    if app.cursor == app.live.accounts.len() + 1 {
        app.login_requested = true;
        return;
    }
    if app.cursor == app.live.accounts.len() {
        match respire::migration::list_legacy_profiles() {
            Ok(value) => {
                app.migration_profiles = value["profiles"].as_array().map(|profiles|
                    profiles.iter().filter(|profile| profile["migrated_to"].is_null()).cloned().collect()
                ).unwrap_or_default();
                app.cursor = 0;
                app.page = Page::Migration;
            }
            Err(error) => app.set_notice(format!("{error:#}")),
        }
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

fn migration_key(app: &mut App, code: KeyCode) {
    if code != KeyCode::Enter { return; }
    let Some(row) = app.migration_profiles.get(app.cursor) else { return; };
    if !row["migrated_to"].is_null() {
        app.set_notice(t("该来源已迁移，不会重复复制", "Already migrated; no duplicate copy"));
        return;
    }
    let (Some(id), Some(account)) = (row["source_id"].as_str(), row["account"].as_str()) else { return; };
    let id = id.to_owned();
    let account = account.to_owned();
    ask(app, t(&format!("将所选旧账户复制为 {account}？当前账户保持不变。"),
        &format!("Copy the selected legacy account into {account}? Current account stays active.")),
        ConfirmKind::Migrate(id, account));
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

fn selected_model_mirror() -> String {
    respire::service::read_agent_config()["model_mirror"].as_str().map(str::to_owned)
        .or_else(respire::model_install::mirror_from_env).unwrap_or_else(|| "auto".to_owned())
}

fn cancel_model(id: &str) -> Result<(), String> {
    if id.is_empty() { return Ok(()); }
    let started = Instant::now();
    let mut cancellation_accepted = false;
    loop {
        let progress = crate::rpc::model_control(id, true).map_err(|error| error.to_string())?;
        if progress["stale"] == true {
            // The original task finished after accepting cancellation. A newly
            // scheduled task must not be cancelled or reported as its failure.
            if cancellation_accepted { return Ok(()); }
            return Err(t("模型任务已变化；刷新进度后重试", "The model task changed; refresh progress and retry"));
        }
        cancellation_accepted |= progress["cancelled"] == true;
        if progress["active"] != true { return Ok(()); }
        if started.elapsed() >= Duration::from_secs(45) {
            return Err(t("取消尚未完成；等待当前网络读取结束后重试", "Cancellation is still pending; wait for the current network read before retrying"));
        }
        std::thread::sleep(FAST);
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
                "安装或校验 BGE-M3 量化模型（543 MiB）？校验通过则跳过。",
                "Install or verify BGE-M3 quantized (543 MiB model)? Verified files are skipped.",
            ),
            ConfirmKind::InstallM3,
        ),
        1 => ask(
            app,
            t(
                "卸载 BGE-M3 并删除模型文件？卸载后 recall 需要重新安装。",
                "Uninstall BGE-M3 and delete its files? Recall will need a reinstall.",
            ),
            ConfirmKind::UninstallM3,
        ),
        2 => {
            let current = selected_model_mirror();
            app.overlay = Overlay::ModelMirror(text_input::Input::new(current));
        }
        cursor => {
            let engines = model_engines();
            if let Some(engine) = cursor.checked_sub(3).and_then(|index| engines.get(index)) {
                run_confirm(app, ConfirmKind::Engine((*engine).to_owned()));
            } else if cfg!(windows) && cursor == 3 + engines.len() {
                ask(
                    app,
                    t(
                        "通过 Windows ML 下载兼容的 NPU 推理引擎？",
                        "Download compatible NPU providers through Windows ML?",
                    ),
                    ConfirmKind::InstallEngines,
                );
            } else if cursor == 3 + engines.len() + usize::from(cfg!(windows)) {
                run_confirm(app, ConfirmKind::ProbeEngine);
            } else {
                let index = 4 + engines.len() + usize::from(cfg!(windows));
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
                    Some(2) => app.overlay = Overlay::RecallApi(recall_api::Form::new()),
                    Some(3) => app.overlay = Overlay::RecallTest(recall_test::Form::new("fast")),
                    Some(4) => app.overlay = Overlay::RecallTest(recall_test::Form::new("quality")),
                    Some(5) => {
                        if let Some(id) = app.live.model_progress["id"].as_str().filter(|_| app.live.model_progress["active"] == true) {
                            let id = id.to_owned();
                            ask(app, t("取消当前模型任务？已完成的模型文件和原索引会保留。", "Cancel the current model task? Completed files and the original index are kept."), ConfirmKind::CancelModel(id));
                        } else { app.set_notice(t("没有正在运行的模型任务", "No model task is running")); }
                    }
                    Some(6) => {
                        let id = app.live.model_progress["id"].as_str().unwrap_or("").to_owned();
                        ask(app, t("取消当前任务并从所选下载源重新下载未完成文件？", "Cancel the current task and redownload unfinished files from the selected source?"), ConfirmKind::RestartM3(id, selected_model_mirror()));
                    }
                    Some(7) => app.page = Page::Home,
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
                    &format!("把整台设备的工作模式改成 {}？", workspace_label(mode)),
                    &format!("Change service mode for this device to {}?", workspace_label(mode)),
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
        ConfirmKind::InstallM3
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
        ConfirmKind::Migrate(_, _) => t("正在迁移所选旧账户", "Migrating selected legacy account"),
        ConfirmKind::Sync => t("正在同步", "Syncing"),
        ConfirmKind::InstallM3 => t("正在安装或校验 BGE-M3", "Installing or verifying BGE-M3"),
        ConfirmKind::UninstallM3 => t("正在卸载 BGE-M3", "Uninstalling BGE-M3"),
        ConfirmKind::CancelModel(_) => t("正在取消模型任务，等待当前网络读取结束", "Cancelling model task; waiting for the current network read"),
        ConfirmKind::RestartM3(_, _) => t("正在取消旧任务并重新安排下载", "Cancelling the old task and scheduling a new download"),
        ConfirmKind::Engine(_) => t("正在保存推理引擎", "Saving inference engine"),
        ConfirmKind::InstallEngines => t("正在下载 NPU 推理引擎", "Downloading NPU providers"),
        ConfirmKind::ProbeEngine => t("正在验证推理引擎", "Checking inference engine"),
        ConfirmKind::RecallMode(_) => t("正在保存召回模式", "Saving recall mode"),
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
                switch_account(&name)
            }
            ConfirmKind::Migrate(id, account) => host_command(&["migrate", "--source", &id, "--account", &account])
                .map(|_| t("迁移完成；可在账户页面切换", "Migration complete; select it on the Accounts page")),
            ConfirmKind::Sync => rpc(&["sync"]).map(|value| sync_notice(&value)),
            ConfirmKind::InstallM3 => model_action(&["model", "install-m3", "--mirror", &selected_model_mirror()])
                .map(|_| t("BGE-M3 处理结束", "BGE-M3 step finished")),
            ConfirmKind::CancelModel(id) => cancel_model(&id)
                .map(|_| t("已取消模型任务", "Model task cancelled")),
            ConfirmKind::RestartM3(id, mirror) => cancel_model(&id)
                .and_then(|_| crate::rpc::prepare_model(&mirror).map_err(|error| error.to_string()))
                .map(|_| t("已重新安排下载；可在模型页面查看进度", "Download rescheduled; progress is shown on the Models page")),
            ConfirmKind::UninstallM3 => {
                rpc(&["model", "uninstall-m3"]).map(|_| t("BGE-M3 已卸载", "BGE-M3 uninstalled"))
            }
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
            ConfirmKind::InstallEngines => host_command(&["model", "install-engines"]).map(|v| {
                format!(
                    "{}: {}",
                    t("推理引擎", "Providers"),
                    v["summary"]["providers"].as_array().map(|providers|
                        providers.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                        .unwrap_or_default()
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
    rpc(&["agent-config", "--set", &format!("workspace_mode={mode}")])?;
    Ok(t("工作模式已保存", "Service mode saved"))
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
    let path = match respire::env::var_os("PATH") {
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
    let agent = respire::env::var("npm_config_user_agent")
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
            Page::Migration => migration_body(app),
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
    // Account for wrapped diagnostics when keeping a menu selection visible.
    if matches!(app.overlay, Overlay::None) {
        let height = chunks[0].height.saturating_sub(3) as usize;
        let width = usize::from(chunks[0].width.saturating_sub(2)).max(1);
        let rows = |line: &Line<'_>| line.width().max(1).div_ceil(width);
        let selected = body.iter().position(|line| {
            line.spans
                .iter()
                .any(|span| span.style.add_modifier.contains(Modifier::REVERSED))
        });
        if let Some(selected) = selected {
            if body[..selected].iter().map(rows).sum::<usize>() >= height.saturating_sub(2) {
                let mut start = selected;
                let mut visible = rows(&body[selected]);
                while start > 0 && visible + rows(&body[start - 1]) <= height / 2 {
                    start -= 1;
                    visible += rows(&body[start]);
                }
                body.drain(..start);
            }
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
                format!("CLI {}", crate::app_version::embedded()),
                runtime_version_label(live),
                stamp.clone(),
            ],
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
                    t("工作模式", "Service mode"),
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
        t("6  工作模式", "6  Service mode"),
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
            let url = crate::web::DASHBOARD_URL;
            if let Err(error) = crate::web::open_browser(url) {
                app.set_notice(error.to_string());
                return false;
            }
            app.set_notice(t(&format!("已打开 {url}"), &format!("Opened {url}")));
        }
        _ => {}
    }
    false
}

fn web_body(app: &App) -> Vec<Line<'static>> {
    let url = crate::web::DASHBOARD_URL;
    vec![
        line(format!("{}: {url}", t("用户后台", "User dashboard"))),
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
        "选择账户后回车切换；新账户使用登录入口。",
        "Enter switches account; use Sign in for a new account.",
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
        t("迁移旧版本", "Migrate old version"),
    ));
    lines.push(choice(
        app.cursor == app.live.accounts.len() + 1,
        t("登录（OAuth / 密码与 TOTP）", "Sign in (OAuth / password and TOTP)"),
    ));
    lines.push(choice(
        app.cursor == app.live.accounts.len() + 2,
        t("0  返回", "0  Back"),
    ));
    lines
}

fn migration_body(app: &App) -> Vec<Line<'static>> {
    let mut lines = vec![line(t("选择来源目录和旧账户，回车确认；不会覆盖已有库。",
        "Choose the source directory and legacy account. Existing libraries are preserved."))];
    for (index, row) in app.migration_profiles.iter().enumerate() {
        let state = if row["migrated_to"].is_null() { "" } else { " [migrated]" };
        lines.push(choice(index == app.cursor, format!("{} | {} → {}{state}",
            row["source"].as_str().unwrap_or(""), row["user"].as_str().unwrap_or(""),
            row["account"].as_str().unwrap_or(""))));
    }
    if app.migration_profiles.is_empty() { lines.push(line(t("没有可迁移的旧库", "No legacy libraries found"))); }
    lines.push(line(t("0  返回", "0  Back")));
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
    let engine = &app.live.engine;
    let mut lines = vec![
        line(format!("BGE-M3  {bge}")),
        choice(
            app.cursor == 0,
            t("安装或校验 BGE-M3 量化模型（543 MiB）", "Install or verify BGE-M3 quantized (543 MiB)"),
        ),
        choice(
            app.cursor == 1,
            t("卸载 BGE-M3（删除文件）", "Uninstall BGE-M3 (delete files)"),
        ),
        choice(app.cursor == 2, format!("{}: {}", t("下载源（回车选择）", "Download source (Enter to choose)"), selected_model_mirror())),
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
        lines.push(choice(app.cursor == index + 3, label));
    }
    let mut index = 3 + model_engines().len();
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
    let index_state = app.live.index["state"].as_str().unwrap_or("unknown");
    lines.push(line(format!("{}: {}", t("后台索引", "Background index"), index_state)));
    if let Some(error) = app.live.index["error"].as_str() {
        lines.push(fail_line(error.to_owned()));
    }
    if app.live.model_progress["active"] == true {
        lines.push(line(crate::output::model_task_text(&app.live.model_progress)));
    }
    if let Some(status) = crate::progress::inference_progress_text(&app.live.inference) {
        if app.live.inference["host_recovery_required"] == true { lines.push(fail_line(status)); }
        else { lines.push(line(status)); }
    }
    if let Some(error) = app.live.inference["error"].as_str() { lines.push(fail_line(error.to_owned())); }
    lines.push(line(t(
        "默认 CPU；runtime 内共享模型与推理；失败报错，不切换引擎。",
        "CPU by default; shared model and inference inside runtime; failures report errors without switching engines.",
    )));
    lines.push(line(t(
        "卡住时在终端运行：rsrs model reset-cpu",
        "If stuck, run in terminal: rsrs model reset-cpu",
    )));
    lines.push(choice(
        app.cursor == index + 3,
        t(
            "配置高质量召回 API（地址 / 模型 / 密钥）",
            "Configure recall API (URL / model / key)",
        ),
    ));
    lines.push(choice(
        app.cursor == index + 4,
        t("测试快速召回", "Test fast recall"),
    ));
    lines.push(choice(
        app.cursor == index + 5,
        t("测试高质量召回", "Test high-quality recall"),
    ));
    lines.push(choice(app.cursor == index + 6, t("取消当前模型任务", "Cancel current model task")));
    lines.push(choice(app.cursor == index + 7, t("从所选下载源重新下载", "Restart download from selected source")));
    lines.push(choice(app.cursor == index + 8, t("0  返回", "0  Back")));
    lines
}

fn workspace_body(app: &App) -> Vec<Line<'static>> {
    let labels = [
        t("正常服务", "Normal service"),
        t("只读服务", "Read-only service"),
        t("禁用服务", "Disabled service"),
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
            "左右键选择，回车保存；切换账号后保持。",
            "Left/right chooses. Enter saves for all accounts on this device.",
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
        line(runtime_version_label(&app.live)),
        line(format!("{}: {}", t("启动方式", "Started as"), manager_name(detect_preferred()))),
        choice(app.cursor == 0, t("检查最新版", "Check the newest version")),
        choice(app.cursor == 1, format!("{} {}  {spec}", t("更新", "Update"), manager_name(tool))),
        choice(app.cursor == 2, t("0  返回", "0  Back")),
        line(t("左右键选择用哪个包管理器更新。直接运行的程序不会被这次更新替换。", "Left and right choose the package manager. A direct binary is not replaced by the update.")),
    ]
}

fn runtime_version_label(live: &Live) -> String {
    if live.runtime_version.is_empty() {
        t("Runtime 未连接", "Runtime not connected")
    } else {
        format!("Runtime {}", live.runtime_version)
    }
}

fn detect_preferred() -> Manager {
    tools_on_path().first().copied().unwrap_or(Manager::Direct)
}

fn doctor_value(live: &Live, name: &str) -> String {
    if name == "embedder" && live.model_progress["active"] == true {
        return t("正在后台准备模型", "Preparing model in background");
    }
    live.doctor
        .iter()
        .find(|(item, _, _)| item == name)
        .map(|(_, status, value)| {
            let value = if value.starts_with("BGE-M3 preparation/indexing ") || value.starts_with("Model operation in progress:") {
                t("已安排后台准备", "Background preparation scheduled")
            } else if value.starts_with("BGE-M3 index pending;") {
                t("等待后台重建", "Waiting for background rebuild")
            } else { value.clone() };
            format!("{status}  {value}")
        })
        .unwrap_or_else(|| t("还没有读到", "not read yet"))
}

#[cfg(test)]
mod model_menu_tests {
    use super::*;

    #[test]
    fn mirror_cancel_restart_keys_and_live_progress_match_the_menu() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK.lock().map_err(|error| anyhow::anyhow!("{error}"))?;
        let dir = tempfile::tempdir()?;
        let previous = respire::env::var("RSRS_DATA_DIR").ok();
        std::env::set_var("RSRS_DATA_DIR", dir.path());
        let result = (|| -> anyhow::Result<()> {
            respire::service::write_agent_config_key("model_mirror", &serde_json::json!("http://127.0.0.1:9999"))?;
            let mut app = App::new(Arc::new(Mutex::new(Live::empty())));
            for width in [40, 100] {
                let rows = home_body(&app, width).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
                assert!(rows.contains(&runtime_version_label(&app.live)));
            }
            let rows = version_body(&app).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            assert!(rows.contains(&runtime_version_label(&app.live)));
            app.live.runtime_version = "1.0.9".to_owned();
            let rows = home_body(&app, 100).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            assert!(rows.contains("CLI "));
            assert!(rows.contains(crate::app_version::embedded()));
            assert!(rows.contains("Runtime 1.0.9"));
            let rows = version_body(&app).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            assert!(rows.contains("Runtime 1.0.9"));
            app.page = Page::Model;
            app.cursor = 2;
            model_key(&mut app, KeyCode::Enter);
            let Overlay::ModelMirror(input) = &app.overlay else { anyhow::bail!("mirror picker did not open"); };
            assert_eq!(input.text, "http://127.0.0.1:9999");
            let picker = overlay_lines(&app).ok_or_else(|| anyhow::anyhow!("mirror picker has no rows"))?;
            assert!(picker.iter().any(|line| line.to_string().contains("hf-mirror.com")));
            app.live.model_progress = serde_json::json!({"id":"fixture-task","active":true,"phase":"download","item":"model_quantized.onnx","done":25,"total":100});
            let rows = model_body(&app).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            assert!(rows.contains("25.0%"));
            assert!(rows.contains("model_quantized.onnx"));
            app.live.inference = serde_json::json!({"active":true,"queued":3,"phase":"loading"});
            let busy_rows = model_body(&app).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            let inference_text = crate::progress::inference_progress_text(&app.live.inference)
                .ok_or_else(|| anyhow::anyhow!("missing inference status"))?;
            assert!(busy_rows.contains(&inference_text));
            app.live.inference = serde_json::json!({"host_recovery_required":true});
            let stalled_rows = model_body(&app).iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
            let stalled_text = crate::progress::inference_progress_text(&app.live.inference)
                .ok_or_else(|| anyhow::anyhow!("missing stalled status"))?;
            assert!(stalled_rows.contains(&stalled_text));
            app.cursor = 9 + model_engines().len() + usize::from(cfg!(windows));
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(&app.overlay, Overlay::Confirm { kind: ConfirmKind::CancelModel(id), .. } if id == "fixture-task"));
            app.cursor += 1;
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(&app.overlay, Overlay::Confirm { kind: ConfirmKind::RestartM3(id, mirror), .. } if id == "fixture-task" && mirror == "http://127.0.0.1:9999"));
            app.cursor += 1;
            model_key(&mut app, KeyCode::Enter);
            assert!(matches!(app.page, Page::Home));
            Ok(())
        })();
        match previous { Some(value) => std::env::set_var("RSRS_DATA_DIR", value), None => std::env::remove_var("RSRS_DATA_DIR") }
        result
    }
}

fn workspace_label(mode: &str) -> String {
    match mode {
        "readonly" => t("只读服务", "Read-only service"),
        "off" => t("禁用服务", "Disabled service"),
        _ => t("正常服务", "Normal service"),
    }
}

fn overlay_lines(app: &App) -> Option<Vec<Line<'static>>> {
    match &app.overlay {
        Overlay::None => None,
        Overlay::ModelMirror(input) => {
            let mut lines = vec![line(t("BGE-M3 下载源", "BGE-M3 download source"))];
            lines.extend(respire::model_install::MIRRORS.iter().map(|mirror| choice(input.text == *mirror, (*mirror).to_owned())));
            lines.push(input.line(70, true, false));
            lines.push(line(t("上下键选择，也可输入自定义地址；回车保存，Esc 返回。", "Up/down selects; custom URL supported; Enter saves, Esc returns.")));
            lines.push(line(t("运行中的下载不会直接换源；保存后可取消并重新下载。", "An active download keeps its source; cancel and restart after saving.")));
            Some(lines)
        }
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
    let result = (|| -> Result<_> {
        execute!(stdout(), EnterAlternateScreen, event::EnableBracketedPaste)?;
        Ok(Terminal::new(CrosstermBackend::new(stdout()))?)
    })();
    match result {
        Ok(terminal) => Ok(terminal),
        Err(mut error) => {
            let restore = execute!(stdout(), event::DisableBracketedPaste, LeaveAlternateScreen, crossterm::cursor::Show);
            let raw_mode = disable_raw_mode();
            if let Err(cleanup) = restore { error = error.context(format!("terminal restoration failed: {cleanup}")); }
            if let Err(cleanup) = raw_mode { error = error.context(format!("disabling raw mode failed: {cleanup}")); }
            Err(error)
        }
    }
}

fn restore(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    execute!(
        terminal.backend_mut(),
        event::DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    Ok(terminal.show_cursor()?)
}
