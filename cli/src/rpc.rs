//! Local authenticated runtime transport. Commands connect to its RPC pipe/HTTP
//! endpoints and auto-start the hidden `--runtime-internal` host entry.

use std::cell::Cell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use interprocess::local_socket::{prelude::*, GenericNamespaced, ListenerOptions, Name, Stream};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::i18n;
use crate::output::{ResultEnvelope, Status as OutputStatus};

pub const PROTOCOL_V: u32 = 1;
const MAX_FRAME: usize = 32 * 1024 * 1024;
const START_POLLS: usize = 100;
const START_WAIT: Duration = Duration::from_millis(150);

thread_local! {
    static WORKER: Cell<bool> = const { Cell::new(false) };
    static SYNC_CONTEXT: Cell<Option<(usize, i64)>> = const { Cell::new(None) };
}

static RUNNING: AtomicUsize = AtomicUsize::new(0);
static RUNNING_STATUS: AtomicUsize = AtomicUsize::new(0);
static WORKERS: AtomicUsize = AtomicUsize::new(1);
static STOPPING: AtomicBool = AtomicBool::new(false);
static JOB_TX: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
static WRITE_TX: Mutex<Option<mpsc::SyncSender<WriteJob>>> = Mutex::new(None);
static STATS_PENDING: AtomicUsize = AtomicUsize::new(0);
static STATS_ENQUEUED: AtomicUsize = AtomicUsize::new(0);
static STATS_PERSISTED: AtomicUsize = AtomicUsize::new(0);
static STATS_REJECTED: AtomicUsize = AtomicUsize::new(0);
static STATS_FAILED: AtomicUsize = AtomicUsize::new(0);
const MAX_PENDING_STATS: usize = 16;
static EXCLUSIVE: OnceLock<Arc<WriteGate>> = OnceLock::new();
static GENERATION: AtomicUsize = AtomicUsize::new(0);
static INDEX_ON: AtomicBool = AtomicBool::new(false);
static INDEX_RUNNING: AtomicBool = AtomicBool::new(false);
static INDEX_CV: Condvar = Condvar::new();
static INDEX_WORK: Mutex<IndexWork> = Mutex::new(IndexWork {
    requested: false,
    state: "idle",
    error: None,
});

struct IndexWork {
    requested: bool,
    state: &'static str,
    error: Option<String>,
}
static WRITE_RUNNING: AtomicBool = AtomicBool::new(false);
static CLASSIFY_RUNNING: AtomicBool = AtomicBool::new(false);
static SYNC_KICK: Mutex<SyncSchedule> = Mutex::new(SyncSchedule {
    due: None,
    manual: VecDeque::new(),
    backoff: 0,
    blocked_generation: None,
    last_success: None,
});
struct SyncSchedule {
    due: Option<Instant>,
    manual: VecDeque<(Job, usize, i64)>,
    backoff: u32,
    blocked_generation: Option<usize>,
    last_success: Option<u64>,
}
#[derive(Default)]
struct GateState {
    held: bool,
    foreground: usize,
}
#[derive(Default)]
struct WriteGate {
    state: Mutex<GateState>,
    changed: Condvar,
}
struct WriteGuard<'a>(&'a WriteGate);
impl WriteGate {
    fn reserve(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .foreground += 1;
    }
    fn cancel_reservation(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.foreground -= 1;
        self.changed.notify_all();
    }
    fn acquire_reserved(&self) -> WriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        while state.held {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        state.foreground -= 1;
        state.held = true;
        WriteGuard(self)
    }
    fn acquire(&self, foreground: bool) -> WriteGuard<'_> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if foreground {
            state.foreground += 1;
        }
        while state.held || (!foreground && state.foreground > 0) {
            state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
        }
        if foreground {
            state.foreground -= 1;
        }
        state.held = true;
        WriteGuard(self)
    }
}
impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.held = false;
        self.0.changed.notify_all();
    }
}
static SYNC_CV: Condvar = Condvar::new();
static SYNC_RUNNING: AtomicBool = AtomicBool::new(false);
static FLIGHT_ON: AtomicBool = AtomicBool::new(false);
static WEB_URL: Mutex<String> = Mutex::new(String::new());
static CACHE: Mutex<Vec<(String, RpcResponse)>> = Mutex::new(Vec::new());

pub fn worker_active() -> bool {
    WORKER.with(|flag| flag.get())
}

pub(crate) fn set_worker_active(on: bool) {
    WORKER.with(|flag| flag.set(on));
}

fn mark_worker() {
    WORKER.with(|flag| flag.set(true));
}

enum WriteJob {
    Command(Job),
    RecallStats(RecallStats, usize),
}

pub(crate) struct RecallStats {
    pub query: String,
    pub project: String,
    pub candidates: Vec<String>,
    pub scores: Vec<f32>,
}

impl RecallStats {
    pub(crate) fn persist(&self, store: &respire::transport::local::LocalStore) -> Result<()> {
        store.write_transaction(|| {
            store.log_query(&self.query, &self.project, "", &self.candidates, &self.scores)?;
            store.bump_recall(&self.candidates)?;
            store.bump_recall_pairs(&self.candidates)
        })
    }
}

pub(crate) fn recall_stats_status() -> Value {
    json!({
        "pending": STATS_PENDING.load(Ordering::Acquire),
        "enqueued": STATS_ENQUEUED.load(Ordering::Acquire),
        "persisted": STATS_PERSISTED.load(Ordering::Acquire),
        "rejected": STATS_REJECTED.load(Ordering::Acquire),
        "failed": STATS_FAILED.load(Ordering::Acquire),
    })
}

/// Statistics are best effort; never wait for queue capacity on the recall reply path.
pub(crate) fn queue_recall_stats(stats: RecallStats, generation: usize) {
    if STATS_PENDING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pending| {
            (pending < MAX_PENDING_STATS).then_some(pending + 1)
        })
        .is_err()
    {
        STATS_REJECTED.fetch_add(1, Ordering::AcqRel);
        eprintln!("recall statistics rejected: pending statistics limit reached");
        return;
    }
    let queued = (|| -> Result<()> {
        check_sync_context(generation)?;
        let tx = WRITE_TX
            .lock()
            .map_err(|_| anyhow::anyhow!("write queue lock poisoned"))?
            .clone()
            .ok_or_else(|| anyhow::anyhow!("write worker is not running"))?;
        let gate = shared_exclusive();
        gate.reserve();
        match tx.try_send(WriteJob::RecallStats(stats, generation)) {
            Ok(()) => Ok(()),
            Err(error) => {
                gate.cancel_reservation();
                match error {
                    mpsc::TrySendError::Full(_) => bail!("write request queue is full"),
                    mpsc::TrySendError::Disconnected(_) => bail!("write worker is gone"),
                }
            }
        }
    })();
    match queued {
        Ok(()) => {
            STATS_ENQUEUED.fetch_add(1, Ordering::AcqRel);
        }
        Err(error) => {
            STATS_PENDING.fetch_sub(1, Ordering::AcqRel);
            STATS_REJECTED.fetch_add(1, Ordering::AcqRel);
            eprintln!("recall statistics rejected: {error:#}");
        }
    }
}

fn shared_exclusive() -> Arc<WriteGate> {
    EXCLUSIVE
        .get_or_init(|| Arc::new(WriteGate::default()))
        .clone()
}

pub(crate) fn sync_generation() -> usize {
    SYNC_CONTEXT
        .with(|context| context.get().map(|v| v.0))
        .unwrap_or_else(|| GENERATION.load(Ordering::Acquire))
}

pub(crate) fn sync_boundary() -> Option<i64> {
    SYNC_CONTEXT.with(|context| {
        let value = context.get()?;
        context.set(Some((value.0, -1)));
        (value.1 >= 0).then_some(value.1)
    })
}

pub(crate) fn sync_local<T>(generation: usize, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let gate = shared_exclusive();
    let _held = gate.acquire(false);
    check_sync_context(generation)?;
    action()
}

/// Short local preparation/commit for commands whose Core call performs networking.
pub(crate) fn foreground_phase<T>(
    generation: usize,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let gate = shared_exclusive();
    let _held = gate.acquire(true);
    check_sync_context(generation)?;
    action()
}

pub(crate) fn invalidate_sync_boundary(generation: usize) -> Result<()> {
    check_sync_context(generation)?;
    GENERATION.fetch_add(1, Ordering::AcqRel);
    context_changed();
    Ok(())
}

pub(crate) fn check_sync_context(generation: usize) -> Result<()> {
    respire::service::ensure_runtime_profile()?;
    if STOPPING.load(Ordering::Acquire) {
        bail!("runtime is stopping");
    }
    if GENERATION.load(Ordering::Acquire) != generation {
        bail!("sync context changed; pending work kept locally");
    }
    Ok(())
}

pub(crate) fn sync_scheduler_status() -> Value {
    let state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    let blocked = state.blocked_generation == Some(GENERATION.load(Ordering::Acquire));
    let phase = if sync_running() {
        "running"
    } else if blocked {
        "blocked"
    } else if state.backoff > 0 {
        "backoff"
    } else if state.due.is_some() {
        "scheduled"
    } else {
        "idle"
    };
    json!({"state":phase, "next_run_ms":state.due.map(|due| due.saturating_duration_since(Instant::now()).as_millis() as u64),
        "manual_waiters":state.manual.len(), "last_success_unix":state.last_success})
}

fn context_changed() {
    let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    state.blocked_generation = None;
    state.backoff = 0;
    state.due = Some(Instant::now() + Duration::from_secs(3));
    drop(state);
    SYNC_CV.notify_one();
    kick_index();
}

pub(crate) fn index_status() -> Value {
    let state = match INDEX_WORK.lock() {
        Ok(state) => state,
        Err(_) => return json!({"state":"failed", "error":"index work lock poisoned"}),
    };
    json!({"state": state.state, "scheduled": state.requested,
        "worker_active": INDEX_ON.load(Ordering::Acquire),
        "running": INDEX_RUNNING.load(Ordering::Acquire), "error": state.error,
        "model_setup": (state.state == "failed").then_some("Automatic BGE-M3 preparation or indexing failed; inspect the reported error and download source settings.")})
}

pub(crate) fn kick_index() {
    if STOPPING.load(Ordering::Acquire) {
        return;
    }
    {
        let mut work = match INDEX_WORK.lock() {
            Ok(work) => work,
            Err(_) => {
                eprintln!("background retrieval indexing failed: index work lock poisoned");
                return;
            }
        };
        work.requested = true;
        if !INDEX_RUNNING.load(Ordering::Acquire) && work.error.is_none() {
            work.state = "scheduled";
        }
    }
    INDEX_CV.notify_one();
}

fn index_yield_to_foreground(generation: usize) -> Result<()> {
    let gate = shared_exclusive();
    let mut state = gate.state.lock().map_err(|_| anyhow::anyhow!("write gate lock poisoned"))?;
    while state.held || state.foreground > 0 {
        check_sync_context(generation)?;
        respire::model_progress::check()?;
        state = gate.changed.wait_timeout(state, Duration::from_millis(100))
            .map_err(|_| anyhow::anyhow!("write gate lock poisoned"))?.0;
    }
    check_sync_context(generation)?;
    respire::model_progress::check()
}

/// The database's source-checked missing artifacts are the resumable work queue.
/// Model preparation runs on this thread without taking the foreground write gate.
fn index_loop() {
    mark_worker();
    if let Err(error) = index_loop_inner() {
        eprintln!("background retrieval index worker stopped: {error:#}");
    }
    INDEX_RUNNING.store(false, Ordering::Release);
    INDEX_ON.store(false, Ordering::Release);
}

fn index_has_work() -> bool {
    INDEX_RUNNING.load(Ordering::Acquire)
        || INDEX_WORK.lock().is_ok_and(|work| work.requested)
}

fn index_loop_inner() -> Result<()> {
    let mut model_wait_started: Option<Instant> = None;
    loop {
        {
            let mut work = INDEX_WORK.lock().map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            while !work.requested && !STOPPING.load(Ordering::Acquire) {
                work = INDEX_CV.wait(work).map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
            }
            if STOPPING.load(Ordering::Acquire) {
                work.state = "stopped";
                work.requested = false;
                return Ok(());
            }
            work.requested = false;
            work.state = "running";
        }
        INDEX_RUNNING.store(true, Ordering::Release);
        let generation = GENERATION.load(Ordering::Acquire);
        let result = (|| -> Result<bool> {
            check_sync_context(generation)?;
            let store = respire::service::open_store()?;
            let model = store.retrieval_model()?;
            if !store.index_pending(&model)? {
                return Ok(true);
            }
            let Some(_operation) = respire::model_progress::Operation::try_begin_background_index()? else {
                return Ok(false);
            };
            index_yield_to_foreground(generation)?;
            let keys = crate::build_session()?;
            if model == "m3" {
                respire::model_progress::update("prepare", "BGE-M3", 0, None)?;
                respire::model_install::prepare_m3_for_index()?;
                check_sync_context(generation)?;
            }
            let embedder = respire::memory::bge::BgeEmbedder::load_model(&model)?;
            loop {
                let rebuilt = store.rebuild_index_with_progress(&keys, &embedder, &model, |done, total| {
                    index_yield_to_foreground(generation)?;
                    respire::model_progress::update("index", &model, done as u64, Some(total as u64))
                });
                match rebuilt {
                    Ok(_) => break,
                    Err(error) if error.downcast_ref::<respire::transport::local::IndexSourceChanged>().is_some() => {
                        // Keep this Operation across source changes: cancellation and
                        // the 30-minute idle budget apply to the whole resumed task.
                        respire::model_progress::check()?;
                        let mut work = INDEX_WORK.lock().map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
                        work.error = Some(format!("{error:#}"));
                        drop(work);
                        for _ in 0..5 {
                            check_sync_context(generation)?;
                            respire::model_progress::check()?;
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            check_sync_context(generation)?;
            Ok(true)
        })();
        INDEX_RUNNING.store(false, Ordering::Release);
        let mut work = INDEX_WORK.lock().map_err(|_| anyhow::anyhow!("index work lock poisoned"))?;
        match result {
            Ok(true) => {
                work.state = "ready";
                work.error = None;
                model_wait_started = None;
            }
            Ok(false) => {
                let started = model_wait_started.get_or_insert_with(Instant::now);
                if started.elapsed() >= Duration::from_secs(1800) {
                    work.state = "failed";
                    work.requested = false;
                    work.error = Some("background indexing timed out waiting for another model operation".into());
                    model_wait_started = None;
                    continue;
                }
                work.state = "waiting_model";
                work.requested = true;
                work = INDEX_CV.wait_timeout(work, Duration::from_secs(1))
                    .map_err(|_| anyhow::anyhow!("index work lock poisoned"))?.0;
            }
            Err(error) if generation != GENERATION.load(Ordering::Acquire) => {
                model_wait_started = None;
                work.state = "scheduled";
                work.requested = true;
                work.error = Some(format!("{error:#}"));
            }
            Err(error) if error.downcast_ref::<respire::model_progress::OperationStopped>().is_some() => {
                model_wait_started = None;
                work.state = "paused";
                work.requested = false;
                work.error = Some(format!("{error:#}"));
            }
            Err(error) => {
                model_wait_started = None;
                work.state = "failed";
                work.error = Some(format!("{error:#}"));
                eprintln!("background retrieval indexing failed: {error:#}");
            }
        }
        drop(work);
    }
}

/// An explicit direct command releases its library lock before starting this work.
pub(crate) fn request_index() -> Result<Value> {
    if worker_active() {
        kick_index();
        return Ok(index_status());
    }
    let response = call_method("index.prepare", Vec::new(), true)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    response.envelope.map(|envelope| envelope.summary)
        .ok_or_else(|| anyhow::anyhow!("runtime did not acknowledge background indexing"))
}

pub(crate) fn sync_running() -> bool {
    SYNC_RUNNING.load(Ordering::Acquire)
}

fn ensure_sync_worker() {
    if FLIGHT_ON
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    if std::thread::Builder::new()
        .name("respire-sync".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(flight_loop)
        .is_err()
    {
        FLIGHT_ON.store(false, Ordering::Release);
        eprintln!("command=sync status=warn error=failed to start sync worker");
    }
}

/// Notifications are hints; the durable outbox holds the work.
pub(crate) fn kick_autosync() {
    let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
    if state.due.is_none() {
        state.due = Some(Instant::now() + Duration::from_secs(3));
    }
    drop(state);
    SYNC_CV.notify_one();
    ensure_sync_worker();
}

fn enqueue_manual(job: Job) {
    let captured = job
        .sync_context
        .ok_or_else(|| anyhow::anyhow!("missing sync request context"));
    match captured {
        Ok((generation, boundary)) => {
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            if state.manual.len() >= 64 {
                let _ = job.reply.send(Err("sync request queue is full".into()));
                return;
            }
            state.manual.push_back((job, generation, boundary));
            drop(state);
            SYNC_CV.notify_one();
            ensure_sync_worker();
        }
        Err(error) => {
            let _ = job.reply.send(Err(format!("{error:#}")));
        }
    }
}

fn flight_loop() {
    mark_worker();
    loop {
        let manual = {
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            loop {
                if STOPPING.load(Ordering::Acquire) {
                    for (job, _, _) in state.manual.drain(..) {
                        let _ = job.reply.send(Err("runtime is stopping".into()));
                    }
                    FLIGHT_ON.store(false, Ordering::Release);
                    return;
                }
                if let Some(job) = state.manual.pop_front() {
                    break Some(job);
                }
                let current_generation = GENERATION.load(Ordering::Acquire);
                if state.blocked_generation == Some(current_generation) {
                    state = SYNC_CV.wait(state).unwrap_or_else(|e| e.into_inner());
                    continue;
                }
                state.blocked_generation = None;
                let now = Instant::now();
                let due = state.due.get_or_insert(now + Duration::from_secs(300));
                if *due <= now {
                    state.due = None;
                    break None;
                }
                let wait = *due - now;
                state = SYNC_CV
                    .wait_timeout(state, wait)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        };
        SYNC_RUNNING.store(true, Ordering::Release);
        if let Some((job, generation, boundary)) = manual {
            SYNC_CONTEXT.with(|context| context.set(Some((generation, boundary))));
            let result = check_sync_context(generation).map(|_| crate::capture_run(job.args));
            if result.as_ref().is_ok_and(|captured| captured.exit == 0) {
                let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
                state.blocked_generation = None;
                state.backoff = 0;
            }
            let _ = job.reply.send(result.map_err(|error| format!("{error:#}")));
        } else {
            let generation = GENERATION.load(Ordering::Acquire);
            let boundary = sync_local(generation, || crate::build_local()?.outgoing_boundary());
            let result = boundary.and_then(|boundary| {
                SYNC_CONTEXT.with(|context| context.set(Some((generation, boundary))));
                crate::background_sync_once()
            });
            let mut state = SYNC_KICK.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(synchronized) => {
                    state.backoff = 0;
                    state.blocked_generation = None;
                    if synchronized {
                        state.last_success = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .ok()
                            .map(|v| v.as_secs());
                    }
                }
                Err(error)
                    if error
                        .downcast_ref::<respire::sync::SyncBoundaryChanged>()
                        .is_some() =>
                {
                    state.backoff = 0;
                    state.blocked_generation = None;
                    state.due = Some(Instant::now() + Duration::from_secs(3));
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
                Err(error) if generation != GENERATION.load(Ordering::Acquire) => {
                    state.backoff = 0;
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
                Err(error) => {
                    let transport = crate::is_retriable_sync_error(&error);
                    let delay = if transport {
                        30_u64.saturating_mul(1 << state.backoff.min(4)).min(300)
                    } else {
                        300
                    };
                    state.backoff = state.backoff.saturating_add(1);
                    if transport {
                        state.due = Some(Instant::now() + Duration::from_secs(delay));
                    } else {
                        state.blocked_generation = Some(generation);
                        state.due = None;
                    }
                    eprintln!("command=sync status=warn mode=auto error={error}");
                }
            }
        }
        SYNC_CONTEXT.with(|context| context.set(None));
        SYNC_RUNNING.store(false, Ordering::Release);
        kick_index();
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeFlags {
    pub port: Option<u16>,
    pub host: String,
    pub status: bool,
    pub stop: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcRequest {
    v: u32,
    id: String,
    method: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RpcResponse {
    v: u32,
    id: String,
    ok: bool,
    exit: i32,
    #[serde(default)]
    bin: String,
    #[serde(default)]
    envelope: Option<ResultEnvelope>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    web_url: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    data_dir: Option<String>,
}

struct Job {
    args: Vec<String>,
    stop: bool,
    reply: Sender<std::result::Result<crate::Captured, String>>,
    sync_context: Option<(usize, i64)>,
}

pub fn call_from_argv() -> Result<()> {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--direct" && arg != "--client-only")
        .collect();
    let json = args.iter().any(|arg| arg == "--json")
        || std::env::var("ONEMEMORY_JSON").is_ok_and(|v| v == "1" || v == "true");
    crate::set_json_mode(json);
    let response = call_method("cli.exec", args, true)?;
    render_response(response, json)
}

pub fn runtime_is_up() -> bool {
    call_method("runtime.status", Vec::new(), false).is_ok()
}

/// Run one command through the resident runtime and return its JSON envelope.
/// Starts the runtime if it is not up yet. The envelope is returned even when
/// the command status is fail, so a dashboard can show the failing checks.
pub fn query_json(args: Vec<String>) -> Result<serde_json::Value> {
    query_json_with_start(args, true)
}

/// TUI polling must not start or replace a runtime while a host action is running.
pub(crate) fn query_existing_json(args: Vec<String>) -> Result<serde_json::Value> {
    query_json_with_start(args, false)
}

fn query_json_with_start(args: Vec<String>, auto_start: bool) -> Result<serde_json::Value> {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push("--json".to_owned());
    full.extend(args);
    if JOB_TX.get().is_some() {
        return execute_json(full).map_err(|err| anyhow::anyhow!("{err}"));
    }
    let response = call_method("cli.exec", full, auto_start)?;
    if let Some(envelope) = response.envelope {
        return Ok(serde_json::to_value(envelope).context("runtime envelope could not be encoded")?);
    }
    let err = response
        .error
        .unwrap_or_else(|| "runtime returned an empty response".to_owned());
    bail!("{err}")
}

/// Pid and web URL of the resident runtime, if it answers.
pub fn runtime_brief() -> Option<(u32, String)> {
    let response = call_method("runtime.status", Vec::new(), false).ok()?;
    Some((
        response.pid.unwrap_or(0),
        response.web_url.unwrap_or_default(),
    ))
}

pub fn stop_if_running() -> Result<()> {
    let _takeover = crate::runtime_policy::takeover_lock()?;
    if let Some(health) = probe_runtime()? {
        stop_occupant(health.pid)?;
    }
    Ok(())
}

/// Host profile changes release the old library before starting its successor.
pub fn change_profile(change: impl FnOnce() -> Result<()>) -> Result<()> {
    let _takeover = crate::runtime_policy::takeover_lock()?;
    let config_path = respire::service::client_config_path();
    let original = match std::fs::read(&config_path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(health) = probe_runtime()? {
        stop_occupant(health.pid)?;
    }
    let changed = change().and_then(|_| ensure_daemon_locked());
    if let Err(error) = changed {
        // Startup failure must restore the original selection and all API fields,
        // including the distinction between an absent config and an empty one.
        match original {
            Some(bytes) => std::fs::write(&config_path, bytes)
                .context("profile switch failed and original configuration could not be restored")?,
            None => match std::fs::remove_file(&config_path) {
                Ok(()) => {}
                Err(remove) if remove.kind() == std::io::ErrorKind::NotFound => {}
                Err(remove) => return Err(error.context(format!("configuration rollback failed: {remove}"))),
            },
        }
        return match ensure_daemon_locked() {
            Ok(()) => Err(error),
            Err(restart) => Err(error.context(format!("original runtime restart failed: {restart:#}"))),
        };
    }
    Ok(())
}

pub fn runtime_entry(flags: RuntimeFlags) -> Result<()> {
    if flags.status {
        return match call_method("runtime.status", Vec::new(), false) {
            Ok(response) => {
                if crate::json_mode() {
                    return crate::emit_result(ResultEnvelope::new(
                        "runtime",
                        OutputStatus::Ok,
                        json!({"state":"up","pid":response.pid,"url":response.web_url,"data_dir":response.data_dir}),
                        Vec::new(),
                    ));
                }
                println!(
                    "runtime=up pid={} url={} data_dir={}",
                    response.pid.unwrap_or(0),
                    response.web_url.as_deref().unwrap_or(""),
                    response.data_dir.as_deref().unwrap_or("")
                );
                Ok(())
            }
            Err(error) => {
                if crate::json_mode() {
                    let mut envelope = ResultEnvelope::new(
                        "runtime",
                        OutputStatus::Warn,
                        json!({"state":"down"}),
                        Vec::new(),
                    );
                    envelope.errors.push(format!("{error:#}"));
                    return crate::emit_result(envelope);
                }
                eprintln!("{error:#}");
                crate::set_exit_code(2);
                Ok(())
            }
        };
    }
    if flags.stop {
        stop_if_running()?;
        if crate::json_mode() {
            return crate::emit_result(ResultEnvelope::new(
                "runtime",
                OutputStatus::Ok,
                json!({"state":"stopped"}),
                Vec::new(),
            ));
        }
        println!("runtime=stopped");
        return Ok(());
    }
    crate::runtime_policy::require_host("runtime startup")?;
    std::env::set_var("ONEMEMORY_RUNTIME", "1");
    serve(flags, true)
}

fn render_response(response: RpcResponse, json: bool) -> Result<()> {
    if let Some(envelope) = response.envelope {
        println!("{}", envelope.render(json)?);
        crate::mark_emitted();
        crate::set_exit_code(response.exit);
        return Ok(());
    }
    bail!(
        "{}",
        response
            .error
            .unwrap_or_else(|| "runtime returned an empty response".to_owned())
    )
}

fn call_method(method: &str, args: Vec<String>, auto_start: bool) -> Result<RpcResponse> {
    let auto = auto_start && !crate::net_rpc::no_autostart();
    // Validate/start the runtime for this data directory before submitting work.
    // Once submitted, a disconnect must not cause a mutating command to be replayed.
    if auto {
        ensure_daemon()?;
    }
    let response = http_roundtrip(method, &args)?;
    if !compatible(&response) {
        bail!("local runtime protocol/version mismatch");
    }
    Ok(response)
}

pub(crate) fn model_control(task_id: &str, cancel: bool) -> Result<Value> {
    let args = vec![task_id.to_owned(), cancel.to_string()];
    let response = call_method("model.control", args, false)?;
    anyhow::ensure!(response.ok, "{}", response.error.unwrap_or_default());
    response
        .envelope
        .map(|envelope| envelope.summary)
        .ok_or_else(|| anyhow::anyhow!("runtime did not return model progress"))
}

fn http_roundtrip(method: &str, args: &[String]) -> Result<RpcResponse> {
    match method {
        "runtime.status" => {
            let health = crate::net_rpc::health()?;
            Ok(RpcResponse {
                v: health.v,
                id: "health".into(),
                ok: true,
                exit: 0,
                bin: health.bin,
                envelope: None,
                error: None,
                code: None,
                web_url: Some(health.url),
                pid: Some(health.pid),
                data_dir: Some(respire::service::data_dir().display().to_string()),
            })
        }
        "runtime.stop" => {
            crate::net_rpc::request_stop()?;
            Ok(RpcResponse {
                v: PROTOCOL_V,
                id: "stop".into(),
                ok: true,
                exit: 0,
                bin: env!("CARGO_PKG_VERSION").to_owned(),
                envelope: None,
                error: None,
                code: None,
                web_url: None,
                pid: None,
                data_dir: None,
            })
        }
        "cli.exec" | "model.control" | "index.prepare" => {
            let parsed = if method == "cli.exec" {
                crate::net_rpc::rpc_exec(args.to_vec())?
            } else {
                crate::net_rpc::rpc_method(method, args.to_vec())?
            };
            serde_json::from_value(parsed).context("runtime rpc response shape mismatch")
        }
        other => bail!("unknown runtime method {other}"),
    }
}

fn compatible(response: &RpcResponse) -> bool {
    response.v == PROTOCOL_V && response.code.as_deref() != Some("protocol_version_mismatch")
}

fn try_exchange(request: &RpcRequest) -> Result<RpcResponse> {
    let mut stream = Stream::connect(pipe_name()?).context("runtime server is not running")?;
    let body = serde_json::to_vec(request)?;
    write_frame(&mut stream, &body)?;
    let bytes = read_frame(&mut stream)?;
    let response: RpcResponse = serde_json::from_slice(&bytes).context("bad runtime response")?;
    if response.id != request.id {
        bail!("runtime response id mismatch");
    }
    Ok(response)
}

fn serve(flags: RuntimeFlags, _detached: bool) -> Result<()> {
    crate::runtime_policy::require_host("runtime startup")?;
    // Ignore SIGHUP off this thread. signal_hook's handler install must not sit
    // in front of bind: under llvm-cov that call can stall the thread that has
    // to become the listener, and the coverage run then never sees the runtime.
    #[cfg(unix)]
    {
        let _ = std::thread::Builder::new()
            .name("respire-sighup".into())
            .spawn(|| {
                let _ = signal_hook::flag::register(
                    signal_hook::consts::SIGHUP,
                    Arc::new(AtomicBool::new(false)),
                );
            });
    }
    let boot = respire::lock::LibraryLock::acquire(&runtime_dir(), Duration::from_secs(15))?;
    // Children only bind. The host caller owns stop/copy/upgrade decisions.
    if probe_runtime()?.is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    clear_dead_socket();
    let listener = match ListenerOptions::new().name(pipe_name()?).create_sync() {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            drop(boot);
            if try_exchange(&RpcRequest {
                v: PROTOCOL_V,
                id: "bind-probe".into(),
                method: "runtime.status".into(),
                args: Vec::new(),
            })
            .is_ok()
            {
                return Ok(());
            }
            return Err(error).context("runtime pipe is already taken");
        }
        Err(error) => return Err(error).context("failed to bind the runtime pipe"),
    };
    let Some(bound) = bind_http(&flags, _detached)? else {
        return Ok(());
    };
    {
        let mut url = WEB_URL.lock().unwrap_or_else(|err| err.into_inner());
        *url = bound.url.clone();
    }
    write_endpoint(&bound.url)?;
    drop(boot);
    let (tx, rx) = mpsc::channel();
    let _ = JOB_TX.set(Mutex::new(tx.clone()));
    // Sandboxed clients cannot restart an idle-exited host runtime.
    let idle = None;
    let limit = worker_limit();
    WORKERS.store(limit, Ordering::Release);
    RUNNING.store(0, Ordering::Release);
    std::thread::Builder::new()
        .name("respire-dispatch".into())
        .spawn(move || dispatch_loop(rx, limit, idle))
        .context("failed to start the runtime dispatcher")?;
    std::thread::spawn(move || {
        if let Err(error) = crate::runtime_http::serve_loop(bound.server) {
            eprintln!("runtime HTTP server stopped: {error:#}");
        }
    });
    accept_loop(listener, tx);
    Ok(())
}

fn bind_http(
    flags: &RuntimeFlags,
    _detached: bool,
) -> Result<Option<crate::runtime_http::BoundRuntime>> {
    crate::runtime_http::bind_runtime(flags.port, &flags.host).map(Some)
}

fn accept_loop(listener: interprocess::local_socket::Listener, tx: Sender<Job>) {
    for connection in listener.incoming() {
        if STOPPING.load(Ordering::Acquire) {
            break;
        }
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("runtime accept failed: {error}");
                continue;
            }
        };
        let tx = tx.clone();
        std::thread::spawn(move || {
            if let Err(error) = handle_connection(connection, &tx) {
                eprintln!("runtime connection failed: {error:#}");
            }
        });
    }
}

fn handle_connection(mut stream: Stream, tx: &Sender<Job>) -> Result<()> {
    let bytes = read_frame(&mut stream)?;
    let request: RpcRequest = serde_json::from_slice(&bytes)?;
    let response = dispatch(request, tx);
    write_frame(&mut stream, &serde_json::to_vec(&response)?)?;
    Ok(())
}

fn dispatch(request: RpcRequest, tx: &Sender<Job>) -> RpcResponse {
    if request.v != PROTOCOL_V {
        return error_response(
            &request,
            "protocol_version_mismatch",
            "protocol version mismatch",
        );
    }
    if let Some(hit) = cached(&request.id) {
        return hit;
    }
    let response = match request.method.as_str() {
        "index.prepare" => {
            kick_index();
            let mut response = status_response(&request);
            response.envelope = Some(ResultEnvelope::new(
                "index.prepare", OutputStatus::Pending, index_status(), Vec::new(),
            ));
            response
        }
        "model.control" => match respire::model_progress::control(
            request.args.first().map(String::as_str).unwrap_or(""),
            request.args.get(1).is_some_and(|arg| arg == "true"),
        ) {
            Ok(progress) => {
                let mut response = status_response(&request);
                response.envelope = Some(ResultEnvelope::new(
                    "model.control",
                    OutputStatus::Ok,
                    progress,
                    Vec::new(),
                ));
                response
            }
            Err(error) => error_response(&request, "model_control_failed", &error.to_string()),
        },
        "runtime.status" => status_response(&request),
        "runtime.stop" => {
            request_drain_exit();
            status_response(&request)
        }
        "cli.exec" => match submit(tx, request.args.clone(), false) {
            Ok(captured) => RpcResponse {
                v: PROTOCOL_V,
                id: request.id.clone(),
                ok: captured.exit == 0,
                exit: captured.exit,
                bin: env!("CARGO_PKG_VERSION").to_owned(),
                envelope: Some(captured.envelope),
                error: None,
                code: None,
                web_url: Some(current_url()),
                pid: Some(std::process::id()),
                data_dir: Some(respire::service::data_dir().display().to_string()),
            },
            Err(error) => error_response(&request, "daemon_unavailable", &error),
        },
        other => error_response(
            &request,
            "protocol_version_mismatch",
            &format!("unknown method {other}"),
        ),
    };
    remember(&request.id, &response);
    response
}

fn status_response(request: &RpcRequest) -> RpcResponse {
    RpcResponse {
        v: PROTOCOL_V,
        id: request.id.clone(),
        ok: true,
        exit: 0,
        bin: env!("CARGO_PKG_VERSION").to_owned(),
        envelope: None,
        error: None,
        code: None,
        web_url: Some(current_url()),
        pid: Some(std::process::id()),
        data_dir: Some(respire::service::data_dir().display().to_string()),
    }
}

fn error_response(request: &RpcRequest, code: &str, error: &str) -> RpcResponse {
    RpcResponse {
        v: PROTOCOL_V,
        id: request.id.clone(),
        ok: false,
        exit: 1,
        bin: env!("CARGO_PKG_VERSION").to_owned(),
        envelope: None,
        error: Some(error.to_owned()),
        code: Some(code.to_owned()),
        web_url: None,
        pid: Some(std::process::id()),
        data_dir: None,
    }
}

fn submit(
    tx: &Sender<Job>,
    args: Vec<String>,
    stop: bool,
) -> std::result::Result<crate::Captured, String> {
    let slots = WORKERS.load(Ordering::Acquire).max(1);
    if !stop
        && is_status(&args)
        && RUNNING
            .load(Ordering::Acquire)
            .saturating_sub(RUNNING_STATUS.load(Ordering::Acquire))
            >= slots
    {
        let mut envelope = ResultEnvelope::new(
            "status",
            OutputStatus::Warn,
            json!({"state": "busy", "workers": slots}),
            Vec::new(),
        );
        envelope.errors.push(i18n::text("busy").to_owned());
        return Ok(crate::Captured { exit: 2, envelope });
    }
    let sync_context = if matches!(
        command_name(&args),
        Some("sync" | "sync-conflicts" | "sync-resolve" | "sync-history")
    ) {
        let gate = shared_exclusive();
        let _held = gate.acquire(true);
        let boundary = crate::build_local()
            .and_then(|store| store.outgoing_boundary())
            .map_err(|error| format!("{error:#}"))?;
        Some((GENERATION.load(Ordering::Acquire), boundary))
    } else if command_name(&args) == Some("classify") {
        let gate = shared_exclusive();
        let _held = gate.acquire(true);
        Some((GENERATION.load(Ordering::Acquire), -1))
    } else {
        None
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(Job {
        args,
        stop,
        reply: reply_tx,
        sync_context,
    })
    .map_err(|_| "runtime worker is gone".to_owned())?;
    reply_rx
        .recv()
        .map_err(|_| "runtime worker dropped the reply".to_owned())?
}

fn execute_json(args: Vec<String>) -> std::result::Result<Value, String> {
    let tx = {
        let guard = JOB_TX
            .get()
            .ok_or_else(|| "runtime worker is not running".to_owned())?
            .lock()
            .map_err(|_| "runtime worker lock poisoned".to_owned())?;
        guard.clone()
    };
    let captured = submit(&tx, args, false)?;
    serde_json::to_value(&captured.envelope).map_err(|err| err.to_string())
}

pub(crate) fn request_drain_exit() {
    STOPPING.store(true, Ordering::Release);
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
    std::thread::spawn(|| {
        for _ in 0..80 {
            if RUNNING.load(Ordering::Acquire) == 0
                && !WRITE_RUNNING.load(Ordering::Acquire)
                && !CLASSIFY_RUNNING.load(Ordering::Acquire)
                && !sync_running()
                && !index_has_work()
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        stop_process(0);
    });
}

pub(crate) fn handle_http_rpc(body: &[u8]) -> Result<RpcResponse> {
    let request: RpcRequest = serde_json::from_slice(body).context("rpc body is not JSON")?;
    let tx = {
        let guard = JOB_TX
            .get()
            .ok_or_else(|| anyhow::anyhow!("runtime worker is not running"))?
            .lock()
            .map_err(|_| anyhow::anyhow!("runtime worker lock poisoned"))?;
        guard.clone()
    };
    Ok(dispatch(request, &tx))
}

pub(crate) fn health_body() -> Value {
    let exe = std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    json!({
        "server": "respire",
        "bin": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "v": PROTOCOL_V,
        "url": current_url(),
        "exe": exe,
        "data_dir": respire::service::data_dir().display().to_string(),
        "recall_statistics": recall_stats_status(),
        "retrieval_index": index_status(),
    })
}

fn stop_process(code: i32) -> ! {
    #[cfg(test)]
    {
        let _ = code;
        loop {
            std::thread::park();
        }
    }
    #[cfg(not(test))]
    {
        std::process::exit(code);
    }
}

const WORKER_CAP: usize = 4;

/// Job slots for this process. `ONEMEMORY_RPC_PARALLELISM` wins, then
/// `client.json` `rpc_parallelism`, otherwise the CPU count. Never above 4.
/// `0` and `cpu` follow the CPU, still capped at 4.
/// Read-only jobs may run in parallel up to this cap. Writes take the exclusive
/// gate and queue. ONNX is a process singleton and queues separately.
pub(crate) fn worker_limit() -> usize {
    if let Ok(raw) = std::env::var("ONEMEMORY_RPC_PARALLELISM") {
        let raw = raw.trim();
        if raw.is_empty() || raw.eq_ignore_ascii_case("cpu") {
            return cpu_count();
        }
        if let Ok(parsed) = raw.parse::<usize>() {
            if parsed == 0 {
                return cpu_count();
            }
            return parsed.clamp(1, WORKER_CAP);
        }
    }
    if let Some(saved) = respire::service::rpc_parallelism_setting() {
        return saved.clamp(1, WORKER_CAP);
    }
    cpu_count()
}

fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, WORKER_CAP)
}

fn is_exclusive(args: &[String]) -> bool {
    matches!(
        command_name(args),
        Some(
            "remember"
                | "update"
                | "forget"
                | "restore"
                | "purge"
                | "attach"
                | "promote"
                | "demote"
                | "retitle"
                | "retitle-many"
                | "import"
                | "reembed"
                | "resort"
                | "split"
                | "tree-deepen"
                | "tree-cure"
                | "tree-float"
                | "sync"
                | "sync-conflicts"
                | "sync-resolve"
                | "sync-restore"
                | "sync-reset"
                | "repack"
                | "inject"
                | "keygen"
                | "account"
                | "space"
                | "fivekeys"
                | "super-reset"
                | "register"
                | "login"
                | "logout"
                | "config"
                | "agent-config"
                | "model"
                | "grant"
                | "session"
                | "query-log"
                | "doctor"
                | "root-create"
                | "share-import"
                | "backup"
        )
    )
}

struct RunningGuard {
    status: bool,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        RUNNING.fetch_sub(1, Ordering::AcqRel);
        if self.status {
            RUNNING_STATUS.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct ClassifyGuard;
impl Drop for ClassifyGuard {
    fn drop(&mut self) {
        SYNC_CONTEXT.with(|context| context.set(None));
        CLASSIFY_RUNNING.store(false, Ordering::Release);
    }
}

fn dispatch_loop(rx: Receiver<Job>, limit: usize, idle: Option<Duration>) {
    let _lock = match respire::lock::LibraryLock::acquire(
        &respire::service::data_dir(),
        Duration::from_secs(120),
    ) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("runtime failed to lock the library: {error:#}");
            stop_process(1);
        }
    };
    // Keep WAL open across requests: closing the last connection can briefly lock
    // a concurrent opener during checkpoint/cleanup, even for read-only status.
    let _store = match respire::service::open_store() {
        Ok(store) => store,
        Err(error) => {
            eprintln!("runtime failed to initialize the library: {error:#}");
            stop_process(1);
        }
    };
    respire::service::install_runtime_profile(respire::service::data_dir());
    let (classify_tx, classify_rx) = mpsc::sync_channel::<Job>(16);
    let classifier = std::thread::Builder::new()
        .name("respire-classify".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            mark_worker();
            while let Ok(job) = classify_rx.recv() {
                if STOPPING.load(Ordering::Acquire) {
                    let _ = job.reply.send(Err("runtime is stopping".into()));
                    continue;
                }
                let Some((generation, _)) = job.sync_context else {
                    let _ = job.reply.send(Err("missing classification context".into()));
                    continue;
                };
                CLASSIFY_RUNNING.store(true, Ordering::Release);
                let _active = ClassifyGuard;
                SYNC_CONTEXT.with(|context| context.set(Some((generation, -1))));
                let result = check_sync_context(generation)
                    .map(|_| crate::capture_run(job.args))
                    .map_err(|error| format!("{error:#}"));
                let _ = job.reply.send(result);
            }
        });
    if classifier.is_err() {
        stop_process(1);
    }
    let (write_tx, write_rx) = mpsc::sync_channel::<WriteJob>(256);
    if let Ok(mut installed) = WRITE_TX.lock() {
        *installed = Some(write_tx.clone());
    } else {
        eprintln!("runtime failed to install the write queue");
        stop_process(1);
    }
    let writer = std::thread::Builder::new()
        .name("respire-write".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || {
            mark_worker();
            while let Ok(work) = write_rx.recv() {
                let job = match work {
                    WriteJob::Command(job) => job,
                    WriteJob::RecallStats(stats, generation) => {
                        let result = if STOPPING.load(Ordering::Acquire) {
                            shared_exclusive().cancel_reservation();
                            Err(anyhow::anyhow!("runtime is stopping"))
                        } else {
                            WRITE_RUNNING.store(true, Ordering::Release);
                            let gate = shared_exclusive();
                            let _held = gate.acquire_reserved();
                            let result = check_sync_context(generation)
                                .and_then(|_| respire::service::open_store())
                                .and_then(|store| stats.persist(&store));
                            drop(_held);
                            WRITE_RUNNING.store(false, Ordering::Release);
                            result
                        };
                        STATS_PENDING.fetch_sub(1, Ordering::AcqRel);
                        match result {
                            Ok(()) => {
                                STATS_PERSISTED.fetch_add(1, Ordering::AcqRel);
                            }
                            Err(error) => {
                                STATS_FAILED.fetch_add(1, Ordering::AcqRel);
                                eprintln!("recall statistics writeback failed: {error:#}");
                            }
                        }
                        continue;
                    }
                };
                if STOPPING.load(Ordering::Acquire) {
                    shared_exclusive().cancel_reservation();
                    let _ = job.reply.send(Err("runtime is stopping".into()));
                    continue;
                }
                WRITE_RUNNING.store(true, Ordering::Release);
                let gate = shared_exclusive();
                let _held = gate.acquire_reserved();
                let changing_context = matches!(
                    command_name(&job.args),
                    Some(
                        "login"
                            | "logout"
                            | "register"
                            | "keygen"
                            | "config"
                            | "session"
                            | "agent-config"
                            | "sync-reset"
                            | "account"
                            | "space"
                            | "fivekeys"
                            | "super-reset"
                    )
                );
                if changing_context {
                    GENERATION.fetch_add(1, Ordering::AcqRel);
                    SYNC_CV.notify_one();
                }
                let captured = crate::capture_run(job.args);
                drop(_held);
                kick_index();
                if changing_context {
                    context_changed();
                }
                WRITE_RUNNING.store(false, Ordering::Release);
                let _ = job.reply.send(Ok(captured));
            }
        });
    if writer.is_err() {
        stop_process(1);
    }
    respire::service::install_autosync_notifier(kick_autosync);
    respire::service::install_index_notifier(kick_index);
    INDEX_ON.store(true, Ordering::Release);
    let indexer = std::thread::Builder::new()
        .name("respire-index".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(index_loop);
    if let Err(error) = indexer.as_ref() {
        eprintln!("runtime failed to start the index worker: {error}");
        stop_process(1);
    }
    kick_index();
    kick_autosync();
    let mut pending = VecDeque::<Job>::new();
    let mut idle_since = Instant::now();
    loop {
        if STOPPING.load(Ordering::Acquire) {
            break;
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok(job) => {
                if job.stop {
                    break;
                }
                idle_since = Instant::now();
                if matches!(
                    command_name(&job.args),
                    Some("sync" | "sync-conflicts" | "sync-resolve" | "sync-history")
                ) {
                    enqueue_manual(job);
                } else if command_name(&job.args) == Some("classify") {
                    match classify_tx.try_send(job) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(job)) => {
                            let _ = job
                                .reply
                                .send(Err("classification request queue is full".into()));
                        }
                        Err(mpsc::TrySendError::Disconnected(job)) => {
                            let _ = job.reply.send(Err("classification worker is gone".into()));
                        }
                    }
                } else if is_exclusive(&job.args) {
                    shared_exclusive().reserve();
                    match write_tx.try_send(WriteJob::Command(job)) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(WriteJob::Command(job))) => {
                            shared_exclusive().cancel_reservation();
                            let _ = job.reply.send(Err("write request queue is full".into()));
                        }
                        Err(mpsc::TrySendError::Disconnected(WriteJob::Command(job))) => {
                            shared_exclusive().cancel_reservation();
                            let _ = job.reply.send(Err("write worker is gone".into()));
                        }
                        Err(_) => unreachable!("only a command was submitted"),
                    }
                } else if pending.len() < 256 {
                    pending.push_back(job);
                } else {
                    let _ = job.reply.send(Err("read request queue is full".into()));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        while RUNNING.load(Ordering::Acquire) < limit {
            let Some(job) = pending.pop_front() else {
                break;
            };
            let status_job = is_status(&job.args);
            if status_job {
                RUNNING_STATUS.fetch_add(1, Ordering::AcqRel);
            }
            RUNNING.fetch_add(1, Ordering::AcqRel);
            let reply = job.reply.clone();
            let spawned = std::thread::Builder::new()
                .name("respire-read".into())
                .stack_size(16 * 1024 * 1024)
                .spawn(move || {
                    let _slot = RunningGuard { status: status_job };
                    mark_worker();
                    let _ = job.reply.send(Ok(crate::capture_run(job.args)));
                });
            if spawned.is_err() {
                RUNNING.fetch_sub(1, Ordering::AcqRel);
                if status_job {
                    RUNNING_STATUS.fetch_sub(1, Ordering::AcqRel);
                }
                let _ = reply.send(Err("failed to start a read thread".into()));
            }
        }
        if let Some(idle) = idle {
            if RUNNING.load(Ordering::Acquire) > 0
                || WRITE_RUNNING.load(Ordering::Acquire)
                || CLASSIFY_RUNNING.load(Ordering::Acquire)
                || sync_running()
                || index_has_work()
                || !pending.is_empty()
            {
                idle_since = Instant::now();
            } else if idle_since.elapsed() >= idle {
                break;
            }
        }
    }
    STOPPING.store(true, Ordering::Release);
    SYNC_CV.notify_all();
    INDEX_CV.notify_all();
    if let Ok(mut installed) = WRITE_TX.lock() {
        installed.take();
    }
    drop(write_tx);
    drop(classify_tx);
    for job in pending {
        let _ = job.reply.send(Err("runtime is stopping".into()));
    }
    if let Ok(writer) = writer {
        let _ = writer.join();
    }
    if let Ok(classifier) = classifier {
        let _ = classifier.join();
    }
    if let Ok(indexer) = indexer {
        if indexer.join().is_err() {
            eprintln!("background index worker panicked during shutdown");
        }
    }
    while RUNNING.load(Ordering::Acquire) > 0 || sync_running() {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(_lock);
    stop_process(0);
}

fn is_status(args: &[String]) -> bool {
    command_name(args) == Some("status")
}

fn command_name(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn cached(id: &str) -> Option<RpcResponse> {
    CACHE
        .lock()
        .ok()?
        .iter()
        .find(|(key, _)| key == id)
        .map(|(_, response)| response.clone())
}

fn remember(id: &str, response: &RpcResponse) {
    if id.is_empty() || id == "bind-probe" {
        return;
    }
    if let Ok(mut cache) = CACHE.lock() {
        cache.retain(|(key, _)| key != id);
        cache.push((id.to_owned(), response.clone()));
        if cache.len() > 64 {
            let extra = cache.len() - 64;
            cache.drain(0..extra);
        }
    }
}

fn current_url() -> String {
    WEB_URL
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .clone()
}

pub(crate) fn runtime_dir_path() -> PathBuf {
    runtime_dir()
}

fn runtime_dir() -> PathBuf {
    respire::service::main_data_dir().join("runtime")
}

fn endpoint_path() -> PathBuf {
    runtime_dir().join("endpoint.json")
}

fn write_endpoint(url: &str) -> Result<()> {
    let dir = runtime_dir();
    std::fs::create_dir_all(&dir)?;
    let body = json!({
        "v": PROTOCOL_V,
        "pid": std::process::id(),
        "bin": env!("CARGO_PKG_VERSION"),
        "url": url,
    });
    std::fs::write(endpoint_path(), serde_json::to_vec_pretty(&body)?)?;
    Ok(())
}

fn endpoint_pid() -> Option<u32> {
    let text = std::fs::read_to_string(endpoint_path()).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    data.get("pid")?
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
}

/// The host-owned endpoint record must identify the actual loopback listener.
pub(crate) fn recorded_runtime_listener(pid: u32) -> bool {
    let Ok(text) = std::fs::read_to_string(endpoint_path()) else {
        return false;
    };
    let Ok(data) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    data["pid"].as_u64() == Some(u64::from(pid))
        && data["v"].as_u64() == Some(u64::from(PROTOCOL_V))
        && data["bin"].as_str().is_some_and(|version| !version.is_empty())
        && data["url"].as_str().is_some_and(|url| {
            url == crate::net_rpc::rpc_base_url()
                || url == format!("http://localhost:{}", crate::net_rpc::rpc_port())
        })
}

/// Recovery must not wait on RPC, model locks or a library lock.
pub(crate) fn force_stop_for_reset() -> Result<Option<u32>> {
    let port = crate::net_rpc::rpc_port();
    let Some(pid) = crate::net_rpc::pid_listening_on(port) else {
        if crate::net_rpc::port_is_open() {
            bail!("CPU saved, but cannot identify runtime on port {port}");
        }
        return Ok(None);
    };
    if pid == std::process::id() || !crate::net_rpc::pid_is_respire(pid) {
        bail!("CPU saved; refusing to terminate non-runtime process {pid} on port {port}");
    }
    #[cfg(windows)]
    let status = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    #[cfg(unix)]
    let status = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()?;
    if !status.success() {
        bail!("CPU saved, but failed to terminate runtime {pid}");
    }
    crate::net_rpc::wait_until_down().context("CPU saved, but runtime port is still occupied")?;
    if endpoint_pid() == Some(pid) && endpoint_path().exists() {
        std::fs::remove_file(endpoint_path())?;
    }
    Ok(Some(pid))
}

fn pipe_label() -> String {
    use sha2::{Digest, Sha256};
    let dir = respire::service::data_dir();
    let mut hasher = Sha256::new();
    hasher.update(dir.to_string_lossy().as_bytes());
    format!("om{}", hex::encode(&hasher.finalize()[..8]))
}

fn pipe_name() -> Result<Name<'static>> {
    #[cfg(windows)]
    {
        std::ffi::OsString::from(pipe_label())
            .to_ns_name::<GenericNamespaced>()
            .context("failed to build the runtime pipe name")
    }
    #[cfg(unix)]
    {
        unix_socket_name()
    }
}

/// Socket path for the current data dir. Not cached: one process runs many
/// tests, and each test points `ONEMEMORY_DATA_DIR` somewhere else.
#[cfg(unix)]
fn socket_path() -> PathBuf {
    runtime_dir().join("rpc.sock")
}

/// Unix keeps the socket inside the data dir so a dead runtime can be cleared.
/// A namespaced name under `/tmp` or `$TMPDIR` stays behind after a crash and the
/// next `--runtime-internal` never becomes ready.
#[cfg(unix)]
fn unix_socket_name() -> Result<Name<'static>> {
    use interprocess::local_socket::GenericFilePath;
    let path = socket_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    path.to_fs_name::<GenericFilePath>()
        .context("failed to build the runtime socket name")
}

/// Drop a socket file left by a dead process. Connecting is the check: an
/// endpoint pid in this data dir can still be alive while the file belongs to
/// an older path, and unlinking from the connect path races the listener.
#[cfg(unix)]
fn clear_dead_socket() {
    let path = socket_path();
    if !path.exists() {
        return;
    }
    let listening = try_exchange(&RpcRequest {
        v: PROTOCOL_V,
        id: "bind-probe".into(),
        method: "runtime.status".into(),
        args: Vec::new(),
    })
    .is_ok();
    if !listening {
        let _ = std::fs::remove_file(path);
    }
}

/// Only a refused connection permits startup; authentication and access failures
/// leave the existing service untouched.
fn probe_runtime() -> Result<Option<crate::net_rpc::Health>> {
    match crate::net_rpc::health() {
        Ok(health) => Ok(Some(health)),
        Err(error)
            if matches!(
                error.downcast_ref::<crate::runtime_error::RuntimeError>(),
                Some(crate::runtime_error::RuntimeError::Unavailable)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_daemon() -> Result<()> {
    if crate::runtime_policy::client_only() {
        crate::net_rpc::health()?;
        return Ok(());
    }
    // Hold across probe, stop, copy, spawn and readiness. Re-probe after waiting.
    let _takeover = crate::runtime_policy::takeover_lock()?;
    ensure_daemon_locked()
}

fn ensure_daemon_locked() -> Result<()> {
    let dest = crate::mcp::stable_bin_path();
    let src = std::env::current_exe().context("failed to locate the rsrs binary")?;
    if let Some(health) = probe_runtime()? {
        let same_lib = health.data_dir == respire::service::data_dir().display().to_string();
        let same_ver = health.bin == env!("CARGO_PKG_VERSION");
        let same_path = crate::mcp::exe_matches_dest(&health.exe, &dest);
        if same_lib
            && same_ver
            && same_path
            && !crate::mcp::bin_needs_refresh(&src, &dest).map_err(anyhow::Error::msg)?
        {
            return Ok(());
        }
        stop_occupant(health.pid)?;
    }
    let executable = crate::mcp::materialize_bin().map_err(anyhow::Error::msg)?;
    let mut child =
        respire_spawn::spawn_runtime(&executable).context("failed to start host runtime")?;
    let result = wait_daemon_ready(&mut child, &executable);
    if result.is_err() && child.try_wait()?.is_none() {
        // Do not leave a delayed startup racing the next lock holder.
        child
            .kill()
            .context("failed to stop unready host runtime")?;
        child
            .wait()
            .context("failed to reap unready host runtime")?;
    }
    result
}

fn stop_occupant(pid: u32) -> Result<()> {
    let health = crate::net_rpc::health()?;
    anyhow::ensure!(health.pid == pid, "runtime owner changed before shutdown");
    crate::net_rpc::request_stop()?;
    if crate::net_rpc::wait_until_down().is_err() {
        // Reauthenticate before escalation; a different owner may have bound.
        if let Some(health) = probe_runtime()? {
            anyhow::ensure!(health.pid == pid, "runtime owner changed during shutdown");
            crate::net_rpc::kill_pid(pid);
            crate::net_rpc::wait_until_down()?;
        }
    }
    crate::net_rpc::wait_until_exited(pid)?;
    // Prove lock.db has been released before a successor opens the library.
    let released = respire::lock::LibraryLock::acquire(
        std::path::Path::new(&health.data_dir), Duration::from_secs(15),
    ).context("stopped runtime has not released its library lock")?;
    drop(released);
    Ok(())
}

fn wait_daemon_ready(child: &mut std::process::Child, executable: &std::path::Path) -> Result<()> {
    let deadline = Instant::now() + START_WAIT * START_POLLS as u32;
    while Instant::now() < deadline {
        std::thread::sleep(START_WAIT);
        if let Some(status) = child.try_wait()? {
            bail!("host runtime exited before readiness: {status}");
        }
        if let Some(health) = probe_runtime()? {
            anyhow::ensure!(
                health.pid == child.id()
                    && crate::mcp::exe_matches_dest(&health.exe, executable)
                    && health.bin == env!("CARGO_PKG_VERSION")
                    && health.data_dir == respire::service::data_dir().display().to_string(),
                "runtime owner changed during startup"
            );
            return Ok(());
        }
    }
    bail!("host runtime did not become ready")
}

pub fn write_frame(mut writer: impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        bail!("frame exceeds {MAX_FRAME} bytes");
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .context("peer closed before a complete frame")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame exceeds {MAX_FRAME} bytes");
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .context("peer closed in the middle of a frame")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::Ordering;

    #[test]
    fn frame_roundtrip() -> Result<()> {
        let payload = b"{\"v\":1}";
        let mut buffer = Vec::new();
        write_frame(&mut buffer, payload)?;
        let mut cursor = Cursor::new(buffer);
        assert_eq!(read_frame(&mut cursor)?, payload);
        Ok(())
    }

    #[test]
    fn rejects_half_frame() {
        let mut cursor = Cursor::new(vec![4, 0, 0, 0, b'{']);
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn rejects_huge_frame_without_allocating_it() {
        let mut cursor = Cursor::new(u32::MAX.to_le_bytes().to_vec());
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn pipe_label_is_stable() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let label = pipe_label();
        assert_eq!(label, pipe_label());
        assert!(label.starts_with("om"));
        assert!(pipe_name().is_ok());
    }

    fn req(method: &str, id: &str) -> RpcRequest {
        RpcRequest {
            v: PROTOCOL_V,
            id: id.to_owned(),
            method: method.to_owned(),
            args: Vec::new(),
        }
    }

    #[test]
    fn frame_rejects_oversized_payload() {
        let mut buffer = Vec::new();
        let payload = vec![0u8; MAX_FRAME + 1];
        assert!(write_frame(&mut buffer, &payload).is_err());
    }

    #[test]
    fn empty_frame_roundtrip() -> Result<()> {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"")?;
        let mut cursor = Cursor::new(buffer);
        assert!(read_frame(&mut cursor)?.is_empty());
        Ok(())
    }

    #[test]
    fn worker_limit_follows_env_then_cpu() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = std::env::var("ONEMEMORY_RPC_PARALLELISM").ok();
        std::env::set_var("ONEMEMORY_RPC_PARALLELISM", "3");
        assert_eq!(worker_limit(), 3);
        std::env::set_var("ONEMEMORY_RPC_PARALLELISM", "0");
        assert_eq!(worker_limit(), cpu_count());
        std::env::set_var("ONEMEMORY_RPC_PARALLELISM", "cpu");
        assert_eq!(worker_limit(), cpu_count());
        std::env::set_var("ONEMEMORY_RPC_PARALLELISM", "20");
        assert_eq!(worker_limit(), WORKER_CAP);
        std::env::set_var("ONEMEMORY_RPC_PARALLELISM", "1000");
        assert_eq!(worker_limit(), WORKER_CAP);
        assert!(cpu_count() <= WORKER_CAP);
        match previous {
            Some(value) => std::env::set_var("ONEMEMORY_RPC_PARALLELISM", value),
            None => std::env::remove_var("ONEMEMORY_RPC_PARALLELISM"),
        }
    }

    #[test]
    fn writes_queue_and_reads_may_run_together() {
        assert!(is_exclusive(&["--json".into(), "sync".into()]));
        assert!(is_exclusive(&["reembed".into()]));
        assert!(is_exclusive(&["remember".into(), "x".into()]));
        assert!(is_exclusive(&["update".into(), "id".into()]));
        assert!(is_exclusive(&["forget".into(), "id".into()]));
        assert!(is_exclusive(&["attach".into(), "id".into()]));
        assert!(!is_exclusive(&["recall".into(), "respire".into()]));
        assert!(!is_exclusive(&["status".into()]));
        assert!(!is_exclusive(&["list".into()]));
        assert!(!is_exclusive(&["show".into(), "id".into()]));
        assert!(!is_exclusive(&["sync-history".into()]));
        assert!(!is_exclusive(&["diary".into()]));
        assert_eq!(WORKER_CAP, 4);
    }

    #[test]
    fn command_names_ignore_flags() {
        assert_eq!(command_name(&[]), None);
        assert_eq!(
            command_name(&["--json".into(), "status".into()]).as_deref(),
            Some("status")
        );
        assert!(is_status(&["--json".into(), "status".into()]));
        assert!(!is_status(&["remember".into()]));
    }

    #[test]
    fn compatible_requires_version_and_bin() {
        let mut response = status_response(&req("runtime.status", "s"));
        assert!(compatible(&response));
        response.v = 99;
        assert!(!compatible(&response));
        response.v = PROTOCOL_V;
        response.bin = "other".into();
        assert!(compatible(&response));
        response.code = Some("protocol_version_mismatch".into());
        assert!(!compatible(&response));
    }

    #[test]
    fn cache_ignores_probe_and_drops_oldest() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let response = error_response(&req("x", "id"), "timeout", "slow");
        remember("", &response);
        remember("bind-probe", &response);
        assert!(cached("bind-probe").is_none());
        for index in 0..70 {
            let id = format!("id-{index}");
            remember(&id, &status_response(&req("runtime.status", &id)));
        }
        assert!(cached("id-0").is_none());
        assert!(cached("id-69").is_some());
    }

    #[test]
    fn dispatch_reports_status_mismatch_and_unknown() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let (tx, _rx) = mpsc::channel();
        let mut bad = req("runtime.status", "bad");
        bad.v = 0;
        let mismatch = dispatch(bad, &tx);
        assert_eq!(mismatch.code.as_deref(), Some("protocol_version_mismatch"));
        let status = dispatch(req("runtime.status", "status-1"), &tx);
        assert!(status.ok);
        assert_eq!(status.web_url.as_deref(), Some(current_url().as_str()));
        let again = dispatch(req("runtime.status", "status-1"), &tx);
        assert_eq!(again.id, "status-1");
        let unknown = dispatch(req("nope", "unknown-1"), &tx);
        assert_eq!(unknown.code.as_deref(), Some("protocol_version_mismatch"));
        assert!(unknown.error.unwrap_or_default().contains("unknown method"));
    }

    #[test]
    fn submit_reports_busy_status_and_dead_worker() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        WORKERS.store(1, Ordering::Release);
        RUNNING.store(1, Ordering::Release);
        let (tx, _rx) = mpsc::channel();
        let busy = submit(&tx, vec!["--json".into(), "status".into()], false)
            .map_err(|err| anyhow::anyhow!(err))?;
        assert_eq!(busy.exit, 2);
        RUNNING.store(0, Ordering::Release);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        assert!(submit(&tx, vec!["remember".into()], false).is_err());
        if JOB_TX.get().is_none() {
            assert!(execute_json(vec!["status".into()]).is_err());
        }
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn socket_path_follows_data_dir() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let first = tempfile::tempdir()?;
        let second = tempfile::tempdir()?;
        std::env::set_var("ONEMEMORY_DATA_DIR", first.path());
        let first_path = socket_path();
        std::env::set_var("ONEMEMORY_DATA_DIR", second.path());
        let second_path = socket_path();
        match previous {
            Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value),
            None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
        }
        if first_path == second_path {
            anyhow::bail!(
                "socket path stayed at {} after the data dir changed",
                first_path.display()
            );
        }
        if !first_path.starts_with(first.path()) || !second_path.starts_with(second.path()) {
            anyhow::bail!(
                "socket path left its data dir: {} / {}",
                first_path.display(),
                second_path.display()
            );
        }
        Ok(())
    }

    #[test]
    fn offline_entry_and_endpoint_roundtrip() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let previous = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let previous_port = std::env::var("ONEMEMORY_RPC_PORT").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        std::env::set_var("ONEMEMORY_RPC_PORT", "18761");
        STOPPING.store(false, Ordering::Release);
        assert!(!runtime_is_up());
        assert!(call_method("runtime.status", Vec::new(), false).is_err());
        let down = RuntimeFlags {
            port: None,
            host: "127.0.0.1".into(),
            status: true,
            stop: false,
        };
        runtime_entry(down.clone())?;
        assert_eq!(crate::exit_code(), 2);
        runtime_entry(RuntimeFlags {
            status: false,
            stop: true,
            ..down
        })?;
        write_endpoint("http://127.0.0.1:9")?;
        assert_eq!(endpoint_pid(), Some(std::process::id()));
        assert_eq!(current_url(), current_url());
        let bare = status_response(&req("runtime.status", "render-none"));
        assert!(render_response(bare, true).is_err());
        let mut with_body = status_response(&req("runtime.status", "render-body"));
        with_body.envelope = Some(crate::output::ResultEnvelope::new(
            "status",
            OutputStatus::Ok,
            json!({"ok": true}),
            Vec::new(),
        ));
        render_response(with_body, true)?;
        assert!(render_response(
            error_response(&req("cli.exec", "render-err"), "timeout", "slow"),
            false,
        )
        .is_err());
        let serve_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let serve_error_slot = Arc::clone(&serve_error);
        let server = std::thread::spawn(move || {
            let started = serve(
                RuntimeFlags {
                    port: Some(18761),
                    host: "127.0.0.1".into(),
                    status: false,
                    stop: false,
                },
                true,
            );
            if let Err(error) = started {
                let mut slot = serve_error_slot
                    .lock()
                    .unwrap_or_else(|err| err.into_inner());
                *slot = Some(format!("{error:#}"));
            }
        });
        let mut ready = false;
        let mut last_error = String::new();
        for _ in 0..100 {
            match call_method("runtime.status", Vec::new(), false) {
                Ok(_) => {
                    ready = true;
                    break;
                }
                Err(error) => last_error = format!("{error:#}"),
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !ready {
            let slot = serve_error.lock().unwrap_or_else(|err| err.into_inner());
            let serve_msg = slot
                .clone()
                .unwrap_or_else(|| "serve has not returned".to_owned());
            anyhow::bail!("runtime did not become ready: {last_error}; {serve_msg}");
        }
        let listed = call_method("cli.exec", vec!["status".into(), "--json".into()], false)?;
        assert!(listed.envelope.is_some());
        STOPPING.store(true, Ordering::Release);
        let _ = try_exchange(&RpcRequest {
            v: PROTOCOL_V,
            id: "test-stop".into(),
            method: "runtime.status".into(),
            args: Vec::new(),
        });
        let _ = server.join();
        match previous {
            Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value),
            None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
        }
        match previous_port {
            Some(value) => std::env::set_var("ONEMEMORY_RPC_PORT", value),
            None => std::env::remove_var("ONEMEMORY_RPC_PORT"),
        }
        Ok(())
    }
}
