//! rsrs CLI - thin shell: parse args and assemble.
//!
//! local-first: remember/recall/list/forget all hit the local store (the authority);
//! `sync` does two-way ciphertext sync (local ↔ cloud backup).
//!
//! Three parts (locked 2026-09-06): (1) memory CLI (this file, memory operations)
//! (2) user client (account/keys/inject distribution) (3) server + frontend (respire-server).
//! The CLI logs in itself: `register` / `login` write session.json (addr/token/user).
//! Without a token, sync and post-write auto-sync cannot reach the server.
//! An existing session.json, or ONEMEMORY_ADDR/TOKEN, also works.

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use uuid::Uuid;

mod app_version;
mod bench;
mod classify;
mod i18n;
mod mcp;
mod net_rpc;
mod output;
mod rpc;
mod runtime_error;
mod runtime_policy;
mod shell;
mod web;

use respire::auth;
use respire::memory::bge::BgeEmbedder;
use respire::memory::model::Kind;
use respire::memory::search::Embedder;
use respire::memory::{MemoryEngine, MemoryQuery, SessionKeys};
use respire::sync::{remote_configured, SyncStats};

struct SyncLive {
    phase: String,
    pulled: u64,
    pushed: u64,
    remote_alive: u64,
    pending: i64,
    conflicts: i64,
    error: String,
}

static SYNC_LIVE: Mutex<SyncLive> = Mutex::new(SyncLive {
    phase: String::new(),
    pulled: 0,
    pushed: 0,
    remote_alive: 0,
    pending: 0,
    conflicts: 0,
    error: String::new(),
});

fn sync_live() -> SyncLive {
    let guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
    SyncLive {
        phase: guard.phase.clone(),
        pulled: guard.pulled,
        pushed: guard.pushed,
        remote_alive: guard.remote_alive,
        pending: guard.pending,
        conflicts: guard.conflicts,
        error: guard.error.clone(),
    }
}

const SYNC_ATTEMPTS: u32 = 3;
mod recall_select;

fn is_retriable_sync_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(ureq::Error::Transport(_)) = cause.downcast_ref::<ureq::Error>() {
            return true;
        }
    }
    let text = format!("{err:#}").to_ascii_lowercase();
    text.contains("timed out")
        || text.contains("timeout")
        || text.contains("connection reset")
        || text.contains("connection refused")
        || text.contains("connection aborted")
}

/// Run a sync attempt up to three times. Only transport failures retry.
/// Backoff is 1s then 2s. Protocol and epoch errors return immediately.
fn run_sync_attempts<T>(mut once: impl FnMut() -> Result<T>) -> Result<T> {
    let mut last = None;
    for attempt in 0..SYNC_ATTEMPTS {
        match once() {
            Ok(value) => return Ok(value),
            Err(err) if attempt + 1 < SYNC_ATTEMPTS && is_retriable_sync_error(&err) => {
                eprintln!(
                    "command=sync status=warn mode=retry attempt={} error={err}",
                    attempt + 1
                );
                let pause = if cfg!(test) {
                    std::time::Duration::from_millis(0)
                } else {
                    std::time::Duration::from_secs(1_u64 << attempt)
                };
                last = Some(err);
                if !pause.is_zero() {
                    std::thread::sleep(pause);
                }
            }
            Err(err) => return Err(err),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("sync failed")))
}

struct RuntimeSyncControl {
    generation: usize,
}
impl respire::sync::SyncControl for RuntimeSyncControl {
    fn boundary_changed(&self) -> Result<()> {
        if rpc::worker_active() {
            rpc::invalidate_sync_boundary(self.generation)?;
        }
        Ok(())
    }
    fn local<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        if rpc::worker_active() {
            rpc::sync_local(self.generation, action)
        } else {
            action()
        }
    }
    fn remote<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        if rpc::worker_active() {
            rpc::check_sync_context(self.generation)?;
        }
        action()
    }
}
fn sync_phase<T>(action: impl FnOnce() -> Result<T>) -> Result<T> {
    if rpc::worker_active() {
        rpc::sync_local(rpc::sync_generation(), action)
    } else {
        action()
    }
}
fn sync_with_retry(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
) -> Result<SyncStats> {
    let boundary = sync_phase(|| local.outgoing_boundary())?;
    let boundary = rpc::sync_boundary().unwrap_or(boundary);
    run_sync_attempts(|| sync_tracked_boundary(session, local, remote, boundary))
}

fn sync_tracked(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
) -> Result<SyncStats> {
    let boundary = sync_phase(|| local.outgoing_boundary())?;
    let boundary = rpc::sync_boundary().unwrap_or(boundary);
    sync_tracked_boundary(session, local, remote, boundary)
}
fn sync_tracked_boundary(
    session: &SessionKeys,
    local: &LocalStore,
    remote: &RemoteTransport,
    boundary: i64,
) -> Result<SyncStats> {
    {
        let mut guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
        guard.phase = "running".to_owned();
        guard.error.clear();
    }
    let control = RuntimeSyncControl {
        generation: rpc::sync_generation(),
    };
    let result = if rpc::worker_active() {
        respire::sync::sync_controlled(session, local, remote, &control, Some(boundary))
    } else {
        respire::sync::sync_all(session, local, remote)
    };
    {
        let mut guard = SYNC_LIVE.lock().unwrap_or_else(|err| err.into_inner());
        match &result {
            Ok(stats) => {
                guard.phase = "ok".to_owned();
                guard.pulled = stats.pulled as u64;
                guard.pushed = stats.pushed as u64;
                guard.remote_alive = stats.remote_alive as u64;
                guard.pending = stats.pending;
                guard.conflicts = stats.conflicts;
                guard.error.clear();
            }
            Err(error) => {
                guard.phase = "err".to_owned();
                guard.error = format!("{error:#}");
            }
        }
    }
    result
}
use output::{Item as OutputItem, ResultEnvelope, Status as OutputStatus};
use respire::transport::local::LocalStore;
use respire::transport::remote::{RemoteConfig, RemoteTransport};
use respire::transport::MemoryTransport;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static DIRECT_MODE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static JSON_MODE: Cell<bool> = const { Cell::new(false) };
    static OUTPUT_EMITTED: Cell<bool> = const { Cell::new(false) };
    static OUTPUT_EXIT_CODE: Cell<u8> = const { Cell::new(0) };
}
static EMBEDDER_SLOT: std::sync::Mutex<Option<Box<BgeEmbedder>>> = std::sync::Mutex::new(None);

struct EmbedderHold(Option<Box<BgeEmbedder>>);

impl Drop for EmbedderHold {
    fn drop(&mut self) {
        if let Ok(mut slot) = EMBEDDER_SLOT.lock() {
            *slot = self.0.take();
        }
    }
}

fn status_exit_code(status: OutputStatus) -> i32 {
    match status {
        OutputStatus::Ok | OutputStatus::Skip => 0,
        OutputStatus::Warn | OutputStatus::Pending => 2,
        OutputStatus::Fail => 1,
    }
}

fn json_mode() -> bool {
    JSON_MODE.with(|flag| flag.get())
}

/// Whether to print progress lines on stderr. The web bridge sets ONEMEMORY_PROGRESS=1
/// for long async jobs: stdout stays JSON (for the bridge), stderr streams progress
/// (so the UI can "scroll"). Without that env var, a TTY decides - same as before.
fn progress_enabled() -> bool {
    if std::env::var("ONEMEMORY_PROGRESS")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return true;
    }
    !json_mode() && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

fn emit_result(result: ResultEnvelope) -> Result<()> {
    let mut result = result;
    result.details = output::sanitize_details(&result.command, &result.details);
    let exit_code = status_exit_code(result.status);
    if rpc::worker_active() {
        CAPTURED.with(|slot| *slot.borrow_mut() = Some(result));
        mark_emitted();
        set_exit_code(exit_code);
        return Ok(());
    }
    println!("{}", result.render(json_mode())?);
    mark_emitted();
    set_exit_code(exit_code);
    Ok(())
}

thread_local! {
    static CAPTURED: std::cell::RefCell<Option<ResultEnvelope>> = const { std::cell::RefCell::new(None) };
}

pub(crate) struct Captured {
    pub exit: i32,
    pub envelope: ResultEnvelope,
}

pub(crate) fn set_json_mode(on: bool) {
    JSON_MODE.with(|flag| flag.set(on));
}

pub(crate) fn mark_emitted() {
    OUTPUT_EMITTED.with(|flag| flag.set(true));
}

pub(crate) fn set_exit_code(code: i32) {
    OUTPUT_EXIT_CODE.with(|flag| flag.set(code.clamp(0, 255) as u8));
}

pub(crate) fn exit_code() -> i32 {
    OUTPUT_EXIT_CODE.with(|flag| flag.get() as i32)
}

fn output_emitted() -> bool {
    OUTPUT_EMITTED.with(|flag| flag.get())
}

/// Run one command on the runtime worker thread and keep the envelope instead of printing it.
pub(crate) fn capture_run(args: Vec<String>) -> Captured {
    CAPTURED.with(|slot| *slot.borrow_mut() = None);
    OUTPUT_EMITTED.with(|flag| flag.set(false));
    OUTPUT_EXIT_CODE.with(|flag| flag.set(0));
    let parsed = Cli::try_parse_from(
        std::iter::once(std::ffi::OsString::from("rsrs"))
            .chain(args.iter().cloned().map(std::ffi::OsString::from)),
    );
    let ran = match parsed {
        Ok(cli) => run(cli),
        Err(error) => {
            let code = error.exit_code();
            let mut envelope = ResultEnvelope::new(
                "cli",
                if code == 0 {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Fail
                },
                serde_json::json!({"reason": "parse"}),
                Vec::new(),
            );
            if code != 0 {
                envelope.errors.push(error.to_string());
            }
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            mark_emitted();
            set_exit_code(code);
            Ok(())
        }
    };
    if let Err(error) = ran {
        if !output_emitted() {
            let mut envelope = ResultEnvelope::new(
                "cli",
                OutputStatus::Fail,
                serde_json::json!({"reason": "runtime_error"}),
                Vec::new(),
            );
            envelope.errors.push(format!("{error:#}"));
            envelope.details = serde_json::json!({"error_type": "runtime"});
            CAPTURED.with(|slot| *slot.borrow_mut() = Some(envelope));
            set_exit_code(1);
        }
    }
    let envelope = CAPTURED
        .with(|slot| slot.borrow_mut().take())
        .unwrap_or_else(|| {
            ResultEnvelope::new("cli", OutputStatus::Ok, serde_json::json!({}), Vec::new())
        });
    Captured {
        exit: exit_code(),
        envelope,
    }
}

fn emit_details(
    command: &str,
    status: OutputStatus,
    summary: serde_json::Value,
    details: serde_json::Value,
) -> Result<()> {
    let mut result = ResultEnvelope::new(command, status, summary, Vec::new());
    result.details = details;
    emit_result(result)
}

struct LogoutOutcome {
    full: bool,
    session_found: bool,
    path: PathBuf,
}

/// Perform logout in the CLI so the output contract does not depend on a
/// newer app-core helper. Keep the same session and full-logout semantics.
fn logout_cli(full: bool) -> Result<LogoutOutcome> {
    let path = auth::session_file()?;
    if full {
        return match std::fs::remove_file(&path) {
            Ok(()) => Ok(LogoutOutcome {
                full,
                session_found: true,
                path,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(LogoutOutcome {
                full,
                session_found: false,
                path,
            }),
            Err(error) => Err(anyhow!("clear failed: {error}")),
        };
    }

    match auth::read_session_json() {
        Ok(mut data) => {
            if let Some(object) = data.as_object_mut() {
                object.remove("token");
                object.remove("session_id");
            }
            auth::write_session_json(&data)?;
            Ok(LogoutOutcome {
                full,
                session_found: true,
                path,
            })
        }
        Err(_error) if !path.exists() => Ok(LogoutOutcome {
            full,
            session_found: false,
            path,
        }),
        Err(error) => Err(error),
    }
}

/// Candidate set: active entries (shared by recall/list/remember judge-then-store).
/// After 2026-09-21 dropped the local subtree, there is no scope filter - whole-store semantics.
fn scoped_candidates(store: &LocalStore) -> Result<Vec<respire::StoredMemory>> {
    let model = store.retrieval_model()?;
    if store.index_pending(&model)? {
        let embedder = BgeEmbedder::load_model(&model)?;
        store.rebuild_index(&build_session()?, &embedder, &model)?;
    }
    store.all(false)
}

fn candidates_preview(store: &LocalStore) -> Result<Vec<respire::StoredMemory>> {
    scoped_candidates(store)
}

fn candidates_count_primary(all: &[respire::StoredMemory]) -> usize {
    all.iter()
        .filter(|m| m.local_importance == "important")
        .count()
}

fn candidates_count_normal(all: &[respire::StoredMemory]) -> usize {
    all.iter()
        .filter(|m| m.local_importance == "normal")
        .count()
}

#[derive(Parser)]
#[command(
    name = "rsrs",
    version,
    about = "跨设备跨软件统一 AI 记忆系统（local-first）",
    after_help = "Sandbox: use --client-only or ONEMEMORY_CLIENT_ONLY=1 to connect to the host HTTP runtime without managing its lifecycle."
)]
struct Cli {
    /// Machine-readable output: stdout is JSON only (progress goes to stderr) - for thin client shells
    #[arg(long, global = true)]
    json: bool,
    /// Correlates TUI progress and cancellation with this model task only.
    #[arg(long, global = true, hide = true)]
    model_task_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum ModelAction {
    /// Download BGE-M3 without switching the active model or index.
    InstallM3 {
        #[arg(long)]
        mirror: Option<String>,
    },
    /// Build a resumable index generation and activate it after complete validation.
    Activate {
        #[arg(value_parser = ["m3", "legacy"])]
        model: String,
    },
    /// Force CPU and terminate the runtime, even when inference or RPC is stuck.
    ResetCpu,
    /// Show or select inference engine. Failures do not switch engines; default CPU.
    Engine {
        #[arg(value_parser = ["npu", "gpu", "cpu"])]
        engine: Option<String>,
    },
    /// Install compatible NPU execution providers through Windows ML.
    InstallEngines,
    /// Run a real BGE inference and report the selected backend.
    Probe {
        #[arg(long, value_parser = ["legacy", "m3"])]
        model: Option<String>,
        /// Text to compare against the CPU baseline, including long-input checks.
        #[arg(long, default_value = "本地推理引擎验证：记忆检索")]
        text: String,
    },
    /// Download and install the BGE embedder (tokenizer.json + onnx/model.onnx, ~390MB)
    InstallBge {
        /// Mirror origin (host only), e.g. https://hf-mirror.com
        #[arg(long)]
        mirror: Option<String>,
    },
    /// Delete the user-installed BGE model files and drop the in-process session
    UninstallBge,
    /// Download and install the cross-encoder rerank model (quantized bge-reranker-base, ~280MB; optional)
    InstallRerank {
        /// Mirror origin (host only), e.g. https://hf-mirror.com
        #[arg(long)]
        mirror: Option<String>,
        /// Custom model source: paste the full URL of any file in the repo (resolve/blob both work;
        /// origin/repo/revision are taken from it; missing revision defaults to main), e.g.
        /// https://huggingface.co/Xenova/bge-reranker-base/resolve/main/tokenizer.json
        #[arg(long)]
        source: Option<String>,
    },
    /// Delete the user-installed rerank model files and drop the in-process session
    UninstallRerank,
}

#[derive(Subcommand)]
enum Command {
    /// Read the full memory workflow before storing or maintaining memories.
    Prompt,
    /// Print the embedded CLI version (same as `--version` / `-v`)
    #[command(name = "v", visible_alias = "version")]
    V,
    /// Manage independent read-only subtree grants for local tools.
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// List or revoke independent cloud login sessions; does not change local decrypt keys.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Generate local key material (offline; writes local session/keyfile - no server, no auth)
    Keygen {
        /// Compatibility flag: unused for encryption since v4 (the super password is system-generated)
        #[arg(long)]
        pass: Option<String>,
        /// Force overwrite with offline keys even if this machine already has cloud key material (drops the cloud session)
        #[arg(long)]
        force: bool,
    },
    /// Store a memory (local authority store; encrypts + embeds automatically).
    /// Judge-then-store (dedup first, then choose): without --force, an internal recall runs first -
    /// high similarity -> suggest merge (`--merge-ids "id1,id2"` deletes old, writes a combined entry);
    /// medium -> suggest attach (`--parent` as cause); no candidate or --force writes directly.
    /// `--parent` = causal attach; parent/child is cause/effect.
    Remember {
        content: String,
        #[arg(long, default_value = "context")]
        r#type: String,
        #[arg(long, default_value = "")]
        tags: String,
        #[arg(long, default_value = "")]
        title: String,
        #[arg(long, default_value = "")]
        project: String,
        #[arg(long, default_value = "")]
        computer: String,
        #[arg(long, default_value = "-1")]
        emotion: f32,
        /// Importance (AI-judged): important (reusable, recall primary zone) | trivial (diary; default). The normal tier is retired.
        #[arg(long, default_value = "trivial")]
        importance: String,
        #[arg(long, default_value = "")]
        parent: String,
        /// Skip judge-then-store and write immediately
        #[arg(long)]
        force: bool,
        /// Merge: delete the listed old memories (comma-separated ids) and store this content as the combined entry (inherits the first cause chain)
        #[arg(long)]
        merge_ids: Option<String>,
    },
    /// Import a JSON-array dump: keep fields, rebuild parent links, sync once after the batch
    Import { file: String },
    /// Semantic recall through the private Core
    Recall {
        query: String,
        /// Override the recall mode for this request without changing saved settings.
        #[arg(long, value_parser = ["fast", "quality"])]
        mode: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        r#type: Option<String>,
        /// Restrict to this project (use when other projects interfere)
        #[arg(long)]
        project: Option<String>,
        /// Recall trace: stderr dumps the full routing path (candidates -> scope -> two zones -> per-axis Top10)
        #[arg(long)]
        trace: bool,
        /// Return compact IDs and titles in JSON; use show to read full memory content.
        #[arg(long)]
        titles: bool,
    },
    /// Query log: each recall's candidates + adoption + model self-grade (local DPO/SFT raw material)
    QueryLog {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Stats only: query count, adoption rate, empty-candidate rate, good/bad self-grade, top entries
        #[arg(long)]
        stats: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
        /// mark: model self-grade (true hit --good / misleading --bad); the main post-training signal
        #[command(subcommand)]
        cmd: Option<QueryLogCmd>,
    },
    /// Retrieval quality benchmark: run an evalset for hit-rate/MRR, optional baseline compare; mine drafts an evalset from query-log
    Bench {
        #[command(subcommand)]
        cmd: BenchCmd,
    },
    /// Batch classify via JEV (TypeSafe): ask which top-level category each entry belongs to, compare with the current parent (read-only)
    Classify {
        /// Process the latest N entries (default 50, so a full-store run is not accidental; --all overrides)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Whole store (overrides --limit)
        #[arg(long)]
        all: bool,
        /// Restrict to a subtree (id or 8-char prefix; includes the node itself and descendants)
        #[arg(long)]
        root: Option<String>,
        /// Truncate each entry body to this many chars (API payload cap)
        #[arg(long, default_value_t = 600)]
        max_chars: usize,
        /// Below this confidence, list as "low confidence, needs a human" (default 0.5)
        #[arg(long, default_value_t = 0.5)]
        min_confidence: f32,
        /// Save suggestion JSON (audit / later apply)
        #[arg(long)]
        save: Option<String>,
        /// Dry run: preview final actions without network access or local writes
        #[arg(long)]
        dry_run: bool,
        /// Use the DS (OpenAI-compatible) backend to emulate JEV: `--ds` uses a stored key; `--ds <key>` takes the key and stores it
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        ds: Option<String>,
        /// Classify backend: jev (TypeSafe official Jev, default) | ds (DeepSeek-compatible emulate) - same as --ds; pick one
        #[arg(long)]
        backend: Option<String>,
        /// Requested classification sample count
        #[arg(long, default_value_t = 5, hide = true)]
        samples: usize,
        /// Tree mode: pick a suggested parent among **existing tree nodes** (not a linear 23-root assignment) - pair with --batch for speed
        #[arg(long)]
        tree: bool,
        /// Requested tree classification batch size
        #[arg(long, default_value_t = 12, hide = true)]
        batch: usize,
        /// Maximum tree depth selected for classification
        #[arg(long, default_value_t = 2, hide = true)]
        tree_depth: usize,
        /// Causal-tree segment rewrite: parent=cause, child=effect; walk by level and let the AI judge order
        /// (prints a resort --spec compatible reparent plan; does not write the store)
        #[arg(long)]
        causal: bool,
        /// Causal mode: only process parents with >= this many children (default 3 - few children have no causal order to sort)
        #[arg(long, default_value_t = 3, hide = true)]
        min_kids: usize,
        /// Causal mode: max segments to process (default 0 = all; more children first)
        #[arg(long, default_value_t = 0, hide = true)]
        segments: usize,
        /// Causal mode: write the reparent plan to a file (resort --spec can consume it)
        #[arg(long)]
        out: Option<String>,
        /// Apply the final organization actions selected by Core
        #[arg(long)]
        auto: bool,
        /// Preview local structural repair actions;
        /// text only, no store writes, no network
        #[arg(long)]
        plan: bool,
        /// Max auto-reparent rounds (default 5)
        #[arg(long, default_value_t = 5, hide = true)]
        rounds: usize,
        /// API base (default TypeSafe; later may switch to a rsrs gateway)
        #[arg(long)]
        api_base: Option<String>,
        /// Model name
        #[arg(long, default_value_t = classify::DEFAULT_MODEL.to_string())]
        model: String,
    },
    /// List recent entries
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Only entries created after this time (RFC3339 or YYYY-MM-DD)
        #[arg(long)]
        since: Option<String>,
        /// Only entries created since the last tidy (maintenance.json resort_at) -
        /// the §3.8 tidy intake: tidy this batch, do not pull the whole store
        #[arg(long)]
        since_resort: bool,
    },
    /// Delete (tombstone; propagates with sync)
    Forget { id: String },
    /// Clear current-version ciphertext; sync history is kept (see sync-history)
    Purge { id: String },
    /// Restore a deleted memory by full ID (keeps body and parent; propagates with sync)
    Restore { id: String },
    /// Causal tree: promote - this entry becomes a more-upstream cause (reattach to grandparent/root; effects follow)
    Promote { id: String },
    /// Causal tree: demote - attach this entry under --parent as its effect (extends the chain by one; cycle-safe)
    Demote {
        id: String,
        #[arg(long)]
        parent: String,
    },
    /// Show one entry in full (cause/effect complete, not truncated)
    Show { id: String },
    /// Causal-chain deep dive: fetch the whole chain at once - ancestor bodies (root first) + this entry + descendants to --depth.
    /// After an AI sees a cause-chain name, it can dig without layer-by-layer show.
    Chain {
        id: String,
        /// Descendant depth (default 3; 0 = ancestors + this entry only)
        #[arg(long, default_value_t = 3)]
        depth: usize,
    },
    /// Attach a child under a parent (explicit attach is intent; no judge-then-store; auto-syncs)
    Attach {
        id: String,
        #[arg(long)]
        parent: String,
    },
    /// Causal tree: render a subtree (--from start, default root forest); --outline prints a full-depth id+title directory (AI tidy reads this first)
    Tree {
        #[arg(long, default_value = "")]
        from: String,
        #[arg(long, default_value_t = 3)]
        depth: usize,
        #[arg(long)]
        outline: bool,
        /// Export this node's subtree as Markdown material (same as the client install dialog)
        #[arg(long)]
        material: Option<String>,
    },
    /// Memory tidy: batch reparent (spec={"ops":[{"id":"child","parent":"parent"}]}; id / first 8 chars / root title all work); dry-run by default, --go writes, auto-syncs, and resets the counter
    Resort {
        #[arg(long)]
        go: bool,
        #[arg(long)]
        spec: Option<String>,
        /// Show tidy counter (adds since last tidy / threshold)
        #[arg(long)]
        status: bool,
        /// Manually reset the counter (e.g. after tidying another way)
        #[arg(long)]
        reset: bool,
        /// Set the alert threshold (new-entry count)
        #[arg(long)]
        threshold: Option<u64>,
    },
    /// AI behavior config (agent.json): no args = print the whole file (AI reads it to decide); --set key=value writes a key
    AgentConfig {
        /// Set a key, format key=value (e.g. diary_mode=verbose)
        #[arg(long)]
        set: Option<String>,
    },
    /// Retitle: decrypt -> change title -> reseal (ciphertext payload updates) -> dirty -> auto-sync
    Retitle {
        id: String,
        /// New title (required - omitting it would blank the title; fixed in the 2026-09-20 audit)
        #[arg(long)]
        title: Option<String>,
    },
    /// Batch retitle (JSON array [{"id":...,"title":...}]; one process, one model load)
    RetitleMany { file: String },
    /// Two-way sync: pull cloud delta -> land locally -> push local changes (LWW)
    Sync,
    /// Show conflicts that still need a decision; --all includes resolved and old-generation history
    SyncConflicts {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        all: bool,
        /// Sync latest content and cross-device resolution state first
        #[arg(long)]
        refresh: bool,
    },
    /// Resolve one kept revision; history is not deleted; marked resolved only after the remote confirms
    SyncResolve {
        #[arg(long)]
        epoch: String,
        #[arg(long)]
        rev: i64,
        /// current.rev shown by sync-conflicts, so the head cannot change under you after you compared
        #[arg(long)]
        head_rev: i64,
        #[arg(long,value_parser=["keep-current","take-incoming","merge"])]
        action: String,
        /// For merge, the explicit merged body; metadata stays on the current version
        #[arg(long)]
        content: Option<String>,
    },
    /// Show kept sync revisions; --remote pulls server history without moving the sync cursor
    SyncHistory {
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remote: bool,
    },
    /// Restore a kept revision as a new local edit
    SyncRestore {
        #[arg(long, conflicts_with = "rev")]
        op_id: Option<String>,
        #[arg(long, conflicts_with = "op_id", requires = "epoch")]
        rev: Option<i64>,
        #[arg(long, requires = "rev", conflicts_with = "op_id")]
        epoch: Option<String>,
    },
    /// Rebuild the snapshot after a server-side backup restore (keeps local history and pending outbound edits)
    SyncReset,
    /// Status
    Status,
    /// Recompute all embeddings (for embedder upgrades / dim changes; re-embed by semantics)
    Reembed,
    /// Stock analysis: cluster BGE vectors, flag lone leaves, suggest a tree (read-only)
    Defrag {
        /// User-selected similarity floor for duplicate suggestions
        #[arg(long, default_value_t = 0.60)]
        min: f32,
        #[arg(long, default_value_t = 20)]
        top: usize,
    },
    /// Split a mixed node (AI decides): no flags prints material JSON for the AI to plan; --go --spec '<json>' applies
    Split {
        id: String,
        /// Apply the split plan
        #[arg(long)]
        go: bool,
        /// AI-authored split-plan JSON (run with no flags first to get material and field docs)
        #[arg(long)]
        spec: Option<String>,
    },
    /// Deepen the tree: cluster flat children of a large root into sub-roots (--root to inspect/apply; --auto deepens every flat large root)
    TreeDeepen {
        /// Target root id (8-char prefix ok); default = every flat large root
        #[arg(long)]
        root: Option<String>,
        /// Apply the plan (pair with --titles)
        #[arg(long)]
        go: bool,
        /// Sub-root title array JSON (draft order; default = longest member title in the cluster)
        #[arg(long)]
        titles: Option<String>,
        /// One-shot: auto-deepen every flat large root (sub-root title = longest member title; retitle later)
        #[arg(long)]
        auto: bool,
        /// User-selected similarity floor for Core grouping
        #[arg(long, default_value_t = 0.55)]
        min: f32,
    },
    /// Distribute the inject source: --targets lists 14 hosts; --id <target> injects; --remove --id <target> uninstalls; no args in a TTY opens the picker
    Inject {
        #[arg(long)]
        targets: bool,
        /// Force the interactive TUI picker (errors if there is no TTY)
        #[arg(long, conflicts_with_all = ["targets", "id", "preview", "expected"])]
        tui: bool,
        /// Inject every detected target (skip the TUI; same as no-args when there is no TTY)
        #[arg(long, conflicts_with_all = ["id", "preview", "expected"])]
        all: bool,
        /// Target id (dsh/opencode/codex/claude/codebuddy/workbuddy/kylinbot/pi/zigcode/deepseek/qwen/doubao/generic)
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        remove: bool,
        /// Preview a Codex inject or uninstall without writing (requires --id codex)
        #[arg(long, conflicts_with = "targets")]
        preview: bool,
        /// Apply only if the config still matches this preview revision (requires --id codex)
        #[arg(long, conflicts_with_all = ["targets", "preview"])]
        expected: Option<String>,
    },
    /// Tree hygiene: root-size bill + lone-leaf attach suggestions (read-only; --id --parent actually attaches)
    TreeCure {
        #[arg(long, default_value_t = 15)]
        top: usize,
        /// Apply: attach --id under --parent (skip suggestions, just do it)
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        /// Auto-attach: apply every suggestion, skip failures, then summarize
        #[arg(long)]
        auto: bool,
        /// User-selected similarity floor for Core attachment suggestions
        #[arg(long, default_value_t = 0.50)]
        min: f32,
    },
    /// Heat float: an entry with more hits than its parent becomes the grandparent's child (effects follow; dry-run report, --go applies)
    TreeFloat {
        /// Apply: float each reported entry (dirty; propagates with sync)
        #[arg(long)]
        go: bool,
        /// Hit-count floor to float (default 3; relative heat - must be strictly above the parent's hits)
        #[arg(long, default_value_t = 3)]
        min: i64,
    },
    /// Self-check: model/store/lock/remote/inject/scope in one pass (first stop for install issues)
    Doctor {
        /// Also probe remote server reachability (GET /health, ~1–3s)
        #[arg(long)]
        remote: bool,
        /// Also check npm for a newer CLI (~1–5s; default reads the 24h cache, no network)
        #[arg(long)]
        check_update: bool,
        /// Install a missing or unusable embedder; default only reports diagnostics
        #[arg(long)]
        fix: bool,
    },
    /// Whole-store health audit: orphans / illegal importance / duplicate titles / truncated titles / deep chains; structured report for an AI audit
    Audit {
        /// JSON output (client/AI consumption)
        #[arg(long)]
        json: bool,
    },
    /// Start the local Web client: the browser is the GUI (hosts tree-ui; invoke becomes a CLI child; business truth stays in the CLI)
    Web {
        /// Listen port (default 15169; if taken, take over a rsrs runtime or fail)
        #[arg(long)]
        port: Option<u16>,
        /// Do not open a browser after start
        #[arg(long)]
        no_open: bool,
        /// Bind address (default 127.0.0.1, this machine only; 0.0.0.0 opens the LAN - use with care)
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Model management: install or uninstall BGE and the optional rerank model
    Model {
        #[command(subcommand)]
        action: ModelAction,
    },
    /// View/set local config (client.json: data dir / server address / auto-sync / auto-cure)
    Config {
        /// Set the data directory (absolute path; empty string clears back to default ~/.respire)
        #[arg(long)]
        data_dir: Option<String>,
        /// Set the server address
        #[arg(long)]
        addr: Option<String>,
        /// Set post-write auto-sync
        #[arg(long)]
        autosync: Option<bool>,
        /// Set periodic auto-cure
        #[arg(long)]
        cure_auto: Option<bool>,
        /// Max concurrent read jobs in the resident runtime. 0 clears the setting and follows the CPU count, never above 4. Writes always queue. Applies after `rsrs web --stop`.
        #[arg(long)]
        rpc_parallelism: Option<u32>,
    },
    /// Judge-then-store candidate bill (read-only): high similarity suggests merge, medium suggests attach, similar candidates suggest merging them
    Candidates { content: String },
    /// Memory passport: ASCII-art card (user / memory count / connected agents / devices) for sharing
    Passport,
    /// Entry change history (audit stream: create/update/delete/restore/purge; SQLite triggers record it)
    History {
        /// Entry id (8-char prefix ok); omit = recent changes for the whole store
        id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Plugin hooks (plugins.json): list shows config; test <EVENT> fires an event
    Plugin {
        #[command(subcommand)]
        command: PluginCommand,
    },
    /// MCP server over stdio JSON-RPC. HTTP/SSE is served by `rsrs web` at `/mcp` and `/sse`.
    Mcp,
    /// Check npm for a newer CLI (24h throttle; --force skips it; --clear drops the cache)
    UpdateCheck {
        /// Skip the throttle and query the network
        #[arg(long)]
        force: bool,
        /// Clear the cache (the next check hits the network)
        #[arg(long)]
        clear: bool,
    },
    /// Backfill: reseal ciphertext so payload.parent_id matches the plaintext column (fixes dual-source drift; idempotent)
    Repack,
    /// Diary = whole-store time chain (the trivial zone is merged in; not filtered by importance): recent (--limit), a day (--date, today/yesterday), a range (--from/--to inclusive), keyword (--contains)
    Diary {
        #[arg(long, default_value_t = 10)]
        limit: usize,
        /// Flip a day (YYYY-MM-DD or today/yesterday, local timezone)
        #[arg(long)]
        date: Option<String>,
        /// Range start (YYYY-MM-DD, inclusive; mutually exclusive with --date)
        #[arg(long)]
        from: Option<String>,
        /// Range end (YYYY-MM-DD, inclusive; mutually exclusive with --date; --to without --from means "up to that day")
        #[arg(long)]
        to: Option<String>,
        /// Keyword filter (literal match on plaintext index: title + body head <=500 chars, case-insensitive)
        #[arg(long)]
        contains: Option<String>,
    },
    /// Built-in top-level catalog (20 human-domain + 3 AI-domain = 23, embedded at compile): --list prints it; --ensure <root,...> creates roots; no args shows current state
    Taxonomy {
        /// List every built-in category (domain / title / surface-word count / gist)
        #[arg(long)]
        list: bool,
        /// Create/fill roots (idempotent): titles must match the catalog, comma-separated; default = fill every missing root
        #[arg(long)]
        ensure: Option<String>,
    },
    /// Create a root outside the catalog (needs the user to say yes): AI proposes -> user allows -> run with --yes; the AI must not create one on its own
    RootCreate {
        title: String,
        /// One-line gist (default = the title)
        #[arg(long)]
        content: Option<String>,
        /// User already allowed this (turn their "yes" into this flag; without it, refuse to write)
        #[arg(long)]
        yes: bool,
    },
    /// Update a memory (any of title/body/tags/kind/importance); decrypt, reseal, auto-sync
    Update {
        id: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        tags: Option<String>,
        #[arg(long)]
        kind: Option<String>,
        /// Importance revision: important | normal | trivial (reseals ciphertext payload and the index column)
        #[arg(long)]
        importance: Option<String>,
    },
    /// Export the whole store as plaintext JSON (local backup)
    Export { file: String },
    /// Back up the local store file (whole SQLite copy, ciphertext and index)
    Backup { file: String },
    /// Show account keys: Account Secret / five-keys (manual cross-device join; leak = loss of the store)
    Secret {
        /// Show the full Secret and five-keys (default is masked)
        #[arg(long)]
        reveal: bool,
    },
    /// Export decrypt keys (super password + Secret Key + vault material) - how a new machine logs in; leak = loss of the store
    KeysExport {
        /// Write a file (mode 600) instead of printing; the file holds every decrypt secret - keep it safe
        #[arg(long)]
        out: Option<String>,
    },
    /// Reset the super password: unlock URK with the current code, issue a new one, upload. Data is unchanged
    SuperReset {
        /// Current super password (omit if already in the local keyring)
        #[arg(long = "super")]
        super_pass: Option<String>,
    },
    /// Five-keys join (another machine): verify and write a local session; a non-empty --addr also logs in for a token
    Fivekeys {
        #[arg(long, default_value = "")]
        addr: String,
        #[arg(long, default_value = "")]
        user: String,
        #[arg(long)]
        pass: String,
        #[arg(long, default_value = "")]
        secret: String,
        #[arg(long)]
        kdf_salt: String,
        #[arg(long)]
        wrapped_urk: String,
        #[arg(long)]
        urk_nonce: String,
        /// Super password (new wrap). If set, login password + Account Secret are not used to unwrap
        #[arg(long = "super", default_value = "")]
        super_pass: String,
    },
    /// Register an account (first device): login password for auth + super password wrapping keys.
    /// Address defaults to https://api.rsrs.rs; use --addr to override it.
    /// Missing user/password drops into an interactive prompt (TTY only).
    Register {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
        /// Super password (for decrypt; separate from the login password; forgotten = memories unrecoverable)
        #[arg(long = "super")]
        super_pass: Option<String>,
    },
    /// Multiple accounts on one machine: each account has its own data dir (local store/keys/session switch as a unit).
    /// Logging into a new account creates a profile; `account list` lists them; `account <name>` switches (main = primary); `remove <name> --yes` deletes.
    Account {
        /// Action: list | remove | or a profile name (same as use; main is the primary profile)
        action: String,
        /// Profile name (required for remove)
        name: Option<String>,
        /// Confirm a real delete on remove (store and keys are unrecoverable)
        #[arg(long)]
        yes: bool,
    },
    /// Spaces (virtual accounts): an owner can create several virtual accounts; each is a space with its own super key and data dir.
    /// Join = a member builds that space's profile on their machine from an invite; they can switch freely; leaving is `kick`.
    Space {
        /// Action: list | create <name> | use <name> | invite | join <code> | members | kick | remove
        action: String,
        /// Space name (needed for create/use/remove)
        name: Option<String>,
        /// Note on invite (written to the member session's device_name, so you can tell who is who later)
        #[arg(long)]
        note: Option<String>,
        /// invite --readonly: sign a read-only invite (that member can recall, not write; enforced server-side)
        #[arg(long)]
        readonly: bool,
        /// Invite code for join (the name positional also accepts it)
        #[arg(long)]
        code: Option<String>,
        /// Member session id to kick
        #[arg(long)]
        session: Option<String>,
        /// kick --all: revoke every member session in this space
        #[arg(long)]
        all: bool,
        /// Confirm a real delete on remove (store and keys are unrecoverable)
        #[arg(long)]
        yes: bool,
    },
    /// Log out: clear addr/token and drop the cloud (identity and keys stay; login brings them back); --full forgets this machine's identity
    Logout {
        /// Delete the whole session.json (including key material - rejoin needs register or five-keys)
        #[arg(long)]
        full: bool,
    },
    /// Log in: login password to the server; a new device must also give the super password to download the key wrap.
    /// Address defaults to the last server this machine used (kept in session.json by register/logout).
    /// Missing user/password drops into an interactive prompt (TTY only).
    Login {
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        pass: Option<String>,
        #[arg(long = "super")]
        super_pass: Option<String>,
        /// Secret Key (vault v3, generated on this machine; the server never has it)
        #[arg(long = "secret-key")]
        secret_key: Option<String>,
        /// When the server has data but no key wrap, explicitly drop the old data and start from this machine's new keys
        #[arg(long)]
        reset_vault: bool,
    },
    /// Book material: a root subtree -> volume/chapter full text (for an AI to draft)
    BookMaterial { root: String },
    /// Portrait material: whole-store portrait aggregate (for an AI to draft a portrait)
    PortraitMaterial {
        #[arg(long, default_value_t = 40)]
        limit: usize,
    },
    /// Share a subtree: emit a prompt another AI can paste (payload is plaintext; the other AI imports from the prompt)
    Share {
        /// Subtree root (8-char prefix ok); default is this machine's scope root, else error
        #[arg(long)]
        root: Option<String>,
        /// Print only the prompt body (pipes/clipboard), no hint lines
        #[arg(long)]
        raw: bool,
        /// Write a file instead of printing (prefer <file>.txt with the full prompt)
        #[arg(long)]
        out: Option<String>,
    },
    /// Import a shared subtree: without --go, print attach-candidate bill (for the AI to judge); --go writes the store
    ShareImport {
        /// Share text file (full prompt or bare payload)
        file: String,
        /// Attach point: hang this subtree under that existing memory (8-char prefix ok); default is a new root
        #[arg(long, default_value = "")]
        parent: String,
        /// Write switch: omit to only print the candidate bill
        #[arg(long)]
        go: bool,
        /// Override the root title (default = the sharer's original title)
        #[arg(long)]
        title: Option<String>,
        /// Bypass Core-reported conflicts and explicitly create a sibling entry
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum GrantCommand {
    /// Create a grant; the token is shown only this once - keep it.
    Create {
        #[arg(long)]
        root: String,
        #[arg(long)]
        label: String,
    },
    List,
    Revoke {
        id: String,
    },
}

/// query-log subcommand: model self-grade report.
#[derive(Subcommand)]
enum QueryLogCmd {
    /// Report a self-grade: true hit --good (chosen) / misleading --bad (rejected).
    /// ids are comma-separated; 8-char prefixes work; matches recall candidates from the last 10 minutes.
    Mark {
        /// Candidate entry ids (comma-separated; prefixes ok)
        ids: String,
        /// Mark as a true hit (post-training chosen)
        #[arg(long)]
        good: bool,
        /// Mark as misleading (post-training rejected)
        #[arg(long)]
        bad: bool,
    },
}

/// bench subcommand: retrieval quality suite (added 2026-09-19).
#[derive(Subcommand)]
enum BenchCmd {
    /// Run an evalset: JSONL one case per line {"query","expect":[8-char prefix or full id...],"project?","note?"}; empty expect = negative
    Run {
        /// Evalset file (JSONL)
        file: String,
        /// Eval depth: whether the expected hit is in the top K (default 5)
        #[arg(long, default_value_t = 5)]
        topk: usize,
        /// Archive this run as JSON (for a later --baseline compare)
        #[arg(long)]
        save: Option<String>,
        /// Compare against a baseline (JSON from a previous --save): per-case up/down/same
        #[arg(long)]
        baseline: Option<String>,
        /// Per-case detail (default lists only misses)
        #[arg(long)]
        verbose: bool,
    },
    /// Mine an evalset draft from query-log (self-grade good is the main signal, adopted is weak)
    Mine {
        /// Output JSONL file
        #[arg(long)]
        out: String,
        /// Max cases to export
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Strict: use self-grade good only, ignore adopted as a weak signal
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Subcommand)]
enum SessionCommand {
    /// List independent sessions for this account (the current one is marked current).
    List,
    /// Revoke cloud access for a session; the full UUID comes from session list.
    Revoke { id: String },
}

/// plugin subcommand: inspect hook config and fire events by hand.
#[derive(Subcommand)]
enum PluginCommand {
    /// List hooks configured in plugins.json (event -> command/timeout/failure policy)
    List,
    /// Fire one event to verify a plugin (--payload is business JSON; a test hook need not actually write the store)
    Test {
        /// Event name: pre-remember | post-remember | post-recall | post-forget | post-sync
        event: String,
        /// Business payload JSON (default {}); combined with event name/timestamp into the full event on plugin stdin
        #[arg(long, default_value = "{}")]
        payload: String,
    },
}

/// Memory-tree outline (--outline): full depth, id+title indent tree, no bodies - the AI tidy's input surface.
fn collect_outline(nodes: &[respire::service::TreeNode], indent: usize, out: &mut Vec<String>) {
    for n in nodes {
        out.push(format!(
            "{}[{}] {}",
            "  ".repeat(indent),
            respire::service::short_id(&n.id),
            n.title
        ));
        collect_outline(&n.children, indent + 1, out);
    }
}

/// Same, but structured rows (for `--json`) - keep depth, id, title for programs.
fn collect_outline_json(
    nodes: &[respire::service::TreeNode],
    depth: usize,
    out: &mut Vec<serde_json::Value>,
) {
    for n in nodes {
        out.push(serde_json::json!({
            "depth": depth,
            "id": n.id,
            "short_id": respire::service::short_id(&n.id),
            "title": n.title,
        }));
        collect_outline_json(&n.children, depth + 1, out);
    }
}

/// Memory tidy (resort): one process batch-reparents - dry-run validates every op (parse/cycle/self-parent); --go writes and syncs once.
/// A successful write bumps the counter +1; at the threshold an alert is returned (§3.8 auto-trigger - the AI sees TIDY and runs three tidy rounds).
/// AI behavior config (agent.json): --set key=value writes a key; no args prints the whole file for the AI to read.
fn run_agent_config(set: Option<&str>) -> Result<()> {
    if let Some(kv) = set {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("format must be key=value (e.g. diary_mode=verbose)"))?;
        let val =
            serde_json::from_str::<serde_json::Value>(v).unwrap_or_else(|_| serde_json::json!(v));
        respire::service::write_agent_config_key(k, &val)?;
        return emit_result(ResultEnvelope::new(
            "agent-config",
            OutputStatus::Ok,
            serde_json::json!({"action":"updated", "key":k, "value":val}),
            vec![OutputItem::new(k, OutputStatus::Ok, v)],
        ));
    }
    let config = respire::service::read_agent_config();
    let object = config
        .as_object()
        .ok_or_else(|| anyhow!("agent config must be an object"))?;
    let rows = object
        .iter()
        .map(|(key, value)| OutputItem::new(key, OutputStatus::Ok, value.to_string()))
        .collect();
    emit_result(ResultEnvelope::new(
        "agent-config",
        OutputStatus::Ok,
        config,
        rows,
    ))
}

fn note_write_maintenance() -> Option<String> {
    // The tidy cycle is also when we check for a new CLI (2026-09-20): **only when TIDY fires**
    // we query npm - so every write does not hit the network (24h throttle, silent offline; see update_check).
    match respire::service::counter_bump(&respire::service::maintenance_path()) {
        Ok((n, t)) if n >= t => {
            let mut notes = vec![format!(
                "TIDY {n} new entries since last tidy (>= threshold {t}) - AI should judge whether to run the §3.8 three-round tidy now (a successful resort --go resets the counter)"
            )];
            if let Some(h) = respire::update_check::hint(false) {
                notes.push(h);
            }
            Some(notes.join("\n"))
        }
        Ok(_) => None,
        Err(e) => {
            eprintln!("WARN maintenance counter failed: {e}");
            None
        }
    }
}

fn run_resort(
    go: bool,
    spec: Option<&str>,
    status: bool,
    reset: bool,
    threshold: Option<u64>,
) -> Result<()> {
    let mpath = respire::service::maintenance_path();
    if status {
        let (n, t) = respire::service::counter_peek(&mpath);
        let state = if n >= t {
            OutputStatus::Warn
        } else {
            OutputStatus::Ok
        };
        let mut result = ResultEnvelope::new(
            "resort",
            state,
            serde_json::json!({"count":n,"threshold":t}),
            vec![OutputItem::new("tidy counter", state, format!("{n}/{t}"))],
        );
        if n >= t {
            result.actions.push("resort --spec <json> --go".into());
        }
        return emit_result(result);
    }
    if reset {
        respire::service::counter_reset(&mpath, &now_stamp())?;
        return emit_result(ResultEnvelope::new(
            "resort",
            OutputStatus::Ok,
            serde_json::json!({"counter":"reset"}),
            vec![OutputItem::new("tidy counter", OutputStatus::Ok, "reset")],
        ));
    }
    if let Some(t) = threshold {
        respire::service::counter_set_threshold(&mpath, t)?;
        if spec.is_none() {
            return emit_result(ResultEnvelope::new(
                "resort",
                OutputStatus::Ok,
                serde_json::json!({"threshold":t}),
                vec![OutputItem::new(
                    "threshold",
                    OutputStatus::Ok,
                    t.to_string(),
                )],
            ));
        }
    }
    let spec = spec.ok_or_else(|| anyhow::anyhow!("need --spec (or --status to inspect the counter / --reset to zero it / --threshold to set it)"))?;
    let session = build_session()?;
    let store = build_local()?;
    let v: serde_json::Value = serde_json::from_str(spec).map_err(|e| {
        anyhow::anyhow!("spec JSON failed to parse: {e} (shape {{\"ops\":[{{\"id\":\"child\",\"parent\":\"parent\"}}]}})")
    })?;
    let ops = v["ops"].as_array().cloned().unwrap_or_default();
    if ops.is_empty() {
        anyhow::bail!("spec has no ops (shape {{\"ops\":[{{\"id\":...,\"parent\":...}}]}})");
    }
    let all = store.all(true)?;
    let mut moved = 0usize;
    let mut rows = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        let (Some(cid), Some(pid)) = (op["id"].as_str(), op["parent"].as_str()) else {
            anyhow::bail!("op#{i} missing id/parent string");
        };
        let child = respire::service::resolve_prefix(&all, cid)?;
        let parent = respire::service::resolve_prefix(&all, pid)?;
        if child == parent {
            anyhow::bail!("op#{i} cannot parent itself: {child}");
        }
        for anc in store.ancestor_chain(&parent)? {
            if anc == child {
                anyhow::bail!(
                    "op#{i} cycle: new parent {} is a descendant of {}",
                    respire::service::short_id(&parent),
                    respire::service::short_id(&child)
                );
            }
        }
        if go {
            respire::service::reparent(&session, &store, &child, &parent)?;
        }
        moved += 1;
        rows.push(OutputItem::new(
            respire::service::short_id(&child),
            if go {
                OutputStatus::Ok
            } else {
                OutputStatus::Pending
            },
            format!(
                "-> {} {}",
                respire::service::short_id(&parent),
                all.iter()
                    .find(|m| m.id == child)
                    .map(|m| m.local_title.as_str())
                    .unwrap_or("")
            ),
        ));
    }
    if go && moved > 0 {
        respire::service::counter_reset(&respire::service::maintenance_path(), &now_stamp())?;
        auto_sync(&session, &store);
        emit_result(ResultEnvelope::new(
            "resort",
            OutputStatus::Ok,
            serde_json::json!({"moved":moved,"applied":true,"counter":"reset"}),
            rows,
        ))?;
    } else {
        let mut result = ResultEnvelope::new(
            "resort",
            OutputStatus::Pending,
            serde_json::json!({"moved":moved,"applied":false}),
            rows,
        );
        result.actions.push("resort --spec <json> --go".into());
        emit_result(result)?;
    }
    Ok(())
}

fn now_stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn current_user() -> String {
    std::env::var("ONEMEMORY_USER").unwrap_or_else(|_| "local".to_owned())
}

/// Assemble transport: ONEMEMORY_ADDR (or session.json addr) -> remote backup store; else local store.
fn build_transport() -> Result<Arc<dyn MemoryTransport>> {
    if let Some((addr, token)) = remote_config_from_session_or_env()? {
        return Ok(Arc::new(RemoteTransport::new(RemoteConfig {
            address: addr,
            token,
        })));
    }
    let db: PathBuf = respire::service::data_dir().join("onememory.db");
    Ok(Arc::new(LocalStore::open(&db)?))
}

fn build_local() -> Result<LocalStore> {
    let db: PathBuf = respire::service::data_dir().join("onememory.db");
    LocalStore::open(&db)
}

/// Remote config: session.json first (addr/token written by client login), then env vars.
fn remote_config_from_session_or_env() -> Result<Option<(String, String)>> {
    // 1) session.json
    if let Ok(data) = read_session_json() {
        if let (Some(addr), Some(token)) = (
            data["addr"].as_str().filter(|s| !s.is_empty()),
            data["token"].as_str().filter(|s| !s.is_empty()),
        ) {
            return Ok(Some((addr.to_owned(), token.to_owned())));
        }
    }
    // 2) env vars
    if let Ok(addr) = std::env::var("ONEMEMORY_ADDR") {
        if !addr.trim().is_empty() {
            let token = std::env::var("ONEMEMORY_TOKEN")
                .map_err(|_| anyhow!("remote mode needs ONEMEMORY_TOKEN"))?;
            return Ok(Some((addr, token)));
        }
    }
    Ok(None)
}

fn build_remote() -> Result<RemoteTransport> {
    let (addr, token) = remote_config_from_session_or_env()?
        .ok_or_else(|| anyhow!("remote store is not configured - have the client/account tool write session.json (addr/token), or set ONEMEMORY_ADDR and ONEMEMORY_TOKEN"))?;
    Ok(RemoteTransport::new(RemoteConfig {
        address: addr,
        token,
    }))
}

/// Unlock session keys: local keyfile first (from keygen/register), else env vars.
fn build_session() -> Result<SessionKeys> {
    if let Ok(keys) = load_local_session() {
        return Ok(keys);
    }
    if read_session_json().is_err() {
        // no local session -> first-run guide
        anyhow::bail!(
            "no local session: rsrs keygen --pass <password> to start fully local (no cloud); \
             or rsrs register / login for a cloud identity; or set the five-keys env vars \
             (ONEMEMORY_PASS/SECRET/KDF_SALT/WRAPPED_URK/URK_NONCE)"
        );
    }
    let password = std::env::var("ONEMEMORY_PASS")
        .map_err(|_| anyhow!("need ONEMEMORY_PASS (master password)"))?;
    let secret = std::env::var("ONEMEMORY_SECRET")
        .map_err(|_| anyhow!("need ONEMEMORY_SECRET (recovery key)"))?;
    let kdf_salt = std::env::var("ONEMEMORY_KDF_SALT")
        .map_err(|_| anyhow!("need ONEMEMORY_KDF_SALT (from keygen/register)"))?;
    let wrapped_urk = std::env::var("ONEMEMORY_WRAPPED_URK")
        .map_err(|_| anyhow!("need ONEMEMORY_WRAPPED_URK (from keygen/login)"))?;
    let urk_nonce = std::env::var("ONEMEMORY_URK_NONCE")
        .map_err(|_| anyhow!("need ONEMEMORY_URK_NONCE (from keygen/login)"))?;
    SessionKeys::unlock(&password, &secret, &kdf_salt, &wrapped_urk, &urk_nonce)
}

fn read_session_json() -> Result<serde_json::Value> {
    auth::read_session_json()
}

/// Deepen the tree: --auto one-shots sub-roots under every flat large root; --root inspects/applies one root.
fn run_tree_deepen(
    root: Option<&str>,
    go: bool,
    titles_json: Option<&str>,
    auto: bool,
    min: f32,
) -> Result<()> {
    let app = respire::service::App::open()?;
    match (root, auto) {
        (_, true) => {
            let all = app.store.all(false)?;
            let roots: Vec<&respire::StoredMemory> = all
                .iter()
                .filter(|m| m.local_parent_id.is_empty())
                .collect();
            let mut total_built = 0usize;
            let mut total_moved = 0usize;
            let mut items = Vec::new();
            let mut details = Vec::new();
            for r in &roots {
                let plan = match respire::service::deepen_plan(&app.store, &r.id, min) {
                    Ok((_, p)) if !p.sub_roots.is_empty() => p,
                    _ => continue,
                };
                let titles: Vec<String> = plan.sub_roots.iter().map(|s| s.title.clone()).collect();
                let (b, m) = respire::service::deepen_apply(
                    &app.keys,
                    &app.embedder,
                    &app.store,
                    &r.id,
                    &plan,
                    &titles,
                )?;
                total_built += b;
                total_moved += m;
                let name = if r.local_title.is_empty() {
                    respire::service::short_id(&r.id)
                } else {
                    r.local_title.clone()
                };
                items.push(OutputItem::new(
                    name,
                    OutputStatus::Ok,
                    format!(
                        "built={b}; moved={m}; root={}",
                        respire::service::short_id(&r.id)
                    ),
                ));
                details.push(serde_json::json!({
                    "root": r.id,
                    "title": r.local_title,
                    "built": b,
                    "moved": m,
                    "sub_roots": titles,
                }));
            }
            let mut result = ResultEnvelope::new(
                "tree-deepen",
                OutputStatus::Ok,
                serde_json::json!({
                    "mode": "auto",
                    "roots": items.len(),
                    "built": total_built,
                    "moved": total_moved,
                }),
                items,
            );
            result.details = serde_json::Value::Array(details);
            emit_result(result)?;
        }
        (Some(root_id), false) => {
            let (rid, plan) = respire::service::deepen_plan(&app.store, root_id, min)?;
            if !go {
                let items = plan
                    .sub_roots
                    .iter()
                    .enumerate()
                    .map(|(index, sub)| {
                        OutputItem::new(
                            format!("sub_root_{}", index + 1),
                            OutputStatus::Pending,
                            format!("title={}; members={}", sub.title, sub.member_ids.len()),
                        )
                    })
                    .collect();
                let mut result = ResultEnvelope::new(
                    "tree-deepen",
                    OutputStatus::Pending,
                    serde_json::json!({
                        "mode": "plan",
                        "root": rid,
                        "sub_roots": plan.sub_roots.len(),
                        "min": min,
                    }),
                    items,
                );
                result.details = serde_json::to_value(&plan)?;
                result.actions.push(format!(
                    "tree-deepen --root {root_id} --go --titles '[\"title1\",\"title2\"]'"
                ));
                return emit_result(result);
            }
            let Some(tj) = titles_json else {
                anyhow::bail!("--go requires --titles '<sub-root title array JSON>'");
            };
            let titles: Vec<String> = serde_json::from_str(tj)
                .map_err(|e| anyhow!("title array failed to parse: {e}"))?;
            let (b, m) = respire::service::deepen_apply(
                &app.keys,
                &app.embedder,
                &app.store,
                &rid,
                &plan,
                &titles,
            )?;
            emit_result(ResultEnvelope::new(
                "tree-deepen",
                OutputStatus::Ok,
                serde_json::json!({
                    "mode": "apply",
                    "root": rid,
                    "built": b,
                    "moved": m,
                }),
                vec![OutputItem::new(
                    "tree-deepen",
                    OutputStatus::Ok,
                    format!(
                        "built={b}; moved={m}; root={}",
                        respire::service::short_id(&rid)
                    ),
                )],
            ))?;
        }
        (None, false) => {
            let all = app.store.all(false)?;
            let mut flat = 0usize;
            let mut items = Vec::new();
            let mut details = Vec::new();
            for r in all.iter().filter(|m| m.local_parent_id.is_empty()) {
                if let Ok((_, plan)) = respire::service::deepen_plan(&app.store, &r.id, min) {
                    if plan.sub_roots.is_empty() {
                        continue;
                    }
                    flat += 1;
                    let title = if r.local_title.is_empty() {
                        "(untitled)"
                    } else {
                        &r.local_title
                    };
                    items.push(OutputItem::new(
                        respire::service::short_id(&r.id),
                        OutputStatus::Pending,
                        format!("title={title}; sub_roots={}", plan.sub_roots.len()),
                    ));
                    details.push(serde_json::json!({
                        "root": r.id,
                        "title": title,
                        "sub_roots": plan.sub_roots,
                    }));
                }
            }
            let mut result = ResultEnvelope::new(
                "tree-deepen",
                if flat == 0 {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                serde_json::json!({"mode":"scan","flat_roots":flat,"min":min}),
                items,
            );
            result.details = serde_json::Value::Array(details);
            if flat > 0 {
                result.actions.push("tree-deepen --root <id>".into());
                result.actions.push("tree-deepen --auto".into());
            }
            emit_result(result)?;
        }
    }
    Ok(())
}

/// Inject-source distribution: no args injects every detected host; --targets lists status; --id injects/uninstalls.
fn run_inject(
    targets_only: bool,
    id: Option<&str>,
    remove: bool,
    all: bool,
    preview: bool,
    expected: Option<&str>,
) -> Result<()> {
    let _ = all; // --all: explicit full inject (skip TUI; no-args in a real TTY opens TUI, otherwise same)
    if preview || expected.is_some() {
        if id != Some("codex") {
            anyhow::bail!("preview and revision check currently support --id codex only");
        }
        if preview {
            emit_details(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"preview":true,"target":"codex"}),
                serde_json::to_value(respire::inject::preview_codex(remove)?)?,
            )?;
        } else if let Some(revision) = expected {
            let changed = respire::inject::apply_codex(remove, revision)?;
            emit_result(ResultEnvelope::new(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"changed":changed,"target":"codex"}),
                vec![OutputItem::new(
                    "codex",
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                )],
            ))?;
        }
        return Ok(());
    }
    if targets_only {
        let ts = respire::inject::targets()?;
        let items = ts
            .iter()
            .map(|t| {
                OutputItem::new(
                    t.id,
                    match t.state {
                        "fresh" => OutputStatus::Ok,
                        "stale" => OutputStatus::Warn,
                        _ => OutputStatus::Skip,
                    },
                    format!("{} {}", t.state, t.path),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "inject",
            OutputStatus::Ok,
            serde_json::json!({"count":ts.len()}),
            items,
        );
        result.details = serde_json::to_value(&ts)?;
        result.actions.push("inject --all".into());
        emit_result(result)?;
        return Ok(());
    }
    match id {
        Some(id) => {
            let changed = if remove {
                respire::inject::remove_one(id)?
            } else {
                respire::inject::inject_one(id)?
            };
            emit_result(ResultEnvelope::new(
                "inject",
                OutputStatus::Ok,
                serde_json::json!({"changed":changed,"id":id}),
                vec![OutputItem::new(
                    id,
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                )],
            ))?;
            Ok(())
        }
        None => {
            let mut any = false;
            let mut failures = Vec::new();
            let mut rows: Vec<serde_json::Value> = Vec::new();
            let mut items: Vec<OutputItem> = Vec::new();
            for t in respire::inject::targets()? {
                if !t.likely_installed && t.id != "generic" {
                    continue;
                }
                let changed = match respire::inject::inject_one(t.id) {
                    Ok(changed) => changed,
                    Err(error) => {
                        let message = format!("{}: {error:#}", t.id);
                        rows.push(
                            serde_json::json!({ "id": t.id, "error": message, "path": t.path }),
                        );
                        items.push(OutputItem::new(t.id, OutputStatus::Fail, "failed"));
                        failures.push(message);
                        continue;
                    }
                };
                any |= changed;
                rows.push(serde_json::json!({ "id": t.id, "changed": changed, "path": t.path }));
                items.push(OutputItem::new(
                    t.id,
                    OutputStatus::Ok,
                    if changed { "updated" } else { "unchanged" },
                ));
            }
            let status = if failures.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "inject",
                status,
                serde_json::json!({"any":any,"count":rows.len()}),
                items,
            );
            result.details = serde_json::Value::Array(rows);
            if any {
                result
                    .actions
                    .push("restart the matching AI app or open a new session".into());
                result.actions.push("inject --targets".into());
            }
            result.errors.extend(failures);
            emit_result(result)?;
            Ok(())
        }
    }
}

/// Split a mixed node: CLI emits material, the AI decides, CLI applies.
fn run_split(id: &str, go: bool, spec_json: Option<&str>) -> Result<()> {
    let app = respire::service::App::open()?;
    let detail = app.show(id)?;
    if !go {
        let m = respire::service::split_material(&detail.entry, &detail.ancestors);
        let mut result = ResultEnvelope::new(
            "split",
            OutputStatus::Skip,
            serde_json::json!({"id": id, "content_len": m.content_len}),
            vec![
                OutputItem::new("plan", OutputStatus::Skip, "inspection only")
                    .action(format!("rsrs split {id} --go --spec '<split-plan-json>'")),
                OutputItem::new("id", OutputStatus::Ok, m.id.clone()),
                OutputItem::new("title", OutputStatus::Ok, m.title.clone()),
                OutputItem::new("kind", OutputStatus::Ok, m.kind.clone()),
                OutputItem::new("content_len", OutputStatus::Ok, m.content_len.to_string()),
                OutputItem::new("parent", OutputStatus::Ok, m.parent_id.clone()),
                OutputItem::new("CONTENT", OutputStatus::Skip, m.content.clone()),
            ],
        );
        result.details = serde_json::to_value(&m)?;
        result
            .actions
            .push("read details and provide --spec JSON".to_owned());
        return emit_result(result);
    }
    let Some(spec_json) = spec_json else {
        anyhow::bail!(
            "--go requires --spec '<split-plan JSON>' (run with no flags first to get material)"
        );
    };
    let spec: respire::service::SplitSpec =
        serde_json::from_str(spec_json).map_err(|e| anyhow!("plan JSON failed to parse: {e}"))?;
    let n =
        respire::service::split_exec(&app.keys, &app.embedder, &app.store, &detail.entry, &spec)?;
    let mut result = ResultEnvelope::new(
        "split",
        OutputStatus::Ok,
        serde_json::json!({"created": n, "root_replaced": spec.summary.is_some()}),
        vec![OutputItem::new("created", OutputStatus::Ok, n.to_string())],
    );
    result.details = serde_json::json!({"root_replaced": spec.summary.is_some()});
    emit_result(result)
}

/// Post-op orphan check: report, do not fix - CLI detects, the model decides; the AI patches with resort after reading.
/// purge resolver: **do not filter deleted entries** - purge's point is to clear tombstone ciphertext.
/// Exact id -> 8-char prefix (including deleted); multiple hits report "prefix not unique" so we do not delete the wrong one.
fn resolve_prefix_incl_deleted(
    store: &respire::transport::local::LocalStore,
    prefix: &str,
) -> Result<String> {
    let prefix = prefix.trim_start_matches('#');
    let all = store.all(true)?;
    if let Some(m) = all.iter().find(|s| s.id == prefix) {
        return Ok(m.id.clone());
    }
    let chars: Vec<char> = prefix.chars().collect();
    let p8: String = chars.iter().take(8).collect();
    let hits: Vec<String> = all
        .iter()
        .filter(|s| s.id.chars().take(8).collect::<String>() == p8)
        .map(|s| s.id.clone())
        .collect();
    match hits.len() {
        1 => Ok(hits[0].clone()),
        0 => anyhow::bail!("no such entry (including deleted): {prefix}"),
        n => anyhow::bail!("prefix not unique ({n} entries): {prefix}"),
    }
}

fn report_orphans(store: &respire::transport::local::LocalStore, action: &str) {
    let all = match store.all(true) {
        Ok(a) => a,
        Err(_) => return,
    };
    let by_id: std::collections::HashMap<&str, &respire::StoredMemory> =
        all.iter().map(|m| (m.id.as_str(), m)).collect();
    let orphans: Vec<&respire::StoredMemory> = all
        .iter()
        .filter(|m| !m.deleted)
        .filter(|m| {
            !m.local_parent_id.is_empty()
                && by_id
                    .get(m.local_parent_id.as_str())
                    .map_or(true, |pp| pp.deleted)
        })
        .collect();
    if orphans.is_empty() {
        return;
    }
    eprintln!("   WARN [{action}] {} orphan(s) (parent deleted/merged; reparent with resort) - `rsrs audit --json` for the whole store:", orphans.len());
    for m in &orphans {
        eprintln!(
            "     {} {} <-was parent {}",
            &m.id[..8.min(m.id.len())],
            m.local_title,
            m.local_parent_id
        );
    }
}

/// Whole-store health audit: orphans / illegal importance / duplicate titles / truncated titles / deep chains - a structured report for an AI to patch after.
/// Query log: list recent queries and adoption/self-grade, or stats (--stats), or report a self-grade (mark).
/// Post-training terms: candidates ≠ hits; chosen = model mark --good, rejected = mark --bad;
/// adopted (used when writing) is a weak signal only.
fn run_query_log(
    limit: usize,
    stats: bool,
    json_flag: bool,
    cmd: Option<&QueryLogCmd>,
) -> Result<()> {
    if json_flag {
        set_json_mode(true);
    }
    let store = build_local()?;
    // mark: model self-grade - the main post-training signal
    if let Some(QueryLogCmd::Mark { ids, good, bad }) = cmd {
        if *good == *bad {
            anyhow::bail!("pick exactly one of --good or --bad");
        }
        let id_list: Vec<String> = ids
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        anyhow::ensure!(!id_list.is_empty(), "ids is empty");
        let unmatched = store.mark_verdict(&id_list, *good)?;
        let status = if unmatched.is_empty() {
            OutputStatus::Ok
        } else {
            OutputStatus::Warn
        };
        let mut result = ResultEnvelope::new(
            "query-log",
            status,
            serde_json::json!({"marked":id_list.len()-unmatched.len(),"good":*good}),
            vec![
                OutputItem::new(
                    "marked",
                    status,
                    (id_list.len() - unmatched.len()).to_string(),
                ),
                OutputItem::new(
                    "verdict",
                    OutputStatus::Ok,
                    if *good { "good" } else { "bad" },
                ),
            ],
        );
        result.details = serde_json::json!({"unmatched":unmatched});
        if !unmatched.is_empty() {
            result.actions.push("query-log --stats".into());
        }
        emit_result(result)?;
        return Ok(());
    }
    if stats {
        let s = store.query_log_stats()?;
        let adopt_rate = if s.total > 0 {
            s.with_adopted as f64 / s.total as f64 * 100.0
        } else {
            0.0
        };
        let empty_rate = if s.total > 0 {
            s.empty_candidates as f64 / s.total as f64 * 100.0
        } else {
            0.0
        };
        let mut result = ResultEnvelope::new(
            "query-log",
            OutputStatus::Ok,
            serde_json::json!({"stats":true,"queries":s.total,"adopted":s.with_adopted,"empty_candidates":s.empty_candidates,"good":s.good_total,"bad":s.bad_total,"adopt_rate":adopt_rate,"empty_rate":empty_rate}),
            vec![
                OutputItem::new("queries", OutputStatus::Ok, s.total.to_string()),
                OutputItem::new(
                    "adopted",
                    OutputStatus::Ok,
                    format!("{} ({adopt_rate:.1}%)", s.with_adopted),
                ),
                OutputItem::new(
                    "empty candidates",
                    OutputStatus::Ok,
                    format!("{} ({empty_rate:.1}%)", s.empty_candidates),
                ),
                OutputItem::new(
                    "self grade",
                    OutputStatus::Ok,
                    format!("good {} / bad {}", s.good_total, s.bad_total),
                ),
            ],
        );
        result.details = serde_json::to_value(&s)?;
        result.items.extend(s.top.iter().map(|(id, c)| {
            OutputItem::new(
                "top adopted",
                OutputStatus::Ok,
                format!("{} count {}", respire::service::short_id(id), c),
            )
        }));
        emit_result(result)?;
        return Ok(());
    }
    let rows = store.query_log_rows(limit)?;
    if rows.is_empty() {
        let mut result = ResultEnvelope::new(
            "query-log",
            OutputStatus::Skip,
            serde_json::json!({"count":0}),
            vec![OutputItem::new("rows", OutputStatus::Skip, "0")],
        );
        result.actions.push("query-log --stats".into());
        emit_result(result)?;
        return Ok(());
    }
    let mut items = Vec::new();
    let mut detail_rows = Vec::new();
    for r in &rows {
        let fmt = |v: &Vec<String>| {
            if v.is_empty() {
                "-".to_owned()
            } else {
                v.iter()
                    .map(|a| respire::service::short_id(a))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        };
        let project = if r.project.is_empty() {
            String::new()
        } else {
            format!(" [{}]", r.project)
        };
        items.push(OutputItem::new(
            "query",
            OutputStatus::Ok,
            format!(
                "{} {}{} cand={} adopted={} good={} bad={}",
                r.ts,
                r.query,
                project,
                fmt(&r.candidates),
                fmt(&r.adopted),
                fmt(&r.good),
                fmt(&r.bad)
            ),
        ));
        detail_rows.push(serde_json::to_value(r)?);
    }
    let mut result = ResultEnvelope::new(
        "query-log",
        OutputStatus::Ok,
        serde_json::json!({"count":rows.len()}),
        items,
    );
    result.details = serde_json::Value::Array(detail_rows);
    emit_result(result)?;
    Ok(())
}

/// Human-readable rank: Some(n) -> #n+1; None -> miss.
fn bench_pos(p: Option<usize>) -> String {
    match p {
        Some(n) => format!("#{}", n + 1),
        None => "miss".to_owned(),
    }
}

/// bench entry: run an evalset / mine an evalset from query-log.
fn run_bench(cmd: &BenchCmd) -> Result<()> {
    match cmd {
        BenchCmd::Run {
            file,
            topk,
            save,
            baseline,
            verbose,
        } => run_bench_run(file, *topk, save.as_deref(), baseline.as_deref(), *verbose),
        BenchCmd::Mine { out, limit, strict } => run_bench_mine(out, *limit, *strict),
    }
}

/// mine: draft an evalset from query-log - expect = good (strict uses only this) ∪ adopted;
/// keep only ids still active; merge same query. Writes JSONL.
fn run_bench_mine(out: &str, limit: usize, strict: bool) -> Result<()> {
    let store = build_local()?;
    let rows = store.query_log_rows(limit * 5)?;
    let active: std::collections::HashSet<String> = scoped_candidates(&store)?
        .iter()
        .map(|m| m.id.clone())
        .collect();
    let cases = bench::mine_from_rows(&rows, strict, limit, &active);
    anyhow::ensure!(
        !cases.is_empty(),
        "nothing to mine: query-log needs a self-grade good (rsrs query-log mark --good) or an adopted record, and the entry must still be in the store"
    );
    let mut buf = String::new();
    for c in &cases {
        buf.push_str(&serde_json::to_string(c)?);
        buf.push('\n');
    }
    std::fs::write(out, buf).map_err(|e| anyhow!("write failed: {out} ({e})"))?;
    emit_result(ResultEnvelope::new(
        "bench-mine",
        OutputStatus::Ok,
        serde_json::json!({"cases":cases.len(),"path":out,"strict":strict}),
        vec![
            OutputItem::new("eval cases", OutputStatus::Ok, cases.len().to_string()),
            OutputItem::new("path", OutputStatus::Ok, out),
            OutputItem::new(
                "source",
                OutputStatus::Ok,
                if strict { "good" } else { "good and adopted" },
            ),
        ],
    ))?;
    Ok(())
}

/// run: execute an evalset - recall each case on the real retrieval path; emit hit-rate/MRR/noise; optional archive and baseline compare.
/// Eval is read-only: no query_log writes, no hit-count bump.
fn run_bench_run(
    file: &str,
    topk: usize,
    save: Option<&str>,
    baseline: Option<&str>,
    verbose: bool,
) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| anyhow!("failed to read evalset: {file} ({e})"))?;
    let cases = bench::parse_evalset(&text)?;
    anyhow::ensure!(!cases.is_empty(), "evalset is empty: {file}");

    // Read the baseline first: fail fast - eval is expensive (per-case recall); do not finish a run then fail on the baseline.
    let base_report: Option<bench::BenchReport> = match baseline {
        Some(bp) => {
            let btext = std::fs::read_to_string(bp)
                .map_err(|e| anyhow!("failed to read baseline: {bp} ({e})"))?;
            Some(
                serde_json::from_str(&btext)
                    .map_err(|e| anyhow!("baseline JSON failed to parse: {bp} ({e})"))?,
            )
        }
        None => None,
    };

    let session = build_session()?;
    let store = build_local()?;
    let candidates = scoped_candidates(&store)?;
    let active_ids: std::collections::HashSet<String> =
        candidates.iter().map(|m| m.id.clone()).collect();
    let embedder = BgeEmbedder::load_model(&build_local()?.retrieval_model()?)?;

    // Expected-id check: warn when not in the active store (deleted/merged) - those cases fail forever
    let mut missing: Vec<String> = Vec::new();
    for c in &cases {
        for e in &c.expect {
            if !active_ids.iter().any(|id| bench::id_match(id, e)) && !missing.contains(e) {
                missing.push(e.clone());
            }
        }
    }

    let mut results = Vec::with_capacity(cases.len());
    let mut latency = Vec::new();
    let mut selector_fallbacks = 0usize;
    for (i, c) in cases.iter().enumerate() {
        eprintln!("[{}/{}] {}", i + 1, cases.len(), c.query);
        let mut q = MemoryQuery::new(&c.query).limit(topk);
        if let Some(p) = &c.project {
            if !p.is_empty() {
                q = q.of_project(p);
            }
        }
        let started = std::time::Instant::now();
        let (ranked, _, fallback) = recall_select::recall(&session, &embedder, &candidates, &q)?;
        latency.push(started.elapsed().as_micros());
        selector_fallbacks += usize::from(fallback.is_some());
        let ids: Vec<String> = ranked.iter().map(|r| r.entry.id.clone()).collect();
        let rank = bench::rank_of(&ids, &c.expect);
        let top1 = ranked.first();
        results.push(bench::CaseResult {
            query: c.query.clone(),
            expect: c.expect.clone(),
            project: c.project.clone(),
            rank,
            ids,
            top1_score: top1.map(|r| r.score),
            top1_title: top1.map(|r| r.entry.title.clone()).unwrap_or_default(),
        });
    }

    let metrics = bench::summarize(&results, topk);
    latency.sort_unstable();
    let mut params = bench::snapshot_params();
    params.insert("embedding_model".into(), embedder.model_name().into());
    params.insert("cli_version".into(), env!("CARGO_PKG_VERSION").into());
    params.insert(
        "recall_mode".into(),
        respire::service::read_agent_config()["recall_mode"]
            .as_str()
            .unwrap_or("fast")
            .into(),
    );
    params.insert("selector_fallbacks".into(), selector_fallbacks.to_string());
    params.insert("retrieval_policy".into(), "Core-owned".into());
    if !latency.is_empty() {
        params.insert("p50_us".into(), latency[latency.len() / 2].to_string());
        params.insert(
            "p95_us".into(),
            latency[(latency.len() * 95 / 100).min(latency.len() - 1)].to_string(),
        );
    }
    let report = bench::BenchReport {
        version: 1,
        ts: chrono::Utc::now().to_rfc3339(),
        evalset: file.to_owned(),
        topk,
        n_entries: candidates.len(),
        params,
        metrics: metrics.clone(),
        results,
    };

    // Baseline compare (optional; base_report was read up front)
    let cmp = base_report
        .as_ref()
        .map(|b| bench::compare(&b.results, &report.results));

    // Archive (optional)
    if let Some(sp) = save {
        let s = serde_json::to_string_pretty(&report)?;
        std::fs::write(sp, s).map_err(|e| anyhow!("failed to archive: {sp} ({e})"))?;
    }

    let m = &report.metrics;
    let mut status = if missing.is_empty() {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    let mut items = vec![
        OutputItem::new("evalset", OutputStatus::Ok, file),
        OutputItem::new(
            "cases",
            OutputStatus::Ok,
            format!("{} ({} positive, {} negative)", m.n, m.n_pos, m.n_neg),
        ),
        OutputItem::new("store", OutputStatus::Ok, report.n_entries.to_string()),
        OutputItem::new(
            "hit rate",
            OutputStatus::Ok,
            format!(
                "hit@1 {:.3}, hit@3 {:.3}, hit@{} {:.3}",
                m.hit1, m.hit3, topk, m.hitk
            ),
        ),
        OutputItem::new("MRR", OutputStatus::Ok, format!("{:.3}", m.mrr)),
        OutputItem::new(
            "noise",
            OutputStatus::Ok,
            format!(
                "empty {}, negative {}/{}",
                m.empty_results, m.neg_noise, m.n_neg
            ),
        ),
    ];
    if !missing.is_empty() {
        status = OutputStatus::Warn;
        items.push(
            OutputItem::new(
                "missing expected ids",
                OutputStatus::Warn,
                missing.join(", "),
            )
            .action("refresh evalset"),
        );
    }

    let missed: Vec<&bench::CaseResult> = report
        .results
        .iter()
        .filter(|r| !r.expect.is_empty() && r.rank.is_none())
        .collect();
    let mut detail = serde_json::json!({"report":report});
    if let (Some(b), Some(c)) = (&base_report, &cmp) {
        detail["baseline"] =
            serde_json::json!({ "file": baseline, "ts": b.ts, "metrics": b.metrics });
        detail["compare"] = serde_json::to_value(c)?;
    }
    if !missed.is_empty() {
        items.push(OutputItem::new(
            "misses",
            OutputStatus::Warn,
            missed.len().to_string(),
        ));
        if matches!(status, OutputStatus::Ok) {
            status = OutputStatus::Warn;
        }
    }
    if verbose {
        items.extend(report.results.iter().enumerate().map(|(i, r)| {
            let score = r
                .top1_score
                .map(|s| format!("{s:.3}"))
                .unwrap_or_else(|| "-".to_owned());
            OutputItem::new(
                format!("case {}", i + 1),
                if r.rank.is_some() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Warn
                },
                format!("{} {} {}", bench_pos(r.rank), score, r.query),
            )
        }));
    }

    if let (Some(b), Some(c)) = (&base_report, &cmp) {
        items.push(OutputItem::new(
            "baseline",
            OutputStatus::Ok,
            format!(
                "{} hit@{} {:.3}->{:.3}, MRR {:.3}->{:.3}",
                baseline.unwrap_or(""),
                topk,
                b.metrics.hitk,
                m.hitk,
                b.metrics.mrr,
                m.mrr
            ),
        ));
        items.push(OutputItem::new(
            "comparison",
            if c.regressed.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            format!(
                "improved {}, regressed {}, same {}, only-new {}, only-baseline {}",
                c.improved.len(),
                c.regressed.len(),
                c.same,
                c.only_in_now,
                c.only_in_base
            ),
        ));
    }
    let mut result = ResultEnvelope::new(
        "bench",
        status,
        serde_json::json!({"evalset":file,"topk":topk,"cases":m.n,"hit1":m.hit1,"hit3":m.hit3,"hitk":m.hitk,"mrr":m.mrr,"missing":missing.len()}),
        items,
    );
    result.details = detail;
    if let Some(sp) = save {
        result.actions.push(format!("report saved to {sp}"));
    }
    emit_result(result)?;
    Ok(())
}

/// Render the final classification status supplied by Core.
fn classify_status(value: &str) -> OutputStatus {
    match value {
        "fail" => OutputStatus::Fail,
        "warn" => OutputStatus::Warn,
        "skip" => OutputStatus::Skip,
        "pending" => OutputStatus::Pending,
        _ => OutputStatus::Ok,
    }
}

fn emit_classify_report(
    report: classify::ClassifyReport,
    mut details: serde_json::Value,
) -> Result<()> {
    let summary = serde_json::to_value(&report.summary)?;
    if let serde_json::Value::Object(ref mut map) = details {
        map.insert("report".to_owned(), serde_json::to_value(&report)?);
    }
    let mut rows = vec![OutputItem::new(
        "summary",
        classify_status(&report.status),
        format!(
            "total={} matched={} mismatch={} unrooted={} low={} failed={}",
            report.summary.total,
            report.summary.matched,
            report.summary.mismatch,
            report.summary.unrooted,
            report.summary.low_confidence,
            report.summary.failed
        ),
    )];
    rows.extend(report.items.iter().map(|item| {
        let value = format!(
            "current={} choice={} confidence={} {}",
            item.current,
            item.choice,
            item.confidence
                .map(|v| format!("{v:.2}"))
                .unwrap_or_default(),
            item.error.clone().unwrap_or_default()
        );
        OutputItem::new(
            format!("{}:{}", item.class, item.id),
            classify_status(&item.status),
            value,
        )
    }));
    let mut envelope = ResultEnvelope::new(
        report.command,
        classify_status(&report.status),
        summary,
        rows,
    );
    envelope.errors = report.errors;
    envelope.details = details;
    emit_result(envelope)
}

fn emit_classify_details(
    command: &str,
    status: OutputStatus,
    summary: serde_json::Value,
    details: serde_json::Value,
    rows: Vec<OutputItem>,
) -> Result<()> {
    let mut result = ResultEnvelope::new(command, status, summary, rows);
    result.details = details;
    emit_result(result)
}

fn run_classify(
    limit: usize,
    all: bool,
    root: Option<&str>,
    max_chars: usize,
    min_confidence: f32,
    save: Option<&str>,
    api_base: Option<&str>,
    model: &str,
    dry_run: bool,
    ds: Option<&str>,
    backend: Option<&str>,
    samples: usize,
    tree: bool,
    batch: usize,
    tree_depth: usize,
    causal: bool,
    min_kids: usize,
    segments: usize,
    out: Option<&str>,
    auto: bool,
    plan: bool,
    rounds: usize,
) -> Result<()> {
    let generation = rpc::sync_generation();
    let (store, memories, selected_root, backend, session) =
        rpc::foreground_phase(generation, || {
            let store = build_local()?;
            let memories = store.all(false)?;
            let selected_root = root
                .map(|prefix| respire::service::resolve_prefix(&memories, prefix))
                .transpose()?;
            let backend = if plan {
                None
            } else {
                Some(build_classify_backend(
                    api_base, model, dry_run, ds, backend,
                )?)
            };
            let session = if auto && !dry_run && !plan {
                Some(build_session()?)
            } else {
                None
            };
            Ok((store, memories, selected_root, backend, session))
        })?;
    let source_revision = classify_source_revision(&memories);
    let mode = if plan {
        "preview"
    } else if auto {
        "auto"
    } else if causal {
        "causal"
    } else if tree {
        "tree"
    } else {
        "standard"
    };
    if progress_enabled() && !dry_run && !plan {
        eprintln!("Running classification...");
    }
    let mut result = classify::execute(
        &memories,
        backend.as_ref(),
        serde_json::json!({
            "mode": mode, "limit": limit, "all": all, "root": selected_root,
            "max_chars": max_chars, "min_confidence": min_confidence, "dry_run": dry_run,
            "samples": samples, "batch": batch, "tree_depth": tree_depth,
            "min_kids": min_kids, "segments": segments, "rounds": rounds,
        }),
    )?;

    rpc::foreground_phase(generation, || Ok(()))?;
    let mut applied = 0usize;
    if let Some(session) = session.as_ref() {
        applied = rpc::foreground_phase(generation, || {
            let current = store.all(false)?;
            anyhow::ensure!(
                classify_source_revision(&current) == source_revision,
                "memory data changed during classification; retry against the current library"
            );
            let ids: std::collections::HashSet<&str> =
                current.iter().map(|memory| memory.id.as_str()).collect();
            let mut changed = std::collections::HashSet::new();
            for action in &result.actions {
                anyhow::ensure!(
                    ids.contains(action.id.as_str()),
                    "classification refers to a missing memory: {}",
                    action.id
                );
                anyhow::ensure!(
                    action.parent_id.is_empty() || ids.contains(action.parent_id.as_str()),
                    "classification refers to a missing parent: {}",
                    action.parent_id
                );
                anyhow::ensure!(
                    changed.insert(action.id.as_str()),
                    "classification returned duplicate actions for {}",
                    action.id
                );
                anyhow::ensure!(
                    action.id != action.parent_id,
                    "classification cannot attach a memory to itself"
                );
            }
            store.write_transaction(|| {
                for action in &result.actions {
                    respire::service::reparent(session, &store, &action.id, &action.parent_id)?;
                }
                Ok(())
            })?;
            if !result.actions.is_empty() {
                respire::service::counter_reset(
                    &respire::service::maintenance_path(),
                    &now_stamp(),
                )?;
            }
            Ok(result.actions.len())
        })?;
        if applied > 0 {
            auto_sync(session, &store);
        }
    }

    let operations: Vec<serde_json::Value> = result
        .actions
        .iter()
        .map(|action| serde_json::json!({"id": action.id, "parent": action.parent_id}))
        .collect();
    if let Some(path) = out {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&serde_json::json!({"ops": operations}))?,
        )
        .map_err(|error| anyhow!("failed to write action preview: {path} ({error})"))?;
    }
    let details = serde_json::json!({
        "mode": mode, "dry_run": dry_run, "items": result.items,
        "ops": operations, "warnings": result.warnings, "applied": applied,
        "backend": backend.as_ref().map(|value| value.name),
        "api_base": backend.as_ref().map(|value| value.base_shown.as_str()),
        "model": backend.as_ref().map(|value| value.model.as_str()),
    });
    if let Some(path) = save {
        std::fs::write(path, serde_json::to_string_pretty(&details)?)
            .map_err(|error| anyhow!("failed to save suggestions: {path} ({error})"))?;
    }
    if let Some(report) = result.report.take() {
        return emit_classify_report(report, details);
    }
    let status = if dry_run {
        OutputStatus::Skip
    } else if result.warnings.is_empty() {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    emit_classify_details(
        if plan { "classify-plan" } else { "classify" },
        status,
        result.summary,
        details,
        vec![
            OutputItem::new("mode", status, mode),
            OutputItem::new("suggested_edits", status, result.actions.len().to_string()),
            OutputItem::new("applied", status, applied.to_string()),
        ],
    )
}

/// Configuration and credentials stay under the selected profile's local gate.
fn build_classify_backend(
    api_base: Option<&str>,
    model: &str,
    dry_run: bool,
    ds: Option<&str>,
    backend: Option<&str>,
) -> Result<classify::Backend> {
    use classify::Backend;
    // -- backend pick --
    // --backend (jev|ds) and --ds collapse: jev plus --ds is a conflict;
    // GUI dropdown or CLI `--ds` / `--backend ds` both reach DS.
    let be = backend
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let ds_sel: Option<String> = match (&be, ds) {
        (Some(b), _) if b == "jev" || b == "typesafe" => {
            if ds.is_some() {
                anyhow::bail!(
                    "--backend jev conflicts with --ds - jev is the default backend; drop --ds"
                );
            }
            None
        }
        (Some(b), Some(k)) if b == "ds" || b == "deepseek" => Some(k.to_owned()),
        (Some(b), None) if b == "ds" || b == "deepseek" => Some(String::new()),
        (Some(b), _) => anyhow::bail!("unknown backend \"{b}\" - choose: jev | ds"),
        (None, k) => k.map(|s| s.to_owned()),
    };
    let ds = ds_sel.as_deref();
    let backend = if let Some(dsk) = ds {
        // Endpoint first: key-ring slot is per host - official DS and b.ai keys are not interchangeable
        let base = match api_base {
            Some(b) => b.to_owned(),
            None => respire::keystore::load_ds_last_base()
                .unwrap_or_else(|| classify::DEFAULT_DS_BASE.to_owned()),
        };
        let host = respire::keystore::host_of(&base);
        let slot = format!("ds@{host}");
        // dry-run hits no network, so no key is required (same as the TypeSafe backend)
        let key = if dry_run {
            respire::keystore::load_classify_key(&slot).unwrap_or_default()
        } else if dsk.trim().is_empty() {
            // `--ds` with no value: load the stored key for this endpoint; else print a setup hint
            respire::keystore::load_classify_key(&slot).ok_or_else(|| {
                anyhow!(
                    "endpoint {host} has no key yet:\n  \
                     rsrs classify --ds <your-key>                      # run now and store in the system keyring\n  \
                     rsrs classify --ds <key> --api-base <endpoint>     # another endpoint (e.g. b.ai)\n  \
                     or  export DS_API_KEY=<your-key>                      # env bypass\n\
                     get a key: https://platform.deepseek.com/api_keys"
                )
            })?
        } else {
            let k = dsk.trim().to_owned();
            // dry-run is inspect-only - do not write the keyring or remember the endpoint (tests must not pollute real config)
            if !dry_run {
                match respire::keystore::save_classify_key(&slot, &k) {
                    Ok(()) => {
                        // remember the endpoint (path included) so the next `--ds` needs no extra flags
                        let _ = respire::keystore::save_ds_last_base(&base);
                        if !json_mode() {
                            eprintln!("KEY key stored in the system keyring (slot {slot}; endpoint {base} remembered)");
                        }
                    }
                    Err(e) => {
                        if !json_mode() {
                            eprintln!("WARN could not store the key in the keyring ({e}) - this run works; next time pass it again or set DS_API_KEY");
                        }
                    }
                }
            }
            k
        };
        let model = if model == classify::DEFAULT_MODEL {
            // model not given: prefer the last model used on this host (relays differ), else the official default
            respire::keystore::load_ds_model(&host)
                .unwrap_or_else(|| classify::DEFAULT_DS_MODEL.to_owned())
        } else {
            model.to_owned()
        };
        if !dry_run && model != classify::DEFAULT_MODEL {
            let _ = respire::keystore::save_ds_model(&host, &model);
        }
        Backend {
            name: "ds",
            key,
            model,
            endpoint: classify::ds_endpoint(&base),
            base_shown: base,
        }
    } else {
        let key = if dry_run {
            String::new()
        } else {
            classify_api_key()?
        };
        let base = api_base.unwrap_or(classify::DEFAULT_API_BASE);
        Backend {
            name: "typesafe",
            key,
            model: model.to_owned(),
            endpoint: base.to_owned(),
            base_shown: base.to_owned(),
        }
    };
    Ok(backend)
}

/// Compare decision inputs without read-only access/heat counters or derived indexes.
fn classify_source_revision(memories: &[respire::StoredMemory]) -> serde_json::Value {
    let mut ordered: Vec<&respire::StoredMemory> = memories.iter().collect();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));
    serde_json::Value::Array(ordered.into_iter().map(|memory| serde_json::json!({
        "id": memory.id, "user": memory.user, "ciphertext": memory.ciphertext,
        "nonce": memory.nonce, "updated_at": memory.updated_at, "deleted": memory.deleted,
        "parent_id": memory.local_parent_id, "title": memory.local_title,
        "kind": memory.local_kind, "tags": memory.local_tags,
        "content_head": memory.local_content_head, "importance": memory.local_importance,
    })).collect())
}

/// JEV API key: TYPESAFE_API_KEY env first, then api_key in <data-dir>/classify.json.
fn classify_api_key() -> Result<String> {
    if let Ok(k) = std::env::var("TYPESAFE_API_KEY") {
        let k = k.trim().to_owned();
        if !k.is_empty() {
            return Ok(k);
        }
    }
    // The GUI "AI backend" dropdown stores the key in the system keyring (slot typesafe) - file and keyring both count
    if let Some(k) = respire::keystore::load_classify_key("typesafe") {
        return Ok(k);
    }
    let p = respire::service::data_dir().join("classify.json");
    if let Ok(text) = std::fs::read_to_string(&p) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(k) = v.get("api_key").and_then(|x| x.as_str()) {
                if !k.trim().is_empty() {
                    return Ok(k.trim().to_owned());
                }
            }
        }
    }
    anyhow::bail!(
        "JEV API key is not set: export TYPESAFE_API_KEY, or write {{\"api_key\":\"...\"}} into {} (apply: console.typesafe.ai/keys, waitlist).\nHint: without a TypeSafe account, use the DS backend - `rsrs classify --ds <key>`",
        p.display()
    )
}

fn run_audit(json_flag: bool) -> Result<()> {
    if json_flag {
        set_json_mode(true);
    }
    let store = build_local()?;
    let all = store.all(true)?;
    let by_id: std::collections::HashMap<&str, &respire::StoredMemory> = all
        .iter()
        .filter(|m| !m.deleted)
        .map(|m| (m.id.as_str(), m))
        .collect();
    let active: Vec<&respire::StoredMemory> = all.iter().filter(|m| !m.deleted).collect();

    // 1. orphans
    let orphans: Vec<&&respire::StoredMemory> = active
        .iter()
        .filter(|m| {
            !m.local_parent_id.is_empty() && !by_id.contains_key(m.local_parent_id.as_str())
        })
        .collect();
    // 2. illegal importance
    let bad_imp: Vec<&&respire::StoredMemory> = active
        .iter()
        .filter(|m| {
            !matches!(
                m.local_importance.as_str(),
                "important" | "normal" | "trivial"
            )
        })
        .collect();
    // 3. duplicate-title groups
    let mut by_title: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
    for m in &active {
        let t = m.local_title.trim();
        if !t.is_empty() {
            by_title.entry(t).or_default().push(m.id.as_str());
        }
    }
    let same_title: Vec<(&str, usize)> = by_title
        .iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, v)| (*k, v.len()))
        .collect();
    // 4. Truncated titles: title is a prefix of the body AND the cut is **mid-word** (next char is not a separator).
    //    "title is a body prefix" alone false-positives - tree roots (CATALOG title + gist) and
    //    entries whose body starts with the title are both prefix-matches with a complete title.
    const TITLE_SEP: &str = "：:，,。.、；;？！!）)】」』\"“” \n\t--/|（(【《「『";
    let truncated: Vec<&&respire::StoredMemory> = active
        .iter()
        .filter(|m| {
            let t = m.local_title.trim();
            if t.is_empty() || t.chars().count() > 20 {
                return false;
            }
            let head = &m.local_content_head;
            if !head.starts_with(t) {
                return false;
            }
            if head.chars().count() <= t.chars().count() + 10 {
                return false;
            }
            match head[t.len()..].chars().next() {
                Some(c) => !TITLE_SEP.contains(c),
                None => false,
            }
        })
        .collect();
    // 5. deep chains
    let depth = |id: &str| -> usize {
        let mut d = 0usize;
        let mut cur = Some(id.to_owned());
        while let Some(c) = cur {
            if d > 30 {
                break;
            }
            if let Some(pp) = by_id.get(c.as_str()) {
                let pid = pp.local_parent_id.clone();
                if pid.is_empty() {
                    break;
                }
                cur = Some(pid);
                d += 1;
            } else {
                break;
            }
        }
        d
    };
    let max_depth = active.iter().map(|m| depth(&m.id)).max().unwrap_or(0);

    // M2 (2026-09-20 audit): previously only the local --json flag was honored;
    // ONEMEMORY_JSON=1 (what the GUI bridge sets) still printed prose, breaking cli-api.md "equivalent" output.
    if json_mode() || json_flag {
        let summary = serde_json::json!({
            "total_active": active.len(),
            "orphans": orphans.len(), "invalid_importance": bad_imp.len(),
            "same_title_groups": same_title.len(), "truncated_titles": truncated.len(),
            "max_depth": max_depth,
        });
        let mut result = ResultEnvelope::new(
            "audit",
            if orphans.is_empty() && bad_imp.is_empty() && truncated.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            summary,
            Vec::new(),
        );
        result.actions.push("audit --json".into());
        let details = serde_json::json!({
            "orphans": orphans.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title, "missing_parent": m.local_parent_id})).collect::<Vec<_>>(),
            "invalid_importance": bad_imp.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title, "importance": m.local_importance})).collect::<Vec<_>>(),
            "same_title_groups": same_title.iter().map(|(t, n)| serde_json::json!({"title": t, "count": n})).collect::<Vec<_>>(),
            "truncated_titles": truncated.iter().map(|m| serde_json::json!({"id": m.id, "title": m.local_title})).collect::<Vec<_>>(),
        });
        result.details = details;
        emit_result(result)?;
        return Ok(());
    }
    let status = if orphans.is_empty() && bad_imp.is_empty() && truncated.is_empty() {
        OutputStatus::Ok
    } else {
        OutputStatus::Warn
    };
    let mut items = vec![
        OutputItem::new("active", OutputStatus::Ok, active.len().to_string()),
        OutputItem::new(
            "orphans",
            if orphans.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            orphans.len().to_string(),
        ),
        OutputItem::new(
            "illegal importance",
            if bad_imp.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            bad_imp.len().to_string(),
        ),
        OutputItem::new(
            "duplicate titles",
            if same_title.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            same_title.len().to_string(),
        ),
        OutputItem::new(
            "truncated titles",
            if truncated.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            },
            truncated.len().to_string(),
        ),
        OutputItem::new("max depth", OutputStatus::Ok, max_depth.to_string()),
    ];
    items.extend(orphans.iter().map(|m| {
        OutputItem::new(
            "orphan",
            OutputStatus::Warn,
            format!(
                "{} parent {}",
                respire::service::short_id(&m.id),
                m.local_parent_id
            ),
        )
        .action("resort")
    }));
    items.extend(bad_imp.iter().map(|m| {
        OutputItem::new(
            "illegal importance",
            OutputStatus::Warn,
            format!(
                "{} {}",
                respire::service::short_id(&m.id),
                m.local_importance
            ),
        )
    }));
    items.extend(same_title.iter().map(|(t, n)| {
        OutputItem::new(
            "duplicate title",
            OutputStatus::Warn,
            format!("{} count {}", t, n),
        )
    }));
    let mut result = ResultEnvelope::new(
        "audit",
        status,
        serde_json::json!({"total_active":active.len(),"orphans":orphans.len(),"invalid_importance":bad_imp.len(),"same_title_groups":same_title.len(),"truncated_titles":truncated.len(),"max_depth":max_depth}),
        items,
    );
    result.actions.push("audit --json".into());
    emit_result(result)?;
    Ok(())
}

fn run_repack() -> Result<()> {
    let session = build_session()?;
    let store = build_local()?;
    let mut fixed = 0usize;
    for stored in store.all(true)? {
        let payload_parent = MemoryEngine::payload_parent(&session, &stored)?;
        if payload_parent != stored.local_parent_id {
            let out = MemoryEngine::reseal_parent(
                &session,
                &stored,
                &stored.local_parent_id,
                &stored.updated_at,
            )?;
            store.put_inner(&out, true)?;
            fixed += 1;
        }
    }
    auto_sync(&session, &store);
    emit_result(ResultEnvelope::new(
        "repack",
        OutputStatus::Ok,
        serde_json::json!({"fixed":fixed}),
        vec![OutputItem::new(
            "resealed",
            OutputStatus::Ok,
            fixed.to_string(),
        )],
    ))
}

/// Local-timezone YYYY-MM-DD (parse failure falls back to the first 10 chars of the original).
fn local_day_of(s: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_else(|_| s.chars().take(10).collect())
}

/// Diary = whole-store time chain (trivia is merged in; not filtered by importance):
fn run_diary(
    limit: usize,
    date: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    contains: Option<&str>,
) -> Result<()> {
    // Date aliases and check: today/yesterday resolve directly; else YYYY-MM-DD, bad format fails fast
    let today = chrono::Local::now().date_naive();
    let resolve_day = |s: &str| -> Result<chrono::NaiveDate> {
        match s {
            "today" => Ok(today),
            "yesterday" => Ok(today - chrono::Duration::days(1)),
            _ => chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map_err(|_| anyhow!("date must be YYYY-MM-DD (or today/yesterday), got: {s}")),
        }
    };
    let date_day = date.map(resolve_day).transpose()?;
    let from_day = from.map(resolve_day).transpose()?;
    let to_day = to.map(resolve_day).transpose()?;
    if date_day.is_some() && (from_day.is_some() || to_day.is_some()) {
        anyhow::bail!("pick one of --date or --from/--to");
    }
    if let (Some(f), Some(t)) = (from_day, to_day) {
        if f > t {
            anyhow::bail!("--from is after --to: {f} > {t}");
        }
    }
    let date_s = date_day.map(|d| d.format("%Y-%m-%d").to_string());
    let from_s = from_day.map(|d| d.format("%Y-%m-%d").to_string());
    let to_s = to_day.map(|d| d.format("%Y-%m-%d").to_string());
    let needle = contains.map(|s| s.to_lowercase());

    let store = build_local()?;
    let mut all: Vec<respire::StoredMemory> = store
        .all(false)?
        .into_iter()
        .filter(|m| {
            let d = local_day_of(&m.local_created_at);
            if let Some(dd) = &date_s {
                return d == *dd;
            }
            if let Some(f) = &from_s {
                if d < *f {
                    return false;
                }
            }
            if let Some(t) = &to_s {
                if d > *t {
                    return false;
                }
            }
            true
        })
        .filter(|m| match &needle {
            Some(n) => {
                m.local_title.to_lowercase().contains(n)
                    || m.local_content_head.to_lowercase().contains(n)
            }
            None => true,
        })
        .collect();
    let ranged = date_s.is_some() || from_s.is_some() || to_s.is_some();
    if ranged {
        all.sort_by(|a, b| a.local_created_at.cmp(&b.local_created_at));
    } else {
        all.sort_by(|a, b| b.local_created_at.cmp(&a.local_created_at));
        all.truncate(limit);
    }
    if json_mode() {
        let rows: Vec<serde_json::Value> = all
            .iter()
            .map(|m| {
                serde_json::json!({
                    "id": m.id, "created_at": m.local_created_at,
                    "day": local_day_of(&m.local_created_at),
                    "kind": m.local_kind, "importance": m.local_importance,
                    "title": m.local_title,
                    "content": m.local_content_head,
                    // Device tag: how an AI tells which machine recorded this (old data is empty)
                    "device": m.local_device,
                    "modified_by": m.local_modified_by,
                })
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "diary",
            OutputStatus::Ok,
            serde_json::json!({"count":rows.len()}),
            rows.iter()
                .map(|row| {
                    OutputItem::new(
                        row["id"].as_str().unwrap_or(""),
                        OutputStatus::Ok,
                        row["title"].as_str().unwrap_or(""),
                    )
                })
                .collect(),
        );
        result.details = serde_json::Value::Array(rows);
        emit_result(result)?;
        return Ok(());
    }
    if all.is_empty() {
        emit_result(ResultEnvelope::new(
            "diary",
            OutputStatus::Skip,
            serde_json::json!({"count":0}),
            vec![
                OutputItem::new("entries", OutputStatus::Skip, "0").action("widen date or keyword")
            ],
        ))?;
        return Ok(());
    }
    let strip = |s: &str| -> String {
        s.strip_prefix("[diary]")
            .map(|r| r.to_owned())
            .unwrap_or_else(|| s.to_owned())
    };
    let title_of = |m: &respire::StoredMemory| -> String {
        let head = strip(&m.local_content_head);
        let head = head.lines().next().unwrap_or("").to_owned();
        if m.local_title.trim().is_empty() {
            head
        } else {
            m.local_title.trim().to_owned()
        }
    };
    let mut items = Vec::new();
    let mut detail_rows = Vec::new();
    for m in &all {
        let dt = chrono::DateTime::parse_from_rfc3339(&m.local_created_at).ok();
        let d = dt
            .as_ref()
            .map(|x| {
                x.with_timezone(&chrono::Local)
                    .format("%Y-%m-%d")
                    .to_string()
            })
            .unwrap_or_else(|| local_day_of(&m.local_created_at));
        let t = dt
            .map(|x| x.with_timezone(&chrono::Local).format("%H:%M").to_string())
            .unwrap_or_else(|| "--:--".to_owned());
        // Device label: diary rows also say which machine recorded them, so paths/commands are not copied across devices.
        let dev = dev_label(&m.local_device, &m.local_computer);
        let title = title_of(m);
        items.push(OutputItem::new(
            "entry",
            OutputStatus::Ok,
            format!("{} {} {} {}", d, t, title, dev),
        ));
        detail_rows.push(serde_json::json!({"id":m.id,"day":d,"time":t,"title":title,"kind":m.local_kind,"importance":m.local_importance,"device":dev,"content":strip(&m.local_content_head)}));
    }
    let mut result = ResultEnvelope::new(
        "diary",
        OutputStatus::Ok,
        serde_json::json!({"count":all.len(),"date":date_s,"from":from_s,"to":to_s,"contains":needle}),
        items,
    );
    result.details = serde_json::Value::Array(detail_rows);
    emit_result(result)?;
    Ok(())
}

/// Built-in catalog: --list prints it; --ensure <root,...> creates/fills roots; no args shows current state (built roots + lone roots).
fn run_taxonomy(list: bool, ensure: Option<&str>) -> Result<()> {
    if list {
        let items = respire::taxonomy::CATALOG
            .iter()
            .map(|c| {
                OutputItem::new(
                    if c.ai { "AI-domain" } else { "human-domain" },
                    OutputStatus::Ok,
                    format!("{} - {}", c.title, c.gist),
                )
            })
            .collect();
        return emit_result(ResultEnvelope::new(
            "taxonomy",
            OutputStatus::Ok,
            serde_json::json!({"count":respire::taxonomy::CATALOG.len()}),
            items,
        ));
    }
    let app = respire::service::App::open()?;
    match ensure {
        Some(names) => {
            let mut built: Vec<(String, String)> = Vec::new();
            for name in names.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Some(idx) = respire::taxonomy::find_by_title(name) else {
                    anyhow::bail!("\"{name}\" is not a built-in catalog root - see rsrs taxonomy --list; a root outside the catalog uses root-create (needs the user to say yes)");
                };
                let rid = respire::taxonomy::ensure_category_root(
                    &app.keys,
                    &app.embedder,
                    &app.store,
                    idx,
                )?;
                built.push((name.to_owned(), rid));
            }
            auto_sync(&app.keys, &app.store);
            let mut result = ResultEnvelope::new(
                "taxonomy",
                OutputStatus::Ok,
                serde_json::json!({"ensured":built.len()}),
                built
                    .iter()
                    .map(|(t, id)| {
                        OutputItem::new(t, OutputStatus::Ok, respire::service::short_id(id))
                    })
                    .collect(),
            );
            result.details = serde_json::json!(built
                .iter()
                .map(|(t, id)| serde_json::json!({"title":t,"root_id":id}))
                .collect::<Vec<_>>());
            emit_result(result)?;
        }
        None => {
            let all = app.store.all(false)?;
            let mut built = 0usize;
            let mut missing: Vec<&str> = Vec::new();
            for c in respire::taxonomy::CATALOG.iter() {
                let rid = respire::taxonomy::root_id(c.title);
                if all.iter().any(|m| m.id == rid) {
                    built += 1;
                } else {
                    missing.push(c.title);
                }
            }
            let lone = respire::taxonomy::lone_roots(&app.store)?;
            let mut result = ResultEnvelope::new(
                "taxonomy",
                if missing.is_empty() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Warn
                },
                serde_json::json!({"total":respire::taxonomy::CATALOG.len(),"built":built,"missing":missing,"lone_roots":lone.len()}),
                vec![
                    OutputItem::new("built", OutputStatus::Ok, built.to_string()),
                    OutputItem::new(
                        "lone roots",
                        if lone.is_empty() {
                            OutputStatus::Ok
                        } else {
                            OutputStatus::Warn
                        },
                        lone.len().to_string(),
                    ),
                ],
            );
            result.actions.push("taxonomy --ensure <roots>".into());
            emit_result(result)?;
        }
    }
    Ok(())
}

/// Create a root outside the catalog: AI proposes -> user allows -> --yes writes. Without --yes, only print the ask; do not write.
fn run_root_create(title: &str, content: Option<&str>, yes: bool) -> Result<()> {
    if respire::taxonomy::find_by_title(title).is_some() {
        anyhow::bail!("\"{title}\" is already a built-in catalog root - rsrs taxonomy --ensure \"{title}\" creates it");
    }
    if !yes {
        let msg = format!(
            "creating a top-level root needs the user to say yes: ask \"create top-level '{title}'? gist: {}\" - rerun with --yes after they allow it; do not create without that",
            content.unwrap_or(title)
        );
        let mut result = ResultEnvelope::new(
            "root-create",
            OutputStatus::Pending,
            serde_json::json!({"title":title,"content":content.unwrap_or(title)}),
            vec![
                OutputItem::new("confirmation", OutputStatus::Pending, msg.clone())
                    .action("rerun with --yes after user approval"),
            ],
        );
        result.actions.push("root-create --yes".into());
        emit_result(result)?;
        return Ok(());
    }
    let app = respire::service::App::open()?;
    let clash = app
        .store
        .all(false)?
        .into_iter()
        .any(|m| m.local_title == title);
    if clash {
        anyhow::bail!("an entry titled \"{title}\" already exists - rename, or hang under it (rsrs show for the id)");
    }
    let rid = respire::taxonomy::root_id(title);
    let now = now_stamp();
    let entry = respire::MemoryEntry {
        id: rid.clone(),
        kind: Kind::Knowledge,
        tags: vec!["catalog root".to_owned(), "custom".to_owned()],
        title: title.to_owned(),
        content: content.unwrap_or(title).to_owned(),
        user: current_user(),
        computer: respire::service::device_tag(),
        device: respire::service::device_tag(),
        modified_by: respire::service::device_tag(),
        project: String::new(),
        created_at: now.clone(),
        updated_at: now,
        emotion: -1.0,
        parent_id: String::new(),
        importance: "important".to_owned(),
    };
    let stored = MemoryEngine::seal(&app.keys, &app.embedder, &entry, &entry.user)?;
    app.store.put(&stored)?;
    auto_sync(&app.keys, &app.store);
    let mut result = ResultEnvelope::new(
        "root-create",
        OutputStatus::Ok,
        serde_json::json!({ "root_id": rid, "title": title }),
        vec![OutputItem::new(
            "root",
            OutputStatus::Ok,
            respire::service::short_id(&rid),
        )],
    );
    result.actions.push(format!(
        "remember <body> --parent {}",
        respire::service::short_id(&rid)
    ));
    emit_result(result)?;
    Ok(())
}

/// Tree hygiene: report (root sizes + attach suggestions) or apply (--id --parent).
fn run_tree_cure(
    top: usize,
    id: Option<&str>,
    parent: Option<&str>,
    auto: bool,
    min: f32,
) -> Result<()> {
    if auto {
        let app = respire::service::App::open()?;
        let report: respire::core_sdk::reports::TreeCureReport = respire::core_sdk::execute(
            "tree_cure",
            serde_json::json!({
                "snapshots": respire::core_sdk::metadata_snapshots(&app.store.all(false)?),
                "top": top, "min": min, "auto": true,
            }),
        )?;
        app.store.write_transaction(|| {
            for suggestion in &report.suggests {
                respire::service::reparent(
                    &app.keys,
                    &app.store,
                    &suggestion.orphan.id,
                    &suggestion.target.id,
                )?;
            }
            Ok(())
        })?;
        if !report.suggests.is_empty() {
            auto_sync(&app.keys, &app.store);
        }
        let items = report
            .suggests
            .iter()
            .map(|suggestion| {
                OutputItem::new(
                    "attach",
                    OutputStatus::Ok,
                    format!(
                        "{} -> {}",
                        suggestion.orphan.title, suggestion.target_tree.title
                    ),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"attached": report.suggests.len(), "failed": 0, "threshold": min}),
            items,
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let app = respire::service::App::open()?;
    if let (Some(id), Some(parent)) = (id, parent) {
        let (child, parent_full) = app.attach(id, parent)?;
        emit_result(ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"child":child,"parent":parent_full}),
            vec![
                OutputItem::new(
                    "child",
                    OutputStatus::Ok,
                    respire::service::short_id(&child),
                ),
                OutputItem::new(
                    "parent",
                    OutputStatus::Ok,
                    respire::service::short_id(&parent_full),
                ),
            ],
        ))?;
        return Ok(());
    }
    let report = app.tree_cure_with_min(top, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots,"suggestions":report.suggests.len()}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let mut items = vec![OutputItem::new(
        "roots",
        OutputStatus::Ok,
        format!(
            "{} total, {} lone leaf",
            report.roots.len(),
            report.lone_roots
        ),
    )];
    for r in report.roots.iter().take(top) {
        items.push(OutputItem::new(
            "root",
            OutputStatus::Ok,
            format!(
                "{} children {} {}",
                r.descendants,
                r.title,
                respire::service::short_id(&r.id)
            ),
        ));
    }
    if report.suggests.is_empty() {
        emit_result(ResultEnvelope::new(
            "tree-cure",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots.len(),"suggestions":0,"threshold":min}),
            items,
        ))?;
        return Ok(());
    }
    for s in &report.suggests {
        items.push(
            OutputItem::new(
                "suggestion",
                OutputStatus::Pending,
                format!(
                    "{} {} -> {} {} tree {}",
                    s.orphan.title,
                    respire::service::short_id(&s.orphan.id),
                    s.target.title,
                    respire::service::short_id(&s.target.id),
                    s.target_tree.title
                ),
            )
            .action("tree-cure --id <id> --parent <parent>"),
        );
    }
    let mut result = ResultEnvelope::new(
        "tree-cure",
        OutputStatus::Pending,
        serde_json::json!({"roots":report.roots.len(),"suggestions":report.suggests.len(),"threshold":min}),
        items,
    );
    result
        .actions
        .push("tree-cure --id <lone-id> --parent <target-id>".into());
    emit_result(result)?;
    Ok(())
}

/// Heat float: high-hit memories move up the cause chain (reattach to grandparent); the tree self-organizes by recall heat.
/// Dry-run prints a report (hot entry -> new cause); --go applies.
fn run_tree_float(go: bool, min: i64) -> Result<()> {
    let app = respire::service::App::open()?;
    let report = app.tree_float(go, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "tree-float",
            if report.items.is_empty() {
                OutputStatus::Ok
            } else if go {
                OutputStatus::Ok
            } else {
                OutputStatus::Pending
            },
            serde_json::json!({"items":report.items.len(),"applied":report.applied}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        if !go && !report.items.is_empty() {
            result.actions.push("tree-float --go".into());
        }
        emit_result(result)?;
        return Ok(());
    }
    if report.items.is_empty() {
        emit_result(ResultEnvelope::new(
            "tree-float",
            OutputStatus::Ok,
            serde_json::json!({"items":0,"applied":report.applied,"min_hits":min}),
            vec![OutputItem::new("candidates", OutputStatus::Ok, "0")],
        ))?;
        return Ok(());
    }
    let mut items = Vec::new();
    for it in &report.items {
        items.push(
            OutputItem::new(
                "candidate",
                if go {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                format!(
                    "{} hits {} {} -> {} {}",
                    it.recall_count,
                    it.title,
                    respire::service::short_id(&it.id),
                    it.new_parent_title,
                    respire::service::short_id(&it.new_parent)
                ),
            )
            .action(if go { "applied" } else { "tree-float --go" }),
        );
    }
    let mut result = ResultEnvelope::new(
        "tree-float",
        if go {
            OutputStatus::Ok
        } else {
            OutputStatus::Pending
        },
        serde_json::json!({"items":report.items.len(),"applied":report.applied,"min_hits":min}),
        items,
    );
    if !go {
        result.actions.push("tree-float --go".into());
    }
    emit_result(result)?;
    Ok(())
}

/// Ask Core for a read-only report of related entries and tree structure.
///
/// **Trivia is not in the tree** (fixed 2026-09-20): drop trivial the same way as `tree`/`tree_cure_with_min` -
/// trivia belongs in the diary (inject §3.4); mixing it in inflates the tree bill (once reported "27 roots" vs a real 23).
/// Orphans after the drop (parent was trivia) count as promoted-to-root, same as `tree`.
fn run_defrag(min: f32, top: usize) -> Result<()> {
    use respire::memory::defrag;
    let store = build_local()?;
    let list = respire::service::tree_scope_list(&store.all(false)?);
    let report = defrag::analyze(&list, min)?;
    if json_mode() {
        let mut result = ResultEnvelope::new(
            "defrag",
            OutputStatus::Ok,
            serde_json::json!({"roots":report.roots,"clusters":report.clusters.len()}),
            Vec::new(),
        );
        result.details = serde_json::to_value(&report)?;
        emit_result(result)?;
        return Ok(());
    }
    let mut items = vec![
        OutputItem::new("active", OutputStatus::Ok, list.len().to_string()),
        OutputItem::new(
            "tree",
            OutputStatus::Ok,
            format!(
                "{} roots, max depth {}, {} lone leaves",
                report.roots, report.max_depth, report.orphans
            ),
        ),
    ];
    if report.clusters.is_empty() {
        emit_result(ResultEnvelope::new(
            "defrag",
            OutputStatus::Ok,
            serde_json::json!({"active":list.len(),"clusters":0,"threshold":min}),
            items,
        ))?;
        return Ok(());
    }
    if report.settled > 0 {
        items.push(OutputItem::new(
            "settled clusters",
            OutputStatus::Ok,
            report.settled.to_string(),
        ));
    }
    for (i, c) in report.clusters.iter().take(top).enumerate() {
        items.push(OutputItem::new(
            format!("cluster {}", i + 1),
            OutputStatus::Pending,
            format!("{} members", c.members.len()),
        ));
        for m in &c.members {
            items.push(OutputItem::new(
                "member",
                OutputStatus::Pending,
                format!(
                    "depth {} date {} id {} {}",
                    m.depth,
                    m.date,
                    &m.id[..m.id.len().min(8)],
                    m.title
                ),
            ));
        }
    }
    if report.clusters.len() > top {
        items.push(
            OutputItem::new(
                "omitted clusters",
                OutputStatus::Skip,
                (report.clusters.len() - top).to_string(),
            )
            .action("raise --top"),
        );
    }
    let mut result = ResultEnvelope::new(
        "defrag",
        OutputStatus::Pending,
        serde_json::json!({"active":list.len(),"clusters":report.clusters.len(),"threshold":min,"shown":top.min(report.clusters.len())}),
        items,
    );
    result
        .actions
        .push("review clusters and use remember --merge-ids or --parent".into());
    emit_result(result)?;
    Ok(())
}
fn load_local_session() -> Result<SessionKeys> {
    auth::load_local_session()
}

fn run_keygen(pass: Option<&str>, force: bool) -> Result<()> {
    // v4: --pass is unused for encryption (super password is system-generated); kept for old scripts
    if pass.is_some() {
        eprintln!("INFO from v4, --pass is not used for encryption: the super password is system-generated; copy the output below");
    }
    // Overwrite guard: keygen issues a new key, and the old key is the only unwrap for store ciphertext -
    // 1. Overwriting while this machine has a cloud session (user/token) drops the session; cloud memories become unreadable.
    // 2. Rotating keys while the local store has memories locks those entries (worse offline: no cloud copy to fall back on).
    // Without --force, refuse and point at the right command.
    let has_wrap = auth::read_session_json()
        .ok()
        .map(|d| {
            let wrap = d["wrapped_urk"].as_str().is_some_and(|s| !s.is_empty());
            let user = d["user"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned);
            let token = d["token"].as_str().is_some_and(|s| !s.is_empty());
            (wrap, user, token)
        })
        .unwrap_or((false, None, false));
    if !force {
        if has_wrap.0 && (has_wrap.1.is_some() || has_wrap.2) {
            anyhow::bail!(
                "this machine already has cloud key material (user {}) - keygen would overwrite it and drop the cloud session, leaving cloud memories unreadable.\
                 To switch to offline keys, add --force. To keep using this machine's memories, rsrs login.\
                 Backup first: rsrs keys-export --out <file>",
                has_wrap.1.as_deref().unwrap_or("(unnamed)")
            );
        }
        // count is a MemoryTransport trait method; the trait must be in scope to call it
        use respire::MemoryTransport as _;
        let alive = respire::service::open_store()
            .and_then(|s| s.count())
            .unwrap_or(0);
        if has_wrap.0 && alive > 0 {
            anyhow::bail!(
                "this store already has {} memories encrypted with the current keys - another keygen would mint new keys and those memories would be unreadable forever.\
                 To start over (old memories discarded), add --force. To keep using this store, run other commands (no need to rebuild keys).",
                alive
            );
        }
    }
    let (path, super_pass) = auth::keygen()?;
    let mut result = ResultEnvelope::new(
        "keygen",
        OutputStatus::Ok,
        serde_json::json!({"path":path.to_string_lossy(),"super":super_pass}),
        vec![OutputItem::new(
            "keys",
            OutputStatus::Ok,
            path.display().to_string(),
        )],
    );
    result
        .actions
        .push("login --user <user> --pass <password>".into());
    emit_result(result)
}

/// Device label: `device` first, `computer` as fallback; both empty -> "unknown device (old data)" -
/// so an AI does not miss the empty field and copy commands across machines.
fn dev_label(device: &str, computer: &str) -> String {
    if !device.trim().is_empty() {
        device.trim().to_owned()
    } else if !computer.trim().is_empty() {
        computer.trim().to_owned()
    } else {
        "unknown device (old data, do not copy commands across machines)".to_owned()
    }
}

/// Time lower bound for list (§3.8 tidy intake). --since takes an explicit time (RFC3339 or YYYY-MM-DD,
/// the latter from 00:00 UTC that day); --since-resort reads maintenance.json resort_at
/// (written when resort --go resets, i.e. "last tidy time"). Both together take the later one.
/// Missing resort_at (never tidied) -> 1970 epoch, i.e. no filter.
fn list_since_bound(since: Option<&str>, since_resort: bool) -> Result<String> {
    let explicit = since.map(respire::service::normalize_since).transpose()?;
    let from_resort = if since_resort {
        respire::service::resort_at()
    } else {
        None
    };
    Ok(respire::service::later_bound(explicit, from_resort))
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Version check (`update-check`): query the npm registry for a newer CLI.
/// 24h throttle (`--force` skips it); `--clear` drops the cache. Any network failure reports "not found", not an error.
fn run_update_check(force: bool, clear: bool) -> Result<()> {
    use respire::update_check as uc;
    if clear {
        uc::clear_cache()?;
        if !force {
            return emit_result(ResultEnvelope::new(
                "update-check",
                OutputStatus::Ok,
                serde_json::json!({"cache":"cleared","checked":false}),
                vec![OutputItem::new("cache", OutputStatus::Ok, "cleared")]
                    .into_iter()
                    .map(|item| item.action("run update-check --force"))
                    .collect(),
            ));
        }
    }
    if !uc::enabled() {
        return emit_result(ResultEnvelope::new(
            "update-check",
            OutputStatus::Skip,
            serde_json::json!({"enabled":false}),
            vec![
                OutputItem::new("version check", OutputStatus::Skip, "disabled")
                    .action("unset ONEMEMORY_UPDATE_CHECK"),
            ],
        ));
    }
    let current = respire::VERSION;
    match uc::check(force) {
        Some(s) => {
            let status = if s.outdated {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            let mut result = ResultEnvelope::new(
                "update-check",
                status,
                serde_json::json!({"current":s.current.clone(),"latest":s.latest.clone(),"outdated":s.outdated,"cached":s.cached}),
                vec![OutputItem::new(
                    "version",
                    status,
                    format!("{} -> {}", s.current, s.latest),
                )],
            );
            if s.outdated {
                result.actions.push("npm i -g @rsrsai/cli@latest".into());
            }
            emit_result(result)
        }
        None => {
            let mut result = ResultEnvelope::new(
                "update-check",
                OutputStatus::Warn,
                serde_json::json!({"current":current,"latest":null,"outdated":null,"cached":false}),
                vec![OutputItem::new("version", OutputStatus::Warn, current)],
            );
            result
                .errors
                .push("registry unavailable or request timed out".into());
            emit_result(result)
        }
    }
}

/// Self-check (OpenViking doctor absorbed): model/store/lock/remote/inject/scope in one pass.
/// --remote also probes server /health. Per-item ok/fail; exit code stays 0 (diagnosis is not failure).
fn run_doctor(check_remote: bool, check_update: bool, fix: bool) -> Result<()> {
    let mut items: Vec<(String, bool, String)> = Vec::new();
    let add = |items: &mut Vec<(String, bool, String)>, name: &str, ok: bool, note: String| {
        items.push((name.to_owned(), ok, note));
    };

    // 1) data dir and store
    let dd = respire::service::data_dir();
    let db = dd.join("onememory.db");
    if db.exists() {
        let store = build_local();
        match store {
            Ok(s) => {
                let n = s.all(true).map(|v| v.len()).unwrap_or(0);
                add(
                    &mut items,
                    "store",
                    true,
                    format!("{} ({} entries)", db.display(), n),
                );
            }
            Err(e) => add(&mut items, "store", false, format!("open failed: {e}")),
        }
    } else {
        add(
            &mut items,
            "store",
            false,
            format!(
                "{} does not exist - register/login or keygen first",
                db.display()
            ),
        );
    }
    add(&mut items, "data dir", true, dd.display().to_string());

    match crate::mcp::materialize_bin() {
        Ok(path) => add(
            &mut items,
            "mcp bin",
            true,
            format!(
                "{} (MCP stdio command; not the npm JS shim)",
                path.display()
            ),
        ),
        Err(err) => add(&mut items, "mcp bin", false, err),
    }
    add(
        &mut items,
        "mcp http",
        true,
        format!(
            "rsrs web serves POST /mcp and GET /sse (default {}/mcp)",
            crate::net_rpc::rpc_base_url()
        ),
    );

    // 2) session (can we unlock)
    match auth::load_local_session() {
        Ok(_) => add(
            &mut items,
            "session",
            true,
            "five-keys complete, can unlock".to_owned(),
        ),
        Err(e) => add(&mut items, "session", false, format!("{e}")),
    }

    // 3) BGE model: diagnostics are read-only unless --fix is explicit.
    let active_model = build_local()?.retrieval_model()?;
    match BgeEmbedder::load_model(&active_model) {
        Ok(e) => add(
            &mut items,
            "embedder",
            true,
            format!("{} {} dims", e.model_name(), e.dims()),
        ),
        Err(e) if !fix => {
            add(
                &mut items,
                "embedder",
                false,
                format!("unavailable: {e} (action: rsrs model install or rsrs doctor --fix)"),
            );
        }
        Err(_) => {
            eprintln!("embedder missing; installing BGE automatically (~100MB; in CN set ONEMEMORY_MIRROR=https://hf-mirror.com)...");
            let mirror = respire::model_install::mirror_from_env();
            let install = if active_model == "m3" {
                respire::model_install::install_m3(mirror.as_deref())
            } else {
                respire::model_install::install(None, mirror.as_deref())
            };
            match install {
                Ok(report) => match BgeEmbedder::load_model(&active_model) {
                    Ok(e) => add(
                        &mut items,
                        "embedder",
                        true,
                        format!(
                            "bge {} dims (auto-installed {})",
                            e.dims(),
                            report.dir.display()
                        ),
                    ),
                    Err(e) => add(
                        &mut items,
                        "embedder",
                        false,
                        format!("still failed to load after install: {e}"),
                    ),
                },
                Err(e) => add(
                    &mut items,
                    "embedder",
                    false,
                    format!(
                        "auto-install failed: {e} (check the network and rerun rsrs doctor --fix)"
                    ),
                ),
            }
        }
    }

    // 3.5) cross-encoder rerank model (**optional**): report if present, hint if not -
    //      extra size (279MB), not auto-downloaded with BGE; run `rsrs model install-rerank`.
    match respire::memory::rerank::resolve_reranker_dir() {
        Ok(dir) => add(
            &mut items,
            "reranker",
            true,
            format!("bge-reranker-base ready ({})", dir.display()),
        ),
        Err(_) => add(
            &mut items,
            "reranker",
            true,
            "not installed (optional; recall still works; enable: rsrs model install-rerank)"
                .to_owned(),
        ),
    }

    // 4) lock: main already holds it exclusively (reaching here proves lock.db is takeable) - never take it twice; two connections in one process deadlock
    add(
        &mut items,
        "lock",
        true,
        "this process holds lock.db exclusively (other sessions wait)".to_owned(),
    );

    // 5) remote (config + optional reachability)
    let configured = remote_configured();
    if configured {
        let (addr, _tok) = remote_config_from_session_or_env()?.unwrap_or_default();
        if check_remote {
            match ureq::get(&format!("{}/health", addr.trim().trim_end_matches('/')))
                .timeout(std::time::Duration::from_secs(5))
                .call()
            {
                Ok(r) => add(
                    &mut items,
                    "remote",
                    true,
                    format!("{addr} /health -> {}", r.status()),
                ),
                Err(e) => add(
                    &mut items,
                    "remote",
                    false,
                    format!("{addr} unreachable: {e}"),
                ),
            }
        } else {
            add(
                &mut items,
                "remote",
                true,
                format!("{addr} (--remote probes reachability)"),
            );
        }
    } else {
        add(
            &mut items,
            "remote",
            true,
            "not configured (local-only)".to_owned(),
        );
    }

    // 6) inject status
    match respire::inject::targets() {
        Ok(ts) => {
            let fresh = ts.iter().filter(|t| t.state == "fresh").count();
            let detected = ts.iter().filter(|t| t.likely_installed).count();
            add(
                &mut items,
                "inject",
                fresh > 0,
                format!("{fresh}/{detected} injected and fresh ({detected} detected)"),
            );
        }
        Err(e) => add(&mut items, "inject", false, format!("{e}")),
    }

    // 6.5) workspace three-state (added 2026-09-21): normal r/w | read-only | temporarily off
    {
        let (ok, note) = match respire::service::workspace_mode() {
            "normal" => (true, "read/write".to_owned()),
            "readonly" => (true, "read-only (writes rejected; team read-only is enforced by the server token)".to_owned()),
            _ => (
                false,
                "temporarily off - recall and store are stopped; `agent-config --set memory_off=false` to restore".to_owned(),
            ),
        };
        add(&mut items, "memory status", ok, note);
    }

    // 8) tidy counter (auto: writes hitting the threshold print TIDY; resort --go resets)
    let (n, t) = respire::service::counter_peek(&respire::service::maintenance_path());
    add(
        &mut items,
        "tidy counter",
        n < t,
        format!("{n}/{t} - new since last tidy (TIDY when the threshold is hit; reset after tidy)"),
    );

    // 9) CLI version (--check-update or ONEMEMORY_UPDATE_CHECK=1 hits the network; default reads cache, no network)
    //    Doctor must not stall on the network, so it does not force a query - report known result, hint how to check if no cache.
    if respire::update_check::enabled() {
        let force = check_update;
        match respire::update_check::check(force) {
            Some(s) if s.outdated => add(
                &mut items,
                "CLI version",
                false,
                format!(
                    "{} -> {} newer available ({}) - npm i -g @rsrsai/cli@latest",
                    s.current,
                    s.latest,
                    if s.cached { "cache" } else { "just checked" }
                ),
            ),
            Some(s) => add(
                &mut items,
                "CLI version",
                true,
                format!("{} is latest ({})", s.current, if s.cached { "cache" } else { "just checked" }),
            ),
            None => add(
                &mut items,
                "CLI version",
                true,
                format!("{} (not checked - add --check-update to query, or set ONEMEMORY_UPDATE_CHECK=0 to disable)", respire::VERSION),
            ),
        }
    } else {
        add(
            &mut items,
            "CLI version",
            true,
            format!("{} (update check disabled)", respire::VERSION),
        );
    }

    let rows: Vec<OutputItem> = items
        .iter()
        .map(|(name, ok, note)| {
            let status = if name == "reranker" && note.starts_with("not installed") {
                OutputStatus::Skip
            } else if name == "remote" && note.starts_with("not configured") {
                OutputStatus::Skip
            } else if name == "CLI version" && note.contains("not checked") {
                OutputStatus::Skip
            } else if name == "tidy counter" && *ok && note.contains("threshold is hit") {
                OutputStatus::Warn
            } else if *ok {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            OutputItem::new(name, status, note)
        })
        .collect();
    let status = output::status_from_items(&rows);
    let pass = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Ok))
        .count();
    let warn = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Warn))
        .count();
    let fail = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Fail))
        .count();
    let skip = rows
        .iter()
        .filter(|i| matches!(i.status, OutputStatus::Skip))
        .count();
    emit_result(ResultEnvelope::new(
        "doctor",
        status,
        serde_json::json!({ "version": respire::VERSION, "pass": pass, "warn": warn, "fail": fail, "skip": skip, "total": rows.len() }),
        rows,
    ))
}

/// One bounded network pass on the runtime synchronization worker.
pub(crate) fn background_sync_once() -> Result<bool> {
    let configured = sync_phase(|| Ok(respire::service::autosync_active() && remote_configured()))?;
    if !configured {
        return Ok(false);
    }
    let (session, local, remote) =
        sync_phase(|| Ok((build_session()?, build_local()?, build_remote()?)))?;
    let stats = sync_with_retry(&session, &local, &remote)?;
    eprintln!(
        "command=sync status=ok mode=auto pulled={} pushed={}",
        stats.pulled, stats.pushed
    );
    respire::hooks::fire(
        respire::hooks::HookEvent::PostSync,
        respire::hooks::sync_payload(stats.pulled, stats.pushed),
    );
    Ok(true)
}

/// Implicit synchronization only notifies the resident runtime after local commit.
/// Direct writes leave durable work for an explicit sync or runtime recovery.
fn schedule_autosync(_session: &SessionKeys, _local: &LocalStore) {
    if rpc::worker_active() && respire::service::autosync_active() && remote_configured() {
        rpc::kick_autosync();
    }
}
fn auto_sync(session: &SessionKeys, local: &LocalStore) {
    schedule_autosync(session, local);
}

fn run_passport() -> Result<()> {
    let si = respire::service::session_info();
    let st = respire::service::status_light().ok();
    let alive = st.as_ref().map(|s| s.local_alive).unwrap_or(0);
    let devices = respire::transport::local::LocalStore::open(
        &respire::service::data_dir().join("onememory.db"),
    )
    .and_then(|s| s.devices_count())
    .unwrap_or(0);
    let agents = respire::inject::targets()
        .map(|ts| {
            ts.iter()
                .filter(|t| t.state == "fresh" || t.state == "stale")
                .count()
        })
        .unwrap_or(0);
    let user = {
        let u = si.user.trim();
        if u.is_empty() {
            "local".to_owned()
        } else {
            u.to_owned()
        }
    };
    let items = vec![
        OutputItem::new("user", OutputStatus::Ok, user.clone()),
        OutputItem::new("memories", OutputStatus::Ok, alive.to_string()),
        OutputItem::new("agents", OutputStatus::Ok, agents.to_string()),
        OutputItem::new("devices", OutputStatus::Ok, devices.to_string()),
    ];
    let mut result = ResultEnvelope::new(
        "passport",
        OutputStatus::Ok,
        serde_json::json!({
            "user": user,
            "memories": alive,
            "agents": agents,
            "devices": devices,
        }),
        items,
    );
    result.details = serde_json::json!({
        "local_first": true,
        "encrypted_sync": true,
        "user_owned": true,
    });
    emit_result(result)
}

/// App::open success -> StatusInfo (unlocked); not unlocked -> None.
fn open_app_status() -> Option<respire::service::StatusInfo> {
    let app = respire::service::App::open().ok()?;
    app.status().ok()
}

/// Subtree material: export this node's subtree as Markdown (for an external AI/App to install).
/// 2026-09-21: moved here from `scope --material` (local-subtree feature dropped; material export stays for install).
fn run_tree_material(prefix: &str) -> Result<()> {
    let session = build_session()?;
    let store = build_local()?;
    let all = store.all(false)?;
    let root_id = respire::service::resolve_prefix(&all, prefix)?;
    let members = respire::service::subtree_members(&all, &root_id);
    let mut entries: Vec<respire::MemoryEntry> = all
        .iter()
        .filter(|m| members.contains(&m.id))
        .filter_map(|s| MemoryEngine::open(&session, s).ok())
        .collect();
    entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    let mut md = String::new();
    md.push_str("# rsrs subtree material\n\n");
    md.push_str(&format!("Node: {root_id}\nCount: {}\n\n", entries.len()));
    for e in &entries {
        let title = if e.title.is_empty() {
            short_id(&e.id)
        } else {
            e.title.clone()
        };
        md.push_str(&format!("## {title}\n\n{}\n\n", e.content));
    }
    let mut result = ResultEnvelope::new(
        "tree-material",
        OutputStatus::Ok,
        serde_json::json!({"node": root_id, "count": entries.len()}),
        vec![OutputItem::new(
            "material",
            OutputStatus::Ok,
            format!("{} entries", entries.len()),
        )],
    );
    result.details = serde_json::json!({"material": md});
    emit_result(result)
}

/// Multiple accounts on one machine: list profiles / use switches / remove deletes.
fn run_account(action: &str, name: Option<&str>, yes: bool) -> Result<()> {
    match action {
        "list" => {
            let v = respire::service::account_list()?;
            let accounts = v["accounts"].as_array().cloned().unwrap_or_default();
            let items = accounts
                .iter()
                .map(|a| {
                    OutputItem::new(
                        a["name"].as_str().unwrap_or(""),
                        OutputStatus::Ok,
                        format!(
                            "{} {}",
                            a["dir"].as_str().unwrap_or(""),
                            a["user"].as_str().unwrap_or("")
                        ),
                    )
                })
                .collect();
            let mut result = ResultEnvelope::new(
                "account",
                OutputStatus::Ok,
                serde_json::json!({"count":accounts.len()}),
                items,
            );
            result.details = v;
            emit_result(result)
        }
        "use" => {
            let name = name.filter(|n| !n.trim().is_empty()).ok_or_else(|| {
                anyhow::anyhow!(
                    "use needs a profile name: rsrs account use <name> (main = primary)"
                )
            })?;
            print_account_use(&respire::service::account_use(name.trim())?)
        }
        "remove" => {
            let name = name.filter(|n| !n.trim().is_empty()).ok_or_else(|| {
                anyhow::anyhow!("remove needs a profile name: rsrs account remove <name> --yes")
            })?;
            if !yes {
                anyhow::bail!("deleting a profile wipes the local store and keys and is unrecoverable - add --yes to confirm");
            }
            respire::service::account_remove(name.trim())?;
            emit_result(ResultEnvelope::new(
                "account",
                OutputStatus::Ok,
                serde_json::json!({"action":"remove","name":name}),
                vec![OutputItem::new("profile", OutputStatus::Ok, "deleted")],
            ))
        }
        // A profile name as the action = switch: rsrs account fslong ≡ account use fslong
        other => print_account_use(&respire::service::account_use(other)?),
    }
}

fn print_account_use(v: &serde_json::Value) -> Result<()> {
    emit_result(ResultEnvelope::new(
        "account",
        OutputStatus::Ok,
        serde_json::json!({"name":v["name"],"dir":v["dir"],"user":v["user"]}),
        vec![
            OutputItem::new(
                "profile",
                OutputStatus::Ok,
                v["name"].as_str().unwrap_or(""),
            ),
            OutputItem::new(
                "directory",
                OutputStatus::Ok,
                v["dir"].as_str().unwrap_or(""),
            ),
        ],
    ))
}

/// Space (virtual-account) command: an owner creates several virtual accounts, each a space; invite codes join people; kick drops membership.
fn run_space(
    action: &str,
    name: Option<&str>,
    note: Option<&str>,
    readonly: bool,
    code: Option<&str>,
    session: Option<&str>,
    all: bool,
    yes: bool,
) -> Result<()> {
    use respire::space;
    match action {
        "list" => {
            let v = space::space_list()?;
            let spaces = v["spaces"].as_array().cloned().unwrap_or_default();
            let items = spaces.iter().map(|s| {
                let name = s["name"].as_str().unwrap_or("");
                let dir = s["dir"].as_str().unwrap_or("");
                let user = s["user"].as_str().unwrap_or("");
                let members = s["members"].as_u64().unwrap_or(0);
                let current = if s["current"].as_bool() == Some(true) { " current" } else { "" };
                OutputItem::new(name, OutputStatus::Ok, format!("dir={dir} user={user} members={members}{current}"))
            }).collect();
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"list","count":spaces.len()}), items);
            result.details = v;
            emit_result(result)
        }
        "create" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("create needs a space name: rsrs space create <name>"))?;
            let v = space::space_create(n)?;
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"create","name":v["name"]}), vec![OutputItem::new("space", OutputStatus::Ok, v["name"].as_str().unwrap_or(""))]);
            result.actions.push(v["hint"].as_str().unwrap_or("").to_owned());
            result.details = v;
            emit_result(result)
        }
        "use" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("use needs a space name: rsrs space use <name>"))?;
            let v = space::space_use(n)?;
            let mut result = ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"use","name":v["name"]}), vec![OutputItem::new("space", OutputStatus::Ok, v["name"].as_str().unwrap_or("")), OutputItem::new("directory", OutputStatus::Ok, v["dir"].as_str().unwrap_or(""))]);
            result.details = v;
            emit_result(result)
        }
        "invite" => {
            let v = space::space_invite(note, readonly)?;
            let status = if v["readonly"].as_bool() == Some(true) { OutputStatus::Warn } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"invite","space":v["space"]}), vec![OutputItem::new("code", status, v["code"].as_str().unwrap_or("")), OutputItem::new("session", OutputStatus::Ok, v["session_id"].as_str().unwrap_or(""))]);
            result.actions.push("space join <code>".into());
            result.details = v;
            emit_result(result)
        }
        "join" => {
            let c = code.or(name).filter(|c| !c.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("join needs an invite code: rsrs space join <code>"))?;
            let v = space::space_join(c)?;
            let status = if v["readonly"].as_bool() == Some(true) || v["keyring"].as_bool() == Some(false) { OutputStatus::Warn } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"join","space":v["space"]}), vec![OutputItem::new("space", status, v["space"].as_str().unwrap_or(""))]);
            result.actions.push(v["hint"].as_str().unwrap_or("").to_owned());
            result.details = v;
            emit_result(result)
        }
        "members" => {
            let v = space::space_members(name)?;
            let ms = v["members"].as_array().cloned().unwrap_or_default();
            let items = ms.iter().map(|m| OutputItem::new(m["session_id"].as_str().unwrap_or(""), OutputStatus::Ok, format!("device={} issued={}", m["device_name"].as_str().unwrap_or(""), m["issued_at"].as_str().unwrap_or("")))).collect();
            let status = if ms.is_empty() { OutputStatus::Skip } else { OutputStatus::Ok };
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"members","space":v["space"],"count":ms.len()}), items);
            if ms.is_empty() { result.actions.push("space invite".into()); }
            result.details = v;
            emit_result(result)
        }
        "kick" => {
            if !session.map(|s| !s.trim().is_empty()).unwrap_or(false) && !all {
                anyhow::bail!("kick needs --session <id> or --all (kick = revoke the member session; they lose access immediately)");
            }
            let v = space::space_kick(session, all)?;
            let revoked = v["revoked"].as_array().cloned().unwrap_or_default();
            let failed = v["failed"].as_array().cloned().unwrap_or_default();
            let status = if failed.is_empty() { OutputStatus::Ok } else { OutputStatus::Warn };
            let items = revoked.iter().map(|r| OutputItem::new("revoked", OutputStatus::Ok, r.as_str().unwrap_or(""))).chain(failed.iter().map(|f| OutputItem::new("failed", OutputStatus::Warn, f.as_str().unwrap_or("")))).collect();
            let mut result = ResultEnvelope::new("space", status, serde_json::json!({"action":"kick","revoked":revoked.len(),"failed":failed.len(),"remaining":v["remaining"]}), items);
            result.details = v;
            emit_result(result)
        }
        "remove" => {
            let n = name.filter(|n| !n.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("remove needs a space name: rsrs space remove <name> --yes"))?;
            if !yes {
                anyhow::bail!("deleting a space profile wipes the local store and keys and is unrecoverable - add --yes to confirm");
            }
            space::space_remove(n)?;
            emit_result(ResultEnvelope::new("space", OutputStatus::Ok, serde_json::json!({"action":"remove","name":n}), vec![OutputItem::new("space", OutputStatus::Ok, "deleted")]))
        }
        other => anyhow::bail!(
            "unknown space action \"{other}\" - use: list | create <name> | use <name> | invite | join <code> | members | kick | remove"
        ),
    }
}

/// Local config: --data-dir/--addr/--autosync/--cure-auto set (all empty = read only).
fn run_config(
    data_dir: Option<&str>,
    addr: Option<&str>,
    autosync: Option<bool>,
    cure_auto: Option<bool>,
    rpc_parallelism: Option<u32>,
) -> Result<()> {
    if let Some(d) = data_dir {
        respire::service::set_data_dir(d)?;
    }
    if let Some(a) = addr {
        respire::service::set_server_addr(a)?;
    }
    if let Some(v) = autosync {
        respire::service::set_autosync(v)?;
    }
    if let Some(v) = cure_auto {
        respire::service::set_cure_auto(v)?;
    }
    if let Some(v) = rpc_parallelism {
        respire::service::set_rpc_parallelism(v)?;
    }
    let workers = rpc::worker_limit();
    let mut worker_text = workers.to_string();
    if rpc_parallelism.is_some() {
        worker_text.push_str(" (after web --stop)");
    }
    let info = serde_json::json!({
        "data_dir": respire::service::data_dir().to_string_lossy(),
        "default_data_dir": respire::service::default_data_dir().to_string_lossy(),
        "addr": respire::service::server_addr(),
        "default_addr": respire::service::DEFAULT_SERVER_ADDR,
        "autosync": respire::service::autosync_enabled(),
        "cure_auto": respire::service::cure_auto_enabled(),
        "rpc_parallelism": respire::service::rpc_parallelism_setting(),
        "rpc_workers": workers,
    });
    let items = vec![
        OutputItem::new(
            "data dir",
            OutputStatus::Ok,
            info["data_dir"].as_str().unwrap_or(""),
        ),
        OutputItem::new(
            "server",
            OutputStatus::Ok,
            info["addr"].as_str().unwrap_or(""),
        ),
        OutputItem::new("auto-sync", OutputStatus::Ok, info["autosync"].to_string()),
        OutputItem::new("auto-cure", OutputStatus::Ok, info["cure_auto"].to_string()),
        OutputItem::new("rpc workers", OutputStatus::Ok, worker_text),
    ];
    emit_result(ResultEnvelope::new("config", OutputStatus::Ok, info, items))
}

fn run_export(file: &str) -> Result<()> {
    let n = respire::service::export_json(std::path::Path::new(file))?;
    emit_result(ResultEnvelope::new(
        "export",
        OutputStatus::Ok,
        serde_json::json!({"exported":n,"path":file}),
        vec![
            OutputItem::new("entries", OutputStatus::Ok, n.to_string()),
            OutputItem::new("path", OutputStatus::Ok, file),
        ],
    ))
}

fn run_backup(file: &str) -> Result<()> {
    let p = respire::service::backup_db(std::path::Path::new(file))?;
    emit_result(ResultEnvelope::new(
        "backup",
        OutputStatus::Ok,
        serde_json::json!({"backed_up":p.to_string_lossy()}),
        vec![OutputItem::new(
            "path",
            OutputStatus::Ok,
            p.display().to_string(),
        )],
    ))
}

/// Export decrypt keys: super password + Secret Key + vault material (how a new machine logs in).
/// Under v3, Account Secret is no longer a decrypt key - export the v3 three-piece; old v1 material is listed as a side note.
fn run_keys_export(out: Option<&str>) -> Result<()> {
    let data = respire::auth::read_session_json()?;
    let user = data["user"].as_str().unwrap_or("").to_owned();
    let addr = data["addr"].as_str().unwrap_or("").to_owned();
    let version = data["vault_version"].as_i64().unwrap_or(0);
    let kdf_salt = data["kdf_salt"].as_str().unwrap_or("").to_owned();
    let wrapped_urk = data["wrapped_urk"].as_str().unwrap_or("").to_owned();
    let urk_nonce = data["urk_nonce"].as_str().unwrap_or("").to_owned();
    if wrapped_urk.is_empty() {
        anyhow::bail!("no local key material (session.json missing wrapped_urk) - this machine never ran register/keys");
    }
    let is_v4 = version >= 4;
    // v4: super password = session["secret_key"] or the keyring; v3: passphrase + Secret Key two-factor
    let super_key = data["secret_key"].as_str().unwrap_or("").to_owned();
    let legacy_super = data["super"].as_str().unwrap_or("").to_owned();
    let super_key = if super_key.is_empty() {
        respire::keystore::load_super(&user).unwrap_or_default()
    } else {
        super_key
    };
    if is_v4 && super_key.is_empty() {
        anyhow::bail!(
            "this machine has no super password (session and keyring are both empty) - \
             if the old machine can still unlock, run rsrs keys-export there; or rsrs super-reset with the current code"
        );
    }
    let is_v3 = version == 3;
    let body = if is_v4 {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- super password (decrypt depends on this; v4 single factor) --\n\
             super password: {super_key}\n\n\
             -- vault wrap material (a new machine login fetches this; listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- import on a new machine --\n\
             rsrs login --user {user} --pass <login-password> --super {super_key}\n\
             (or fill the same super password on the website Keys & Recovery page after login)\n"
        )
    } else {
        format!(
            "rsrs key-recovery notes (leak = loss of the store; lost super password = cloud data permanently unreadable)\n\
             user: {user}\nserver: {addr}\n\n\
             -- decrypt keys (v3 two-factor: passphrase + recovery code; login auto-upgrades to v4) --\n\
             super password (passphrase): {legacy_super}\n\
             Secret Key (recovery code): {super_key}\n\n\
             -- vault wrap material (listed for lookup) --\n\
             vault_version: {version}\n\
             kdf_salt: {kdf_salt}\n\
             wrapped_urk: {wrapped_urk}\n\
             urk_nonce: {urk_nonce}\n\n\
             -- import on a new machine --\n\
             rsrs login --user {user} --pass <login-password> --super \"{legacy_super}\" --secret-key {super_key}\n"
        )
    };
    if !(is_v4 || is_v3) {
        eprintln!("WARN this machine still has a v1/v2 key wrap - rsrs login to upgrade to v4 before exporting");
    }
    match out {
        Some(path) => {
            #[cfg(unix)]
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(path)?;
                f.write_all(body.as_bytes())?;
            }
            #[cfg(not(unix))]
            std::fs::write(path, &body)?;
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Ok,
                serde_json::json!({"path":path,"version":version,"user":user}),
                vec![OutputItem::new("file", OutputStatus::Ok, path)],
            );
            result
                .actions
                .push("protect file; it contains decrypt secrets".into());
            emit_result(result)?;
        }
        None => {
            let mut result = ResultEnvelope::new(
                "keys-export",
                OutputStatus::Warn,
                serde_json::json!({"version":version,"user":user,"inline":true}),
                vec![OutputItem::new("content", OutputStatus::Warn, body)],
            );
            result
                .actions
                .push("use --out <file> for protected storage".into());
            emit_result(result)?;
        }
    }
    Ok(())
}

/// Account Secret / five-keys view (--reveal shows full text; default is masked).
fn run_secret(reveal: bool) -> Result<()> {
    let info = respire::service::session_info();
    if !info.has_session {
        let mut result = ResultEnvelope::new(
            "secret",
            OutputStatus::Skip,
            serde_json::json!({"session":false}),
            vec![OutputItem::new(
                "session",
                OutputStatus::Skip,
                "not available",
            )],
        );
        result.actions.push("register or login".into());
        return emit_result(result);
    }
    let mut items = vec![
        OutputItem::new("user", OutputStatus::Ok, info.user.clone()),
        OutputItem::new("address", OutputStatus::Ok, info.addr.clone()),
        OutputItem::new(
            "token",
            OutputStatus::Ok,
            if info.has_token { "present" } else { "missing" },
        ),
    ];
    let mut details = serde_json::json!({"session":serde_json::to_value(&info)?});
    if reveal {
        let secret = respire::service::session_secret_full()?;
        let five = respire::service::session_five_keys()?;
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Warn,
            secret.clone(),
        ));
        items.push(OutputItem::new(
            "keys",
            OutputStatus::Warn,
            serde_json::to_string(&five)?,
        ));
        details["secret"] = serde_json::json!(secret);
        details["five"] = five;
    } else {
        items.push(OutputItem::new(
            "secret",
            OutputStatus::Ok,
            info.secret_masked,
        ));
    }
    let mut result = ResultEnvelope::new(
        "secret",
        if reveal {
            OutputStatus::Warn
        } else {
            OutputStatus::Ok
        },
        serde_json::json!({"reveal":reveal,"user":info.user}),
        items,
    );
    result.details = details;
    if reveal {
        result.actions.push("protect secret output".into());
    }
    emit_result(result)
}

fn run_fivekeys(
    addr: &str,
    user: &str,
    pass: &str,
    secret: &str,
    kdf_salt: &str,
    wrapped_urk: &str,
    urk_nonce: &str,
    super_pass: &str,
) -> Result<()> {
    auth::fivekeys_login(
        addr,
        user,
        pass,
        secret,
        kdf_salt,
        wrapped_urk,
        urk_nonce,
        super_pass,
    )?;
    emit_result(ResultEnvelope::new(
        "fivekeys",
        OutputStatus::Ok,
        serde_json::json!({"ok":true,"user":user,"addr":addr}),
        vec![OutputItem::new("session", OutputStatus::Ok, "ready")],
    ))
}

fn run_register(
    addr: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    super_pass: Option<&str>,
) -> Result<()> {
    let addr: &str = addr
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(respire::service::DEFAULT_SERVER_ADDR);
    // Missing args: interactive prompt (TTY and not --json); args the prompt cannot fill still error.
    let interactive = respire::prompt::interactive();
    let user: String = match user.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_owned(),
        None if interactive => {
            eprintln!("register server={addr}");
            respire::prompt::ask("username: ")?
        }
        None => {
            return Err(anyhow::anyhow!(
            "missing --user <username> (bare `rsrs register` in a TTY opens an interactive prompt)"
        ))
        }
    };
    let pass: String = match pass.filter(|s| !s.is_empty()) {
        Some(p) => p.to_owned(),
        None if interactive => {
            let p = respire::prompt::ask_secret("login password (for the server; can be reset): ")?;
            if p.len() < 8 {
                return Err(anyhow::anyhow!(
                    "login password must be at least 8 characters"
                ));
            }
            p
        }
        None => return Err(anyhow::anyhow!("missing --pass <login-password>")),
    };
    let super_pass: String = match super_pass.filter(|s| !s.is_empty()) {
        Some(s) => s.to_owned(),
        None => String::new(),
    };
    let issued = respire::service::register(addr, &user, &pass, &super_pass)?;
    let data = auth::read_session_json().unwrap_or_else(|_| serde_json::json!({}));
    let secret_key = data["secret_key"].as_str().unwrap_or("").to_owned();
    let super_key = issued.unwrap_or_else(|| secret_key.clone());
    let mut result = ResultEnvelope::new(
        "register",
        OutputStatus::Ok,
        serde_json::json!({"ok":true,"user":user,"addr":addr,"super":super_key}),
        vec![OutputItem::new("account", OutputStatus::Ok, user.clone())],
    );
    result.actions.push("secret --reveal".into());
    emit_result(result)
}

fn run_login(
    addr: Option<&str>,
    user: Option<&str>,
    pass: Option<&str>,
    super_pass: Option<&str>,
    secret_key: Option<&str>,
    reset_vault: bool,
) -> Result<()> {
    // Address default: last server this machine used (register / last logout keep it in session.json).
    let last = if addr.map(|s| s.trim()).filter(|s| !s.is_empty()).is_none() {
        respire::auth::read_session_json().ok().and_then(|d| {
            d["addr"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_owned())
        })
    } else {
        None
    };
    let addr: &str = match addr.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(a) => a,
        None => match last.as_deref() {
            Some(a) => a,
            // New machine with no stored address: default official server (same as register); --addr is no longer required
            None => respire::service::DEFAULT_SERVER_ADDR,
        },
    };
    // Missing args: interactive prompt (TTY and not --json).
    let interactive = respire::prompt::interactive();
    let user: String = match user.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(u) => u.to_owned(),
        None if interactive => {
            eprintln!("login server={addr}");
            respire::prompt::ask("username: ")?
        }
        None => {
            return Err(anyhow::anyhow!(
            "missing --user <username> (bare `rsrs login` in a TTY opens an interactive prompt)"
        ))
        }
    };
    let pass: String = match pass.filter(|s| !s.is_empty()) {
        Some(p) => p.to_owned(),
        None if interactive => respire::prompt::ask_secret("login password: ")?,
        None => return Err(anyhow::anyhow!("missing --pass <login-password>")),
    };
    let issued = respire::service::login(addr, &user, &pass, super_pass, secret_key, reset_vault)?;
    let mut result = ResultEnvelope::new(
        "login",
        OutputStatus::Ok,
        serde_json::json!({"ok":true,"user":user,"addr":addr,"super_issued":issued}),
        vec![OutputItem::new("session", OutputStatus::Ok, "ready")],
    );
    result.actions.push("secret --reveal".into());
    emit_result(result)
}

fn run_book_material(root: &str) -> Result<()> {
    let app = respire::service::App::open()?;
    let m = app.book_material(root)?;
    let mut result = ResultEnvelope::new(
        "book-material",
        OutputStatus::Ok,
        serde_json::json!({"title":m.root.title,"chapters":m.chapters.len(),"entries":m.total_entries,"chars":m.total_chars}),
        vec![
            OutputItem::new("volume", OutputStatus::Ok, m.root.title.clone()),
            OutputItem::new("chapters", OutputStatus::Ok, m.chapters.len().to_string()),
            OutputItem::new("entries", OutputStatus::Ok, m.total_entries.to_string()),
            OutputItem::new("chars", OutputStatus::Ok, m.total_chars.to_string()),
        ],
    );
    result.details = serde_json::to_value(&m)?;
    emit_result(result)
}

fn run_portrait_material(limit: usize) -> Result<()> {
    let app = respire::service::App::open()?;
    let m = app.portrait_material(limit)?;
    let count = m
        .get("entries")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    let mut result = ResultEnvelope::new(
        "portrait-material",
        OutputStatus::Ok,
        serde_json::json!({"limit":limit,"count":count}),
        vec![
            OutputItem::new("entries", OutputStatus::Ok, count.to_string()),
            OutputItem::new("limit", OutputStatus::Ok, limit.to_string()),
        ],
    );
    result.details = m;
    emit_result(result)
}

/// Share a subtree: emit a prompt another AI can paste.
///
/// Missing `--root` uses this machine's scope root; if that is also unset, error and list candidate roots -
/// sharing a subtree is an explicit action; do not silently pick one (2026-09-21).
fn run_share(root: Option<&str>, raw: bool, out: Option<&str>) -> Result<()> {
    let root_id = match root.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(r) => r.to_owned(),
        None => {
            return Err(anyhow!(
                "no subtree specified: `rsrs share --root <id>` (run `rsrs tree --outline` first to see subtree ids)"
            ));
        }
    };
    let (payload, encoded) = respire::service::export_subtree_payload(&root_id)?;
    let prompt = respire::share::build_prompt(&payload, &encoded);

    if let Some(path) = out.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        std::fs::write(path, &prompt).map_err(|e| anyhow!("write failed {path}: {e}"))?;
        let mut result = ResultEnvelope::new(
            "share",
            OutputStatus::Ok,
            serde_json::json!({"path":path,"root":payload.root_title,"count":payload.items.len(),"chars":payload.total_chars(),"prompt_chars":prompt.chars().count()}),
            vec![OutputItem::new("file", OutputStatus::Ok, path)],
        );
        result.actions.push("protect plaintext payload".into());
        emit_result(result)?;
        return Ok(());
    }

    let status = if raw {
        OutputStatus::Warn
    } else {
        OutputStatus::Ok
    };
    let mut result = ResultEnvelope::new(
        "share",
        status,
        serde_json::json!({"root":payload.root_title,"count":payload.items.len(),"chars":payload.total_chars(),"prompt_chars":prompt.chars().count()}),
        vec![OutputItem::new("prompt", status, prompt)],
    );
    result.details = serde_json::json!({"payload":encoded});
    result.actions.push("protect plaintext payload".into());
    emit_result(result)
}

/// Import a shared subtree: without `--go`, print attach-candidate bill (for the AI to judge); `--go` writes.
/// Refuse Core-reported conflicts before writing; `--force` is the explicit override.
fn run_share_import(
    file: &str,
    parent: &str,
    go: bool,
    title: Option<&str>,
    force: bool,
) -> Result<()> {
    let mut payload = respire::service::read_share_file(std::path::Path::new(file))?;
    if let Some(t) = title.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        payload.root_title = t.to_owned();
    }

    if !go {
        let embedder = BgeEmbedder::load_model(&build_local()?.retrieval_model()?)?;
        let bill = respire::service::share_candidates_with(&payload, &embedder)?;
        let cands = bill["candidates"].as_array().cloned().unwrap_or_default();
        let items = cands
            .iter()
            .take(8)
            .map(|c| {
                OutputItem::new(
                    c["short_id"].as_str().unwrap_or(""),
                    OutputStatus::Pending,
                    format!(
                        "score={} title={}",
                        c["score"].as_f64().unwrap_or(0.0),
                        c["title"].as_str().unwrap_or("")
                    ),
                )
            })
            .collect();
        let mut result = ResultEnvelope::new(
            "share-import",
            OutputStatus::Pending,
            serde_json::json!({"need_go":true,"root":payload.root_title,"entries":payload.items.len(),"chars":payload.total_chars(),"candidates":cands.len()}),
            items,
        );
        result.details = bill;
        result.actions.push(format!("share-import {file} --go"));
        emit_result(result)?;
        return Ok(());
    }

    let embedder = BgeEmbedder::load_model(&build_local()?.retrieval_model()?)?;
    let report = respire::service::import_share_payload(&payload, parent, force, &embedder)?;
    let status = if report.orphaned > 0 || report.skipped > 0 {
        OutputStatus::Warn
    } else {
        OutputStatus::Ok
    };
    let items = vec![
        OutputItem::new("imported", status, report.imported.to_string()),
        OutputItem::new(
            "skipped",
            if report.skipped > 0 {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            },
            report.skipped.to_string(),
        ),
        OutputItem::new(
            "reattached",
            OutputStatus::Ok,
            report.reattached.to_string(),
        ),
        OutputItem::new(
            "orphaned",
            if report.orphaned > 0 {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            },
            report.orphaned.to_string(),
        ),
    ];
    emit_result(ResultEnvelope::new(
        "share-import",
        status,
        serde_json::json!({"root_title":payload.root_title,"imported":report.imported,"skipped":report.skipped,"reattached":report.reattached,"orphaned":report.orphaned,"parent":parent}),
        items,
    ))
}

/// Whether this command writes the store (must refuse in read-only mode).
///
/// Rule: commands that change local store data. **The sync family is not a write** - it only moves existing data;
/// a read-only member must still pull memories others just stored (pull rewrite is the sync engine, not this gate).
/// Also not a write: recall/list/show/chain/diary/tree/status/audit/export/backup/
/// doctor/bench/query-log/taxonomy/agent-config/config/space(switch profile)/inject(writes external files).
fn is_write_command(c: &Command) -> bool {
    matches!(
        c,
        Command::Remember { .. }
            | Command::Update { .. }
            | Command::Forget { .. }
            | Command::Restore { .. }
            | Command::Purge { .. }
            | Command::Attach { .. }
            | Command::Promote { .. }
            | Command::Demote { .. }
            | Command::Resort { .. }
            | Command::Split { .. }
            | Command::Import { .. }
            | Command::Repack
            | Command::RootCreate { .. }
            | Command::TreeCure { .. }
            | Command::TreeDeepen { .. }
            | Command::TreeFloat { .. }
            | Command::Defrag { .. }
            // Audit add (2026-09-20): these change the store or credentials; they were missing so read-only could bypass.
            // Grant writes access_grants (a read-only grant is itself a write);
            // Taxonomy --ensure creates roots; Keygen rotates key material (--force can wreck the store);
            // Model installs to disk; Account switch writes client.json; Login/Register/
            // Fivekeys/SuperReset/KeysExport change session and credentials; Session/Logout change session;
            // Space creates/deletes profiles and issues sessions.
            | Command::Grant { .. }
            | Command::Taxonomy { .. }
            | Command::Keygen { .. }
            | Command::Model { .. }
            | Command::Login { .. }
            | Command::Register { .. }
            | Command::Fivekeys { .. }
            | Command::SuperReset { .. }
            | Command::KeysExport { .. }
            | Command::Logout { .. }
            | Command::Space { .. }
            | Command::Reembed { .. }
            | Command::Retitle { .. }
            | Command::RetitleMany { .. }
            | Command::SyncResolve { .. }
            | Command::SyncRestore { .. }
    )
}

/// Whether this command **changes the read-only switch itself** (agent.json `readonly` key).
///
/// Why (2026-09-20 audit): the read-only gate reads agent.json; if the command that edits it is not gated,
/// a read-only member can `agent-config --set readonly=false` and unlock themselves (reproduced).
/// So identify it separately, and in read-only **only allow keeping/enabling read-only, never turning it off**.
fn is_readonly_switch_off(c: &Command) -> bool {
    match c {
        Command::AgentConfig { set: Some(kv) } => {
            let (k, v) = kv.split_once('=').unwrap_or(("", ""));
            k.trim() == "readonly"
                && matches!(v.trim().to_ascii_lowercase().as_str(), "false" | "0" | "no")
        }
        _ => false,
    }
}

/// Fine-grained write check: these commands are **part write, part read**, so they cannot go wholesale into `is_write_command`.
///
/// Why (2026-09-20 audit): putting all of `Account`/`Session` on the list would block read-only members -
/// they should still `account list` and `session list`.
/// `Account`: list/use read, remove deletes a profile (write); `Session`: list read, revoke changes session (write).
/// Temporarily-off **allowlist**: memory is fully stopped, but admin/identity/inject infrastructure must still work.
///
/// Use an **allowlist** not a blocklist - a new command is refused by default, which matches "off";
/// missing an admin command is only a hassle (turn memory back on); missing a memory command is an accident.
fn is_off_allowed(c: &Command) -> bool {
    matches!(
        c,
        // Self-restore and inject (the only way out of off)
        Command::AgentConfig { .. } | Command::Inject { .. }
        // Status and doctor
        | Command::Status | Command::Doctor { .. } | Command::UpdateCheck { .. }
        // Infrastructure (web server, MCP shell, models, plugins, config)
        | Command::Web { .. } | Command::Mcp { .. } | Command::V | Command::Model { .. }
        | Command::Plugin { .. } | Command::Config { .. }
        // Sync (infrastructure - off blocks memory r/w, not the cloud)
        | Command::Sync { .. } | Command::SyncConflicts { .. } | Command::SyncHistory { .. }
        // Identity / account / credentials / space admin
        | Command::Login { .. } | Command::Logout { .. } | Command::Register { .. }
        | Command::Account { .. } | Command::Session { .. } | Command::Keygen { .. }
        | Command::KeysExport { .. } | Command::SuperReset { .. } | Command::Fivekeys { .. }
        | Command::Secret { .. } | Command::Space { .. }
    )
}

fn is_write_command_fine(c: &Command) -> bool {
    match c {
        Command::Account { action, .. } => {
            let a = action.trim().to_ascii_lowercase();
            a != "list"
        }
        Command::Session { command } => matches!(command, SessionCommand::Revoke { .. }),
        // share-import without --go only prints the candidate bill (read); --go writes
        Command::ShareImport { go, .. } => *go,
        _ => false,
    }
}

fn main() {
    // The command enum and the ONNX session are large. Debug builds on Windows
    // give the main thread a 1MB stack, which overflows inside clap. Do the work
    // on a thread with room.
    let handle = match std::thread::Builder::new()
        .name("rsrs".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(main_body)
    {
        Ok(handle) => handle,
        Err(error) => {
            eprintln!("failed to start the command thread: {error}");
            std::process::exit(1);
        }
    };
    match handle.join() {
        Ok(exit) => std::process::exit(exit),
        Err(payload) => {
            eprintln!("command thread panicked: {}", panic_message(payload));
            std::process::exit(1);
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "command thread panicked without a string payload".to_owned()
}

fn main_body() -> i32 {
    if std::env::args_os().any(|arg| arg == "--client-only") {
        std::env::set_var("ONEMEMORY_CLIENT_ONLY", "1");
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "--internal-inference-worker")
    {
        return match runtime_policy::require_host("inference worker")
            .and_then(|()| respire::memory::onnx::run_worker())
        {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("inference worker: {error:#}");
                1
            }
        };
    }
    match std::env::current_exe() {
        Ok(executable) => {
            if let Err(error) = respire::memory::onnx::enable_worker(executable) {
                eprintln!("cannot enable inference worker: {error:#}");
                return 1;
            }
        }
        Err(error) => {
            eprintln!("cannot locate inference worker executable: {error}");
            return 1;
        }
    }
    // Parse args, then run the command, so a Windows debug stack does not hold both at once.
    // `web` and `--direct` are peeled off before clap: the command enum is large enough that
    // extra derived fields overflow the debug main thread.
    let result = match preprocess_args() {
        Preparsed::Version { json } => {
            set_json_mode(json);
            crate::app_version::emit(json)
        }
        Preparsed::Web(flags) => rpc::web_entry(flags),
        Preparsed::Cli { direct, args } => {
            DIRECT_MODE.store(direct, Ordering::Relaxed);
            run(Cli::parse_from(
                std::iter::once(std::ffi::OsString::from("rsrs")).chain(args),
            ))
        }
    };
    if let Err(error) = result {
        if output_emitted() {
            eprintln!("ERROR: {error:#}");
        } else {
            let mut failure = ResultEnvelope::new(
                "cli",
                OutputStatus::Fail,
                serde_json::json!({"reason":"runtime_error"}),
                Vec::new(),
            );
            failure.errors.push(format!("{error:#}"));
            failure.details = serde_json::json!({"error_type":"runtime"});
            if let Err(render_error) = emit_result(failure) {
                eprintln!("ERROR: {error:#}; output_error: {render_error:#}");
            }
        }
        std::process::exit(1);
    }
    let exit_code = exit_code();
    if exit_code != 0 {
        return exit_code;
    }
    0
}

enum Preparsed {
    Version {
        json: bool,
    },
    Web(rpc::WebFlags),
    Cli {
        direct: bool,
        args: Vec<std::ffi::OsString>,
    },
}

fn is_short_v_version(args: &[String]) -> Option<bool> {
    let mut json = false;
    let mut version = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-v" => version = true,
            _ => return None,
        }
    }
    if version {
        Some(json)
    } else {
        None
    }
}

fn preprocess_args() -> Preparsed {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let direct = args.iter().any(|arg| arg == "--direct");
    args.retain(|arg| arg != "--direct" && arg != "--client-only");
    if let Some(json) = is_short_v_version(&args) {
        return Preparsed::Version { json };
    }
    if args.first().map(String::as_str) == Some("web") {
        let mut flags = rpc::WebFlags {
            port: None,
            no_open: false,
            host: "127.0.0.1".to_owned(),
            internal: false,
            status: false,
            stop: false,
        };
        let mut index = 1;
        while index < args.len() {
            match args[index].as_str() {
                "--internal" => flags.internal = true,
                "--status" => flags.status = true,
                "--stop" => flags.stop = true,
                "--no-open" => flags.no_open = true,
                "--port" => {
                    index += 1;
                    flags.port = args.get(index).and_then(|value| value.parse().ok());
                }
                "--host" => {
                    index += 1;
                    if let Some(host) = args.get(index) {
                        flags.host = host.clone();
                    }
                }
                other => {
                    eprintln!("unknown web flag: {other}");
                    std::process::exit(2);
                }
            }
            index += 1;
        }
        return Preparsed::Web(flags);
    }
    Preparsed::Cli {
        direct,
        args: args.into_iter().map(std::ffi::OsString::from).collect(),
    }
}

fn run(args: Cli) -> Result<()> {
    let _model_task = respire::model_progress::TaskScope::new(args.model_task_id.clone());
    set_json_mode(
        args.json || std::env::var("ONEMEMORY_JSON").is_ok_and(|v| v == "1" || v == "true"),
    );
    if matches!(args.command, Some(Command::V)) {
        return crate::app_version::emit(json_mode());
    }
    if rpc::worker_active() {
        return run_local(args);
    }
    if matches!(
        args.command,
        Some(Command::Model {
            action: ModelAction::ResetCpu
        })
    ) {
        runtime_policy::require_host("CPU recovery and runtime shutdown")?;
        let _takeover = runtime_policy::takeover_lock()?;
        respire::memory::onnx::reset_cpu_config()?;
        let stopped_pid = rpc::force_stop_for_reset()?;
        return emit_result(ResultEnvelope::new(
            "model",
            OutputStatus::Ok,
            serde_json::json!({"engine":"cpu", "force_cpu":true, "stopped_pid":stopped_pid}),
            vec![],
        ));
    }
    if let Some(Command::Web {
        port,
        no_open,
        host,
    }) = args.command.as_ref()
    {
        return rpc::web_entry(rpc::WebFlags {
            port: *port,
            no_open: *no_open,
            host: host.clone(),
            internal: false,
            status: false,
            stop: false,
        });
    }
    if matches!(args.command, Some(Command::Mcp)) {
        if DIRECT_MODE.load(Ordering::Relaxed) {
            anyhow::bail!("mcp uses the resident runtime; do not pass --direct");
        }
        return mcp::serve();
    }
    if DIRECT_MODE.load(Ordering::Relaxed) {
        runtime_policy::require_host("direct local execution")?;
        if rpc::runtime_is_up() {
            anyhow::bail!(
                "the local runtime is running; stop it with `rsrs web --stop` before --direct"
            );
        }
        eprintln!("{}", i18n::text("direct"));
        return run_local(args);
    }
    if args.command.is_none() {
        if std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            return shell::run();
        }
        eprintln!("{}", i18n::text("need_tty"));
        set_exit_code(2);
        return Ok(());
    }
    rpc::call_from_argv()
}

fn run_local(args: Cli) -> Result<()> {
    if rpc::worker_active() {
        respire::service::ensure_runtime_profile()?;
    }
    set_json_mode(
        args.json || std::env::var("ONEMEMORY_JSON").is_ok_and(|v| v == "1" || v == "true"),
    );
    if matches!(args.command, Some(Command::V)) {
        return crate::app_version::emit(json_mode());
    }
    if matches!(args.command, Some(Command::Web { .. })) {
        anyhow::bail!("the web runtime does not run inside a command worker");
    }
    // The runtime worker already holds lock.db for the process lifetime.
    let _library_lock = if rpc::worker_active() {
        None
    } else {
        Some(respire::lock::LibraryLock::acquire(
            &respire::service::data_dir(),
            std::time::Duration::from_secs(120),
        )?)
    };
    // -- Read-only gate (added 2026-09-20; same-day audit moved it) --
    // When this space's agent.json has readonly=true, every write command is refused.
    //
    // **Must sit before the "no embedder needed" early-return match below** - it used to sit after
    // `let command = args.command.unwrap_or(...)` (~line 4882), while resort/
    // split/repack/tree-cure/defrag/root-create writes **returned early** from the match around 4688
    // and never hit the gate - read-only was a no-op (reproduced: those commands still reached unlock).
    // Raised here so every write goes through.
    if let Some(cmd) = args.command.as_ref() {
        // -- Temporarily-off gate (added 2026-09-21; one of the personal-space three states) --
        // memory_off=true refuses both read and write, leaving only admin/identity/inject infrastructure -
        // the owner restores with agent-config --set memory_off=false (unlike team read-only, which is
        // server-enforced: off is a local switch, no need to block self-unlock).
        if respire::service::off_mode() {
            if !is_off_allowed(cmd) {
                anyhow::bail!(
                    "the memory store is temporarily off - this turn provides no memory service (recall and store both stop).\n\
                     \x20  restore: `rsrs agent-config --set memory_off=false` then `rsrs inject --all` to redistribute the prompt."
                );
            }
        } else {
            if is_write_command(cmd) || is_write_command_fine(cmd) {
                respire::service::ensure_writable()?;
            }
            // H2 anti-self-unlock: in read-only, do not allow readonly back to false - **team read-only only**
            // (readonly_team=true, written by space join --readonly). Personal read-only
            // (GUI/agent-config) is the owner's own switch and must be liftable.
            // Even if a team member bypasses the local gate, the server still refuses writes by session token (the real line).
            if respire::service::readonly_mode()
                && respire::service::readonly_team()
                && is_readonly_switch_off(cmd)
            {
                anyhow::bail!(
                    "this space is read-only - you cannot lift read-only yourself.\n\
                     \x20  the space owner must lift it (the server enforces by session token; editing local agent.json does nothing);\n\
                     \x20  if you are the owner and need to write, re-issue a read-write session on the server then `rsrs space join`."
                );
            }
        }
    }
    // keygen/defrag/scope/config etc. do not need the embedder - handle early
    match args.command.as_ref() {
        Some(Command::Grant { command }) => {
            let store = respire::service::open_store()?;
            let (action, result) = match command {
                GrantCommand::Create { root, label } => {
                    let (grant, token) = store.create_grant(root, label)?;
                    (
                        "create",
                        serde_json::json!({"grant": grant, "token": token}),
                    )
                }
                GrantCommand::List => ("list", serde_json::json!({"grants": store.list_grants()?})),
                GrantCommand::Revoke { id } => (
                    "revoke",
                    serde_json::json!({"revoked": store.revoke_grant(id)?}),
                ),
            };
            let items = if action == "list" {
                result["grants"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|g| {
                        OutputItem::new(
                            g["id"].as_str().unwrap_or("grant"),
                            OutputStatus::Ok,
                            serde_json::to_string(g).unwrap_or_default(),
                        )
                    })
                    .collect()
            } else {
                vec![OutputItem::new(
                    "result",
                    OutputStatus::Ok,
                    serde_json::to_string(&result).unwrap_or_default(),
                )]
            };
            let mut envelope = ResultEnvelope::new(
                "grant",
                OutputStatus::Ok,
                serde_json::json!({"action":action}),
                items,
            );
            envelope.details = result;
            return emit_result(envelope);
        }
        Some(Command::Session { command }) => {
            let revoke = match command {
                SessionCommand::List => None,
                SessionCommand::Revoke { id } => Some(id.as_str()),
            };
            let action = if revoke.is_some() { "revoke" } else { "list" };
            let details = respire::auth::sessions(revoke)?;
            let rows = details.as_array().cloned().unwrap_or_default();
            let items = rows
                .iter()
                .map(|s| {
                    OutputItem::new(
                        s["id"]
                            .as_str()
                            .or_else(|| s["session_id"].as_str())
                            .unwrap_or("session"),
                        OutputStatus::Ok,
                        serde_json::to_string(s).unwrap_or_default(),
                    )
                })
                .collect();
            let mut envelope = ResultEnvelope::new(
                "session",
                OutputStatus::Ok,
                serde_json::json!({"action":action,"count":rows.len()}),
                items,
            );
            envelope.details = details;
            return emit_result(envelope);
        }
        Some(Command::Keygen { pass, force }) => return run_keygen(pass.as_deref(), *force),
        Some(Command::Defrag { min, top }) => return run_defrag(*min, *top),
        Some(Command::TreeCure {
            top,
            id,
            parent,
            auto,
            min,
        }) => return run_tree_cure(*top, id.as_deref(), parent.as_deref(), *auto, *min),
        Some(Command::TreeFloat { go, min }) => return run_tree_float(*go, *min),
        Some(Command::Split { id, go, spec }) => return run_split(id, *go, spec.as_deref()),
        Some(Command::Inject {
            targets,
            id,
            remove,
            all,
            preview,
            expected,
            tui,
        }) => {
            // Default interactive: no args + real TTY -> TUI; client child/script (no tty) -> original full inject, same behavior
            let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout());
            let bare = !*targets && id.is_none() && !*remove && !*preview && expected.is_none();
            if *tui || (bare && !*all && interactive) {
                return respire::inject_tui::run();
            }
            return run_inject(
                *targets,
                id.as_deref(),
                *remove,
                *all,
                *preview,
                expected.as_deref(),
            );
        }
        Some(Command::Diary {
            limit,
            date,
            from,
            to,
            contains,
        }) => {
            return run_diary(
                *limit,
                date.as_deref(),
                from.as_deref(),
                to.as_deref(),
                contains.as_deref(),
            )
        }
        Some(Command::Logout { full }) => {
            let outcome = logout_cli(*full)?;
            let status = if outcome.session_found {
                OutputStatus::Ok
            } else {
                OutputStatus::Skip
            };
            let action = if outcome.full {
                if outcome.session_found {
                    "deleted"
                } else {
                    "absent"
                }
            } else if outcome.session_found {
                "cleared"
            } else {
                "absent"
            };
            let mut result = ResultEnvelope::new(
                "logout",
                status,
                serde_json::json!({
                    "mode": if outcome.full { "full" } else { "session" },
                    "action": action,
                    "session_found": outcome.session_found,
                }),
                vec![OutputItem::new("session", status, action)],
            );
            result.details = serde_json::json!({
                "path": outcome.path.display().to_string(),
                "identity_deleted": outcome.full && outcome.session_found,
                "credentials_cleared": !outcome.full && outcome.session_found,
            });
            if outcome.full && outcome.session_found {
                result
                    .actions
                    .push("register or import five-key material to reconnect".to_owned());
            } else if !outcome.full && outcome.session_found {
                result.actions.push("login to reconnect".to_owned());
            }
            return emit_result(result);
        }
        Some(Command::Account { action, name, yes }) => {
            return run_account(action, name.as_deref(), *yes)
        }
        Some(Command::Space {
            action,
            name,
            note,
            readonly,
            code,
            session,
            all,
            yes,
        }) => {
            return run_space(
                action,
                name.as_deref(),
                note.as_deref(),
                *readonly,
                code.as_deref(),
                session.as_deref(),
                *all,
                *yes,
            )
        }
        Some(Command::Repack) => return run_repack(),
        Some(Command::Tree {
            material: Some(root),
            ..
        }) => return run_tree_material(root),
        Some(Command::Tree {
            from,
            outline: true,
            ..
        }) => {
            let app = respire::service::App::open()?;
            let nodes = app.tree(from, usize::MAX)?;
            // --json contract: every command must emit JSON (this used to hard-take the text path,
            // the only CLI command that broke the contract - found in the 2026-09-20 audit).
            if json_mode() {
                let mut rows: Vec<serde_json::Value> = Vec::new();
                collect_outline_json(&nodes, 0, &mut rows);
                let mut result = ResultEnvelope::new(
                    "tree",
                    OutputStatus::Ok,
                    serde_json::json!({"count":rows.len(),"outline":true}),
                    rows.iter()
                        .map(|r| {
                            OutputItem::new(
                                r["short_id"].as_str().unwrap_or(""),
                                OutputStatus::Ok,
                                r["title"].as_str().unwrap_or(""),
                            )
                        })
                        .collect(),
                );
                result.details = serde_json::Value::Array(rows);
                emit_result(result)?;
                return Ok(());
            }
            let mut lines: Vec<String> = Vec::new();
            collect_outline(&nodes, 0, &mut lines);
            emit_result(ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count":lines.len(),"outline":true}),
                lines
                    .iter()
                    .map(|line| OutputItem::new("node", OutputStatus::Ok, line))
                    .collect(),
            ))?;
            return Ok(());
        }
        Some(Command::Resort {
            go,
            spec,
            status,
            reset,
            threshold,
        }) => return run_resort(*go, spec.as_deref(), *status, *reset, *threshold),
        Some(Command::Prompt) => {
            let text = respire::inject::INSTRUCTIONS_MD;
            return emit_result(ResultEnvelope::new(
                "prompt",
                OutputStatus::Ok,
                serde_json::json!({"instructions":text}),
                vec![OutputItem::new("instructions", OutputStatus::Ok, text)],
            ));
        }
        Some(Command::AgentConfig { set }) => return run_agent_config(set.as_deref()),
        Some(Command::Tree { from, depth, .. }) if json_mode() => {
            let app = respire::service::App::open()?;
            let nodes = app.tree(from, *depth)?;
            let mut result = ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count":nodes.len(),"depth":depth}),
                Vec::new(),
            );
            result.details = serde_json::to_value(&nodes)?;
            emit_result(result)?;
            return Ok(());
        }
        Some(Command::TreeDeepen {
            root,
            go,
            titles,
            auto,
            min,
        }) => return run_tree_deepen(root.as_deref(), *go, titles.as_deref(), *auto, *min),
        // Share: decrypt only, no retrieval (no BGE load), so it sits in the no-model section
        Some(Command::Share { root, raw, out }) => {
            return run_share(root.as_deref(), *raw, out.as_deref())
        }
        Some(Command::Doctor {
            remote,
            check_update,
            fix,
        }) => return run_doctor(*remote, *check_update, *fix),
        Some(Command::UpdateCheck { force, clear }) => return run_update_check(*force, *clear),
        Some(Command::Audit { json }) => return run_audit(*json),
        Some(Command::KeysExport { out }) => return run_keys_export(out.as_deref()),
        Some(Command::SuperReset { super_pass }) => {
            let new_super = respire::auth::super_reset(None, super_pass.as_deref())?;
            emit_result(ResultEnvelope::new(
                "super-reset",
                OutputStatus::Ok,
                serde_json::json!({"ok":true,"super":new_super}),
                vec![OutputItem::new("password", OutputStatus::Ok, "issued")],
            ))?;
            return Ok(());
        }
        Some(Command::QueryLog {
            limit,
            stats,
            json,
            cmd,
        }) => return run_query_log(*limit, *stats, *json, cmd.as_ref()),
        Some(Command::Bench { cmd }) => return run_bench(cmd),
        Some(Command::Classify {
            limit,
            all,
            root,
            max_chars,
            min_confidence,
            save,
            dry_run,
            ds,
            backend,
            samples,
            tree,
            batch,
            tree_depth,
            causal,
            min_kids,
            segments,
            out,
            auto,
            plan,
            rounds,
            api_base,
            model,
        }) => {
            return run_classify(
                *limit,
                *all,
                root.as_deref(),
                *max_chars,
                *min_confidence,
                save.as_deref(),
                api_base.as_deref(),
                model,
                *dry_run,
                ds.as_deref(),
                backend.as_deref(),
                *samples,
                *tree,
                *batch,
                *tree_depth,
                *causal,
                *min_kids,
                *segments,
                out.as_deref(),
                *auto,
                *plan,
                *rounds,
            )
        }
        Some(Command::Model { action }) => {
            return match action {
                ModelAction::InstallM3 { mirror } => {
                    let report = respire::model_install::install_m3(
                        mirror
                            .as_deref()
                            .or(respire::model_install::mirror_from_env().as_deref()),
                    )?;
                    emit_result(ResultEnvelope::new(
                        "model install-m3",
                        OutputStatus::Ok,
                        serde_json::json!({"dir":report.dir,"skipped":report.skipped,"activated":false}),
                        vec![OutputItem::new(
                            "model",
                            OutputStatus::Ok,
                            "BGE-M3 downloaded; activate to rebuild the index",
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::Activate { model } => {
                    use respire::model_progress;
                    let _operation = model_progress::Operation::begin("load")?;
                    let store = build_local()?;
                    let keys = build_session()?;
                    let embedder = BgeEmbedder::load_model(model)?;
                    let count = store.rebuild_index_with_progress(
                        &keys,
                        &embedder,
                        model,
                        |done, total| {
                            model_progress::update("index", model, done as u64, Some(total as u64))
                        },
                    )?;
                    *EMBEDDER_SLOT
                        .lock()
                        .map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    emit_result(ResultEnvelope::new(
                        "model activate",
                        OutputStatus::Ok,
                        serde_json::json!({"model":model,"indexed":count,"dimensions":embedder.dims()}),
                        vec![OutputItem::new(
                            "active_model",
                            OutputStatus::Ok,
                            model.clone(),
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::ResetCpu => {
                    anyhow::bail!("run `rsrs model reset-cpu` directly in your terminal")
                }
                ModelAction::Engine { engine } => {
                    use respire::memory::onnx;
                    if let Some(engine) = engine {
                        onnx::save_engine(onnx::Engine::parse(engine)?)?;
                        *EMBEDDER_SLOT
                            .lock()
                            .map_err(|_| anyhow!("embedder cache poisoned"))? = None;
                    }
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        serde_json::json!({"engine":onnx::configured_engine()?}),
                        vec![],
                    ))?;
                    Ok(())
                }
                ModelAction::InstallEngines => {
                    let providers = respire::memory::onnx::install_accelerators()?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        serde_json::json!({"providers":providers}),
                        vec![],
                    ))?;
                    Ok(())
                }
                ModelAction::Probe { text, model } => {
                    let selected = match model {
                        Some(model) => model.clone(),
                        None => build_local()?.retrieval_model()?,
                    };
                    let result = BgeEmbedder::load_model(&selected)?.probe(text)?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        result,
                        vec![],
                    ))?;
                    Ok(())
                }
                ModelAction::InstallBge { mirror } => {
                    let report = respire::model_install::install(
                        None,
                        mirror
                            .as_deref()
                            .or(respire::model_install::mirror_from_env().as_deref()),
                    )?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        serde_json::json!({"dir":report.dir.display().to_string(),"skipped":report.skipped,"model":"bge-base-zh-v1.5"}),
                        vec![OutputItem::new(
                            "model",
                            OutputStatus::Ok,
                            report.dir.display().to_string(),
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::UninstallBge => {
                    let report = respire::model_install::uninstall_bge()?;
                    let status = if report.removed {
                        OutputStatus::Ok
                    } else {
                        OutputStatus::Skip
                    };
                    emit_result(ResultEnvelope::new(
                        "model",
                        status,
                        serde_json::json!({"dir":report.dir.display().to_string(),"removed":report.removed,"model":"bge-base-zh-v1.5"}),
                        vec![OutputItem::new(
                            "model",
                            status,
                            if report.removed {
                                report.dir.display().to_string()
                            } else {
                                "not installed".to_owned()
                            },
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::InstallRerank { mirror, source } => {
                    let report = respire::model_install::install_rerank(
                        None,
                        mirror
                            .as_deref()
                            .or(respire::model_install::mirror_from_env().as_deref()),
                        source.as_deref(),
                    )?;
                    emit_result(ResultEnvelope::new(
                        "model",
                        OutputStatus::Ok,
                        serde_json::json!({"dir":report.dir.display().to_string(),"skipped":report.skipped,"model":"bge-reranker-base"}),
                        vec![OutputItem::new(
                            "model",
                            OutputStatus::Ok,
                            report.dir.display().to_string(),
                        )],
                    ))?;
                    Ok(())
                }
                ModelAction::UninstallRerank => {
                    let report = respire::model_install::uninstall_rerank()?;
                    let status = if report.removed {
                        OutputStatus::Ok
                    } else {
                        OutputStatus::Skip
                    };
                    emit_result(ResultEnvelope::new(
                        "model",
                        status,
                        serde_json::json!({"dir":report.dir.display().to_string(),"removed":report.removed,"model":"bge-reranker-base"}),
                        vec![OutputItem::new(
                            "model",
                            status,
                            if report.removed {
                                report.dir.display().to_string()
                            } else {
                                "not installed".to_owned()
                            },
                        )],
                    ))?;
                    Ok(())
                }
            };
        }
        Some(Command::Config {
            data_dir,
            addr,
            autosync,
            cure_auto,
            rpc_parallelism,
        }) => {
            return run_config(
                data_dir.as_deref(),
                addr.as_deref(),
                *autosync,
                *cure_auto,
                *rpc_parallelism,
            )
        }
        Some(Command::Export { file }) => return run_export(file),
        Some(Command::Backup { file }) => return run_backup(file),
        Some(Command::Secret { reveal }) => return run_secret(*reveal),
        Some(Command::Fivekeys {
            addr,
            user,
            pass,
            secret,
            kdf_salt,
            wrapped_urk,
            urk_nonce,
            super_pass,
        }) => {
            return run_fivekeys(
                addr,
                user,
                pass,
                secret,
                kdf_salt,
                wrapped_urk,
                urk_nonce,
                super_pass,
            )
        }
        Some(Command::Register {
            addr,
            user,
            pass,
            super_pass,
        }) => {
            return run_register(
                addr.as_deref(),
                user.as_deref(),
                pass.as_deref(),
                super_pass.as_deref(),
            )
        }
        Some(Command::Login {
            addr,
            user,
            pass,
            super_pass,
            secret_key,
            reset_vault,
        }) => {
            return run_login(
                addr.as_deref(),
                user.as_deref(),
                pass.as_deref(),
                super_pass.as_deref(),
                secret_key.as_deref(),
                *reset_vault,
            )
        }
        Some(Command::BookMaterial { root }) => return run_book_material(root),
        Some(Command::PortraitMaterial { limit }) => return run_portrait_material(*limit),
        Some(Command::Taxonomy { list, ensure }) => return run_taxonomy(*list, ensure.as_deref()),
        Some(Command::RootCreate {
            title,
            content,
            yes,
        }) => return run_root_create(title, content.as_deref(), *yes),
        _ => {}
    }
    let command = args.command.unwrap_or(Command::Status);
    // Lazy-load the embedder: Show/Sync/Status/tree ops do not pay BGE cost.
    // The runtime worker puts the loaded model back so the next request does not pay it again.
    let mut embedder_hold = EmbedderHold(
        EMBEDDER_SLOT
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take(),
    );
    macro_rules! embedder {
        () => {{
            let model = build_local()?.retrieval_model()?;
            if embedder_hold
                .0
                .as_ref()
                .is_some_and(|e| e.model_name() != model)
            {
                embedder_hold.0 = None;
            }
            if embedder_hold.0.is_none() {
                embedder_hold.0 = Some(Box::new(BgeEmbedder::load_model(&model)?));
            }
            match embedder_hold.0.as_deref() {
                Some(e) => e,
                None => return Err(anyhow::anyhow!("embedder not loaded")),
            }
        }};
    }
    match command {
        Command::Remember {
            content,
            r#type,
            tags,
            title,
            project,
            computer,
            emotion,
            importance,
            parent,
            force,
            merge_ids,
        } => {
            // importance enum check: an illegal value (e.g. a kind name "task" by mistake) cannot be filtered by audit/UI after write
            // 2026-09-19 two-tier: normal is retired - new writes are important/trivial only (stock normal still reads)
            if !matches!(importance.as_str(), "important" | "trivial") {
                anyhow::bail!("importance must be important/trivial (normal is retired; normal is logged as diary trivia), got \"{}\"", importance);
            }
            // -- Plugin hook pre-remember: may veto the write (sensitive scan etc.). Veto is a normal business state, exit 0 --
            {
                let hv = respire::hooks::fire(
                    respire::hooks::HookEvent::PreRemember,
                    respire::hooks::remember_payload(
                        &title,
                        &importance,
                        &r#type,
                        &project,
                        &content,
                    ),
                );
                if hv.blocked {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "event": "pre-remember",
                            "state": "blocked",
                            "reason": hv.reason,
                        }),
                        vec![OutputItem::new(
                            "pre-remember hook",
                            OutputStatus::Pending,
                            "write blocked",
                        )],
                    );
                    result
                        .actions
                        .push("inspect the hook veto before retrying".into());
                    emit_result(result)?;
                    return Ok(());
                }
                for w in &hv.warnings {
                    eprintln!("WARN {w}");
                }
            }
            let session = build_session()?;
            let store = build_local()?;
            let stamp = now_stamp();
            let mut id = Uuid::new_v4().to_string();
            // Auto-fill device tag: explicit --computer first, else hostname/platform - so recall across devices can tell whose paths they are
            let computer = if computer.trim().is_empty() {
                respire::service::device_tag()
            } else {
                computer
            };

            // -- Trivia = diary, two modes (agent.json diary_mode; the AI reads it from the inject source):
            //    concise (default) = one diary-track entry per day, timestamped lines appended;
            //    verbose = one diary entry each (old behavior) --
            let (mut content, mut title) = (content, title);
            if importance == "trivial" {
                if respire::service::diary_mode() != "verbose" {
                    // Track mode: one diary-track entry per day. Look up every same-title track (many sessions/devices may each have created one):
                    // found -> merge all lines into the earliest by time, tombstone the rest (self-heal); none -> create with a deterministic id (same id across devices, sync converges)
                    let now_local = chrono::Local::now();
                    let day = now_local.format("%Y-%m-%d").to_string();
                    let track_title = format!("活动轨迹 {day}");
                    let line = format!("【{}】{}", now_local.format("%H:%M"), content.trim());
                    let all = store.all(false)?;
                    // Track identity is the title only (the dated track title is specific enough):
                    // do not also require importance - a merged/old-peer copy may be normal,
                    // and that filter kicked the track off the day's chain, old lines flowing back (reproduced 2026-09-11)
                    let mut tracks: Vec<&respire::StoredMemory> = all
                        .iter()
                        .filter(|m| !m.deleted && m.local_title == track_title)
                        .collect();
                    tracks.sort_by(|a, b| a.local_created_at.cmp(&b.local_created_at));
                    let track_id = uuid::Uuid::new_v5(
                        &uuid::Uuid::NAMESPACE_URL,
                        format!("activity-track/{}/{}", current_user(), day).as_bytes(),
                    )
                    .to_string();
                    if !tracks.is_empty() {
                        // Primary = earliest created; other entries' lines merge in, then tombstone (self-heal merge)
                        let main = tracks[0];
                        let mut merged = String::new();
                        for (i, t) in tracks.iter().enumerate() {
                            let full = MemoryEngine::open(&session, t)?;
                            for row in full.content.lines() {
                                if row.trim() == format!("【活动轨迹】{day}")
                                    || row.trim().is_empty()
                                {
                                    continue;
                                }
                                merged.push_str(row.trim_end());
                                merged.push('\n');
                            }
                            if i > 0 {
                                MemoryTransport::forget(&store, &t.id).map_err(|e| {
                                    anyhow::anyhow!(
                                        "failed to tombstone merged track ({}): {e}",
                                        t.id
                                    )
                                })?;
                            }
                        }
                        merged.push_str(&line);
                        let e = respire::MemoryEntry {
                            id: main.id.clone(),
                            kind: respire::memory::model::Kind::from_str(&main.local_kind),
                            tags: vec![],
                            title: track_title.clone(),
                            content: merged,
                            user: main.user.clone(),
                            computer: if main.local_computer.is_empty() {
                                respire::service::device_tag()
                            } else {
                                main.local_computer.clone()
                            },
                            device: if main.local_device.is_empty() {
                                respire::service::device_tag()
                            } else {
                                main.local_device.clone()
                            },
                            modified_by: respire::service::device_tag(),
                            project: main.local_project.clone(),
                            created_at: main.local_created_at.clone(),
                            updated_at: stamp.clone(),
                            emotion: 0.0,
                            parent_id: main.local_parent_id.clone(),
                            importance: "trivial".to_owned(),
                        };
                        let stored = MemoryEngine::seal(&session, embedder!(), &e, &e.user)?;
                        store.put(&stored)?;
                        respire::hooks::fire(
                            respire::hooks::HookEvent::PostRemember,
                            respire::hooks::remember_done_payload(&stored.id, &title, "trivial"),
                        );
                        // A sealed StoredMemory contains the encrypted payload and local
                        // storage columns.  It is an internal persistence shape, not a
                        // user-facing remember result.  Keep the public result to the
                        // stable summary/item contract and never expose it in DETAILS.
                        emit_result(ResultEnvelope::new(
                            "remember",
                            OutputStatus::Ok,
                            serde_json::json!({
                                "action": "diary_appended",
                                "id": stored.id,
                                "title": track_title,
                            }),
                            vec![OutputItem::new(
                                "write",
                                OutputStatus::Ok,
                                format!("id={}", stored.id),
                            )],
                        ))?;
                        return Ok(());
                    }
                    // No track for today: create with a deterministic id (same id across devices that day; sync converges), then the generic create path
                    id = track_id;
                    content = format!("【活动轨迹】{day}\n{line}");
                    title = track_title;
                } else {
                    content = respire::taxonomy::diary_content(&content);
                }
            }
            // -- Untitled fallback: first 20 chars of the first body line (tree view must not show a blank title; an explicit --title is untouched) --
            if title.trim().is_empty() {
                title = respire::service::derive_title(&content);
            }

            // -- Judge-then-store (dedup first, then choose): unless --force/--merge-ids/--parent (explicit attach is intent)
            //    run an internal recall of similar candidates; diary trivia skips dedup (daily log is not a duplicate event; it goes on the time chain) --
            if !force && merge_ids.is_none() && parent.is_empty() && importance != "trivial" {
                let candidates_all = scoped_candidates(&store)?;
                let q = MemoryQuery::new(&content).limit(5);
                let candidates =
                    MemoryEngine::remember_candidates(&session, embedder!(), &candidates_all, &q)?;
                let merge_cand = candidates.merge;
                let parent_cand = candidates.parent;

                if !merge_cand.is_empty() {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "state": "candidates",
                            "merge_count": merge_cand.len(),
                            "parent_count": parent_cand.len(),
                            "written": false,
                        }),
                        merge_cand
                            .iter()
                            .take(3)
                            .map(|(score, entry)| {
                                OutputItem::new(
                                    respire::service::short_id(&entry.id),
                                    OutputStatus::Pending,
                                    format!(
                                        "similarity={:.0}% title={}",
                                        score * 100.0,
                                        entry.title
                                    ),
                                )
                                .action("merge or attach")
                            })
                            .collect(),
                    );
                    let ids = merge_cand
                        .iter()
                        .take(3)
                        .map(|(_, e)| e.id.clone())
                        .collect::<Vec<_>>()
                        .join(",");
                    result.actions.push(format!(
                        "rsrs remember \"<combined content>\" --merge-ids \"{ids}\""
                    ));
                    if !parent_cand.is_empty() {
                        result
                            .actions
                            .push("rsrs remember \"<content>\" --parent <candidate id>".into());
                    }
                    result
                        .actions
                        .push("rsrs remember \"<content>\" --force to write as new entry".into());
                    emit_result(result)?;
                    return Ok(());
                }
                if !parent_cand.is_empty() {
                    let mut result = ResultEnvelope::new(
                        "remember",
                        OutputStatus::Pending,
                        serde_json::json!({
                            "state": "parent_candidates",
                            "written": false,
                            "count": parent_cand.len(),
                        }),
                        parent_cand
                            .iter()
                            .take(3)
                            .map(|(score, entry)| {
                                OutputItem::new(
                                    respire::service::short_id(&entry.id),
                                    OutputStatus::Pending,
                                    format!(
                                        "similarity={:.0}% title={}",
                                        score * 100.0,
                                        entry.title
                                    ),
                                )
                                .action("attach with --parent")
                            })
                            .collect(),
                    );
                    result
                        .actions
                        .push("rsrs remember \"<content>\" --parent <candidate id>".into());
                    result
                        .actions
                        .push("rsrs remember \"<content>\" --force to write as new entry".into());
                    emit_result(result)?;
                    return Ok(());
                }
            }

            // -- --merge-ids: merge path - tombstone the listed old memories (children reattach to their cause), store a combined new entry (inherits the first cause chain) --
            if let Some(ids) = merge_ids {
                let to_merge: Vec<String> = ids
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                let mut entry = respire::MemoryEntry {
                    id,
                    kind: Kind::from_str(&r#type),
                    tags: tags
                        .split(',')
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .map(ToOwned::to_owned)
                        .collect(),
                    title,
                    content,
                    user: current_user(),
                    computer,
                    project,
                    created_at: stamp.clone(),
                    updated_at: stamp,
                    emotion,
                    parent_id: String::new(),
                    importance,
                    device: respire::service::device_tag(),
                    modified_by: respire::service::device_tag(),
                };
                let merged_full = respire::service::merge_entries(
                    &session,
                    &store,
                    embedder!(),
                    &mut entry,
                    &to_merge,
                    &parent,
                    true,
                )?;
                let dropped = merged_full.len();
                report_orphans(&store, "merge");
                respire::hooks::fire(
                    respire::hooks::HookEvent::PostRemember,
                    respire::hooks::remember_done_payload(
                        &entry.id,
                        &entry.title,
                        &entry.importance,
                    ),
                );
                // Adoption: a merge adopts the old entries (they were the preferred recall candidates)
                for mid in &merged_full {
                    let _ = store.mark_adopted(mid);
                }
                let hint = note_write_maintenance();
                let mut result = ResultEnvelope::new(
                    "remember",
                    OutputStatus::Ok,
                    serde_json::json!({
                        "action": "merged",
                        "dropped": dropped,
                        "id": entry.id,
                        "parent": entry.parent_id,
                        "maintenance_hint": hint,
                    }),
                    vec![OutputItem::new(
                        "merge",
                        OutputStatus::Ok,
                        format!("dropped={dropped} id={}", entry.id),
                    )],
                );
                if let Some(h) = hint {
                    result.actions.push(h);
                }
                emit_result(result)?;
                schedule_autosync(&session, &store);
                return Ok(());
            }

            // -- Causal attach: --parent is the cause (full id first; unique 8-char prefix also works) --
            // Unresolvable -> warn and actually clear (own cause), so we never warn "stored independently" then print "attached".
            let mut issues: Vec<String> = Vec::new();
            let parent_id = if !parent.is_empty() {
                let all = store.all(true)?;
                match respire::service::resolve_prefix(&all, &parent) {
                    Ok(full) => Some(full),
                    Err(e) => {
                        issues.push(format!(
                            "parent (cause) cannot be resolved ({e}); stored independently"
                        ));
                        None
                    }
                }
            } else {
                None
            };
            let parent_id = parent_id.unwrap_or_default();
            let entry = respire::MemoryEntry {
                id,
                kind: Kind::from_str(&r#type),
                tags: tags
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                title,
                content,
                user: current_user(),
                computer,
                project,
                created_at: stamp.clone(),
                updated_at: stamp,
                emotion,
                parent_id: parent_id.clone(),
                importance: importance.clone(),
                device: respire::service::device_tag(),
                modified_by: respire::service::device_tag(),
            };
            let stored = MemoryEngine::seal(&session, embedder!(), &entry, &entry.user)?;
            store.put(&stored)?;
            // Plugin hook post-remember: observe only, never blocks (failure policy is inside hooks::fire)
            {
                let hv = respire::hooks::fire(
                    respire::hooks::HookEvent::PostRemember,
                    respire::hooks::remember_done_payload(
                        &stored.id,
                        &entry.title,
                        &entry.importance,
                    ),
                );
                issues.extend(hv.warnings.iter().cloned());
            }
            // Adoption: explicit attach (--parent) adopts that cause node; --force with no hang is not adoption
            if !parent_id.is_empty() {
                let _ = store.mark_adopted(&parent_id);
            }
            let hint = note_write_maintenance();
            let status = if issues.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "remember",
                status,
                serde_json::json!({
                    "action": "created",
                    "id": entry.id,
                    "parent": parent_id,
                    "maintenance_hint": hint,
                }),
                vec![OutputItem::new(
                    "write",
                    OutputStatus::Ok,
                    format!("id={}", entry.id),
                )],
            );
            if let Some(h) = hint {
                result.actions.push(h);
            }
            result.errors.extend(issues);
            emit_result(result)?;
            schedule_autosync(&session, &store);
        }
        Command::Import { file } => {
            let report = respire::service::import_json(std::path::Path::new(&file))?;
            let status = if report.orphaned > 0 || report.skipped > 0 {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            let mut result = ResultEnvelope::new(
                "import",
                status,
                serde_json::to_value(&report)?,
                vec![
                    OutputItem::new("written", OutputStatus::Ok, report.imported.to_string()),
                    OutputItem::new(
                        "skipped",
                        if report.skipped > 0 {
                            OutputStatus::Warn
                        } else {
                            OutputStatus::Ok
                        },
                        report.skipped.to_string(),
                    ),
                    OutputItem::new(
                        "parent links",
                        OutputStatus::Ok,
                        report.reattached.to_string(),
                    ),
                ],
            );
            if report.orphaned > 0 {
                result.errors.push(format!(
                    "{} records had a parent not in the backup; imported as roots",
                    report.orphaned
                ));
            }
            emit_result(result)?;
        }
        Command::ShareImport {
            file,
            parent,
            go,
            title,
            force,
        } => {
            return run_share_import(&file, &parent, go, title.as_deref(), force);
        }
        Command::Recall {
            query,
            mode,
            limit,
            r#type,
            project,
            trace,
            titles,
        } => {
            let session = build_session()?;
            let store = build_local()?;
            if trace {
                let preview = candidates_preview(&store)?;
                let primary = candidates_count_primary(&preview);
                let normals = candidates_count_normal(&preview);
                eprintln!(
                    "[trace] {} active candidates | important {} / normal {} / trivia {} | retrieval policy is Core-owned",
                    preview.len(),
                    primary,
                    normals,
                    preview.len() - primary - normals,
                );
                std::env::set_var("ONEMEMORY_DEBUG_SCORE", "1");
            }
            let mut q = MemoryQuery::new(&query).limit(limit);
            if let Some(k) = r#type {
                q = q.of_kind(Kind::from_str(&k));
            }
            if let Some(p) = &project {
                q = q.of_project(p);
            }
            let candidates = scoped_candidates(&store)?;
            // 3. small-to-big: hit body + ancestor bodies (budget is built-in; ONEMEMORY_ANCESTOR_BUDGET=0 turns it off)
            let (ranked, recall_mode, selection_fallback) = match mode {
                Some(mode) => {
                    recall_select::recall_with_mode(&session, embedder!(), &candidates, &q, &mode)?
                }
                None => recall_select::recall(&session, embedder!(), &candidates, &q)?,
            };
            // Query log: each recall writes a candidate record (including empty - negatives are post-training material too).
            // Note: this is the candidate set, not a hit - a hit is the model query-log mark self-grade
            {
                let candidates: Vec<String> = ranked.iter().map(|r| r.entry.id.clone()).collect();
                let scores: Vec<f32> = ranked.iter().map(|r| r.score).collect();
                let _ = store.log_query(
                    &query,
                    project.as_deref().unwrap_or(""),
                    "",
                    &candidates,
                    &scores,
                );
                // Hit-heat writeback: top hits recall_count+1 - source of the heat-axis hit_score (used to be read-only, always 0; this round fills it)
                // Plugin hook post-recall: query and hit summary (post-training / external telemetry)
                {
                    let hits: Vec<(String, f32)> = ranked
                        .iter()
                        .map(|r| (r.entry.id.clone(), r.score))
                        .collect();
                    respire::hooks::fire(
                        respire::hooks::HookEvent::PostRecall,
                        respire::hooks::recall_payload(
                            &query,
                            project.as_deref().unwrap_or(""),
                            &hits,
                        ),
                    );
                }
            }
            if ranked.is_empty() {
                emit_result(ResultEnvelope::new(
                    "recall",
                    OutputStatus::Skip,
                    serde_json::json!({"query":query,"count":0,"recall_mode":recall_mode,
                        "selection_fallback":selection_fallback,"embedding_model":store.retrieval_model()?}),
                    vec![OutputItem::new("results", OutputStatus::Skip, "0")],
                ))?;
                return Ok(());
            }
            let items = ranked
                .iter()
                .map(|r| {
                    OutputItem::new(
                        respire::service::short_id(&r.entry.id),
                        OutputStatus::Ok,
                        format!(
                            "{:.3} {}",
                            r.score,
                            if r.entry.title.is_empty() {
                                "(untitled)"
                            } else {
                                &r.entry.title
                            }
                        ),
                    )
                })
                .collect::<Vec<_>>();
            let mut result = ResultEnvelope::new(
                "recall",
                OutputStatus::Ok,
                serde_json::json!({"query":query,"count":ranked.len(),"limit":limit,"project":project,
                    "recall_mode":recall_mode,"selection_fallback":selection_fallback,"embedding_model":store.retrieval_model()?}),
                items,
            );
            result.details = if titles {
                serde_json::json!(ranked
                    .iter()
                    .map(|r| serde_json::json!({
                        "id":r.entry.id,"title":r.entry.title,"score":r.score
                    }))
                    .collect::<Vec<_>>())
            } else {
                serde_json::json!(ranked
                    .iter()
                    .map(|r| serde_json::json!({
                        "score":r.score,"entry":r.entry,"ancestors":r.ancestors
                    }))
                    .collect::<Vec<_>>())
            };
            emit_result(result)?;
            for r in &ranked {
                // Hit heat: increment as soon as recall returns (heat-axis source, local only, not synced)
                let _ = store.bump_recall_count(&r.entry.id);
            }
        }
        Command::Attach { id, parent } => {
            let session = build_session()?;
            let store = build_local()?;
            // Always resolve_prefix: exact id -> exact catalog title -> 8-char prefix (char-safe)
            let all = store.all(true)?;
            let child = respire::service::resolve_prefix(&all, &id)?;
            let parent_full = respire::service::resolve_prefix(&all, &parent)?;
            if child == parent_full {
                anyhow::bail!("cannot attach to itself");
            }
            // Cycle guard: the new parent's cause chain must not contain the child
            for anc in store.ancestor_chain(&parent_full)? {
                if anc == child {
                    anyhow::bail!("cycle: new parent is a descendant of this entry");
                }
            }
            respire::service::reparent(&session, &store, &child, &parent_full)?;
            // Adoption: explicit attach is adoption (parent and child both count - choosing the hang and the attached entry are recall decisions)
            let _ = store.mark_adopted(&parent_full);
            let _ = store.mark_adopted(&child);
            emit_result(ResultEnvelope::new(
                "attach",
                OutputStatus::Ok,
                serde_json::json!({"child":child,"parent":parent_full}),
                vec![
                    OutputItem::new(
                        "child",
                        OutputStatus::Ok,
                        respire::service::short_id(&child),
                    ),
                    OutputItem::new(
                        "parent",
                        OutputStatus::Ok,
                        respire::service::short_id(&parent_full),
                    ),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Chain { id, depth } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(false)?;
            let full = match respire::service::resolve_prefix(&all, id.as_str()) {
                Ok(v) => v,
                Err(e) => {
                    emit_result(ResultEnvelope::new(
                        "chain",
                        OutputStatus::Fail,
                        serde_json::json!({"id": id, "depth": depth}),
                        vec![OutputItem::new(
                            "entry",
                            OutputStatus::Fail,
                            format!("not found ({e})"),
                        )],
                    ))?;
                    return Ok(());
                }
            };
            let by_id: std::collections::HashMap<String, &respire::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let title_of = |pid: &str| -> String {
                by_id
                    .get(pid)
                    .map(|m| {
                        if m.local_title.is_empty() {
                            short_id(pid)
                        } else {
                            m.local_title.clone()
                        }
                    })
                    .unwrap_or_else(|| short_id(pid))
            };
            // 1. Cause chain: root -> direct parent, full body per layer (no truncate - chain is an explicit "I want the whole picture")
            let anc_ids = store.ancestor_chain(&full).unwrap_or_default();
            let mut ancestors: Vec<respire::MemoryEntry> = Vec::new();
            for pid in &anc_ids {
                if let Some(s) = by_id.get(pid) {
                    if let Ok(e) = MemoryEngine::open(&session, s) {
                        ancestors.push(e);
                    }
                }
            }
            let entry = by_id
                .get(&full)
                .and_then(|s| MemoryEngine::open(&session, s).ok());
            // 2. Effect chain: BFS down `depth` layers
            let mut descendants: Vec<(usize, respire::MemoryEntry)> = Vec::new();
            let mut frontier: Vec<(String, usize)> = vec![(full.clone(), 1)];
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            while let Some((cur, lv)) = frontier.pop() {
                if lv > depth {
                    continue;
                }
                for c in store.children(&cur).unwrap_or_default() {
                    if !seen.insert(c.id.clone()) {
                        continue;
                    }
                    if let Ok(e) = MemoryEngine::open(&session, &c) {
                        let next = e.id.clone();
                        descendants.push((lv, e));
                        frontier.push((next, lv + 1));
                    }
                }
            }
            let anc_json: Vec<serde_json::Value> = ancestors
                .iter()
                .map(|a| serde_json::json!({ "id": a.id, "title": a.title, "content": a.content }))
                .collect();
            let des_json: Vec<serde_json::Value> = descendants
                .iter()
                .map(|(lv, d)| serde_json::json!({ "level": lv, "id": d.id, "title": d.title, "content": d.content }))
                .collect();
            let mut items = Vec::with_capacity(ancestors.len() + descendants.len() + 1);
            for a in &ancestors {
                items.push(OutputItem::new(
                    format!("cause-{}", short_id(&a.id)),
                    OutputStatus::Ok,
                    title_of(&a.id),
                ));
            }
            if let Some(e) = &entry {
                items.push(OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    format!("{} {}", short_id(&e.id), e.title),
                ));
            }
            for (lv, d) in &descendants {
                items.push(OutputItem::new(
                    format!("effect-{lv}-{}", short_id(&d.id)),
                    OutputStatus::Ok,
                    d.title.clone(),
                ));
            }
            let mut result = ResultEnvelope::new(
                "chain",
                OutputStatus::Ok,
                serde_json::json!({"id": full, "depth": depth, "ancestors": ancestors.len(), "descendants": descendants.len()}),
                items,
            );
            result.details =
                serde_json::json!({"entry": entry, "ancestors": anc_json, "descendants": des_json});
            emit_result(result)?;
        }
        Command::Show { id } => {
            let session = build_session()?;
            let store = build_local()?;
            // Full id or first-8 prefix match
            let candidates = store.all(false)?;
            let mut hit: Option<&respire::StoredMemory> = None;
            for s in &candidates {
                if s.id == id
                    || (s.id.len() >= 8
                        && id.len() >= 8
                        && respire::service::short_id(&s.id) == respire::service::short_id(&id))
                {
                    hit = Some(s);
                    break;
                }
            }
            match hit {
                Some(s) => {
                    let e = MemoryEngine::open(&session, s)?;
                    let all_t = store.all(true).unwrap_or_default();
                    let title_of = |pid: &str| -> String {
                        all_t
                            .iter()
                            .find(|m| m.id == pid)
                            .map(|m| {
                                if m.local_title.is_empty() {
                                    short_id(&m.id)
                                } else {
                                    m.local_title.clone()
                                }
                            })
                            .unwrap_or_else(|| pid.chars().take(8).collect())
                    };
                    let ancestors: Vec<serde_json::Value> = store
                        .ancestor_chain(&e.id)
                        .unwrap_or_default()
                        .iter()
                        .map(|pid| serde_json::json!({"id":pid,"title":title_of(pid)}))
                        .collect();
                    let children: Vec<serde_json::Value> = store.children(&e.id).unwrap_or_default().iter().map(|c| serde_json::json!({"id":c.id,"title":if c.local_title.is_empty(){c.id.chars().take(8).collect::<String>()}else{c.local_title.clone()},"summary":c.local_content_head.chars().take(80).collect::<String>()})).collect();
                    let mut result = ResultEnvelope::new(
                        "show",
                        OutputStatus::Ok,
                        serde_json::json!({"id":e.id,"title":e.title}),
                        vec![OutputItem::new("entry", OutputStatus::Ok, short_id(&e.id))],
                    );
                    result.details =
                        serde_json::json!({"entry":e,"ancestors":ancestors,"children":children});
                    emit_result(result)?;
                }
                None => emit_result(ResultEnvelope::new(
                    "show",
                    OutputStatus::Fail,
                    serde_json::json!({"id":id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?,
            }
        }
        Command::List {
            limit,
            since,
            since_resort,
        } => {
            let session = build_session()?;
            let store = build_local()?;
            let mut candidates = scoped_candidates(&store)?;
            let mut filter_summary = serde_json::Value::Null;
            // Time filter (§3.8 tidy intake): --since-resort reads resort_at, --since takes an explicit time;
            // both together take the later (stricter). Old entries with empty created_at are excluded.
            if since_resort || since.is_some() {
                let from = list_since_bound(since.as_deref(), since_resort)?;
                let before = candidates.len();
                candidates.retain(|s| s.local_created_at.as_str() > from.as_str());
                filter_summary =
                    serde_json::json!({"from": from, "before": before, "after": candidates.len()});
            }
            candidates.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            candidates.truncate(limit);
            let out: Vec<respire::MemoryEntry> = candidates
                .iter()
                .filter_map(|s| MemoryEngine::open(&session, s).ok())
                .collect();
            let items = out
                .iter()
                .map(|e| OutputItem::new(short_id(&e.id), OutputStatus::Ok, e.title.clone()))
                .collect();
            let mut result = ResultEnvelope::new(
                "list",
                OutputStatus::Ok,
                serde_json::json!({"count":out.len(),"limit":limit,"filter":filter_summary}),
                items,
            );
            result.details = serde_json::Value::Array(
                out.into_iter()
                    .filter_map(|e| serde_json::to_value(e).ok())
                    .collect(),
            );
            emit_result(result)?;
        }
        Command::Forget { id } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let full = respire::service::resolve_prefix(&all, &id)?;
            let deleted = store.forget(&full)?;
            report_orphans(&store, "forget");
            if deleted {
                // Plugin hook post-forget: observe only
                respire::hooks::fire(
                    respire::hooks::HookEvent::PostForget,
                    respire::hooks::forget_payload(&full),
                );
            }
            let status = if deleted {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            emit_result(ResultEnvelope::new(
                "forget",
                status,
                serde_json::json!({"deleted":deleted,"id":full}),
                vec![OutputItem::new(
                    "entry",
                    status,
                    if deleted { "deleted" } else { "not found" },
                )],
            ))?;
            if deleted {
                schedule_autosync(&session, &store);
            }
        }
        Command::Purge { id } => {
            let session = build_session()?;
            let store = build_local()?;
            // Hard-delete must handle **already-forgotten tombstones** (purge's point is to clear tombstone ciphertext) -
            // resolve_prefix always filter(!deleted), so this path uses a dedicated include-deleted resolver.
            let full = resolve_prefix_incl_deleted(&store, &id)?;
            let purged = store.purge_entry(&full)?;
            report_orphans(&store, "purge");
            let status = if purged {
                OutputStatus::Ok
            } else {
                OutputStatus::Fail
            };
            emit_result(ResultEnvelope::new(
                "purge",
                status,
                serde_json::json!({"purged":purged,"id":full}),
                vec![OutputItem::new(
                    "entry",
                    status,
                    if purged { "purged" } else { "not found" },
                )],
            ))?;
            if purged {
                auto_sync(&session, &store);
            }
        }
        Command::Restore { id } => {
            let app = respire::service::App::open()?;
            let entry = app.restore(&id)?;
            emit_result(ResultEnvelope::new(
                "restore",
                OutputStatus::Ok,
                serde_json::json!({"id":entry.id,"restored":true}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    short_id(&entry.id),
                )],
            ))?;
        }
        Command::Promote { id } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            // Short prefix is ok (counted in chars, CJK/multibyte-safe)
            let full = respire::service::resolve_prefix(&all, &id)?;
            let by_id: std::collections::HashMap<String, &respire::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let Some(me) = by_id.get(&full) else {
                emit_result(ResultEnvelope::new(
                    "promote",
                    OutputStatus::Fail,
                    serde_json::json!({"id": id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?;
                return Ok(());
            };
            if me.deleted || me.local_parent_id.is_empty() {
                emit_result(ResultEnvelope::new(
                    "promote",
                    OutputStatus::Skip,
                    serde_json::json!({"id": full, "reason": "already_root_or_deleted"}),
                    vec![OutputItem::new("entry", OutputStatus::Skip, "no change")],
                ))?;
                return Ok(());
            }
            let parent_id = me.local_parent_id.clone();
            // New cause = the cause's cause (grandparent); none -> promote to root
            let grandparent = by_id
                .get(&parent_id)
                .and_then(|p| {
                    if p.local_parent_id.is_empty() {
                        None
                    } else {
                        Some(p.local_parent_id.clone())
                    }
                })
                .unwrap_or_default();
            respire::service::reparent(&session, &store, &full, &grandparent)?;
            emit_result(ResultEnvelope::new(
                "promote",
                OutputStatus::Ok,
                serde_json::json!({"id": full, "new_parent": grandparent}),
                vec![OutputItem::new("entry", OutputStatus::Ok, short_id(&full))],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Demote { id, parent } => {
            let session = build_session()?;
            let store = build_local()?;
            // Same resolve_prefix as attach (fixed 2026-09-21): --parent used to be exact-equal,
            // so a short prefix/catalog title always said "target cause missing", unlike attach.
            let all = store.all(true)?;
            let id_full = respire::service::resolve_prefix(&all, &id)?;
            let parent_full = respire::service::resolve_prefix(&all, &parent)?;
            if id_full == parent_full {
                anyhow::bail!("cannot demote onto itself");
            }
            // Cycle guard: the new cause (parent) chain must not contain this id
            let chain = store.ancestor_chain(&parent_full)?;
            if chain.iter().any(|p| *p == id_full) {
                anyhow::bail!("target cause is a descendant of this entry; that would cycle");
            }
            respire::service::reparent(&session, &store, &id_full, &parent_full)?;
            // Adoption: a demote-attach is adoption
            let _ = store.mark_adopted(&parent_full);
            let _ = store.mark_adopted(&id_full);
            emit_result(ResultEnvelope::new(
                "demote",
                OutputStatus::Ok,
                serde_json::json!({"id": id_full, "parent": parent_full}),
                vec![
                    OutputItem::new("entry", OutputStatus::Ok, short_id(&id_full)),
                    OutputItem::new("parent", OutputStatus::Ok, short_id(&parent_full)),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::Tree { from, depth, .. } => {
            let from = from.as_str();
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let by_id: std::collections::HashMap<String, &respire::StoredMemory> =
                all.iter().map(|m| (m.id.clone(), m)).collect();
            let children_of = |pid: &str| -> Vec<String> {
                all.iter()
                    .filter(|m| !m.deleted && m.local_parent_id == pid)
                    .map(|m| m.id.clone())
                    .collect()
            };
            let label = |id: &str| -> String {
                by_id
                    .get(id)
                    .map(|m| {
                        if m.local_title.is_empty() {
                            id[..id.len().min(8)].to_owned()
                        } else {
                            m.local_title.clone()
                        }
                    })
                    .unwrap_or_else(|| id[..id.len().min(8)].to_owned())
            };
            fn render(
                store: &LocalStore,
                by_id: &std::collections::HashMap<String, &respire::StoredMemory>,
                children_of: &dyn Fn(&str) -> Vec<String>,
                label: &dyn Fn(&str) -> String,
                node: &str,
                depth: usize,
                prefix: &str,
                out: &mut Vec<String>,
            ) {
                let title = label(node);
                let kids = children_of(node);
                let meta = by_id.get(node).map(|m| m.local_kind.as_str()).unwrap_or("");
                let leaf = kids.is_empty();
                let level = prefix.chars().filter(|c| *c == '|').count();
                out.push(format!(
                    "id={} title={} kind={} level={} leaf={}",
                    node[..node.len().min(8)].to_owned(),
                    title,
                    meta,
                    level,
                    leaf
                ));
                if depth == 0 {
                    return;
                }
                let n = kids.len();
                for (i, kid) in kids.iter().enumerate() {
                    let last = i == n - 1;
                    let branch = if last { "`-- " } else { "|-- " };
                    // M1 (2026-09-20 audit): child-layer prefix must use next_prefix - non-last-child
                    // descendants inherit the vertical bar, else a 3-level tree renders `|-- |-- A1` instead of
                    // `|  |-- A1`. Code used to compute next_prefix then pass prefix, with
                    // `let _ = next_prefix;` silencing the unused warning - that line hid the bug.
                    let next_prefix = format!("{prefix}{}", if last { "   " } else { "|  " });
                    render(
                        store,
                        by_id,
                        children_of,
                        label,
                        kid,
                        depth - 1,
                        &format!("{next_prefix}{branch}"),
                        out,
                    );
                }
            }
            let _ = &session;
            let mut out = Vec::new();
            if from.is_empty() {
                let roots: Vec<String> = by_id
                    .iter()
                    .filter(|(_, m)| !m.deleted && m.local_parent_id.is_empty())
                    .map(|(id, _)| id.clone())
                    .collect();
                if roots.is_empty() {
                    emit_result(ResultEnvelope::new(
                        "tree",
                        OutputStatus::Skip,
                        serde_json::json!({"roots": 0, "depth": depth}),
                        vec![OutputItem::new("tree", OutputStatus::Skip, "no roots")],
                    ))?;
                    return Ok(());
                }
                for r in roots {
                    out.push(format!(
                        "id={} title={} kind=root level=0 leaf={}",
                        r[..r.len().min(8)].to_owned(),
                        label(&r),
                        children_of(&r).is_empty()
                    ));
                    let kids = children_of(&r);
                    let n = kids.len();
                    for (i, kid) in kids.iter().enumerate() {
                        let last = i == n - 1;
                        let branch = if last { "`-- " } else { "|-- " };
                        render(
                            &store,
                            &by_id,
                            &children_of,
                            &label,
                            kid,
                            depth - 1,
                            &branch,
                            &mut out,
                        );
                    }
                }
            } else {
                let full_from = respire::service::resolve_prefix(&all, from)?;
                out.push(format!(
                    "root={} depth={} mode=from",
                    short_id(&full_from),
                    depth
                ));
                render(
                    &store,
                    &by_id,
                    &children_of,
                    &label,
                    &full_from,
                    depth,
                    "",
                    &mut out,
                );
            }
            let items = out
                .iter()
                .enumerate()
                .map(|(i, row)| {
                    OutputItem::new(format!("node-{}", i + 1), OutputStatus::Ok, row.clone())
                })
                .collect();
            let mut result = ResultEnvelope::new(
                "tree",
                OutputStatus::Ok,
                serde_json::json!({"count": out.len(), "depth": depth, "from": from}),
                items,
            );
            result.details = serde_json::json!({"rows": out});
            emit_result(result)?;
        }
        Command::Retitle { id, title } => {
            // M5: omitting --title used to silently blank the title (data damage). Now required.
            let Some(new_title) = title.as_ref().filter(|t| !t.trim().is_empty()) else {
                anyhow::bail!("need --title <new-title> (omitting it would blank the title, so there is no empty default)");
            };
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            // M4: use the shared prefix resolver (used to be exact match; 8-char short id said "not found").
            let full = respire::service::resolve_prefix(&all, id.as_str())?;
            let Some(stored) = all.iter().find(|m| m.id == full && !m.deleted) else {
                emit_result(ResultEnvelope::new(
                    "retitle",
                    OutputStatus::Fail,
                    serde_json::json!({"id": id}),
                    vec![OutputItem::new("entry", OutputStatus::Fail, "not found")],
                ))?;
                return Ok(());
            };
            let mut entry = MemoryEngine::open(&session, stored)?;
            let old = entry.title.clone();
            entry.title = new_title.clone();
            // Bump updated_at (LWW needs a new timestamp so a remote old blob cannot push back)
            entry.updated_at = store.edit_stamp(&stored.id)?;
            entry.modified_by = respire::service::device_tag();
            let user = entry.user.clone();
            let new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
            store.put(&new_stored)?;
            // Adoption: a retitle is adoption
            let _ = store.mark_adopted(&stored.id);
            let mut result = ResultEnvelope::new(
                "retitle",
                OutputStatus::Ok,
                serde_json::json!({"id": entry.id, "old_title": old, "new_title": new_title}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    short_id(&entry.id),
                )],
            );
            result.details = serde_json::json!({"entry": entry});
            emit_result(result)?;
            auto_sync(&session, &store);
        }
        Command::RetitleMany { file } => {
            let session = build_session()?;
            let store = build_local()?;
            let text = std::fs::read_to_string(&file)
                .map_err(|e| anyhow!("failed to read {file}: {e}"))?;
            let items: Vec<serde_json::Value> =
                serde_json::from_str(&text).map_err(|e| anyhow!("failed to parse {file}: {e}"))?;
            let all = store.all(true)?;
            let by_id: std::collections::HashMap<&str, &respire::StoredMemory> =
                all.iter().map(|m| (m.id.as_str(), m)).collect();
            let mut done = 0usize;
            let mut missing = 0usize;
            for it in &items {
                let id = it["id"].as_str().unwrap_or_default();
                let title = it["title"].as_str().unwrap_or_default().to_owned();
                if id.is_empty() {
                    continue;
                }
                let Some(stored) = by_id.get(id).copied().filter(|m| !m.deleted) else {
                    missing += 1;
                    continue;
                };
                let mut entry = MemoryEngine::open(&session, stored)?;
                entry.title = title;
                entry.updated_at = store.edit_stamp(&stored.id)?;
                entry.modified_by = respire::service::device_tag();
                let user = entry.user.clone();
                let new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
                store.put(&new_stored)?;
                done += 1;
            }
            let status = if missing == 0 {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            emit_result(ResultEnvelope::new(
                "retitle-many",
                status,
                serde_json::json!({"updated": done, "missing": missing}),
                vec![
                    OutputItem::new("updated", OutputStatus::Ok, done.to_string()),
                    OutputItem::new(
                        "missing",
                        if missing == 0 {
                            OutputStatus::Ok
                        } else {
                            OutputStatus::Warn
                        },
                        missing.to_string(),
                    ),
                ],
            ))?;
            auto_sync(&session, &store);
        }
        Command::SyncConflicts { id, all, refresh } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            if refresh {
                sync_tracked(&session, &local, &sync_phase(build_remote)?)?;
            }
            let mut after = 0;
            while let Some(next) =
                sync_phase(|| local.classify_conflicts_batch(&session, false, after))?
            {
                after = next;
            }
            let conflicts = sync_phase(|| local.list_conflicts(&session, id.as_deref(), all))?;
            let status = if conflicts.is_empty() {
                OutputStatus::Ok
            } else {
                OutputStatus::Warn
            };
            let mut result = ResultEnvelope::new(
                "sync-conflicts",
                status,
                serde_json::json!({"count": conflicts.len(), "refresh": refresh}),
                vec![OutputItem::new(
                    "conflicts",
                    status,
                    conflicts.len().to_string(),
                )],
            );
            if !conflicts.is_empty() {
                result.actions.push("sync-conflicts --json".into());
            }
            result.details = serde_json::Value::Array(conflicts);
            emit_result(result)?;
        }
        Command::SyncResolve {
            epoch,
            rev,
            head_rev,
            action,
            content,
        } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let remote = sync_phase(build_remote)?;
            sync_tracked(&session, &local, &remote)?;
            sync_phase(|| {
                local.queue_conflict_resolution(
                    &session,
                    &epoch,
                    rev,
                    head_rev,
                    &action.replace('-', "_"),
                    content.as_deref(),
                )
            })?;
            let stats = sync_tracked(&session, &local, &remote)?;
            let processed = sync_phase(|| local.processed_conflict_action(&epoch, rev))?;
            emit_result(ResultEnvelope::new(
                "sync-resolve",
                if processed.is_some() {
                    OutputStatus::Ok
                } else {
                    OutputStatus::Pending
                },
                serde_json::json!({"epoch":epoch,"rev":rev,"processed":processed.is_some(),"action":processed,"pending_conflicts":stats.conflicts}),
                vec![OutputItem::new(
                    "revision",
                    if processed.is_some() {
                        OutputStatus::Ok
                    } else {
                        OutputStatus::Pending
                    },
                    rev.to_string(),
                )],
            ))?;
            if processed.is_none() {
                anyhow::bail!("current version changed or the adopt conflicted; the record is still pending - re-run sync-conflicts");
            }
        }
        Command::SyncHistory { id, remote } => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            if remote {
                let transport = sync_phase(build_remote)?;
                let cap = transport
                    .capabilities()?
                    .ok_or_else(|| anyhow!("server does not support revision history"))?;
                sync_phase(|| local.begin_sync_epoch(&cap.epoch))?;
                let mut after = 0;
                let mut until = None;
                loop {
                    let page = transport.pull_v2(&cap.epoch, after, until, false)?;
                    if page.epoch != cap.epoch
                        || page.cursor < after
                        || (page.has_more && page.cursor == after)
                        || until.is_some_and(|v| v != page.until)
                    {
                        anyhow::bail!("illegal history page");
                    }
                    sync_phase(|| local.cache_history(&page))?;
                    after = page.cursor;
                    until = Some(page.until);
                    if !page.has_more {
                        break;
                    }
                }
            }
            let mut history = sync_phase(|| local.sync_history(id.as_deref()))?;
            for row in &mut history {
                let b: respire::StoredMemory = serde_json::from_value(row["blob"].clone())?;
                match MemoryEngine::open(&session, &b) {
                    Ok(entry) => row["entry"] = serde_json::to_value(entry)?,
                    Err(e) => row["decode_error"] = serde_json::json!(e.to_string()),
                }
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("blob");
                }
            }
            let mut result = ResultEnvelope::new(
                "sync-history",
                OutputStatus::Ok,
                serde_json::json!({"count": history.len(), "remote": remote}),
                vec![OutputItem::new(
                    "versions",
                    OutputStatus::Ok,
                    history.len().to_string(),
                )],
            );
            result.details = serde_json::Value::Array(history);
            if !result.details.as_array().is_some_and(Vec::is_empty) {
                result.actions.push("sync-history --json".into());
            }
            emit_result(result)?;
        }
        Command::SyncRestore { op_id, rev, epoch } => {
            let session = build_session()?;
            let local = build_local()?;
            let id =
                local.restore_sync_version(&session, op_id.as_deref(), rev, epoch.as_deref())?;
            emit_result(ResultEnvelope::new(
                "sync-restore",
                OutputStatus::Pending,
                serde_json::json!({"restored":id,"pending_sync":true}),
                vec![OutputItem::new("restored", OutputStatus::Pending, &id).action("sync")],
            ))?;
            auto_sync(&session, &local);
        }
        Command::SyncReset => {
            build_local()?.reset_sync_snapshot()?;
            let mut result = ResultEnvelope::new(
                "sync-reset",
                OutputStatus::Ok,
                serde_json::json!({"history_kept":true,"pending_outbound_kept":true}),
                vec![
                    OutputItem::new("snapshot", OutputStatus::Ok, "reset"),
                    OutputItem::new("history", OutputStatus::Ok, "kept"),
                    OutputItem::new("pending outbound", OutputStatus::Ok, "kept"),
                ],
            );
            result.actions.push("sync".into());
            emit_result(result)?;
        }
        Command::Sync => {
            let session = sync_phase(build_session)?;
            let local = sync_phase(build_local)?;
            let remote = sync_phase(build_remote)?;
            let mut stats = sync_with_retry(&session, &local, &remote)?;
            let mut purged = 0usize;
            // Auto-purge old tombstones (purge_days from agent.json; 0=immediate, default 30)
            let purge_days = respire::service::read_agent_config()
                .get("purge_days")
                .and_then(|v| v.as_i64())
                .unwrap_or(30);
            if purge_days >= 0 {
                let n = sync_phase(|| local.auto_purge_old(purge_days))?;
                purged = n;
                if n > 0 {
                    // Maintenance creates later operations; never extend the caller's upload boundary.
                    schedule_autosync(&session, &local);
                    stats.pending = sync_phase(|| local.sync_counts())?.0;
                }
            }
            // One hook after all rounds, with the same totals as the final report.
            respire::hooks::fire(
                respire::hooks::HookEvent::PostSync,
                respire::hooks::sync_payload(stats.pulled, stats.pushed),
            );
            // Missing vectors are durable index work, not part of network sync.
            let index_pending = sync_phase(|| local.missing_embedding())?.len();
            let local_blobs = sync_phase(|| local.all(true))?;
            let local_total = local_blobs.len();
            let local_alive = local_blobs.iter().filter(|m| !m.deleted).count();
            let total_matched = local_total == stats.remote_total;
            let converged = total_matched && local_alive == stats.remote_alive;
            let sync_status = if converged && stats.conflicts == 0 && stats.undecodable == 0 {
                OutputStatus::Ok
            } else if stats.conflicts > 0 || stats.undecodable > 0 || !total_matched {
                OutputStatus::Warn
            } else {
                OutputStatus::Ok
            };
            if json_mode() {
                let summary = serde_json::json!({
                    "pulled": stats.pulled, "pushed": stats.pushed,
                    "remote_total": stats.remote_total, "remote_alive": stats.remote_alive,
                    "local_total": local_total, "local_alive": local_alive,
                    "total_matched": total_matched, "converged": converged,
                    "protocol": stats.protocol, "pending": stats.pending,
                    "conflicts": stats.conflicts, "conflict_history": stats.conflict_history,
                    "processed_conflicts": stats.processed_conflicts,
                    "historical_conflicts": stats.historical_conflicts,
                    "resolving_conflicts": stats.resolving_conflicts,
                    "resolution_supported": stats.resolution_supported,
                    "undecodable": stats.undecodable, "index_pending": index_pending,
                    "purged": purged,
                });
                let mut result = ResultEnvelope::new("sync", sync_status, summary, Vec::new());
                if stats.conflicts > 0 {
                    result.actions.push("sync-conflicts".into());
                }
                if index_pending > 0 {
                    result.actions.push("reembed".into());
                }
                emit_result(result)?;
                return Ok(());
            }
            let mut result = ResultEnvelope::new(
                "sync",
                sync_status,
                serde_json::json!({
                    "pulled": stats.pulled, "pushed": stats.pushed,
                    "remote_total": stats.remote_total, "remote_alive": stats.remote_alive,
                    "local_total": local_total, "local_alive": local_alive,
                    "total_matched": total_matched, "converged": converged,
                    "protocol": stats.protocol, "pending": stats.pending,
                    "conflicts": stats.conflicts, "conflict_history": stats.conflict_history,
                    "processed_conflicts": stats.processed_conflicts,
                    "historical_conflicts": stats.historical_conflicts,
                    "resolving_conflicts": stats.resolving_conflicts,
                    "resolution_supported": stats.resolution_supported,
                    "undecodable": stats.undecodable, "index_pending": index_pending,
                    "purged": purged,
                }),
                vec![
                    OutputItem::new(
                        "remote",
                        OutputStatus::Ok,
                        format!(
                            "{} total / {} active",
                            stats.remote_total, stats.remote_alive
                        ),
                    ),
                    OutputItem::new(
                        "local",
                        OutputStatus::Ok,
                        format!("{} total / {} active", local_total, local_alive),
                    ),
                    OutputItem::new(
                        "changes",
                        OutputStatus::Ok,
                        format!("pulled {} / pushed {}", stats.pulled, stats.pushed),
                    ),
                    OutputItem::new(
                        "state",
                        sync_status,
                        if converged {
                            "converged"
                        } else if total_matched {
                            "active-count-diff"
                        } else {
                            "not-converged"
                        },
                    ),
                    OutputItem::new(
                        "pending",
                        if stats.pending > 0
                            || stats.conflicts > 0
                            || stats.undecodable > 0
                            || index_pending > 0
                        {
                            OutputStatus::Warn
                        } else {
                            OutputStatus::Ok
                        },
                        format!(
                            "send {} / conflicts {} / decrypt {} / index {}",
                            stats.pending, stats.conflicts, stats.undecodable, index_pending
                        ),
                    ),
                    OutputItem::new("purged", OutputStatus::Ok, purged.to_string()),
                ],
            );
            if stats.conflicts > 0 {
                result.actions.push("sync-conflicts".into());
            }
            if index_pending > 0 {
                result.actions.push("reembed".into());
            }
            emit_result(result)?;
        }
        Command::Status => {
            if json_mode() {
                // Lightweight status (no session unlock, no embedder) - the client calls this often at start; must be fast
                let app_status = respire::service::status_light()?;
                let si = respire::service::session_info();
                // "local store is readable" = this machine has a key wrap (wrapped_urk) and can unwrap it - unrelated to "logged into the cloud".
                // Old code used has_token: offline local mode has no token, always showed locked, the client kept popping login
                // asking to "join the memory store" (user report 2026-09-16). Rule: a key wrap means the local store is joined;
                // an empty nominal user (offline keygen with no name) still counts as joined.
                let unlocked = si.has_local_keys;
                let mut v = serde_json::json!({
                    "unlocked": unlocked,
                    "offline": !remote_configured() && si.has_local_keys,
                    "data_dir": respire::service::data_dir().to_string_lossy(),
                    "session": si,
                    "server_addr": respire::service::server_addr(),
                    "autosync": respire::service::autosync_enabled(),
                    "remote_configured": remote_configured(),
                });
                v["local_total"] = serde_json::json!(app_status.local_total);
                v["local_alive"] = serde_json::json!(app_status.local_alive);
                v["max_updated_at"] = serde_json::json!(app_status.max_updated_at);
                v["workspace"] = serde_json::json!(respire::service::workspace_mode());
                let live = sync_live();
                v["sync_scheduler"] = rpc::sync_scheduler_status();
                v["sync_live"] = serde_json::json!({
                    "phase": if live.phase.is_empty() { "idle" } else { live.phase.as_str() },
                    "pulled": live.pulled,
                    "pushed": live.pushed,
                    "remote_alive": live.remote_alive,
                    "pending": live.pending,
                    "conflicts": live.conflicts,
                    "error": live.error,
                });
                emit_result(ResultEnvelope::new(
                    "status",
                    OutputStatus::Ok,
                    v,
                    Vec::new(),
                ))?;
                return Ok(());
            }
            let app_status = respire::service::status_light()?;
            let count = app_status.local_alive;
            let user = read_session_json()
                .ok()
                .and_then(|d| d["user"].as_str().map(|s| s.to_owned()))
                .unwrap_or_else(|| "local".to_owned());
            let (mode, server) = match remote_config_from_session_or_env()? {
                Some((addr, _)) => {
                    let mode = if respire::service::autosync_enabled() {
                        "cloud sync (auto)"
                    } else {
                        "cloud sync (manual)"
                    };
                    (mode, Some(addr))
                }
                None => ("local authority store (offline)", None),
            };
            let mut items = vec![
                OutputItem::new("mode", OutputStatus::Ok, mode),
                OutputItem::new("user", OutputStatus::Ok, user),
                OutputItem::new("memories", OutputStatus::Ok, count.to_string()),
                OutputItem::new(
                    "local_total",
                    OutputStatus::Ok,
                    app_status.local_total.to_string(),
                ),
                OutputItem::new(
                    "max_updated_at",
                    OutputStatus::Ok,
                    app_status.max_updated_at.clone().unwrap_or_default(),
                ),
            ];
            if let Some(addr) = server.as_ref() {
                items.insert(2, OutputItem::new("server", OutputStatus::Ok, addr.clone()));
            }
            emit_result(ResultEnvelope::new(
                "status",
                OutputStatus::Ok,
                serde_json::json!({
                    "remote_configured": server.is_some(),
                    "local_alive": count,
                    "local_total": app_status.local_total,
                    "max_updated_at": app_status.max_updated_at,
                }),
                items,
            ))?;
        }
        Command::Reembed => {
            let session = build_session()?;
            let store = build_local()?;
            let model = store.retrieval_model()?;
            let n = store.rebuild_index(&session, embedder!(), &model)?;
            let dims = embedder!().dims();
            emit_result(ResultEnvelope::new(
                "reembed",
                OutputStatus::Ok,
                serde_json::json!({"reembedded":n,"dims":dims}),
                vec![
                    OutputItem::new("reembedded", OutputStatus::Ok, n.to_string()),
                    OutputItem::new("dimensions", OutputStatus::Ok, dims.to_string()),
                ],
            ))?;
        }
        Command::Candidates { content } => {
            let session = build_session()?;
            let store = build_local()?;
            let all = scoped_candidates(&store)?;
            let report = respire::service::candidate_report(&session, embedder!(), &all, &content)?;
            let mut result = ResultEnvelope::new(
                "candidates",
                OutputStatus::Ok,
                serde_json::json!({"merge_count":report.merge.len(),"parent_count":report.parent.len()}),
                vec![
                    OutputItem::new(
                        "merge candidates",
                        OutputStatus::Ok,
                        report.merge.len().to_string(),
                    ),
                    OutputItem::new(
                        "parent candidates",
                        OutputStatus::Ok,
                        report.parent.len().to_string(),
                    ),
                ],
            );
            result.details = serde_json::json!({"merge":report.merge,"parent":report.parent});
            result.actions.push("candidates <content> --json".into());
            emit_result(result)?;
        }
        Command::V => unreachable!("version is printed before run_local work"),
        Command::Mcp => unreachable!("mcp is served before run_local"),
        Command::Passport => {
            return run_passport();
        }
        Command::History { id, limit } => {
            let store = build_local()?;
            let full = match id.as_deref() {
                Some(i) => {
                    let all = store.all(true)?;
                    Some(respire::service::resolve_prefix(&all, i)?)
                }
                None => None,
            };
            let rows = store.entry_audit(full.as_deref(), limit)?;
            if json_mode() {
                let mut result = ResultEnvelope::new(
                    "history",
                    OutputStatus::Ok,
                    serde_json::json!({"count": rows.len()}),
                    Vec::new(),
                );
                result.details = serde_json::Value::Array(rows);
                emit_result(result)?;
                return Ok(());
            }
            let status = if rows.is_empty() {
                OutputStatus::Skip
            } else {
                OutputStatus::Ok
            };
            let items = rows
                .iter()
                .map(|r| {
                    let ts = r["ts"].as_str().unwrap_or("");
                    let action = r["action"].as_str().unwrap_or("");
                    let id = r["entry_id"].as_str().unwrap_or("").get(..8).unwrap_or("");
                    let title = r["title"].as_str().unwrap_or("");
                    OutputItem::new("change", status, format!("{ts} {action} {id} {title}"))
                })
                .collect::<Vec<_>>();
            let mut result = ResultEnvelope::new(
                "history",
                status,
                serde_json::json!({"count": rows.len()}),
                if items.is_empty() {
                    vec![OutputItem::new(
                        "history",
                        OutputStatus::Skip,
                        "no change records",
                    )]
                } else {
                    items
                },
            );
            result.details = serde_json::Value::Array(rows);
            emit_result(result)?;
        }
        Command::Plugin { command } => match command {
            PluginCommand::List => {
                let cfg = respire::hooks::read_config();
                let path = respire::hooks::config_path();
                let mut items = Vec::new();
                for (ev, hooks) in &cfg.hooks {
                    for h in hooks {
                        let policy = if h.on_error.is_empty() {
                            "default"
                        } else {
                            &h.on_error
                        };
                        items.push(OutputItem::new(
                            ev,
                            OutputStatus::Ok,
                            format!("{} timeout={}ms on_error={policy}", h.cmd, h.timeout_ms),
                        ));
                    }
                }
                if items.is_empty() {
                    items.push(OutputItem::new(
                        "hooks",
                        OutputStatus::Skip,
                        format!("none configured; file={}", path.display()),
                    ));
                }
                let mut result = ResultEnvelope::new(
                    "plugin-list",
                    if cfg.hooks.is_empty() {
                        OutputStatus::Skip
                    } else {
                        OutputStatus::Ok
                    },
                    serde_json::json!({
                        "config_path": path.to_string_lossy(),
                        "events": respire::hooks::EVENT_NAMES,
                        "count": cfg.hooks.values().map(Vec::len).sum::<usize>(),
                    }),
                    items,
                );
                result.details = serde_json::to_value(&cfg.hooks)?;
                result
                    .actions
                    .push("plugin test <EVENT> --payload <JSON>".into());
                emit_result(result)?;
            }
            PluginCommand::Test { event, payload } => {
                let ev = respire::hooks::HookEvent::parse(event.as_str()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown event \"{event}\"; available: {}",
                        respire::hooks::EVENT_NAMES.join(" / ")
                    )
                })?;
                let data: serde_json::Value = serde_json::from_str(payload.as_str())
                    .map_err(|e| anyhow::anyhow!("--payload is not JSON: {e}"))?;
                let v = respire::hooks::fire(ev, data);
                let status = if v.blocked {
                    OutputStatus::Warn
                } else {
                    OutputStatus::Ok
                };
                let mut result = ResultEnvelope::new(
                    "plugin-test",
                    status,
                    serde_json::json!({"event": ev.as_str(), "blocked": v.blocked, "warning_count": v.warnings.len()}),
                    vec![OutputItem::new(
                        "event",
                        status,
                        if v.blocked {
                            format!("{} blocked: {}", ev.as_str(), v.reason)
                        } else {
                            format!("{} allowed", ev.as_str())
                        },
                    )],
                );
                result.details = serde_json::json!({"event": ev.as_str(), "blocked": v.blocked, "reason": v.reason, "warnings": v.warnings});
                if v.blocked {
                    result.actions.push("review plugin policy".into());
                }
                emit_result(result)?;
            }
        },
        Command::Update {
            id,
            title,
            content,
            tags,
            kind,
            importance,
        } => {
            if let Some(imp) = importance.as_deref() {
                // Two-tier: normal is retired; update may not set normal either
                if !matches!(imp, "important" | "trivial") {
                    anyhow::bail!(
                        "importance must be important/trivial (normal is retired), got \"{}\"",
                        imp
                    );
                }
            }
            let session = build_session()?;
            let store = build_local()?;
            let all = store.all(true)?;
            let full = respire::service::resolve_prefix(&all, &id)?;
            let stored = all
                .iter()
                .find(|m| m.id == full && !m.deleted)
                .ok_or_else(|| anyhow!("not found #{id}"))?;
            let mut entry = MemoryEngine::open(&session, stored)?;
            if let Some(t) = title {
                entry.title = t;
            }
            if let Some(c) = content {
                entry.content = c;
            }
            if let Some(tg) = tags {
                entry.tags = tg
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
            }
            if let Some(k) = kind {
                entry.kind = Kind::from_str(&k);
            }
            if let Some(imp) = importance {
                let imp = imp.trim().to_lowercase();
                if !matches!(imp.as_str(), "important" | "normal" | "trivial") {
                    anyhow::bail!(
                        "invalid importance: {imp} (choose important / trivial; normal is retired)"
                    );
                }
                entry.importance = imp;
            }
            entry.updated_at = store.edit_stamp(&stored.id)?;
            entry.modified_by = respire::service::device_tag();
            let user = entry.user.clone();
            let new_stored = MemoryEngine::seal(&session, embedder!(), &entry, &user)?;
            store.put(&new_stored)?;
            // Adoption: an update is adoption - if a query in the last 10 minutes hit this entry, record it in query_log
            let _ = store.mark_adopted(&stored.id);
            let hint = note_write_maintenance();
            let mut result = ResultEnvelope::new(
                "update",
                OutputStatus::Ok,
                serde_json::json!({"action":"written", "id": stored.id, "maintenance_hint": hint}),
                vec![OutputItem::new(
                    "entry",
                    OutputStatus::Ok,
                    format!(
                        "{} {}",
                        stored.id.get(..8).unwrap_or(&stored.id),
                        entry.title
                    ),
                )],
            );
            result.details = serde_json::to_value(entry)?;
            emit_result(result)?;
            schedule_autosync(&session, &store);
        }
        // The commands above already returned at the top of this function (no embedder needed); this arm is unreachable - only to exhaust the match.
        Command::Keygen { .. } | Command::Session { .. } | Command::Grant { .. } => {
            unreachable!("already returned at the top of main")
        }
        Command::Defrag { .. }
        | Command::TreeCure { .. }
        | Command::TreeFloat { .. }
        | Command::Split { .. }
        | Command::Inject { .. }
        | Command::TreeDeepen { .. }
        | Command::Config { .. }
        | Command::Export { .. }
        | Command::Backup { .. }
        | Command::Secret { .. }
        | Command::Fivekeys { .. }
        | Command::Register { .. }
        | Command::Login { .. }
        | Command::KeysExport { .. }
        | Command::SuperReset { .. }
        | Command::BookMaterial { .. }
        | Command::PortraitMaterial { .. }
        | Command::Doctor { .. }
        | Command::Audit { .. }
        | Command::UpdateCheck { .. }
        | Command::Model { .. }
        | Command::Share { .. }
        | Command::Diary { .. }
        | Command::Taxonomy { .. }
        | Command::RootCreate { .. }
        | Command::Repack
        | Command::Logout { .. }
        | Command::Account { .. }
        | Command::Space { .. }
        | Command::Resort { .. }
        | Command::AgentConfig { .. }
        | Command::Prompt
        | Command::QueryLog { .. }
        | Command::Bench { .. }
        | Command::Classify { .. }
        | Command::Web { .. } => unreachable!(
            "commands that do not need the embedder already returned at the top of main"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod capture_tests {
    use clap::{CommandFactory, Parser};

    #[test]
    fn help_matches_command_contracts() -> anyhow::Result<()> {
        let mut command = super::Cli::command();
        let split = command
            .find_subcommand_mut("split")
            .ok_or_else(|| anyhow::anyhow!("split command missing"))?
            .render_long_help()
            .to_string();
        assert!(split.contains("Split a mixed node"));
        assert!(!split.contains("Tree hygiene"));
        assert!(!split.contains("--parent"));
        let cure = command
            .find_subcommand_mut("tree-cure")
            .ok_or_else(|| anyhow::anyhow!("tree-cure command missing"))?
            .render_long_help()
            .to_string();
        assert!(cure.contains("Tree hygiene"));
        let plugin = command
            .find_subcommand_mut("plugin")
            .ok_or_else(|| anyhow::anyhow!("plugin command missing"))?
            .render_long_help()
            .to_string();
        assert!(plugin.contains("list shows config"));
        assert!(!plugin.contains("--list"));
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "list"]).is_ok());
        assert!(super::Cli::try_parse_from([
            "rsrs",
            "plugin",
            "test",
            "post-sync",
            "--payload",
            "{}"
        ])
        .is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "--list"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "plugin", "test"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "chain", "entry-id"]).is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "chain", "--from", "entry-id"]).is_err());
        assert!(super::Cli::try_parse_from(["rsrs", "config", "--data-dir", "isolated"]).is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "v"]).is_ok());
        assert!(super::Cli::try_parse_from(["rsrs", "version"]).is_ok());
        let v_help = command
            .find_subcommand_mut("v")
            .ok_or_else(|| anyhow::anyhow!("v command missing"))?
            .render_long_help()
            .to_string();
        assert!(v_help.to_ascii_lowercase().contains("version"));
        Ok(())
    }

    use super::capture_run;

    struct EnvGuard {
        prev: Option<String>,
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            crate::rpc::set_worker_active(false);
            match &self.prev {
                Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value),
                None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
            }
        }
    }

    #[test]
    fn doctor_json_keeps_command_envelope() -> Result<(), String> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let dir = tempfile::tempdir().map_err(|err| err.to_string())?;
        let guard = EnvGuard {
            prev: std::env::var("ONEMEMORY_DATA_DIR").ok(),
        };
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        let prev_bin = std::env::var("ONEMEMORY_BIN_DIR").ok();
        std::env::set_var("ONEMEMORY_BIN_DIR", dir.path().join("bin"));
        respire::service::set_server_addr("https://example.invalid")
            .map_err(|err| err.to_string())?;
        crate::rpc::set_worker_active(true);
        for args in [
            vec!["--json".to_owned(), "doctor".to_owned()],
            vec![
                "--json".to_owned(),
                "doctor".to_owned(),
                "--remote".to_owned(),
            ],
        ] {
            let captured = capture_run(args);
            if captured.envelope.command != "doctor" {
                return Err(format!(
                    "doctor JSON was captured as command {}",
                    captured.envelope.command
                ));
            }
            let total = captured
                .envelope
                .summary
                .get("total")
                .and_then(|value| value.as_u64())
                .ok_or("doctor summary is missing total")?;
            if total == 0 || captured.envelope.items.is_empty() {
                return Err("doctor envelope has no checks".to_owned());
            }
            let want = match captured.envelope.status {
                crate::OutputStatus::Ok | crate::OutputStatus::Skip => 0,
                crate::OutputStatus::Warn | crate::OutputStatus::Pending => 2,
                crate::OutputStatus::Fail => 1,
            };
            if captured.exit != want {
                return Err(format!(
                    "doctor exit {} does not match status {want}",
                    captured.exit
                ));
            }
        }
        drop(guard);
        match prev_bin {
            Some(value) => std::env::set_var("ONEMEMORY_BIN_DIR", value),
            None => std::env::remove_var("ONEMEMORY_BIN_DIR"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod sync_retry_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use anyhow::anyhow;

    use super::run_sync_attempts;

    #[test]
    fn retries_transport_timeout_then_succeeds() -> anyhow::Result<()> {
        let hits = AtomicUsize::new(0);
        let value = run_sync_attempts(|| {
            let n = hits.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                Err(anyhow!("connection timed out"))
            } else {
                Ok(7)
            }
        })?;
        assert_eq!(value, 7);
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[test]
    fn protocol_error_does_not_retry() {
        let hits = AtomicUsize::new(0);
        let err = run_sync_attempts(|| {
            hits.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(anyhow!("server sync epoch changed; local edits kept"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("epoch"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn worker_schedules_autosync_without_waiting_on_the_remote() -> anyhow::Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        let prev_dir = std::env::var("ONEMEMORY_DATA_DIR").ok();
        let prev_off = std::env::var("ONEMEMORY_NO_AUTOSYNC").ok();
        let dir = tempfile::tempdir()?;
        std::env::set_var("ONEMEMORY_DATA_DIR", dir.path());
        std::env::remove_var("ONEMEMORY_NO_AUTOSYNC");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(sock) = conn else { break };
                std::thread::sleep(std::time::Duration::from_secs(60));
                drop(sock);
            }
        });
        std::fs::write(
            dir.path().join("session.json"),
            format!(r#"{{"addr":"http://127.0.0.1:{port}","token":"hang"}}"#),
        )?;
        let store = super::build_local()?;
        let keys = respire::SessionKeys::from_urk([9u8; 32])?;
        crate::rpc::set_worker_active(true);
        let started = std::time::Instant::now();
        super::schedule_autosync(&keys, &store);
        let elapsed = started.elapsed();
        crate::rpc::set_worker_active(false);
        match prev_dir {
            Some(value) => std::env::set_var("ONEMEMORY_DATA_DIR", value),
            None => std::env::remove_var("ONEMEMORY_DATA_DIR"),
        }
        match prev_off {
            Some(value) => std::env::set_var("ONEMEMORY_NO_AUTOSYNC", value),
            None => std::env::remove_var("ONEMEMORY_NO_AUTOSYNC"),
        }
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "autosync blocked the worker for {elapsed:?}"
        );
        Ok(())
    }
}
