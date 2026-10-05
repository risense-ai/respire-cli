//! Runtime-owned model work, polled independently of the command worker queue.
use std::cell::{Cell, RefCell};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

thread_local! { static TRACKED: Cell<bool> = const { Cell::new(false) }; }
thread_local! { static TASK_ID: RefCell<Option<String>> = const { RefCell::new(None) }; }
static CURRENT: Mutex<Option<Progress>> = Mutex::new(None);

pub struct TaskScope(Option<String>);
impl TaskScope {
    pub fn new(id: Option<String>) -> Self {
        Self(TASK_ID.replace(id))
    }
}
impl Drop for TaskScope {
    fn drop(&mut self) {
        TASK_ID.replace(self.0.take());
    }
}

struct Progress {
    id: String,
    phase: String,
    item: String,
    done: u64,
    total: Option<u64>,
    started: Instant,
    updated: Instant,
    idle_timeout: bool,
    cancelled: bool,
}

pub struct Operation;

#[derive(Debug)]
pub enum OperationStopped {
    Cancelled,
    TimedOut,
    IdleTimedOut,
}

impl std::fmt::Display for OperationStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "model operation cancelled",
            Self::TimedOut => "model operation timed out after 30 minutes",
            Self::IdleTimedOut => "background indexing made no progress for 30 minutes",
        })
    }
}

impl std::error::Error for OperationStopped {}

fn check_progress(progress: &Progress) -> Result<()> {
    if progress.cancelled {
        return Err(OperationStopped::Cancelled.into());
    }
    if progress.idle_timeout {
        if progress.updated.elapsed().as_secs() >= 1800 {
            return Err(OperationStopped::IdleTimedOut.into());
        }
    } else if progress.started.elapsed().as_secs() >= 1800 {
        return Err(OperationStopped::TimedOut.into());
    }
    Ok(())
}

impl Operation {
    pub fn begin(phase: &str) -> Result<Self> {
        Self::try_begin(phase)?.ok_or_else(|| anyhow!("another model operation is running"))
    }

    /// Reserve the model slot without waiting, with the foreground total budget.
    pub fn try_begin(phase: &str) -> Result<Option<Self>> {
        Self::try_begin_with_idle_timeout(phase, false)
    }

    /// Large libraries may take hours; only a lack of progress pauses indexing.
    pub fn try_begin_background_index() -> Result<Option<Self>> {
        Self::try_begin_with_idle_timeout("index-load", true)
    }

    fn try_begin_with_idle_timeout(phase: &str, idle_timeout: bool) -> Result<Option<Self>> {
        let mut slot = CURRENT
            .lock()
            .map_err(|_| anyhow!("model progress lock poisoned"))?;
        if slot.is_some() {
            return Ok(None);
        }
        *slot = Some(Progress {
            id: TASK_ID
                .with_borrow(|id| id.clone())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            phase: phase.to_owned(),
            item: String::new(),
            done: 0,
            total: None,
            started: Instant::now(),
            updated: Instant::now(),
            idle_timeout,
            cancelled: false,
        });
        TRACKED.set(true);
        Ok(Some(Self))
    }
}

pub fn status() -> Result<Value> {
    let slot = CURRENT.lock().map_err(|_| anyhow!("model progress lock poisoned"))?;
    Ok(match slot.as_ref() {
        Some(progress) => json!({
            "active": true, "id": progress.id, "phase": progress.phase,
            "item": progress.item, "done": progress.done, "total": progress.total,
            "elapsed": progress.started.elapsed().as_secs(),
            "idle": progress.updated.elapsed().as_secs(), "cancelled": progress.cancelled,
        }),
        None => json!({"active": false}),
    })
}

impl Drop for Operation {
    fn drop(&mut self) {
        TRACKED.set(false);
        if let Ok(mut slot) = CURRENT.lock() {
            *slot = None;
        }
    }
}

pub fn update(phase: &str, item: &str, done: u64, total: Option<u64>) -> Result<()> {
    if !TRACKED.get() {
        return Ok(());
    }
    let mut slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    if let Some(progress) = slot.as_mut() {
        check_progress(progress)?;
        if progress.phase != phase || progress.item != item || progress.done != done {
            progress.updated = Instant::now();
        }
        progress.phase = phase.to_owned();
        progress.item = item.to_owned();
        progress.done = done;
        progress.total = total;
    }
    Ok(())
}

pub fn check() -> Result<()> {
    if TRACKED.get() {
        let slot = CURRENT
            .lock()
            .map_err(|_| anyhow!("model progress lock poisoned"))?;
        if let Some(progress) = slot.as_ref() {
            check_progress(progress)?;
        }
    }
    Ok(())
}

pub fn control(task_id: &str, cancel: bool) -> Result<Value> {
    let mut slot = CURRENT
        .lock()
        .map_err(|_| anyhow!("model progress lock poisoned"))?;
    let Some(p) = slot.as_mut() else {
        return Ok(json!({"active":false}));
    };
    if p.id != task_id {
        return Ok(json!({"active":false}));
    }
    if cancel {
        p.cancelled = true;
    }
    Ok(json!({
        "active": true,
        "id": p.id,
        "phase": p.phase,
        "item": p.item,
        "done": p.done,
        "total": p.total,
        "elapsed": p.started.elapsed().as_secs(),
        "idle": p.updated.elapsed().as_secs(),
        "cancelled": p.cancelled,
    }))
}
