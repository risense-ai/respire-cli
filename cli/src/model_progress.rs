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
    cancelled: bool,
}

pub struct Operation;

impl Operation {
    pub fn begin(phase: &str) -> Result<Self> {
        let mut slot = CURRENT
            .lock()
            .map_err(|_| anyhow!("model progress lock poisoned"))?;
        anyhow::ensure!(slot.is_none(), "another model operation is running");
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
            cancelled: false,
        });
        TRACKED.set(true);
        Ok(Self)
    }
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
        anyhow::ensure!(!progress.cancelled, "model operation cancelled");
        anyhow::ensure!(
            progress.started.elapsed().as_secs() < 1800,
            "model operation timed out after 30 minutes"
        );
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
        anyhow::ensure!(
            !slot.as_ref().is_some_and(|p| p.cancelled),
            "model operation cancelled"
        );
        anyhow::ensure!(
            !slot
                .as_ref()
                .is_some_and(|p| p.started.elapsed().as_secs() >= 1800),
            "model operation timed out after 30 minutes"
        );
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
