//! Foreground supervisor started by the sign-in registration. It owns and
//! restarts the separate `rsrs-runtime` child process; the runtime binary
//! itself never registers, restarts or updates anything.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::{lifecycle, read_registration, Registration};

#[path = "launch_authorization.rs"]
mod launch_authorization;
pub(crate) use launch_authorization::control::{
    auth_keygen_locked, auth_result_locked, AuthOutcomeUnknown,
};

/// Delay between a failed child attempt and the next start.
const RESTART_DELAY: Duration = Duration::from_secs(60);
/// Child uptime after which the consecutive-failure counter resets.
const STABLE_UPTIME_RESET: Duration = Duration::from_secs(120);
/// Consecutive short-lived failures that trip the circuit breaker.
const MAX_CONSECUTIVE_FAILURES: u8 = 3;

/// Registration entry point (`rsrs runtime supervise --data-dir <root>`).
/// Resolves the managed runtime, spawns `rsrs-runtime serve --supervised` and
/// keeps it alive with a bounded retry budget.
pub(crate) fn supervise(data_dir: &Path) -> Result<()> {
    let root = data_dir
        .canonicalize()
        .with_context(|| format!("invalid --data-dir {}", data_dir.display()))?;
    let config = read_registration(&root)?
        .context("no startup registration for this installation; enable runtime autostart first")?;
    lifecycle::owned(&config)?;
    let registered_root = PathBuf::from(
        config
            .environment
            .get("RSRS_DATA_DIR")
            .context("registered runtime root is missing")?,
    );
    anyhow::ensure!(
        registered_root.canonicalize()? == root,
        "registered runtime root belongs to another installation"
    );
    // Align this process with the registration environment before resolving
    // the runtime, exactly like the managed foreground run does.
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| {
            key.starts_with("RSRS_") || key.starts_with("ONEMEMORY_") || key.starts_with("RESPIRE_")
        }) {
            std::env::remove_var(key);
        }
    }
    for (key, value) in &config.environment {
        std::env::set_var(key, value);
    }
    // The registered task is the foreground owner. A kill-on-close job keeps a
    // dead supervisor from orphaning the runtime child (Windows 8+ nested jobs
    // preserve the enclosing Task Scheduler job).
    #[cfg(windows)]
    respire_spawn::confine_supervisor_tree()
        .context("cannot establish owned supervisor process tree")?;
    // Unix delivery forwards the signal to the child and exits without
    // counting the shutdown against the retry budget.
    #[cfg(unix)]
    let stopped = {
        let stopped = Arc::new(AtomicBool::new(false));
        signal_hook::flag::register(signal_hook::consts::SIGTERM, stopped.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, stopped.clone())?;
        stopped
    };
    #[cfg(not(unix))]
    let stopped = Arc::new(AtomicBool::new(false));
    let mut failures: u8 = 0;
    loop {
        if !supervise_may_run(&root, &config)? {
            return Ok(());
        }
        let started = Instant::now();
        let binary = match resolve_child_plan() {
            Ok(binary) => binary,
            Err(error) => {
                eprintln!("runtime resolution failed: {error:#}");
                if error.is::<crate::runtime_fetch::ManagedRuntimeRepairRequired>() {
                    lifecycle::record_supervise_event(&config, "exit_error");
                    return Err(error);
                }
                if !failure_backoff(&config, &root, &mut failures, Duration::ZERO)? {
                    return Err(error);
                }
                continue;
            }
        };
        lifecycle::record_supervise_event(&config, "starting");
        let arguments: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("serve"),
            std::ffi::OsString::from("--data-dir"),
            registered_root.clone().into_os_string(),
            std::ffi::OsString::from("--supervised"),
        ];
        let outcome = spawn_authorized_runtime(&binary, &arguments, Some(&config.id))
            .map(|(mut child, _instance_id)| wait_child(&mut child, &stopped));
        let uptime = started.elapsed();
        match outcome {
            // Signalled shutdown: the supervisor exits without retrying.
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(status))) if status.success() => {
                lifecycle::record_supervise_event(&config, "exit_ok");
                return Ok(());
            }
            Ok(Ok(Some(_))) => {
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Ok(Err(error)) => {
                eprintln!("runtime child supervision failed: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
            Err(error) => {
                eprintln!("runtime child could not be started: {error:#}");
                if !failure_backoff(&config, &root, &mut failures, uptime)? {
                    return Ok(());
                }
            }
        }
    }
}

/// Both detached and supervised children use the same single-use startup grant.
pub(crate) fn spawn_authorized_runtime(
    binary: &Path,
    arguments: &[std::ffi::OsString],
    managed_id: Option<&str>,
) -> Result<(std::process::Child, String)> {
    launch_authorization::spawn(binary, arguments, managed_id)
}

pub(crate) fn control_memory_revision() -> Result<respire_commands::output::ResultEnvelope> {
    launch_authorization::control_memory_revision()
}

/// Wait for the child, honoring a signal flag. `Ok(None)` means the supervisor
/// was signalled and the child has been stopped.
fn wait_child(
    child: &mut std::process::Child,
    stopped: &AtomicBool,
) -> Result<Option<std::process::ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if stopped.load(Ordering::Acquire) {
            let _ = child.kill();
            child
                .wait()
                .context("cannot reap the stopped runtime child")?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The supervisor only starts independent Runtime images. Legacy compatibility
/// remains available through the explicit CLI foreground entry.
fn resolve_child_plan() -> Result<PathBuf> {
    let binary = crate::rpc::resolve_runtime_executable()?;
    anyhow::ensure!(
        !crate::rpc::explicit_cli_runtime(&binary)?,
        "supervision requires the independent Runtime; use --runtime-internal explicitly for legacy CLI compatibility"
    );
    Ok(binary)
}

/// Record the failure, keep the restart budget bounded and sleep out the retry
/// delay while still honoring disablement. `Ok(false)` stops the supervisor.
fn failure_backoff(
    config: &Registration,
    root: &Path,
    failures: &mut u8,
    uptime: Duration,
) -> Result<bool> {
    lifecycle::record_supervise_event(config, "exit_error");
    if !supervise_may_run(root, config)? {
        return Ok(false);
    }
    if !supervise_retry(failures, uptime) {
        lifecycle::record_supervise_event(config, "crash_limit");
        return Ok(false);
    }
    let deadline = Instant::now() + RESTART_DELAY;
    while Instant::now() < deadline {
        if !supervise_may_run(root, config)? {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(true)
}

/// Continue only while the registration still exists unchanged, enabled and
/// not manually stopped. Identity changes fail loudly instead of silently
/// abandoning a runtime we no longer own.
fn supervise_may_run(root: &Path, expected: &Registration) -> Result<bool> {
    let Some(current) = read_registration(root)? else {
        return Ok(false);
    };
    anyhow::ensure!(
        current.id == expected.id
            && current.owner == expected.owner
            && current.executable == expected.executable,
        "supervised registration identity changed"
    );
    Ok(current.enabled && !current.manually_stopped)
}

/// Bounded retry budget: three consecutive short-lived failures trip the
/// circuit breaker; stable uptime resets the counter.
fn supervise_retry(failures: &mut u8, uptime: Duration) -> bool {
    if uptime >= STABLE_UPTIME_RESET {
        *failures = 0;
    }
    *failures = failures.saturating_add(1);
    *failures < MAX_CONSECUTIVE_FAILURES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_never_turns_resolution_failure_into_a_shim() -> Result<()> {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("RSRS_RUNTIME_BIN", value),
                    None => std::env::remove_var("RSRS_RUNTIME_BIN"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("RSRS_RUNTIME_BIN"));
        let directory = tempfile::tempdir()?;
        std::env::set_var("RSRS_RUNTIME_BIN", directory.path().join("missing-runtime"));
        anyhow::ensure!(resolve_child_plan().is_err());

        // A file override is a selection fixture only; this test executes no binary.
        let binary = directory.path().join("synthetic-runtime");
        std::fs::write(&binary, b"synthetic runtime selection")?;
        std::env::set_var("RSRS_RUNTIME_BIN", &binary);
        anyhow::ensure!(resolve_child_plan()? == binary);
        std::env::set_var("RSRS_RUNTIME_BIN", std::env::current_exe()?);
        anyhow::ensure!(resolve_child_plan().is_err());
        Ok(())
    }

    #[test]
    fn supervisor_retries_are_bounded_and_reset_only_after_stability() {
        let mut failures = 0;
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(!supervise_retry(&mut failures, Duration::from_secs(1)));
        assert!(supervise_retry(&mut failures, Duration::from_secs(120)));
        assert_eq!(failures, 1);
    }
}
