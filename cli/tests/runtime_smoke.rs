//! Smoke the local runtime without touching the user library.

use std::process::{Command, Output};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn run(dir: &std::path::Path, args: &[&str]) -> std::io::Result<Output> {
    Command::new(bin())
        .args(args)
        .env("ONEMEMORY_DATA_DIR", dir)
        .env_remove("ONEMEMORY_LANG")
        .output()
}

#[test]
fn runtime_serves_status_and_stops() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let status = run(dir.path(), &["status", "--json"])?;
    let stdout = String::from_utf8(status.stdout)?;
    let stderr = String::from_utf8(status.stderr)?;
    if !status.status.success() {
        return Err(format!("status failed: stdout={stdout} stderr={stderr}").into());
    }
    let value: serde_json::Value = serde_json::from_str(stdout.trim())?;
    if value["command"] != "status" {
        return Err(format!("status envelope command was {}", value["command"]).into());
    }

    let again = run(dir.path(), &["--runtime-internal", "--status"])?;
    let text = String::from_utf8(again.stdout)?;
    if !text.contains("runtime=up") {
        return Err(format!(
            "expected a running runtime, got {text} {}",
            String::from_utf8(again.stderr)?
        )
        .into());
    }

    let stopped = run(dir.path(), &["--runtime-internal", "--stop"])?;
    if !stopped.status.success() {
        return Err(format!("stop failed: {}", String::from_utf8(stopped.stderr)?).into());
    }
    std::thread::sleep(Duration::from_millis(300));
    let down = run(dir.path(), &["--runtime-internal", "--status"])?;
    let down_text = String::from_utf8(down.stdout)?;
    if down.status.code() != Some(2)
        && !down_text.contains("没有在运行")
        && !down_text.contains("not running")
    {
        return Err(format!("runtime still up: {down_text}").into());
    }
    Ok(())
}

#[test]
fn no_command_without_tty_exits_2() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let output = run(dir.path(), &[])?;
    if output.status.code() != Some(2) {
        return Err(format!(
            "exit {:?} stderr {}",
            output.status.code(),
            String::from_utf8(output.stderr)?
        )
        .into());
    }
    Ok(())
}
