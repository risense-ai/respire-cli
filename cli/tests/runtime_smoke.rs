//! CLI lifecycle regressions against an independent Runtime with synthetic data.
//! Supply RSRS_RUNTIME_BIN or stage rsrs-runtime beside the Cargo CLI binary.
//! Passing these checks alone is not release artifact or G1 evidence.

use std::process::{Command, Output};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn runtime_bin() -> std::path::PathBuf {
    std::env::var_os("RSRS_RUNTIME_BIN")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(bin()).with_file_name(if cfg!(windows) {
                "rsrs-runtime.exe"
            } else {
                "rsrs-runtime"
            })
        })
}

fn isolated_command(models: Option<&std::path::Path>) -> Command {
    let mut command = Command::new(bin());
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| {
            name.starts_with("RSRS_")
                || name.starts_with("ONEMEMORY_")
                || name.starts_with("RESPIRE_")
        }) {
            command.env_remove(name);
        }
    }
    command.env("RSRS_RUNTIME_BIN", runtime_bin());
    if let Some(models) = models {
        command.env("RSRS_M3_DIR", models).env("RSRS_ENGINE", "cpu");
    }
    command
}

fn run(dir: &std::path::Path, port: u16, args: &[&str]) -> std::io::Result<Output> {
    isolated_command(None)
        .args(args)
        .env("RSRS_DATA_DIR", dir)
        .env("HOME", dir)
        .env("USERPROFILE", dir)
        .env("RSRS_RPC_PORT", port.to_string())
        .env("RSRS_NO_AUTOSYNC", "1")
        .env("RSRS_UPDATE_CHECK", "0")
        .env("RSRS_CORE_TEST_MODE", "1")
        .env_remove("RSRS_RPC_URL")
        .env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART")
        .env_remove("RSRS_RUNTIME_WORKER")
        .env_remove("RSRS_LANG")
        .output()
}

#[test]
fn runtime_serves_status_and_stops() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let status = run(dir.path(), port, &["status", "--json"])?;
    let stdout = String::from_utf8(status.stdout)?;
    let stderr = String::from_utf8(status.stderr)?;
    if !status.status.success() {
        return Err(format!("status failed: stdout={stdout} stderr={stderr}").into());
    }
    let value: serde_json::Value = serde_json::from_str(stdout.trim())?;
    if value["command"] != "status" {
        return Err(format!("status envelope command was {}", value["command"]).into());
    }

    let health_url = format!("http://127.0.0.1:{port}/api/health");
    let owned_runtime: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    let executable = owned_runtime["exe"]
        .as_str()
        .ok_or("Runtime executable missing")?;
    assert_eq!(
        std::path::Path::new(executable).canonicalize()?,
        runtime_bin().canonicalize()?,
        "status must use the independent Runtime"
    );

    // Static policy and host preview must work alongside the owned Runtime.
    // The preview must preserve an existing user file and must not write it.
    let prompt = run(dir.path(), port, &["--client-only", "prompt", "--json"])?;
    assert!(
        prompt.status.success(),
        "{}",
        String::from_utf8_lossy(&prompt.stdout)
    );
    let prompt: serde_json::Value = serde_json::from_slice(&prompt.stdout)?;
    assert_eq!(
        prompt["summary"]["instructions"],
        respire::inject::INSTRUCTIONS_MD
    );
    let codex = dir.path().join(".codex/AGENTS.md");
    std::fs::create_dir_all(codex.parent().ok_or("Codex instructions parent missing")?)?;
    let owned = "Synthetic owned Codex instructions\n";
    std::fs::write(&codex, owned)?;
    let preview = run(
        dir.path(),
        port,
        &[
            "--client-only",
            "inject",
            "--id",
            "codex",
            "--preview",
            "--json",
        ],
    )?;
    assert!(
        preview.status.success(),
        "{}",
        String::from_utf8_lossy(&preview.stdout)
    );
    let preview: serde_json::Value = serde_json::from_slice(&preview.stdout)?;
    let preview_text = preview.to_string();
    assert!(preview_text.contains("Synthetic owned Codex instructions"));
    assert!(preview_text.contains("--depth 3"));
    assert!(!preview_text.contains("--depth 1-3"));
    assert_eq!(std::fs::read_to_string(&codex)?, owned);

    let again = run(dir.path(), port, &["--runtime-internal", "--status"])?;
    let text = String::from_utf8(again.stdout)?;
    if !text.contains("runtime=up") {
        return Err(format!(
            "expected a running runtime, got {text} {}",
            String::from_utf8(again.stderr)?
        )
        .into());
    }

    let before: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    assert_eq!(
        before["pid"], owned_runtime["pid"],
        "static policy and preview must not replace the owned Runtime"
    );
    let restarted = run(dir.path(), port, &["--json", "restart", "--timeout", "2"])?;
    if !restarted.status.success() {
        return Err(format!(
            "restart failed: {} {}",
            String::from_utf8_lossy(&restarted.stdout),
            String::from_utf8_lossy(&restarted.stderr)
        )
        .into());
    }
    let restarted: serde_json::Value = serde_json::from_slice(&restarted.stdout)?;
    assert_eq!(restarted["command"], "restart");
    assert_eq!(restarted["summary"]["forced"], false);
    assert_eq!(restarted["summary"]["stopped_pid"], before["pid"]);
    assert_ne!(restarted["summary"]["pid"], before["pid"]);
    assert_eq!(restarted["summary"]["data_dir"], before["data_dir"]);
    let rejected = run(dir.path(), port, &["--client-only", "--json", "restart"])?;
    assert_eq!(rejected.status.code(), Some(1));
    let after: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    assert_eq!(after["pid"], restarted["summary"]["pid"]);
    let stopped = run(dir.path(), port, &["--runtime-internal", "--stop"])?;
    if !stopped.status.success() {
        return Err(format!("stop failed: {}", String::from_utf8(stopped.stderr)?).into());
    }
    std::thread::sleep(Duration::from_millis(300));
    let down = run(dir.path(), port, &["--runtime-internal", "--status"])?;
    let down_text = String::from_utf8(down.stdout)?;
    if down.status.code() != Some(2)
        && !down_text.contains("\u{6ca1}\u{6709}\u{5728}\u{8fd0}\u{884c}")
        && !down_text.contains("not running")
    {
        return Err(format!("runtime still up: {down_text}").into());
    }
    Ok(())
}

#[test]
fn no_command_without_tty_exits_2() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let output = run(dir.path(), port, &[])?;
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

#[test]
fn doctor_reports_the_real_wait_before_completion_and_json_stays_quiet(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let dir = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let addr = format!("http://{}", server.server_addr());
    let worker = std::thread::spawn(move || -> Result<(), String> {
        for _ in 0..2 {
            // The json run waits for the runtime the human run autostarted; a
            // coverage-instrumented binary can need well over 30s to be ready.
            let request = server
                .recv_timeout(Duration::from_secs(120))
                .map_err(|error| error.to_string())?
                .ok_or("doctor never probed the server")?;
            if request.url() != "/health" {
                return Err("unexpected doctor request".into());
            }
            std::thread::sleep(Duration::from_millis(1500));
            request
                .respond(tiny_http::Response::from_string("{}"))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    let command = |json: bool| {
        let mut command = isolated_command(None);
        command.args(["doctor", "--remote"]);
        if json {
            command.arg("--json");
        }
        command
            .env("HOME", dir.path())
            .env("USERPROFILE", dir.path())
            .env("RSRS_DATA_DIR", dir.path())
            .env("RSRS_RPC_PORT", port.to_string())
            .env("RSRS_ADDR", &addr)
            .env("RSRS_LANG", "en")
            .env("RSRS_TOKEN", "synthetic-probe-token")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env_remove("RSRS_RPC_URL")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART")
            .env_remove("RSRS_RUNTIME_WORKER")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut child = command(false).spawn()?;
        let stderr = child.stderr.take().ok_or("human stderr missing")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut saw_wait = false;
        let mut phases = Vec::new();
        while let Ok(line) = receiver.recv_timeout(Duration::from_secs(60)) {
            let line = line?;
            phases.push(line.clone());
            assert!(
                !line.contains('\u{1b}'),
                "redirected progress must be plain text"
            );
            if line.contains("Checking server connection; waiting for response") {
                assert!(
                    child.try_wait()?.is_none(),
                    "progress arrived only after completion"
                );
                saw_wait = true;
                break;
            }
        }
        let human = child.wait_with_output()?;
        reader.join().map_err(|_| "progress reader panicked")?;
        if !saw_wait {
            return Err(format!(
                "doctor never reported its real server wait; phases={phases:?}; stdout={}",
                String::from_utf8_lossy(&human.stdout)
            )
            .into());
        }
        assert!(String::from_utf8(human.stdout)?.contains("STATUS"));
        let json = command(true).output()?;
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout)?;
        assert_eq!(envelope["command"], "doctor");
        assert!(
            json.stderr.is_empty(),
            "JSON emitted human progress: {}",
            String::from_utf8_lossy(&json.stderr)
        );
        Ok(())
    })();
    let cleanup = run(dir.path(), port, &["--runtime-internal", "--stop"]);
    let served = worker.join().map_err(|_| "doctor server panicked")?;
    result?;
    cleanup?;
    served.map_err(Into::into)
}
