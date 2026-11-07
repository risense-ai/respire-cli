//! CLI lifecycle regressions against an independent Runtime with synthetic data.
//! Supply RSRS_RUNTIME_BIN from a complete official managed installation, with
//! its original runtime.json receipt and verified Runtime dependency bundle.
//! Passing these checks alone is not release artifact or G1 evidence.

use std::process::{Command, Output};
use std::time::Duration;

mod support;

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

fn runtime_command(dir: &std::path::Path, port: u16, args: &[&str]) -> Command {
    let mut command = isolated_command(None);
    command
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
        .env_remove("RSRS_LANG");
    command
}

fn run(dir: &std::path::Path, port: u16, args: &[&str]) -> std::io::Result<Output> {
    runtime_command(dir, port, args).output()
}

struct OwnedRuntimeFixture {
    directory: tempfile::TempDir,
    port: u16,
    managed: bool,
    owners: std::cell::RefCell<Vec<respire::net_rpc::Health>>,
    unverified_launch: std::cell::Cell<bool>,
    cleaned: std::cell::Cell<bool>,
}

impl OwnedRuntimeFixture {
    fn new(managed: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        if managed {
            // Retain the installer's original release proof and complete file set.
            // The product verifies them; the test must not synthesize that proof.
            support::install_runtime_fixture(directory.path())?;
        }
        Ok(Self {
            directory,
            port,
            managed,
            owners: std::cell::RefCell::new(Vec::new()),
            unverified_launch: std::cell::Cell::new(false),
            cleaned: std::cell::Cell::new(false),
        })
    }

    fn path(&self) -> &std::path::Path {
        self.directory.path()
    }

    fn run(&self, args: &[&str]) -> std::io::Result<Output> {
        if !args.contains(&"--client-only")
            && (args.first() == Some(&"status") || args.contains(&"restart"))
        {
            self.unverified_launch.set(true);
            self.cleaned.set(false);
        }
        let mut command = runtime_command(self.path(), self.port, args);
        if self.managed {
            // Exercise managed resolution rather than launching the source fixture.
            command.env_remove("RSRS_RUNTIME_BIN");
        }
        command.output()
    }

    fn remember_owner(&self, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
        let health: respire::net_rpc::Health = serde_json::from_value(value.clone())?;
        let identity = respire::net_rpc::runtime_process_identity(health.pid)?;
        let prefix = if cfg!(windows) {
            "windows-filetime-"
        } else if cfg!(target_os = "linux") {
            "linux-starttime-"
        } else {
            "darwin-lstart-"
        };
        assert_eq!(
            health.process_start_id,
            format!("{prefix}{}", identity.started_at)
        );
        assert_eq!(
            std::fs::canonicalize(&health.image_path)?,
            std::fs::canonicalize(identity.executable)?
        );
        assert_eq!(
            std::fs::canonicalize(&health.installation_root)?,
            self.path().canonicalize()?
        );
        assert_eq!(
            std::fs::canonicalize(&health.data_dir)?,
            self.path().canonicalize()?
        );
        uuid::Uuid::parse_str(&health.instance_id)?;
        let mut owners = self.owners.borrow_mut();
        if !owners
            .iter()
            .any(|owner| owner.instance_id == health.instance_id)
        {
            owners.push(health);
        }
        self.unverified_launch.set(false);
        Ok(())
    }

    fn stop_and_verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        let stopped = self.run(&["--runtime-internal", "--stop"])?;
        if !stopped.status.success() || self.unverified_launch.get() {
            return Err("fixture stop or last launched owner was not verified".into());
        }
        for owner in self.owners.borrow().iter() {
            // A reused live PID conservatively retains the fixture. A closed
            // listener, an identity-read error, or stop exit=0 is not enough.
            respire::net_rpc::wait_until_exited(owner.pid)?;
            let receipt_path = self
                .path()
                .join("runtime")
                .join(format!("stop-{}.json", owner.instance_id));
            let receipt = serde_json::from_slice(&std::fs::read(receipt_path)?)?;
            respire::net_rpc::validate_final_stop_receipt(owner, None, &receipt)?;
        }
        match std::fs::symlink_metadata(self.path().join("runtime/endpoint.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("fixture endpoint removal was not verified".into()),
        }
        self.cleaned.set(true);
        Ok(())
    }
}

impl Drop for OwnedRuntimeFixture {
    fn drop(&mut self) {
        // The CLI verifies the owner before stopping it. Never kill a PID found
        // by port, and keep the fixture if verified cleanup cannot be confirmed.
        if !self.cleaned.get() && self.stop_and_verify().is_err() {
            self.directory.disable_cleanup(true);
            eprintln!(
                "Runtime fixture cleanup was not confirmed; retained {}",
                self.path().display()
            );
        }
    }
}

#[test]
fn runtime_serves_status_and_stops() -> Result<(), Box<dyn std::error::Error>> {
    let dir = OwnedRuntimeFixture::new(true)?;
    let port = dir.port;
    let status = dir.run(&["status", "--json"])?;
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
    dir.remember_owner(&owned_runtime)?;
    let executable = owned_runtime["exe"]
        .as_str()
        .ok_or("Runtime executable missing")?;
    let selection: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("runtime.json"))?)?;
    let selected_version = selection["version"]
        .as_str()
        .ok_or("Runtime selection missing")?;
    let installed = dir
        .path()
        .join("runtime")
        .join(selected_version)
        .join(if cfg!(windows) {
            "rsrs-runtime.exe"
        } else {
            "rsrs-runtime"
        });
    assert_eq!(
        std::path::Path::new(executable).canonicalize()?,
        installed.canonicalize()?,
        "status must use the verified installed Runtime"
    );

    // Static policy and host preview must work alongside the owned Runtime.
    // The preview must preserve an existing user file and must not write it.
    let prompt = dir.run(&["--client-only", "prompt", "--json"])?;
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
    let preview = dir.run(&[
        "--client-only",
        "inject",
        "--id",
        "codex",
        "--preview",
        "--json",
    ])?;
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

    let again = dir.run(&["--runtime-internal", "--status"])?;
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
    let restarted = dir.run(&["--json", "restart", "--timeout", "2"])?;
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
    let rejected = dir.run(&["--client-only", "--json", "restart"])?;
    assert_eq!(rejected.status.code(), Some(1));
    let after: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    dir.remember_owner(&after)?;
    assert_eq!(after["pid"], restarted["summary"]["pid"]);
    assert_ne!(after["instance_id"], before["instance_id"]);
    for field in [
        "exe",
        "image_path",
        "image_sha256",
        "installation_id",
        "installation_root",
        "data_dir",
        "account_id",
    ] {
        assert_eq!(
            after[field], before[field],
            "managed restart changed {field}"
        );
    }
    dir.stop_and_verify()?;
    std::thread::sleep(Duration::from_millis(300));
    let down = dir.run(&["--runtime-internal", "--status"])?;
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
fn unbound_explicit_runtime_restart_preserves_the_existing_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = OwnedRuntimeFixture::new(false)?;
    let data_path = fixture.path().join("owned-data-sentinel.txt");
    let data = b"synthetic owned data must remain untouched\n";
    std::fs::write(&data_path, data)?;
    let status = fixture.run(&["status", "--json"])?;
    assert!(
        status.status.success(),
        "explicit Runtime fixture startup failed"
    );
    let health_url = format!("http://127.0.0.1:{}/api/health", fixture.port);
    let before: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    fixture.remember_owner(&before)?;
    let endpoint_path = fixture.path().join("runtime/endpoint.json");
    let endpoint = std::fs::read(&endpoint_path)?;
    assert!(!fixture.path().join("runtime.json").exists());

    let rejected = fixture.run(&["--json", "restart", "--timeout", "2"])?;
    assert!(
        !rejected.status.success(),
        "unbound restart must be deferred"
    );
    let failure: serde_json::Value = serde_json::from_slice(&rejected.stdout)?;
    assert!(failure["errors"]
        .to_string()
        .contains("legacy_runtime_migration_required"));
    let after: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    fixture.remember_owner(&after)?;
    for field in [
        "pid",
        "installation_id",
        "account_id",
        "instance_id",
        "generation",
        "image_path",
        "image_sha256",
    ] {
        assert_eq!(
            after[field], before[field],
            "deferred restart changed {field}"
        );
    }
    assert_eq!(std::fs::read(endpoint_path)?, endpoint);
    assert_eq!(std::fs::read(data_path)?, data);
    assert!(!fixture.path().join("runtime.json").exists());
    assert!(!fixture
        .path()
        .join("runtime/autostart/registration.json")
        .exists());
    assert!(!fixture
        .path()
        .join("runtime/autostart/maintenance.json")
        .exists());
    let old_status = fixture.run(&["--runtime-internal", "--status"])?;
    assert!(old_status.status.success());
    assert!(String::from_utf8(old_status.stdout)?.contains("runtime=up"));
    fixture.stop_and_verify()?;
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
