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
    authorization_preserves_and_commits_profiles()?;
    Ok(())
}

/// Exercise the shipped client against an isolated authorization server, including
/// failures before commit and the host/runtime account verification after commit.
fn authorization_preserves_and_commits_profiles() -> Result<(), Box<dyn std::error::Error>> {
    use respire_app::memory::{crypto, SessionKeys};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    let home = tempfile::tempdir()?;
    let root = home.path().join(".rsrs");
    let original = root.join("accounts/original");
    std::fs::create_dir_all(&original)?;
    let session_bytes = br#"{"user":"original","addr":"https://previous.invalid"}"#;
    std::fs::write(original.join("session.json"), session_bytes)?;
    let config_bytes = serde_json::to_vec(
        &json!({"data_dir":original,"api_base":"https://previous.invalid","custom":"preserve"}),
    )?;
    std::fs::write(root.join("client.json"), &config_bytes)?;
    let super_password = crypto::generate_secret_key();
    let salt = crypto::random_hex(16);
    let urk = [42_u8; 32];
    let (nonce, wrapped) = crypto::wrap_key(&urk, &crypto::derive_kek_v4(&super_password, &salt)?)?;
    let cloud = Arc::new(Mutex::new(
        json!({"version":4,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce}),
    ));
    let mode = Arc::new(Mutex::new("authorized".to_owned()));
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let server =
        Arc::new(tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?);
    let addr = format!("http://{}", server.server_addr());
    let runtime_port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let running = Arc::new(AtomicBool::new(true));
    let worker_server = server.clone();
    let worker_running = running.clone();
    let worker_cloud = cloud.clone();
    let worker_mode = mode.clone();
    let worker_requests = requests.clone();
    let worker_addr = addr.clone();
    let worker = std::thread::spawn(move || -> Result<(), String> {
        while worker_running.load(Ordering::SeqCst) {
            let Some(mut request) = worker_server
                .recv_timeout(Duration::from_millis(50))
                .map_err(|error| error.to_string())?
            else {
                continue;
            };
            let path = request.url().to_owned();
            worker_requests
                .lock()
                .map_err(|error| error.to_string())?
                .push(path.clone());
            let mode = worker_mode
                .lock()
                .map_err(|error| error.to_string())?
                .clone();
            let mut status = 200;
            let reply = match path.as_str() {
                "/oauth/device/code" => {
                    json!({"device_code":"synthetic-device-code","user_code":"ABCDEF123456","expires_in":60,"interval":1,"verification_uri_complete":format!("{worker_addr}/#/authorize?code=ABCDEF123456")})
                }
                "/oauth/token" if mode != "authorized" => {
                    status = 400;
                    json!({"error":mode})
                }
                "/oauth/token" => {
                    json!({"access_token":"synthetic-grant-token","token_type":"Bearer","user":"authorized","session_id":"fixture"})
                }
                "/login" if mode == "totp" => {
                    json!({"totp_required":true,"ticket":"synthetic-ticket"})
                }
                "/login" => {
                    json!({"token":"synthetic-grant-token","user":"authorized","session_id":"fixture"})
                }
                "/api/self/vault" => {
                    if !request.headers().iter().any(|header| {
                        header.field.equiv("Authorization")
                            && header.value.as_str() == "Bearer synthetic-grant-token"
                    }) {
                        return Err("vault request missing authorization".to_owned());
                    }
                    if request.method() == &tiny_http::Method::Post {
                        let value: Value = serde_json::from_reader(request.as_reader())
                            .map_err(|error| error.to_string())?;
                        *worker_cloud.lock().map_err(|error| error.to_string())? = value;
                        json!({"ok":true})
                    } else {
                        worker_cloud
                            .lock()
                            .map_err(|error| error.to_string())?
                            .clone()
                    }
                }
                _ => return Err(format!("unexpected authorization request: {path}")),
            };
            request
                .respond(
                    tiny_http::Response::from_string(reply.to_string()).with_status_code(status),
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    let execute = |args: &[&str]| -> std::io::Result<Output> {
        Command::new(bin())
            .args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("ONEMEMORY_DATA_DIR", &root)
            .env("ONEMEMORY_RPC_PORT", runtime_port.to_string())
            .env("ONEMEMORY_SUPER", &super_password)
            .env("ONEMEMORY_NO_AUTOSYNC", "1")
            .env("ONEMEMORY_UPDATE_CHECK", "0")
            .env("RESPIRE_CORE_TEST_MODE", "1")
            .env_remove("ONEMEMORY_CLIENT_ONLY")
            .env_remove("ONEMEMORY_NO_AUTOSTART")
            .env_remove("ONEMEMORY_RUNTIME_WORKER")
            .env_remove("ONEMEMORY_RPC_TOKEN")
            .env_remove("ONEMEMORY_LANG")
            .output()
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for reply in [
            "access_denied",
            "expired_token",
            "invalid_grant",
            "unexpected_error",
        ] {
            *mode.lock().map_err(|error| error.to_string())? = reply.to_owned();
            let output = execute(&[
                "login",
                "--oauth",
                "--addr",
                &addr,
                "--dashboard",
                &addr,
                "--no-open",
                "--super",
                &super_password,
            ])?;
            if output.status.success() {
                return Err(format!("OAuth failure {reply} was accepted").into());
            }
            if std::fs::read(root.join("client.json"))? != config_bytes
                || std::fs::read(original.join("session.json"))? != session_bytes
            {
                return Err("rejected authorization changed the original account".into());
            }
        }
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
        for args in [
            vec![
                "login",
                "--oauth",
                "--addr",
                &addr,
                "--dashboard",
                &addr,
                "--no-open",
            ],
            vec![
                "login",
                "--interactive",
                "--addr",
                &addr,
                "--user",
                "authorized",
                "--pass=fixture-password",
                "--super=wrong-super",
            ],
        ] {
            let output = execute(&args)?;
            if output.status.success() {
                return Err("missing or incorrect super password was accepted".into());
            }
            if std::fs::read(root.join("client.json"))? != config_bytes
                || std::fs::read(original.join("session.json"))? != session_bytes
            {
                return Err("failed vault verification changed the original account".into());
            }
        }
        *mode.lock().map_err(|error| error.to_string())? = "totp".to_owned();
        let totp = execute(&[
            "login",
            "--interactive",
            "--addr",
            &addr,
            "--user",
            "authorized",
            "--pass=fixture-password",
            "--super",
            &super_password,
        ])?;
        if totp.status.success() || std::fs::read(root.join("client.json"))? != config_bytes {
            return Err("headless TOTP changed the account before authorization".into());
        }
        *mode.lock().map_err(|error| error.to_string())? = "authorized".to_owned();
        let authorized = execute(&[
            "--json",
            "login",
            "--oauth",
            "--addr",
            &addr,
            "--dashboard",
            &addr,
            "--no-open",
            "--super",
            &super_password,
        ])?;
        if !authorized.status.success() {
            return Err(format!(
                "authorized OAuth login failed: {} {}",
                String::from_utf8_lossy(&authorized.stdout),
                String::from_utf8_lossy(&authorized.stderr)
            )
            .into());
        }
        let envelope: Value = serde_json::from_slice(&authorized.stdout)?;
        if envelope["status"] != "ok" || envelope["summary"]["user"] != "authorized" {
            return Err("OAuth login did not report the verified account".into());
        }
        let selected: Value = serde_json::from_slice(&std::fs::read(root.join("client.json"))?)?;
        let target = std::path::PathBuf::from(
            selected["data_dir"]
                .as_str()
                .ok_or("selected directory missing")?,
        );
        if !target.starts_with(&root)
            || selected["custom"] != "preserve"
            || selected["api_base"] != "https://previous.invalid"
        {
            return Err("login changed unrelated API preferences or escaped the fixture".into());
        }
        let saved: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        if saved["user"] != "authorized"
            || saved.get("super").is_some()
            || saved.get("keyring_account").is_some()
        {
            return Err("headless login persisted an unexpected credential".into());
        }
        let stopped = execute(&["--runtime-internal", "--stop"])?;
        if !stopped.status.success() {
            return Err("could not stop the isolated OAuth runtime".into());
        }

        let legacy_super = "synthetic-legacy-passphrase";
        let salt = crypto::random_hex(16);
        let (nonce, wrapped) =
            crypto::wrap_key(&urk, &crypto::derive_super_kek(legacy_super, &salt)?)?;
        let legacy = json!({"user":"authorized","addr":addr,"vault_version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        *cloud.lock().map_err(|error| error.to_string())? =
            json!({"version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        let migrated = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super",
            &super_password,
        ])?;
        if !migrated.status.success() {
            return Err(format!(
                "explicit vault migration failed: {} {}",
                String::from_utf8_lossy(&migrated.stdout),
                String::from_utf8_lossy(&migrated.stderr)
            )
            .into());
        }
        let current = cloud.lock().map_err(|error| error.to_string())?.clone();
        let keys = SessionKeys::unlock_v4(
            &super_password,
            current["kdf_salt"].as_str().ok_or("salt missing")?,
            current["wrapped_urk"].as_str().ok_or("wrap missing")?,
            current["urk_nonce"].as_str().ok_or("nonce missing")?,
        )?;
        if current["version"] != 4 || keys.urk != urk {
            return Err("migration replaced the existing memory key".into());
        }
        let stopped = execute(&["--runtime-internal", "--stop"])?;
        if !stopped.status.success() {
            return Err("could not stop the isolated migration runtime".into());
        }
        // Reproduce a committed cloud wrap with a locally rolled-back legacy
        // session: retry must prove the same URK, never overwrite the cloud key.
        let legacy_bytes = serde_json::to_vec(&legacy)?;
        std::fs::write(target.join("session.json"), &legacy_bytes)?;
        let wrong = execute(&[
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super=wrong-recovery-code",
        ])?;
        if wrong.status.success() || std::fs::read(target.join("session.json"))? != legacy_bytes {
            return Err("migration resume accepted an incorrect recovery code".into());
        }
        let resumed = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super",
            &super_password,
        ])?;
        if !resumed.status.success() {
            return Err(format!(
                "migration resume failed: {} {}",
                String::from_utf8_lossy(&resumed.stdout),
                String::from_utf8_lossy(&resumed.stderr)
            )
            .into());
        }
        let saved: Value = serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
        if saved["vault_version"] != 4
            || *cloud.lock().map_err(|error| error.to_string())? != current
        {
            return Err(
                "migration resume did not commit locally or republished the cloud vault".into(),
            );
        }
        if std::fs::read(original.join("session.json"))? != session_bytes {
            return Err("migration modified the unrelated original account".into());
        }
        let paths = requests.lock().map_err(|error| error.to_string())?;
        if !paths.iter().any(|path| path == "/oauth/token")
            || !paths.iter().any(|path| path == "/api/self/vault")
        {
            return Err("authorization did not exercise polling and vault verification".into());
        }
        Ok(())
    })();
    let stopped = execute(&["--runtime-internal", "--stop"]);
    running.store(false, Ordering::SeqCst);
    let served = worker
        .join()
        .map_err(|_| "authorization fixture thread panicked")?;
    result?;
    stopped?;
    served.map_err(Into::into)
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
