//! Smoke the local runtime without touching the user library.

use std::process::{Command, Output};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

fn isolated_command() -> Command {
    let mut command = Command::new(bin());
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(|name| name.starts_with("RSRS_")
            || name.starts_with("ONEMEMORY_") || name.starts_with("RESPIRE_")) {
            command.env_remove(name);
        }
    }
    command
}

#[test]
fn spaces_coordinate_with_the_owned_runtime() -> Result<(), Box<dyn std::error::Error>> {
    use serde_json::{json, Value};
    let home = tempfile::tempdir()?;
    let library = home.path().join(".rsrs");
    std::fs::create_dir(&library)?;
    let config = library.join("client.json");
    std::fs::write(&config, serde_json::to_vec(&json!({
        "data_dir":library,"api_base":"https://fixture.invalid","custom":"preserve"
    }))?)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let invoke = |args: &[&str], expected: i32| -> Result<Value, Box<dyn std::error::Error>> {
        let output = isolated_command().arg("--json").args(args)
            .env("HOME",home.path()).env("USERPROFILE",home.path())
            .env("RSRS_DATA_DIR",&library).env("RSRS_RPC_PORT",port.to_string())
            .env("RSRS_NO_AUTOSYNC","1").env("RSRS_UPDATE_CHECK","0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env_remove("RSRS_RPC_URL").env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART").env_remove("RSRS_RUNTIME_WORKER")
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let value:Value=serde_json::from_str(stdout.trim())?;
        // Headless systems can join successfully without an available OS keyring.
        let keyring_warning = expected == 0 && args.first() == Some(&"space") && args.get(1) == Some(&"join")
            && output.status.code() == Some(2) && value["status"] == "warn" && value["details"]["keyring"] == false;
        if output.status.code()!=Some(expected) && !keyring_warning {
            return Err(format!("owned space command {args:?} exited {:?}: {stdout} {}",output.status.code(),String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(value)
    };
    let health = |profile: &std::path::Path| -> Result<u64, Box<dyn std::error::Error>> {
        let status:Value=ureq::get(&format!("http://127.0.0.1:{port}/api/health"))
            .timeout(Duration::from_secs(5)).call()?.into_json()?;
        if status["data_dir"].as_str().map(std::path::Path::new)!=Some(profile)
            || status["bin"]!=env!("CARGO_PKG_VERSION") {
            return Err(format!("runtime profile readback failed: {status}").into());
        }
        status["pid"].as_u64().ok_or_else(|| "runtime PID missing".into())
    };
    let result=(|| -> Result<(), Box<dyn std::error::Error>> {
        invoke(&["space","list"],0)?;
        let original_pid=health(&library)?;
        let before=std::fs::read(&config)?;
        for args in [vec!["space","join","BADCODE"],vec!["space","join","--code","BADCODE"]] {
            let rejected=invoke(&args,2)?;
            assert_eq!(rejected["summary"]["reason"],"invalid_input");
            assert_eq!(rejected["details"]["error_type"],"user");
            assert_eq!(health(&library)?,original_pid, "bad invite must not stop the current runtime");
            assert_eq!(std::fs::read(&config)?,before);
        }
        for readonly in [false,true] {
            let server=tiny_http::Server::http("127.0.0.1:0").map_err(|error|error.to_string())?;
            let name=if readonly {"joined-readonly"} else {"joined-writable"};
            let user=format!("join-fixture-{}",uuid::Uuid::new_v4());
            let payload=json!({"space":name,"addr":format!("http://{}",server.server_addr()),"user":user,"token":"synthetic-member-token","super":"synthetic-super","readonly":readonly});
            let code=format!("1mem-invite:{}",serde_json::to_vec(&payload)?.iter().map(|byte|format!("{byte:02x}")).collect::<String>());
            let worker=std::thread::spawn(move || -> Result<(),String> {
                let request=server.recv_timeout(Duration::from_secs(20)).map_err(|error|error.to_string())?.ok_or("join never fetched the vault")?;
                if request.url()!="/api/self/vault" || !request.headers().iter().any(|header|header.field.equiv("Authorization") && header.value.as_str()=="Bearer synthetic-member-token") {
                    return Err("join did not authenticate its vault request".into());
                }
                request.respond(tiny_http::Response::from_string(json!({"version":4,"kdf_salt":"synthetic-salt","wrapped_urk":"synthetic-wrap","urk_nonce":"synthetic-nonce"}).to_string())).map_err(|error|error.to_string())
            });
            let joined=invoke(&["space","join",&code],if readonly {2} else {0});
            let served=worker.join().map_err(|_|"join fixture panicked")?;
            respire_app::keystore::delete_super(&user);
            served.map_err(|error|format!("join server: {error}"))?;
            let joined=joined?;
            assert_eq!(joined["status"],if readonly || joined["details"]["keyring"] == false {"warn"} else {"ok"});
            assert_eq!(joined["details"]["readonly"],readonly);
            assert_eq!(std::fs::read(&config)?,before);
            assert_ne!(health(&library)?,original_pid);
            let target=library.join("accounts").join(name);
            let session:Value=serde_json::from_slice(&std::fs::read(target.join("session.json"))?)?;
            assert_eq!(session["user"],user);
            if readonly {
                let agent:Value=serde_json::from_slice(&std::fs::read(target.join("agent.json"))?)?;
                assert_eq!(agent["readonly_team"],true);
            }
            let pid=health(&library)?;
            invoke(&["space","join","--code",&code],2)?;
            assert_eq!(health(&library)?,pid,"existing target must fail before stopping the runtime");
        }
        let server=tiny_http::Server::http("127.0.0.1:0").map_err(|error|error.to_string())?;
        let payload=json!({"space":"rejected-join","addr":format!("http://{}",server.server_addr()),"user":"fixture-rejected","token":"revoked-token","super":"synthetic-super"});
        let code=format!("1mem-invite:{}",serde_json::to_vec(&payload)?.iter().map(|byte|format!("{byte:02x}")).collect::<String>());
        let worker=std::thread::spawn(move || -> Result<(),String> {
            let request=server.recv_timeout(Duration::from_secs(20)).map_err(|error|error.to_string())?.ok_or("rejected join never fetched the vault")?;
            request.respond(tiny_http::Response::empty(401)).map_err(|error|error.to_string())
        });
        let rejected=invoke(&["space","join",&code],1);
        worker.join().map_err(|_|"rejected join fixture panicked")?.map_err(|error|format!("join server: {error}"))?;
        assert_eq!(rejected?["details"]["error_type"],"runtime");
        assert_eq!(std::fs::read(&config)?,before);
        assert!(!library.join("accounts/rejected-join").exists());
        health(&library)?;
        invoke(&["space","create","probe"],0)?;
        let probe=library.join("accounts/probe");
        assert!(probe.join("space_owner.json").is_file());
        assert_ne!(health(&probe)?,original_pid);
        let before=std::fs::read(&config)?;
        let blocked=invoke(&["space","remove","probe"],2)?;
        assert_eq!(blocked["summary"]["reason"],"invalid_input");
        assert_eq!(std::fs::read(&config)?,before);
        let blocked=invoke(&["space","remove","probe","--yes"],2)?;
        assert_eq!(blocked["details"]["error_type"],"user");
        assert!(probe.is_dir());
        health(&probe)?;
        invoke(&["space","use","main"],0)?;
        health(&library)?;
        let before=std::fs::read(&config)?;
        invoke(&["space","use","missing"],2)?;
        assert_eq!(std::fs::read(&config)?,before);
        health(&library)?;
        invoke(&["space","remove","probe","--yes"],0)?;
        assert!(!probe.exists());
        health(&library)?;
        let preserved:Value=serde_json::from_slice(&std::fs::read(&config)?)?;
        assert_eq!(preserved["api_base"],"https://fixture.invalid");
        assert_eq!(preserved["custom"],"preserve");
        Ok(())
    })();
    let cleanup=invoke(&["--runtime-internal","--stop"],0);
    result?;
    cleanup?;
    assert!(std::net::TcpStream::connect(("127.0.0.1",port)).is_err());
    Ok(())
}

fn run(dir: &std::path::Path, port: u16, args: &[&str]) -> std::io::Result<Output> {
    isolated_command()
        .args(args)
        .env("RSRS_DATA_DIR", dir)
        .env("HOME", dir).env("USERPROFILE", dir)
        .env("RSRS_RPC_PORT", port.to_string())
        .env("RSRS_NO_AUTOSYNC", "1").env("RSRS_UPDATE_CHECK", "0")
        .env("RSRS_CORE_TEST_MODE", "1")
        .env_remove("RSRS_RPC_URL").env_remove("RSRS_CLIENT_ONLY")
        .env_remove("RSRS_NO_AUTOSTART").env_remove("RSRS_RUNTIME_WORKER")
        .env_remove("RSRS_LANG")
        .output()
}

#[test]
fn runtime_serves_status_and_stops() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
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

    let again = run(dir.path(), port, &["--runtime-internal", "--status"])?;
    let text = String::from_utf8(again.stdout)?;
    if !text.contains("runtime=up") {
        return Err(format!(
            "expected a running runtime, got {text} {}",
            String::from_utf8(again.stderr)?
        )
        .into());
    }

    let health_url = format!("http://127.0.0.1:{port}/api/health");
    let before: serde_json::Value = ureq::get(&health_url).call()?.into_json()?;
    let restarted = run(dir.path(), port, &["--json", "restart", "--timeout", "2"])?;
    if !restarted.status.success() {
        return Err(format!("restart failed: {} {}", String::from_utf8_lossy(&restarted.stdout), String::from_utf8_lossy(&restarted.stderr)).into());
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
    let initial_auth_salt = crypto::derive_legacy_auth_salt("authorized")?;
    let current_auth_salt = crypto::derive_auth_salt("authorized")?;
    let authentication_salt = Arc::new(Mutex::new(initial_auth_salt));
    let worker_authentication_salt = authentication_salt.clone();
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
                path if path.starts_with("/auth/salt?user=authorized") => {
                    json!({"salt":worker_authentication_salt.lock().map_err(|error| error.to_string())?.clone()})
                }
                "/api/self/password" => {
                    if !request.headers().iter().any(|header| header.field.equiv("Authorization")
                        && header.value.as_str() == "Bearer synthetic-grant-token") {
                        return Err("password namespace update missing authorization".to_owned());
                    }
                    let value: Value = serde_json::from_reader(request.as_reader()).map_err(|error| error.to_string())?;
                    if value["salt"] != current_auth_salt
                        || value["pass_hash"] != crypto::derive_pass_hash("fixture-password", &current_auth_salt).map_err(|error| error.to_string())? {
                        return Err("migration changed the original login password".to_owned());
                    }
                    *worker_authentication_salt.lock().map_err(|error| error.to_string())? = current_auth_salt.clone();
                    json!({"ok":true})
                }
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
        isolated_command()
            .args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("RSRS_DATA_DIR", &root)
            .env("RSRS_RPC_PORT", runtime_port.to_string())
            .env("RSRS_SUPER", args.windows(2).find(|pair| pair[0] == "--super").map(|pair| pair[1]).unwrap_or(&super_password))
            .env("RSRS_NO_AUTOSYNC", "1")
            .env("RSRS_UPDATE_CHECK", "0")
            .env("RSRS_CORE_TEST_MODE", "1")
            .env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART")
            .env_remove("RSRS_RUNTIME_WORKER")
            .env_remove("RSRS_RPC_TOKEN")
            .env_remove("RSRS_LANG")
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
        let mut legacy = json!({"user":"authorized","addr":addr,"vault_version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        *cloud.lock().map_err(|error| error.to_string())? =
            json!({"version":2,"kdf_salt":salt,"wrapped_urk":wrapped,"urk_nonce":nonce});
        let incomplete = execute(&["migrate", "--vault", "--pass=fixture-password", "--super", legacy_super])?;
        if incomplete.status.success() || std::fs::read(target.join("session.json"))? != serde_json::to_vec(&legacy)? {
            return Err("vault-only operation bypassed full library migration".into());
        }
        // The real public library conversion is covered by migration_readiness_tests.
        // This authorization fixture begins with its verified v2 namespace wrap.
        legacy["crypto_namespace"] = json!(crypto::RSRS_PREFIX);
        legacy["wrapped_urk"] = json!(format!("{}{wrapped}", crypto::RSRS_PREFIX));
        std::fs::write(target.join("session.json"), serde_json::to_vec(&legacy)?)?;
        let migrated = execute(&[
            "--json",
            "migrate",
            "--vault",
            "--pass=fixture-password",
            "--super",
            legacy_super,
            "--new-super",
            legacy_super,
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
        let keys = SessionKeys::unlock_super(
            legacy_super,
            current["kdf_salt"].as_str().ok_or("salt missing")?,
            current["wrapped_urk"].as_str().ok_or("wrap missing")?,
            current["urk_nonce"].as_str().ok_or("nonce missing")?,
        )?;
        if current["version"] != 2 || keys.urk != urk || !current["wrapped_urk"].as_str().is_some_and(|value| value.starts_with(crypto::RSRS_PREFIX)) {
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
            legacy_super,
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
        if saved["vault_version"] != 2
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
    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
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
fn doctor_reports_the_real_wait_before_completion_and_json_stays_quiet() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;
    let dir = tempfile::tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|error| error.to_string())?;
    let addr = format!("http://{}", server.server_addr());
    let worker = std::thread::spawn(move || -> Result<(), String> {
        for _ in 0..2 {
            let request = server.recv_timeout(Duration::from_secs(30)).map_err(|error| error.to_string())?.ok_or("doctor never probed the server")?;
            if request.url() != "/health" { return Err("unexpected doctor request".into()); }
            std::thread::sleep(Duration::from_millis(1500));
            request.respond(tiny_http::Response::from_string("{}")) .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    let command = |json: bool| {
        let mut command = isolated_command();
        command.args(["doctor", "--remote"]);
        if json { command.arg("--json"); }
        command.env("HOME", dir.path()).env("USERPROFILE", dir.path())
            .env("RSRS_DATA_DIR", dir.path()).env("RSRS_RPC_PORT", port.to_string())
            .env("RSRS_ADDR", &addr).env("RSRS_LANG", "en")
            .env("RSRS_TOKEN", "synthetic-probe-token")
            .env("RSRS_NO_AUTOSYNC", "1").env("RSRS_UPDATE_CHECK", "0")
            .env_remove("RSRS_RPC_URL").env_remove("RSRS_CLIENT_ONLY")
            .env_remove("RSRS_NO_AUTOSTART").env_remove("RSRS_RUNTIME_WORKER")
            .stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    };
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut child = command(false).spawn()?;
        let stderr = child.stderr.take().ok_or("human stderr missing")?;
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if sender.send(line).is_err() { break; }
            }
        });
        let mut saw_wait = false;
        let mut phases = Vec::new();
        while let Ok(line) = receiver.recv_timeout(Duration::from_secs(20)) {
            let line = line?;
            phases.push(line.clone());
            assert!(!line.contains('\u{1b}'), "redirected progress must be plain text");
            if line.contains("Checking server connection; waiting for response") {
                assert!(child.try_wait()?.is_none(), "progress arrived only after completion");
                saw_wait = true;
                break;
            }
        }
        let human = child.wait_with_output()?;
        reader.join().map_err(|_| "progress reader panicked")?;
        if !saw_wait {
            return Err(format!("doctor never reported its real server wait; phases={phases:?}; stdout={}", String::from_utf8_lossy(&human.stdout)).into());
        }
        assert!(String::from_utf8(human.stdout)?.contains("STATUS"));
        let json = command(true).output()?;
        let envelope: serde_json::Value = serde_json::from_slice(&json.stdout)?;
        assert_eq!(envelope["command"], "doctor");
        assert!(json.stderr.is_empty(), "JSON emitted human progress: {}", String::from_utf8_lossy(&json.stderr));
        Ok(())
    })();
    let cleanup = run(dir.path(), port, &["--runtime-internal", "--stop"]);
    let served = worker.join().map_err(|_| "doctor server panicked")?;
    result?;
    cleanup?;
    served.map_err(Into::into)
}
