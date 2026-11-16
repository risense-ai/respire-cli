//! One-shot host RPC survives the memory Runtime's profile transition.
//! Credentials arrive only on stdin; normal Runtime RPC retains its host gates.
use anyhow::{bail, ensure, Context, Result};
use respire_commands::output_state::HOST_RPC_OUTPUT;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};

thread_local! {static TOTP:std::cell::RefCell<Option<String>>=const {std::cell::RefCell::new(None)};}
thread_local! {static LOGIN_INPUT:std::cell::RefCell<Option<respire_protocol::host_control::HostAuthLoginContinuation>>=const {std::cell::RefCell::new(None)};}
pub(crate) fn initial_login_input(
    default: respire_protocol::host_control::HostAuthLoginContinuation,
) -> respire_protocol::host_control::HostAuthLoginContinuation {
    LOGIN_INPUT.with(|slot| match slot.borrow_mut().take() {
        Some(mut input) => {
            if input.legacy_password.is_none() {
                input.legacy_password = default.legacy_password;
            }
            input
        }
        None => default,
    })
}
pub(crate) fn totp_code() -> Option<String> {
    TOTP.with(|value| value.borrow().clone())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    v: u8,
    id: String,
    method: String,
    params: BTreeMap<String, String>,
}

fn validate_header(v: u8, id: &str) -> Result<()> {
    ensure!(v == 1, "unsupported host RPC version");
    ensure!(
        !id.is_empty()
            && id.len() <= 96
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)),
        "invalid host RPC request ID"
    );
    Ok(())
}

fn arguments(request: &Request) -> Result<Vec<String>> {
    validate_header(request.v, &request.id)?;
    let (command, fields, required): (&str, &[(&str, &str)], &[&str]) =
        match request.method.as_str() {
            "auth.register" => (
                "register",
                &[("addr", "addr"), ("user", "user"), ("password", "pass")],
                &["user", "password"],
            ),
            "auth.login.browser" => ("login", &[("addr", "addr")], &[]),
            "auth.login" => (
                "login",
                &[
                    ("addr", "addr"),
                    ("user", "user"),
                    ("password", "pass"),
                    ("super", "super"),
                ],
                &["user", "password"],
            ),
            "auth.recover" => (
                concat!("five", "keys"),
                &[
                    ("addr", "addr"),
                    ("user", "user"),
                    ("password", "pass"),
                    ("secret", "secret"),
                    ("super", "super"),
                    ("kdf_salt", "kdf-salt"),
                    ("wrapped_urk", "wrapped-urk"),
                    ("urk_nonce", "urk-nonce"),
                ],
                &["kdf_salt", "wrapped_urk", "urk_nonce"],
            ),
            "auth.reset" => ("super-reset", &[("super", "super")], &[]),
            _ => bail!("unknown host RPC method"),
        };
    for key in request.params.keys() {
        ensure!(
            fields.iter().any(|(name, _)| name == key)
                || (request.method == "auth.login"
                    && matches!(
                        key.as_str(),
                        "totp"
                            | "continuation"
                            | "migrate_local"
                            | "migrate_vault"
                            | "offer_local_merge"
                    )),
            "unknown authentication field"
        );
    }
    if let Some(addr) = request.params.get("addr").filter(|value| !value.is_empty()) {
        crate::login::origin(addr).context("invalid authentication server origin")?;
    }
    if request.method == "auth.recover" {
        let present = |key: &str| {
            request
                .params
                .get(key)
                .is_some_and(|value| !value.is_empty())
        };
        ensure!(
            present("super") || (present("password") && present("secret")),
            "recovery requires a super password or the legacy password and Account Secret"
        );
    }
    if let Some(code) = request.params.get("totp") {
        ensure!(
            code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
            "TOTP code must contain 6 digits"
        );
    }
    for key in required {
        ensure!(
            request.params.get(*key).is_some_and(|v| !v.is_empty()),
            "missing authentication field: {key}"
        );
    }
    let mut args = vec!["--json".to_owned(), command.to_owned()];
    if request.method == "auth.login" {
        args.push("--interactive".to_owned());
    }
    if request.method == "auth.login.browser" {
        args.push("--oauth".to_owned());
    }
    if request.method == "auth.recover" && !request.params.contains_key("password") {
        args.push("--pass=".to_owned());
    }
    for (key, flag) in fields {
        if let Some(value) = request.params.get(*key) {
            ensure!(
                value.len() <= 16384 && !value.contains('\0'),
                "invalid authentication field"
            );
            args.push(format!("--{flag}={value}"));
        }
    }
    Ok(args)
}

fn scrub(value: &mut Value, secrets: &[&str]) {
    match value {
        Value::String(text) => {
            for secret in secrets {
                if !secret.is_empty() {
                    *text = text.replace(secret, "[redacted]");
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                scrub(value, secrets);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                scrub(value, secrets);
            }
        }
        _ => {}
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    v: u8,
    id: String,
    method: String,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginContinue {
    operation_id: String,
    source_profile: std::path::PathBuf,
    continuation: Value,
    super_password: Option<String>,
    totp: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyContinue {
    operation_id: String,
    source_profile: std::path::PathBuf,
    input: Value,
}

fn supplemental_input(
    value: Value,
) -> Result<respire_protocol::host_control::HostAuthLoginContinuation> {
    let object = value
        .as_object()
        .context("login continuation must be an object")?;
    ensure!(
        object.keys().all(|key| matches!(
            key.as_str(),
            "legacy_password"
                | "account_secret"
                | "source_secret"
                | "secret_key"
                | "new_super"
                | "merge_local"
        )),
        "login continuation cannot replace original intent or private material"
    );
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid login supplemental input"))
}

fn key_input(value: Value) -> Result<respire_protocol::key_control::HostKeyInput> {
    let object = value.as_object().context("key input must be an object")?;
    ensure!(
        object.keys().all(|key| matches!(
            key.as_str(),
            "password" | "super_password" | "account_secret" | "totp"
        )),
        "key input cannot supply private material"
    );
    serde_json::from_value(value).map_err(|_| anyhow::anyhow!("invalid key supplemental input"))
}

fn initial_input(
    params: &BTreeMap<String, String>,
) -> Result<respire_protocol::host_control::HostAuthLoginContinuation> {
    let mut input = match params.get("continuation") {
        Some(value) => supplemental_input(
            serde_json::from_str(value)
                .map_err(|_| anyhow::anyhow!("invalid login continuation JSON"))?,
        )?,
        None => Default::default(),
    };
    let intent = |name: &str| -> Result<bool> {
        match params.get(name).map(String::as_str) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            _ => bail!("login intent must be true or false"),
        }
    };
    input.migrate_local = intent("migrate_local")?;
    input.migrate_vault = intent("migrate_vault")?;
    input.offer_local_merge = intent("offer_local_merge")?;
    Ok(input)
}

fn continue_request(request: &WireRequest) -> Result<respire_commands::output::ResultEnvelope> {
    validate_header(request.v, &request.id)?;
    // Validate all desktop input before starting or querying the original host transaction.
    // A fenced original resumes through its coordinator's maintenance binding and custody checks.
    match request.method.as_str() {
        "auth.login.continue" => {
            let params: LoginContinue = serde_json::from_value(request.params.clone())
                .map_err(|_| anyhow::anyhow!("invalid login continuation fields"))?;
            let input = supplemental_input(params.continuation)?;
            if let Some(code) = &params.totp {
                ensure!(
                    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
                    "TOTP code must contain 6 digits"
                );
            }
            crate::prepare_command_runtime()?;
            crate::autostart::rpc_accounts().continue_login(
                &params.operation_id,
                &params.source_profile,
                input,
                params.super_password,
                params.totp,
            )
        }
        "auth.key.continue" => {
            let params: KeyContinue = serde_json::from_value(request.params.clone())
                .map_err(|_| anyhow::anyhow!("invalid key continuation fields"))?;
            let input = key_input(params.input)?;
            if let Some(code) = &input.totp {
                ensure!(
                    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit()),
                    "TOTP code must contain 6 digits"
                );
            }
            crate::prepare_command_runtime()?;
            crate::autostart::rpc_keys().continue_input(
                &params.operation_id,
                &params.source_profile,
                input,
            )
        }
        _ => bail!("unknown host RPC continuation method"),
    }
}

fn capture_request(request: &WireRequest) -> crate::Captured {
    let result = (|| -> Result<crate::Captured> {
        validate_header(request.v, &request.id)?;
        if matches!(
            request.method.as_str(),
            "auth.login.continue" | "auth.key.continue"
        ) {
            let envelope = continue_request(request)?;
            return Ok(crate::Captured {
                exit: respire_commands::output_state::status_exit_code(envelope.status),
                envelope,
            });
        }
        let legacy = Request {
            v: request.v,
            id: request.id.clone(),
            method: request.method.clone(),
            params: serde_json::from_value(request.params.clone())
                .map_err(|_| anyhow::anyhow!("authentication fields must be strings"))?,
        };
        let args = arguments(&legacy)?;
        if matches!(legacy.method.as_str(), "auth.login" | "auth.login.browser") {
            let input = initial_input(&legacy.params)?;
            LOGIN_INPUT.with(|slot| *slot.borrow_mut() = Some(input));
        }
        crate::prepare_command_runtime()?;
        TOTP.with(|value| *value.borrow_mut() = legacy.params.get("totp").cloned());
        Ok(crate::capture_run(args))
    })();
    LOGIN_INPUT.with(|slot| *slot.borrow_mut() = None);
    TOTP.with(|value| *value.borrow_mut() = None);
    match result {
        Ok(captured) => captured,
        Err(error) => {
            let (envelope, exit) = crate::command_failure(&error);
            crate::Captured { exit, envelope }
        }
    }
}

fn secret_values(value: &Value, values: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "continuation" | "input") {
                    if let Some(text) = value.as_str() {
                        values.push(text.to_owned());
                        if let Ok(nested) = serde_json::from_str::<Value>(text) {
                            secret_values(&nested, values);
                        }
                    } else {
                        secret_values(value, values);
                    }
                } else if matches!(
                    key.as_str(),
                    "password"
                        | "super"
                        | "secret"
                        | "wrapped_urk"
                        | "totp"
                        | "super_password"
                        | "legacy_password"
                        | "account_secret"
                        | "source_secret"
                        | "secret_key"
                        | "new_super"
                ) {
                    if let Some(value) = value.as_str() {
                        values.push(value.to_owned());
                    }
                }
            }
        }
        Value::String(value) => values.push(value.to_owned()),
        _ => {}
    }
}

pub(crate) fn serve() -> Result<i32> {
    crate::runtime_policy::require_host("authentication RPC")?;
    ensure!(
        std::env::args_os()
            .skip(1)
            .all(|arg| arg == "--json" || arg == "--host-rpc-stdio" || arg == "--client-only"),
        "host RPC accepts no command-line payload"
    );
    let mut bytes = Vec::new();
    std::io::stdin().take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "host RPC request exceeds 64 KiB");
    let request: WireRequest = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid host RPC JSON request"))?;
    HOST_RPC_OUTPUT.set(true);
    let captured = capture_request(&request);
    HOST_RPC_OUTPUT.set(false);
    let mut envelope = serde_json::to_value(captured.envelope)?;
    let mut secrets = Vec::new();
    secret_values(&request.params, &mut secrets);
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    if envelope["status"] == "fail" {
        scrub(&mut envelope, &secrets);
    } else if let Some(errors) = envelope.get_mut("errors") {
        scrub(errors, &secrets);
    }
    let response = json!({"v":1,"id":request.id,"ok":captured.exit==0,"exit":captured.exit,"envelope":envelope});
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).context("write host RPC reply")?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(captured.exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: &[(&str, &str)]) -> Request {
        Request {
            v: 1,
            id: "original-client2-request".into(),
            method: method.into(),
            params: params
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    #[test]
    fn original_offline_recovery_keeps_empty_server_and_user() -> Result<()> {
        let command = arguments(&request(
            "auth.recover",
            &[
                ("super", "synthetic-super"),
                ("kdf_salt", "synthetic-salt"),
                ("wrapped_urk", "synthetic-wrap"),
                ("urk_nonce", "synthetic-nonce"),
            ],
        ))?;
        assert_eq!(command[1], "fivekeys");
        assert!(command.iter().any(|value| value == "--pass="));
        assert!(!command
            .iter()
            .any(|value| value.starts_with("--addr=") || value.starts_with("--user=")));
        Ok(())
    }

    #[test]
    fn original_password_totp_form_retains_its_existing_fields() -> Result<()> {
        let command = arguments(&request(
            "auth.login",
            &[
                ("addr", "http://127.0.0.1:9"),
                ("user", "synthetic-user"),
                ("password", "synthetic-password"),
                ("totp", "123456"),
            ],
        ))?;
        let input = initial_input(
            &request(
                "auth.login",
                &[
                    ("migrate_local", "true"),
                    ("offer_local_merge", "false"),
                    (
                        "continuation",
                        r#"{"source_secret":"synthetic-source","merge_local":true}"#,
                    ),
                ],
            )
            .params,
        )?;
        assert!(input.migrate_local && !input.migrate_vault && !input.offer_local_merge);
        assert_eq!(input.source_secret.as_deref(), Some("synthetic-source"));
        assert_eq!(input.merge_local, Some(true));
        let browser = arguments(&request("auth.login.browser", &[]))?;
        assert_eq!(browser, vec!["--json", "login", "--oauth"]);
        let browser = arguments(&request(
            "auth.login.browser",
            &[("addr", "http://127.0.0.1:9")],
        ))?;
        assert!(browser
            .iter()
            .any(|value| value == "--addr=http://127.0.0.1:9"));
        for field in [
            "password",
            "user",
            "authorization",
            "token",
            "totp",
            "continuation",
            "material",
            "migrate_local",
        ] {
            assert!(arguments(&request("auth.login.browser", &[(field, "forbidden")])).is_err());
        }
        assert!(command.iter().any(|value| value == "--interactive"));
        assert!(!command.iter().any(|value| value.contains("123456")));
        assert!(arguments(&request(
            "auth.login",
            &[
                ("user", "synthetic-user"),
                ("password", "synthetic-password"),
                ("totp", "invalid")
            ]
        ))
        .is_err());
        Ok(())
    }

    #[test]
    fn existing_transport_rejects_unknown_method_fields_and_missing_inputs() -> Result<()> {
        let login: LoginContinue = serde_json::from_value(json!({
            "operation_id":"a7e71cb4-0016-4a1d-bc18-8f83816078ec", "source_profile":"synthetic-profile",
            "continuation":{"account_secret":"synthetic-secret"}, "totp":"123456"
        }))?;
        assert!(supplemental_input(login.continuation).is_ok());
        assert!(key_input(json!({"totp":"123456"})).is_ok());
        for field in [
            "material",
            "challenge",
            "custody_ack",
            "operation",
            "receipt",
        ] {
            let mut value = json!({});
            value[field] = json!({});
            assert!(key_input(value).is_err());
        }
        for field in [
            "authorization",
            "addr",
            "user",
            "migrate_local",
            "material",
            "challenge",
            "custody_ack",
        ] {
            let mut value = json!({"operation_id":"original", "source_profile":"synthetic-profile", "continuation":{}});
            value[field] = json!("forbidden");
            assert!(serde_json::from_value::<LoginContinue>(value).is_err());
            assert!(supplemental_input(json!({field:"forbidden"})).is_err());
        }
        assert!(serde_json::from_value::<LoginContinue>(
            json!({"source_profile":"synthetic-profile", "continuation":{}})
        )
        .is_err());
        assert!(serde_json::from_value::<KeyContinue>(json!({"operation_id":"original", "source_profile":"synthetic-profile", "input":{}, "receipt":{}})).is_err());
        assert!(initial_input(&request("auth.login", &[("migrate_local", "yes")]).params).is_err());
        assert!(initial_input(
            &request(
                "auth.login",
                &[("continuation", r#"{"migrate_local":true}"#)]
            )
            .params
        )
        .is_err());
        assert!(arguments(&request("auth.unknown", &[])).is_err());
        assert!(arguments(&request("auth.login", &[("user", "synthetic-user")])).is_err());
        assert!(arguments(&request("auth.reset", &[("unexpected", "value")])).is_err());
        assert!(arguments(&request(
            "auth.recover",
            &[
                ("kdf_salt", "salt"),
                ("wrapped_urk", "wrap"),
                ("urk_nonce", "nonce")
            ]
        ))
        .is_err());
        Ok(())
    }

    #[test]
    fn pending_maintenance_continuation_reaches_original_transaction_validation() -> Result<()> {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match &self.0 {
                    Some(value) => std::env::set_var("RSRS_DATA_DIR", value),
                    None => std::env::remove_var("RSRS_DATA_DIR"),
                }
            }
        }
        let _restore = Restore(std::env::var_os("RSRS_DATA_DIR"));
        let directory = tempfile::tempdir()?;
        std::env::set_var("RSRS_DATA_DIR", directory.path());
        let marker = directory.path().join("runtime/autostart/maintenance.json");
        std::fs::create_dir_all(marker.parent().context("test marker parent")?)?;
        let bytes = serde_json::to_vec(&json!({
            "schema": 1, "id": "fixture-installation", "token": uuid::Uuid::new_v4().to_string(),
            "phase": "Paused", "expected_profile": directory.path().canonicalize()?,
            "expected_version": env!("CARGO_PKG_VERSION"),
            "owner_pid": std::process::id(), "owner_birth": "fixture-birth"
        }))?;
        std::fs::write(&marker, &bytes)?;
        assert!(crate::autostart::check_direct_access().is_err());
        let request = WireRequest {
            v: 1,
            id: "resume-transport".into(),
            method: "auth.login.continue".into(),
            params: json!({"operation_id": "not-an-operation", "source_profile": directory.path(),
                           "continuation": {}, "super_password": "fixture-super"}),
        };
        let error = continue_request(&request)
            .err()
            .context("foreign operation was accepted")?;
        assert!(
            format!("{error:#}").contains("invalid account operation ID"),
            "{error:#}"
        );
        let request = WireRequest {
            method: "auth.key.continue".into(),
            params: json!({"operation_id": uuid::Uuid::new_v4().to_string(),
                           "source_profile": directory.path(), "input": {}}),
            ..request
        };
        let error = continue_request(&request)
            .err()
            .context("unverified Runtime was accepted")?;
        assert!(
            format!("{error:#}").contains("model control Runtime manifest is missing"),
            "{error:#}"
        );
        assert!(crate::autostart::check_direct_access().is_err());
        assert_eq!(std::fs::read(&marker)?, bytes);
        Ok(())
    }

    #[test]
    fn existing_failure_scrubber_removes_synthetic_values() {
        let mut value =
            json!({"errors":["synthetic-secret", {"detail":"prefix synthetic-secret suffix"}]});
        let mut values = Vec::new();
        secret_values(
            &json!({"continuation":r#"{"account_secret":"synthetic-secret"}"#,
            "input":{"super_password":"synthetic-super"}}),
            &mut values,
        );
        assert!(values.iter().any(|secret| secret == "synthetic-secret"));
        assert!(values.iter().any(|secret| secret == "synthetic-super"));
        let refs: Vec<&str> = values.iter().map(String::as_str).collect();
        scrub(&mut value, &refs);
        assert!(!value.to_string().contains("synthetic-secret"));
    }
}
