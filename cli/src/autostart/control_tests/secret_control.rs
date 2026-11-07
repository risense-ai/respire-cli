//! Synthetic host-output and response tests. No Runtime, keyring or network is used.
use super::*;
use respire_protocol::secret_control::HostSecretSession;
use serde_json::{json, Value};

fn read(has_session: bool, has_token: bool, reveal: bool) -> HostSecretReadResult {
    HostSecretReadResult {
        session: HostSecretSession {
            has_session,
            has_token,
            user: "fixture-user".into(),
            addr: "https://example.invalid".into(),
            secret_masked: "fixture-***".into(),
            has_local_keys: true,
        },
        secret: reveal.then(|| "synthetic-secret".into()),
        five: reveal.then(|| json!({"synthetic": true})),
    }
}

fn request() -> Result<RpcRequest> {
    Ok(serde_json::from_value(
        json!({"v":1,"id":"fixture-request","method":"control.secret.read","args":[]}),
    )?)
}

fn response(command: &str, directory: &Path) -> Value {
    json!({"v":1,"id":"fixture-request","ok":true,"exit":0,"bin":"rsrs-runtime",
        "pid":42,"data_dir":directory,"envelope":{"command":command,"status":"ok",
        "summary": if command == "session" { json!({"action":"list"}) } else { json!({}) },
        "items":[{"name":"control_ready","status":"ok","value":"true"},
                 {"name":"store_ready","status":"skip","value":"false"}],
        "actions":[],"errors":[],"details":null}})
}

#[test]
fn secret_output_keeps_absent_masked_and_revealed_states_distinct() -> Result<()> {
    let absent = secret_result(read(false, false, false), false)?;
    assert!(matches!(absent.status, OutputStatus::Skip));
    assert_eq!(absent.summary, json!({"session":false}));
    assert_eq!(absent.actions, ["register or login"]);
    assert!(absent.details.is_null());
    for token in [false, true] {
        let masked = secret_result(read(true, token, false), false)?;
        assert!(matches!(masked.status, OutputStatus::Ok));
        assert_eq!(
            masked
                .items
                .iter()
                .find(|i| i.name == "token")
                .context("token output")?
                .value,
            if token { "present" } else { "missing" }
        );
        assert_eq!(
            masked
                .items
                .iter()
                .find(|i| i.name == "secret")
                .context("masked output")?
                .value,
            "fixture-***"
        );
        assert!(masked.details.get("secret").is_none());
        assert!(!serde_json::to_string(&masked)?.contains("synthetic-secret"));
    }
    let revealed = secret_result(read(true, true, true), true)?;
    assert!(matches!(revealed.status, OutputStatus::Warn));
    assert_eq!(revealed.details["secret"], "synthetic-secret");
    assert_eq!(revealed.details["five"], json!({"synthetic":true}));
    assert_eq!(revealed.actions, ["protect secret output"]);
    assert!(revealed
        .items
        .iter()
        .any(|i| i.name == "keys" && matches!(i.status, OutputStatus::Warn)));
    Ok(())
}

#[test]
fn secret_rendering_rejects_inconsistent_reveal_shapes() -> Result<()> {
    assert!(secret_result(read(true, true, true), false).is_err());
    assert!(secret_result(read(false, false, true), true).is_err());
    assert!(secret_result(read(true, true, false), true).is_err());
    let mut malformed = read(true, true, true);
    malformed.five = Some(json!("not-an-object"));
    assert!(secret_result(malformed, true).is_err());
    let mut malformed = read(true, true, true);
    malformed.secret = None;
    assert!(secret_result(malformed, true).is_err());
    Ok(())
}

#[test]
fn export_output_uses_private_files_and_preserves_inline_contract() -> Result<()> {
    let exported = || HostKeysExportReadResult {
        version: 4,
        user: "fixture-user".into(),
        body: "synthetic-export-body".into(),
        legacy_warning: false,
    };
    let inline = keys_export_result(exported(), None)?;
    assert!(matches!(inline.status, OutputStatus::Warn));
    assert_eq!(inline.summary["inline"], true);
    assert_eq!(inline.items[0].value, "synthetic-export-body");
    let dir = tempfile::tempdir()?;
    let output = dir.path().join("keys.txt");
    let path = output.to_str().context("temporary path is Unicode")?;
    let saved = keys_export_result(exported(), Some(path))?;
    assert!(matches!(saved.status, OutputStatus::Ok));
    assert_eq!(std::fs::read_to_string(&output)?, "synthetic-export-body");
    assert!(!serde_json::to_string(&saved)?.contains("synthetic-export-body"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&output)?.permissions().mode() & 0o777,
            0o600
        );
    }
    let mut legacy = exported();
    legacy.version = 2;
    legacy.legacy_warning = true;
    assert_eq!(keys_export_result(legacy, None)?.summary["version"], 2);
    assert!(keys_export_result(
        exported(),
        Some(dir.path().to_str().context("directory path")?)
    )
    .is_err());
    Ok(())
}

#[test]
fn private_read_responses_validate_all_binding_and_readiness_fields() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let request = request()?;
    for command in ["secret-read", "keys-export-read", "session"] {
        let baseline = response(command, &profile);
        validate_response(
            serde_json::from_value(baseline.clone())?,
            &request,
            &profile,
            42,
            command,
        )?;
        for (pointer, value) in [
            ("/v", json!(2)),
            ("/id", json!("another-request")),
            ("/pid", json!(43)),
            ("/bin", json!("another-program")),
            ("/operation_id", json!("unexpected")),
            ("/idempotency_key", json!("unexpected")),
            ("/web_url", json!("https://example.invalid")),
            ("/ok", json!(false)),
            ("/exit", json!(2)),
            ("/error", json!("synthetic-peer-diagnostic")),
            ("/envelope/command", json!("another-command")),
            ("/envelope/status", json!("fail")),
            ("/envelope/summary", json!({"unexpected":true})),
            ("/envelope/errors", json!(["synthetic-peer-diagnostic"])),
            ("/envelope/actions", json!(["unexpected"])),
            ("/envelope/items/0/value", json!("false")),
            ("/envelope/items/0/status", json!("skip")),
            ("/envelope/items/1/value", json!("true")),
            ("/envelope/items/1/status", json!("ok")),
        ] {
            let mut changed = baseline.clone();
            if let Some(target) = changed.pointer_mut(pointer) {
                *target = value;
            } else {
                changed[pointer.trim_start_matches('/')] = value;
            }
            let result = validate_response(
                serde_json::from_value(changed)?,
                &request,
                &profile,
                42,
                command,
            );
            assert!(result.is_err(), "accepted changed field {pointer}");
        }
        let mut duplicate = baseline.clone();
        duplicate["envelope"]["items"] = json!([
            {"name":"control_ready","status":"ok","value":"true"},
            {"name":"control_ready","status":"ok","value":"true"}]);
        assert!(validate_response(
            serde_json::from_value(duplicate)?,
            &request,
            &profile,
            42,
            command
        )
        .is_err());
        let mut missing = baseline.clone();
        missing["envelope"] = Value::Null;
        assert!(validate_response(
            serde_json::from_value(missing)?,
            &request,
            &profile,
            42,
            command
        )
        .is_err());
        let mut pending = baseline.clone();
        pending["code"] = json!("auth_recovery_pending");
        let error = validate_response(
            serde_json::from_value(pending)?,
            &request,
            &profile,
            42,
            command,
        )
        .err()
        .context("pending recovery must fail")?;
        assert!(error.to_string().contains("auth_recovery_pending"));
        let mut rejected = baseline;
        rejected["error"] = json!("synthetic-peer-diagnostic");
        let error = validate_response(
            serde_json::from_value(rejected)?,
            &request,
            &profile,
            42,
            command,
        )
        .err()
        .context("peer error must fail")?;
        assert!(!error.to_string().contains("synthetic-peer-diagnostic"));
    }
    Ok(())
}
