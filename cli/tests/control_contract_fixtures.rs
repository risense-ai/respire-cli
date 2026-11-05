use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod private_host_control {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/runtime-control/consumers/private_host_control.rs"));
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/runtime-control/consumers/space_control.rs"));
}

fn contract_root() -> Result<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is set")?;
    Ok(Path::new(&manifest_dir)
        .join("../contracts/runtime-control")
        .canonicalize()
        .context("runtime control contract exists")?)
}

fn fixture(name: &str) -> Result<Value> {
    let path = contract_root()?.join("fixtures").join(name);
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && hex::decode(value).is_ok()
}

#[test]
fn cli_reads_backend_load_evidence_and_legacy_file_checks() -> Result<()> {
    use respire_protocol::{AssetsStatus, BackendLoadState};
    let loaded = fixture("positive/assets-loaded.json")?;
    let status: AssetsStatus = serde_json::from_value(loaded["payload"].clone())?;
    assert!(status.complete && status.missing.is_empty());
    let load = status.backend_load.context("backend load result")?;
    assert_eq!(load.state, BackendLoadState::Loaded);
    let evidence = load.evidence.context("sanitized SDK evidence")?;
    assert!(evidence.ready && evidence.fresh_session && evidence.inference_completed);
    assert_eq!(serde_json::to_value(evidence)?, loaded["payload"]["backend_load"]["evidence"]);
    let file_only: AssetsStatus = serde_json::from_value(json!({"complete":true,"missing":[]}))?;
    assert!(file_only.complete && file_only.backend_load.is_none());
    Ok(())
}

fn validate_release(fixture: &Value) -> Result<()> {
    let payload = fixture["payload"].as_object().context("metadata payload")?;
    let version = payload["schema_version"]
        .as_u64()
        .context("schema_version")?;
    let runtime = payload["runtime_version"]
        .as_str()
        .context("runtime_version")?;
    let tag = payload["tag"].as_str().context("tag")?;
    assert_eq!(tag.strip_prefix('v'), Some(runtime));

    let target = payload["target_triple"]
        .as_str()
        .or_else(|| payload["triple"].as_str())
        .context("target")?;
    assert!(!target.is_empty());
    let archive = payload["archive_sha256"]
        .as_str()
        .or_else(|| payload["sha256"].as_str())
        .context("archive digest")?;
    assert!(valid_digest(archive));
    if let (Some(canonical), Some(alias)) = (
        payload.get("archive_sha256").and_then(Value::as_str),
        payload.get("sha256").and_then(Value::as_str),
    ) {
        assert_eq!(canonical, alias, "legacy archive alias conflict");
    }
    if let (Some(canonical), Some(alias)) = (
        payload.get("target_triple").and_then(Value::as_str),
        payload.get("triple").and_then(Value::as_str),
    ) {
        assert_eq!(canonical, alias, "legacy target alias conflict");
    }
    if version >= 2 {
        let binary = payload["binary_sha256"].as_str().context("binary digest")?;
        assert!(valid_digest(binary));
        assert_ne!(binary, archive, "digests describe different bytes");
    }
    Ok(())
}

#[test]
fn cli_consumes_the_runtime_control_contract() -> Result<()> {
    let manifest: Value = serde_json::from_str(&std::fs::read_to_string(
        contract_root()?.join("manifest.json"),
    )?)?;
    assert_eq!(manifest["contract"], "runtime-control");
    assert_eq!(manifest["release_metadata_schema_version"], 2);
    let positive = manifest["fixtures"]["positive"]
        .as_array()
        .context("positive fixtures")?;
    let negative = manifest["fixtures"]["negative"]
        .as_array()
        .context("negative fixtures")?;
    assert_eq!(positive.len(), 89);
    assert_eq!(negative.len(), 287);

    for bound in manifest["files"].as_array().context("bound files")? {
        let relative = bound["path"].as_str().context("bound path")?;
        let expected = bound["sha256"].as_str().context("bound digest")?;
        assert_eq!(sha256(&contract_root()?.join(relative))?, expected);
    }

    for name in [
        "positive/release-metadata-v2.json",
        "positive/release-metadata-v1.json",
    ] {
        validate_release(&fixture(name)?)?;
    }

    let conflicting = fixture("negative/release-metadata-conflicting-hash.json")?;
    assert_eq!(conflicting["error_code"], "metadata_alias_conflict");
    assert_ne!(
        conflicting["payload"]["archive_sha256"],
        conflicting["payload"]["sha256"]
    );
    assert_ne!(
        conflicting["payload"]["target_triple"],
        conflicting["payload"]["triple"]
    );

    let missing = fixture("negative/release-metadata-missing-binary-hash.json")?;
    assert_eq!(missing["error_code"], "missing_binary_sha256");
    assert!(missing["payload"].get("binary_sha256").is_none());

    let wrong_target = fixture("negative/release-metadata-wrong-target.json")?;
    assert_eq!(wrong_target["error_code"], "target_mismatch");
    let target = wrong_target["payload"]["target_triple"]
        .as_str()
        .context("wrong-target fixture names its target")?;
    let archive_name = wrong_target["payload"]["archive_file"]
        .as_str()
        .context("wrong-target fixture names its archive")?;
    assert!(!archive_name.contains(target));

    let identity = fixture("negative/health-identity-pid-only.json")?;
    assert_eq!(identity["error_code"], "identity_incomplete");
    assert!(identity["payload"]["instance_id"].is_null());

    let stop = fixture("negative/stop-ambiguous-ok.json")?;
    assert_eq!(stop["error_code"], "ambiguous_stop_result");
    assert_eq!(stop["payload"]["state"], "drained");
    let unfinished = stop["payload"]["unfinished"]
        .as_array()
        .context("unfinished stop operations")?;
    assert_eq!(unfinished.len(), 1);

    for (name, outcome) in [
        ("positive/stop-final-forced-timeout.json", respire_protocol::RuntimeStopOutcome::ForcedTimeout),
        ("positive/stop-final-compatibility-timeout.json", respire_protocol::RuntimeStopOutcome::CompatibilityTimeout),
    ] {
        let fixture = fixture(name)?;
        let receipt: respire_protocol::RuntimeStopReceipt =
            serde_json::from_value(fixture["payload"].clone())?;
        assert_eq!(receipt.state, outcome);
        assert_ne!(receipt.state, respire_protocol::RuntimeStopOutcome::Drained);
        assert!(!receipt.unfinished.is_empty());
        assert!(receipt.unfinished.iter().all(|operation|
            !operation.operation_id.is_empty() && matches!(operation.result, respire_protocol::RuntimeUnfinishedOutcome::Aborted | respire_protocol::RuntimeUnfinishedOutcome::Unknown)));
        assert_eq!(serde_json::to_value(receipt)?, fixture["payload"]);
    }
    let fabricated = fixture("negative/stop-final-fabricated-completion.json")?;
    assert_eq!(fabricated["error_code"], "stop_outcome_invalid");
    assert_eq!(fabricated["payload"]["unfinished"][0]["result"], "completed");
    assert!(serde_json::from_value::<respire_protocol::RuntimeStopReceipt>(
        fabricated["payload"].clone()
    ).is_err());

    let operation = fixture("negative/idempotency-conflict.json")?;
    assert_eq!(operation["error_code"], "idempotency_conflict");
    assert_eq!(operation["payload"]["method"], "model.probe");

    let route = fixture("positive/bootstrap-route.json")?;
    assert_eq!(route["payload"]["operation"], "auth.login");
    assert_eq!(route["payload"]["executor"], "cli");
    private_host_control::space_contract_fixtures()?;
    Ok(())
}

#[test]
fn cli_preserves_business_scope_in_submission_and_result_queries() -> Result<()> {
    fn scope_failure(payload: &Value, current: &Value) -> Option<&'static str> {
        let Ok(request) = serde_json::from_value::<respire_protocol::RpcRequest>(payload.clone()) else {
            return Some("rpc_body_invalid");
        };
        let Some(scope) = request.scope else {
            return Some("scope_required");
        };
        if scope.account_id.trim().is_empty()
            || scope.instance_id.trim().is_empty()
            || scope.generation == 0 || payload["scope"] != *current
        {
            return Some("scope_mismatch");
        }
        None
    }
    let health = fixture("positive/health-identity.json")?;
    let current = json!({
        "account_id": health["payload"]["account_id"],
        "instance_id": health["payload"]["instance_id"],
        "generation": health["payload"]["generation"],
    });
    let manifest: Value = serde_json::from_slice(&std::fs::read(contract_root()?.join("manifest.json"))?)?;
    for group in ["positive", "negative"] {
        for name in manifest["fixtures"][group].as_array().context("fixture group")? {
            let name = name.as_str().context("fixture path")?;
            let case = fixture(name.strip_prefix("fixtures/").context("fixture prefix")?)?;
            if case["fixture_type"] == "business_rpc_response" {
                let expected = if case["expected"] == "accept" { None } else { case["error_code"].as_str() };
                assert_eq!(response_failure(&case["payload"]), expected, "{name}");
                continue;
            }
            if case["fixture_type"] != "business_rpc_request" { continue; }
            let expected = if case["expected"] == "accept" { None } else { case["error_code"].as_str() };
            assert_eq!(scope_failure(&case["payload"], &current), expected, "{name}");
        }
    }
    let submit = fixture("positive/business-rpc-scoped.json")?;
    let request: respire_protocol::RpcRequest = serde_json::from_value(submit["payload"].clone())?;
    assert_eq!(serde_json::to_value(request)?, submit["payload"]);
    let completed = fixture("positive/rpc-response-completed.json")?;
    let response: respire_protocol::RpcResponse<Value> =
        serde_json::from_value(completed["payload"]["response"].clone())?;
    assert_eq!(serde_json::to_value(response)?, completed["payload"]["response"]);
    let result = fixture("positive/runtime-result-scoped.json")?;
    assert_eq!(submit["payload"]["scope"], current);
    assert_eq!(result["payload"]["scope"], current);
    assert_ne!(submit["payload"]["id"], result["payload"]["id"]);
    assert_eq!(result["payload"]["args"][0], submit["payload"]["operation_id"]);
    for name in ["positive/operation-result-completed.json", "negative/idempotency-conflict.json"] {
        assert_eq!(fixture(name)?["payload"]["scope"], current);
    }
    let mut unknown = submit["payload"].clone();
    unknown["scope"]["extra"] = json!(true);
    assert_eq!(scope_failure(&unknown, &current), Some("rpc_body_invalid"));
    Ok(())
}


// Fixture-only counterpart of the read-only CLI response checker.
fn response_failure(payload: &Value) -> Option<&'static str> {
    let request = &payload["request"];
    let response = &payload["response"];
    if response["v"].as_u64() != Some(1) || response["id"] != request["id"]
        || response["code"] == "protocol_version_mismatch"
    {
        return Some("response_header_mismatch");
    }
    let Some(exit) = response["exit"].as_u64() else { return Some("response_status_mismatch"); };
    if response["ok"].as_bool() != Some(exit == 0) { return Some("response_status_mismatch"); }
    for (key, error) in [("operation_id", "response_operation_mismatch"),
        ("idempotency_key", "response_key_mismatch")]
    {
        if response.get(key).is_some_and(|value| value != &request[key]) { return Some(error); }
    }
    if matches!(response["code"].as_str(), Some("scope_required" | "scope_mismatch")) {
        if exit == 0 || response.get("envelope").filter(|value| !value.is_null())
            .is_some_and(|envelope| envelope["status"] != "fail")
        { return Some("response_status_mismatch"); }
        if let Some(scope) = response.get("scope").filter(|value| !value.is_null()) {
            if serde_json::from_value::<respire_protocol::RuntimeRequestScope>(scope.clone()).is_err() {
                return Some("response_scope_mismatch");
            }
        }
        return None;
    }
    let receipt = if request["method"] == "runtime.result" { &response["envelope"]["summary"] } else { response };
    if receipt["operation_id"] != request["operation_id"] { return Some("response_operation_mismatch"); }
    if serde_json::from_value::<respire_protocol::RuntimeRequestScope>(receipt["scope"].clone()).is_err()
        || receipt["scope"] != request["scope"]
    { return Some("response_scope_mismatch"); }
    if receipt.get("idempotency_key").is_some_and(|key| key != &request["idempotency_key"]) {
        return Some("response_key_mismatch");
    }
    if request["method"] == "runtime.result" {
        if receipt["request_id"] != request["id"] { return Some("response_result_request_mismatch"); }
        if response.get("scope").is_some_and(|scope| scope != &receipt["scope"]) {
            return Some("response_scope_mismatch");
        }
    }
    if let Some(cached) = payload.get("cached_response") {
        let mut replay = response.clone();
        replay["id"] = cached["id"].clone();
        if &replay != cached { return Some("response_replay_mismatch"); }
    }
    None
}
