//! A submitted switch is never replayed. Waits only inspect its scoped receipt.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

use crate::output::{Item, ResultEnvelope, Status};
use crate::runtime_error::{OperationContext, RuntimeError};

const WAIT_LIMIT: Duration = Duration::from_secs(30 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(800);
const POLL_DEADLINE: Duration = Duration::from_secs(5);

pub(crate) fn submit(choice: Value, wait: bool, show_progress: bool) -> Result<ResultEnvelope> {
    let reply =
        crate::rpc::call_method("model.switch", vec![serde_json::to_string(&choice)?], true)?;
    follow(reply, wait, show_progress)
}

pub(crate) fn submit_for_scope(
    choice: Value,
    scope: &respire_protocol::RuntimeRequestScope,
) -> Result<ResultEnvelope> {
    let reply = crate::net_rpc::rpc_model_switch_for_scope(serde_json::to_string(&choice)?, scope)?;
    follow(serde_json::from_value(reply)?, true, false)
}

fn follow(
    reply: crate::rpc::RpcResponse,
    wait: bool,
    show_progress: bool,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(
        reply.ok,
        "{}",
        reply
            .error
            .unwrap_or_else(|| "model profile request failed".into())
    );
    let acceptance = reply.envelope.context("model profile response missing")?;
    if !wait || !matches!(acceptance.status, Status::Pending) {
        return Ok(acceptance);
    }
    let operation_id = reply
        .operation_id
        .context("pending model switch has no operation ID; do not submit it again")?;
    // This client generates the original operation ID and idempotency key
    // together; historical runtimes may omit the optional key in their echo.
    let operation = OperationContext {
        scope: reply
            .scope
            .context("pending model switch has no original scope; do not submit it again")?,
        idempotency_key: reply
            .idempotency_key
            .unwrap_or_else(|| operation_id.clone()),
        operation_id,
    };
    let unknown = |error: anyhow::Error| RuntimeError::OutcomeUnknown {
        request_id: reply.id.clone(),
        operation: operation.clone(),
        detail: format!("model switch completion was not verified: {error:#}"),
    };
    anyhow::ensure!(
        acceptance.summary["id"].as_str() == Some(operation.operation_id.as_str()),
        unknown(anyhow!("Runtime returned a foreign model switch task"))
    );
    if show_progress {
        eprintln!(
            "Model switch {} accepted; waiting for Runtime.",
            operation.operation_id
        );
    }
    let started = Instant::now();
    let mut next_progress = started;
    let mut previous_phase = String::new();
    loop {
        let remain = WAIT_LIMIT.saturating_sub(started.elapsed());
        if remain.is_zero() {
            return Err(unknown(anyhow!("wait timed out")).into());
        }
        let receipt =
            crate::net_rpc::rpc_result_with_timeout(&operation, Some(POLL_DEADLINE.min(remain)))
                .map_err(&unknown)?;
        match terminal_receipt(&receipt, &operation).map_err(&unknown)? {
            Receipt::Terminal(result) => return Ok(result),
            Receipt::Pending => {}
        }
        if show_progress && Instant::now() >= next_progress {
            let remain = WAIT_LIMIT.saturating_sub(started.elapsed());
            if !remain.is_zero() {
                if let Ok(progress) = crate::net_rpc::rpc_method_with_timeout(
                    "model.progress",
                    Vec::new(),
                    Some(Duration::from_secs(1).min(remain)),
                ) {
                    if let Some(phase) = observed_phase(&progress, &operation.operation_id) {
                        if phase != previous_phase {
                            eprintln!("Model switch: {phase}");
                            previous_phase = phase.to_owned();
                        }
                    }
                }
            }
            next_progress = Instant::now() + Duration::from_secs(2);
        }
        std::thread::sleep(POLL_INTERVAL.min(WAIT_LIMIT.saturating_sub(started.elapsed())));
    }
}

enum Receipt {
    Pending,
    Terminal(ResultEnvelope),
}

fn observed_phase<'a>(response: &'a Value, operation_id: &str) -> Option<&'a str> {
    let progress = &response["envelope"]["summary"]["operation"];
    if response["ok"] == true && progress["id"].as_str() == Some(operation_id) {
        return progress["phase"].as_str().filter(|phase| {
            !phase.is_empty()
                && phase.len() < 50
                && phase
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    }
    None
}

fn terminal_receipt(receipt: &Value, operation: &OperationContext) -> Result<Receipt> {
    anyhow::ensure!(
        receipt["ok"] == true,
        "Runtime did not accept the original result query"
    );
    let lookup = &receipt["envelope"]["summary"];
    anyhow::ensure!(
        lookup["operation_id"].as_str() == Some(operation.operation_id.as_str()),
        "Runtime returned a different operation"
    );
    let lookup_scope: respire_protocol::RuntimeRequestScope =
        serde_json::from_value(lookup["scope"].clone())?;
    anyhow::ensure!(
        lookup_scope == operation.scope,
        "Runtime returned a different scope"
    );
    let reply = &lookup["response"];
    let state = lookup["state"]
        .as_str()
        .context("Runtime omitted result state")?;
    if state == "pending" && reply.is_null() {
        return Ok(Receipt::Pending);
    }
    anyhow::ensure!(
        matches!(state, "pending" | "completed" | "failed") && reply.is_object(),
        "Runtime no longer has an authoritative result for this operation"
    );
    let original: respire_protocol::RpcResponse<ResultEnvelope> =
        serde_json::from_value(reply.clone())?;
    anyhow::ensure!(
        original.operation_id.as_deref() == Some(operation.operation_id.as_str())
            && original.scope.as_ref() == Some(&operation.scope)
            && original
                .idempotency_key
                .as_ref()
                .is_none_or(|key| key == &operation.idempotency_key),
        "Runtime returned a foreign stored receipt"
    );
    if let Some(envelope) = original.envelope {
        anyhow::ensure!(
            envelope.command == "model.switch"
                && envelope.summary["id"].as_str() == Some(operation.operation_id.as_str()),
            "Runtime returned a mismatched switch receipt"
        );
        return match envelope.status {
            Status::Pending if original.ok => Ok(Receipt::Pending),
            Status::Ok | Status::Skip if original.ok && envelope.summary["state"] == "ready" => {
                Ok(Receipt::Terminal(envelope))
            }
            Status::Fail if !original.ok => Ok(Receipt::Terminal(envelope)),
            _ => Err(anyhow!("Runtime returned inconsistent model switch status")),
        };
    }
    anyhow::ensure!(
        state == "failed" && !original.ok,
        "Runtime omitted the terminal switch receipt"
    );
    let error = original.error.context("failed switch has no diagnostic")?;
    let mut result = ResultEnvelope::new(
        "model.switch",
        Status::Fail,
        json!({"id":operation.operation_id, "state":"failed"}),
        vec![Item::new("model switch", Status::Fail, &error)],
    );
    result.errors.push(error);
    Ok(Receipt::Terminal(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> OperationContext {
        OperationContext {
            scope: respire_protocol::RuntimeRequestScope {
                account_id: "account".into(),
                instance_id: "instance".into(),
                generation: 1,
            },
            operation_id: "switch-1".into(),
            idempotency_key: "switch-1".into(),
        }
    }

    #[test]
    fn model_switch_polls_pending_then_terminal_receipt_without_rebinding_scope() -> Result<()> {
        let op = operation();
        let acceptance = ResultEnvelope::new(
            "model.switch",
            Status::Pending,
            json!({"id":op.operation_id,"state":"pending"}),
            vec![],
        );
        let response = json!({"v":crate::rpc::PROTOCOL_V,"id":"accept","operation_id":op.operation_id,
            "scope":op.scope,"idempotency_key":op.idempotency_key,"ok":true,"exit":0,"bin":"fixture",
            "envelope":acceptance});
        let mut receipt = json!({"ok":true,"envelope":{"summary":{
            "operation_id":op.operation_id,"scope":op.scope,"state":"completed","response":response
        }}});
        // Some existing runtimes label their cached acceptance as completed
        // despite the inner switch envelope still explicitly being Pending.
        assert!(matches!(terminal_receipt(&receipt, &op)?, Receipt::Pending));
        let saved = &mut receipt["envelope"]["summary"]["response"]["envelope"];
        saved["status"] = json!("ok");
        saved["summary"]["state"] = json!("ready");
        assert!(matches!(
            terminal_receipt(&receipt, &op)?,
            Receipt::Terminal(_)
        ));
        receipt["envelope"]["summary"]["response"]["scope"]["generation"] = json!(2);
        assert!(terminal_receipt(&receipt, &op).is_err());
        receipt["envelope"]["summary"]["response"] = Value::Null;
        receipt["envelope"]["summary"]["state"] = json!("unknown");
        assert!(terminal_receipt(&receipt, &op).is_err());
        Ok(())
    }

    #[test]
    fn model_switch_returns_real_terminal_error_and_ignores_foreign_progress() -> Result<()> {
        let op = operation();
        let failure = json!({"ok":true,"envelope":{"summary":{
            "operation_id":op.operation_id,"scope":op.scope,"state":"failed",
            "response":{"v":crate::rpc::PROTOCOL_V,"id":"accept","operation_id":op.operation_id,"scope":op.scope,
                "ok":false,"exit":1,"bin":"fixture","error":"checksum mismatch; old selection retained"}
        }}});
        let Receipt::Terminal(result) = terminal_receipt(&failure, &op)? else {
            anyhow::bail!("failed operation incorrectly remained pending");
        };
        assert!(matches!(result.status, Status::Fail));
        assert_eq!(result.errors, ["checksum mismatch; old selection retained"]);
        let progress = json!({"ok":true,"envelope":{"summary":{"operation":{"id":op.operation_id,"phase":"switch-verify"}}}});
        assert_eq!(
            observed_phase(&progress, &op.operation_id),
            Some("switch-verify")
        );
        assert_eq!(observed_phase(&progress, "another-switch"), None);
        Ok(())
    }
}
