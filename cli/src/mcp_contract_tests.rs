use super::*;
use serde_json::json;

#[test]
fn extract_filters_and_recall_relationship_flag_preserve_argv() -> Result<(), String> {
    for (authorization, suffix) in [("dry_run", vec!["--dry-run"]), ("confirm", vec![])] {
        let mut arguments = json!({
            "id": "entry-1", "limit": 0, "since": "2026-01-01",
            "importance": "important", "parent": "parent-1"
        });
        arguments[authorization] = json!(true);
        let mut expected = vec!["extract", "--id", "entry-1"];
        expected.extend(suffix);
        expected.extend([
            "--limit",
            "0",
            "--since",
            "2026-01-01",
            "--importance",
            "important",
            "--parent",
            "parent-1",
        ]);
        assert_eq!(tool_argv("memory_extract", &arguments)?, expected);
    }
    for related in [true, false] {
        let mut expected = vec!["recall", "literal query"];
        if !related {
            expected.push("--no-related");
        }
        expected.extend(["--limit", "3"]);
        assert_eq!(
            tool_argv(
                "memory_recall",
                &json!({"query":"literal query","related":related,"limit":3})
            )?,
            expected
        );
    }
    Ok(())
}

#[test]
fn remember_relationship_arguments_preserve_order_and_reject_wrong_types() -> Result<(), String> {
    assert_eq!(
        tool_argv(
            "memory_remember",
            &json!({
                "content":"literal content", "supersedes":"old-id", "see_also":["a", "b"]
            })
        )?,
        [
            "remember",
            "literal content",
            "--supersedes",
            "old-id",
            "--see-also",
            "a,b"
        ]
    );
    for arguments in [
        json!({"content":"literal content"}),
        json!({"content":"literal content","see_also":[]}),
    ] {
        assert_eq!(
            tool_argv("memory_remember", &arguments)?,
            ["remember", "literal content"]
        );
    }
    for invalid in [json!(null), json!("a,b"), json!({"id":"a"})] {
        assert_eq!(
            tool_argv(
                "memory_remember",
                &json!({"content":"literal content","see_also":invalid})
            ),
            Err("see_also must be an array".to_owned())
        );
    }
    for invalid in [json!(["a", 1]), json!([null]), json!([true])] {
        assert_eq!(
            tool_argv(
                "memory_remember",
                &json!({"content":"literal content","see_also":invalid})
            ),
            Err("see_also IDs must be strings".to_owned())
        );
    }
    Ok(())
}

#[test]
fn envelope_status_and_collection_contracts_are_validated_without_execution() -> Result<(), String>
{
    // These are parser fixtures only, not receipts for executed business operations.
    let original = json!({
        "command":"status", "status":"ok", "summary":{},
        "items":[], "actions":[], "errors":[], "details":{}
    });
    for status in ["ok", "warn", "fail", "skip", "pending"] {
        let mut envelope = original.clone();
        envelope["status"] = json!(status);
        ensure_envelope(&envelope)?;
    }
    let mut invalid = original.clone();
    invalid["status"] = json!("unknown");
    assert_eq!(
        ensure_envelope(&invalid),
        Err("CLI ResultEnvelope has invalid status: unknown".to_owned())
    );
    invalid["status"] = json!(false);
    assert_eq!(
        ensure_envelope(&invalid),
        Err("CLI ResultEnvelope status must be a string".to_owned())
    );
    for key in ["items", "actions", "errors"] {
        for value in [json!(null), json!({}), json!("[]")] {
            let mut envelope = original.clone();
            envelope[key] = value;
            assert_eq!(
                ensure_envelope(&envelope),
                Err("CLI ResultEnvelope items/actions/errors must be arrays".to_owned())
            );
        }
    }
    Ok(())
}
