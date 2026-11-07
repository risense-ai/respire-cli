//! Hidden runtime help must be usable before host/profile setup, including in a sandbox.
use clap::Parser;
use respire_commands::{
    autostart::RuntimeCommand,
    cli_def::{Cli, Command as CliCommand},
};
use serde_json::Value;
use std::process::Command;

#[test]
fn runtime_help_is_static_without_a_profile_or_lifecycle_action() -> anyhow::Result<()> {
    let context = r#"{"scope":{"account_id":"account-1","instance_id":"instance-1","generation":7},"operation_id":"operation-1","idempotency_key":"key-1"}"#;
    let parsed = Cli::try_parse_from(["rsrs", "runtime", "result", "--context", context])?;
    let Some(CliCommand::Runtime {
        command: RuntimeCommand::Result { context: parsed },
    }) = parsed.command
    else {
        anyhow::bail!("runtime result did not parse as a context query");
    };
    assert_eq!(
        serde_json::to_value(parsed)?,
        serde_json::from_str::<Value>(context)?
    );

    let operation = "7c633a08-9077-4710-882e-ac3d2998ab8b";
    for flags in [
        vec!["auth-result", "--operation-id", operation],
        vec!["account-result", "--operation-id", operation, "--source-profile", "original-profile", "--register"],
        vec!["account-rollback", "--operation-id", operation, "--source-profile", "original-profile", "--confirm"],
    ] {
        Cli::try_parse_from(["rsrs", "runtime"].into_iter().chain(flags))?;
    }
    let root = tempfile::tempdir()?;
    for flags in [
        vec!["--runtime-internal", "--help"],
        vec!["--client-only", "--runtime-internal", "-h"],
        vec!["--json", "--runtime-internal", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(&flags)
            .env("HOME", root.path().join("absent-home"))
            .env("USERPROFILE", root.path().join("absent-home"))
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .env("RSRS_M3_DIR", root.path().join("absent-model"))
            .env("RSRS_RPC_PORT", "1")
            .env_remove("RSRS_JSON")
            .output()?;
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let text = if flags.contains(&"--json") {
            let v: Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(v["command"], "runtime-help");
            assert_eq!(v["status"], "ok");
            assert_eq!(v["summary"]["lifecycle"], "host-managed");
            v["summary"]["usage"].as_str().unwrap_or("").to_owned()
        } else {
            String::from_utf8(output.stdout)?
        };
        for flag in ["--status", "--stop", "--port", "--host", "--no-open"] {
            assert!(text.contains(flag), "missing {flag}");
        }
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    Ok(())
}

#[test]
fn help_cannot_swallow_a_stop_or_unknown_argument() -> anyhow::Result<()> {
    for flags in [
        vec!["--core-worker-internal"],
        vec!["--core-worker-internal", "--json"],
        vec!["--json", "--core-worker-internal"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("rsrs").chain(flags)).is_err());
    }
    assert!(Cli::try_parse_from(["rsrs", "runtime", "result"]).is_err());
    for operation in ["not-uuid", "12345678-1234-1234-8234-123456789abc", "7C633A08-9077-4710-882E-AC3D2998AB8B"] {
        assert!(Cli::try_parse_from(["rsrs", "runtime", "auth-result", "--operation-id", operation]).is_err());
    }
    assert!(Cli::try_parse_from(["rsrs", "runtime", "account-result", "--operation-id", "7c633a08-9077-4710-882e-ac3d2998ab8b"]).is_err());
    for context in [
        "not-json",
        "{}",
        r#"{"scope":{"account_id":"a","instance_id":"i","generation":1},"operation_id":"o","idempotency_key":"k","extra":true}"#,
        r#"{"scope":{"account_id":"a","instance_id":"i","generation":1,"extra":true},"operation_id":"o","idempotency_key":"k"}"#,
        r#"{"scope":{"account_id":"a","instance_id":"i","generation":"1"},"operation_id":"o","idempotency_key":"k"}"#,
    ] {
        assert!(
            Cli::try_parse_from(["rsrs", "runtime", "result", "--context", context]).is_err(),
            "accepted invalid operation context: {context}"
        );
    }

    let root = tempfile::tempdir()?;
    for flags in [
        vec!["--core-worker-internal", "--json"],
        vec!["--json", "--core-worker-internal"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args(flags)
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .env("RSRS_BIN_DIR", root.path().join("absent-bin"))
            .env("RSRS_M3_DIR", root.path().join("absent-model"))
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        let value: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(value["status"], "fail");
        assert_eq!(value["summary"]["reason"], "invalid_input");
        assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
    }
    for extra in ["--stop", "--unknown-flag"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rsrs"))
            .args([
                "--client-only",
                "--json",
                "--runtime-internal",
                "--help",
                extra,
            ])
            .env("RSRS_DATA_DIR", root.path().join("absent-profile"))
            .output()?;
        assert_eq!(output.status.code(), Some(2));
        let v: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(v["status"], "fail");
        assert_eq!(v["summary"]["reason"], "invalid_input");
        assert!(!root.path().join("absent-profile").exists());
    }
    Ok(())
}
