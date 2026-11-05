use anyhow::{ensure, Context, Result};

use crate::output::{self, Item, ResultEnvelope, Status};
use crate::{progress, rpc, runtime_policy};

pub(crate) fn run(remote: bool, check_update: bool, fix: bool) -> Result<()> {
    let client_only = runtime_policy::client_only();
    if check_update || fix {
        runtime_policy::require_host("doctor repair and CLI update checks")?;
    }
    if client_only {
        return crate::emit_result(runtime_doctor(remote)?);
    }

    crate::prepare_command_runtime()?;
    crate::autostart::check_managed_request()?;
    let mut host = host_rows(check_update);
    let mut result = runtime_doctor(remote)?;
    if fix {
        let repair = repair(&result)?;
        if !matches!(repair.status, Status::Skip) {
            result = runtime_doctor(remote)?;
        }
        host.push(repair);
    }
    if diagnostics_paused(&result) {
        result.command = "doctor".to_owned();
        result.items.push(Item::new(
            "Runtime diagnostics",
            Status::Warn,
            "Memory is off; Runtime diagnostics were not executed",
        ));
    }

    let runtime_status = result.status;
    result.items.extend(host);
    result.status = output::status_from_items(&result.items);
    if matches!(runtime_status, Status::Fail) || !result.errors.is_empty() {
        result.status = Status::Fail;
    } else if matches!(runtime_status, Status::Warn | Status::Pending)
        && matches!(result.status, Status::Ok)
    {
        result.status = Status::Warn;
    }
    let summary = result
        .summary
        .as_object_mut()
        .context("doctor summary missing")?;
    summary.insert("version".into(), serde_json::json!(respire::VERSION));
    summary.insert("scope".into(), serde_json::json!("host+runtime"));
    summary.insert("host_checks".into(), serde_json::json!("completed"));
    for (name, status) in [
        ("pass", Status::Ok),
        ("warn", Status::Warn),
        ("fail", Status::Fail),
        ("skip", Status::Skip),
    ] {
        let count = result
            .items
            .iter()
            .filter(|row| row.status.as_str() == status.as_str())
            .count();
        summary.insert(name.into(), serde_json::json!(count));
    }
    summary.insert("total".into(), serde_json::json!(result.items.len()));
    crate::emit_result(result)
}

fn runtime_doctor(remote: bool) -> Result<ResultEnvelope> {
    let mut args = vec!["doctor".to_owned()];
    if remote {
        args.push("--remote".to_owned());
    }
    if let Some(id) = progress::remote_id() {
        args.extend(["--progress-id".to_owned(), id]);
    }
    let result: ResultEnvelope = serde_json::from_value(rpc::query_json(args)?)?;
    // The off-mode gate returns before doctor dispatch and never opens the store.
    if result.command == "memory" && diagnostics_paused(&result) {
        return Ok(result);
    }
    ensure!(
        result.command == "doctor" && result.summary["scope"] == "runtime",
        "doctor requires an independent Runtime with scope=runtime diagnostics; upgrade the Runtime"
    );
    Ok(result)
}

fn diagnostics_paused(result: &ResultEnvelope) -> bool {
    result.summary["mode"] == "off" && result.summary["skipped"] == true
}

fn host_rows(check_update: bool) -> Vec<Item> {
    let mut rows = Vec::new();
    progress::phase("Checking host configuration", "Checking host configuration");
    match respire::migration::pending_legacy_profiles() {
        Ok(profiles) if !profiles.is_empty() => rows.push(Item::new(
            "migration",
            Status::Warn,
            format!(
                "{} legacy account(s) need explicit migration; use rsrs migrate",
                profiles.len()
            ),
        )),
        Ok(_) => {}
        Err(error) => rows.push(Item::new("migration", Status::Fail, format!("{error:#}"))),
    }
    rows.push(match respire::auth::load_local_session() {
        Ok(_) => Item::new("session", Status::Ok, "Five-keys complete, can unlock"),
        Err(error) => Item::new("session", Status::Fail, format!("{error:#}")),
    });
    rows.push(match respire::inject::targets() {
        Ok(targets) => {
            let detected = targets
                .iter()
                .filter(|target| target.likely_installed)
                .count();
            let fresh = targets
                .iter()
                .filter(|target| target.likely_installed && target.state == "fresh")
                .count();
            let status = if detected == 0 {
                Status::Skip
            } else if fresh == detected {
                Status::Ok
            } else if fresh == 0 {
                Status::Fail
            } else {
                Status::Warn
            };
            Item::new(
                "inject",
                status,
                format!("{fresh}/{detected} injected and fresh ({detected} detected)"),
            )
        }
        Err(error) => Item::new("inject", Status::Fail, format!("{error:#}")),
    });
    let binary = crate::mcp::stable_bin_path();
    rows.push(match std::fs::metadata(&binary) {
        Ok(metadata) if metadata.is_file() => {
            Item::new("mcp bin", Status::Ok, binary.display().to_string())
        }
        Ok(_) => Item::new(
            "mcp bin",
            Status::Fail,
            format!("{} is not a file", binary.display()),
        ),
        Err(error) => Item::new(
            "mcp bin",
            Status::Fail,
            format!("{}: {error}", binary.display()),
        ),
    });
    rows.push(if !respire::update_check::enabled() {
        Item::new("CLI version", Status::Skip, "Update check disabled")
    } else if !check_update {
        Item::new(
            "CLI version",
            Status::Skip,
            "Version check not requested; use doctor --check-update to refresh",
        )
    } else {
        progress::phase(
            "Checking CLI version; waiting for version registry",
            "Checking CLI version; waiting for version registry",
        );
        match respire::update_check::check(true) {
            Some(status) => Item::new(
                "CLI version",
                if status.outdated {
                    Status::Warn
                } else {
                    Status::Ok
                },
                format!(
                    "{} ({})",
                    status.comparison(),
                    if status.cached {
                        "cached"
                    } else {
                        "just checked"
                    }
                ),
            ),
            None => Item::new(
                "CLI version",
                Status::Skip,
                "Version check unavailable; no update result verified",
            ),
        }
    });
    rows
}

fn repair(diagnostic: &ResultEnvelope) -> Result<Item> {
    if diagnostics_paused(diagnostic) || respire::service::off_mode() {
        return Ok(Item::new(
            "host repair",
            Status::Skip,
            "Memory is off; repair skipped without reading selection or preparing models/indexes",
        ));
    }
    if diagnostic.details["model_operation"]["active"] == true {
        return Ok(Item::new(
            "host repair",
            Status::Warn,
            "Model operation in progress; repair deferred without changing assets",
        ));
    }
    let needs_assets = diagnostic
        .items
        .iter()
        .any(|row| row.name == "embedder" && !matches!(row.status, Status::Ok));
    let needs_index = diagnostic
        .items
        .iter()
        .any(|row| row.name == "model index" && !matches!(row.status, Status::Ok));
    if !needs_assets && !needs_index {
        return Ok(Item::new(
            "host repair",
            Status::Ok,
            "No asset or index repair requested by Runtime diagnostics",
        ));
    }
    respire::service::ensure_writable()?;
    let mirror = respire::model_install::mirror_from_env();
    if needs_assets {
        rpc::change_host_assets(|| {
            ensure!(
                !respire::service::off_mode(),
                "memory was paused before asset maintenance; selection was not read"
            );
            // Read selection only after the owner drains; never open a business engine here.
            if let Some(selection) = respire_app::embedding::saved_selection()? {
                respire_app::embedding::prepare(&selection, |name, _, _| {
                    progress::phase(name, name);
                    Ok(())
                })?;
            } else {
                respire::model_install::install_m3(mirror.as_deref())?;
            }
            Ok(())
        })?;
        ensure!(
            !respire::service::off_mode(),
            "memory was paused after asset maintenance; Runtime preparation was not requested"
        );
        rpc::prepare_model(mirror.as_deref().unwrap_or("auto"))?;
    }
    ensure!(
        !respire::service::off_mode(),
        "memory is paused; Runtime index preparation was not requested"
    );
    let response = rpc::call_method("index.prepare", Vec::new(), false)?;
    ensure!(
        response.ok,
        "{}",
        response
            .error
            .as_deref()
            .unwrap_or("Runtime index preparation failed")
    );
    Ok(Item::new("host repair", Status::Ok, "Host assets prepared if needed; Runtime preparation/indexing requested; diagnostic results follow"))
}
