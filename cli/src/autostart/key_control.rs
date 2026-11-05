//! Fixed key control. Passwords and issued codes never enter recovery metadata.
//! Mount beside control.rs under launch_authorization; shared entry points are wired by the caller.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::key_control::*;
use respire_protocol::{HostAuthIdentity, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Original {
    schema_version: u32,
    root: PathBuf,
    profile: PathBuf,
    operation_id: String,
    key: String,
    source_identity: HostAuthIdentity,
    operation: HostKeyOperation,
    token: String,
    coordinator: String,
    was_serving: bool,
    store_ready: bool,
    sent: bool,
}

pub(crate) struct KeyRecoveryRequired {
    pub operation_id: String,
    pub source_profile: PathBuf,
}
impl std::fmt::Display for KeyRecoveryRequired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "key_outcome_unknown operation_id={}; query this original operation; do not repeat the key operation", self.operation_id)
    }
}
impl std::fmt::Debug for KeyRecoveryRequired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(self, out) }
}
impl std::error::Error for KeyRecoveryRequired {}

impl Original {
    fn recovery(&self) -> KeyRecoveryRequired {
        KeyRecoveryRequired { operation_id: self.operation_id.clone(), source_profile: self.profile.clone() }
    }
    fn fingerprint(&self) -> Result<String> {
        Ok(super::hash(&serde_json::to_vec(&json!({"schema_version":HOST_KEY_SCHEMA_V,
            "method":"control.key", "root":self.root,"profile":self.profile,
            "source_identity":self.source_identity,"operation":self.operation}))?))
    }
}

enum Action<'a> {
    Reset { operation: HostKeyOperation, input: HostKeyInput, resume: Option<&'a HostKeyResult> },
    Query(&'a str),
    Rollback(&'a str),
}

pub(crate) fn control_super_reset(super_pass: Option<&str>) -> Result<ResultEnvelope> {
    control_super_reset_step(None, HostKeyInput {
        password: None, super_password: super_pass.map(str::to_owned),
        ..HostKeyInput::default()
    }, None)
}

pub(crate) fn control_super_reset_step(
    addr: Option<&str>, input: HostKeyInput, resume: Option<&HostKeyResult>,
) -> Result<ResultEnvelope> {
    control_key(Action::Reset { operation: HostKeyOperation::SuperReset { addr: addr.map(str::to_owned) }, input, resume })
}

pub(crate) fn control_key_result(operation_id: &str) -> Result<ResultEnvelope> {
    control_key(Action::Query(operation_id))
}

pub(crate) fn control_key_rollback(operation_id: &str) -> Result<ResultEnvelope> {
    control_key(Action::Rollback(operation_id))
}

pub(crate) fn control_fivekeys(
    operation: HostKeyOperation, input: HostKeyInput, resume: Option<&HostKeyResult>,
) -> Result<ResultEnvelope> {
    anyhow::ensure!(matches!(operation, HostKeyOperation::Fivekeys { .. }), "not a fivekeys intent");
    control_key(Action::Reset { operation, input, resume })
}

fn execute_method(operation: &HostKeyOperation) -> &'static str {
    match operation { HostKeyOperation::SuperReset { .. } => HOST_KEY_SUPER_RESET_METHOD,
        HostKeyOperation::Fivekeys { .. } => HOST_KEY_FIVEKEYS_METHOD }
}

fn canonical(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.to_string() == value)
}

fn read_original(path: &Path) -> Result<Option<(Original, String)>> {
    for ancestor in path.ancestors() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(!metadata.file_type().is_symlink(), "key recovery path is a symlink");
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(metadata.file_attributes() & 0x400 == 0, "key recovery path is a reparse point");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(metadata.is_file() && metadata.len() <= 16 * 1024, "invalid key recovery file");
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 16 * 1024, "key recovery context exceeds its bound");
    let original = serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid key recovery metadata"))?;
    Ok(Some((original, super::hash(&bytes))))
}

fn control_key(action: Action<'_>) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("private key control")?;
    anyhow::ensure!(super::lifecycle::current_boot_token().is_none(), "key control must own maintenance");
    let takeover = crate::runtime_policy::takeover_lock()?;
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = respire_client_host::config::control_roots()?;
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&profile)?;
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let path = root.join("runtime/autostart/key-control.json");
    let active = read_original(&path)?;
    let (saved, archived) = if active.is_some() { (active, false) } else {
        match &action {
            Action::Query(id) | Action::Rollback(id) => {
                anyhow::ensure!(canonical(id), "key query requires a canonical original operation ID");
                (read_original(&archive_path(&root, id))?, true)
            }
            _ => (None, false),
        }
    };
    let expected = super::control::identity(&profile)?;
    let registration = super::read_registration(&root)?;
    let managed = registration.as_ref().filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    anyhow::ensure!(owner.is_some() || !crate::rpc::endpoint_path().try_exists()?,
        "key control has a recorded owner without verifiable health");
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "key control cannot identify the registered supervisor's owner");
    }
    if let Some(owner) = owner.as_ref() {
        super::model_control::verify_model_owner(owner, &root, &profile, managed, &binary, &manifest,
            Some(&account(&expected, &profile)))?;
    }
    let (mut original, mut digest, mut maintenance, reconnect) = if let Some((original, digest)) = saved {
        anyhow::ensure!(original.schema_version == HOST_KEY_SCHEMA_V && canonical(&original.operation_id)
            && original.key == original.operation_id && canonical(&original.token), "invalid key recovery binding");
        anyhow::ensure!(original.root == root && (original.profile == profile
            || matches!(original.operation, HostKeyOperation::Fivekeys { .. })),
            "key recovery belongs to another selection");
        match &action {
            Action::Reset { operation, resume, .. } => {
                anyhow::ensure!(serde_json::to_value(operation)? == serde_json::to_value(&original.operation)?,
                    "key continuation changed the original operation");
                if let Some(receipt) = resume { validate_receipt(receipt, &original)?; }
            }
            Action::Query(id) | Action::Rollback(id) => anyhow::ensure!(*id == original.operation_id,
                "key recovery requires the original operation ID"),
        }
        let maintenance = super::lifecycle::resume_key_maintenance(
            &root, &profile, &original.profile, &original.token, &original.coordinator)?;
        (original, digest, maintenance, true)
    } else {
        let operation = match &action {
            Action::Reset { operation, resume: None, .. } => operation.clone(),
            _ => anyhow::bail!("original key recovery metadata is missing; no new operation was sent"),
        };
        let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
        let binding = maintenance.auth_launch_binding(&profile)?.context("key control requires persistent Paused maintenance")?;
        let id = uuid::Uuid::new_v4().to_string();
        let original = Original { schema_version: HOST_KEY_SCHEMA_V, root: root.clone(), profile: profile.clone(),
            operation_id: id.clone(), key: id, source_identity: expected, operation,
            token: super::lifecycle::current_boot_token().context("key maintenance token missing")?,
            coordinator: binding["coordinator_id"].as_str().context("key coordinator missing")?.to_owned(),
            was_serving: owner.is_some(), store_ready: owner.as_ref().is_some_and(|health| health.store_ready), sent: false };
        let bytes = serde_json::to_vec(&original)?;
        super::private_write(&path, &bytes, None)?;
        let digest = super::hash(&bytes);
        (original, digest, maintenance, false)
    };
    let mut finished = false;
    let result: Result<ResultEnvelope> = (|| {
        maintenance.auth_launch_binding(&profile)?.context("key control requires an actual Paused grant")?;
        maintenance.check_account_runtime()?;
        if let Some(owner) = owner.as_ref() { maintenance.drain_runtime(owner)?; }
        anyhow::ensure!(!crate::net_rpc::port_is_open(), "key control requires a drained Runtime");
        let deadline = Instant::now() + Duration::from_secs(185);
        let mut receipt = if original.sent {
            exchange(&takeover, &mut maintenance, &original, HOST_KEY_RESULT_METHOD, None, deadline)?
        } else {
            anyhow::ensure!(matches!(&action, Action::Reset { resume: None, .. }),
                "key operation was not sent; explicit queries cannot admit it");
            anyhow::ensure!(super::control::identity(&profile)? == original.source_identity,
                "key source identity changed before admission");
            // Persist uncertainty before sending any operation; a failed write is never retried.
            original.sent = true;
            let bytes = serde_json::to_vec(&original)?;
            super::private_write(&path, &bytes, Some(&digest))?;
            digest = super::hash(&bytes);
            let input = match &action { Action::Reset { input, .. } => Some(input), _ => None };
            exchange(&takeover, &mut maintenance, &original, execute_method(&original.operation), input, deadline)?
        };
        if reconnect && receipt.outcome == HostKeyOutcome::AwaitingInput {
            match &action {
                Action::Reset { input, resume: Some(previous), .. } if previous.outcome == HostKeyOutcome::AwaitingInput => {
                    receipt = exchange(&takeover, &mut maintenance, &original, execute_method(&original.operation), Some(input), deadline)?;
                }
                Action::Rollback(_) => {
                    receipt = exchange(&takeover, &mut maintenance, &original, HOST_KEY_ROLLBACK_METHOD, None, deadline)?;
                }
                _ => {}
            }
        } else if reconnect && receipt.outcome == HostKeyOutcome::Pending && matches!(action, Action::Rollback(_)) {
            receipt = exchange(&takeover, &mut maintenance, &original, HOST_KEY_ROLLBACK_METHOD, None, deadline)?;
        }
        if matches!(original.operation, HostKeyOperation::Fivekeys { .. })
            && (receipt.verification_required || receipt.outcome == HostKeyOutcome::Committed) {
            let target = account_view(&receipt)?;
            maintenance.start_account_target(&original.profile, &original.operation_id, &target, false)?;
            if receipt.verification_required {
                receipt = exchange_complete(&takeover, &mut maintenance, &original, &receipt, deadline)?;
                anyhow::ensure!(receipt.outcome == HostKeyOutcome::Committed && !receipt.verification_required,
                    "fivekeys completion is not committed; retain the original operation");
            }
        }
        match receipt.outcome {
            HostKeyOutcome::Unknown => anyhow::bail!("key_outcome_unknown: query the original operation"),
            HostKeyOutcome::Pending | HostKeyOutcome::AwaitingInput => {
                maintenance.mark(super::lifecycle::Phase::Paused)?;
                let mut output = ResultEnvelope::new("key-control", Status::Pending, serde_json::to_value(receipt)?, Vec::new());
                output.actions.push("supply only the requested inputs using this same operation; query after uncertainty".into());
                return Ok(output);
            }
            HostKeyOutcome::Committed | HostKeyOutcome::RolledBack => {}
        }
        unchanged(&original, &receipt, &binary, &manifest)?;
        let restore_owner = if archived { owner.is_some() } else { original.was_serving };
        let restore_store = if archived { owner.as_ref().is_some_and(|health| health.store_ready) } else { original.store_ready };
        let fivekeys = matches!(original.operation, HostKeyOperation::Fivekeys { .. });
        if restore_owner && !(fivekeys && receipt.outcome == HostKeyOutcome::Committed) {
            maintenance.start_account_runtime()?;
            let restored = crate::rpc::probe_runtime()?.context("original key owner did not resume")?;
            let (_, selected) = respire_client_host::config::control_roots()?;
            let selected = selected.canonicalize()?;
            super::model_control::verify_model_owner(&restored, &root, &selected, managed, &binary, &manifest,
                Some(&account(&receipt.identity, &selected)))?;
            anyhow::ensure!(!restore_store || restored.store_ready,
                "restored key owner did not confirm its original store readiness");
        }
        unchanged(&original, &receipt, &binary, &manifest)?;
        maintenance.finish()?;
        finished = true;
        if !archived {
            // Retain only the original nonsecret binding so an explicit O query can recover lost output.
            let archive = archive_path(&root, &original.operation_id);
            let bytes = serde_json::to_vec(&original)?;
            match read_original(&archive)? {
                Some((_, hash)) => anyhow::ensure!(hash == super::hash(&bytes), "key result binding archive changed"),
                None => super::private_write(&archive, &bytes, None)?,
            }
            anyhow::ensure!(read_original(&path)?.as_ref().map(|(_, hash)| hash.as_str()) == Some(digest.as_str()),
                "key recovery metadata changed before cleanup");
            std::fs::remove_file(&path)?;
            respire_spawn::durable::sync_directory(path.parent().context("key recovery parent missing")?)
                .map_err(|_| anyhow::anyhow!("key operation completed; recovery namespace cleanup needs verification"))?;
        }
        if receipt.outcome == HostKeyOutcome::Committed && fivekeys {
            let HostKeyOperation::Fivekeys { user, addr, .. } = &receipt.operation else { anyhow::bail!("fivekeys intent missing"); };
            return Ok(ResultEnvelope::new("fivekeys", Status::Ok, json!({"ok":true,"user":user,"addr":addr}),
                vec![Item::new("session", Status::Ok, "ready")]));
        }
        if receipt.outcome == HostKeyOutcome::Committed {
            let issued = receipt.super_password.context("verified key receipt has no issued code")?;
            return Ok(ResultEnvelope::new("super-reset", Status::Ok, json!({"ok":true,"super":issued}),
                vec![Item::new("password", Status::Ok, "issued")]));
        }
        Ok(ResultEnvelope::new("key-control", Status::Ok, serde_json::to_value(receipt)?, Vec::new()))
    })();
    result.map_err(|error| {
        let error = if finished { error.context("key operation verified and maintenance finished; cleanup needs verification") }
        else {
            let pause = maintenance.mark(super::lifecycle::Phase::Paused);
            error.context(format!("key operation retained; Paused publication: {pause:?}"))
        };
        error.context(original.recovery())
    })
}

fn archive_path(root: &Path, operation_id: &str) -> PathBuf {
    root.join("runtime/autostart/key-results").join(format!("{operation_id}.json"))
}

fn account(identity: &HostAuthIdentity, profile: &Path) -> String {
    match identity { HostAuthIdentity::Bound { account_id, .. } => account_id.clone(),
        _ => super::hash(profile.display().to_string().as_bytes()) }
}

fn account_view(receipt: &HostKeyResult) -> Result<respire_protocol::host_control::HostAuthAccountResult> {
    use respire_protocol::host_control::{HostAuthAccountOutcome, HostAuthAccountResult};
    anyhow::ensure!(matches!(receipt.operation, HostKeyOperation::Fivekeys { .. })
        && (receipt.verification_required || receipt.outcome == HostKeyOutcome::Committed),
        "fivekeys has no applied target receipt");
    // This view reuses lifecycle attestation, not account authentication/admission.
    Ok(HostAuthAccountResult { operation_id: receipt.operation_id.clone(),
        outcome: if receipt.verification_required { HostAuthAccountOutcome::AwaitingVerification } else { HostAuthAccountOutcome::Committed },
        source_profile: receipt.source_profile.clone(), target_profile: receipt.target_profile.clone(),
        account_id: receipt.account_id.clone(), session_sha256: receipt.session_sha256.clone(),
        super_password: None, login: None })
}

fn unchanged(original: &Original, receipt: &HostKeyResult, binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest) -> Result<()> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    let (current, release) = super::model_control::installed_model_runtime()?;
    let selected = if matches!(original.operation, HostKeyOperation::Fivekeys { .. })
        && receipt.outcome == HostKeyOutcome::Committed { receipt.target_profile.as_ref().context("fivekeys target missing")? }
        else { &original.profile };
    anyhow::ensure!(root.canonicalize()? == original.root && profile.canonicalize()? == *selected
        && current == binary && release.version == manifest.version && release.sha256.eq_ignore_ascii_case(&manifest.sha256)
        && super::control::identity(selected)? == receipt.identity, "key operation installation, profile, image or identity changed");
    Ok(())
}

fn exchange(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &Original, method: &str, input: Option<&HostKeyInput>, deadline: Instant,
) -> Result<HostKeyResult> {
    exchange_inner(takeover, maintenance, original, method, input, None, deadline)
}

fn exchange_complete(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &Original, receipt: &HostKeyResult, deadline: Instant,
) -> Result<HostKeyResult> {
    let view = account_view(receipt)?;
    exchange_inner(takeover, maintenance, original, HOST_KEY_COMPLETE_METHOD, None, Some(&view), deadline)
}

fn exchange_inner(takeover: &LibraryLock, maintenance: &mut super::lifecycle::Maintenance,
    original: &Original, method: &str, input: Option<&HostKeyInput>,
    completion: Option<&respire_protocol::host_control::HostAuthAccountResult>, deadline: Instant,
) -> Result<HostKeyResult> {
    let input = input.map(|input| HostKeyInput { password: input.password.clone(), super_password: input.super_password.clone(),
        account_secret: input.account_secret.clone(), totp: input.totp.clone() });
    let envelope = super::control::auth_exchange(takeover, maintenance, deadline,
        completion.map(|receipt| (original.profile.as_path(), original.operation_id.as_str(), receipt, false)),
        |binding, identity| {
            anyhow::ensure!(binding.installation_root == original.root && (binding.profile == original.profile
                || matches!(original.operation, HostKeyOperation::Fivekeys { .. })),
                "key control launch selection changed");
            let params = HostKeyParams { schema_version: HOST_KEY_SCHEMA_V, binding, identity,
                source_identity: original.source_identity.clone(), operation: original.operation.clone(), input };
            let argument = serde_json::to_string(&params).map_err(|_| anyhow::anyhow!("cannot encode private key request"))?;
            Ok(RpcRequest { v: respire_commands::rpc_client::PROTOCOL_V, id: uuid::Uuid::new_v4().to_string(),
                method: method.to_owned(), args: vec![argument], scope: None,
                operation_id: Some(original.operation_id.clone()), idempotency_key: Some(original.key.clone()),
                parent_operation_id: None, queue_wait_ms: None, lifecycle: None })
        }, |response, request, profile, pid| validate_response(response, request, profile, pid, original),
        |_| anyhow::anyhow!("private key exchange failed; query the original operation"))?;
    serde_json::from_value(envelope.summary).map_err(|_| anyhow::anyhow!("invalid private key receipt"))
}

fn validate_receipt(receipt: &HostKeyResult, original: &Original) -> Result<()> {
    anyhow::ensure!(receipt.operation_id == original.operation_id && receipt.fingerprint == original.fingerprint()?
        && serde_json::to_value(&receipt.operation)? == serde_json::to_value(&original.operation)?
        && receipt.source_profile == original.profile, "key receipt changed its original intent or source");
    if let HostKeyOperation::Fivekeys { user, .. } = &original.operation {
        anyhow::ensure!(receipt.super_password.is_none()
            && receipt.required_inputs.iter().all(|field| matches!(field.as_str(), "password" | "super_password" | "account_secret" | "totp")),
            "invalid fivekeys secret or requested input");
        if receipt.verification_required || receipt.outcome == HostKeyOutcome::Committed {
            let target = receipt.target_profile.as_ref().context("fivekeys receipt target missing")?;
            let (_, selected) = respire_client_host::config::control_roots()?;
            let account = super::hash(user.as_bytes());
            anyhow::ensure!(target.is_absolute() && target.canonicalize()? == *target && selected.canonicalize()? == *target
                && receipt.required_inputs.is_empty() && receipt.account_id.as_ref() == Some(&account)
                && matches!(&receipt.identity, HostAuthIdentity::Bound { account_id, session_sha256 }
                    if account_id == &account && Some(session_sha256) == receipt.session_sha256.as_ref())
                && super::control::identity(target)? == receipt.identity
                && if receipt.verification_required { receipt.outcome == HostKeyOutcome::Pending }
                    else { receipt.outcome == HostKeyOutcome::Committed }, "fivekeys applied receipt identity mismatch");
        } else {
            anyhow::ensure!(receipt.account_id.is_none() && receipt.session_sha256.is_none()
                && receipt.identity == original.source_identity, "unpublished fivekeys changed its source identity");
            anyhow::ensure!((receipt.outcome == HostKeyOutcome::AwaitingInput) == !receipt.required_inputs.is_empty(),
                "fivekeys input status mismatch");
        }
        return Ok(());
    }
    anyhow::ensure!(!receipt.verification_required
        && receipt.target_profile.as_ref().is_none_or(|path| path == &original.profile), "super-reset changed its profile");
    let source_account = match &original.source_identity {
        HostAuthIdentity::Bound { account_id, .. } => account_id,
        _ => anyhow::bail!("super-reset requires an original bound account"),
    };
    let (account, digest) = match &receipt.identity {
        HostAuthIdentity::Bound { account_id, session_sha256 } => (account_id, session_sha256),
        _ => anyhow::bail!("key receipt lost its bound account"),
    };
    anyhow::ensure!(account == source_account, "key receipt changed its original account");
    anyhow::ensure!(receipt.required_inputs.iter().all(|key| matches!(key.as_str(), "password" | "super_password")),
        "unsupported key continuation inputs");
    if receipt.outcome == HostKeyOutcome::Committed {
        anyhow::ensure!(receipt.target_profile.as_ref() == Some(&original.profile)
            && receipt.account_id.as_ref() == Some(account) && receipt.session_sha256.as_ref() == Some(digest)
            && receipt.required_inputs.is_empty() && receipt.super_password.as_ref().is_some_and(|code| !code.is_empty()),
            "invalid committed key receipt");
    } else {
        anyhow::ensure!(receipt.super_password.is_none() && receipt.session_sha256.is_none() && receipt.account_id.is_none()
            && receipt.identity == original.source_identity, "noncommitted key receipt exposed a code or changed its source");
        if receipt.outcome == HostKeyOutcome::AwaitingInput {
            anyhow::ensure!(!receipt.required_inputs.is_empty(), "missing key continuation inputs");
        } else if receipt.outcome != HostKeyOutcome::RolledBack {
            anyhow::ensure!(receipt.required_inputs.is_empty(), "unexpected key input request");
        }
    }
    Ok(())
}

fn validate_response(response: RpcResponse<ResultEnvelope>, request: &RpcRequest, profile: &Path,
    pid: u32, original: &Original) -> Result<ResultEnvelope> {
    anyhow::ensure!(response.v == request.v && response.id == request.id && response.pid == Some(pid)
        && response.bin == "rsrs-runtime" && response.scope.is_none() && response.web_url.is_none()
        && response.operation_id.as_deref() == Some(original.operation_id.as_str())
        && response.idempotency_key.as_deref() == Some(original.key.as_str()), "key response binding mismatch");
    if let Some(path) = response.data_dir.as_deref() {
        anyhow::ensure!(Path::new(path).canonicalize()? == profile, "key response profile mismatch");
    }
    let envelope = response.envelope.context("private key receipt missing")?;
    anyhow::ensure!(envelope.command == "key-control" && envelope.details.is_null() && envelope.actions.is_empty()
        && envelope.items.len() == 2 && envelope.related.is_empty(),
        "invalid key response envelope");
    for (name, value) in [("control_ready", "true"), ("store_ready", "false")] {
        let mut items = envelope.items.iter().filter(|item| item.name == name);
        anyhow::ensure!(items.next().is_some_and(|item| item.value == value && if name == "control_ready" {
            matches!(item.status, Status::Ok) } else { matches!(item.status, Status::Skip) }) && items.next().is_none(),
            "key helper readiness mismatch");
    }
    let receipt: HostKeyResult = serde_json::from_value(envelope.summary.clone())
        .map_err(|_| anyhow::anyhow!("invalid private key receipt shape"))?;
    validate_receipt(&receipt, original)?;
    let (_, selected) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(super::control::identity(&selected.canonicalize()?)? == receipt.identity,
        "key receipt does not match the selected session");
    match receipt.outcome {
        HostKeyOutcome::Committed | HostKeyOutcome::RolledBack => anyhow::ensure!(response.ok && response.exit == 0
            && response.code.is_none() && response.error.is_none() && matches!(envelope.status, Status::Ok)
            && envelope.errors.is_empty(), "invalid terminal key response"),
        HostKeyOutcome::Pending | HostKeyOutcome::AwaitingInput => anyhow::ensure!(response.ok && response.exit == 0
            && response.code.is_none() && response.error.is_none() && matches!(envelope.status, Status::Pending)
            && envelope.errors.is_empty(), "invalid pending key response"),
        HostKeyOutcome::Unknown => anyhow::ensure!(!response.ok && response.exit == 2
            && response.code.as_deref() == Some("key_outcome_unknown") && matches!(envelope.status, Status::Fail),
            "invalid unknown key response"),
    }
    Ok(envelope)
}
