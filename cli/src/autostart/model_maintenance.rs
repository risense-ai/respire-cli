//! Host-owned component planning, configuration publication and file verification.
//! Only fresh core backend evidence comes from Runtime's preparation control.
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::output::{Item, ResultEnvelope, Status};
use respire_protocol::model_maintenance::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

#[cfg(windows)]
const PACKAGE_SOURCE: &str = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.ai.machinelearning/2.4.89/microsoft.windows.ai.machinelearning.2.4.89.nupkg";
#[cfg(windows)]
const PACKAGE_SHA256: &str = "5c68ecfb947223267abf159a023f5192ad42725e4e9cc995e7c1470dd54dff63";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Read only committed selection metadata. Never open Core or create a library.
pub(super) fn saved_selection(profile: &Path) -> Result<Option<serde_json::Value>> {
    use rusqlite::{Connection, OpenFlags, OptionalExtension};
    let current = profile.join("rsrs.db");
    let legacy = profile.join("onememory.db");
    anyhow::ensure!(
        !(current.try_exists()? && legacy.try_exists()?),
        "both rsrs.db and the legacy database exist; select the intended library explicitly"
    );
    let path = if current.try_exists()? {
        current
    } else {
        legacy
    };
    check_path(&path)?;
    if !path.try_exists()? {
        return Ok(None);
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let value: Option<String> = connection
        .query_row(
            "SELECT value FROM meta WHERE key=?1",
            ["embedding.active.selection.v1"],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .transpose()
}

fn local_plan(
    kind: ModelMaintenanceKind,
    root: &Path,
    profile: &Path,
) -> Result<ModelMaintenancePlan> {
    let selected = saved_selection(profile)?;
    if kind == ModelMaintenanceKind::ResetCpu {
        anyhow::ensure!(selected.is_none(),
            "library uses a model profile; use model switch PROFILE --backend onnx --engine cpu for CPU recovery");
    }
    let settings = cpu_settings(root)?;
    let registry = read_maintenance_file(&root.join("embedding-profiles-v1.json"))?;
    let selection_sha256 = hash(&serde_json::to_vec(&(
        MODEL_MAINTENANCE_SCHEMA_V,
        kind,
        root,
        profile,
        selected,
        registry,
        respire_client_host::env::var_os("RSRS_ENGINE"),
        respire_client_host::env::var_os("RSRS_MODEL_VARIANT"),
        respire_client_host::env::var_os("RSRS_M3_DIR"),
    ))?);
    let revision_sha256 = cpu_revision(&settings, &selection_sha256)?;
    let mut plan = ModelMaintenancePlan {
        kind,
        review: ModelMaintenanceReview {
            selection_sha256,
            revision_sha256,
        },
        preparation: None,
        catalog: None,
        uninstall_directory: None,
        cpu_candidate_sha256: None,
    };
    match kind {
        ModelMaintenanceKind::ResetCpu => {
            plan.cpu_candidate_sha256 = Some(hash(&cpu_candidate(&settings)?))
        }
        ModelMaintenanceKind::UninstallM3 => {
            let directory = local_m3_directory()?;
            check_path(&directory)?;
            anyhow::ensure!(
                !directory
                    .to_string_lossy()
                    .replace('\\', "/")
                    .contains("/usr/lib/respire/models"),
                "refusing to delete the system model dir"
            );
            plan.uninstall_directory = Some(directory);
        }
        ModelMaintenanceKind::InstallEngines => {
            #[cfg(windows)]
            {
                plan.catalog = Some(catalog_pin(root)?);
            }
        }
    }
    Ok(plan)
}

#[cfg(windows)]
fn catalog_pin(root: &Path) -> Result<ModelCatalogPin> {
    // These DLL pins were measured from the SHA-256-verified official NuGet package.
    let (arch, dll_size, dll_sha256) = if cfg!(target_arch = "x86_64") {
        (
            "x64",
            971504,
            "b401a47552a745755d65100828faefcf3df3895c759f96ac625ddf990711c8dd",
        )
    } else if cfg!(target_arch = "aarch64") {
        (
            "arm64",
            1091328,
            "457295ca2aec34db4aec7064cb401520bc85f29fd18f7e7bb9e25ddb849bedb1",
        )
    } else {
        anyhow::bail!("unsupported Windows ML architecture")
    };
    Ok(ModelCatalogPin {
        version: "2.4.89".into(),
        package_source: PACKAGE_SOURCE.into(),
        package_sha256: PACKAGE_SHA256.into(),
        archive_member: format!(
            "runtimes/win-{arch}/native/Microsoft.Windows.AI.MachineLearning.dll"
        ),
        destination: root.join("engines/winml-2.4.89/Microsoft.Windows.AI.MachineLearning.dll"),
        dll_size,
        dll_sha256: dll_sha256.into(),
    })
}

fn verify_catalog(pin: &ModelCatalogPin) -> Result<()> {
    check_path(&pin.destination)?;
    let metadata = fs::symlink_metadata(&pin.destination)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() == pin.dll_size,
        "installed catalog is not the pinned regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(&pin.destination)?
        .take(pin.dll_size + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 == pin.dll_size && hash(&bytes) == pin.dll_sha256,
        "installed catalog differs from the official host pin"
    );
    Ok(())
}

fn verify_maintenance(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    plan: &ModelMaintenancePlan,
    root: &Path,
    profile: &Path,
) -> Result<ModelMaintenanceReceipt> {
    let mut receipt = ModelMaintenanceReceipt {
        plan: plan.clone(),
        phase: ModelMaintenancePhase::Verify,
        verified: false,
        config_applied: false,
        npu_ready: false,
        warning: None,
    };
    {
        let _installation = LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
        let _library = LibraryLock::acquire(profile, Duration::ZERO)?;
        anyhow::ensure!(
            local_plan(plan.kind, root, profile)?.review == plan.review,
            "model maintenance selection/revision changed during file verification"
        );
        match plan.kind {
            ModelMaintenanceKind::UninstallM3 => {
                let directory = plan
                    .uninstall_directory
                    .as_deref()
                    .context("host uninstall target missing")?;
                anyhow::ensure!(
                    fs::symlink_metadata(directory)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                    "model uninstall not complete; target still exists or cannot be inspected"
                );
            }
            ModelMaintenanceKind::InstallEngines => {
                if let Some(pin) = &plan.catalog {
                    verify_catalog(pin)?;
                }
            }
            ModelMaintenanceKind::ResetCpu => {
                anyhow::bail!("CPU reset requires its configuration publication receipt")
            }
        }
    }
    #[cfg(windows)]
    if plan.kind == ModelMaintenanceKind::InstallEngines {
        let preparation = plan
            .preparation
            .as_ref()
            .context("NPU preparation selection missing")?;
        let verified = super::model_control::model_install_verify_locked(
            takeover,
            maintenance,
            &respire_protocol::ModelInstallIntent {
                for_engine: Some("npu".into()),
                ..Default::default()
            },
            &preparation.selection_sha256,
        )?;
        let backend = verified
            .assets
            .backend_load
            .as_ref()
            .context("Runtime backend verification missing")?;
        let evidence = backend.evidence.as_ref().with_context(|| {
            format!(
                "Runtime returned no inference evidence: state={:?}, reason={:?}",
                backend.state, backend.reason
            )
        })?;
        anyhow::ensure!(
            verified.assets.complete
                && verified.assets.missing.is_empty()
                && !verified.assets.assets.is_empty()
                && verified
                    .assets
                    .assets
                    .iter()
                    .all(|asset| asset.state == respire_protocol::AssetState::Complete)
                && backend.state == respire_protocol::BackendLoadState::Loaded
                && backend.reason.is_none()
                && evidence.contract == 1
                && evidence.status == respire_protocol::BackendLoadState::Loaded
                && evidence.ready
                && evidence.fresh_session
                && evidence.inference_completed,
            "Runtime did not verify fresh core backend inference"
        );
        receipt.plan.preparation = Some(verified);
        receipt.warning = Some("npu_provider_unverified: core inference passed; catalog integrity does not attest unpinned provider payloads".into());
    }
    #[cfg(not(windows))]
    {
        let _ = (takeover, maintenance);
    }
    anyhow::ensure!(
        local_plan(plan.kind, root, profile)?.review == plan.review,
        "model maintenance selection/revision changed during backend verification"
    );
    receipt.verified = true;
    Ok(receipt)
}

struct CpuSettings {
    target: PathBuf,
    target_bytes: Option<Vec<u8>>,
    source: PathBuf,
    source_bytes: Option<Vec<u8>>,
    value: serde_json::Value,
}

fn read_maintenance_file(path: &Path) -> Result<Option<Vec<u8>>> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "model maintenance path contains a symlink"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "model maintenance path contains a reparse point"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 64 * 1024,
        "model maintenance input must be a bounded regular file"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 64 * 1024,
        "model maintenance input is too large"
    );
    Ok(Some(bytes))
}

fn cpu_settings(root: &Path) -> Result<CpuSettings> {
    let target = root.join("inference.json");
    let target_bytes = read_maintenance_file(&target)?;
    let mut source = target.clone();
    let mut source_bytes = target_bytes.clone();
    if source_bytes.is_none() && respire_client_host::env::var_os("RSRS_DATA_DIR").is_none() {
        let home = dirs::home_dir()
            .or_else(|| respire_client_host::env::var_os("HOME").map(PathBuf::from))
            .or_else(|| respire_client_host::env::var_os("USERPROFILE").map(PathBuf::from));
        for legacy in [".respire/inference.json", ".onememory/inference.json"] {
            let candidate = home
                .as_ref()
                .map(|home| home.join(legacy))
                .unwrap_or_else(|| PathBuf::from(format!("~/{legacy}")));
            if let Some(bytes) = read_maintenance_file(&candidate)? {
                source = candidate;
                source_bytes = Some(bytes);
                break;
            }
        }
    }
    let value: serde_json::Value = source_bytes
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()?
        .unwrap_or_else(|| json!({"engine":"cpu"}));
    anyhow::ensure!(value.is_object(), "inference.json must contain an object");
    Ok(CpuSettings {
        target,
        target_bytes,
        source,
        source_bytes,
        value,
    })
}

fn cpu_revision(settings: &CpuSettings, selection: &str) -> Result<String> {
    let client = read_maintenance_file(&respire_client_host::paths::client_config_path())?;
    Ok(hash(&serde_json::to_vec(&(
        selection,
        &settings.target,
        &settings.target_bytes,
        &settings.source,
        &settings.source_bytes,
        &client,
    ))?))
}

fn cpu_candidate(settings: &CpuSettings) -> Result<Vec<u8>> {
    let mut value = settings.value.clone();
    if let Some(model) = value.get("model") {
        let model = model
            .as_str()
            .context("inference.json model must be a string")?
            .trim()
            .to_ascii_lowercase();
        anyhow::ensure!(
            matches!(
                model.as_str(),
                "quantized" | "fp16" | "int8" | "uint8" | "q4" | "q4f16"
            ),
            "unsupported model variant in inference.json"
        );
        value["model"] = json!(model);
    }
    value["engine"] = json!("cpu");
    value["force_cpu"] = json!(true);
    Ok(serde_json::to_vec_pretty(&value)?)
}

fn apply_cpu_reset(
    takeover: &LibraryLock,
    maintenance: &mut super::lifecycle::Maintenance,
    expected: &ModelMaintenancePlan,
    unchanged: impl Fn() -> Result<()>,
    publication_attempted: &mut bool,
) -> Result<ModelMaintenanceReceipt> {
    let (root, profile) = roots()?;
    anyhow::ensure!(
        takeover.protects(&root.join("runtime/takeover"))?,
        "model maintenance takeover mismatch"
    );
    let _installation = LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
    let _library = LibraryLock::acquire(&profile, Duration::ZERO)?;
    let registry_path = root.join("embedding-profiles-v1.json");
    let registry = read_maintenance_file(&registry_path)?;
    let reviewed = local_plan(ModelMaintenanceKind::ResetCpu, &root, &profile)?;
    anyhow::ensure!(
        reviewed.review == expected.review
            && reviewed.cpu_candidate_sha256 == expected.cpu_candidate_sha256
            && read_maintenance_file(&registry_path)? == registry,
        "model reset selection/revision conflict; no mutation performed"
    );
    let lock_path = root.join("inference.json.lock");
    check_path(&lock_path)?;
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_file(),
            "inference configuration lock is not a regular file"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.lock()?;
    let before = cpu_settings(&root)?;
    let _legacy_lock = if before.source != before.target {
        let path = before.source.with_file_name("inference.json.lock");
        read_maintenance_file(&path)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        lock.lock()?;
        anyhow::ensure!(
            read_maintenance_file(&before.source)? == before.source_bytes,
            "legacy inference source changed while obtaining its configuration lock"
        );
        Some(lock)
    } else {
        None
    };
    let candidate = cpu_candidate(&before)?;
    anyhow::ensure!(
        cpu_revision(&before, &expected.review.selection_sha256)?
            == expected.review.revision_sha256
            && Some(hash(&candidate)) == expected.cpu_candidate_sha256,
        "model reset revision or candidate changed before CAS"
    );
    unchanged()?;
    maintenance
        .auth_launch_binding(&profile)?
        .context("model reset lost Paused authority")?;
    let staged = root.join(format!(".inference-reset-{}.json", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        file.write_all(&candidate)?;
        file.sync_all()?;
        unchanged()?;
        maintenance
            .auth_launch_binding(&profile)?
            .context("model reset lost Paused authority")?;
        let inspected = local_plan(ModelMaintenanceKind::ResetCpu, &root, &profile)?;
        anyhow::ensure!(
            inspected.review == expected.review
                && inspected.cpu_candidate_sha256 == expected.cpu_candidate_sha256,
            "model reset selection or candidate changed before CAS"
        );
        let current = cpu_settings(&root)?;
        anyhow::ensure!(
            cpu_revision(&current, &expected.review.selection_sha256)?
                == expected.review.revision_sha256
                && read_maintenance_file(&registry_path)? == registry
                && current.target_bytes == before.target_bytes,
            "model reset revision changed before CAS"
        );
        *publication_attempted = true;
        if before.target_bytes.is_some() {
            respire_spawn::durable::replace_file(&staged, &before.target)?;
        } else {
            respire_spawn::durable::publish_new_file(&staged, &before.target)?;
        }
        Ok(())
    })();
    if result.is_err() && staged.try_exists()? {
        fs::remove_file(&staged)?;
    }
    result?;
    anyhow::ensure!(
        read_maintenance_file(&before.target)?.as_deref() == Some(candidate.as_slice()),
        "CPU reset outcome unknown; inspect configuration, do not replay"
    );
    unchanged()?;
    maintenance
        .auth_launch_binding(&profile)?
        .context("model reset lost Paused authority")?;
    Ok(ModelMaintenanceReceipt {
        plan: reviewed,
        phase: ModelMaintenancePhase::Apply,
        verified: true,
        config_applied: true,
        npu_ready: false,
        warning: None,
    })
}

pub(crate) fn control_install_engines() -> Result<ResultEnvelope> {
    anyhow::ensure!(!cfg!(windows),
        "Windows NPU engine installation is unavailable: its signed provider is not verified");
    coordinate(ModelMaintenanceKind::InstallEngines)
}
pub(crate) fn control_uninstall_m3() -> Result<ResultEnvelope> {
    coordinate(ModelMaintenanceKind::UninstallM3)
}
pub(crate) fn control_reset_cpu() -> Result<ResultEnvelope> {
    coordinate(ModelMaintenanceKind::ResetCpu)
}

fn roots() -> Result<(PathBuf, PathBuf)> {
    let (root, profile) = respire_client_host::config::control_roots()?;
    fs::create_dir_all(&root)?;
    fs::create_dir_all(&profile)?;
    Ok((root.canonicalize()?, profile.canonicalize()?))
}

fn account(profile: &Path) -> Result<Option<String>> {
    Ok(
        respire_client_host::identity::host_session_user_of_dir(profile, hash)?
            .map(|user| hash(user.as_bytes())),
    )
}

fn verify_owner(
    health: &crate::net_rpc::Health,
    root: &Path,
    profile: &Path,
    binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest,
    managed: Option<&super::super::super::Registration>,
    expected_account: Option<&str>,
) -> Result<()> {
    crate::net_rpc::request_scope(health)?;
    if let Some(config) = managed {
        super::lifecycle::verify_owned_runtime(config, health)?;
    }
    let birth =
        crate::autostart::process_birth(health.pid)?.context("model maintenance owner exited")?;
    let process = crate::net_rpc::runtime_process_identity(health.pid)?;
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    let expected_scope = super::model_control::owner_scope_id(profile, expected_account)?;
    // Unlike normal preparation, reset must accept a correctly identified owner
    // whose inference is stalled. Identity and installation checks are unchanged.
    anyhow::ensure!(
        health.managed_id.as_deref() == managed.map(|config| config.id.as_str())
            && health.account_id == expected_scope
            && Path::new(&health.installation_root).canonicalize()? == root
            && Path::new(&health.data_dir).canonicalize()? == profile
            && health.installation_id == hash(root.display().to_string().as_bytes())
            && Path::new(&health.exe).canonicalize()? == binary
            && Path::new(&health.image_path).canonicalize()? == binary
            && Path::new(&process.executable).canonicalize()? == binary
            && health.runtime_version == manifest.version
            && health.image_sha256.eq_ignore_ascii_case(&manifest.sha256)
            && health.process_start_id == format!("{prefix}{birth}")
            && (process.started_at == birth || process.started_at == health.process_start_id),
        "model maintenance owner identity/profile/image mismatch"
    );
    anyhow::ensure!(
        crate::net_rpc::runtime_process_identity(health.pid)? == process,
        "model maintenance owner changed during verification"
    );
    Ok(())
}

fn coordinate(kind: ModelMaintenanceKind) -> Result<ResultEnvelope> {
    crate::runtime_policy::require_host("model maintenance")?;
    anyhow::ensure!(
        super::lifecycle::current_boot_token().is_none(),
        "model maintenance cannot nest"
    );
    let takeover = crate::runtime_policy::takeover_lock()?;
    if crate::runtime_fetch::read_manifest()?.is_none() {
        crate::runtime_fetch::download_and_install(None, None)?;
    }
    let (binary, manifest) = super::model_control::installed_model_runtime()?;
    let (root, profile) = roots()?;
    let expected_account = account(&profile)?;
    let registration = super::read_registration(&root)?;
    let managed = registration
        .as_ref()
        .filter(|config| config.enabled && !config.manually_stopped);
    let owner = crate::rpc::probe_runtime()?;
    // Reuse the complete dead-owner claim verifier. A legacy/live unobservable
    // locator cannot authorize forced termination of a possibly foreign owner.
    let stale = if owner.is_none() && crate::rpc::endpoint_path().try_exists()? {
        Some(
            super::super::super::recovery::StaleOwner::prepare_locked().context(
                "model maintenance cannot prove owner exit; no force-stop or config mutation",
            )?,
        )
    } else {
        None
    };
    if let Some(config) = managed {
        super::lifecycle::owned(config)?;
        super::lifecycle::ensure_control_endpoint(config)?;
        anyhow::ensure!(
            owner.is_some() || !super::super::super::manager::inspect(config)?.running,
            "model maintenance has a running supervisor without an observable owner"
        );
    }
    if let Some(owner) = owner.as_ref() {
        verify_owner(
            owner,
            &root,
            &profile,
            &binary,
            &manifest,
            managed,
            expected_account.as_deref(),
        )?;
        anyhow::ensure!(
            kind == ModelMaintenanceKind::ResetCpu || !owner.inference_stalled(),
            "inference is stalled; use model reset-cpu first"
        );
    }
    let unchanged = || -> Result<()> {
        let (current, release) = super::model_control::installed_model_runtime()?;
        anyhow::ensure!(
            current == binary
                && release.version == manifest.version
                && release.sha256.eq_ignore_ascii_case(&manifest.sha256)
                && roots()? == (root.clone(), profile.clone())
                && account(&profile)? == expected_account,
            "model maintenance installation/profile/account changed"
        );
        Ok(())
    };
    let mut maintenance = super::lifecycle::begin_maintenance_locked()?;
    let result = (|| -> Result<ResultEnvelope> {
        maintenance.check_account_runtime()?;
        maintenance
            .auth_launch_binding(&profile)?
            .context("model maintenance requires durable Paused authority")?;
        let cpu_plan = if kind == ModelMaintenanceKind::ResetCpu {
            Some(local_plan(kind, &root, &profile)?)
        } else {
            None
        };
        if let Some(stale) = stale {
            stale.remove_endpoint_locked()?;
        }
        if let Some(owner) = owner.as_ref() {
            let drained = maintenance.drain_runtime(owner);
            if let Err(error) = drained {
                if kind != ModelMaintenanceKind::ResetCpu || managed.is_some() {
                    return Err(error);
                }
                // Manual CPU recovery retains the explicit force-stop behavior,
                // but only for the full owner we observed and verified above.
                force_stop_observed(
                    owner,
                    &root,
                    &profile,
                    &binary,
                    &manifest,
                    expected_account.as_deref(),
                )?;
            }
        }
        unchanged()?;
        let plan = match cpu_plan {
            Some(plan) => plan,
            None => local_plan(kind, &root, &profile)?,
        };
        #[cfg(windows)]
        let plan = {
            let mut plan = plan;
            if kind == ModelMaintenanceKind::InstallEngines {
                plan.preparation = Some(super::model_control::model_install_plan_locked(
                    &takeover,
                    &mut maintenance,
                    &respire_protocol::ModelInstallIntent {
                        for_engine: Some("npu".into()),
                        ..Default::default()
                    },
                )?);
            }
            plan
        };
        let mut providers: Vec<String> = Vec::new();
        let mut removed = false;
        let mut reset_reconciled = false;
        let receipt = match kind {
            ModelMaintenanceKind::ResetCpu => {
                let mut publication_attempted = false;
                match apply_cpu_reset(
                    &takeover,
                    &mut maintenance,
                    &plan,
                    &unchanged,
                    &mut publication_attempted,
                ) {
                    Ok(receipt) => {
                        anyhow::ensure!(
                            receipt.config_applied && receipt.verified,
                            "CPU reset was not confirmed"
                        );
                        receipt
                    }
                    Err(error) if publication_attempted => {
                        // Read the postcondition once. Never repeat the uncertain CAS.
                        let inspected = local_plan(kind, &root, &profile)
                            .context("CPU reset outcome unknown; no Apply was replayed")?;
                        let candidate = plan
                            .cpu_candidate_sha256
                            .as_deref()
                            .context("CPU reset candidate missing")?;
                        let bytes = fs::read(root.join("inference.json"))?;
                        anyhow::ensure!(
                            hash(&bytes) == candidate
                                && inspected.cpu_candidate_sha256.as_deref() == Some(candidate),
                            "CPU reset outcome unknown: {error:#}; no Apply was replayed"
                        );
                        reset_reconciled = true;
                        ModelMaintenanceReceipt {
                            plan: inspected,
                            phase: ModelMaintenancePhase::Apply,
                            verified: true,
                            config_applied: true,
                            npu_ready: false,
                            warning: None,
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            ModelMaintenanceKind::InstallEngines | ModelMaintenanceKind::UninstallM3 => {
                {
                    let _installation =
                        LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
                    let _library = LibraryLock::acquire(&profile, Duration::ZERO)?;
                    check_path(&root.join("inference.json.lock"))?;
                    let lock = fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create(true)
                        .truncate(false)
                        .open(root.join("inference.json.lock"))?;
                    lock.lock()?;
                    unchanged()?;
                    anyhow::ensure!(
                        local_plan(kind, &root, &profile)?.review == plan.review,
                        "model maintenance selection/revision conflict; no mutation performed"
                    );
                    if kind == ModelMaintenanceKind::InstallEngines {
                        providers = install_catalog(&root, plan.catalog.as_ref())?;
                    } else {
                        removed = remove_m3(
                            &root,
                            &profile,
                            plan.uninstall_directory
                                .as_deref()
                                .context("host uninstall directory missing")?,
                        )?;
                    }
                }
                let receipt =
                    verify_maintenance(&takeover, &mut maintenance, &plan, &root, &profile)?;
                receipt
            }
        };
        unchanged()?;
        if kind == ModelMaintenanceKind::ResetCpu {
            anyhow::ensure!(
                Some(hash(&fs::read(root.join("inference.json"))?)) == plan.cpu_candidate_sha256,
                "CPU reset configuration changed before owner restoration"
            );
        }
        let restart =
            owner.is_some() && (kind != ModelMaintenanceKind::ResetCpu || managed.is_some());
        if restart {
            maintenance.start_account_runtime()?;
            let restored =
                crate::rpc::probe_runtime()?.context("model maintenance owner did not resume")?;
            verify_owner(
                &restored,
                &root,
                &profile,
                &binary,
                &manifest,
                managed,
                expected_account.as_deref(),
            )?;
            anyhow::ensure!(
                !owner.as_ref().is_some_and(|owner| owner.store_ready) || restored.store_ready,
                "restored model owner lost store readiness"
            );
        }
        unchanged()?;
        if kind == ModelMaintenanceKind::ResetCpu {
            anyhow::ensure!(
                Some(hash(&fs::read(root.join("inference.json"))?)) == plan.cpu_candidate_sha256,
                "CPU reset configuration changed during owner restoration"
            );
        }
        let mut output = match kind {
            ModelMaintenanceKind::InstallEngines => ResultEnvelope::new(
                "model",
                if receipt.warning.is_some() {
                    Status::Warn
                } else {
                    Status::Ok
                },
                json!({"providers":providers,"npu_ready":false}),
                Vec::new(),
            ),
            ModelMaintenanceKind::UninstallM3 => {
                let status = if removed { Status::Ok } else { Status::Skip };
                let directory = plan
                    .uninstall_directory
                    .as_ref()
                    .context("uninstall directory missing")?;
                ResultEnvelope::new(
                    "model",
                    status,
                    json!({"dir":directory,"removed":removed,"model":"bge-m3"}),
                    vec![Item::new(
                        "model",
                        status,
                        if removed {
                            directory.display().to_string()
                        } else {
                            "not installed".into()
                        },
                    )],
                )
            }
            ModelMaintenanceKind::ResetCpu => ResultEnvelope::new(
                "model",
                Status::Ok,
                json!({"engine":"cpu","force_cpu":true,"runtime_restarted":restart,
                    "stopped_pid":owner.as_ref().map(|owner| owner.pid)}),
                Vec::new(),
            ),
        };
        output.details = serde_json::to_value(&receipt)?;
        if reset_reconciled {
            output.details["reset_postcondition_confirmed_by_read"] = json!(true);
        }
        if let Some(warning) = receipt.warning {
            output.errors.push(warning);
        }
        // Files/config are already accepted. Marker cleanup must not undo them.
        if let Err(error) = maintenance
            .finish()
            .and_then(|()| maintenance.finish_handoff())
        {
            output.status = Status::Warn;
            output.errors.push(format!(
                "model maintenance completed; marker cleanup pending: {error:#}"
            ));
        }
        Ok(output)
    })();
    if result.is_err() {
        maintenance
            .mark(super::lifecycle::Phase::Paused)
            .context("model maintenance failed and Paused fencing could not be restored")?;
    }
    result
}

fn force_stop_observed(
    health: &crate::net_rpc::Health,
    root: &Path,
    profile: &Path,
    binary: &Path,
    manifest: &crate::runtime_fetch::ManagedManifest,
    expected_account: Option<&str>,
) -> Result<()> {
    let endpoint = crate::rpc::endpoint_path();
    let original = fs::read(&endpoint)?;
    let record: serde_json::Value = serde_json::from_slice(&original)?;
    anyhow::ensure!(
        record["pid"].as_u64() == Some(u64::from(health.pid)),
        "CPU reset endpoint changed"
    );
    if crate::autostart::process_birth(health.pid)?.is_some() {
        verify_owner(
            health,
            root,
            profile,
            binary,
            manifest,
            None,
            expected_account,
        )?;
        let identity = crate::net_rpc::runtime_process_identity(health.pid)?;
        crate::net_rpc::kill_runtime(health.pid, &identity)?;
        crate::net_rpc::wait_until_exited(health.pid)?;
    }
    let _installation = LibraryLock::acquire(&root.join("runtime"), Duration::ZERO)?;
    let _library = LibraryLock::acquire(profile, Duration::ZERO)?;
    anyhow::ensure!(
        crate::autostart::process_birth(health.pid)?.is_none() && fs::read(&endpoint)? == original,
        "CPU reset old owner/endpoint changed; cleanup refused"
    );
    fs::remove_file(&endpoint)?;
    respire_spawn::durable::sync_directory(endpoint.parent().context("endpoint parent missing")?)?;
    Ok(())
}

fn check_path(path: &Path) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute() && path.to_str().is_some(),
        "model maintenance path must be absolute Unicode"
    );
    let mut prefix = PathBuf::new();
    for component in path.components() {
        anyhow::ensure!(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "model path has dot components"
        );
        if let Component::Normal(name) = component {
            let text = name.to_str().context("model path must be Unicode")?;
            anyhow::ensure!(
                !text.contains([':', '\\']) && !text.ends_with(['.', ' ']),
                "ambiguous model path"
            );
        }
        prefix.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) => {
                anyhow::ensure!(
                    !metadata.file_type().is_symlink(),
                    "model maintenance cannot follow symlinks"
                );
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    anyhow::ensure!(
                        metadata.file_attributes() & 0x400 == 0,
                        "model maintenance cannot follow reparse points"
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub(super) fn local_m3_directory() -> Result<PathBuf> {
    let home = || {
        dirs::home_dir()
            .or_else(|| respire_client_host::env::var_os("HOME").map(PathBuf::from))
            .or_else(|| respire_client_host::env::var_os("USERPROFILE").map(PathBuf::from))
    };
    let raw = respire_client_host::env::var_os("RSRS_M3_DIR");
    let path = if let Some(raw) = raw {
        let raw = raw.to_str().context("RSRS_M3_DIR must be Unicode")?.trim();
        anyhow::ensure!(!raw.is_empty(), "RSRS_M3_DIR must not be empty");
        match raw.strip_prefix("~/") {
            Some(rest) => home().context("model override home missing")?.join(rest),
            None => PathBuf::from(raw),
        }
    } else if let Some(root) = respire_client_host::env::var_os("RSRS_DATA_DIR") {
        PathBuf::from(root).join("models/bge-m3")
    } else {
        home()
            .context("model home missing")?
            .join(".rsrs/models/bge-m3")
    };
    Ok(std::path::absolute(path)?)
}

fn remove_m3(root: &Path, profile: &Path, target: &Path) -> Result<bool> {
    let local = local_m3_directory()?;
    anyhow::ensure!(
        target == local
            && !target
                .to_string_lossy()
                .replace('\\', "/")
                .contains("/usr/lib/respire/models")
            && target.parent().is_some(),
        "uninstall target is outside the exact local model destination"
    );
    check_path(target)?;
    for protected in [
        Some(root.to_path_buf()),
        Some(profile.to_path_buf()),
        dirs::home_dir(),
    ]
    .into_iter()
    .flatten()
    {
        anyhow::ensure!(
            target != protected && !protected.starts_with(target),
            "refusing to remove an installation/profile/home ancestor"
        );
    }
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir(),
            "model uninstall target is not a directory"
        ),
    }
    let canonical = target.canonicalize()?;
    for protected in [
        Some(root.to_path_buf()),
        Some(profile.to_path_buf()),
        dirs::home_dir(),
    ]
    .into_iter()
    .flatten()
    {
        let protected = protected.canonicalize()?;
        anyhow::ensure!(
            canonical != protected && !protected.starts_with(&canonical),
            "canonical model target is an installation/profile/home ancestor"
        );
    }
    let mut pending = vec![target.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            check_path(&path)?;
            anyhow::ensure!(
                path.canonicalize()?.starts_with(&canonical),
                "model deletion escapes its exact target"
            );
            let metadata = fs::symlink_metadata(&path)?;
            anyhow::ensure!(
                metadata.is_dir() || metadata.is_file(),
                "model deletion refuses special files"
            );
            if metadata.is_dir() {
                pending.push(path);
            }
        }
    }
    check_path(target)?;
    anyhow::ensure!(
        target.canonicalize()? == canonical,
        "model uninstall target changed"
    );
    fs::remove_dir_all(target)?;
    Ok(true)
}

#[cfg(not(windows))]
fn install_catalog(_root: &Path, pin: Option<&ModelCatalogPin>) -> Result<Vec<String>> {
    anyhow::ensure!(pin.is_none(), "Windows ML plan is invalid on this host");
    Ok(Vec::new())
}

#[cfg(windows)]
fn install_catalog(root: &Path, pin: Option<&ModelCatalogPin>) -> Result<Vec<String>> {
    let pin = pin.context("Windows ML catalog plan missing")?;
    let arch = if cfg!(target_arch = "x86_64") {
        "x64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        anyhow::bail!("unsupported Windows ML architecture")
    };
    let directory = root.join("engines/winml-2.4.89");
    let dll = directory.join("Microsoft.Windows.AI.MachineLearning.dll");
    anyhow::ensure!(
        pin.version == "2.4.89"
            && pin.package_source == PACKAGE_SOURCE
            && pin.package_sha256 == PACKAGE_SHA256
            && pin.destination == dll
            && pin.archive_member
                == format!("runtimes/win-{arch}/native/Microsoft.Windows.AI.MachineLearning.dll"),
        "catalog plan differs from local official pin/architecture/destination"
    );
    check_path(&dll)?;
    fs::create_dir_all(&directory)?;
    let package = directory.join(".winml-2.4.89.nupkg");
    check_path(&package)?;
    respire_commands::model_download::download_with_fallback(
        &[PACKAGE_SOURCE.into()],
        &package,
        PACKAGE_SHA256,
        false,
        Default::default(),
        None,
    )?;
    let mut archive = zip::ZipArchive::new(fs::File::open(&package)?)?;
    for (member, destination, limit) in [
        (
            pin.archive_member.as_str(),
            dll.clone(),
            64 * 1024 * 1024u64,
        ),
        ("license.txt", directory.join("license.txt"), 1024 * 1024u64),
    ] {
        let file = archive.by_name(member)?;
        anyhow::ensure!(
            file.is_file() && file.size() <= limit,
            "catalog package member is not a bounded regular file"
        );
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() as u64 <= limit,
            "catalog package member exceeds bound"
        );
        if destination == dll {
            anyhow::ensure!(
                bytes.len() as u64 == pin.dll_size && hash(&bytes) == pin.dll_sha256,
                "catalog DLL differs from the official host pin"
            );
        }
        publish(&destination, &bytes)?;
    }
    // Only the host invokes Windows ML's installer. A provider manifest is not
    // proof that an unpinned hardware payload is safe or ready for inference.
    let providers = respire_spawn::install_accelerators(&dll)?;
    publish(
        &root.join("engines/providers.json"),
        &serde_json::to_vec_pretty(&providers)?,
    )?;
    Ok(providers.into_keys().collect())
}

#[cfg(windows)]
fn publish(target: &Path, bytes: &[u8]) -> Result<()> {
    check_path(target)?;
    let parent = target.parent().context("catalog target parent missing")?;
    let staged = parent.join(format!(".catalog-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        check_path(target)?;
        if target.try_exists()? {
            respire_spawn::durable::replace_file(&staged, target)?;
        } else {
            respire_spawn::durable::publish_new_file(&staged, target)?;
        }
        Ok(())
    })();
    if result.is_err() && staged.try_exists()? {
        fs::remove_file(staged)?;
    }
    result
}

#[cfg(test)]
#[path = "control_tests/model_maintenance.rs"]
mod tests;
