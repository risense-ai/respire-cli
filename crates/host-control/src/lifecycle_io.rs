//! Shared exact-owner loopback drain and grant-authorized replacement startup.
//! Extracted from CLI rpc::{drain_occupant,wait_daemon_ready}; never force an
//! existing owner. A just-spawned child remains owned by its Child handle.
use crate::{LaunchContext, VerifiedRuntime};
use anyhow::{Context, Result};
use respire_client_host::lock::LibraryLock;
use respire_commands::net_rpc::{self, Health};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountRuntimeExpectation {
    Unlock,
    Startup,
    LockedAfterFullLogout,
}

impl AccountRuntimeExpectation {
    /// Call only after verifying the Runtime owner, image and launch instance.
    pub fn confirm_credentials(self, health: &Health) -> Result<()> {
        match self {
            Self::Startup => {
                let (_, profile) = respire_client_host::config::control_roots()?;
                // Initial startup may remain locked; account restoration still requires Unlock.
                if matches!(crate::identity(&profile)?, respire_protocol::HostAuthIdentity::Absent) {
                    Self::LockedAfterFullLogout.confirm_credentials(health)
                } else {
                    Self::Unlock.confirm_credentials(health)
                }?;
            }
            // Startup coordinators already hold takeover ownership and migrated before spawn.
            Self::Unlock if !health.store_ready => { supply_verified_runtime_credentials(health)?; }
            Self::Unlock => {}
            Self::LockedAfterFullLogout => {
                let (root, profile) = respire_client_host::config::control_roots()?;
                anyhow::ensure!(Path::new(&health.installation_root).canonicalize()? == root.canonicalize()?
                    && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?
                    && matches!(crate::identity(&profile)?, respire_protocol::HostAuthIdentity::Absent)
                    && !health.store_ready && health.credential_state == "required",
                    "full logout requires the selected session to remain absent and Runtime locked");
            }
        }
        Ok(())
    }
}

pub fn endpoint_path() -> PathBuf {
    respire_client_host::paths::main_data_dir().join("runtime/endpoint.json")
}

pub fn probe_runtime() -> Result<Option<Health>> {
    match net_rpc::health() {
        Ok(health) => Ok(Some(health)),
        Err(error)
            if matches!(
                error.downcast_ref::<respire_commands::runtime_error::RuntimeError>(),
                Some(respire_commands::runtime_error::RuntimeError::Unavailable)
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// Normal readers never rewrite sessions. Only this host-owned upgrade stage may do so.
pub fn migrate_legacy_session() -> Result<bool> {
    if respire_client_host::settings::off_mode()? { return Ok(false); }
    let (_, profile) = respire_client_host::config::control_roots()?;
    if !legacy_session_pending(&profile)? { return Ok(false); }
    let takeover = crate::maintenance::takeover_lock()?;
    migrate_legacy_session_under_takeover(&takeover)
}

fn legacy_session_pending(profile: &Path) -> Result<bool> {
    let Some(bytes) = crate::maintenance::private_io::bounded_bytes(&profile.join("session.json"), 65536)? else {
        return Ok(false);
    };
    let session = serde_json::from_slice(&bytes).context("invalid historical session")?;
    Ok(respire_client_host::host_credentials::legacy_session_needs_migration(&session))
}

pub(crate) fn legacy_recovery_clear(root: &Path, journal: &Path) -> Result<()> {
    for name in ["account-active.json", "key-control.json", "offline-keygen.json"] {
        anyhow::ensure!(!root.join("runtime/autostart").join(name).try_exists()?,
            "historical session migration requires account/key recovery to finish first");
    }
    let marker = root.join("runtime/autostart/maintenance.json");
    if let Some(bytes) = crate::maintenance::private_io::bounded_bytes(&marker, 16 * 1024)? {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let birth = crate::launch::process_birth(std::process::id())?
            .context("historical session migration has no live host identity")?;
        anyhow::ensure!(value["owner_pid"].as_u64() == Some(u64::from(std::process::id()))
            && value["owner_birth"].as_str() == Some(birth.as_str())
            && value.get("snapshot").is_none_or(serde_json::Value::is_null)
            && value.get("agent_config").is_none_or(serde_json::Value::is_null),
            "historical session migration cannot bypass maintenance recovery");
    }
    if journal.try_exists()? {
        let journal = respire_client_host::config::normalize_control_path(&journal)?;
        let value: serde_json::Value = serde_json::from_reader(std::fs::File::open(journal)?)?;
        anyhow::ensure!(value["schema_version"] == 2 && value.get("active").is_some_and(serde_json::Value::is_null)
            && value["operations"].as_array().is_some_and(|operations| operations.iter().all(|record|
                matches!(record["phase"].as_str(), Some("committed" | "rolled_back")))),
            "historical session migration requires login recovery to finish first");
    }
    Ok(())
}

/// The ordinary restart receipt exception cannot complete a private transaction.
pub fn verify_no_private_recovery_for_restart() -> Result<()> {
    let (root, _) = respire_client_host::config::control_roots()?;
    let journal = respire_client_host::paths::client_config_path().with_file_name(".login-recovery.json");
    legacy_recovery_clear(&root, &journal).context("private lifecycle recovery requires its original stop receipt")
}

/// The caller holds installation takeover ownership, before any child readiness wait.
pub fn migrate_legacy_session_under_takeover(takeover: &respire_client_host::lock::LibraryLock) -> Result<bool> {
    use sha2::{Digest, Sha256};
    if respire_client_host::settings::off_mode()? { return Ok(false); }
    let (root, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(takeover.protects(&root.join("runtime/takeover"))?,
        "historical session migration requires this installation's takeover lock");
    let path = profile.join("session.json");
    let Some(original) = crate::maintenance::private_io::bounded_bytes(&path, 65536)? else { return Ok(false); };
    let session = serde_json::from_slice(&original).context("invalid historical session")?;
    if !respire_client_host::host_credentials::legacy_session_needs_migration(&session) { return Ok(false); }
    let root = root.canonicalize()?;
    let profile = profile.canonicalize()?;
    let journal = respire_client_host::paths::client_config_path().with_file_name(".login-recovery.json");
    legacy_recovery_clear(&root, &journal)?;
    let owner = probe_runtime()?;
    if let Some(owner) = &owner { verify_credential_owner(owner)?; }
    else { anyhow::ensure!(!endpoint_path().try_exists()?, "historical session migration has an unverified Runtime endpoint"); }
    let original_sha256 = format!("{:x}", Sha256::digest(&original));
    let alias = format!("legacy-{:x}", Sha256::digest([profile.to_string_lossy().as_bytes(), original.as_slice()].concat()));
    eprintln!("HOST_LEGACY_SESSION_MIGRATION stage=credential_custody");
    let migrated = respire_client_host::host_credentials::prepare_legacy_session(&session, &alias)?;
    let bytes = serde_json::to_vec_pretty(&migrated)?;
    legacy_recovery_clear(&root, &journal)?;
    let (selected_root, selected_profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(selected_root.canonicalize()? == root && selected_profile.canonicalize()? == profile
        && takeover.protects(&root.join("runtime/takeover"))?,
        "historical session selection or takeover ownership changed before publication");
    verify_migration_owner(owner.as_ref())?;
    crate::maintenance::private_io::private_write_record(&path, &bytes, Some(&original_sha256), 65536)?;
    anyhow::ensure!(crate::maintenance::private_io::bounded_bytes(&path, 65536)?.as_deref() == Some(bytes.as_slice()),
        "historical session changed after publication");
    verify_migration_owner(owner.as_ref())?;
    if let Some(owner) = &owner {
        // V2 re-reads the factor-free session and binds the newly published digest.
        supply_verified_runtime_credentials(owner)?;
    }
    eprintln!("HOST_LEGACY_SESSION_MIGRATION stage=completed");
    Ok(true)
}

fn verify_migration_owner(original: Option<&Health>) -> Result<()> {
    let current = probe_runtime()?;
    match (original, current.as_ref()) {
        (Some(original), Some(current)) => {
            verify_credential_owner(current)?;
            anyhow::ensure!(current.pid == original.pid && current.instance_id == original.instance_id
                && current.generation == original.generation && current.process_start_id == original.process_start_id
                && current.image_path == original.image_path && current.image_sha256 == original.image_sha256
                && current.url == original.url && current.account_id == original.account_id,
                "Runtime identity changed during historical session migration");
        }
        (None, None) => anyhow::ensure!(!endpoint_path().try_exists()?, "Runtime appeared during historical session migration"),
        _ => anyhow::bail!("Runtime owner changed during historical session migration"),
    }
    Ok(())
}

/// Deliver keys only to the verified local profile owner. Never start a process here.
pub fn unlock_if_needed(health: &Health) -> Result<bool> {
    if health.store_ready {
        let (_, profile) = respire_client_host::config::control_roots()?;
        if respire_client_host::settings::off_mode()? || !legacy_session_pending(&profile)? { return Ok(true); }
    }
    Ok(supply_runtime_credentials(health)?.is_some())
}

/// Refresh an existing owner after settings are saved; never start or restart it.
pub fn refresh_running_runtime_credentials() -> Result<()> {
    let result = (|| -> Result<()> {
        let Some(health) = probe_runtime()? else { return Ok(()); };
        let receipt = supply_runtime_credentials(&health)?
            .context("Runtime is not ready for credential delivery")?;
        if let respire_protocol::credentials::ProviderCredentialStatus::Unavailable { code } = receipt.provider_status {
            anyhow::bail!("Runtime library is unlocked, but provider credentials are unavailable ({code:?})");
        }
        Ok(())
    })();
    result.context("Configuration was saved, but Runtime credential refresh could not be confirmed")
}

/// Deliver a complete V2 update and retain the verified provider outcome for CLI output.
pub fn supply_runtime_credentials(health: &Health)
    -> Result<Option<respire_protocol::credentials::RuntimeUnlockReceipt>> {
    if respire_client_host::settings::off_mode()? { return Ok(None); }
    let (_, profile) = respire_client_host::config::control_roots()?;
    if legacy_session_pending(&profile)? {
        let takeover = crate::maintenance::takeover_lock()?;
        return supply_runtime_credentials_under_takeover(health, &takeover);
    }
    supply_verified_runtime_credentials(health)
}

/// Already-owned callers must not acquire SQLite takeover ownership a second time.
pub fn supply_runtime_credentials_under_takeover(health: &Health,
    takeover: &respire_client_host::lock::LibraryLock)
    -> Result<Option<respire_protocol::credentials::RuntimeUnlockReceipt>> {
    if respire_client_host::settings::off_mode()? { return Ok(None); }
    verify_migration_owner(Some(health))?;
    migrate_legacy_session_under_takeover(takeover)?;
    verify_migration_owner(Some(health))?;
    supply_verified_runtime_credentials(health)
}

fn supply_verified_runtime_credentials(health: &Health)
    -> Result<Option<respire_protocol::credentials::RuntimeUnlockReceipt>> {
    if (!health.store_ready && health.credential_state != "required")
        || respire_client_host::settings::off_mode()? {
        return Ok(None);
    }
    let (installation, profile) = verify_credential_owner(health)?;
    respire_client_host::host_credentials::unlock_runtime(
        &health.url, &installation, &profile, &health.instance_id, health.generation,
    ).map(Some)
}

fn verify_credential_owner(health: &Health) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    let (installation, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(Path::new(&health.installation_root).canonicalize()? == installation.canonicalize()?
        && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?
        && health.v == crate::PROTOCOL_V && !health.instance_id.is_empty() && health.generation > 0,
        "unlock Runtime does not own the selected profile");
    let process = net_rpc::runtime_process_identity(health.pid)?;
    let executable = Path::new(&health.image_path).canonicalize()?;
    anyhow::ensure!(Path::new(&process.executable).canonicalize()? == executable
        && start_matches(&process.started_at, &health.process_start_id),
        "unlock Runtime process identity changed");
    use sha2::{Digest, Sha256};
    anyhow::ensure!(format!("{:x}", Sha256::digest(std::fs::read(executable)?)) == health.image_sha256,
        "unlock Runtime image changed");
    Ok((installation, profile))
}

fn endpoint_pid() -> Result<Option<u32>> {
    let path = respire_client_host::config::normalize_control_path(&endpoint_path())?;
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(bytes.len() <= 65536, "runtime endpoint record is too large");
    let data: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(data
        .get("pid")
        .and_then(serde_json::Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok()))
}

pub fn drain_runtime(health: &Health) -> Result<()> {
    let pid = health.pid;
    let (root, profile) = respire_client_host::config::control_roots()?;
    anyhow::ensure!(
        Path::new(&health.installation_root).canonicalize()? == root.canonicalize()?
            && Path::new(&health.data_dir).canonicalize()? == profile.canonicalize()?,
        "runtime restart blocked: owner roots do not match this installation"
    );
    let birth = crate::launch::process_birth(pid)?.context("runtime process already exited")?;
    anyhow::ensure!(
        start_matches(&birth, &health.process_start_id),
        "runtime process birth differs from health"
    );
    let accepted = net_rpc::request_stop_for(health, Duration::from_secs(120))?;
    let operation_id = accepted;
    let deadline = Instant::now() + Duration::from_secs(60);
    while crate::launch::process_birth(pid)?.as_deref() == Some(birth.as_str()) {
        anyhow::ensure!(
            Instant::now() < deadline,
            "runtime drain is still pending; no process was forced to exit"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    net_rpc::final_stop_receipt(health, Some(&operation_id))?;
    net_rpc::wait_until_down()?;
    let released = LibraryLock::acquire(&profile, Duration::from_secs(15))
        .context("stopped runtime has not released its library lock")?;
    if endpoint_path().try_exists()? {
        anyhow::ensure!(
            endpoint_pid()? == Some(pid) && crate::launch::process_birth(pid)?.is_none(),
            "runtime endpoint owner changed after drain; record was not removed"
        );
        std::fs::remove_file(endpoint_path())?;
    }
    drop(released);
    Ok(())
}

fn start_matches(birth: &str, observed: &str) -> bool {
    let prefix = if cfg!(windows) {
        "windows-filetime-"
    } else if cfg!(target_os = "linux") {
        "linux-starttime-"
    } else {
        "darwin-lstart-"
    };
    !birth.is_empty() && observed.strip_prefix(prefix) == Some(birth)
}

/// A successful return proves this owned child's identity. The maintenance owner
/// requires an open store for committed targets, but can restore an originally locked owner.
pub fn start_account_runtime(context: &LaunchContext, image: &VerifiedRuntime,
    expectation: AccountRuntimeExpectation) -> Result<()> {
    anyhow::ensure!(
        image.port() == net_rpc::rpc_port(),
        "selected Runtime port differs from host transport"
    );
    let (mut child, instance_id) = crate::spawn_serving(context, image)?;
    let result = (|| -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "owned account Runtime exited before readiness"
            );
            let Some(health) = probe_runtime()? else {
                continue;
            };
            let birth =
                crate::launch::process_birth(child.id())?.context("starting Runtime exited")?;
            let process = net_rpc::runtime_process_identity(child.id())?;
            anyhow::ensure!(
                health.pid == child.id()
                    && start_matches(&birth, &health.process_start_id)
                    && health.v == crate::PROTOCOL_V
                    && health.generation > 0
                    && !health.account_id.is_empty()
                    && health.instance_id == instance_id
                    && health.runtime_version == image.version()
                    && Path::new(&health.image_path).canonicalize()? == image.path()
                    && Path::new(&process.executable).canonicalize()? == image.path()
                    && health.image_sha256.eq_ignore_ascii_case(image.sha256())
                    && Path::new(&health.installation_root).canonicalize()?
                        == context.installation_root()
                    && Path::new(&health.data_dir).canonicalize()? == context.profile(),
                "Runtime owner changed during account startup"
            );
            net_rpc::request_scope(&health)?;
            anyhow::ensure!(
                net_rpc::runtime_process_identity(child.id())? == process,
                "Runtime process changed during account startup verification"
            );
            image.revalidate()?;
            if !health.store_ready {
                if health.credential_state != "required" {
                    continue;
                }
            }
            expectation.confirm_credentials(&health)?;
            return Ok(());
        }
        anyhow::bail!("owned account Runtime did not become ready; query the original operation")
    })();
    if result.is_err() && child.try_wait()?.is_none() {
        child
            .kill()
            .context("failed to stop owned unready Runtime")?;
        child
            .wait()
            .context("failed to reap owned unready Runtime")?;
    }
    result
}
