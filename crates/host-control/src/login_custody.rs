//! Private login handoffs never enter public account receipts or filesystem journals.
use anyhow::{Context, Result, ensure};
use respire_client_host::{host_credentials::login as native, lock::LibraryLock};
use respire_protocol::{RpcRequest, host_control::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::{Path, PathBuf}};

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

pub(crate) fn unpack(response: &mut respire_protocol::RpcResponse<respire_commands::output::ResultEnvelope>,
    register: bool) -> Result<Option<HostAuthLoginHandoff>> {
    if register || response.error.is_some() { return Ok(None); }
    let envelope = response.envelope.as_mut().context("private login response missing")?;
    if envelope.summary.get("receipt").is_some() {
        let reply: HostAuthLoginReply = serde_json::from_value(envelope.summary.take())
            .map_err(|_| anyhow::anyhow!("invalid private login response"))?;
        envelope.summary = serde_json::to_value(reply.receipt)?;
        Ok(reply.handoff)
    } else {
        // Runtime uses a plain receipt only when no login continuation exists.
        let receipt: HostAuthAccountResult = serde_json::from_value(envelope.summary.clone())
            .map_err(|_| anyhow::anyhow!("invalid account receipt"))?;
        ensure!(receipt.login.is_none(), "login continuation requires its private reply wrapper");
        Ok(None)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    operation_id: String,
    root: PathBuf,
    source: PathBuf,
    account: String,
    backend: String,
    candidate: Option<Value>,
    challenge_sha256: Option<String>,
    rolled_back: bool,
    slots_removed: bool,
    retired: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Secrets {
    request: HostAuthLoginParams,
    candidate: Option<HostAuthSessionMaterial>,
    slots: BTreeMap<String, String>,
}

pub(crate) struct LoginCustody {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
    record: Record,
    encoded: Option<String>,
    secrets: Option<Secrets>,
}

impl LoginCustody {
    pub(crate) fn open(takeover: &LibraryLock, root: &Path, source: &Path, id: &str) -> Result<Self> {
        ensure!(takeover.protects(&root.join("runtime/takeover"))?, "login custody requires installation takeover");
        let parsed = uuid::Uuid::parse_str(id)?;
        ensure!(parsed.get_version_num() == 4 && parsed.to_string() == id, "invalid login custody operation");
        let path = root.join("runtime/autostart").join(format!("account-login-{id}.json"));
        let bytes = crate::maintenance::private_io::bounded_bytes(&path, 65536)?;
        let record = match bytes.as_deref() {
            Some(bytes) => serde_json::from_slice::<Record>(bytes)?,
            None => Record { operation_id: id.to_owned(), root: root.to_owned(), source: source.to_owned(),
                account: format!("login-{}", parsed.simple()), backend: if cfg!(target_os = "linux") {
                    "secret_service".to_owned() } else { "native".to_owned() }, candidate: None,
                challenge_sha256: None, rolled_back: false, slots_removed: false, retired: false },
        };
        ensure!(record.operation_id == id && record.root == root && record.source == source
            && record.account == format!("login-{}", parsed.simple()), "login custody binding changed");
        let encoded = if bytes.is_some() && !record.retired {
            native::read(&record.account, &record.backend, "login-control")?
        } else { None };
        let secrets = encoded.as_deref().map(serde_json::from_str).transpose()?;
        Ok(Self { path, bytes, record, encoded, secrets })
    }

    pub(crate) fn continue_operation(mut self, receipt: &HostAuthAccountResult,
        mut input: HostAuthLoginContinuation, super_password: Option<String>, totp: Option<String>,
    ) -> Result<crate::account_control::AccountControl> {
        ensure!(receipt.operation_id == self.record.operation_id
            && receipt.source_profile == self.record.source
            && receipt.outcome == HostAuthAccountOutcome::AwaitingInput,
            "login continuation does not match original custody");
        let original = self.secrets.take().context("original login input custody is missing; do not replay authentication")?.request;
        let status = receipt.login.as_ref().context("original login status is missing")?;
        ensure!(status.addr == original.addr && status.user == original.user,
            "login receipt differs from original custody");
        let intent = original.continuation.as_ref().context("original login intent is missing")?;
        input.migrate_local = intent.migrate_local;
        input.migrate_vault = intent.migrate_vault;
        input.offer_local_merge = intent.offer_local_merge;
        let mut authorization = original.authorization;
        if let Some(totp) = totp {
            let HostAuthAuthorization::Password { totp: code, .. } = &mut authorization else {
                anyhow::bail!("original authorization does not accept TOTP");
            };
            *code = Some(totp);
        }
        Ok(crate::account_control::AccountControl::LoginStep {
            addr: original.addr, user: original.user, authorization, super_password, input,
        })
    }

    fn save(&mut self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.record)?;
        crate::maintenance::private_io::private_write_record(&self.path, &bytes,
            self.bytes.as_deref().map(digest).as_deref(), 65536)?;
        self.bytes = Some(bytes);
        Ok(())
    }

    fn save_secrets(&mut self) -> Result<()> {
        let encoded = serde_json::to_string(self.secrets.as_ref().context("login custody input missing")?)?;
        native::write(&self.record.account, &self.record.backend, "login-control", self.encoded.as_deref(), &encoded)?;
        self.encoded = Some(encoded);
        Ok(())
    }

    pub(crate) fn prepare(&mut self, request: &mut RpcRequest) -> Result<()> {
        let argument = request.args.first_mut().context("login request parameters missing")?;
        if request.method == HOST_AUTH_LOGIN_METHOD {
            ensure!(!self.record.rolled_back && !self.record.retired, "login custody is already retired");
            let mut params: HostAuthLoginParams = serde_json::from_str(argument)?;
            if let Some(original) = &self.secrets {
                ensure!(original.request.addr == params.addr && original.request.user == params.user,
                    "login custody user or server changed");
                if original.request.challenge.is_some() {
                    match (&original.request.authorization, &mut params.authorization) {
                        (HostAuthAuthorization::Password { password: original, .. },
                            HostAuthAuthorization::Password { password, .. }) => *password = original.clone(),
                        _ => anyhow::bail!("password challenge cannot change authorization method"),
                    }
                }
                params.super_password = params.super_password.or_else(|| original.request.super_password.clone());
                if let (Some(previous), Some(input)) = (&original.request.continuation, params.continuation.as_mut()) {
                    if input.legacy_password.is_none() { input.legacy_password = previous.legacy_password.clone(); }
                    if input.account_secret.is_none() { input.account_secret = previous.account_secret.clone(); }
                    if input.secret_key.is_none() { input.secret_key = previous.secret_key.clone(); }
                    if input.source_secret.is_none() { input.source_secret = previous.source_secret.clone(); }
                    if input.new_super.is_none() { input.new_super = previous.new_super.clone(); }
                }
                params.material = original.request.material.clone();
                params.challenge = original.request.challenge.clone();
                params.custody_ack = original.request.custody_ack.clone();
            } else {
                ensure!(self.bytes.is_none(), "original login input custody is missing; do not replay authentication");
                let source = session_material(&self.record.source,
                    params.continuation.as_ref().and_then(|input| input.source_secret.as_deref()))?;
                let target_original = target_material(&self.record.root, &self.record.source, &params.addr, &params.user)?;
                params.material = Some(HostAuthLoginMaterial { keyring_account: self.record.account.clone(),
                    keyring_backend: self.record.backend.clone(), source, target_original });
            }
            *argument = serde_json::to_string(&params)?;
            let candidate = self.secrets.as_ref().and_then(|secret| secret.candidate.clone());
            let slots = self.secrets.as_ref().map(|secret| secret.slots.clone()).unwrap_or_default();
            self.secrets = Some(Secrets { request: params, candidate, slots });
            self.save()?;
            self.save_secrets()?;
        } else {
            let mut params: HostAuthAccountParams = serde_json::from_str(argument)?;
            if let Some(secrets) = &self.secrets {
                params.candidate = secrets.candidate.clone();
                if request.method == HOST_AUTH_ACCOUNT_COMPLETE_METHOD {
                    params.migration_password = password(&secrets.request).map(str::to_owned);
                }
            } else {
                ensure!(self.bytes.is_none() || self.record.retired || self.record.slots_removed,
                    "original login custody is missing; operation retained");
                if !self.record.rolled_back {
                    if let Some(session) = &self.record.candidate {
                        params.candidate = Some(native::session_material(&serde_json::to_vec_pretty(session)?, None)?);
                    }
                }
            }
            *argument = serde_json::to_string(&params)?;
        }
        Ok(())
    }

    /// Returns the same login step with a custody acknowledgement, never a new authorization.
    pub(crate) fn consume(&mut self, handoff: HostAuthLoginHandoff, request: &RpcRequest,
        receipt: &HostAuthAccountResult) -> Result<Option<RpcRequest>> {
        ensure!(receipt.operation_id == self.record.operation_id && receipt.outcome == HostAuthAccountOutcome::AwaitingInput,
            "login handoff is not owned by an awaiting-input receipt");
        let secrets = self.secrets.as_mut().context("original private login input missing")?;
        match handoff {
            HostAuthLoginHandoff::Challenge { payload, sha256 } => {
                ensure!(digest(payload.as_bytes()) == sha256 && receipt.login.as_ref()
                    .is_some_and(|status| status.required_inputs == ["totp"]), "login challenge binding mismatch");
                self.record.challenge_sha256 = Some(sha256.clone());
                secrets.request.challenge = Some(HostAuthLoginChallenge { payload, sha256 });
                self.save()?;
                self.save_secrets()?;
                Ok(None)
            },
            HostAuthLoginHandoff::Credentials { candidate_sha256, session, slots } => {
                ensure!(receipt.login.as_ref().is_some_and(|status| status.required_inputs == ["host_credentials"])
                    && digest(&serde_json::to_vec_pretty(&session)?) == candidate_sha256
                    && session["keyring_account"].as_str() == Some(self.record.account.as_str())
                    && session["keyring_backend"].as_str() == Some(self.record.backend.as_str())
                    && session["user"].as_str() == Some(secrets.request.user.as_str())
                    && session["addr"].as_str() == Some(secrets.request.addr.trim().trim_end_matches('/'))
                    && ["pass", "super", "secret", "secret_key"].iter().all(|field| session.get(*field).is_none()),
                    "login candidate handoff binding mismatch");
                if let Some(original) = &self.record.candidate {
                    ensure!(*original == session, "login custody candidate changed");
                }
                let factors = candidate_factors(&session, &secrets.request)?;
                let expected = serving_slots(&factors, password(&secrets.request));
                let mut requested: Vec<_> = slots.iter().map(|slot| match slot {
                    HostAuthLoginSlot::Super => "super", HostAuthLoginSlot::Pass => "pass",
                    HostAuthLoginSlot::LegacySecret => "legacy-secret", }).collect();
                requested.sort_unstable();
                ensure!(requested == expected.keys().map(String::as_str).collect::<Vec<_>>(), "login candidate slot plan changed");
                secrets.candidate = Some(HostAuthSessionMaterial { session_sha256: candidate_sha256.clone(), factors });
                secrets.slots = expected;
                secrets.request.custody_ack = Some(HostAuthLoginCustodyAck { candidate_sha256 });
                self.record.candidate = Some(session);
                self.save()?;
                self.save_secrets()?;
                let secrets = self.secrets.as_ref().context("login custody input missing")?;
                for (slot, value) in &secrets.slots {
                    native::write(&self.record.account, &self.record.backend, slot, None, value)?;
                }
                let mut resumed: HostAuthLoginParams = serde_json::from_str(&serde_json::to_string(&secrets.request)?)?;
                // Query and completion launch grants are not login grants.
                let binding: HostAuthAccountParams = if request.method != HOST_AUTH_LOGIN_METHOD {
                    serde_json::from_str(request.args.first().context("account parameters missing")?)?
                } else {
                    let login: HostAuthLoginParams = serde_json::from_str(request.args.first().context("login parameters missing")?)?;
                    HostAuthAccountParams { schema_version: login.schema_version, binding: login.binding,
                        identity: login.identity, candidate: None, migration_password: None }
                };
                resumed.binding = binding.binding;
                resumed.identity = binding.identity;
                Ok(Some(RpcRequest { v: request.v, id: uuid::Uuid::new_v4().to_string(),
                    method: HOST_AUTH_LOGIN_METHOD.to_owned(), args: vec![serde_json::to_string(&resumed)?],
                    scope: None, operation_id: request.operation_id.clone(), idempotency_key: request.idempotency_key.clone(),
                    parent_operation_id: None, queue_wait_ms: None, lifecycle: None }))
            },
        }
    }

    pub(crate) fn finish(&mut self, rolled_back: bool) -> Result<()> {
        if self.record.retired { return Ok(()); }
        ensure!(self.secrets.is_some() || self.record.slots_removed || self.bytes.is_none(),
            "original login cleanup custody is missing; operation retained");
        self.record.rolled_back = rolled_back;
        self.save()?;
        if let Some(secrets) = &self.secrets {
            if rolled_back {
                // Check every slot before deleting any; a conflicting owner remains untouched.
                for (slot, expected) in &secrets.slots {
                    ensure!(native::read(&self.record.account, &self.record.backend, slot)?.as_deref()
                        .is_none_or(|value| value == expected), "login rollback credential conflict; original retained");
                }
                for (slot, value) in &secrets.slots {
                    native::remove(&self.record.account, &self.record.backend, slot, value)?;
                }
            }
        }
        self.record.slots_removed = true;
        self.save()?;
        if let Some(encoded) = &self.encoded {
            native::remove(&self.record.account, &self.record.backend, "login-control", encoded)?;
        }
        self.record.retired = true;
        self.save()
    }
}

fn session_material(directory: &Path, primary: Option<&str>) -> Result<Option<HostAuthSessionMaterial>> {
    let Some(bytes) = crate::maintenance::private_io::bounded_bytes(&directory.join("session.json"), 65536)?
        else { return Ok(None); };
    let session: Value = serde_json::from_slice(&bytes)?;
    if session.get("vault_version").is_none() { return Ok(None); }
    native::session_material(&bytes, primary).map(Some)
}

fn target_material(root: &Path, source: &Path, addr: &str, user: &str) -> Result<Option<HostAuthSessionMaterial>> {
    let mut directories = vec![source.to_owned(), root.to_owned()];
    let accounts = root.join("accounts");
    if accounts.is_dir() {
        for entry in std::fs::read_dir(accounts)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { directories.push(entry.path()); }
        }
    }
    for directory in directories {
        let Some(bytes) = crate::maintenance::private_io::bounded_bytes(&directory.join("session.json"), 65536)?
            else { continue; };
        let session: Value = serde_json::from_slice(&bytes)?;
        if session["user"].as_str() == Some(user)
            && session["addr"].as_str().is_some_and(|value| value.trim().trim_end_matches('/') == addr.trim().trim_end_matches('/')) {
            return session_material(&directory, None);
        }
    }
    Ok(None)
}

fn password(params: &HostAuthLoginParams) -> Option<&str> {
    params.continuation.as_ref().and_then(|input| input.legacy_password.as_deref()).or_else(||
        match &params.authorization {
            respire_protocol::host_control::HostAuthAuthorization::Password { password, .. } => Some(password.as_str()),
            _ => None,
        })
}

fn candidate_factors(session: &Value, params: &HostAuthLoginParams) -> Result<HostAuthVaultFactors> {
    let input = params.continuation.as_ref();
    Ok(match session["vault_version"].as_u64() {
        Some(1) => HostAuthVaultFactors::V1 { password: password(params).context("original v1 password missing")?.to_owned(),
            account_secret: input.and_then(|input| input.account_secret.as_ref()).context("original Account Secret missing")?.clone() },
        Some(2) => HostAuthVaultFactors::V2 { super_password: params.super_password.clone().context("original super key missing")? },
        Some(3) => HostAuthVaultFactors::V3 { super_password: params.super_password.clone().context("original super key missing")?,
            secret_key: input.and_then(|input| input.secret_key.as_ref()).context("original Secret Key missing")?.clone() },
        Some(4) => HostAuthVaultFactors::V4 { super_password: params.super_password.clone().context("original super key missing")? },
        _ => anyhow::bail!("unsupported login candidate vault version"),
    })
}

fn serving_slots(factors: &HostAuthVaultFactors, login_password: Option<&str>) -> BTreeMap<String, String> {
    let mut slots = BTreeMap::new();
    match factors {
        HostAuthVaultFactors::V1 { password, account_secret } => {
            slots.insert("pass".to_owned(), password.clone());
            slots.insert("legacy-secret".to_owned(), account_secret.clone());
        },
        HostAuthVaultFactors::V2 { super_password } | HostAuthVaultFactors::V4 { super_password } => {
            slots.insert("super".to_owned(), super_password.clone());
        },
        HostAuthVaultFactors::V3 { super_password, secret_key } => {
            slots.insert("super".to_owned(), super_password.clone());
            slots.insert("legacy-secret".to_owned(), secret_key.clone());
        },
    }
    if let Some(password) = login_password { slots.insert("pass".to_owned(), password.to_owned()); }
    slots
}
