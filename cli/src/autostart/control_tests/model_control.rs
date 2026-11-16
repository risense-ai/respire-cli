//! Pure model plan and local-source policy tests. No source URL is requested.
use super::*;
use serde_json::{json, Value};
use std::ffi::OsString;

struct Restore(Vec<(&'static str, Option<OsString>)>);
impl Drop for Restore {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn isolate(root: &Path) -> Restore {
    let names = [
        "HOME",
        "USERPROFILE",
        "RSRS_DATA_DIR",
        "ONEMEMORY_DATA_DIR",
        "RESPIRE_DATA_DIR",
        "RSRS_DEFAULT_DATA_DIR",
        "ONEMEMORY_DEFAULT_DATA_DIR",
        "RESPIRE_DEFAULT_DATA_DIR",
        "RSRS_M3_DIR",
        "ONEMEMORY_M3_DIR",
        "RESPIRE_M3_DIR",
        "RSRS_MIRROR",
        "ONEMEMORY_MIRROR",
        "RESPIRE_MIRROR",
        "RSRS_CPU_OWNED_ORT_FILE",
        "ONEMEMORY_CPU_OWNED_ORT_FILE",
        "RESPIRE_CPU_OWNED_ORT_FILE",
        "RSRS_CPU_ORT_MIRROR",
        "ONEMEMORY_CPU_ORT_MIRROR",
        "RESPIRE_CPU_ORT_MIRROR",
    ];
    let restore = Restore(
        names
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
    );
    for key in names {
        std::env::remove_var(key);
    }
    std::env::set_var("HOME", root);
    std::env::set_var("USERPROFILE", root);
    std::env::set_var("RSRS_DATA_DIR", root);
    restore
}

fn assets(values: &[(&str, &str)]) -> Result<AssetsStatus> {
    let assets = values
        .iter()
        .map(|(name, source)| {
            serde_json::from_value(json!({"name":name,"suggested_source":source}))
        })
        .collect::<std::result::Result<Vec<respire_protocol::AssetRequirement>, _>>()?;
    Ok(AssetsStatus::installation_plan(assets))
}

#[test]
fn model_preparation_preserves_damaged_installations_before_maintenance() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let _restore = isolate(&root);
    std::fs::create_dir_all(root.join("bin"))?;
    let manifest = root.join("bin/runtime.json");
    let unproved = serde_json::to_vec(&json!({
        "version": "1.0.21-dev.17", "sha256": "a".repeat(64)
    }))?;
    for bytes in [b"not-json".as_slice(), br#"{}"#, unproved.as_slice()] {
        std::fs::write(&manifest, bytes)?;
        let error = control_prepare_model(&ModelInstallIntent::default())
            .expect_err("damaged installation must not bootstrap or enter maintenance");
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains("repair required"), "{diagnostic}");
        assert_eq!(std::fs::read(&manifest)?, bytes);
        assert!(!root.join("models").exists());
        assert!(!root.join("runtime/autostart/maintenance.json").exists());
    }
    Ok(())
}

#[test]
fn model_roots_follow_selected_profiles_and_only_explicit_local_overrides() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let _restore = isolate(&root);
    assert_eq!(local_roots()?, (root.clone(), root.clone()));
    assert_eq!(allowed_model_roots()?, [root.join("models")]);
    let profile = root.join("accounts/synthetic");
    std::fs::create_dir_all(&profile)?;
    std::fs::write(
        root.join("client.json"),
        serde_json::to_vec(&json!({"data_dir":profile}))?,
    )?;
    assert_eq!(local_roots()?, (root.clone(), profile.clone()));
    assert_eq!(
        allowed_model_roots()?,
        [root.join("models"), profile.join("models")]
    );
    std::env::set_var("RSRS_M3_DIR", root.join("models"));
    assert_eq!(
        allowed_model_roots()?.len(),
        2,
        "an existing root must not be duplicated"
    );
    let explicit = root.join("explicit-model");
    std::env::set_var("RSRS_M3_DIR", &explicit);
    assert_eq!(
        allowed_model_roots()?,
        [
            root.join("models"),
            profile.join("models"),
            explicit.clone()
        ]
    );
    assert!(
        !explicit.exists(),
        "root selection must not create a model directory"
    );
    // Platform home lookup is read-only. On Windows it ignores HOME/USERPROFILE.
    let platform_home = dirs::home_dir().context("platform home directory")?;
    std::env::set_var("RSRS_M3_DIR", "~/explicit-model");
    assert_eq!(
        allowed_model_roots()?,
        [
            root.join("models"),
            profile.join("models"),
            platform_home.join("explicit-model")
        ]
    );
    std::env::set_var("RSRS_M3_DIR", "  \t ");
    assert!(allowed_model_roots().is_err());
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        std::env::set_var("RSRS_M3_DIR", OsString::from_vec(vec![0xff]));
        assert!(allowed_model_roots().is_err());
    }
    // Preserve Runtime's configured path spelling, rather than the canonical control root.
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_M3_DIR", &explicit);
    let directory = root.join("models/bge-m3");
    let ort = std::path::absolute(respire_client_host::roots::default_user_model_dir()?
        .join("onnx").join("model_quantized.cpu-v1.ort"))?;
    #[cfg(windows)]
    assert!(!ort.to_str().context("cache path must be Unicode")?.starts_with(r"\\?\"));
    let tokenizer = host_tokenizer(&directory)?;
    let cpu = host_cpu_container(&ort)?;
    let mut core = AssetsStatus::installation_plan(vec![tokenizer.clone(), cpu]);
    // Diagnostic source strings carry no download authority, even when files are complete.
    for requirement in &mut core.assets {
        requirement.state = AssetState::Complete;
        requirement.actual_size = requirement.expected_size;
        requirement.actual_sha256 = requirement.sha256.clone();
        requirement.suggested_source = "https://untrusted.invalid/payload".into();
    }
    core.complete = true;
    core.missing.clear();
    let mut intent = ModelInstallIntent { model: Some("fp16".into()), ..Default::default() };
    let plan = host_installation_plan(&intent, &core, None, &directory, &ort)?;
    assert_eq!(plan.assets.len(), 4, "ORT core choice must still install baseline and requested extra");
    assert_eq!(plan.missing, plan.assets);
    assert!(!plan.complete && plan.backend_load.is_none());
    assert!(plan.assets.iter().all(|asset| asset.state == AssetState::Missing
        && asset.actual_size.is_none() && asset.actual_sha256.is_none()
        && !asset.suggested_source.contains("untrusted.invalid")));
    // Runtime22 preparation pins the default cache even when it is absent and M3 is overridden.
    let explicit_core = AssetsStatus::installation_plan(vec![
        host_tokenizer(&explicit)?, host_cpu_container(&ort)?,
    ]);
    assert!(!ort.exists());
    let planned = host_installation_plan(&intent, &explicit_core, None, &explicit, &ort)?;
    assert_eq!(planned.assets.iter().find(|asset| asset.name == "bge-m3-cpu-ort")
        .context("CPU container missing")?.path.as_deref(), ort.to_str());
    let mut loader_destination = explicit_core.clone();
    loader_destination.assets[1] = host_cpu_container(&explicit.join("onnx/model_quantized.cpu-v1.ort"))?;
    assert!(host_installation_plan(&intent, &loader_destination, None, &explicit, &ort).is_err());
    std::fs::create_dir_all(ort.parent().context("cache parent missing")?)?;
    std::fs::write(&ort, b"cache fixture; pin validation remains required")?;
    let planned = host_installation_plan(&intent, &explicit_core, None, &explicit, &ort)?;
    assert_eq!(planned.assets.iter().find(|asset| asset.name == "bge-m3-cpu-ort")
        .context("cached CPU container missing")?.path.as_deref(), ort.to_str());
    for field in ["sha256", "expected_size", "path"] {
        let mut changed = serde_json::to_value(&explicit_core)?;
        changed["assets"][1][field] = Value::Null;
        let changed = serde_json::from_value(changed)?;
        assert!(host_installation_plan(&intent, &changed, None, &explicit, &ort).is_err(),
            "accepted mismatched CPU container pin {field}");
    }
    std::fs::remove_file(&ort)?;
    for (name, _, _) in MODEL_VARIANTS {
        let mut model = host_variant(&directory, name)?;
        model.name = "bge-m3-model".into();
        model.version = Some((*name).into());
        let requirements = AssetsStatus::installation_plan(vec![tokenizer.clone(), model]);
        intent.model = Some((*name).into());
        let planned = host_installation_plan(&intent, &requirements, None, &directory, &ort)?;
        assert_eq!(planned.assets.len(), if *name == "quantized" { 2 } else { 3 });
    }
    for field in ["sha256", "expected_size", "path"] {
        let mut changed = serde_json::to_value(&core)?;
        changed["assets"][0][field] = Value::Null;
        let changed = serde_json::from_value(changed)?;
        assert!(host_installation_plan(&intent, &changed, None, &directory, &ort).is_err(),
            "accepted mismatched core pin {field}");
    }
    let mut incompatible = core.clone();
    incompatible.assets[0].state = AssetState::Incompatible;
    assert!(host_installation_plan(&intent, &incompatible, None, &directory, &ort).is_err());
    let mut duplicate = core.clone();
    duplicate.assets[1] = duplicate.assets[0].clone();
    assert!(host_installation_plan(&intent, &duplicate, None, &directory, &ort).is_err());
    intent.model = Some("unknown-variant".into());
    assert!(host_installation_plan(&intent, &core, None, &directory, &ort).is_err());
    intent.model = None;
    std::env::set_var("RSRS_CPU_OWNED_ORT_FILE", &ort);
    assert!(host_installation_plan(&intent, &core, None, &directory, &ort).is_err());
    std::env::remove_var("RSRS_CPU_OWNED_ORT_FILE");
    let revision = "b".repeat(40);
    let source = format!("https://huggingface.co/fixture/profile/resolve/{revision}/tokenizer.json");
    let selected = json!({"engine":"cpu","backend_profile":{"backend":"onnx"},"profile":{"embedding":{"revision":revision},
        "tokenizer":{"path":tokenizer.path,"size":tokenizer.expected_size,"sha256":tokenizer.sha256,"download":source},
        "weights":{"path":directory.join("weights.onnx"),"size":7,"sha256":"a".repeat(64),
            "download":format!("https://huggingface.co/fixture/profile/resolve/{revision}/weights.onnx")}}});
    let profile_assets = vec![
        host_asset("profile-tokenizer", "profile-v1", directory.join("tokenizer.json"), 17_082_821,
            selected["profile"]["tokenizer"]["sha256"].as_str().context("fixture hash")?, "diagnostic only".into())?,
        host_asset("profile-weights", "profile-v1", directory.join("weights.onnx"), 7, &"a".repeat(64), "diagnostic only".into())?,
    ];
    let profile_core = AssetsStatus::installation_plan(profile_assets);
    let planned = host_installation_plan(&intent, &profile_core, Some(&selected), &directory, &ort)?;
    assert_eq!(planned.assets[0].suggested_source, source);
    assert_eq!(planned.assets[0].version.as_deref(), Some(revision.as_str()));
    let mut no_source = selected.clone();
    no_source["profile"]["weights"]["download"] = Value::Null;
    assert!(host_installation_plan(&intent, &profile_core, Some(&no_source), &directory, &ort).is_err());
    intent.model = Some("fp16".into());
    let planned = host_installation_plan(&intent, &profile_core, Some(&selected), &directory, &ort)?;
    assert_eq!(planned.assets.len(), 4, "profile files plus legacy baseline and requested variant");
    assert_eq!(account(&profile)?, None);
    std::fs::write(
        profile.join("session.json"),
        br#"{"user":"synthetic-model-user"}"#,
    )?;
    assert_eq!(
        account(&profile)?,
        Some(super::super::hash(b"synthetic-model-user"))
    );
    std::fs::write(profile.join("session.json"), b"invalid JSON")?;
    assert!(account(&profile).is_err());
    Ok(())
}

#[test]
fn local_mirror_policy_has_explicit_environment_config_and_default_precedence() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let _restore = isolate(&root);
    let official = "https://huggingface.co/fixture/model/resolve/fixed/model.onnx";
    let profile_official = "https://huggingface.co/fixture/profile/resolve/fixed/config.json";
    let cpu = "https://github.com/risense-ai/respire-cli/releases/download/synthetic/ort.tgz";
    let plan = assets(&[
        ("model", official),
        ("profile-config", profile_official),
        ("bge-m3-cpu-ort", cpu),
    ])?;
    let mut intent = ModelInstallIntent::default();
    let sources = local_model_sources(&intent, &plan)?;
    assert_eq!(
        sources[0],
        [
            "https://hf-mirror.com/fixture/model/resolve/fixed/model.onnx",
            "https://hf-mirror.net/fixture/model/resolve/fixed/model.onnx",
            official
        ]
    );
    assert_eq!(sources[1], [profile_official]);
    assert_eq!(
        sources[2],
        [format!("https://gh-proxy.org/{cpu}"), cpu.to_owned()]
    );
    std::fs::write(
        root.join("client.json"),
        serde_json::to_vec(&json!({
        "model_mirror":"config.invalid","model_cpu_ort_mirror":"github"}))?,
    )?;
    let sources = local_model_sources(&intent, &plan)?;
    assert_eq!(
        sources[0],
        ["https://config.invalid/fixture/model/resolve/fixed/model.onnx"]
    );
    assert_eq!(sources[2], [cpu]);
    std::env::set_var("RSRS_MIRROR", "https://environment.invalid");
    std::env::set_var("RSRS_CPU_ORT_MIRROR", "cpu.invalid");
    let sources = local_model_sources(&intent, &plan)?;
    assert_eq!(
        sources[0],
        ["https://environment.invalid/fixture/model/resolve/fixed/model.onnx"]
    );
    assert_eq!(sources[2], [format!("https://cpu.invalid/{cpu}")]);
    intent.mirror = Some("http://explicit.invalid:1234".into());
    let sources = local_model_sources(&intent, &plan)?;
    assert_eq!(
        sources[0],
        ["http://explicit.invalid:1234/fixture/model/resolve/fixed/model.onnx"]
    );
    assert_eq!(
        sources[1],
        [profile_official],
        "profile assets retain their immutable official source"
    );
    std::env::set_var("RSRS_CPU_ORT_MIRROR", "https://github.com/");
    assert_eq!(local_model_sources(&intent, &plan)?[2], [cpu]);
    std::env::set_var("RSRS_MIRROR", " ");
    intent.mirror = None;
    assert_eq!(
        local_model_sources(&intent, &plan)?[0],
        ["https://config.invalid/fixture/model/resolve/fixed/model.onnx"]
    );
    Ok(())
}

#[test]
fn source_selection_rejects_unpinned_sources_and_malformed_cpu_origins() -> Result<()> {
    let _guard = crate::TEST_ENV_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("test environment lock poisoned"))?;
    let dir = tempfile::tempdir()?;
    let root = dir.path().canonicalize()?;
    let _restore = isolate(&root);
    let intent = ModelInstallIntent::default();
    for name in ["model", "profile-config", "bge-m3-cpu-ort"] {
        assert!(local_model_sources(
            &intent,
            &assets(&[(name, "https://example.invalid/unpinned")])?
        )
        .is_err());
    }
    let plan = assets(&[(
        "bge-m3-cpu-ort",
        "https://github.com/risense-ai/respire-cli/releases/download/synthetic/ort.tgz",
    )])?;
    for mirror in [
        "ftp://example.invalid",
        "https://user@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid/?query=1",
        "https://example.invalid/#fragment",
        "https://bad host.invalid",
    ] {
        std::env::set_var("RSRS_CPU_ORT_MIRROR", mirror);
        assert!(
            local_model_sources(&intent, &plan).is_err(),
            "accepted invalid CPU origin {mirror}"
        );
    }
    std::env::remove_var("RSRS_CPU_ORT_MIRROR");
    assert!(local_model_sources(&intent, &plan).is_ok());
    std::fs::write(root.join("client.json"), b"invalid JSON")?;
    assert!(local_model_sources(&intent, &plan).is_err());
    Ok(())
}

#[test]
fn selection_digests_and_mirror_origins_are_validated_without_fetching() -> Result<()> {
    validate_selection_digest(&"0".repeat(64))?;
    validate_selection_digest(&"abcdef0123456789".repeat(4))?;
    for digest in [
        String::new(),
        "0".repeat(63),
        "0".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        assert!(validate_selection_digest(&digest).is_err());
    }
    for (raw, expected) in [
        ("example.invalid", "https://example.invalid"),
        (" https://example.invalid/ ", "https://example.invalid"),
        ("http://example.invalid:1234", "http://example.invalid:1234"),
    ] {
        assert_eq!(model_mirror_origin(raw)?, expected);
    }
    for raw in [
        "",
        "  ",
        "ftp://example.invalid",
        "https:///missing",
        "https://user@example.invalid",
        "https://example.invalid?query=1",
        "https://example.invalid#fragment",
        "https://bad host.invalid",
    ] {
        assert!(
            model_mirror_origin(raw).is_err(),
            "accepted invalid model mirror {raw}"
        );
    }
    Ok(())
}

#[test]
fn model_plan_responses_require_the_original_peer_and_private_readiness() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let profile = dir.path().canonicalize()?;
    let request: RpcRequest = serde_json::from_value(
        json!({"v":1,"id":"model-request","method":"control.model.plan","args":[]}),
    )?;
    for command in ["model-install-plan", "model-install-verify"] {
        let baseline = json!({"v":1,"id":"model-request","pid":42,"bin":"rsrs-runtime","ok":true,"exit":0,
            "data_dir":profile,"envelope":{"command":command,"status":"ok","summary":{},"details":{},
                "actions":[],"errors":[],"items":[{"name":"control_ready","status":"ok","value":"true"},
                    {"name":"store_ready","status":"skip","value":"false"}]}});
        validate_plan_response(
            serde_json::from_value(baseline.clone())?,
            &request,
            &profile,
            42,
            command,
        )?;
        for (pointer, value) in [
            ("/v", json!(2)),
            ("/id", json!("different")),
            ("/pid", json!(43)),
            ("/bin", json!("different")),
            ("/ok", json!(false)),
            ("/exit", json!(2)),
            ("/envelope/command", json!("different")),
            ("/envelope/status", json!("fail")),
            ("/envelope/errors", json!(["synthetic"])),
            ("/envelope/items/0/value", json!("false")),
            ("/envelope/items/1/status", json!("ok")),
        ] {
            let mut changed = baseline.clone();
            *changed
                .pointer_mut(pointer)
                .context("synthetic model response field")? = value;
            assert!(
                validate_plan_response(
                    serde_json::from_value(changed)?,
                    &request,
                    &profile,
                    42,
                    command
                )
                .is_err(),
                "accepted changed model response {pointer}"
            );
        }
        for (field, value) in [
            ("operation_id", json!("unexpected")),
            ("idempotency_key", json!("unexpected")),
            ("web_url", json!("https://example.invalid")),
            (
                "scope",
                json!({"account_id":"synthetic","instance_id":"synthetic","generation":1}),
            ),
            ("error", json!("synthetic-peer-diagnostic")),
            ("code", json!("unexpected")),
        ] {
            let mut changed = baseline.clone();
            changed[field] = value;
            let error = validate_plan_response(
                serde_json::from_value(changed)?,
                &request,
                &profile,
                42,
                command,
            )
            .err()
            .context("invalid response must be rejected")?;
            assert!(!error.to_string().contains("synthetic-peer-diagnostic"));
        }
        let mut pending = baseline.clone();
        pending["code"] = json!("auth_recovery_pending");
        assert!(validate_plan_response(
            serde_json::from_value(pending)?,
            &request,
            &profile,
            42,
            command
        )
        .err()
        .context("pending account recovery must be rejected")?
        .to_string()
        .contains("auth_recovery_pending"));
        let mut missing = baseline.clone();
        missing["envelope"] = Value::Null;
        assert!(validate_plan_response(
            serde_json::from_value(missing)?,
            &request,
            &profile,
            42,
            command
        )
        .is_err());
        let mut duplicate = baseline;
        duplicate["envelope"]["items"] = json!([
            {"name":"control_ready","status":"ok","value":"true"},{"name":"control_ready","status":"ok","value":"true"}]);
        assert!(validate_plan_response(
            serde_json::from_value(duplicate)?,
            &request,
            &profile,
            42,
            command
        )
        .is_err());
    }
    Ok(())
}
