//! Tests for the managed runtime fetcher: pin parsing, whitelist extraction,
//! stage verification and offline installation against fixture archives.
use super::*;

/// Serialize env-mutating tests and restore the previous environment on drop.
fn env_scope(keys: &[&'static str]) -> Result<impl Drop> {
    struct Restore {
        _guard: std::sync::MutexGuard<'static, ()>,
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
    Ok(Restore {
        _guard: crate::TEST_ENV_LOCK
            .lock()
            .map_err(|error| anyhow::anyhow!("test environment lock poisoned: {error}"))?,
        saved: keys
            .iter()
            .map(|key| (*key, std::env::var_os(*key)))
            .collect(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Build one ustar header block with a valid checksum field.
fn tar_header(name: &str, size: u64, typeflag: u8, mode: u32) -> [u8; 512] {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    let mode_text = format!("{mode:o}");
    header[100..100 + mode_text.len()].copy_from_slice(mode_text.as_bytes());
    let size_text = format!("{size:o}");
    header[124..124 + size_text.len()].copy_from_slice(size_text.as_bytes());
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) { u64::from(b' ') } else { u64::from(*byte) };
    }
    let checksum = format!("{sum:o}");
    let mut field = [0u8; 8];
    field[..checksum.len()].copy_from_slice(checksum.as_bytes());
    header[148..156].copy_from_slice(&field);
    header
}

/// Assemble a raw tar archive from (name, typeflag, mode, payload) entries.
fn tar_bytes(entries: &[(&str, u8, u32, &[u8])]) -> Vec<u8> {
    let mut raw = Vec::new();
    for (name, typeflag, mode, payload) in entries {
        raw.extend_from_slice(&tar_header(name, payload.len() as u64, *typeflag, *mode));
        raw.extend_from_slice(payload);
        let padding = (512 - (payload.len() as u64 % 512)) % 512;
        raw.extend(std::iter::repeat(0u8).take(padding as usize));
    }
    raw.extend_from_slice(&[0u8; 1024]);
    raw
}

fn gz(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).context("fixture archive compression failed")?;
    encoder.finish().context("fixture archive compression failed")
}

/// A complete, verifiable release fixture: binary + core manifest + library.
fn release_fixture(triple: &str) -> Result<(Vec<u8>, String)> {
    release_fixture_with(triple, RUNTIME_BINARY)
}

/// Build a fixture with either the bare managed name or the release triple name.
fn release_fixture_with(triple: &str, binary_file: &str) -> Result<(Vec<u8>, String)> {
    const BINARY: &[u8] = b"synthetic rsrs-runtime binary bytes";
    let hash = sha256_hex(BINARY);
    let manifest = serde_json::json!({
        "schema_version": 1,
        "target": triple,
        "files": [{"path": binary_file, "sha256": hash}],
    });
    let raw = tar_bytes(&[
        ("./", b'5', 0o700, b""),
        ("lib/", b'5', 0o700, b""),
        ("lib/provider.json", b'0', 0o600, b"{}"),
        (CORE_MANIFEST_FILE, b'0', 0o600, manifest.to_string().as_bytes()),
        (binary_file, b'0', 0o755, BINARY),
    ]);
    Ok((gz(&raw)?, hash))
}

/// Build release metadata carrying the two distinct published checksums.
fn release_metadata(triple: &str, archive_sha256: &str, binary_sha256: &str) -> Result<String> {
    anyhow::ensure!(archive_sha256 != binary_sha256);
    Ok(serde_json::json!({
        "runtime_version": "1.0.21-dev.1",
        "tag": "v1.0.21-dev.1",
        "triple": triple,
        "sha256": archive_sha256,
        "binary_sha256": binary_sha256,
        "binary_file": release_binary_name(triple),
        "compat": {"min_cli": "1.0.0", "max_cli": "*"},
    })
    .to_string())
}

/// Serve one metadata response followed by one archive response.
fn fixture_release_server(metadata: String, archive: Vec<u8>) -> Result<std::net::SocketAddr> {
    let server = tiny_http::Server::http("127.0.0.1:0")
        .map_err(|error| anyhow::anyhow!("fixture HTTP server bind failed: {error}"))?;
    let address = server.server_addr().to_ip().context("fixture server address")?;
    std::thread::spawn(move || -> Result<(), String> {
        for body in [metadata.into_bytes(), archive] {
            let request = server
                .recv_timeout(std::time::Duration::from_secs(20))
                .map_err(|error| error.to_string())?
                .ok_or("fixture download request timed out")?;
            request
                .respond(tiny_http::Response::from_data(body))
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    });
    Ok(address)
}

#[test]
fn pin_file_parses_and_accept_range_gates_versions() -> Result<()> {
    let pin = pinned()?;
    anyhow::ensure!(pin.required == "1.0.21-dev.1", "unexpected pin {pin:?}");
    anyhow::ensure!(pin.accept.contains("1.0.21-dev.1"));
    anyhow::ensure!(pin.accept.contains("1.0.21"));
    anyhow::ensure!(pin.accept.contains("1.9.9"));
    anyhow::ensure!(!pin.accept.contains("1.0.20"));
    anyhow::ensure!(!pin.accept.contains("2.0.0"));
    anyhow::ensure!(!pin.accept.contains("2.1.0-dev.1"));
    anyhow::ensure!(version_in_accept("1.0.21-dev.1") && !version_in_accept("0.9.0"));
    Ok(())
}

#[test]
fn accept_ranges_reject_malformed_bounds() -> Result<()> {
    for raw in ["", "1.2.3", ">=", "<1.0.0,>=2.0.0", ">=1.0.0,<=2.0.0", "<:>"] {
        anyhow::ensure!(
            AcceptRange::parse(raw).is_err(),
            "malformed range {raw:?} was accepted"
        );
    }
    anyhow::ensure!(AcceptRange::parse("<2.0.0")?.contains("1.9.9"));
    anyhow::ensure!(!AcceptRange::parse("<2.0.0")?.contains("2.0.0"));
    anyhow::ensure!(AcceptRange::parse(">=1.0.21-dev.1")?.contains("1.0.21-dev.2"));
    Ok(())
}

#[test]
fn version_charset_rejects_separators_and_malformed_shapes() {
    for version in ["1.0.21-dev.1", "1.2.3+build.7", "2.0.0", "1.0.0-alpha-1"] {
        assert!(valid_version(version), "{version:?} should be valid");
    }
    for version in [
        "",
        "1/2",
        "a\\b",
        "C:evil",
        "1 2",
        "a\nb",
        "x@y",
        "v1.2.3",
        "1.2",
        "1.2.x",
        "=2.0.0",
        "1.2.3+",
        "1.2.3-alpha..1",
    ] {
        assert!(!valid_version(version), "{version:?} should be rejected");
    }
}

#[test]
fn entry_names_reject_traversal_and_separators() {
    for name in ["lib/x.json", "./lib/x.json", "rsrs-runtime", "a/b/c/"] {
        assert!(safe_entry_name(name).is_some(), "{name:?} should be accepted");
    }
    for name in [
        "../escape",
        "a/../../escape",
        "/absolute",
        "back\\slash",
        "drive:C",
        "a//b",
        "a/./b",
        "",
        ".",
    ] {
        assert!(safe_entry_name(name).is_none(), "{name:?} should be rejected");
    }
}

#[test]
fn extraction_whitelist_matches_client2_semantics() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let dir = tempfile::tempdir()?;
    let (archive, _) = release_fixture(&triple)?;
    let archive_path = dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let stage = dir.path().join("stage");
    extract_archive(&archive_path, &stage)?;
    anyhow::ensure!(stage.join(RUNTIME_BINARY).is_file());
    anyhow::ensure!(stage.join(CORE_MANIFEST_FILE).is_file());
    anyhow::ensure!(stage.join("lib/provider.json").is_file());
    // Entry names that fail the whitelist are rejected outright.
    let hostile = gz(&tar_bytes(&[("../escape", b'0', 0o600, b"x")]))?;
    fs::write(dir.path().join("hostile.tar.gz"), &hostile)?;
    anyhow::ensure!(
        extract_archive(&dir.path().join("hostile.tar.gz"), &dir.path().join("hostile")).is_err(),
        "traversal entry was accepted"
    );
    anyhow::ensure!(!dir.path().join("escape").exists());
    for (name, typeflag) in [("C:\\bad", b'0'), ("link-target", b'2'), ("fifo", b'6')] {
        let entry = gz(&tar_bytes(&[(name, typeflag, 0o600, b"x")]))?;
        fs::write(dir.path().join("hostile2.tar.gz"), &entry)?;
        anyhow::ensure!(
            extract_archive(&dir.path().join("hostile2.tar.gz"), &dir.path().join("hostile2"))
                .is_err(),
            "unsafe entry {name} with flag {typeflag} was accepted"
        );
    }
    // A truncated archive never produces a usable stage.
    let truncated = gz(&tar_fixture_truncated())?;
    fs::write(dir.path().join("short.tar.gz"), &truncated)?;
    anyhow::ensure!(
        extract_archive(&dir.path().join("short.tar.gz"), &dir.path().join("short")).is_err()
    );
    Ok(())
}

fn tar_fixture_truncated() -> Vec<u8> {
    let mut raw = tar_bytes(&[("rsrs-runtime", b'0', 0o755, b"payload")]);
    raw.truncate(raw.len() - 600);
    raw
}

#[test]
fn stage_verification_enforces_manifest_and_binary_hash() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let dir = tempfile::tempdir()?;
    let (archive, binary_hash) = release_fixture(&triple)?;
    let archive_path = dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let stage = dir.path().join("stage");
    extract_archive(&archive_path, &stage)?;
    let binary = RUNTIME_BINARY.to_owned();
    let verified = verify_stage(&stage, &binary, &triple, &binary_hash)?;
    anyhow::ensure!(verified == stage.join(&binary));
    anyhow::ensure!(verify_stage(&stage, &binary, &triple, &"0".repeat(64)).is_err());
    anyhow::ensure!(verify_stage(&stage, &binary, "other-triple", &binary_hash).is_err());
    anyhow::ensure!(verify_stage(&stage, "missing-binary", &triple, &binary_hash).is_err());
    // A manifest listing a foreign path fails the whitelist.
    fs::write(
        stage.join(CORE_MANIFEST_FILE),
        serde_json::json!({
            "schema_version": 1,
            "target": triple,
            "files": [{"path": "../outside", "sha256": sha256_hex(b"x")}],
        })
        .to_string(),
    )?;
    anyhow::ensure!(verify_stage(&stage, &binary, &triple, &binary_hash).is_err());
    Ok(())
}

#[test]
fn install_placement_renames_the_full_triple_binary() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let stage = dir.path().join("stage");
    fs::create_dir_all(&stage)?;
    let full = release_binary_name("x86_64-pc-windows-msvc");
    let bare = RUNTIME_BINARY;
    anyhow::ensure!(full != bare, "platform constant must use the bare name");
    fs::write(stage.join(&full), b"binary bytes")?;
    place_managed_binary(&stage, &full)?;
    anyhow::ensure!(stage.join(bare).is_file());
    anyhow::ensure!(!stage.join(&full).exists());
    anyhow::ensure!(fs::read(stage.join(bare))? == b"binary bytes");
    fs::write(stage.join(&full), b"again")?;
    anyhow::ensure!(place_managed_binary(&stage, "../escape").is_err());
    anyhow::ensure!(place_managed_binary(&stage, "missing-binary").is_err());
    Ok(())
}

#[test]
fn offline_install_publishes_manifest_and_retains_one_rollback() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let _env = env_scope(&["RSRS_DATA_DIR"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    let (archive, hash) = release_fixture(&triple)?;
    let archive_path = dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let binary = install_from_file(&archive_path, "1.0.21-dev.1")?;
    anyhow::ensure!(binary.is_file());
    let manifest = read_manifest()?.context("manifest missing after install")?;
    anyhow::ensure!(manifest.version == "1.0.21-dev.1");
    anyhow::ensure!(manifest.sha256 == hash);
    anyhow::ensure!(managed_runtime_path()?.context("managed path missing")? == binary);
    // Side installs of older and newer versions; only current + newest survive.
    for version in ["1.0.20", "1.0.19", "1.0.21"] {
        let side = version_dir(version);
        fs::create_dir_all(&side)?;
        fs::write(side.join(RUNTIME_BINARY), b"synthetic side runtime")?;
    }
    let removed = clean_old()?;
    anyhow::ensure!(
        removed == vec!["1.0.20".to_owned(), "1.0.19".to_owned()],
        "unexpected removals: {removed:?}"
    );
    let listed = list_installed()?;
    anyhow::ensure!(listed.len() == 2, "unexpected inventory: {listed:?}");
    anyhow::ensure!(listed.iter().all(|entry| entry.version != "1.0.20"));
    anyhow::ensure!(
        listed
            .iter()
            .find(|entry| entry.version == "1.0.21-dev.1")
            .context("current missing")?
            .current
    );
    // Reinstalling an identical build is a no-op and removes nothing.
    let again = install_from_file(&archive_path, "1.0.21-dev.1")?;
    anyhow::ensure!(again == binary);
    anyhow::ensure!(clean_old()?.is_empty());
    anyhow::ensure!(read_manifest()?.context("manifest disappeared")?.sha256 == hash);
    Ok(())
}

#[test]
fn release_triple_override_is_validated() -> Result<()> {
    let _env = env_scope(&["RSRS_RUNTIME_TRIPLE"])?;
    std::env::set_var("RSRS_RUNTIME_TRIPLE", "aarch64-unknown-linux-musl");
    anyhow::ensure!(release_triple()? == "aarch64-unknown-linux-musl");
    std::env::set_var("RSRS_RUNTIME_TRIPLE", "not-a-triple");
    anyhow::ensure!(release_triple().is_err());
    Ok(())
}

#[test]
fn mirror_override_builds_fallback_origins() -> Result<()> {
    let _env = env_scope(&["RSRS_MIRROR", "RSRS_DATA_DIR"])?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    // Origins are host-level prefixes: release_asset appends the repo path,
    // tag and asset name itself.
    let official = RELEASE_BASE.to_owned();
    anyhow::ensure!(
        download_origins(Some("https://mirror.example"))?
            == vec![format!("https://mirror.example/{official}"), official.clone()]
    );
    anyhow::ensure!(
        download_origins(Some("mirror.example"))?
            == vec![format!("https://mirror.example/{official}"), official.clone()],
        "bare mirror hosts must default to https"
    );
    anyhow::ensure!(
        download_origins(Some("https://user:secret@mirror.example")).is_err(),
        "credentials were accepted in a mirror origin"
    );
    anyhow::ensure!(download_origins(Some("https://mirror.example/path")).is_err());
    std::env::remove_var("RSRS_MIRROR");
    anyhow::ensure!(
        download_origins(None)? == vec![official.clone(), format!("{MIRROR_PREFIX}/{official}")]
    );
    Ok(())
}

#[test]
fn metadata_validation_rejects_cross_purpose_documents() -> Result<()> {
    let triple = match release_triple() {
        Ok(triple) => triple,
        Err(_) => return Ok(()),
    };
    let base = serde_json::json!({
        "runtime_version": "1.0.21-dev.1",
        "tag": "v1.0.21-dev.1",
        "triple": triple,
        "sha256": sha256_hex(b"archive"),
        "binary_file": release_binary_name(&triple),
        "compat": {"min_cli": "1.0.0", "max_cli": "*"},
    });
    let metadata: BuildMetadata = serde_json::from_value(base.clone())?;
    metadata.validate("1.0.21-dev.1", &triple)?;
    // The binary_sha256 field is accepted as an alias for sha256.
    let mut alias = base.clone();
    alias["sha256"] = serde_json::json!("");
    alias["binary_sha256"] = serde_json::json!(sha256_hex(b"archive"));
    let alias: BuildMetadata = serde_json::from_value(alias)?;
    alias.validate("1.0.21-dev.1", &triple)?;
    for (field, value) in [
        ("runtime_version", serde_json::json!("1.0.22")),
        ("tag", serde_json::json!("bad /tag")),
        ("triple", serde_json::json!("x86_64-unknown-freebsd")),
        ("sha256", serde_json::json!("zz")),
        ("binary_sha256", serde_json::json!("zz")),
        ("binary_file", serde_json::json!("../escape")),
        ("binary_file", serde_json::json!(RUNTIME_BINARY)),
        ("compat", serde_json::json!({"min_cli":"99.0.0","max_cli":"*"})),
        ("compat", serde_json::json!({"min_cli":"1.0.0","max_cli":"no!pe"})),
    ] {
        let mut changed = base.clone();
        changed[field] = value;
        let changed: BuildMetadata = serde_json::from_value(changed)?;
        anyhow::ensure!(
            changed.validate("1.0.21-dev.1", &triple).is_err(),
            "invalid metadata accepted: {field}"
        );
    }
    // Distinct archive and binary checksums match the release protocol.
    let mut conflicting = base.clone();
    conflicting["sha256"] = serde_json::json!(sha256_hex(b"archive"));
    conflicting["binary_sha256"] = serde_json::json!(sha256_hex(b"binary"));
    let conflicting: BuildMetadata = serde_json::from_value(conflicting)?;
    anyhow::ensure!(conflicting.validate("1.0.21-dev.1", &triple).is_ok());
    Ok(())
}

#[test]
fn download_installs_verified_release_from_local_mirror() -> Result<()> {
    let _env = env_scope(&["RSRS_CORE_TEST_MODE", "RSRS_DATA_DIR", "RSRS_RUNTIME_TRIPLE"])?;
    let triple = "x86_64-pc-windows-msvc";
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_RUNTIME_TRIPLE", &triple);
    std::env::remove_var("RSRS_CORE_TEST_MODE");
    let (archive, binary_sha256) =
        release_fixture_with(triple, &release_binary_name(triple))?;
    let archive_sha256 = sha256_hex(&archive);
    let metadata = release_metadata(triple, &archive_sha256, &binary_sha256)?;
    let address = fixture_release_server(metadata, archive)?;
    let mirror = format!("http://{address}");
    let installed = download_and_install(Some("1.0.21-dev.1"), Some(&mirror))?;
    anyhow::ensure!(installed.is_file());
    anyhow::ensure!(fs::read(&installed)? == b"synthetic rsrs-runtime binary bytes");
    anyhow::ensure!(managed_runtime_path()?.as_ref() == Some(&installed));
    let manifest = read_manifest()?.context("download manifest missing")?;
    anyhow::ensure!(manifest.version == "1.0.21-dev.1");
    anyhow::ensure!(manifest.sha256 == binary_sha256);
    let installed_list = list_installed()?;
    anyhow::ensure!(installed_list.len() == 1);
    anyhow::ensure!(installed_list[0].current);
    let reused = download_and_install(Some("1.0.21-dev.1"), Some(&mirror))?;
    anyhow::ensure!(reused == installed);
    anyhow::ensure!(download_and_install(Some("bad-version"), None).is_err());
    Ok(())
}

#[test]
fn runtime_resolution_prefers_explicit_and_managed_binaries() -> Result<()> {
    let _env = env_scope(&[
        "RSRS_CORE_TEST_MODE",
        "RSRS_DATA_DIR",
        "RSRS_RUNTIME_BIN",
        "RSRS_RUNTIME_TRIPLE",
        "RSRS_BIN_DIR",
    ])?;
    let triple = release_triple()?;
    let dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", dir.path());
    std::env::set_var("RSRS_BIN_DIR", dir.path().join("absent-bin"));
    std::env::set_var("RSRS_RUNTIME_TRIPLE", &triple);
    std::env::remove_var("RSRS_CORE_TEST_MODE");
    std::env::set_var("RSRS_RUNTIME_BIN", "");
    anyhow::ensure!(resolve_runtime_bin().is_err());
    std::env::set_var("RSRS_RUNTIME_BIN", dir.path().join("absent-runtime"));
    anyhow::ensure!(resolve_runtime_bin().is_err());
    let explicit = dir.path().join("explicit-runtime");
    fs::write(&explicit, b"synthetic explicit runtime")?;
    std::env::set_var("RSRS_RUNTIME_BIN", &explicit);
    anyhow::ensure!(resolve_runtime_bin()? == ResolvedRuntime::Ready(explicit));
    std::env::remove_var("RSRS_RUNTIME_BIN");
    std::env::set_var("RSRS_CORE_TEST_MODE", "1");
    anyhow::ensure!(resolve_runtime_bin().is_err());
    std::env::remove_var("RSRS_CORE_TEST_MODE");
    let managed_dir = tempfile::tempdir()?;
    std::env::set_var("RSRS_DATA_DIR", managed_dir.path());
    let (archive, _) = release_fixture(&triple)?;
    let archive_path = managed_dir.path().join("runtime.tar.gz");
    fs::write(&archive_path, &archive)?;
    let managed = install_from_file(&archive_path, "1.0.21-dev.1")?;
    anyhow::ensure!(resolve_runtime_bin()? == ResolvedRuntime::Ready(managed));
    Ok(())
}
