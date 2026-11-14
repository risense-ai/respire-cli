use std::path::Path;

use anyhow::Context;
use serde_json::Value;

// Reuse the official installation prepared for snapshot_lifecycle/runtime_smoke in CI.
// RSRS_RUNTIME_BIN locates that fixture only; product commands cannot use the override.
pub(crate) fn install_runtime_fixture(root: &Path) -> anyhow::Result<()> {
    let binary = std::path::PathBuf::from(
        std::env::var_os("RSRS_RUNTIME_BIN")
            .context("official managed Runtime fixture required")?,
    )
    .canonicalize()?;
    anyhow::ensure!(
        binary != Path::new(env!("CARGO_BIN_EXE_rsrs")).canonicalize()?,
        "CLI shim cannot substitute for the Runtime fixture"
    );
    let version_dir = binary
        .parent()
        .context("Runtime fixture version directory missing")?;
    let source_root = version_dir
        .parent()
        .and_then(Path::parent)
        .context("Runtime fixture installation root missing")?;
    let receipt = source_root.join("runtime.json");
    let selected: Value = serde_json::from_slice(&std::fs::read(&receipt)?)?;
    let pin: Value = serde_json::from_str(include_str!("../../../runtime-pin.json"))?;
    let version = pin["required"]
        .as_str()
        .context("Runtime pin required missing")?;
    anyhow::ensure!(
        selected["version"] == version
            && selected["release"]["metadata_json"].is_string()
            && source_root.join("runtime").join(version) == version_dir,
        "Runtime fixture must be the official pinned managed installation"
    );
    let destination = root.join("bin/runtime").join(version);
    let mut pending = vec![(version_dir.to_path_buf(), destination)];
    while let Some((source, target)) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&source)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "Runtime fixture contains a link"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            anyhow::ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "Runtime fixture contains a reparse point"
            );
        }
        if metadata.is_dir() {
            std::fs::create_dir_all(&target)?;
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                pending.push((entry.path(), target.join(entry.file_name())));
            }
        } else {
            anyhow::ensure!(metadata.is_file(), "Runtime fixture contains a non-file");
            std::fs::copy(source, target)?;
        }
    }
    // Copy the installer's receipt verbatim; managed_runtime_path verifies its proof/files.
    anyhow::ensure!(
        std::fs::symlink_metadata(&receipt)?.is_file(),
        "Runtime fixture receipt missing"
    );
    std::fs::copy(receipt, root.join("bin/runtime.json"))?;
    Ok(())
}

// Normal host startup needs the installed Runtime and the same stable CLI bytes.
pub(crate) fn install_host_fixture(root: &Path, bin_directory: &Path) -> anyhow::Result<()> {
    install_runtime_fixture(root)?;
    stage_cli_fixture(bin_directory)
}

pub(crate) fn stage_cli_fixture(bin_directory: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(bin_directory)?;
    let destination = bin_directory.join(if cfg!(windows) { "rsrs.exe" } else { "rsrs" });
    std::fs::copy(env!("CARGO_BIN_EXE_rsrs"), &destination)?;
    anyhow::ensure!(
        std::fs::read(&destination)? == std::fs::read(env!("CARGO_BIN_EXE_rsrs"))?,
        "stable CLI fixture differs from the tested binary"
    );
    Ok(())
}
