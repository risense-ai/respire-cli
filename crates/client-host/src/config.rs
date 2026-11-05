//! Read and validate client configuration without inspecting model state.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// Resolve only the host-control roots; never inspect models or create directories.
pub fn control_roots() -> Result<(PathBuf, PathBuf)> {
    if let Some(raw) = crate::env::var_os("RSRS_DATA_DIR") {
        anyhow::ensure!(raw.to_str().is_some_and(|value| !value.trim().is_empty()),
            "RSRS_DATA_DIR must be a nonempty UTF-8 path");
    }
    let root = absolute_control_path(crate::paths::main_data_dir())?;
    let config_path = absolute_control_path(crate::paths::client_config_path())?;
    let config = read_client_config(&config_path)?;
    // Validate even a configured path that legacy whole-installation isolation ignores.
    if let Some(value) = config.as_ref().and_then(|config| config["data_dir"].as_str())
        .filter(|value| !value.is_empty()) {
        absolute_control_path(crate::paths::expand_tilde(value))?;
    }
    let profile = absolute_control_path(crate::paths::data_dir_from_config(config.as_ref()))?;
    Ok((root, profile))
}

fn absolute_control_path(path: PathBuf) -> Result<PathBuf> {
    anyhow::ensure!(!path.components().any(|part| part == Component::ParentDir),
        "host control does not support parent traversal; use an explicit root without '..'");
    Ok(std::path::absolute(path)?)
}

pub fn read_client_config(path: &Path) -> Result<Option<serde_json::Value>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot read client config {}", path.display()))
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("client config {} contains invalid JSON", path.display()))?;
    anyhow::ensure!(
        value.is_object(),
        "client config {} must contain a JSON object",
        path.display()
    );
    for key in [
        "lang",
        "data_dir",
        "addr",
        "api_base",
        "service_mode",
        "engine",
        "model",
    ] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(
                field.is_string(),
                "client config {} has invalid type for {key}",
                path.display()
            );
        }
    }
    for key in ["autosync", "cure_auto"] {
        if let Some(field) = value.get(key) {
            anyhow::ensure!(
                field.is_boolean(),
                "client config {} has invalid type for {key}",
                path.display()
            );
        }
    }
    if let Some(field) = value.get("rpc_parallelism") {
        anyhow::ensure!(
            field.as_u64().is_some_and(|value| value <= u32::MAX as u64),
            "client config {} has invalid rpc_parallelism",
            path.display()
        );
    }
    Ok(Some(value))
}
