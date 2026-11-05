//! Read and validate client configuration without inspecting model state.

use std::path::Path;

use anyhow::{Context, Result};

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
