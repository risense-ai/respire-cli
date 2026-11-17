//! Pure host reads. Client configuration errors are never converted to defaults.

use anyhow::Result;
use serde_json::Value;

use crate::config;

fn read_settings() -> Result<(Option<Value>, Value)> {
    let (_, profile, client) = config::read_control_config()?;
    let path = profile.join("agent.json");
    // Preserve the original agent reader: absent, unreadable or malformed files
    // yield an empty object. Field types remain checked by as_str/as_bool at use.
    // This compatibility behavior does not apply to the strict client reader above.
    let agent = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    Ok((client, agent))
}

pub fn read_agent_config() -> Result<Value> {
    read_settings().map(|(_, agent)| agent)
}

/// Display one validated local snapshot without creating a profile or consulting Runtime.
pub fn agent_config_snapshot() -> Result<Value> {
    use anyhow::Context;
    let (_, profile, client) = config::read_control_config()?;
    let path = config::normalize_control_path(&profile.join("agent.json"))?;
    let mut agent: Value = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid agent configuration: {}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let object = agent.as_object_mut().context("agent config must be an object")?;
    let mode = device_service_mode(client.as_ref());
    let readonly = object.get("readonly_team").and_then(Value::as_bool).unwrap_or(false)
        || match mode {
            Some(mode) => mode == "readonly",
            None => object.get("readonly").and_then(Value::as_bool).unwrap_or(false),
        };
    let off = match mode {
        Some(mode) => mode == "off",
        None => object.get("memory_off").and_then(Value::as_bool).unwrap_or(false),
    };
    object.insert("readonly".into(), serde_json::json!(readonly));
    object.insert("memory_off".into(), serde_json::json!(off));
    object.insert("workspace_mode".into(), serde_json::json!(if off { "off" } else if readonly { "readonly" } else { "normal" }));
    Ok(agent)
}

fn device_service_mode(client: Option<&Value>) -> Option<&str> {
    client.and_then(|config| config["service_mode"].as_str())
        .filter(|mode| matches!(*mode, "normal" | "readonly" | "off"))
}

pub fn readonly_mode() -> Result<bool> {
    let (client, agent) = read_settings()?;
    Ok(agent["readonly_team"].as_bool().unwrap_or(false)
        || match device_service_mode(client.as_ref()) {
            Some(mode) => mode == "readonly",
            None => agent["readonly"].as_bool().unwrap_or(false),
        })
}

/// Preserve the host write gate without opening the store or loading Core.
pub fn ensure_writable() -> Result<()> {
    if readonly_mode()? {
        let hint = if read_agent_config()?["readonly_team"].as_bool().unwrap_or(false) {
            "read-only is enforced by the server via the session token; editing local agent.json has no effect. To write, ask the space owner for a read-write session and run rsrs space join."
        } else {
            "restore normal service on this device with `agent-config --set workspace_mode=normal`."
        };
        anyhow::bail!(
            "this space is read-only \u{2014} recall/list/show/diary/tree are allowed; write/edit/delete are not.\n  {hint}"
        );
    }
    Ok(())
}

pub fn off_mode() -> Result<bool> {
    let (client, agent) = read_settings()?;
    Ok(match device_service_mode(client.as_ref()) {
        Some(mode) => mode == "off",
        None => agent["memory_off"].as_bool().unwrap_or(false),
    })
}

pub fn mirror_from_env() -> Result<Option<String>> {
    // Validate client.json even when the environment supplies the selected mirror.
    let agent = read_agent_config()?;
    Ok(crate::env::var("RSRS_MIRROR").ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| agent["model_mirror"].as_str().map(str::to_owned)))
}
