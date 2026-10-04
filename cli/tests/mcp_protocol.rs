//! Stdio MCP protocol smoke: initialize, tools/list, ping. Does not write memories.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rsrs")
}

#[test]
fn stdio_initialize_lists_all_tools() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let mut child = Command::new(bin())
        .arg("mcp")
        .env("ONEMEMORY_DATA_DIR", dir.path())
        .env("ONEMEMORY_BIN_DIR", &bin_dir)
        .env_remove("ONEMEMORY_LANG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child.stdin.as_mut().ok_or("stdin")?;
        stdin.write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"ping"}
"#,
        )?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(format!(
            "mcp exit {:?} stderr {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let stdout = String::from_utf8(output.stdout)?;
    let mut saw_init = false;
    let mut saw_list = false;
    let mut saw_ping = false;
    let mut names = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)?;
        match value["id"].as_u64() {
            Some(1) => {
                saw_init = value["result"]["protocolVersion"] == "2025-03-26";
            }
            Some(2) => {
                saw_list = true;
                if let Some(tools) = value["result"]["tools"].as_array() {
                    names = tools
                        .iter()
                        .filter_map(|tool| tool["name"].as_str().map(ToOwned::to_owned))
                        .collect();
                }
            }
            Some(3) => saw_ping = value.get("result").is_some(),
            _ => {}
        }
    }
    if !saw_init {
        return Err(format!("initialize missing in {stdout}").into());
    }
    if !saw_ping {
        return Err("ping missing".into());
    }
    if !saw_list {
        return Err("tools/list missing".into());
    }
    for want in [
        "memory_status",
        "memory_remember",
        "memory_recall",
        "memory_list",
        "memory_show",
        "memory_update",
        "memory_attach",
        "memory_tree",
        "memory_history",
        "memory_diary",
        "memory_chain",
        "memory_query_log_mark",
        "memory_forget",
        "memory_restore",
        "memory_taxonomy",
    ] {
        if !names.iter().any(|name| name == want) {
            return Err(format!("missing tool {want} in {names:?}").into());
        }
    }
    let _ = Duration::from_millis(1);
    Ok(())
}
