use std::io;
use std::process::{Child, Command, Stdio};

/// Keep control-child lifetime separate from the caller's detached Runtime.
pub fn spawn_control_helper(command: &mut Command) -> io::Result<Child> {
    command
        .env_remove("RSRS_RUNTIME_BOOT_TOKEN")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    crate::spawn_host_control(command)
}
