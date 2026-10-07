//! Invalid command input is distinct from storage, network and engine failures.

#[derive(Debug)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for InputError {}

/// Missing user-selected files are input errors. Other I/O failures remain runtime failures.
pub fn read_file(path: &std::path::Path, purpose: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path).map_err(|error| {
        let message = format!("failed to read {purpose}: {} ({error})", path.display());
        if error.kind() == std::io::ErrorKind::NotFound {
            InputError(message).into()
        } else {
            anyhow::Error::new(error).context(message)
        }
    })
}
