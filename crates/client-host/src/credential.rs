//! Read an existing runtime token without generating or replacing credentials.

use std::path::Path;

use anyhow::{Context, Result};

pub fn read_token_file(path: &Path) -> Result<Option<String>> {
    let value = match std::fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot read runtime token {}", path.display()))
        }
    };
    let token = value.trim();
    anyhow::ensure!(
        !token.is_empty(),
        "runtime token {} is empty",
        path.display()
    );
    Ok(Some(token.to_owned()))
}
