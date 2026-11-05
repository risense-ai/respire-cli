//! Shared client paths; only environment, filesystem paths and home lookup.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};

/// Expand `~` (`~/` and Windows `~\` both count) — **the only impl**; do not rewrite elsewhere.
///
/// Why (2026-09-20 audit): this fn used to have three independent impls (two here + web.rs),
/// and they disagreed — inject.rs accepted `~\`, service.rs three sites only `~/`, so on Windows
/// `~\...` paths did not expand. Now collected here; every caller uses this.
pub fn expand_tilde(v: &str) -> PathBuf {
    if let Some(rest) = v.strip_prefix("~/").or_else(|| v.strip_prefix("~\\")) {
        if let Ok(h) = home_dir() {
            return h.join(rest);
        }
    }
    PathBuf::from(v)
}

/// Resolve `RSRS_DATA_DIR` to an absolute path (None if unset or empty).
/// Semantics: the env var names the profile root — the `main` profile is that root, space profiles live under its `accounts/`,
/// and client.json lives there too (an isolated instance must not write config into the real user dir).
pub fn env_root_dir() -> Option<PathBuf> {
    let v = crate::env::var("RSRS_DATA_DIR").ok()?;
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    if internally_configured_root(v) {
        return None;
    }
    Some(expand_tilde(v))
}

// Sunk from the client-side migration module (WP-2c): engine flows must classify the
// internally configured default home, and the domain crate cannot reach back into the
// client crate. The client migration module re-imports this function.
const DEFAULT_ENV: &str = "RSRS_DEFAULT_DATA_DIR";

/// The SDK accepts the original data-root environment variable. This marker lets
/// app configuration retain its default-home and active-profile semantics.
pub fn internally_configured_root(value: &str) -> bool {
    crate::env::var(DEFAULT_ENV).ok().is_some_and(|marker| {
        equivalent_path(
            &expand_tilde(&marker),
            &expand_tilde(value),
        ) && equivalent_path(
            &expand_tilde(value),
            &default_data_dir(),
        )
    })
}

fn equivalent_path(left: &Path, right: &Path) -> bool {
    let absolute = |path: &Path| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|root| root.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    };
    let normalize = |path: PathBuf| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                _ => normalized.push(component.as_os_str()),
            }
        }
        normalized
    };
    let left = normalize(absolute(left));
    let right = normalize(absolute(right));
    if cfg!(windows) {
        left.to_string_lossy()
            .replace('/', "\\")
            .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
    } else {
        left == right
    }
}

pub fn default_data_dir() -> PathBuf {
    home_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".rsrs")
}

pub fn home_dir() -> Result<PathBuf> {
    if let Ok(home) = crate::env::var("HOME") {
        if !home.trim().is_empty() {
            return Ok(PathBuf::from(home));
        }
    }
    dirs::home_dir().ok_or_else(|| anyhow!("cannot determine home directory"))
}
