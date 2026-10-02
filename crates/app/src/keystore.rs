//! keystore — super-password (v4 single-factor key) storage.
//!
//! Priority: OS keyring (gnome-keyring/Keychain/Credential Manager) > env ONEMEMORY_SUPER
//! > none. Plaintext is never written to session.json from v4 on — a disk copy cannot decrypt.
//! Headless servers (no keyring) use ONEMEMORY_SUPER or pass --super each time.

use anyhow::{anyhow, Result};

const SERVICE: &str = "respire";

fn entry(user: &str) -> Result<keyring::Entry> {
    // Pure local keygen has no account name — use the "local" slot
    let acct = if user.trim().is_empty() { "local" } else { user.trim() };
    keyring::Entry::new(SERVICE, &format!("super:{acct}"))
        .map_err(|e| anyhow!("keyring init failed: {e}"))
}

/// Save the super password into the OS keyring. Headless with no keyring returns Err
/// (caller warns and falls back to the env var).
pub fn save_super(user: &str, super_pass: &str) -> Result<()> {
    entry(user)?
        .set_password(super_pass)
        .map_err(|e| anyhow!("keyring write failed ({e}) — on a headless server set ONEMEMORY_SUPER"))
}

fn login_entry(user: &str) -> Result<keyring::Entry> {
    let acct = if user.trim().is_empty() { "local" } else { user.trim() };
    keyring::Entry::new(SERVICE, &format!("pass:{acct}"))
        .map_err(|e| anyhow!("keyring init failed: {e}"))
}

/// Save the server login password next to the super password.
/// The web client reads it back so a later open does not ask again.
/// Plaintext still never goes into session.json.
pub fn save_login_pass(user: &str, pass: &str) -> Result<()> {
    if pass.is_empty() {
        return Ok(());
    }
    login_entry(user)?
        .set_password(pass)
        .map_err(|e| anyhow!("keyring write failed ({e}) — the login password was not stored"))
}

/// Load the server login password from the OS keyring. None if the slot is missing.
pub fn load_login_pass(user: &str) -> Option<String> {
    login_entry(user)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| !v.is_empty())
}

/// Delete the stored login password (logout --full).
pub fn delete_login_pass(user: &str) {
    match login_entry(user) {
        Ok(e) => {
            if let Err(err) = e.delete_credential() {
                eprintln!("warning: failed to delete login password from keyring ({err})");
            }
        }
        Err(err) => eprintln!("warning: keyring unavailable, could not delete login password ({err})"),
    }
}

/// Load super password: OS keyring → env ONEMEMORY_SUPER → None.
/// Any failure of entry()/get_password() (headless, no keyring) must fall through to the env var.
pub fn load_super(user: &str) -> Option<String> {
    let from_ring = entry(user)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| !v.is_empty());
    from_ring.or_else(|| {
        std::env::var("ONEMEMORY_SUPER")
            .ok()
            .filter(|s| !s.is_empty())
    })
}

/// Delete the super password from the keyring (logout --full / post-reset cleanup).
///
/// Failures must be reported (L8, 2026-09-20 audit): a silent failure makes the user
/// think the key is gone while the keyring still holds a code that unlocks all memories.
pub fn delete_super(user: &str) {
    match entry(user) {
        Ok(e) => {
            if let Err(err) = e.delete_credential() {
                eprintln!("warning: failed to delete super password from keyring ({err}) — on a shared machine clear it from Credential Manager");
            }
        }
        Err(err) => eprintln!("warning: keyring unavailable, could not delete super password ({err})"),
    }
}

// ───────────────────── classify (classification backend) API key ─────────────────────

/// classify backend slot (separate account under the same OS keyring service).
/// DS backends are keyed by **endpoint host** — official deepseek.com and b.ai relay keys
/// are not interchangeable; sharing one slot overwrites the other (hit 2026-09-20).
fn classify_entry(backend: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, &format!("classify:{backend}"))
        .map_err(|e| anyhow!("keyring init failed: {e}"))
}

/// Host from an endpoint URL, used as the DS key-slot suffix (e.g. api.deepseek.com / api.b.ai).
pub fn host_of(base: &str) -> String {
    let b = base.trim();
    let rest = b.split_once("://").map(|(_, r)| r).unwrap_or(b);
    rest.split(['/', '?', '#']).next().unwrap_or(rest).to_owned()
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn host_of_strips_scheme_and_path() {
        assert_eq!(host_of("https://api.deepseek.com/v1"), "api.deepseek.com");
        assert_eq!(host_of("api.b.ai/chat"), "api.b.ai");
        assert_eq!(host_of("  https://x.test/a?b=1#c  "), "x.test");
    }

    #[test]
    fn load_super_falls_back_to_env() {
        let _guard = crate::test_lock::guard();
        let saved = std::env::var("ONEMEMORY_SUPER").ok();
        std::env::set_var("ONEMEMORY_SUPER", "env-super");
        let got = load_super("no-such-user-zzzz");
        assert_eq!(got.as_deref(), Some("env-super"));
        match saved {
            Some(v) => std::env::set_var("ONEMEMORY_SUPER", v),
            None => std::env::remove_var("ONEMEMORY_SUPER"),
        }
    }
}

/// Save a classify backend key (backend ∈ "ds" | "typesafe").
pub fn save_classify_key(backend: &str, key: &str) -> Result<()> {
    classify_entry(backend)?
        .set_password(key)
        .map_err(|e| anyhow!("keyring write failed ({e}) — without a keyring set TYPESAFE_API_KEY / DS_API_KEY"))
}

/// Load a classify backend key: OS keyring → env (DS_API_KEY / TYPESAFE_API_KEY) → None.
pub fn load_classify_key(backend: &str) -> Option<String> {
    let from_ring = classify_entry(backend)
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| !v.is_empty());
    from_ring.or_else(|| {
        let var = if backend.starts_with("ds") { "DS_API_KEY" } else { "TYPESAFE_API_KEY" };
        std::env::var(var).ok().filter(|s| !s.is_empty())
    })
}

/// Remember the last DS endpoint used (including path, e.g. https://api.b.ai/v1)
/// so a stored key is not paired with a host that dropped the path.
pub fn save_ds_last_base(base: &str) {
    if let Ok(e) = keyring::Entry::new(SERVICE, "classify:ds-last-base") {
        let _ = e.set_password(base);
    }
}

/// Load the last DS endpoint used (full base).
pub fn load_ds_last_base() -> Option<String> {
    keyring::Entry::new(SERVICE, "classify:ds-last-base")
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| !v.is_empty())
}

/// Remember the last model used for an endpoint (relay names differ: official deepseek-chat, b.ai deepseek-v4.1-flash).
pub fn save_ds_model(host: &str, model: &str) {
    if let Ok(e) = keyring::Entry::new(SERVICE, &format!("classify:ds-model@{host}")) {
        let _ = e.set_password(model);
    }
}

/// Load the last model used for an endpoint.
pub fn load_ds_model(host: &str) -> Option<String> {
    keyring::Entry::new(SERVICE, &format!("classify:ds-model@{host}"))
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| !v.is_empty())
}

/// Remember the classify backend choice (GUI "AI backend" dropdown; "jev" | "ds").
pub fn save_classify_backend(backend: &str) {
    if let Ok(e) = keyring::Entry::new(SERVICE, "classify:last-backend") {
        let _ = e.set_password(backend);
    }
}

/// Load the last classify backend (None if unset; caller picks the default).
pub fn load_classify_backend() -> Option<String> {
    keyring::Entry::new(SERVICE, "classify:last-backend")
        .ok()
        .and_then(|e| e.get_password().ok())
        .filter(|v| v == "jev" || v == "ds")
}

/// Delete a classify key from the keyring (key rotation / revoke).
pub fn delete_classify_key(backend: &str) {
    if let Ok(e) = classify_entry(backend) {
        let _ = e.delete_credential();
    }
}
