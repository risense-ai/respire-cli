#![forbid(unsafe_code)]

//! rsrs CLI library: command surface and CLI-only modules.
//! Domain logic lives in app-core; this crate re-exports it.
//!
//! Module map:
//! + re-export app-core: auth keystore prompt share sync transport lock taxonomy service inject memory
//! + hooks / inject_tui / model_install / space / update_check / classify / bench / web
//! + main: CLI entry

pub use respire_app::auth;
pub use respire_app::core_sdk;
pub mod hooks;
pub use respire_app::inject;
pub mod inject_tui;
pub use respire_app::keystore;
pub use respire_app::lock;
pub use respire_app::migration;
pub mod memory;
pub mod model_install;
pub mod model_progress;
pub use respire_app::prompt;
pub use respire_app::service;
pub use respire_app::share;
pub mod space;
pub use respire_app::sync;
pub use respire_app::taxonomy;
pub use respire_app::transport;
pub mod update_check;

pub use memory::engine::{hydrate_local, MemoryEngine, SessionKeys};
pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};
pub use transport::MemoryTransport;

/// Version string (used by server /health).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
