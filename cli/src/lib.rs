#![forbid(unsafe_code)]

//! rsrs CLI library: command surface and CLI-only modules.
//! Business execution stays behind Runtime RPC.
//!
//! Module map:
//! + host UI: prompt / inject / recall_fusion
//! + inject_tui / space / update_check and pure memory protocol types
//! + re-export the shared command surface: respire_commands (cli_def gates output output_state i18n
//!   metadata review autostart classify app_version)
//! + main: CLI entry

pub use respire_client_host::env;
pub use respire_commands::app_version;
pub use respire_commands::autostart;
pub use respire_commands::classify;
pub use respire_commands::cli_def;
pub use respire_commands::gates;
pub use respire_commands::i18n;
pub use respire_commands::metadata;
pub use respire_commands::net_rpc;
pub use respire_commands::output;
pub use respire_commands::output_state;
pub use respire_commands::review;
pub use respire_commands::runtime_error;
pub use respire_commands::runtime_policy;
pub mod extract_tui;
mod host_ui;
pub use host_ui::{inject, prompt, recall_fusion};
pub mod inject_tui;
pub use respire_client_host::lock;
pub mod memory;
pub use respire_commands::model_progress;
pub mod space;
pub mod update_check;

pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};

/// Version string (used by server /health).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
