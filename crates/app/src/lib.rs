#![forbid(unsafe_code)]


//! respire_app — auth, service, taxonomy, inject, lock, sync, and remote transport
//!
//! Public application services use the binary Core SDK and public ciphertext helpers.

pub use respire_core_sdk::env;

#[cfg(test)]
mod test_lock;

pub mod auth;
pub mod input_error;
pub mod login_transaction;
pub mod inject;
pub mod lock;
pub mod migration;
pub mod service;
pub mod sync;
pub mod taxonomy;
pub mod transport;
pub use respire_core_sdk as core_sdk;

pub mod memory {
    pub use respire_core_sdk::{bge, defrag, onnx, search};
    pub use respire_crypto::{crypto, engine};
    pub use respire_crypto::{hydrate_local, reembed_embedding, MemoryEngine, SessionKeys};
    pub use respire_protocol as model;
    pub use respire_protocol::{Kind, MemoryEntry, MemoryQuery, VERSION_TAG};
}

pub use memory::{hydrate_local, MemoryEngine, SessionKeys};
pub use memory::model::{Kind, MemoryEntry, MemoryQuery, StoredMemory, VERSION_TAG};
pub use transport::MemoryTransport;

/// Compatibility version exported for server health responses.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod share;

pub mod keystore;

pub mod prompt;
