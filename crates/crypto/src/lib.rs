#![forbid(unsafe_code)]
pub mod crypto;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub use engine::{hydrate_local, reembed_embedding, MemoryEngine, SessionKeys};
pub use respire_protocol as model;
