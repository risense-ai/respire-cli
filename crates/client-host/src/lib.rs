#![forbid(unsafe_code)]

//! Client host helpers shared without app or Core dependencies.

pub mod env;
#[cfg(feature = "locks")]
pub mod lock;
pub mod paths;
mod version;

pub use version::version_cmp;
