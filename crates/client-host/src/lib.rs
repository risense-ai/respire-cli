#![forbid(unsafe_code)]

//! Client host helpers shared without app or Core dependencies.

pub mod env;
pub mod paths;
mod version;

pub use version::version_cmp;
