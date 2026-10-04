//! Errors that must never be mistaken for permission to take over a runtime.

use std::fmt;

#[derive(Debug)]
pub enum RuntimeError {
    Unavailable,
    TokenUnreadable(String),
    Unauthorized,
    Transport(String),
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "runtime_unavailable: host HTTP runtime is not running at {}; start `rsrs --runtime-internal` in the host terminal", crate::net_rpc::rpc_base_url()),
            Self::TokenUnreadable(detail) => write!(f, "runtime_token_unreadable: {detail}; have the host provide RPC authentication"),
            Self::Unauthorized => write!(f, "runtime_unauthorized: HTTP runtime rejected the request; loopback clients need an updated host runtime, and non-loopback clients need a valid token"),
            Self::Transport(detail) => write!(f, "runtime_transport: {detail}; check sandbox access to the host HTTP runtime"),
        }
    }
}

impl std::error::Error for RuntimeError {}

pub fn http(error: ureq::Error) -> anyhow::Error {
    match error {
        ureq::Error::Status(401 | 403, _) => RuntimeError::Unauthorized.into(),
        error => RuntimeError::Transport(error.to_string()).into(),
    }
}
