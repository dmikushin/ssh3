use crate::msg::FailReason;

/// Application close codes on the QUIC connection.
pub mod close {
    pub const SHUTDOWN: u32 = 0;
    pub const PROTOCOL: u32 = 1;
    pub const AUTH_FAILED: u32 = 2;
    pub const SUPERSEDED: u32 = 3;
    pub const RESOURCE_LIMIT: u32 = 4;
    pub const INTERNAL: u32 = 5;
    /// The client ended the session on purpose (SPEC §5): destroy it, do not
    /// linger.
    pub const SESSION_END: u32 = 6;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("host key verification failed: {0}")]
    HostKey(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("tls configuration: {0}")]
    Tls(String),
    #[error("request refused by peer: {0}")]
    Refused(FailReason),
    #[error("carrier connection lost")]
    CarrierLost,
    #[error("timed out: {0}")]
    Deadline(String),
    /// Every address of the server was tried and none completed a
    /// handshake; names each address with its error.
    #[error("no address reachable: {0}")]
    Unreachable(String),
}

pub type Result<T> = std::result::Result<T, Error>;
