use thiserror::Error;

/// Error types for the ZettaTransport protocol.
#[derive(Error, Debug)]
pub enum ZtError {
    /// Errors related to underlying network IO.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Errors occurring during encryption or decryption (AEAD failures, etc).
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Errors related to malformed or unexpected packet structures.
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Triggered when a connection attempt or a reliable packet times out.
    #[error("Connection timed out")]
    Timeout,

    /// Triggered when unauthorized access is detected or CID mismatch occurs.
    #[error("Unauthorized access")]
    Unauthorized,

    /// Generic catch-all error for unknown issues.
    #[error("Unknown error")]
    Unknown,
}

/// A specialized Result type for ZettaTransport operations.
pub type Result<T> = std::result::Result<T, ZtError>;