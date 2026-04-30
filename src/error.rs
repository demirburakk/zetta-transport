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

    /// Packet number overflowed its bounds.
    #[error("Packet number overflow")]
    PacketNumberOverflow,

    /// Connection ID allocation failed/exhausted.
    #[error("Connection ID exhausted")]
    ConnectionIdExhausted,

    /// Actor task failed or channel closed.
    #[error("Actor task failed")]
    ActorFailed,

    /// Send was blocked because the peer's flow control window is full.
    /// The caller should retry after the window opens.
    #[error("Flow control window is full")]
    FlowControlBlocked,

    /// Send was blocked because the local congestion window is full.
    /// The caller should retry after in-flight bytes decrease.
    #[error("Congestion window is full")]
    CongestionWindowFull,

    /// The connection has reached its maximum number of concurrent streams.
    #[error("Too many concurrent streams (limit: {limit})")]
    TooManyStreams { limit: usize },
}

/// A specialized Result type for ZettaTransport operations.
pub type Result<T> = std::result::Result<T, ZtError>;
