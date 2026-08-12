//! # ZettaTransport
//!
//! ZettaTransport is an experimental, encrypted, multiplexed transport protocol over UDP.
//! It provides reliable ordered streams, unreliable datagrams, Tokio asynchronous I/O,
//! congestion control, flow control, path validation, and path-MTU discovery.
//!
//! > **Experimental software:** this crate implements a custom protocol, not QUIC. It has not
//! > received an independent security audit and is not intended for production or
//! > mission-critical deployments. Prefer a standards-based QUIC implementation when
//! > interoperability or production assurance is required.
//!
//! ## Start here
//!
//! Most applications use these types:
//!
//! - [`ZtEndpoint`](transport::endpoint::ZtEndpoint) owns a UDP socket and creates connections.
//! - [`ZtConnectionHandle`](stream::ZtConnectionHandle) opens/accepts streams and sends datagrams.
//! - [`ZtStream`](stream::ZtStream) is a reliable ordered byte stream implementing
//!   [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`].
//! - [`ZtConfig`](config::ZtConfig) controls timeouts, limits, MTU discovery, security, and
//!   congestion control.
//! - [`ZtError`](error::ZtError) exposes typed transport failures.
//!
//! Add the crate and the Tokio runtime to your project:
//!
//! ```toml
//! [dependencies]
//! zetta-transport = "0.1.26"
//! tokio = { version = "1", features = ["full"] }
//! bytes = "1"
//! ```
//!
//! ## Echo server
//!
//! The endpoint is reference-counted. Each accepted connection owns its incoming stream queue,
//! and every accepted stream can be processed in its own task.
//!
//! ```no_run
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let endpoint = ZtEndpoint::bind("0.0.0.0:4433", None).await?;
//!     println!("listening on {}", endpoint.local_addr()?);
//!
//!     while let Some(mut connection) = endpoint.accept().await {
//!         tokio::spawn(async move {
//!             while let Some(mut stream) = connection.accept_stream().await {
//!                 tokio::spawn(async move {
//!                     let mut buffer = [0_u8; 16 * 1024];
//!                     loop {
//!                         let read = match stream.read(&mut buffer).await {
//!                             Ok(0) | Err(_) => break,
//!                             Ok(read) => read,
//!                         };
//!                         if stream.write_all(&buffer[..read]).await.is_err() {
//!                             break;
//!                         }
//!                     }
//!                 });
//!             }
//!         });
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Client
//!
//! ```no_run
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let endpoint = ZtEndpoint::bind("0.0.0.0:0", None).await?;
//!     let connection = endpoint.connect("127.0.0.1:4433".parse()?).await?;
//!     let mut stream = connection.open_stream().await?;
//!
//!     stream.write_all(b"hello").await?;
//!     stream.flush().await?;
//!
//!     let mut reply = [0_u8; 5];
//!     stream.read_exact(&mut reply).await?;
//!     assert_eq!(&reply, b"hello");
//!     Ok(())
//! }
//! ```
//!
//! ## Streams and datagrams
//!
//! [`stream::ZtConnectionHandle::open_stream`] creates a bidirectional stream. Use
//! [`stream::ZtConnectionHandle::open_stream_with_type`] for a send-only stream. A receive-only
//! stream is created locally when the peer opens a send-only stream; it cannot be opened directly.
//! Dropping or calling [`stream::ZtStream::close`] gracefully finishes a stream. Use
//! [`stream::ZtStream::reset`] to terminate it with an application error code.
//!
//! Datagrams are encrypted and congestion-controlled but are not ordered or retransmitted. They
//! are appropriate only when losing an individual message is acceptable.
//!
//! ## Preserving close reasons
//!
//! Convenience receive methods return `Option` and collapse termination into `None`. Applications
//! that need the exact cause should use [`stream::ZtStream::recv_result`],
//! [`stream::ZtConnectionHandle::accept_stream_result`], and
//! [`stream::ZtConnectionHandle::recv_datagram_result`]. These methods preserve peer reset codes,
//! peer connection-close reasons, and idle timeouts.
//!
//! ## Authentication
//!
//! Every endpoint creates an Ed25519 identity at bind time and uses ephemeral X25519 keys for each
//! connection. By default, cryptographic identity proves handshake integrity but is not tied to a
//! trusted name. Experiments that need peer authentication should install a verifier with
//! [`transport::endpoint::ZtEndpoint::set_peer_key_verifier`] and may additionally configure a
//! shared 32-byte PSK through [`config::ZtConfig::psk`]. Endpoint identities are currently
//! ephemeral unless the application pins and redistributes the exposed public key itself.
//!
//! ## Protocol compatibility
//!
//! Version 0.1.26 speaks ZettaTransport wire protocol version 2. Version 2 is intentionally not
//! wire-compatible with earlier crate releases: it signs transport parameters, transmits stream
//! direction on the wire, and includes a final byte offset in graceful stream closure.
//!
//! See the crate modules below for the complete API and the repository's `DOCUMENTATION.md` for
//! packet/frame layout and protocol internals.

#![warn(missing_docs)]

/// Endpoint configuration and validation.
pub mod config;
pub(crate) mod crypto;
/// Public error and result types.
pub mod error;
pub(crate) mod protocol;
/// Connection telemetry snapshots.
pub mod stats;
/// Connection and stream application APIs.
pub mod stream;
/// Endpoint construction, stream direction, and congestion-control selection.
pub mod transport;

#[cfg(any(test, feature = "testing"))]
/// Deterministic endpoint-scoped network fault injection for tests.
pub mod simulation;

/// Narrow test-only entry points used by the out-of-process fuzz targets.
#[cfg(any(test, feature = "testing"))]
pub mod fuzzing {
    /// Decodes a complete frame corpus, guaranteeing forward progress even for malformed input.
    pub fn decode_frames(data: &[u8]) {
        let mut bytes = bytes::Bytes::copy_from_slice(data);
        while !bytes.is_empty() {
            let before = bytes.len();
            if crate::protocol::frame::Frame::decode(&mut bytes).is_err() {
                break;
            }
            if bytes.len() >= before {
                break;
            }
        }
    }
}
