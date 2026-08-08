//! # ZettaTransport (ZT)
//!
//! **An Experimental, High-Performance, Multiplexed UDP-Based Transport Protocol**
//!
//! > **Note:** ZettaTransport is primarily a **hobby and learning project**. It is an
//! > experimental playground for exploring network protocol design, congestion control,
//! > multiplexing, and cryptographic transport. It is **not** intended for mission-critical
//! > or production use.
//!
//! ZettaTransport is a research-oriented transport protocol built in Rust. It operates
//! over UDP and provides a robust feature set normally found in modern standard protocols (like QUIC),
//! including reliable in-order delivery of multiplexed streams, low-latency unreliable datagrams,
//! auto-tuning flow control, pluggable congestion control, and built-in cryptography.
//!
//! ## Core Capabilities
//!
//! - **Multiplexed Streams (tokio::io compatible):** Open multiple independent streams over a single connection
//!   to completely eliminate Head-of-Line (HoL) blocking. `ZtStream` fully implements `tokio::io::AsyncRead`
//!   and `tokio::io::AsyncWrite`, making it natively compatible with the Tokio ecosystem (e.g., `tokio::io::copy`).
//! - **Unreliable Datagram API:** In addition to reliable streams, ZettaTransport supports low-latency,
//!   unreliable datagrams (`send_datagram` / `recv_datagram`). Datagrams bypass stream sequencing and retransmission,
//!   making them ideal for real-time applications like multiplayer gaming or VoIP, while still respecting connection-level congestion control.
//! - **Pluggable Congestion Control (CUBIC by default):** Implements modern congestion control. By default, it uses
//!   **CUBIC** (RFC 8312) to efficiently scale window growth on high-bandwidth, high-latency (BDP) networks. Classic **TCP Reno** (AIMD) is also available.
//! - **Zero-Copy Transmission:** Provides a `send_bytes` method that takes `bytes::Bytes` payloads,
//!   allowing data to be sent out in MTU-sized chunks without allocation or copying overhead.
//! - **Cryptographic Security:** Every packet is encrypted in-place using **ChaCha20-Poly1305** AEAD,
//!   with initial handshakes secured by **X25519 Diffie-Hellman** and **Ed25519** signatures.
//! - **Path MTU Discovery (PMTUD):** Dynamically probes the network path to discover the Maximum
//!   Transmission Unit, upgrading the packet size up to 9000 bytes when jumbo frames are supported.
//!
//! ## Comprehensive Examples
//!
//! ### 1. Reliable Multiplexed Streams (Echo Server)
//!
//! This example demonstrates how to use the standard `tokio::io` traits to build a concurrent echo server.
//!
//! ```no_run
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Bind the endpoint to a local UDP port using default CUBIC congestion control.
//!     let server = ZtEndpoint::bind("127.0.0.1:8080", None).await?;
//!     println!("Server listening on {}", server.local_addr()?);
//!     
//!     while let Some(mut conn) = server.accept().await {
//!         tokio::spawn(async move {
//!             // Accept multiple concurrent streams from the same connection
//!             while let Some(mut stream) = conn.accept_stream().await {
//!                 tokio::spawn(async move {
//!                     let mut buf = vec![0u8; 1024];
//!                     // ZtStream implements AsyncRead and AsyncWrite
//!                     while let Ok(n) = stream.read(&mut buf).await {
//!                         if n == 0 { break; } // EOF
//!                         let _ = stream.write_all(&buf[..n]).await;
//!                     }
//!                 });
//!             }
//!         });
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### 2. Low-Latency Datagrams & Connection Stats
//!
//! Datagrams are perfect for real-time state sync. Here is how a client sends datagrams and reads connection telemetry.
//!
//! ```no_run
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
//!     let mut conn = client.connect("127.0.0.1:8080".parse()?).await?;
//!     
//!     // Send an unreliable, unsequenced datagram (still governed by CUBIC pacing)
//!     conn.send_datagram(Bytes::from_static(b"player_position_update")).await?;
//!     
//!     // Receive datagrams from the peer
//!     if let Some(datagram) = conn.recv_datagram().await {
//!         println!("Received datagram: {:?}", datagram);
//!     }
//!
//!     // Inspect real-time transport statistics
//!     let stats = conn.stats().await?;
//!     println!("RTT: {:?}, CWND: {} bytes, MTU: {} bytes", stats.rtt, stats.cwnd, stats.mtu);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### 3. Zero-Copy Stream Transmission
//!
//! For high-throughput scenarios, avoid copying memory by passing `Bytes` directly to `send_bytes`.
//!
//! ```no_run
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//! use bytes::Bytes;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
//!     let mut conn = client.connect("127.0.0.1:8080".parse()?).await?;
//!     let mut stream = conn.open_stream().await?;
//!     
//!     let payload = Bytes::from(vec![0u8; 1024 * 1024]); // 1MB payload
//!     
//!     // Sent without memory copies; the stream chunks it directly onto the network.
//!     stream.send_bytes(payload).await?;
//!     
//!     Ok(())
//! }
//! ```

pub(crate) mod crypto;
pub mod error;
pub(crate) mod protocol;
pub mod stream;
pub mod transport;
pub mod config;
pub mod stats;

#[cfg(any(test, feature = "testing"))]
pub mod simulation;

