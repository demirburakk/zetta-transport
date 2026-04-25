//! # ZettaTransport (ZT)
//!
//! An industrial-grade, ultra-resilient transport layer protocol built on top of UDP using **Rust 2024**.
//! It is specifically engineered for the high-throughput, low-latency, and extreme-security requirements of
//! **autonomous drone swarms, real-time robotics, and edge IoT networks** operating in hostile or unstable RF environments.
//!
//! ## Core Features
//!
//! * **Active FEC & AIMD:** Dual-engine Forward Error Correction (XOR Parity and Reed-Solomon) mathematically
//!   reconstructs dropped packets. AIMD congestion control protects against buffer bloat.
//! * **Zero-Trust Security:** X25519 Diffie-Hellman key exchange and ChaCha20-Poly1305 AEAD payload encryption.
//! * **O(1) Replay Protection:** A blazing-fast sliding window algorithm drops malicious replay attacks instantly.
//! * **Seamless Mobility:** Connections use an 8-byte Connection ID (CID) rather than relying on IP/Port pairs.
//!   If an edge device switches networks (e.g., Wi-Fi to 5G), the connection seamlessly resumes.
//!
//! ## Quick Start: Secure Client-Server Communication
//!
//! ```rust,no_run
//! use zetta_transport::{ZtEndpoint, Result};
//! use bytes::Bytes;
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Start the Server Node (Gateway)
//!     let mut server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
//!     println!("Server listening on port 4433...");
//!
//!     // Start the Client Node (Edge Device)
//!     let mut client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
//!     
//!     // Handshake and Connect
//!     let peer_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
//!     client.connect(peer_addr).await?;
//!     
//!     // Dispatch Telemetry Data (Client -> Server)
//!     let payload = Bytes::from("{\"telemetry\": {\"alt\": 120.5, \"batt\": 98.2}}");
//!     client.send(server.local_addr().unwrap().ip().to_string().as_bytes(), &payload).await?;
//!
//!     // Receive Data (Server)
//!     if let Some(received) = server.recv().await {
//!         println!("Received cryptographically verified data from {:?}", received.cid);
//!     }
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Architecture Overview
//! MAVLink, ROS2 DDS, or raw telemetry frames can be passed down to the `ZtEndpoint` or `ZtStream`.
//! The protocol layers robust sequence numbering, handles packet fragmentation, and guards against
//! connection truncation and spoofing.

mod connection;
mod crypto;
mod endpoint;
pub mod error;
mod fec;
mod packet;
pub mod stream;

pub use endpoint::{ReceivedData, ZtEndpoint};
pub use error::{Result, ZtError};
pub use stream::ZtStream;
