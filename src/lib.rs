//! # ZettaTransport (ZT)
//!
//! **An Experimental, Multiplexed UDP-Based Transport Protocol**
//!
//! > **Note:** ZettaTransport is primarily a **hobby and learning project**. It is an 
//! > experimental playground for exploring network protocol design, congestion control, 
//! > multiplexing, and cryptographic transport. It is **not** intended for mission-critical 
//! > or production use.
//!
//! ZettaTransport is a research-oriented transport protocol built in Rust. It operates
//! over UDP and aims to provide reliable, in-order delivery of multiplexed streams with built-in
//! cryptography (AEAD ChaCha20-Poly1305 and X25519 Diffie-Hellman).
//!
//! ## Core Features Explored
//!
//! - **Multiplexed Streams:** Transfer multiple independent data streams over a single connection,
//!   studying solutions to Head-of-Line blocking.
//! - **In-Place Crypto:** Utilizes in-place AEAD encryption/decryption to minimize
//!   memory allocation overhead.
//! - **Fast Retransmit & AIMD:** Implements basic TCP-like congestion control and loss recovery.
//! - **Key Rotation:** Explores epoch-based encryption key rotation for long-lived connections.
//! - **Anti-Amplification (DoS Mitigation):** Enforces a 1200-byte minimum padding size for
//!   initial handshake packets to study IP spoofing defenses.
//! - **Path MTU Discovery (PMTUD):** Dynamically probes the network path to discover the maximum
//!   transmission unit.
//!
//! ## Quick Start
//!
//! ### Server Example
//!
//! ```no_run
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Bind the endpoint to a local UDP port
//!     let server = ZtEndpoint::bind("127.0.0.1:8080", None).await?;
//!     
//!     // Listen for incoming connections
//!     while let Some(mut stream) = server.accept().await {
//!         tokio::spawn(async move {
//!             while let Some(data) = stream.recv().await {
//!                 println!("Received: {:?}", String::from_utf8_lossy(&data));
//!                 let _ = stream.send(b"ACK").await;
//!             }
//!         });
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ### Client Example
//!
//! ```no_run
//! use zetta_transport::transport::endpoint::ZtEndpoint;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Bind the client endpoint to a random port
//!     let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
//!     
//!     // Connect to the remote server
//!     let target = "127.0.0.1:8080".parse()?;
//!     let mut stream = client.connect(target).await?;
//!     
//!     // Send data reliably over the multiplexed stream
//!     stream.send(b"Hello Zetta!").await?;
//!     
//!     Ok(())
//! }
//! ```

pub mod crypto;
pub mod error;
pub mod protocol;
pub mod stream;
pub mod transport;
