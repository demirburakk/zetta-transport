# ZettaTransport (ZT)

**An Experimental, UDP-Based Transport Protocol in Rust**

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/zetta-transport.svg)](https://crates.io/crates/zetta-transport)
[![Documentation](https://docs.rs/zetta-transport/badge.svg)](https://docs.rs/zetta-transport)

> **Note:** ZettaTransport is primarily a **hobby and learning project**. It is an experimental playground for exploring network protocol design, congestion control, multiplexing, and cryptographic transport. It is **not** intended for mission-critical or production use, but rather as a deep dive into how modern protocols like QUIC function under the hood.

ZettaTransport (ZT) is a research-oriented transport protocol built entirely in Rust. It operates over UDP and provides **reliable, in-order delivery** of **multiplexed streams** with built-in end-to-end encryption (AEAD ChaCha20-Poly1305, X25519 ECDH, Ed25519 authentication).

## ✨ Core Features

| Feature | Description |
|---|---|
| **Multiplexed Streams** | Multiple independent bidirectional data streams over a single UDP connection, eliminating TCP's Head-of-Line blocking. |
| **End-to-End Encryption** | X25519 ECDH key exchange + Ed25519 signature authentication + ChaCha20-Poly1305 AEAD for all payloads. |
| **In-Place Cryptography** | Encryption/decryption performed directly in mutable buffers — zero extra allocations on the data path. |
| **Forward Secrecy via Key Ratcheting** | Epoch-based key rotation with HKDF ratcheting and `zeroize` for secure erasure of old secrets. |
| **QUIC-Style Header Protection** | ChaCha20-based header obfuscation to prevent ossification by middleboxes. |
| **Stateless Retry (DoS Mitigation)** | HMAC-SHA256 cookie-based address validation before allocating any per-connection state. |
| **Anti-Amplification** | 1200-byte minimum Initial packet size + 3× amplification limit on server responses. |
| **Congestion Control (AIMD)** | Slow Start + Congestion Avoidance with byte-granular AIMD and RTO-based loss detection. |
| **Selective ACK (SACK)** | Range-based selective acknowledgments for efficient loss recovery. |
| **Path MTU Discovery** | Periodic probing at [1200, 1350, 1400, 1450, 1500] byte sizes to maximize throughput. |
| **O(1) Replay Protection** | 128-bit sliding window bitmask for constant-time duplicate packet detection. |
| **Per-Connection Actor Model** | Each connection runs as an independent Tokio task, achieving lock-free concurrency. |
| **Vectored I/O (Unix)** | `sendmsg(2)` syscall for scatter/gather I/O on Unix platforms. |

## 📦 Installation

Add ZettaTransport to your `Cargo.toml`:

```toml
[dependencies]
zetta-transport = "0.1.9"
tokio = { version = "1.52", features = ["full"] }
```

## 🚀 Quick Start

ZettaTransport exposes an asynchronous API built on [Tokio](https://tokio.rs/). The core abstractions are:

- **`ZtEndpoint`** — Binds a UDP socket, manages routing, and accepts/initiates connections.
- **`ZtConnectionHandle`** — Represents a connection to a remote peer. Open or accept streams through it.
- **`ZtStream`** — A reliable, encrypted, multiplexed data stream (similar to a TCP stream).

### Server

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind the endpoint to a local port.
    let server = ZtEndpoint::bind("127.0.0.1:8080", None).await?;
    println!("Server listening on 127.0.0.1:8080");

    // 2. Accept incoming connections.
    while let Some(mut conn) = server.accept().await {
        tokio::spawn(async move {
            // 3. Accept multiplexed streams (stream 0 is created automatically).
            while let Some(mut stream) = conn.accept_stream().await {
                println!("New stream opened: {}", stream.stream_id);

                // 4. Receive and send data reliably and in-order.
                while let Some(data) = stream.recv().await {
                    println!("Received: {:?}", String::from_utf8_lossy(&data));
                    let _ = stream.send(b"Message received!").await;
                }
            }
        });
    }

    Ok(())
}
```

### Client

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind the client to an available local UDP port.
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;

    // 2. Connect to the server (performs X25519 + Ed25519 handshake with Retry).
    let target: SocketAddr = "127.0.0.1:8080".parse()?;
    let mut conn = client.connect(target).await?;
    println!("Connected to the server!");

    // 3. Accept the default stream (stream 0).
    let mut stream = conn.accept_stream().await.expect("Stream 0");

    // 4. Send data — automatic chunking, backpressure, and congestion control.
    stream.send(b"Hello from ZettaTransport!").await?;

    // 5. Receive the response.
    if let Some(reply) = stream.recv().await {
        println!("Server replied: {:?}", String::from_utf8_lossy(&reply));
    }

    // 6. Gracefully close.
    stream.close().await?;
    conn.close().await?;

    Ok(())
}
```

### Multiple Streams

```rust
// Open additional streams on an existing connection
let mut stream_a = conn.open_stream().await?;
let mut stream_b = conn.open_stream().await?;

// Each stream has independent ordering and flow control
stream_a.send(b"Data on stream A").await?;
stream_b.send(b"Data on stream B").await?;
```

### Pre-Shared Key (PSK)

```rust
let psk: [u8; 32] = /* your pre-shared key */;
let server = ZtEndpoint::bind("0.0.0.0:8080", Some(psk)).await?;
let client = ZtEndpoint::bind("0.0.0.0:0", Some(psk)).await?;
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                    ZtEndpoint                        │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ UDP Socket │  │ Routing Table│  │   Crypto     │ │
│  │ (recv_from)│  │(DashMap<CID>)│  │ (X25519/Ed)  │ │
│  └─────┬──────┘  └──────┬───────┘  └──────────────┘ │
│        │                │                            │
│        └───── Router Task (packet dispatch) ─────────│
│                         │                            │
│          ┌──────────────┼──────────────┐             │
│          ▼              ▼              ▼             │
│   ┌────────────┐ ┌────────────┐ ┌────────────┐      │
│   │   Actor    │ │   Actor    │ │   Actor    │      │
│   │ (conn #1)  │ │ (conn #2)  │ │ (conn #N)  │      │
│   │            │ │            │ │            │      │
│   │ ┌────────┐ │ │ ┌────────┐ │ │ ┌────────┐ │      │
│   │ │Stream 0│ │ │ │Stream 0│ │ │ │Stream 0│ │      │
│   │ │Stream 1│ │ │ │Stream 1│ │ │ │Stream 1│ │      │
│   │ │  ...   │ │ │ │  ...   │ │ │ │  ...   │ │      │
│   │ └────────┘ │ │ └────────┘ │ │ └────────┘ │      │
│   └────────────┘ └────────────┘ └────────────┘      │
└──────────────────────────────────────────────────────┘
```

### Module Overview

| Module | File(s) | Responsibility |
|---|---|---|
| **`transport::endpoint`** | `endpoint.rs` | UDP socket management, packet routing via `DashMap`, X25519/Ed25519 handshake orchestration, Stateless Retry, connection lifecycle. |
| **`transport::actor`** | `actor.rs` | Per-connection async state machine. Handles congestion control, PMTUD, key rotation, retransmissions, keep-alives, delayed ACKs, and stream I/O. |
| **`transport::state`** | `state.rs` | `ZtConnection` state (RTT, CWND, unacked packets, replay bitmask), `StreamState` (ring buffer, reorder tracking), ACK/loss handling. |
| **`stream`** | `mod.rs` | `ZtConnectionHandle` (connection-level API) and `ZtStream` (stream-level `.send()`/`.recv()` API with backpressure). |
| **`protocol::packet`** | `packet.rs` | Long/Short header encoding/decoding, packet type definitions, PN offset calculation. |
| **`protocol::frame`** | `frame.rs` | Frame encoding/decoding: Padding, Stream, Ack (with SACK ranges), ConnectionClose, Handshake, Cookie, StreamClose. |
| **`crypto`** | `mod.rs` | HKDF-SHA256 key derivation, ChaCha20-Poly1305 AEAD, in-place encrypt/decrypt, nonce generation, key ratcheting with `zeroize`, QUIC-style header protection. |
| **`error`** | `error.rs` | `ZtError` enum: IO, Crypto, InvalidPacket, Timeout, Unauthorized, PacketNumberOverflow, ConnectionIdExhausted, ActorFailed. |
| **`util`** | `util.rs` | Fast DCID extraction for zero-parse packet routing. |

## 🔐 Security Model

### Handshake Flow

```
Client                                   Server
  │                                         │
  │──── Initial (X25519 + Ed25519 sig) ────▶│  ← 1200B padded
  │                                         │  Server: no cookie → Retry
  │◀───────── Retry (HMAC cookie) ──────────│
  │                                         │
  │── Initial (keys + cookie echoed) ──────▶│  ← Address validated
  │                                         │  Server: verify cookie, sig
  │◀──── Handshake (server X25519+Ed) ──────│  ← Session keys derived
  │                                         │
  │═══════ Encrypted Data Channel ═════════│
```

### Cryptographic Primitives

| Primitive | Algorithm | Usage |
|---|---|---|
| Key Exchange | X25519 (ECDH) | Derive 32-byte shared secret |
| Authentication | Ed25519 | Sign/verify public keys during handshake |
| AEAD Cipher | ChaCha20-Poly1305 | Encrypt/authenticate all payloads (16-byte tag) |
| Key Derivation | HKDF-SHA256 | Derive per-epoch TX/RX keys, IVs, and HP keys |
| Key Ratcheting | HKDF + zeroize | Forward secrecy via epoch-based secret rotation |
| Header Protection | ChaCha20 | QUIC-style header obfuscation |
| Cookie MAC | HMAC-SHA256 | Stateless address validation (30s expiry) |
| Nonce Construction | IV ⊕ PacketNumber | 12-byte nonce = IV XOR right-aligned 64-bit PN |

## 📊 Protocol Parameters

| Parameter | Default Value | Notes |
|---|---|---|
| Initial MTU | 1200 bytes | Minimum safe UDP payload size |
| Max MTU Probe | 1500 bytes | Stepped probing: 1200→1350→1400→1450→1500 |
| Initial CWND | `10 × MTU` (12,000 B) | Slow start begins here |
| ssthresh | 64 KB | Slow Start → Congestion Avoidance threshold |
| Initial RTT | 333ms | Conservative estimate before measurements |
| RTO | `RTT + 4×RTTVAR` (min 50ms) | Karn's Algorithm applied |
| Flow Window | 1 MB | Per-connection flow control window |
| Stream Window | 1 MB | Per-stream ring buffer size (lazy allocated) |
| Max Streams | 100 | Per-connection concurrent stream limit |
| Replay Window | 128-bit bitmask | O(1) sliding window duplicate detection |
| Key Rotation | Every 16M packets | Epoch-based with HKDF ratcheting |
| Idle Timeout | 60s | Actor exits after 60s of inactivity |
| Retry Cookie TTL | 30s | HMAC-SHA256 cookie validity window |
| Handshake Timeout | 5s | Client-side connection timeout |
| Max Retransmits | 10 | Per-packet retry limit before drop |
| Delayed ACK | 25ms / 10 packets | Whichever threshold is reached first |
| MTU Probe Interval | 15s | Periodic PMTUD probing |
| Handshake Semaphore | 256 | Max concurrent handshake processing |
| Connection ID | 8 bytes | Randomly generated per connection |

## 🧪 Testing

```bash
# Run integration tests
cargo test

# Run with tracing output
RUST_LOG=debug cargo test -- --nocapture

# Run the example
cargo run --example basic
```

## 📚 Further Reading

- **[DOCUMENTATION.md](DOCUMENTATION.md)** — Full protocol specification (wire format, state machine, cryptographic operations, congestion control algorithms).
- **[docs.rs](https://docs.rs/zetta-transport)** — API documentation.

## 📋 Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime, timers, channels |
| `chacha20poly1305` | AEAD encryption |
| `x25519-dalek` | X25519 ECDH key exchange |
| `ed25519-dalek` | Ed25519 digital signatures |
| `hkdf` / `sha2` | HKDF-SHA256 key derivation |
| `hmac` | HMAC-SHA256 for Retry cookies |
| `chacha20` | Header protection cipher |
| `zeroize` | Secure secret erasure |
| `dashmap` | Lock-free concurrent routing table |
| `bytes` | Zero-copy buffer management |
| `thiserror` | Ergonomic error types |
| `tracing` | Structured logging |
| `rand` | Cryptographic randomness |
| `libc` | `sendmsg(2)` vectored I/O on Unix |

## 📄 License

Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

---
*Developed as a learning journey in Systems Programming and Network Engineering by **Burak Demir**.*
