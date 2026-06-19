# ZettaTransport (ZT)

> [!WARNING]
> **Experimental / Hobby & Learning Project**
>
> ZettaTransport is an educational research project built to explore the internals of modern transport protocols. It has **not** been audited for security, is **not** production-ready, and should **not** be deployed in real-world applications. If you need a production-grade UDP-based multiplexed transport, please use standard [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) implementations such as [Quinn](https://github.com/quinn-rs/quinn) or [s2n-quic](https://github.com/aws/s2n-quic).

---

ZettaTransport is a custom, multiplexed, encrypted transport protocol implemented over UDP in Rust. It provides reliable, stream-oriented delivery alongside low-latency unreliable datagram channels, pluggable congestion control, and secure path migration.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](#license)

---

## Key Features

- **Multiplexed Streams**: Open multiple independent streams over a single connection to eliminate head-of-line blocking.
- **Idiomatic Async I/O**: `ZtStream` fully implements Tokio's `AsyncRead` and `AsyncWrite` traits, allowing seamless integration with standard tools like `tokio::io::copy`.
- **Zero-Copy Transmissions**: Leverage `send_bytes` to transmit `bytes::Bytes` payloads without copying overhead.
- **Pluggable Congestion Control**: Supports switching algorithms on a per-endpoint basis, including implementations for **CUBIC** (RFC 8312) and classic **TCP Reno** (AIMD).
- **Unreliable Datagrams**: Exposes non-reliable, congestion-controlled datagram channels (`send_datagram` / `recv_datagram`) that bypass stream sequencing and packet retransmissions.
- **Auto-Tuning Flow Control**: Tracks stream consumption relative to Round-Trip Time (RTT) and dynamically doubles the flow control window (up to 16MB) to sustain high-throughput networks.
- **Secure Path Migration**: Automatically detects IP/port changes, triggering a cryptographically secure 3-way `PathChallenge` / `PathResponse` handshake to prevent reflection and amplification DDoS attacks.
- **Cryptographic Security**: Every packet is encrypted with ChaCha20-Poly1305 AEAD, authenticated via Ed25519 signatures over X25519 Diffie-Hellman handshakes, protected via AES-128 header obfuscation, and protected against replays with a sliding bitmask.

---

## Protocol Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Application Layer                      │
│        ZtStream (Async I/O)  ·  ZtConnectionHandle       │
├──────────────────────────────────────────────────────────┤
│                    Transport Layer                       │
│  ZtEndpoint  →  Packet Router  →  ZtConnectionActor      │
│                                   (per-connection loop)  │
├──────────────────────────────────────────────────────────┤
│                    Protocol Layer                        │
│         PacketHeader  ·  Frame  ·  PacketNumber          │
├──────────────────────────────────────────────────────────┤
│                    Crypto Layer                          │
│  X25519 DH  ·  HKDF/SHA-256  ·  ChaCha20-Poly1305        │
│  AES-128 Header Protection  ·  Ed25519 Auth              │
└──────────────────────────────────────────────────────────┘
                         UDP / OS
```

Each connection is driven by an async actor task (`ZtConnectionActor`) implementing a single-threaded async event loop. The `ZtEndpoint` demultiplexes incoming UDP datagrams to the correct actor using Connection IDs (CIDs).

---

## Quick Start

Add ZettaTransport to your `Cargo.toml`:

```toml
[dependencies]
zetta-transport = { path = "." }
tokio = { version = "1", features = ["full"] }
bytes = "1"
```

### Echo Server (Async Read/Write)

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;
use zetta_transport::transport::CongestionControlAlgorithm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind the server with Reno Congestion Control (or CongestionControlAlgorithm::Cubic)
    let server = ZtEndpoint::bind_with_config(
        "127.0.0.1:8080", 
        None, 
        CongestionControlAlgorithm::Reno
    ).await?;
    println!("Server listening on {}", server.local_addr()?);

    while let Some(mut conn) = server.accept().await {
        tokio::spawn(async move {
            while let Some(mut stream) = conn.accept_stream().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 { break; } // EOF
                        let _ = stream.write_all(&buf[..n]).await;
                        let _ = stream.flush().await;
                    }
                });
            }
        });
    }
    Ok(())
}
```

### Client (Async Read/Write & Datagrams)

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let mut conn = client.connect("127.0.0.1:8080".parse()?).await?;

    // 1. Send an unreliable datagram
    conn.send_datagram(Bytes::from_static(b"unreliable alert")).await?;
    if let Some(datagram) = conn.recv_datagram().await {
        println!("Received datagram: {:?}", datagram);
    }

    // 2. Open an async stream
    let mut stream = conn.open_stream().await?;
    
    // Zero-copy transmission
    stream.send_bytes(Bytes::from_static(b"Hello ZettaTransport")).await?;
    stream.flush().await?;

    let mut reply = vec![0u8; 1024];
    let n = stream.read(&mut reply).await?;
    println!("Got stream reply: {}", String::from_utf8_lossy(&reply[..n]));

    Ok(())
}
```

---

## Running Tests & Simulations

To run unit, integration, and network loss recovery simulation tests:

```bash
cargo test --features testing
```

To run clippy or check that everything builds with zero warnings:

```bash
cargo clippy --all-targets --all-features
```

For verbose protocol tracing during tests:

```bash
RUST_LOG=debug cargo test --features testing -- --nocapture
```

---

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
