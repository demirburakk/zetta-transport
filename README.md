# ZettaTransport (ZT)

> **⚠️ Experimental / Hobby Project**
> ZettaTransport is a personal learning and research project. It is **not** production-ready, has not undergone security auditing, and is not recommended for use in real-world applications. If you're looking for a battle-tested UDP transport, consider [QUIC](https://datatracker.ietf.org/doc/html/rfc9000) implementations such as [Quinn](https://github.com/quinn-rs/quinn) or [s2n-quic](https://github.com/aws/s2n-quic).

---

A handcrafted, multiplexed UDP transport protocol written in Rust — built to explore the internals of modern network protocol design.

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue.svg)](#license)

---

## What is ZettaTransport?

ZettaTransport is a custom transport protocol that runs over UDP and provides:

- **Reliable, ordered delivery** — like TCP, but over UDP
- **Stream multiplexing** — multiple independent streams over a single connection, without Head-of-Line blocking
- **Built-in encryption** — X25519 key exchange + ChaCha20-Poly1305 AEAD for every packet
- **Congestion control** — AIMD with slow start and fast retransmit
- **Path MTU Discovery** — dynamic MTU probing to maximize throughput
- **Key rotation** — epoch-based ratcheting for long-lived connections

This project was built to understand how protocols like QUIC work from the inside out — by implementing one from scratch.

---

## Motivation

Reading an RFC is one thing. Writing the code that makes it work is another.

ZettaTransport exists to answer questions like:

- How does a handshake with DoS protection actually work?
- What does header protection look like at the byte level?
- How do you multiplex streams without introducing Head-of-Line blocking?
- What does AIMD feel like to implement?

This is the kind of project where the goal is understanding, not shipping.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                   Application Layer                      │
│              ZtStream  ·  ZtConnectionHandle             │
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

Each connection is managed by a dedicated **actor task** — a single-threaded async event loop that owns all mutable state for that connection. The `ZtEndpoint` dispatches incoming packets to the correct actor via a routing table keyed on Connection IDs (CIDs).

---

## Cryptographic Design

The handshake and encryption design is heavily inspired by QUIC (RFC 9001):

| Phase | Mechanism |
|---|---|
| Key Exchange | X25519 Ephemeral Diffie-Hellman |
| Authentication | Ed25519 signatures on transcript hash |
| Master Secret | HKDF-SHA256 over shared secret + CIDs + optional PSK |
| Data Encryption | ChaCha20-Poly1305 AEAD (in-place) |
| Header Protection | AES-128-ECB on a ciphertext sample |
| Key Rotation | HKDF ratchet per epoch |
| DoS Mitigation | HMAC-SHA256 Retry cookie (30s expiry) |
| Replay Protection | 2048-bit sliding window bitmask |

Initial packets are authenticated but not confidential (by design, same approach as QUIC). Confidentiality begins after the handshake completes.

Cryptographic key material is zeroized on drop via the `zeroize` crate.

---

## Protocol Features

### Connection Lifecycle

```
Client                          Server
  │                               │
  │─── Initial (padded ≥1200B) ──▶│  ← Anti-amplification
  │◀── Retry (HMAC cookie) ───────│
  │─── Initial + Cookie ─────────▶│  ← Ed25519 auth + X25519 DH
  │◀── Handshake (server DH) ─────│
  │         [Active]              │
  │◀══ Encrypted Data Streams ═══▶│
  │─── Close ────────────────────▶│
```

### Multiplexed Streams

- Client opens even-numbered streams (0, 2, 4, …); server opens odd-numbered (1, 3, 5, …)
- Stream 0 is always pre-allocated during handshake
- Maximum 100 concurrent streams per connection
- Per-stream flow control with a 1 MB receive window
- Reorder buffer handles out-of-order delivery before delivering to application

### Congestion Control

- **Slow Start → Congestion Avoidance** (AIMD)
- **Fast Retransmit** — SACK-based gap detection (threshold: 3 packets ahead)
- **RTO** — RFC 6298 algorithm (srtt + 4×rttvar, minimum 50ms)
- **CUBIC-inspired loss response** — multiplicative decrease factor of 0.7 (vs Reno's 0.5)

### Path MTU Discovery

MTU probes are sent every 15 seconds at increasing sizes (1200 → 1350 → 1400 → 1450 → 1500 bytes). A successful probe upgrades the connection MTU.

---

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
zetta-transport = { path = "." }
tokio = { version = "1", features = ["full"] }
```

### Echo Server

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = ZtEndpoint::bind("127.0.0.1:8080", None).await?;
    println!("Server listening on {}", server.local_addr()?);

    while let Some(mut conn) = server.accept().await {
        tokio::spawn(async move {
            while let Some(mut stream) = conn.accept_stream().await {
                tokio::spawn(async move {
                    while let Some(data) = stream.recv().await {
                        let _ = stream.send(&data).await; // echo
                    }
                });
            }
        });
    }
    Ok(())
}
```

### Client

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let mut conn = client.connect("127.0.0.1:8080".parse()?).await?;

    // Stream 0 is ready immediately after connect
    let mut stream = conn.accept_stream().await.unwrap();
    stream.send(b"Hello, ZettaTransport!").await?;

    if let Some(reply) = stream.recv().await {
        println!("Got: {}", String::from_utf8_lossy(&reply));
    }
    Ok(())
}
```

### Pre-Shared Key (PSK) Mode

Both sides must use the same 32-byte PSK:

```rust
let psk: [u8; 32] = [0x42u8; 32]; // use a real key
let server = ZtEndpoint::bind("0.0.0.0:9000", Some(psk)).await?;
let client = ZtEndpoint::bind("0.0.0.0:0", Some(psk)).await?;
```

### Peer Key Pinning

You can enforce which remote public keys are accepted:

```rust
use std::sync::Arc;
use zetta_transport::transport::endpoint::ZtEndpoint;

let trusted_key: [u8; 32] = /* known Ed25519 public key */;
let mut endpoint = ZtEndpoint::bind("0.0.0.0:9000", None).await?;

// Arc::get_mut only works before cloning the endpoint
Arc::get_mut(&mut endpoint).unwrap().verify_peer_key = Some(Arc::new(move |key| {
    key == &trusted_key
}));
```

See the [`examples/`](examples/) directory for a runnable demo.

---

## Running Tests

```bash
cargo test
```

The integration test `echo_roundtrip_large_payload` sends a 200 KB payload end-to-end through the full handshake + encryption + congestion control path and verifies byte-for-byte integrity.

For verbose protocol tracing:

```bash
RUST_LOG=debug cargo test -- --nocapture
```

---

## Project Structure

```
src/
├── lib.rs                  # Crate root and public API docs
├── error.rs                # ZtError enum + Result alias
│
├── crypto/
│   ├── keypair.rs          # X25519 key generation + DH
│   ├── key_derivation.rs   # HKDF, epoch keys, secret ratchet
│   ├── header_protection.rs # AES-128 header protection
│   └── context.rs          # CryptoContext — per-connection crypto state
│
├── protocol/
│   ├── frame.rs            # Frame encoding/decoding (Stream, Ack, Handshake, …)
│   ├── packet.rs           # PacketHeader (long/short form)
│   ├── packet_number.rs    # PN truncation, expansion
│   └── routing.rs          # Fast DCID extraction for packet dispatch
│
├── stream/
│   └── mod.rs              # ZtStream + ZtConnectionHandle (public API)
│
└── transport/
    ├── endpoint.rs         # ZtEndpoint — bind, connect, accept
    ├── connection.rs       # ZtConnection — per-connection state
    ├── handshake.rs        # Server-side handshake processing
    ├── congestion.rs       # ACK handling, RTT, CWND, loss
    ├── cookie.rs           # HMAC Retry cookie
    ├── stream_state.rs     # StreamState, UnackedPacket, ConnectionState
    ├── window.rs           # UnackedWindow + ReplayWindow
    └── actor/
        ├── mod.rs          # ZtConnectionActor + ActorMessage
        ├── event_loop.rs   # Main select! loop (timers, RTO, MTU probes)
        ├── incoming_handler.rs # Packet decryption + frame dispatch
        ├── handshake_handler.rs # Client-side handshake + retry
        └── packet_sender.rs    # Outgoing packet construction + retransmit
```

---

## Known Limitations

Since this is a learning project, there are intentional simplifications:

- **No 0-RTT / early data** — all connections require a full 1-RTT handshake
- **No connection migration** — IP/port changes will break an active connection
- **No priority streams** — all streams are treated equally
- **No flow control at the connection level** — only per-stream flow control exists
- **Single-threaded actor model** — one goroutine per connection; fine for experimentation, not optimal for high fan-out servers
- **Limited fuzzing / formal verification** — the protocol format has not been fuzz-tested
- **No interoperability** — ZT is a custom protocol, not compatible with QUIC or any other standard

---

## Dependencies

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `bytes` | Zero-copy byte buffer |
| `chacha20poly1305` | AEAD encryption |
| `x25519-dalek` | X25519 Diffie-Hellman |
| `ed25519-dalek` | Ed25519 signature auth |
| `hkdf` + `sha2` | Key derivation |
| `aes` | AES-128 header protection |
| `hmac` | Retry cookie MAC |
| `zeroize` | Secure memory wipe |
| `dashmap` | Concurrent routing table |
| `subtle` | Constant-time comparison |
| `rand` | CSPRNG |
| `thiserror` | Error type derivation |
| `tracing` | Structured logging |

---

## What I Learned Building This

- Why QUIC uses version-pinned initial salts and why they're public knowledge
- How header protection prevents traffic analysis without adding per-packet overhead
- The subtlety of packet number expansion — truncating PNs and recovering full numbers
- Why the anti-amplification limit (3× received bytes) matters during handshake
- How actor-per-connection models eliminate lock contention in stateful protocols
- The difference between CUBIC's 0.7 multiplier and Reno's 0.5 in practice

---

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

---

*Built as a hobby project to understand how QUIC-like protocols work from first principles.*
