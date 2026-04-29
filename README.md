# ZettaTransport (ZT)
**An Experimental, Multiplexed UDP-Based Transport Protocol in Rust**

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Crates.io](https://img.shields.io/crates/v/zetta-transport.svg)](https://crates.io/crates/zetta-transport)
[![Documentation](https://docs.rs/zetta-transport/badge.svg)](https://docs.rs/zetta-transport)

> **Note:** ZettaTransport is primarily a **hobby and learning project**. It is an experimental playground for exploring network protocol design, congestion control, multiplexing, and cryptographic transport. It is **not** intended for mission-critical or production use, but rather as a deep dive into how modern protocols like QUIC function under the hood.

ZettaTransport (ZT) is a research-oriented transport protocol built entirely in Rust. It operates over UDP and aims to provide reliable, in-order delivery of multiplexed streams with built-in cryptography (AEAD ChaCha20-Poly1305 and X25519 Diffie-Hellman).

## Core Features Explored

*   **Multiplexed Streams:** Transfer multiple independent data streams over a single UDP connection. This is implemented to study solutions to the Head-of-Line blocking problem found in TCP.
*   **In-Place Cryptography:** Payload encryption and decryption are performed directly in place to minimize memory allocations and understand zero-copy data paths.
*   **Congestion Control & Loss Recovery:** Experimenting with AIMD (Additive Increase/Multiplicative Decrease) with timeout-based loss recovery.
*   **Cryptographic Key Rotation:** Implementing epoch-based key rotation for ChaCha20 to study how protocols prevent key exhaustion on long-lived connections.
*   **DoS Mitigation Concepts:** Enforcing a 1200-byte padding requirement for initial handshake packets to explore anti-amplification techniques against IP spoofing.
*   **Path MTU Discovery (PMTUD):** Probing the network with inflated packets to dynamically adjust the MTU size based on the current network path.

## Installation

Add ZettaTransport to your `Cargo.toml`:

```toml
[dependencies]
zetta-transport = "0.1.5"
tokio = { version = "1.52", features = ["full"] }
```

## Usage Guide

ZettaTransport exposes an asynchronous API built on top of Tokio.

### Server Side

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind the endpoint to a local port. (None means no Pre-Shared Key is used).
    let server = ZtEndpoint::bind("127.0.0.1:8080", None).await?;
    println!("Server listening on 127.0.0.1:8080");

    // 2. Accept incoming connections in a loop.
    while let Some(mut stream) = server.accept().await {
        println!("New connection established!");
        
        tokio::spawn(async move {
            // 3. Receive data reliably and in-order.
            while let Some(data) = stream.recv().await {
                println!("Received: {:?}", String::from_utf8_lossy(&data));
                
                // 4. Send a response back.
                let _ = stream.send(b"Message received!").await;
            }
        });
    }
    
    Ok(())
}
```

### Client Side

```rust
use zetta_transport::transport::endpoint::ZtEndpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Bind the client to an available local UDP port.
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    
    // 2. Connect to the target server. This performs the X25519 handshake.
    let target: SocketAddr = "127.0.0.1:8080".parse()?;
    let mut stream = client.connect(target).await?;
    println!("Connected to the server!");

    // 3. Send data over the stream.
    stream.send(b"Hello from ZettaTransport Client!").await?;
    
    // 4. Await a response from the server.
    if let Some(reply) = stream.recv().await {
        println!("Server replied: {:?}", String::from_utf8_lossy(&reply));
    }

    Ok(())
}
```

## Project Architecture Overview

*   `transport/endpoint.rs`: The main UDP socket manager. Routes packets and handles the X25519 cryptography during handshakes.
*   `transport/actor.rs`: An asynchronous state machine that runs independently for every connected peer. It manages congestion control, PMTUD, Keep-Alives, and Retransmits.
*   `stream/mod.rs`: The `ZtStream` object returned to the user. It isolates multiplexed data flows and provides the `.send()` and `.recv()` API.
*   `crypto/mod.rs`: Wrapper for `chacha20poly1305` and `x25519-dalek` providing in-place encryption utilities.

## License

Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

---
*Developed as a learning journey in Systems Programming and Network Engineering by **Burak Demir**.*
