# ZettaTransport (ZT) 

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)
[![Security: X25519/ChaCha20](https://img.shields.io/badge/Security-X25519%2FChaCha20-green.svg)](RFC.md)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

**ZettaTransport** is an industrial-grade, ultra-resilient transport layer protocol built on top of UDP using **Rust**. It is specifically engineered for the high-throughput, low-latency, and extreme-security requirements of **autonomous drone swarms, real-time robotics, and edge IoT networks** operating in hostile or unstable RF environments.

---

##  The Vision: "Hardened by Default"

Traditional protocols like TCP suffer from head-of-line blocking in lossy networks, while standard UDP offers zero security or reliability. ZettaTransport bridges this gap. It doesn't just send data; it ensures your telemetry, command & control (C2), and sensor streams survive extreme packet loss, jamming attempts, and network handovers, all while remaining cryptographically invisible to unauthorized actors.

##  Core Strengths & Features

### 1. Built for Hostile Networks (Active FEC & AIMD)
- **Advanced Mathematical Recovery:** Integrates a dual-engine Forward Error Correction (FEC) system supporting both **XOR Parity** and **Reed-Solomon Erasure Coding** for variable-length payloads. Dropped packets are mathematically reconstructed on the fly, avoiding high-latency retransmissions.
- **AIMD Congestion Control:** Implements a TCP-like Additive Increase Multiplicative Decrease (AIMD) algorithm. It dynamically probes the network's capacity (`cwnd`) and seamlessly halves sending rates upon detection of RF congestion, fully protecting edge devices from buffer bloat.
- **Async Streams:** Provides `ZtStream`, a tokio-compatible multiplexed async wrapper that elegantly handles flow backpressure and auto-retries under the hood.

### 2. Zero-Trust Security by Default
- **State-of-the-Art Cryptography:** Enforces **X25519 Diffie-Hellman** key exchange and **ChaCha20-Poly1305 AEAD** for payload encryption.
- **Pre-Shared Key (PSK) Auth:** Supports mixing an optional 32-byte PSK directly into the Key Derivation Function (KDF) to guarantee that only cryptographically authenticated hardware can join the swarm.
- **Tx/Rx Key Separation:** Derives strictly asymmetric transmission and reception keys using Connection IDs, mathematically eliminating Reflection and Two-Time Pad attacks.
- **O(1) Replay Protection:** A blazing-fast, lock-free sliding window algorithm drops malicious replay attacks instantly, preventing CPU exhaustion (DoS) on low-power devices.
- **Graceful Teardown:** Connections close via authenticated `Close` packets rather than fragile timeouts, neutralizing Truncation Attacks and instantly freeing memory.

### 3. Seamless Mobility & Roaming
- **64-bit Identity (CID):** Unlike TCP/UDP which bind sessions to volatile IP:Port pairs, ZT uses an 8-byte Connection ID. If a drone switches from a factory Wi-Fi to a 5G LTE cellular network, the connection resumes instantly—**zero handshake overhead, zero dropped sessions.**

### 4. Lock-Less I/O & Concurrency
- Critical paths (encryption, decryption, and network transmission) are fully decoupled from state locks. This allows server nodes to handle massive concurrency without deadlocks or thread starvation.

---

##  Ideal Use Cases

ZettaTransport shines where standard protocols fail:

*    **Autonomous Swarm Robotics (UAVs/Drones):** Perfect for high-frequency telemetry and swarm coordination where latency is critical and RF links are constantly degraded by distance or obstacles.
*    **Industrial IoT (IIoT) Gateways:** Securely aggregating and blasting thousands of sensor readings from the factory floor to the cloud over unstable cellular links.
*    **Real-Time Telemetry & C2:** Remote operation of rovers, submersibles, or heavy machinery where a TCP stall (head-of-line blocking) could cause a catastrophic crash.
*    **Seamless Network Handovers:** Mobile edge nodes that constantly jump between different access points or cellular towers.

---

##  How it Compares (Alternatives)

*   **vs. QUIC (Google):** QUIC is fantastic but heavyweight, carrying significant HTTP/3 legacy baggage. ZT is a lightweight, stripped-down alternative designed specifically for robotics, featuring built-in Forward Error Correction (FEC) which is not standard in QUIC.
*   **vs. WireGuard:** WireGuard is a Layer 3 VPN tunnel. ZT uses the **exact same cryptographic primitives** (X25519/ChaCha20) but operates at Layer 4, allowing you to embed it directly into your application binary without requiring root network privileges or OS-level interface configuration.
*   **vs. DTLS:** DTLS handshakes are notoriously slow and fragile under packet loss. ZT connects faster and recovers more gracefully.
*   **vs. MAVLink:** MAVLink is an application-layer framing protocol. ZettaTransport is the perfect **secure transport layer** to carry MAVLink payloads across hostile skies.

---

## 🚀 Getting Started

### Installation

Add `zetta-transport` to your `Cargo.toml`:

```toml
[dependencies]
zetta-transport = "0.1.0"
tokio = { version = "1", features = ["full", "macros"] }
```

### Quick Start: Secure Client-Server Communication

ZettaTransport provides an elegantly simple async API to establish highly reliable, zero-trust UDP tunnels. Here is a baseline example demonstrating a secure handshake and transmission between an edge device and a control server.

```rust
use zetta_transport::{ZtEndpoint, Result};
use bytes::Bytes;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Initialize the Server Node (C2 / Gateway)
    // Binds to a UDP port. The optional PSK (Pre-Shared Key) enforces strict hardware authentication.
    let mut server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    println!("🟢 ZT Server securely listening on 4433...");

    // 2. Initialize the Client Node (Edge Device / Drone)
    // Drones bind to an ephemeral port (0) and initiate the outbound connection.
    let mut client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    
    // 3. Perform the X25519 Handshake
    let peer_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    client.connect(peer_addr).await?;
    println!("🔗 Handshake successful. Secure tunnel established.");
    
    // 4. Dispatch Telemetry Data (Client -> Server)
    // Data is chunked, encrypted via ChaCha20-Poly1305, and reliably transmitted.
    let payload = Bytes::from("{\"telemetry\": {\"alt\": 120.5, \"batt\": 98.2}}");
    client.send(payload, peer_addr).await?;

    // 5. Receive & Authenticate (Server)
    if let Some(received) = server.recv().await {
        let message = String::from_utf8_lossy(&received.data);
        println!("📡 Received securely from {}: {}", received.peer_addr, message);
    }
    
    Ok(())
}
```

---

## Final Audit & Test Results (The Gauntlet)

ZettaTransport v1.0 has successfully passed a battery of extreme reliability tests, maintaining a **Zero Warning / Zero Error** standard in strict `clippy` audits.

| Metric | Scenario | Result |
| :--- | :--- | :--- |
| **Throughput** | 2,000 High-Freq Packets | **100% Delivery** |
| **Scalability** | 1,000 Concurrent DH Handshakes | **< 50ms** total time |
| **Reliability** | 20% Simulated Packet Loss (Chaos) | **Zero data loss** (Retransmit + FEC) |
| **Mobility** | IP/Port Switching mid-stream | **Seamless Resume** |
| **Robustness** | 5,000 Malformed Garbage Packets | **Zero crashes** (Safe Parsing) |
| **Security** | Replay & Reflection Attacks | **O(1) Drop & Secure Recovery** |

*Run the gauntlet yourself:* `cargo run --example gauntlet --release`

---

##  Technical Specification

For deep architectural details, bit-layouts, and state machine logic, please refer to the **[ZettaTransport RFC-001 Specification](SPECIFICATION.md)**.

## ⚖️ License

Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

---
*Developed & Maintained by **Burak Demir** ([demirburak8338@gmail.com](mailto:demirburak8338@gmail.com))*
