# 🛰️ ZettaTransport (ZT)
**An Experimental, High-Performance UDP Transport Protocol in Rust**

[![License: MIT/Apache-2.0](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

> **⚠️ Note:** ZettaTransport is a **hobby and learning project**. It is an experimental playground for exploring network protocol design, congestion control, and cryptographic transport. It is **not** intended for production use, but rather as a deep dive into how modern protocols like QUIC and WireGuard function under the hood.

## 🚀 The Vision
ZettaTransport (ZT) is a research-oriented transport protocol built on top of UDP. The goal of this project is to implement and experiment with advanced networking concepts in a "clean-slate" environment using Rust. It focuses on low-latency communication, resilience in unstable environments (like drone/IoT telemetry), and modern concurrency patterns.

## 🛠️ Implemented Concepts & Learning Goals
Through this project, the following network engineering challenges are being addressed:

*   **Custom Handshake & Security:** Implementing a X25519 Diffie-Hellman key exchange and AEAD (ChaCha20-Poly1305) encryption from scratch.
*   **Stateless Handshake (DoS Mitigation):** Exploring the use of "Stateless Cookies" to prevent CPU exhaustion during connection establishment.
*   **Forward Error Correction (FEC):** Implementing XOR-based and Reed-Solomon erasure coding to recover lost packets without retransmission overhead.
*   **Congestion Control:** Experimenting with AIMD (Additive Increase/Multiplicative Decrease) and exploring more advanced algorithms like Fast Retransmit.
*   **Path MTU Discovery (PMTUD):** Dynamically probing the network to find the maximum possible packet size without fragmentation.
*   **Lock-Free Concurrency:** Leveraging `DashMap` and the Actor pattern to handle thousands of concurrent connections without global mutex contention.

## 🏗️ Project Architecture
The project is modularized for better maintainability and study:
*   `transport/`: Core endpoint logic and background workers.
*   `protocol/`: Packet definitions and binary encoding/decoding.
*   `crypto/`: Handshake and encrypted transport wrappers.
*   `fec/`: Error correction engines.
*   `stream/`: (In Progress) High-level API for ordered data streams.

## 🧪 Running the Experiments
Since this is a research project, you can explore the examples to see the protocol in action:
```bash
# Run a basic client-server handshake simulation
cargo run --example basic
```

## ⚖️ License
Licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

---
*Developed as a learning journey in Systems Programming and Network Engineering by **Burak Demir**.*
