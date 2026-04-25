# RFC-001: ZettaTransport Protocol Specification (ZT-v1.0)

**Author:** Burak Demir <demirburak8338@gmail.com>  
**Status:** Stable / Final  
**Date:** April 2026

## 1. Introduction
ZettaTransport (ZT) is a secure, reliable, and high-performance transport layer protocol built over UDP. It is designed for low-latency communication in hostile network environments, utilizing state-of-the-art cryptography and redundant error correction.

## 2. Structural Integrity

### 2.1. 64-bit Identity (CID)
Unlike standard UDP which relies on IP:Port pairs, ZT uses an **8-byte (64-bit)** Connection ID (CID). This enables:
- **Collision Resistance:** $2^{64}$ unique IDs prevent session overlap.
- **Connection Migration:** Seamless IP/Port switching without re-handshaking.

### 2.2. Lock-Less I/O Design
To maximize async performance, ZT implements a "Minimal Lock" strategy:
- **State Lock:** Held only during connection lookup and state transitions.
- **Data Path:** Cryptography (ChaCha20) and Network I/O (UDP send_to) occur **outside** of the state lock, preventing head-of-line blocking at the server's state map.

## 3. Packet Architecture

### 3.1. Long Header (Initial/Handshake)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|  Type (4b)  |             Version (32 bits)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8b) |           Destination CID (8 bytes)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Len (8b) |             Source CID (8 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (64 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2. Short Header (Data/Ack/FEC)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|  Type (4b)  | DCID Len (8b) |    Destination CID (8 bytes)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (64 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Window Size (32b - Only for ACKs)        |    Payload    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## 4. Cryptographic Hardening

### 4.1. Key Derivation, Tx/Rx Separation & Pre-Shared Key (PSK)
To prevent Reflection Attacks and Two-Time Pad vulnerabilities, ZT derives **separate** asymmetric keys for Transmission (Tx) and Reception (Rx) using a SHA-256 KDF.
For enhanced authentication, an optional 32-byte Pre-Shared Key (PSK) can be mixed into the derivation process. If provided, unauthorized clients cannot even complete the handshake.
- `Tx Key`: `SHA256(Shared_Secret || My_SCID [|| PSK])`
- `Rx Key`: `SHA256(Shared_Secret || Peer_DCID [|| PSK])`

### 4.2. Nonce Management
The 96-bit ChaCha20 nonce is derived as follows:
- `[0..32]`: Constant padding (4 bytes zero).
- `[32..96]`: Monotonically increasing Packet Number (8 bytes, Big-Endian).
This guarantees nonce uniqueness for $2^{64}$ packets per session.

### 4.3. Associated Data (AAD) & Reconstructed Headers
To prevent header tampering, the **entire raw packet header** is bound as AAD to the AEAD cipher. Any modification to the CID, Packet Number, or Type will result in a decryption failure and packet rejection. During FEC recovery, the AAD is virtually reconstructed to validate the recovered ciphertext.

### 4.4. O(1) Replay Protection
ZT employs a high-performance sliding window mechanism (`highest_processed_pn`) combined with a dynamic HashSet to detect and drop replayed or outdated packets in **O(1) time complexity**, preventing CPU Denial of Service attacks on low-power devices.

## 5. Reliability and Flow

### 5.1. Forward Error Correction (FEC)
ZT uses Erasure Coding with support for **variable-length shards**.
- **Engine:** Supports both zero-padding XOR Parity (for fast, 1-parity recovery) and advanced **Reed-Solomon** (for multi-parity environments).
- **Processing:** FEC shards are stored as **ciphertexts**. Recovery occurs at the ciphertext level by zero-padding smaller shards, followed by decryption using the inferred missing Packet Number and reconstructed AAD.

### 5.2. Congestion Control (AIMD) & Flow Control
- **Flow Control:** Managed via `local_window` updates in every ACK. ZT implements **Backpressure** by blocking the application-level `send` calls when the `remote_window` is exhausted.
- **Congestion Control:** Implements TCP-like **AIMD** (Additive Increase Multiplicative Decrease). The `cwnd` (Congestion Window) grows per successful ACK but is halved immediately upon packet loss (timeout), preventing network buffer bloat.
- **Async Streams:** Provides a multiplexed `ZtStream` wrapper that asynchronously backs off and auto-retries when windows are exhausted.

### 5.3. Path MTU Discovery (PMTUD)
ZT introduces `MtuProbe` (Type 0x06) packets to dynamically probe network links, avoiding costly and insecure IP-level packet fragmentation.

## 6. Resource Management

### 6.1. Graceful Teardown & Cryptographic Close
Endpoints employ a secure `Close` (Type 0x05) packet. Unlike a raw UDP disconnect, this packet is fully authenticated. It prevents "Truncation Attacks" and allows the server to instantly reclaim memory without waiting for hour-long timeouts.

### 6.2. Two-Tier Cleanup
- **Tier 1 (60s):** Prunes heavy memory buffers (unacked packets, FEC shards).
- **Tier 2 (3600s):** Prunes session state (keys, CID) if not explicitly closed.
This tiering enables IoT "Sleep & Resume" without sacrificing server memory for inactive clients.
