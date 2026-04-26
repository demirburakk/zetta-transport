# RFC-001: ZettaTransport Protocol Specification (ZT-v0.1.1)

**Author:** Burak Demir <demirburak8338@gmail.com>  
**Status:** Review / Testing  
**Date:** April 2026

## 1. Introduction
ZettaTransport (ZT) is a secure, reliable, and high-performance transport layer protocol built over UDP. It rigorously defines packet structures, state machine transitions, and cryptographic operations to allow independent, interoperable implementations.

## 2. Packet Types
ZT defines the following packet types (represented as a 4-bit integer):

- `0x00` **Initial**: Starts the cryptographic handshake negotiation.
- `0x01` **Handshake**: Completes the handshake and establishes Tx/Rx keys.
- `0x02` **Data**: Carries encrypted application data payload.
- `0x03` **Ack**: Acknowledges received packets and advertises window size.
- `0x04` **Fec**: Forward Error Correction redundancy packet.
- `0x05` **Close**: Cryptographically terminates the connection.
- `0x06` **MtuProbe**: Probes the network for Path MTU boundaries.

## 3. Packet Architecture & Header Formatting
Packets are either Long Headers (for unestablished connections) or Short Headers (established). Data types are correctly scaled (all width markers denote bits unless otherwise specified). 

### 3.1. Header Field Definitions
- **Form (1 bit)**: `1` for Long Header, `0` for Short Header.
- **Reserved (3 bits)**: Reserved for future use. Must be `0`.
- **Type (4 bits)**: Specifies the packet type (see Section 2).
- **Version (32 bits)**: Network byte order. For ZT-v1.0, this is `1`.
- **DCID Len (8 bits)**: Length of Destination Connection ID in bytes.
- **Destination CID (Variable)**: The receiver's Connection ID (typically 8 bytes).
- **SCID Len (8 bits)**: Length of Source Connection ID in bytes.
- **Source CID (Variable)**: The sender's Connection ID (typically 8 bytes).
- **Packet Number (64 bits)**: Monotonically increasing 64-bit integer, preventing replay.
- **Window Size (32 bits)**: Flow control window size, present ONLY in ACK packets.

### 3.2. Long Header (Initial / Handshake)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1| Rsvd| Type  |             Version (Top 24 bits)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (Bot 8) | DCID Length |    Destination CID (var) ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| SCID Length   |      Source CID (Variable Bytes) ...          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Packet Number (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.3. Short Header (Data / Fec / Close / MtuProbe)
```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0| Rsvd| Type  | DCID Length   |    Destination CID (var) ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Packet Number (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
*(Note: If Type is `0x03` (Ack), a 32-bit `Window Size` field IMMEDIATELY follows the Packet Number, before any payload.)*

## 4. State Machine and Lifecycle
Connections transition through the following states: `Handshaking -> Active -> Closed`.

### 4.1. Handshake (Initiation)
1. **Client** generates local SCID. Sends `Initial` packet (Long Header).
2. **Server** receives `Initial`. Extracts SCID as DCID for response. Combines `Shared_Secret` + CIDs + optional `PSK` to derive Tx/Rx keys. Sends `Handshake` packet.
3. **Client** receives `Handshake`. Derives keys identically. Transitions to `Active`. State locks are released for high-throughput mode.

### 4.2. Timers and Keep-Alives
- **Retransmission Timeout (RTO)**: Starts dynamically at 400ms (based on a 100ms base RTT x 4), adjusted via exponential backoff upon loss.
- **Idle Timeout**: If no packets (including ACKs or Data) are received for 60s, unacked buffers are pruned (Tier 1). Total session state is destroyed after 3600s (Tier 2).

### 4.3. Finalization
A graceful teardown occurs when either party sends a `Close (0x05)` packet. The connection transitions to `Closed`, and memory buffers for that CID are reclaimed instantly without relying on the Idle Timeout.

## 5. Definitions and Calculations

### 5.1. Cryptography and Key Exchange
- **Key Exchange**: Uses **X25519** (Elliptic Curve Diffie-Hellman) to establish a 32-byte `Shared_Secret`.
- ZT mandates **ChaCha20-Poly1305** for its AEAD cipher due to its high performance without hardware acceleration.
- **Key Derivation**: 32-byte session keys are derived via `SHA-256` to ensure distinct Tx and Rx keys, preventing two-time pad attacks.
  - `Tx Key` = `SHA256( Shared_Secret || Local_SCID [|| Optional_PSK] )`
  - `Rx Key` = `SHA256( Shared_Secret || Peer_DCID [|| Optional_PSK] )`
- **Nonce Generation (12 bytes)**: The 96-bit nonce is constructed by taking 4 bytes of zero padding (`0x00 0x00 0x00 0x00`) prepended to the 8-byte **Packet Number (Big-Endian)**.
- **AAD (Associated Data)**: The complete correctly framed packet header (everything before the payload) is bound as AAD for ciphertext integrity validation. 

### 5.2. Forward Error Correction (FEC)
Variable-length shards are supported natively. Shards inside an FEC block are evaluated by determining the `max_len` across the block.
- **XOR Engine**: Smaller shards are logically right-padded with `0x00` up to `max_len`. Parity is computed byte-by-byte: `parity[i] = shard1[i] ^ shard2[i] ^ ...`
- **Reed-Solomon Engine**: Employs Galois $2^8$ finite fields. To reconstruct lost packets, padded ciphertext fragments are run backwards through the interpolation matrix (commonly grouped as 4 data + 1 parity shards). The result is decrypted via Poly1305.

### 5.3. Reliability, Flow, and Congestion Control
Congestion relies on TCP-like AIMD calculated in exact bytes (not abstracted packets). The initial `MTU` is set to `1200` bytes.
- **Initialization**: 
  - `ssthresh` (Slow Start Threshold) = `64 KB` (`64 * 1024` bytes).
  - `cwnd` (Congestion Window) = `10 * MTU` (`12000` bytes).
  - `local_window/remote_window` = `1 MB` (`1024 * 1024` bytes).
- **On Successful Ack**:
  - If `cwnd < ssthresh` (Slow Start): `cwnd = cwnd + MTU`
  - If `cwnd >= ssthresh` (Congestion Avoidance): `cwnd = cwnd + ((MTU * MTU) / max(cwnd, MTU))`
- **On Packet Loss (Timeout)**:
  - `ssthresh = max(cwnd / 2, MTU * 2)`
  - `cwnd = ssthresh` (Immediate multiplication decrease)

### 5.4. Replay Protection (O(1) Sliding Window)
ZT mitigates CPU-exhaustion attacks by keeping `highest_processed_pn` and a fixed `max_replay_window` of `1024`.
- **Immediate Rejection:** Any incoming packet where `Packet Number < highest_processed_pn - 1024` is considered too old and instantly dropped.
- **HashSet Check:** Packets within the valid window bounds are checked against a dynamic `HashSet`. Duplicates are dropped. Upon processing, the window slides forward and prunes numbers behind the new threshold.

