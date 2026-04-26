# RFC-001: ZettaTransport Protocol Specification (ZT-v1.0)

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

## 5. Exact Definitions

### 5.1. Cryptography and Key Exchange
- ZT mandates **ChaCha20-Poly1305** for its AEAD cipher due to its performance without hardware acceleration.
- **Key Derivation**: 32-byte derivations run through `SHA-256`. 
  - `Tx Key` = `SHA256(Shared_Secret || SCID [|| PSK])`
  - `Rx Key` = `SHA256(Shared_Secret || DCID [|| PSK])`
- **Nonce generation**: padding `00 00 00 00` prepended to the 8-byte, Big-Endian Packet Number.
- **AAD**: The complete correctly framed packet header (everything before the payload) acts as Associated Data. 

### 5.2. Forward Error Correction (FEC)
Variable-length standard XOR/Reed-Solomon shards are stored directly as ciphertexts. Recovery happens pre-decryption. Upon identifying a gap inside a stripe via missing PN, the engine leverages 0-padding of sub-length fragments to reconstruct the erased ciphertext block, which is then decrypted via Poly1305 using the reconstructed packet header (AAD).

### 5.3. Flow and Congestion Windows
- `local_window`: The number of bytes/packets the local endpoint can ingest. Sent in every `Ack` packet using the `Window Size` field.
- `cwnd`: Congestion window size. Starts at 10 packets. Increased by 1 MSS (Maximum Segment Size) for each acknowledged packet. On timeout event (packet drop), `cwnd` immediately halves (AIMD multiplicative decrease).

