# RFC-001: ZettaTransport Protocol Specification (ZT-v0.1.4)

**Author:** Burak Demir <demirburak8338@gmail.com>  
**Status:** Review / Testing  
**Date:** April 2026

## 1. Introduction
ZettaTransport (ZT) is a transport layer protocol built over UDP. It defines packet structures, state machine transitions, and cryptographic operations to allow independent, interoperable implementations.

## 2. Packet Types
ZT defines the following packet types (represented as a 4-bit integer):

- `0x00` **Initial**: Starts the cryptographic handshake negotiation.
- `0x01` **Handshake**: Completes the handshake and establishes Tx/Rx keys.
- `0x02` **Data**: Carries encrypted application data payload.
- `0x05` **Close**: Cryptographically terminates the connection.
- `0x06` **MtuProbe**: Probes the network for Path MTU boundaries. The payload consists of zero-padding representing the tested MTU size. The receiver MUST respond with an `Ack` frame acknowledging this exact Packet Number to prove the path can handle the tested size.
- `0x07` **Retry**: Server-side stateless retry. The payload carries an opaque cookie that the client must echo back in a subsequent `Initial` using a `Cookie` frame.

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
- **Payload Length:** ZT relies on the underlying UDP datagram framing. The length of the Payload is implicitly defined as the remaining bytes in the UDP datagram after parsing the ZT header.

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

**Payload Structure for Initial/Handshake:** The payload is a sequence of *Frames* (see Section 3.4) and is **AEAD-encrypted** using the *Initial* keys. A 16-byte Poly1305 authentication tag is appended.

### 3.3. Short Header (Data / Close / MtuProbe)
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
*(Note 2: Short Headers omit the 32-bit Version field to save overhead; the protocol version is implicitly bound to the Destination CID established during the Handshake.)*
*(Note 3: For `Data` (0x02), `Close` (0x05), and `MtuProbe` (0x06) packets, the payload may be empty (0 bytes) or just padding, but it must still undergo AEAD encryption (using the header as AAD). This generates a mandatory 16-byte Poly1305 Authentication Tag.)*

### 3.4. Payload Framing (Frames)
The payload of `Initial`, `Handshake`, and `Data` packets is a sequence of frames. Frame types are 1 byte:

- `0x00` **Padding**: One or more consecutive `0x00` bytes.
- `0x01` **Stream**: `u32 stream_id` + `u64 offset` + `u16 len` + `len` bytes.
- `0x02` **Ack**: `u64 largest_acked` + `u32 window_size`.
  - Semantics: acknowledges *all* packets with Packet Number $\le$ `largest_acked`.
- `0x03` **ConnectionClose**: no payload.
- `0x04` **Handshake**: `public_key[32]` + `ed_public_key[32]` + `signature[64]`.
- `0x05` **Cookie**: `u16 len` + `len` bytes opaque cookie.

## 4. State Machine and Lifecycle
Connections transition through the following states: `Handshaking -> Active -> Closed`.

### 4.1. Handshake (Initiation)
1. **Client** generates local SCID. Sends `Initial` packet (Long Header) containing a `Handshake` frame.
2. **Server** receives `Initial`.
  - If no valid retry cookie is present, the server sends a `Retry` packet whose payload is an opaque cookie, then returns without allocating per-connection state.
  - If a valid cookie is present, the server proceeds.
3. **Client** receives `Retry` and resends `Initial`, embedding the received cookie in a `Cookie` frame.
4. **Server** sends `Handshake` (Long Header) containing a `Handshake` frame.
5. **Client** receives `Handshake`, derives session keys, and transitions to `Active`.

**State Enforcement:** Any Short Header packet (`Data`, `MtuProbe`, `Close`) received while a connection is in the `Handshaking` state MUST be silently dropped. Once in the `Active` state, all incoming Short Header packets MUST pass AEAD decryption (Authentication Tag verification) or be dropped. Any `Initial` packet received when a connection is already `Active` is treated as a new connection attempt and processed independently.

### 4.2. Timers and Keep-Alives
- **Retransmission Timeout (RTO)**: Starts dynamically at 400ms (based on a 100ms base RTT x 4), adjusted via exponential backoff upon loss. Round-Trip Time (RTT) measurements MUST ignore retransmitted packets to avoid Retransmission Ambiguity (Karn's Algorithm).
- **Idle Timeout**: If no packets (including ACKs or Data) are received for 60s, unacked buffers are pruned (Tier 1). Total session state is destroyed after 3600s (Tier 2).
- **Keep-Alive Mechanism**: To prevent the Idle Timeout from triggering during long silent periods, endpoints SHOULD periodically send an empty `Data` (0x02) packet (0-byte payload). This forces the peer to generate an `Ack` response, reliably refreshing the activity timer on both ends.

### 4.3. Finalization
A graceful teardown occurs when either party sends a `Close (0x05)` packet. The connection transitions to `Closed`, and memory buffers for that CID are reclaimed instantly without relying on the Idle Timeout.

## 5. Definitions and Calculations

### 5.1. Cryptography and Key Exchange
- **Key Exchange**: Uses **X25519** (Elliptic Curve Diffie-Hellman) to establish a 32-byte `Shared_Secret`.
- ZT mandates **ChaCha20-Poly1305** for its AEAD cipher due to its high performance without hardware acceleration.
- **Initial Keys**: Derived from `SHA256("ZettaInitialSalt" || DCID)` and expanded into AEAD keys, header-protection keys, and IVs.
- **Session Master Secret**: Derived as `SHA256( shared_secret || sort(my_scid, peer_dcid) [|| Optional_PSK] )`.
- **Key Expansion**: For each epoch, keys/IVs are derived using SHA-256 with role-specific labels:
  - `tx_key  = SHA256(master_secret || ("client_key"|"server_key") || epoch_be)`
  - `rx_key  = SHA256(master_secret || ("server_key"|"client_key") || epoch_be)`
  - `tx_hp   = SHA256(master_secret || ("client_hp"|"server_hp") || epoch_be)`
  - `rx_hp   = SHA256(master_secret || ("server_hp"|"client_hp") || epoch_be)`
  - `tx_iv   = SHA256(master_secret || ("client_iv"|"server_iv") || epoch_be)[0..12]`
  - `rx_iv   = SHA256(master_secret || ("server_iv"|"client_iv") || epoch_be)[0..12]`
- **Nonce Generation (12 bytes)**: `nonce[0..4] = iv[0..4]`, and `nonce[4..12] = iv[4..12] XOR packet_number_be`.
- **AAD (Associated Data)**: The complete correctly framed packet header (everything before the payload) is bound as AAD for ciphertext integrity validation. 
- **Authentication Tag (16 bytes)**: A 16-byte Poly1305 Authentication Tag is appended to the end of every encrypted payload (including `Initial`, `Handshake`, `Data`, `Close`, and `MtuProbe`).

**Header Protection:** ZT applies QUIC-style header protection using ChaCha20 over a 16-byte sample from the ciphertext payload. The first byte is masked (low bits depend on Long vs Short header), and the first 4 bytes at the packet-number offset are masked.

### 5.2. Forward Error Correction (FEC)
This section is **non-normative**. FEC is a future direction and is not implemented in the current codebase.

**Stripe Mapping Rule:** An `Fec` packet with Packet Number $N$ always protects the immediately preceding contiguous block of `Data` packets. For example, in a 4-data-shard configuration, `Fec` packet $N$ protects packets $(N-4, N-3, N-2, N-1)$.

- **XOR Engine (Default)**: Smaller shards are logically right-padded with `0x00` up to `max_len`. Parity is computed byte-by-byte: `parity[i] = shard1[i] ^ shard2[i] ^ ...`
- **Reed-Solomon Engine**: Employs Galois $2^8$ finite fields. To reconstruct lost packets, padded ciphertext fragments are run backwards through the interpolation matrix (commonly grouped as 4 data + 1 parity shards). The result is decrypted via Poly1305.

*(Implementation Note: In ZT-v0.1.1, there is no dynamic runtime flag in the `Fec` packet header to distinguish between XOR and Reed-Solomon payloads. The protocol statically defaults to the XOR Engine payload structure. Future versions will handle algorithm negotiation via the Handshake parameters.)*

### 5.3. Reliability, Flow, and Congestion Control
Congestion relies on TCP-like AIMD calculated in exact bytes (not abstracted packets). The initial `MTU` is set to `1200` bytes.
- **Initialization**: 
  - `ssthresh` (Slow Start Threshold) = `64 KB` (`64 * 1024` bytes).
  - `cwnd` (Congestion Window) = `10 * MTU` (`12000` bytes).
  - `local_window/remote_window` = `1 MB` (`1024 * 1024` bytes).
- **On Successful Ack**:
  - ACK information is carried in the `Ack` frame and is cumulative by `largest_acked`.
  - If `cwnd < ssthresh` (Slow Start): `cwnd = cwnd + bytes_acked`
  - If `cwnd >= ssthresh` (Congestion Avoidance): `cwnd = cwnd + ((MTU * bytes_acked) / max(cwnd, MTU))`
- **On Packet Loss (Timeout)**:
  - Loss Detection: In ZT-v0.1.1, packet loss is detected STRICTLY via the expiration of the RTO timer for unacked `Data` packets. ZT does not currently use TCP-style Fast Retransmit (e.g. 3-duplicate-ACKs).
  - `ssthresh = max(cwnd / 2, MTU * 2)`
  - `cwnd = ssthresh` (Immediate multiplication decrease)

### 5.4. Replay Protection (O(1) Sliding Window)
ZT uses `highest_processed_pn` and a 64-bit bitmask to track duplicates within a small window.
- **Immediate Rejection:** Any incoming packet with `Packet Number <= highest_processed_pn - 64` is considered too old and dropped.
- **Bitmask Check:** Packets with `Packet Number <= highest_processed_pn` are checked against the bitmask and dropped if already seen.
- **Window Slide:** When processing a new highest packet number, the bitmask shifts and records the new PN.