# ZettaTransport Protocol Specification (ZT-v0.1.9)

**Author:** Burak Demir <demirburak8338@gmail.com>  
**Status:** Experimental / Active Development  
**Date:** April 2026

---

## 1. Introduction

ZettaTransport (ZT) is a transport layer protocol built over UDP. It defines packet structures, frame types, state machine transitions, cryptographic operations, and congestion control algorithms. This document serves as the normative specification for implementing a compatible ZT endpoint.

ZT draws heavy inspiration from QUIC (RFC 9000/9001) while making deliberate simplifications for educational clarity.

---

## 2. Packet Types

ZT defines the following packet types (4-bit integer, lower nibble of the first byte):

| Code | Name | Header | Description |
|------|------|--------|-------------|
| `0x00` | **Initial** | Long | Starts the cryptographic handshake. Must be ≥1200 bytes (anti-amplification). |
| `0x01` | **Handshake** | Long | Server's handshake response. Completes key exchange and transitions to Active. |
| `0x02` | **Data** | Short | Carries encrypted application data as a sequence of frames. |
| `0x05` | **Close** | Short | Initiates graceful connection teardown. |
| `0x06` | **MtuProbe** | Short | Probes the network path for MTU boundaries. Payload is zero-padding. The receiver MUST respond with an `Ack` frame for this Packet Number. |
| `0x07` | **Retry** | Long | Stateless retry. Payload carries an opaque HMAC cookie that the client must echo back in a subsequent `Initial` using a `Cookie` frame. |

---

## 3. Packet Architecture & Header Formatting

Packets use either **Long Headers** (unestablished connections) or **Short Headers** (established connections). All multi-byte integers are in **network byte order** (big-endian).

### 3.1. Header Field Definitions

| Field | Width | Description |
|-------|-------|-------------|
| **Form** | 1 bit | `1` = Long Header, `0` = Short Header |
| **Key Phase** | 1 bit | (Short Header only, bit 6) Signals the current key epoch parity for key rotation |
| **Reserved** | 2-3 bits | Reserved for future use. Must be `0` |
| **Type** | 4-6 bits | Packet type (see Section 2) |
| **Version** | 32 bits | Protocol version. `1` for ZT-v1.0 (Long Header only) |
| **DCID Len** | 8 bits | Length of Destination Connection ID in bytes |
| **Destination CID** | Variable | The receiver's Connection ID (typically 8 bytes) |
| **SCID Len** | 8 bits | Length of Source Connection ID (Long Header only) |
| **Source CID** | Variable | The sender's Connection ID (Long Header only) |
| **Packet Number** | 64 bits | Monotonically increasing, prevents replay |

### 3.2. Long Header (Initial / Handshake / Retry)

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

**First byte encoding:** `0x80 | packet_type`

### 3.3. Short Header (Data / Close / MtuProbe)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|K| Rsvd| Type| DCID Length   |    Destination CID (var) ...  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                    Packet Number (64 bits)                    +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**First byte encoding:** `(packet_type & 0x3F) | (key_phase ? 0x40 : 0x00)`

- Short Headers **omit** the Version and SCID fields.
- The **Key Phase (K)** bit (bit 6) indicates which key epoch is in use, enabling in-band key rotation detection.
- All payloads undergo AEAD encryption with the header as AAD, producing a mandatory 16-byte Poly1305 Authentication Tag appended to the payload.

### 3.4. Payload Framing (Frames)

The payload of `Initial`, `Handshake`, and `Data` packets is a sequence of frames. Frame type is identified by a 1-byte tag:

| Code | Frame | Wire Format | Description |
|------|-------|------------|-------------|
| `0x00` | **Padding** | `N` consecutive `0x00` bytes | Padding for anti-amplification |
| `0x01` | **Stream** | `u32 stream_id` + `u64 offset` + `u16 len` + `len` bytes | Application data for a specific stream |
| `0x02` | **Ack** | `u64 largest_acked` + `u32 window_size` + `u8 range_count` + `range_count × (u64 start, u64 end)` | Cumulative + selective acknowledgment with flow control |
| `0x03` | **ConnectionClose** | (no payload) | Signals connection termination |
| `0x04` | **Handshake** | `[u8; 32] x25519_pk` + `[u8; 32] ed25519_pk` + `[u8; 64] signature` | Carries key exchange material and authentication |
| `0x05` | **Cookie** | `u16 len` + `len` bytes | Echoes a Retry cookie from the server |
| `0x06` | **StreamClose** | `u32 stream_id` | Signals graceful closure of a single stream |

**Ack frame semantics:**
- `largest_acked`: Cumulative acknowledgment — all packets ≤ this PN are acknowledged.
- `window_size`: Receiver's current flow control window (bytes available).
- `ack_ranges`: SACK ranges for selective acknowledgment of non-contiguous packets within the replay bitmask window.

---

## 4. State Machine and Connection Lifecycle

### 4.1. Connection States

```
 ┌──────────────┐     Handshake Complete    ┌────────┐
 │ Handshaking  │ ─────────────────────────▶│ Active │
 └──────────────┘                           └───┬────┘
                                                │
                                    Close sent  │  Close received
                                    or received │  
                                                ▼
                                          ┌─────────┐
                                          │ Closing  │
                                          └────┬────┘
                                               │ Timeout / confirmed
                                               ▼
                                          ┌────────┐
                                          │ Closed │
                                          └────────┘
```

States: `Handshaking → Active → Closing → Closed`

### 4.2. Handshake (Stateless Retry)

1. **Client** generates a random 8-byte SCID. Sends `Initial` packet (Long Header, ≥1200 bytes) containing a `Handshake` frame with `(x25519_public_key, ed25519_public_key, ed25519_signature)`.

2. **Server** receives `Initial`.
   - If **no valid Retry cookie** is present: server sends a `Retry` packet with an HMAC-SHA256 cookie (containing timestamp + address binding). **No per-connection state is allocated.**
   - If **a valid cookie** is present: server proceeds to step 4.

3. **Client** receives `Retry`, extracts the opaque cookie, and resends `Initial` with a `Cookie` frame echoing it.

4. **Server** validates the cookie (HMAC verification, ≤30s expiry, address/SCID binding), verifies the Ed25519 signature on the X25519 public key, performs ECDH, derives session keys, generates a random server SCID, and sends a `Handshake` response (Long Header).

5. **Client** receives `Handshake`, verifies Ed25519 signature, performs ECDH, derives identical session keys, and transitions to `Active`.

**State Enforcement:**
- Short Header packets received during `Handshaking` state MUST be silently dropped.
- All `Active` state Short Header packets MUST pass AEAD decryption or be dropped.
- A server receiving an `Initial` for an already-Active CID treats it as a new connection.

**Amplification Limit:** During handshaking, the server MUST NOT send more than `3 × bytes_received` bytes total, preventing reflection amplification attacks.

**Handshake Concurrency:** A semaphore limits concurrent handshake processing to 256, preventing resource exhaustion from spoofed Initial floods.

### 4.3. Timers

| Timer | Interval | Behavior |
|-------|----------|----------|
| **RTO** | `RTT + 4×RTTVAR` (min 50ms) | Retransmit unacked packets. Karn's Algorithm: RTT measurements ignore retransmitted packets. |
| **Delayed ACK** | 25ms or 10 pending ACKs | Whichever threshold is reached first triggers an ACK flush. |
| **Idle Timeout** | 60s | If no packets are received, the actor task exits and the connection is destroyed. |
| **PMTUD Probe** | 15s | Periodic MTU probe at the next step size. |

### 4.4. Stream Lifecycle

- **Stream 0** is automatically created during the handshake for both endpoints.
- Additional streams can be opened via `ZtConnectionHandle::open_stream()`.
- Remote-initiated streams are auto-created when a `Stream` frame with an unknown `stream_id` is received.
- Streams are closed via `StreamClose` frame (`0x06`), which notifies the peer to release resources for that stream.
- Maximum **100 concurrent streams** per connection (configurable via `MAX_CONCURRENT_STREAMS`).

### 4.5. Connection Finalization

A graceful teardown occurs when either party sends a `Close` (`0x05`) packet containing a `ConnectionClose` frame. The connection transitions to `Closing`, and after a brief drain period (5s idle timer), memory is reclaimed and the actor exits.

---

## 5. Cryptography

### 5.1. Key Exchange and Authentication

- **X25519** (Curve25519 ECDH) produces a 32-byte `shared_secret`.
- **Ed25519** signatures authenticate each peer's X25519 public key, preventing MITM attacks.
- Optional **Pre-Shared Key (PSK)** can be mixed into the master secret for additional authentication.

### 5.2. Key Derivation (HKDF-SHA256)

**Master Secret derivation:**

```
ikm = shared_secret || sort(my_scid, peer_dcid) [|| PSK]
salt = "ZettaTransport v1"
master_secret = HKDF-Expand(HKDF-Extract(salt, ikm), "master_secret", 32)
```

**Per-epoch key expansion** (using HKDF-Expand with the master secret as PRK):

```
tx_key  = HKDF-Expand(secret, "client_key" | "server_key", 32)
rx_key  = HKDF-Expand(secret, "server_key" | "client_key", 32)
tx_hp   = HKDF-Expand(secret, "client_hp"  | "server_hp",  32)
rx_hp   = HKDF-Expand(secret, "server_hp"  | "client_hp",  32)
tx_iv   = HKDF-Expand(secret, "client_iv"  | "server_iv",  12)
rx_iv   = HKDF-Expand(secret, "server_iv"  | "client_iv",  12)
```

Labels are chosen based on the endpoint role (client uses `client_*` for TX, `server_*` for RX).

**Initial Keys** (for encrypting Initial/Handshake packets before session keys exist):

```
salt = "ZettaInitialSalt v1"
initial_secret = HKDF-Expand(HKDF-Extract(salt, DCID), "initial_secret", 32)
```

### 5.3. AEAD Encryption (ChaCha20-Poly1305)

- **Nonce (12 bytes):** `nonce = tx_iv XOR (0x0000_0000 || packet_number_be)` — the 64-bit packet number is XOR'd into the rightmost 8 bytes of the IV.
- **AAD (Associated Data):** The complete packet header (everything before the payload).
- **Authentication Tag:** 16-byte Poly1305 tag appended after the encrypted payload.
- **In-place operation:** Encryption and decryption mutate the payload buffer directly.

### 5.4. Key Rotation (Forward Secrecy)

Key rotation occurs every **16,000,000 packets** (epoch = PN / 16M):

1. Previous RX keys are retained (one epoch back) for decrypting out-of-order packets.
2. A new secret is derived: `next_secret = HKDF-Expand(HKDF-Extract(None, current_secret), "ratchet", 32)`
3. The old secret is **securely erased** using `zeroize`.
4. New TX/RX keys, IVs, and HP keys are derived from the new secret.
5. The **Key Phase** bit in the Short Header signals the epoch parity, enabling the receiver to detect key rotation.

### 5.5. Header Protection

ZT applies QUIC-style header protection using ChaCha20:

1. **Sample:** 16 bytes taken from `packet[pn_offset + 4 .. pn_offset + 20]`.
2. **Nonce:** First 12 bytes of the sample.
3. **Mask:** 5 bytes of ChaCha20 keystream generated with the HP key and sample nonce.
4. **Apply:**
   - First byte: `packet[0] ^= mask[0] & (0x0F for Long, 0x1F for Short)`
   - Packet number bytes: `packet[pn_offset + i] ^= mask[i + 1]` for `i in 0..4`

---

## 6. Reliability, Flow, and Congestion Control

### 6.1. Congestion Control (AIMD)

Congestion control operates in **exact bytes** (not abstracted packets).

**Initialization:**
- `cwnd` = `10 × MTU` = 12,000 bytes
- `ssthresh` = 64 KB
- `local_window` / `remote_window` = 1 MB

**On Successful ACK:**
- **Slow Start** (`cwnd < ssthresh`): `cwnd += bytes_acked`
- **Congestion Avoidance** (`cwnd ≥ ssthresh`): `cwnd += (MTU × bytes_acked) / max(cwnd, MTU)`

**On Packet Loss (RTO expiration):**
- `ssthresh = max(cwnd / 2, MTU × 2)`
- `cwnd = ssthresh + 3 × MTU`

### 6.2. RTT Estimation

Uses the standard TCP RTT estimator (RFC 6298):
- Initial: `RTT = 333ms`, `RTTVAR = 166ms`
- On sample (first-transmission packets only, Karn's Algorithm):
  - First sample: `RTT = sample`, `RTTVAR = sample / 2`
  - Subsequent: `RTTVAR = (3×RTTVAR + |RTT - sample|) / 4`, `RTT = (7×RTT + sample) / 8`
- `RTO = RTT + 4×RTTVAR` (minimum 50ms)

### 6.3. Loss Detection and Retransmission

- Loss is detected via **RTO timer expiration** for unacked Data packets.
- Each packet is retransmitted up to **10 times** before being dropped.
- If all unacked packets exceed the retry limit, the connection is terminated.
- ZT does **not** implement Fast Retransmit (3-duplicate-ACKs) in v0.1.9.

### 6.4. Flow Control

- Each ACK frame carries the sender's `window_size` (available receive buffer).
- `ZtStream::send()` blocks (via `Notify`) when `remote_window` or `cwnd` is exhausted.
- The local window is dynamically recalculated as `1MB - total_buffered_bytes`.

### 6.5. Selective Acknowledgment (SACK)

ACK frames carry both a cumulative `largest_acked` and optional SACK ranges derived from the replay bitmask. The sender processes SACK ranges first, then cumulative ACKs, allowing efficient recovery of non-contiguous losses.

---

## 7. Replay Protection (O(1) Sliding Window)

ZT uses a **128-bit bitmask** sliding window for O(1) replay detection:

- **`highest_processed_pn`**: Tracks the highest packet number successfully processed.
- **Immediate Rejection:** Any packet with `PN ≤ highest_processed_pn - 128` is dropped.
- **Bitmask Check:** Packets with `PN ≤ highest_processed_pn` are checked against the 128-bit bitmask and dropped if already seen.
- **Window Slide:** When a new highest PN is processed, the bitmask shifts left by the difference and the new PN is recorded.

---

## 8. Path MTU Discovery (PMTUD)

ZT periodically probes the network path to discover the maximum transmission unit:

- **Probe sizes:** `[1200, 1350, 1400, 1450, 1500]` bytes
- **Probe interval:** Every 15 seconds
- **Mechanism:** Send an `MtuProbe` (`0x06`) packet padded to the target size. If acknowledged, upgrade the MTU.
- **Maximum:** 1500 bytes (Ethernet standard)
- **Probe packets** are tracked in `mtu_probes` map and marked `is_mtu_probe = true` in the unacked packet store.

---

## 9. Multiplexed Stream Management

### 9.1. Stream State

Each stream maintains:
- **Ring buffer** (1MB, lazily allocated) for reordering out-of-order data.
- **`expected_rx_offset`** / **`next_tx_offset`**: Track ordered delivery and transmission progress.
- **`received_ranges`** (`BTreeMap<u64, u64>`): Track received byte ranges for gap detection and merge.
- **Application channel** (`mpsc::Sender<Bytes>`): Delivers reassembled, in-order data to the user.

### 9.2. Data Reassembly

1. Incoming `Stream` frames are written to the ring buffer at `offset % window_size`.
2. Received ranges are merged (adjacent/overlapping ranges coalesced).
3. Contiguous data starting from `expected_rx_offset` is extracted and delivered to the application channel.
4. `ZtStream::send()` automatically chunks data to fit within `MTU - 64` bytes.

### 9.3. Backpressure

When the congestion window or remote flow window is full, `ZtStream::send()` returns `WouldBlock`. The stream awaits a `Notify` signal from the ACK handler, which fires when window space becomes available.

---

## 10. Anti-Amplification & DoS Mitigation

| Mechanism | Description |
|-----------|-------------|
| **1200-byte minimum** | Initial packets below 1200 bytes are silently dropped. |
| **3× amplification limit** | Server tracks `bytes_sent` vs `bytes_received` and drops packets if `bytes_sent > 3 × bytes_received`. |
| **Stateless Retry** | Server allocates zero state for unvalidated clients. The HMAC-SHA256 cookie binds to `(IP, port, client_SCID, timestamp)` with 30-second expiry. |
| **Handshake semaphore** | Maximum 256 concurrent handshake tasks prevent resource exhaustion. |

---
