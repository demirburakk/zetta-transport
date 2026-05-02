# ZettaTransport — Technical Documentation

> This document covers the internal design and implementation details of ZettaTransport.
> For a high-level overview and usage examples, see [README.md](README.md).

---

## Table of Contents

1. [Module Overview](#module-overview)
2. [Public API](#public-api)
   - [ZtEndpoint](#ztendpoint)
   - [ZtConnectionHandle](#ztconnectionhandle)
   - [ZtStream](#ztstream)
   - [ZtError](#zterror)
3. [Packet Format](#packet-format)
   - [Long Header](#long-header-packets)
   - [Short Header](#short-header-packets)
   - [Packet Types](#packet-types)
4. [Frame Format](#frame-format)
5. [Cryptographic Design](#cryptographic-design)
   - [Handshake](#handshake-phase)
   - [Key Derivation](#key-derivation)
   - [Header Protection](#header-protection)
   - [Key Rotation](#key-rotation)
   - [Replay Protection](#replay-protection)
6. [Connection Lifecycle](#connection-lifecycle)
7. [Stream Multiplexing](#stream-multiplexing)
8. [Flow Control](#flow-control)
9. [Congestion Control](#congestion-control)
10. [Path MTU Discovery](#path-mtu-discovery)
11. [Actor Model](#actor-model)
12. [Packet Routing](#packet-routing)
13. [Timers](#timers)

---

## Module Overview

```
src/
├── lib.rs                        # Crate root; re-exports public API
├── error.rs                      # ZtError, Result<T>
├── crypto/
│   ├── mod.rs                    # Re-exports CryptoContext
│   ├── keypair.rs                # X25519 keypair generation + DH
│   ├── key_derivation.rs         # HKDF helpers, epoch key derivation, ratchet
│   ├── header_protection.rs      # AES-128 apply/remove header protection
│   └── context.rs                # CryptoContext (per-connection crypto state)
├── protocol/
│   ├── mod.rs
│   ├── frame.rs                  # Frame enum + encode/decode
│   ├── packet.rs                 # PacketHeader encode/decode, PacketType
│   ├── packet_number.rs          # PN truncation and expansion
│   └── routing.rs                # Fast DCID extraction
├── stream/
│   └── mod.rs                    # ZtStream, ZtConnectionHandle
└── transport/
    ├── mod.rs
    ├── endpoint.rs               # ZtEndpoint — public entry point
    ├── connection.rs             # ZtConnection — per-connection state struct
    ├── handshake.rs              # Server-side handshake handler
    ├── congestion.rs             # ACK/loss/RTT logic (impl on ZtConnection)
    ├── cookie.rs                 # HMAC Retry cookie generation/verification
    ├── stream_state.rs           # StreamState, UnackedPacket, ConnectionState
    ├── window.rs                 # UnackedWindow (ring buffer), ReplayWindow (bitmask)
    └── actor/
        ├── mod.rs                # ZtConnectionActor, ActorMessage
        ├── event_loop.rs         # Main select! loop
        ├── incoming_handler.rs   # Decryption + frame dispatch
        ├── handshake_handler.rs  # Client-side handshake + retry
        └── packet_sender.rs      # Outgoing packet construction, RTO, MTU probe
```

---

## Public API

### `ZtEndpoint`

The main entry point. Binds to a UDP socket and manages all connections.

```rust
pub struct ZtEndpoint {
    pub ed_public_key: VerifyingKey,
    pub verify_peer_key: Option<PeerKeyVerifier>,
    // fields are otherwise private
}
```

#### Methods

```rust
/// Bind to a local UDP address and start the packet router.
/// Pass Some(psk) to require a pre-shared key on top of the X25519 handshake.
pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>>

/// Initiate an outgoing connection. Blocks until the handshake completes
/// (or times out after 5 seconds).
pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<ZtConnectionHandle>

/// Accept the next incoming connection. Returns None if the endpoint is dropped.
pub async fn accept(&self) -> Option<ZtConnectionHandle>

/// Return the local socket address this endpoint is bound to.
pub fn local_addr(&self) -> Result<SocketAddr>
```

#### Internal methods (used by the actor layer)

```rust
pub async fn send(&self, cid: &[u8], stream_id: u32, data: &[u8]) -> Result<()>
pub async fn close(&self, cid: &[u8]) -> Result<()>
pub async fn close_stream(&self, cid: &[u8], stream_id: u32) -> Result<()>
pub async fn open_stream(&self, cid: &[u8]) -> Result<ZtStream>
pub async fn get_mtu(&self, cid: &[u8]) -> usize
```

#### `PeerKeyVerifier`

An optional callback used to pin or allowlist remote peer keys:

```rust
pub type PeerKeyVerifier = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;
```

If set, the callback receives the remote peer's Ed25519 public key during the server-side handshake. Returning `false` causes the handshake to fail with `ZtError::Unauthorized`.

---

### `ZtConnectionHandle`

A handle to an established connection. Returned by both `connect()` and `accept()`.

```rust
pub struct ZtConnectionHandle { /* private */ }
```

#### Methods

```rust
/// Open a new outgoing stream to the peer.
pub async fn open_stream(&self) -> Result<ZtStream>

/// Wait for the peer to open an incoming stream.
/// Returns None when the connection is closed.
pub async fn accept_stream(&mut self) -> Option<ZtStream>

/// Gracefully close the connection.
pub async fn close(&self) -> Result<()>
```

Stream IDs follow a parity convention: clients use even IDs (0, 2, 4, …) and servers use odd IDs (1, 3, 5, …). Stream 0 is always pre-created during the handshake and available on both sides immediately after connection.

---

### `ZtStream`

Represents a single reliable, ordered, encrypted stream within a connection.

```rust
pub struct ZtStream { /* private */ }
```

#### Methods

```rust
/// Send data to the peer. Automatically chunks data to fit the current MTU.
/// Blocks transparently under flow control or congestion pressure.
pub async fn send(&self, data: &[u8]) -> Result<()>

/// Receive the next in-order chunk of data from the peer.
/// Returns None when the stream is closed.
pub async fn recv(&mut self) -> Option<Bytes>

/// Send a StreamClose frame and remove stream state.
pub async fn close(&self) -> Result<()>
```

`send()` chunks data into MTU-sized segments (MTU − 64 bytes overhead, minimum 512 bytes). When the peer's flow control window or the local congestion window is exhausted, `send()` yields and retries automatically after a window-open notification.

---

### `ZtError`

```rust
pub enum ZtError {
    Io(std::io::Error),           // Underlying socket error
    Crypto(String),               // AEAD failure, bad keys, invalid signatures
    InvalidPacket(String),        // Malformed or truncated packet/frame
    Timeout,                      // Connection or retransmit timeout
    Unauthorized,                 // CID mismatch or peer key rejected
    PacketNumberOverflow,         // u64 PN space exhausted
    ConnectionIdExhausted,        // Could not allocate a unique CID
    ActorFailed,                  // Actor task dropped or channel closed
    FlowControlBlocked,           // Peer's receive window is full
    CongestionWindowFull,         // Local CWND is full
    TooManyStreams { limit: usize }, // Peer exceeded MAX_CONCURRENT_STREAMS
}
```

---

## Packet Format

All packets are UDP datagrams. The first byte determines whether the packet has a long header (MSB = 1) or a short header (MSB = 0).

### Long Header Packets

Used for Initial, Handshake, and Retry packets.

```
Byte 0 (first byte):
  bit 7   : 1 (long header flag)
  bit 6   : 0 (reserved, unused)
  bits 5-2: Packet Type (4 bits)
  bits 1-0: PN Length encoding — actual pn_len = (bits1-0) + 1

  first_byte = 0x80 | ((packet_type & 0x0F) << 2) | (pn_len - 1)

Bytes 1–4 : Version (u32, big-endian) — always 1
Byte  5   : DCID Length (u8)
Bytes 6…  : DCID (variable, DCID Length bytes)
Next byte : SCID Length (u8)
Next bytes: SCID (variable, SCID Length bytes)
Next bytes: Packet Number (pn_len bytes, truncated, big-endian)
Remaining : Encrypted payload
Last 16 B : AEAD tag (ChaCha20-Poly1305)
```

- **Version:** Always `1` for ZettaTransport v1
- **DCID / SCID:** Variable length, each prefixed by a 1-byte length field
- **PN Len:** `pn_len = (first_byte & 0x03) + 1` → 1 to 4 bytes

### Short Header Packets

Used for Data, Close, and MtuProbe packets once a connection is established.

```
Byte 0 (first byte):
  bit 7   : 0 (short header flag)
  bit 6   : Key Phase (KP) — toggles on each key rotation epoch
  bits 5-2: Packet Type (4 bits)
  bits 1-0: PN Length encoding — actual pn_len = (bits1-0) + 1

  first_byte = ((packet_type & 0x0F) << 2) | (pn_len - 1)
               | (0x40 if key_phase)

Byte  1   : DCID Length (u8)
Next bytes: DCID (variable, DCID Length bytes)
Next bytes: Packet Number (pn_len bytes, truncated, big-endian)
Remaining : Encrypted payload
Last 16 B : AEAD tag (ChaCha20-Poly1305)
```

- **KP (bit 6):** Key Phase — set via `first_byte |= 0x40`; decoded as `(first_byte & 0x40) != 0`
- **Packet Type:** `(first_byte >> 2) & 0x0F`
- **PN Len:** `(first_byte & 0x03) + 1`, read **after** header protection is removed

### Packet Types

| Value | Name | Header | Description |
|---|---|---|---|
| `0x00` | `Initial` | Long | First handshake packet from client |
| `0x01` | `Handshake` | Long | Server handshake response |
| `0x02` | `Data` | Short | Application data / ACK |
| `0x05` | `Close` | Short | Graceful connection close |
| `0x06` | `MtuProbe` | Short | Path MTU discovery probe |
| `0x07` | `Retry` | Long | Server DoS retry with cookie |

> Note: Frame type values and Packet type values occupy separate namespaces. For example, `Frame::StreamClose` encodes as `0x06` on the wire, which is the same byte value as `PacketType::MtuProbe` — but they appear in different positions in the packet structure.

### Packet Number Encoding

Packet numbers are truncated to 1–4 bytes on the wire. The number of bytes used (`pn_len`) is selected dynamically based on the gap between the next PN and the lowest unacknowledged PN:

```rust
// src/protocol/packet_number.rs
pub fn truncate_pn(pn: u64, largest_acked: u64) -> (u32, usize)
pub fn expand_pn(pn_truncated: u64, pn_len: usize, largest_pn: u64) -> u64
```

`expand_pn` recovers the full 64-bit PN from a truncated value using the RFC 9000 §A.3 algorithm: candidate = `(expected & !mask) | truncated`, then adjust by ±window if outside the half-window around `expected`.

---

## Frame Format

Frames are the payload of decrypted packets. A single packet may contain multiple frames concatenated.

### `0x00` — Padding

One or more zero bytes. Consumed contiguously.

### `0x01` — Stream

```
[0x01][stream_id: u32][offset: u64][length: u16][data: length bytes]
```

- `stream_id`: identifies which stream this chunk belongs to
- `offset`: byte offset of this chunk within the stream
- `length`: number of payload bytes following

### `0x02` — Ack

```
[0x02][largest_acked: u64][window_size: u32][range_count: u8]
      ([start: u64][end: u64]) × range_count
```

- `largest_acked`: highest PN the sender has processed
- `window_size`: sender's current receive window (used for flow control)
- `ack_ranges`: SACK blocks as `(start_pn, end_pn)` inclusive pairs; maximum 128 ranges

### `0x03` — ConnectionClose

```
[0x03]
```

No payload. Signals graceful teardown.

### `0x04` — Handshake

```
[0x04][x25519_public_key: 32][ed25519_public_key: 32]
      [transcript_hash_len: u16][transcript_hash: variable]
      [ed25519_signature: 64]
```

Carries key material and authentication for the handshake exchange.

### `0x05` — Cookie

```
[0x05][length: u16][cookie: length bytes]
```

Client includes this frame in the second Initial packet after receiving a Retry.

### `0x06` — StreamClose

```
[0x06][stream_id: u32]
```

Signals that the sending side has finished writing to the stream.

---

## Cryptographic Design

### Handshake Phase

The handshake is a 1-RTT exchange (2-RTT if a Retry is required):

**Round 1 (optional — DoS protection):**
1. Client sends an Initial packet (padded to ≥ 1200 bytes) with a `Handshake` frame containing its ephemeral X25519 public key and Ed25519 signature over `SHA-256(client_scid ‖ server_dcid ‖ x25519_pubkey)`.
2. Server verifies the minimum packet size (anti-amplification guard). If no valid cookie is present, it responds with a `Retry` packet containing a 40-byte HMAC cookie.

**Round 2 (handshake completion):**
1. Client retransmits the Initial packet with its `Cookie` frame and the HMAC cookie.
2. Server verifies the cookie, then verifies the Ed25519 signature and transcript hash. It performs X25519 DH to derive the shared secret, creates the `CryptoContext`, spawns the actor, and responds with a `Handshake` packet carrying its ephemeral key, Ed25519 key, and signature.
3. Client verifies the server's signature and transcript hash, completes the DH, derives the same shared secret, and marks the connection active.

All Initial packets use **deterministic Initial keys** derived from the DCID (not secret — same purpose as QUIC's initial secrets). Packet confidentiality begins after the handshake completes.

#### Transcript Hash

```
transcript_hash = SHA-256(client_scid ‖ server_dcid ‖ client_x25519_pubkey [‖ cookie])
```

The server's transcript extends this with the server's ephemeral key:

```
transcript_hash = SHA-256(client_scid ‖ server_scid ‖ client_x25519_pubkey ‖ server_x25519_pubkey)
```

Both sides sign their respective transcript hashes with Ed25519.

#### Retry Cookie

```rust
// src/transport/cookie.rs
fn make_retry_cookie(cookie_key: &[u8; 32], addr: &SocketAddr, client_scid: &[u8], now: u64) -> [u8; 40]
```

Cookie layout: `[timestamp: 8 bytes][HMAC-SHA256: 32 bytes]`

The HMAC input is `IP ‖ port ‖ client_scid ‖ timestamp`. Cookies expire after 30 seconds. Verification uses `subtle::ConstantTimeEq` to prevent timing attacks.

---

### Key Derivation

All key derivation uses **HKDF-SHA256** (`hkdf` crate).

#### Initial Keys (non-secret)

```
initial_secret = HKDF-Extract(salt=INITIAL_SALT, ikm=dcid)
```

`INITIAL_SALT = b"ZettaTransport v1 InitialSalt\x00\x00\x00"` (version-pinned, public)

#### Master Secret

```
ikm = shared_secret ‖ client_scid ‖ server_scid [‖ psk]
master_secret = HKDF-Expand(HKDF-Extract(salt="ZettaTransport v1", ikm), "master_secret", 32)
```

CID ordering is role-based (not lexicographic) to ensure both sides derive the same IKM:
- Client appends `my_scid` first, then `peer_dcid`
- Server appends `peer_dcid` first, then `my_scid`

#### Per-Epoch Keys

```
key    = HKDF-Expand(prk, "{role}_key:{epoch}", 32)
hp_key = HKDF-Expand(prk, "{role}_hp:{epoch}", 32)
iv     = HKDF-Expand(prk, "{role}_iv:{epoch}", 12)
```

Where `role` is `client` or `server`. The epoch suffix ensures distinct key material across epochs even if the PRK were reused.

#### Secret Ratchet

```
next_secret = HKDF-Expand(HKDF-Extract(None, current_secret), "ratchet", 32)
```

The old secret is zeroized after ratcheting.

---

### Header Protection

Header protection conceals the packet number and key phase bit from passive observers, preventing traffic analysis.

**Applying (send path):**
1. Sample 16 bytes from the ciphertext starting at `pn_offset + 4`
2. Encrypt the sample with AES-128-ECB using the HP key (first 16 bytes of the 32-byte HP key)
3. Derive a mask from the encrypted block
4. XOR `packet[0]` with `mask[0] & 0x0F` (long header) or `mask[0] & 0x1F` (short header)
5. XOR each PN byte `packet[pn_offset + i]` with `mask[i + 1]`

**Removing (receive path):** Same operation (XOR is its own inverse), but the PN length is read from the first byte **after** removing the mask.

---

### Key Rotation

Key rotation is triggered when a Data packet arrives with a Key Phase (KP) bit that differs from the expected phase:

1. If the packet number is ≥ the highest processed PN, the peer has initiated a rotation: call `CryptoContext::rotate_keys()` which saves the current RX keys as fallback, ratchets the secret, and derives new epoch keys.
2. If the packet number is below the highest processed PN, this is a late packet from the previous epoch: decrypt with the fallback (`prev_rx_*`) keys.

This allows graceful handling of out-of-order packets across a key rotation boundary.

---

### Replay Protection

The `ReplayWindow` tracks the 2048 most recent packet numbers in a bitmask (`[u64; 32]` = 2048 bits). On receipt:

1. If `pn ≤ highest - 2048`: unconditional replay (drop)
2. If `pn ≤ highest`: check the corresponding bitmask bit
3. If `pn > highest`: advance the window

ACK ranges for SACK are also derived from this bitmask via `get_ack_ranges()`.

---

## Connection Lifecycle

```
ConnectionState::Handshaking  →  ConnectionState::Active  →  ConnectionState::Closing  →  ConnectionState::Closed
```

- **Handshaking:** Client sends Initial, awaits Handshake response. Actor does not process Data packets in this state.
- **Active:** Normal data exchange. Actor processes Data, MtuProbe, and Close packets.
- **Closing:** `ConnectionClose` frame sent; actor awaits acknowledgment or idle timeout (5 seconds).
- **Closed:** Actor removes itself from the routing table and exits.

**Idle timeout:** 60 seconds of inactivity causes the actor to exit and clean up.

---

## Stream Multiplexing

Each connection can carry up to `MAX_CONCURRENT_STREAMS = 100` concurrent streams.

Stream IDs follow a parity scheme to avoid collisions:
- **Client-initiated:** Even IDs — 0, 2, 4, …
- **Server-initiated:** Odd IDs — 1, 3, 5, …

Stream 0 is always pre-created during the handshake on both sides and is immediately available after `connect()` / `accept()`.

### Receive Buffer

Per stream, received chunks are stored in a `BTreeMap<u64, Bytes>` keyed by byte offset. The actor delivers chunks to the application in order:

1. On `Frame::Stream` arrival, the chunk is inserted into the map.
2. A delivery loop checks whether `expected_rx_offset` is available in the map (or a chunk that overlaps it).
3. Overlapping chunks are sliced at `expected_rx_offset` before delivery.
4. Fully consumed chunks are removed from the map.

This approach handles retransmissions and reordering without a pre-allocated ring buffer.

### Backpressure

Each stream has a `window_size` of 1 MB. If `buffered_bytes + incoming > window_size`, the incoming chunk is dropped (the peer will retransmit). The `window_size` field in ACK frames communicates the available window back to the sender.

---

## Flow Control

Flow control operates at two levels:

**Per-stream receive window:** `StreamState::window_size` (1 MB). The receiver's current available window is advertised in every ACK frame's `window_size` field. If the sender's `remote_window` is less than the chunk size, `process_outgoing_data` returns `ZtError::FlowControlBlocked`.

**Connection-level window:** `ZtConnection::local_window` is recalculated as `1 MB - sum(buffered_bytes across all streams)` before each ACK flush or MTU probe.

When `FlowControlBlocked` or `CongestionWindowFull` is returned from the actor, `ZtStream::send()` waits on `window_opened.notified()` — a `tokio::sync::Notify` that is triggered whenever an ACK is processed.

---

## Congestion Control

ZettaTransport implements a TCP-like AIMD algorithm with CUBIC-inspired loss response.

### Slow Start

```
if cwnd < ssthresh:
    cwnd += bytes_acked
```

Initial values: `cwnd = 10 × 1200 = 12000`, `ssthresh = 65536`.

### Congestion Avoidance

```
if cwnd >= ssthresh:
    cwnd += (mtu × bytes_acked) / cwnd
```

This is the standard AIMD additive increase formula.

### Loss Detection

Two mechanisms:

1. **Fast Retransmit (SACK-based):** Any unacknowledged packet with `pn + 3 ≤ largest_acked` is considered lost and retransmitted immediately. This is equivalent to the 3-duplicate-ACK threshold in TCP.

2. **RTO (Retransmit Timeout):** Packets unacknowledged for longer than `rtt + 4 × rttvar` (minimum 50ms) are retransmitted. After 10 retries, the packet is abandoned.

### RTT Estimation

Follows RFC 6298:

```
On first sample:
    rtt    = sample
    rttvar = sample / 2

Subsequent samples:
    rttvar = (3 × rttvar + |rtt - sample|) / 4
    rtt    = (7 × rtt + sample) / 8
```

Only unretransmitted packets (`retries == 0`) contribute to RTT samples to avoid Karn's algorithm violations.

### Loss Response (CUBIC-inspired)

```
ssthresh = max(cwnd × 0.7, 2 × mtu)
cwnd     = ssthresh
```

The multiplicative decrease factor is 0.7 (versus TCP Reno's 0.5), matching CUBIC's `β_cubic`.

---

## Path MTU Discovery

The actor sends MTU probe packets every 15 seconds. Probes are short-header Data packets padded to a target size with `Frame::Padding`:

**Probe sizes tried (bytes):** `1200 → 1350 → 1400 → 1450 → 1500`

The actor selects the smallest probe size larger than the current MTU. If a probe is acknowledged (either via cumulative ACK or SACK), the MTU is upgraded:

```rust
if up.is_mtu_probe && up.payload.len() > self.mtu {
    self.mtu = up.payload.len();
}
```

Probes are tracked in `mtu_probes: HashMap<u64, usize>` (PN → target size). MTU probes are not retransmitted on loss — a new probe cycle begins at the next 15-second interval.

The current MTU affects stream chunking: `chunk_size = mtu - 64` (leaving room for headers and AEAD tag).

---

## Actor Model

Each connection is managed by a `ZtConnectionActor` — a Tokio task that owns all mutable state for that connection. This design eliminates lock contention: the actor is the only writer of `ZtConnection`.

### `ActorMessage`

Messages sent to the actor via an unbounded `mpsc::channel(1024)`:

| Message | Sender | Purpose |
|---|---|---|
| `IncomingPacket { data, addr }` | Packet router | Deliver a received datagram |
| `OutgoingData { stream_id, data, respond_to }` | `ZtStream::send()` | Send application data |
| `GetMtu { respond_to }` | `ZtStream::send()` | Query current MTU |
| `CloseStream { stream_id }` | `ZtStream::close()` | Close a specific stream |
| `OpenStream { respond_to }` | `ZtConnectionHandle::open_stream()` | Open a new stream |
| `Close` | `ZtConnectionHandle::close()` | Close the connection |

The actor uses `try_send` for internal operations where dropping is acceptable (e.g., delayed ACK timer overflow) and awaited `send` for application-facing responses.

---

## Packet Routing

The `ZtEndpoint` maintains a `DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>` routing table keyed on the **local SCID** (which is the DCID from the peer's perspective).

**Dispatch logic (in `start_router`):**

1. Call `extract_dcid_fast()` on the raw datagram — this reads the DCID length and bytes without full header parsing.
2. Look up the DCID in the routing table.
3. If found: `try_send(IncomingPacket)` to the actor channel. Drops the packet if the channel is full (backpressure).
4. If not found: spawn `handle_handshake()` to attempt a new handshake.

`extract_dcid_fast` handles both long-header (offset 5, length at byte 5) and short-header (offset 1, length at byte 1) formats.

---

## Timers

Each actor manages four independent timers using `tokio::time::sleep_until` + `tokio::pin!`:

| Timer | Default | Behaviour |
|---|---|---|
| `rto_timer` | `rtt` (333ms initial) | Triggers `handle_retransmits()` for unacknowledged packets |
| `idle_timer` | 60 seconds | Closes the connection if no messages arrive |
| `delayed_ack_timer` | Off (1 year) | Activates 25ms after the first unacknowledged incoming packet |
| `mtu_probe_timer` | 15 seconds | Sends an MTU probe packet |

The delayed ACK timer implements **delayed acknowledgment**: ACKs are batched for up to 25ms or until 10 frames have arrived (whichever comes first), reducing ACK traffic.

After a `CloseStream` or `Close` message, the idle timer is shortened to 5 seconds to allow the close packet to be acknowledged before the actor exits.
