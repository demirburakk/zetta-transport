# ZettaTransport — Technical Documentation

> [!WARNING]
> This document details the internal design and technical implementation details of ZettaTransport. ZettaTransport is an educational hobby and learning project. It is **not** production-ready and has **not** been audited for security. For a quick start and basic example code, see [README.md](README.md).

---

## Table of Contents

1. [Module Design](#module-design)
2. [Public API & Component Reference](#public-api--component-reference)
   - [ZtEndpoint](#ztendpoint)
   - [ZtConnectionHandle](#ztconnectionhandle)
   - [ZtStream](#ztstream)
   - [CongestionControlAlgorithm](#congestioncontrolalgorithm)
   - [ZtError](#zterror)
3. [Protocol & Packet Format](#protocol--packet-format)
   - [Long Header Packets](#long-header-packets)
   - [Short Header Packets](#short-header-packets)
4. [Frame Reference](#frame-reference)
5. [Cryptographic Design](#cryptographic-design)
   - [Handshake Cryptography](#handshake-cryptography)
   - [In-Place Encryption](#in-place-encryption)
   - [Header Protection](#header-protection)
   - [Replay Protection](#replay-protection)
6. [Connection Lifecycle & Path Validation](#connection-lifecycle--path-validation)
   - [Handshake Sequence](#handshake-sequence)
   - [Path Validation and IP Migration](#path-validation-and-ip-migration)
7. [Stream Multiplexing & Flow Control](#stream-multiplexing--flow-control)
   - [Multiplexing Mechanics](#multiplexing-mechanics)
   - [Auto-Tuning Flow Control](#auto-tuning-flow-control)
8. [Congestion Control & Pacing](#congestion-control--pacing)
   - [Pluggable Congestion Controller](#pluggable-congestion-controller)
   - [Unreliable Datagram Lifecycle](#unreliable-datagram-lifecycle)
9. [Actor Loop Architecture](#actor-loop-architecture)

---

## Module Design

The codebase layout is separated into modular components:

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
│   ├── mod.rs                    # Re-exports ZtStream, ZtConnectionHandle
│   ├── stream.rs                 # AsyncRead/AsyncWrite state machines, send_bytes
│   └── connection_handle.rs      # Public connection handle, Datagram API
└── transport/
    ├── mod.rs
    ├── endpoint.rs               # ZtEndpoint — public entry point
    ├── connection.rs             # ZtConnection — per-connection state struct
    ├── handshake.rs              # Server-side handshake handler
    ├── congestion.rs             # Pluggable CC, CubicController, RenoController
    ├── cookie.rs                 # HMAC Retry cookie generation/verification
    ├── state/
    │   ├── stream_state.rs       # StreamState (tracks flow-control variables)
    │   ├── stream_buffer.rs      # StreamReceiveBuffer (dynamic circular buffer)
    │   ├── unacked.rs            # UnackedPacket, UnackedPayload
    │   └── window.rs             # UnackedWindow, ReplayWindow (bitmask)
    └── actor/
        ├── mod.rs                # ZtConnectionActor, ActorMessage
        ├── event_loop.rs         # Main event loop (RTO, challenge timers)
        ├── incoming_handler.rs   # Decryption, validation & frame dispatch
        ├── handshake_handler.rs  # Client-side handshake + retry
        └── packet_sender.rs      # Outgoing packet construction & pacing
```

---

## Public API & Component Reference

### `ZtEndpoint`

Binds directly to a local UDP port. Manages connection routing, handshakes, and actor generation.

```rust
pub struct ZtEndpoint {
    pub ed_public_key: VerifyingKey,
    pub verify_peer_key: Option<PeerKeyVerifier>,
    // Private fields: socket, routing tables, and configurations.
}
```

#### Constructors & Methods
- `pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>>`
  Binds the endpoint using the default **CUBIC** congestion control algorithm.
- `pub async fn bind_with_config(addr: &str, psk: Option<[u8; 32]>, cc_algo: CongestionControlAlgorithm) -> Result<Arc<Self>>`
  Binds the endpoint specifying the congestion control algorithm used for all connections accepted or initiated by this endpoint.
- `pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<ZtConnectionHandle>`
  Initiates an outgoing handshake to a server. Times out after 5 seconds if unanswered.
- `pub async fn accept(&self) -> Option<ZtConnectionHandle>`
  Yields the next established connection handle accepted by the server. Returns `None` if the endpoint is dropped.
- `pub fn local_addr(&self) -> Result<SocketAddr>`
  Returns the bound socket address.

---

### `ZtConnectionHandle`

Exposes stream and datagram APIs on a successfully established connection.

```rust
pub struct ZtConnectionHandle {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
    incoming_streams: mpsc::Receiver<ZtStream>,
    incoming_datagrams: mpsc::Receiver<Bytes>,
}
```

#### Methods
- `pub async fn open_stream(&self) -> Result<ZtStream>`
  Asynchronously opens a new outgoing stream to the remote peer.
- `pub async fn accept_stream(&mut self) -> Option<ZtStream>`
  Yields the next incoming stream initiated by the remote peer. Returns `None` when closed.
- `pub async fn send_datagram(&self, data: Bytes) -> Result<()>`
  Transmits an unreliable datagram. Datagrams bypass stream reordering buffers and packet retransmission logic but remain subject to congestion control limits and transmission pacing.
- `pub async fn recv_datagram(&mut self) -> Option<Bytes>`
  Retrieves the next unreliable datagram received from the remote peer.
- `pub async fn close(&self) -> Result<()>`
  Gracefully terminates the connection.

---

### `ZtStream`

Represents a reliable, multiplexed data stream. Fully implements `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`.

```rust
pub struct ZtStream {
    stream_id: u32,
    receiver: mpsc::Receiver<Bytes>,
    window_opened: Arc<Notify>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    // Private read and write states.
}
```

#### Async I/O State Machine
`ZtStream` manages asynchronous writing using a state machine:
- `WriteState::Idle`: Ready to receive new writes from the application layer.
- `WriteState::Sending`: Packet chunk dispatched to the connection actor; waiting on confirmation.
- `WriteState::Blocked`: Yields the task when congestion window or peer flow-control window is exhausted. Automatically resumes upon ACK reception.
- `WriteState::Pacing`: Yields when the transmission pacing timer restricts output burst.

#### Methods
- `pub async fn send_bytes(&self, mut data: Bytes) -> Result<()>`
  Zero-copy transmission. Splits a `Bytes` reference into MTU-friendly slices without data allocation or copying.
- `pub async fn close(&self) -> Result<()>`
  Closes the stream. Sends a `StreamClose` frame to the peer.

---

### `CongestionControlAlgorithm`

Defines choices for pluggable congestion control:
- `CongestionControlAlgorithm::Cubic`: CUBIC congestion control (RFC 8312). Scales window growth as a cubic function of time since the last loss event, rendering it independent of RTT.
- `CongestionControlAlgorithm::Reno`: TCP Reno. Standard AIMD (Additive Increase, Multiplicative Decrease) algorithm.

---

### `ZtError`

```rust
pub enum ZtError {
    Io(std::io::Error),
    Crypto(String),
    InvalidPacket(String),
    Timeout,
    Unauthorized,
    PacketNumberOverflow,
    ConnectionIdExhausted,
    ActorFailed,
    FlowControlBlocked,
    CongestionWindowFull,
    PacingBlocked(std::time::Duration),
    TooManyStreams { limit: usize },
}
```

---

## Protocol & Packet Format

Every UDP packet is classified by its first byte (Header Byte).

```
Long Header Flag (MSB = 1)   : 1xxxxxxx
Short Header Flag (MSB = 0)  : 0xxxxxxx
```

### Long Header Packets

Used for connection setup (Initial, Handshake, Retry).

```
+------------------+-----------------------+-------------------+
| First Byte (1 B) | Version (4 B = 0x01)  | DCID Length (1 B) |
+------------------+-----------------------+-------------------+
| DCID (Var-Len)   | SCID Length (1 B)     | SCID (Var-Len)    |
+------------------+-----------------------+-------------------+
| Packet Number (1-4 B, Truncated)         | Encrypted Payload |
+------------------------------------------+-------------------+
| AEAD Auth Tag (16 B, ChaCha20-Poly1305)                      |
+--------------------------------------------------------------+
```

### Short Header Packets

Used for active data transmission (Data, Close, MtuProbe).

```
+------------------+-----------------------+-------------------+
| First Byte (1 B) | DCID Length (1 B)     | DCID (Var-Len)    |
+------------------+-----------------------+-------------------+
| Packet Number (1-4 B, Truncated)         | Encrypted Payload |
+------------------------------------------+-------------------+
| AEAD Auth Tag (16 B, ChaCha20-Poly1305)                      |
+--------------------------------------------------------------+
```

---

## Frame Reference

Inside decrypted packet payloads, data is structured into sequential frames. ZettaTransport supports the following frames:

| ID | Frame Name | Payload Fields | Description |
|---|---|---|---|
| `0x00` | `Padding` | None | Variable length padding for anti-amplification. |
| `0x01` | `Stream` | `id: u32, offset: u64, data: Bytes` | Transmits stream-multiplexed data. |
| `0x02` | `Ack` | `largest_acked: u64, window: u32, ranges: Vec` | Signals packet reception and peer window size. |
| `0x03` | `ConnectionClose`| None | Terminates the connection immediately. |
| `0x04` | `Handshake` | `dh_pub: [u8;32], ed_pub: [u8;32], sig: [u8;64]` | Handshake credentials exchange. |
| `0x05` | `Cookie` | `cookie: Bytes` | Anti-DoS proof verification. |
| `0x06` | `StreamClose` | `id: u32` | Notifies peer that a stream has ended. |
| `0x07` | `MaxStreamData` | `id: u32, max_data: u64` | Expands flow control limit for a specific stream. |
| `0x08` | `MaxData` | `max_data: u64` | Expands flow control limit for the connection. |
| `0x09` | `Datagram` | `data: Bytes` | Transmits an unreliable datagram chunk. |
| `0x0A` | `PathChallenge` | `data: [u8; 8]` | Asks candidate path to echo a secure random token. |
| `0x0B` | `PathResponse` | `data: [u8; 8]` | Echoes token back to validate path bidirectionality. |

---

## Cryptographic Design

### Handshake Cryptography

The handshake establishes mutual authentication and keys using:
1. **Key Exchange**: Ephemeral Diffie-Hellman using Curve25519 (X25519).
2. **Authentication**: Ed25519 signing over the handshake transcript hash.
3. **Secret Derivation**: HKDF-SHA256 generates master secrets combining DH results, connection IDs, and optional PSKs.
4. **Key Rotation**: Long-lived connections ratchet secrets using HKDF-SHA256 upon moving to subsequent key epochs.

### In-Place Encryption

To minimize allocation overhead and optimize CPU caches, ZettaTransport performs **in-place AEAD** encryption and decryption using `ChaCha20-Poly1305` over a single contiguous buffer (`BytesMut`), appending or verifying the 16-byte authentication tag at the end.

### Header Protection

To prevent passive network observers from tracking packet numbers, packet headers are obfuscated:
- A 16-byte sample is extracted from the encrypted payload.
- The sample is encrypted using `AES-128-ECB` (seeded by header protection keys derived during handshake).
- The resulting mask is XOR-ed with the packet number bytes and the low-order bits of the first byte.

### Replay Protection

Each connection maintains a sliding 2048-bit replay window mask. If an incoming packet's decrypted packet number falls behind the window edge or matches a bit already set in the mask, it is rejected immediately as a replay attempt.

---

## Connection Lifecycle & Path Validation

### Handshake Sequence

```
Client                                      Server
  │                                           │
  │─── Initial Packet (padded ≥ 1200 B) ─────▶│  (1) Anti-Amplification Guard
  │◀── Retry Packet (HMAC Cookie) ────────────│  (2) DoS Cookie Verification
  │─── Initial + Cookie ─────────────────────▶│
  │◀── Handshake (Server X25519 Public) ──────│  (3) Keys Established
  │             [ ACTIVE STATE ]              │
  │◀══════ Encrypted Streams / Datagrams ════▶│
```

1. **Anti-Amplification**: Client Initial packets are padded with zeros to at least 1200 bytes. This ensures servers do not respond to spoofed IPs with larger response payloads.
2. **Retry Cookie**: The server verifies the client's IP address by issuing a stateless `Retry` packet containing an HMAC-SHA256 cookie that binds the client IP, port, and timestamp.

### Path Validation and IP Migration

If the connection actor receives a valid, decrypted short header packet from an IP address or port that differs from `self.state.addr`, it flags a potential **Connection Migration**:

```
Connection Actor (Server)                  New Peer Path (Client)
  │                                           │
  │─── PathChallenge (8-byte random token) ──▶│  (Buffered queue for new path)
  │◀── PathResponse (matching token) ─────────│  (Validated)
  │             [ PATH UPDATED ]              │
```

1. **Validation Probing**: The actor generates an 8-byte random token and sends a `PathChallenge` frame immediately to the candidate address.
2. **Buffer Queue**: During validation, normal data frames received from the unvalidated path are buffered or discarded.
3. **PFS and Timeouts**: Challenges are retransmitted up to 3 times if no response arrives within `2 * RTT`. If no `PathResponse` containing the matching token is received after 3 attempts, the candidate path is abandoned.

---

## Stream Multiplexing & Flow Control

### Multiplexing Mechanics

Stream IDs prevent collisions through parities:
- Clients initiate even-numbered stream IDs.
- Servers initiate odd-numbered stream IDs.
- Stream 0 is pre-allocated upon connection establishment.
- A maximum of 100 concurrent streams are supported per connection.

### Auto-Tuning Flow Control

To maximize throughput across high Bandwidth-Delay Product (BDP) pipes:
- Each stream tracks the volume of bytes read by the application.
- If the application reads more than half of the stream window size within `2 * RTT`, it indicates the flow control window is throttling throughput.
- The stream doubles its window size (capped at 16MB) and resizes its circular `StreamReceiveBuffer` in-place, mapping old indices safely around wrap boundaries.
- The actor transmits a `MaxStreamData` frame notifying the peer of the expanded window limit.

---

## Congestion Control & Pacing

### Pluggable Congestion Controller

The `CongestionController` trait abstracts all congestion control interactions:

```rust
pub(crate) trait CongestionController: Send + Sync {
    fn on_packet_sent(&mut self, pn: u64, bytes: usize, sent_at: Instant);
    fn on_packet_acked(&mut self, bytes_acked: usize, rtt: Duration, now: Instant);
    fn on_congestion_event(&mut self, rtt: Duration, now: Instant);
    fn cwnd(&self) -> usize;
    fn ssthresh(&self) -> usize;
    fn set_cwnd(&mut self, cwnd: usize);
    fn set_ssthresh(&mut self, ssthresh: usize);
    fn set_mtu(&mut self, mtu: usize);
}
```

The active congestion controller performs pacing on outgoing data frames. If the controller signals a `PacingBlocked` status, the actor yields and queues a sleep timer before resuming transmissions.

### Unreliable Datagram Lifecycle

Datagram payloads are integrated into the congestion control system:
- Outgoing datagram size is accounted for in `cwnd` utilization.
- They are subject to pacing limits to prevent burst flooding.
- Unlike streams, datagrams do **not** trigger retransmissions. When a datagram packet is flagged as lost via SACK or RTO timeout, it is removed from the `unacked_packets` table immediately without incrementing retry thresholds.

---

## Actor Loop Architecture

Each ZettaTransport connection is isolated inside an async actor loop (`ZtConnectionActor` running in a spawned `tokio` task) executing a `select!` loop:

```
                  ┌───────────────────────────┐
                  │   Actor Select Loop       │
                  └─────────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ Socket Rx    │        │ Stream Tx    │        │ Timer Fire   │
 │ (UDP Read)   │        │ (App Writes) │        │ (RTO/Pacing) │
 └──────────────┘        └──────────────┘        └──────────────┘
```

By confining connection state modifications to a single-threaded async event loop, ZettaTransport avoids locks (`Mutex` / `RwLock`) in the hot path, ensuring predictable, high-performance packet processing.
