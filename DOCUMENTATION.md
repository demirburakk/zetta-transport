# ZettaTransport protocol version 2

This document is the implementation guide for the wire protocol spoken by `zetta-transport`
0.1.26. It complements the generated [Rust API documentation](https://docs.rs/zetta-transport):
docs.rs explains how to use the crate, while this file explains how another implementation can
encode, authenticate, and process packets.

> [!WARNING]
> This is an experimental, non-standard protocol. It is not QUIC, has not received an independent
> security audit, and is not production-ready. The implementation is the ultimate authority if
> this document and the source ever disagree.

All multi-byte fixed-width integers use network byte order (big endian). `varint` below means a
1-, 2-, 4-, or 8-byte unsigned integer whose two most significant bits select the width (`00`,
`01`, `10`, or `11`); the remaining 6, 14, 30, or 62 bits carry the value.

## 1. Design and architecture

ZettaTransport runs over UDP. A `ZtEndpoint` owns one socket, routes packets by destination
connection ID (DCID), and creates one asynchronous actor per connection. The actor is the sole
writer of connection state and handles application commands, packets, pacing, retransmission,
idle timeout, PMTUD, and path validation.

The public layering is:

```text
application
  ├─ ZtConnectionHandle: stream and datagram lifecycle
  └─ ZtStream: reliable bytes, AsyncRead, AsyncWrite
endpoint
  └─ UDP receive loop and DCID routing
connection actor
  ├─ handshake and key epochs
  ├─ frame processing and stream state
  ├─ flow/congestion control and recovery
  └─ path validation and PMTUD
wire
  └─ protected packet header + protected frame sequence + AEAD tag
```

The relevant source directories are `src/protocol` (encoding), `src/crypto` (key schedule and
packet protection), `src/transport` (state machines), and `src/stream` (application handles).

## 2. Version and compatibility

The four-byte long-header version is `0x00000002`. An endpoint silently drops unsupported versions;
there is no version-negotiation packet. Version 2 is incompatible with version 1 because it:

- includes transport parameters in the signed handshake transcript;
- carries stream direction in `STREAM` frames; and
- carries `final_size` in `STREAM_CLOSE` frames.

The protocol has no compatibility relationship with QUIC, DTLS, TCP, or TLS. Before a stable crate
release, any wire field may change in a new protocol version.

## 3. Packet headers

The first byte has this common structure:

```text
bit       7        6        5 4 3 2        1 0
long    long=1   unused     packet type   PN length - 1
short   long=0  key phase   packet type   PN length - 1
```

Packet number length is therefore 1 through 4 bytes. The sender transmits the least-significant
bytes and the receiver expands them relative to its largest processed packet number.

### 3.1 Long header

```text
first:u8
version:u32
dcid_len:u8 | dcid:bytes[dcid_len]
scid_len:u8 | scid:bytes[scid_len]
packet_number:bytes[pn_len]
protected_payload:bytes[..]
tag:bytes[16]
```

Valid long-header packet-type nibbles are:

| Value | Name | Purpose |
|---:|---|---|
| `0x0` | Initial | Client handshake attempt |
| `0x1` | Handshake | Server handshake response |
| `0xC` | Retry | Stateless address-validation cookie |

### 3.2 Short header

```text
first:u8
dcid_len:u8 | dcid:bytes[dcid_len]
packet_number:bytes[pn_len]
protected_payload:bytes[..]
tag:bytes[16]
```

Valid short-header packet-type nibbles are:

| Value | Name | Purpose |
|---:|---|---|
| `0x2` | Data | Streams, datagrams, ACKs, and control frames |
| `0xA` | Close | Connection shutdown |
| `0xB` | MtuProbe | Padded path-MTU probe |

Connection IDs are normally eight random bytes in this implementation. Parsers must honor the
encoded lengths and reject truncation rather than assuming eight.

## 4. Packet protection

The encoded header, through the truncated packet number, is AEAD associated data. The frame bytes
are encrypted in place with ChaCha20-Poly1305 and followed by its 16-byte tag. A nonce is derived
from the direction's 12-byte IV and packet number. Do not process frames until authentication has
succeeded.

After payload encryption, ChaCha20 header protection masks selected low bits of the first byte and
the packet-number bytes using a sample from the ciphertext. A receiver removes header protection
before decoding the packet-number width and reconstructing the full number.

Initial, Handshake, and Retry packets use keys derived from the public version-specific initial salt
and DCID. They provide packet-format protection and anti-spoofing mechanics, not confidentiality
against an observer. Active-connection keys come from ephemeral X25519 agreement, HKDF-SHA-256,
the ordered client/server connection IDs, and the optional PSK.

Directional AEAD keys and IVs are derived separately. The short-header key-phase bit is the parity
of the sending epoch. After the configured packet interval, the sender ratchets its secret with a
domain-separated HKDF step; the receiver retains the immediately previous epoch and pre-derives the
next one to tolerate reordering without unbounded trial derivation.

Each packet number is accepted at most once. The receiver uses a 2048-packet sliding replay bitmap;
duplicates and packets older than the window are discarded.

## 5. Frames

A protected payload is a concatenation of frames. There is no outer frame-count field. A decoder
must either consume one complete frame or return an error; it must never retry without advancing.

| ID | Frame layout after the one-byte ID |
|---:|---|
| `0x00` | `PADDING`: consecutive zero bytes form one padding run |
| `0x01` | `STREAM`: `id:u32, direction:u8, offset:u64, len:varint, data[len]` |
| `0x02` | `ACK`: `largest:u64, receive_window:u32, ack_delay_us:varint, range_count:u8, (start:u64, end:u64)[range_count]` |
| `0x03` | `CONNECTION_CLOSE`: no fields |
| `0x04` | `HANDSHAKE`: `x25519_key[32], ed25519_key[32], hash_len:u16, hash[hash_len], signature[64], alpn_len:u8, alpn[alpn_len]` |
| `0x05` | `COOKIE`: `len:u16, cookie[len]` |
| `0x06` | `STREAM_CLOSE`: `id:u32, final_size:u64` |
| `0x07` | `MAX_STREAM_DATA`: `id:u32, max_data:u64` |
| `0x08` | `MAX_DATA`: `max_data:u64` |
| `0x09` | `DATAGRAM`: `len:varint, data[len]` |
| `0x0A` | `PATH_CHALLENGE`: `token[8]` |
| `0x0B` | `PATH_RESPONSE`: `token[8]` |
| `0x0C` | `CRYPTO`: `offset:u64, len:varint, data[len]` |
| `0x0D` | `PING`: no fields |
| `0x0E` | `RESET_STREAM`: `id:u32, error_code:varint, final_size:varint` |
| `0x0F` | `STOP_SENDING`: `id:u32, error_code:varint` |
| `0x10` | `DATA_BLOCKED`: `max_data:varint` |
| `0x11` | `STREAM_DATA_BLOCKED`: `id:u32, max_data:varint` |
| `0x12` | `MAX_STREAMS`: `max_streams:u64` |
| `0x13` | `STREAMS_BLOCKED`: `max_streams:u64` |
| `0x14` | `CONNECTION_CLOSE_V2`: `error_code:varint, reason_len:varint, UTF-8 reason[reason_len]` |
| `0x15` | `TRANSPORT_PARAMETERS`: fixed 36-byte structure described below |

Unknown IDs are fatal to that packet's frame decoding. ACK range count is limited to 128. A
`CONNECTION_CLOSE_V2` reason is limited to 1024 bytes. Frame lengths and offset additions must be
checked for integer overflow before allocation or buffer access.

Stream direction values are `0` bidirectional, `1` unidirectional from the initiator, and `2`
unidirectional toward the initiator. Applications may open values 0 and 1; value 2 is the local
view created when the peer opens a value-1 stream.

## 6. Transport parameters

The fixed body of frame `0x15` is:

```text
max_streams:u64
initial_stream_window:u64
initial_max_data:u64
max_datagram_size:u32
idle_timeout_ms:u64
```

Both peers send exactly one transport-parameter frame during the handshake. Duplicate or missing
parameters fail the handshake. The peer values limit local sending; the effective idle timeout is
the smaller of the local and peer timeout. Values are signed as part of the handshake transcript,
preventing an unauthenticated intermediary from raising or lowering them.

Required validation includes non-zero stream, flow-control, datagram, and timeout values;
`max_streams <= u32::MAX / 2`; and `initial_max_data <= u32::MAX` because the ACK receive-window
field is 32 bits.

## 7. Handshake

The normal exchange is:

```text
client                                                server
  | Initial: HANDSHAKE + PARAMETERS + padding >=1200    |
  |----------------------------------------------------->|
  | Retry: COOKIE                                       |
  |<-----------------------------------------------------|
  | Initial: HANDSHAKE + PARAMETERS + COOKIE + padding  |
  |----------------------------------------------------->|
  | Handshake: HANDSHAKE + PARAMETERS                   |
  |<-----------------------------------------------------|
  |              protected short-header traffic         |
```

An Initial datagram shorter than 1200 bytes is dropped. The retry cookie is HMAC-SHA-256 over the
source address, source port, client SCID, and issue time, and expires according to
`cookie_max_age_ms`. A server consumes a valid cookie only after transcript and signature checks;
reuse is rejected by a bounded-time replay filter.

Each side's `HANDSHAKE` contains an ephemeral X25519 public key and an Ed25519 identity public key.
The transcript hash is SHA-256 and the signature is Ed25519 over that hash.

The client transcript concatenates, without length prefixes beyond fields that already have a
fixed representation:

```text
version:u32
client_scid
initial_server_dcid
client_x25519_key[32]
retry_cookie (only on the retried Initial)
client_transport_parameters[36]
```

The server transcript extends that exact client transcript with:

```text
server_scid
server_x25519_key[32]
server_transport_parameters[36]
```

The ALPN bytes are carried in the handshake frame and must equal the endpoint's configured ALPN;
this version does not negotiate from a list. ALPN is not currently included in the signed
transcript, so applications must not treat it as a strong channel binding.

By default, any correctly self-signed Ed25519 identity is accepted. A conforming application that
needs authenticated peers must pin or otherwise validate the presented identity. Endpoint
identities generated by this crate last only for the bound endpoint's lifetime. The optional PSK
is mixed into the active master secret and must match on both sides.

## 8. Streams

Client-created stream IDs are even; server-created IDs are odd. This implementation reserves zero,
starts client allocation at 2 and server allocation at 1, and increments by 2. A receiver rejects a
new stream with the wrong initiator parity. `max_streams` is counted independently for streams
opened by each side.

`STREAM.offset` is the absolute byte offset. Data can arrive out of order and is retained until all
preceding bytes exist. Overlaps, duplicate data, integer overflow, final-size violations, per-stream
window violations, and connection-memory-limit violations must be rejected or ignored according to
the established state without delivering duplicate bytes.

`STREAM_CLOSE.final_size` establishes the exclusive final byte offset. EOF becomes visible only
after every byte through that offset has been delivered, so a reordered close cannot discard tail
data. A different final size or data beyond the final size is a protocol error.

`RESET_STREAM` aborts receive delivery with an application code and final size. `STOP_SENDING`
instructs the peer to cease transmission. The Rust API exposes a received reset as
`ZtError::StreamReset` when the application uses an error-preserving receive method.

## 9. Flow control and backpressure

There are two byte limits:

- `MAX_STREAM_DATA` advances an absolute per-stream receive limit.
- `MAX_DATA` advances an absolute connection-wide receive limit.

The sender must not transmit beyond either peer-advertised value. If blocked, it can emit
`STREAM_DATA_BLOCKED` or `DATA_BLOCKED` and wait for an update. `MAX_STREAMS` similarly increases
the number of peer-created streams; `STREAMS_BLOCKED` reports exhaustion.

As the application consumes stream bytes, the receiver returns credit. If more than half the
window is consumed within approximately two RTTs, the implementation doubles the stream window up
to `max_stream_window`. Total buffered stream data is capped by `max_connection_buffer`. Bounded
actor, stream, datagram, and accept queues provide additional backpressure.

## 10. ACK, loss recovery, congestion control, and pacing

ACK frames carry the largest packet number, advertised connection receive window, peer ACK delay in
microseconds, and inclusive SACK ranges. ACK ranges must be ordered, internally valid
(`start <= end`), and bounded. RTT sampling subtracts a credible ACK delay.

A reliable packet is declared lost after a later ACK establishes a three-packet gap or after the
time threshold. The retransmission timeout is at least 50 ms, uses smoothed RTT plus four times RTT
variance, backs off exponentially, and is capped at 10 seconds. Reliable frames are retransmitted;
application datagrams are removed when lost and are never retransmitted.

Every packet consumes congestion-window capacity. The configured controller is either Reno (AIMD)
or CUBIC. Pacing spaces transmissions to avoid bursts even when the congestion window has room.
Flow-control, congestion-window, and pacing backpressure propagate to stream writers rather than
allowing unbounded buffering.

## 11. Datagrams

One `DATAGRAM` frame carries one application message. Messages are encrypted and participate in
congestion control and pacing, but delivery is unordered, unreliable, and at most once within the
packet replay window. The protocol does not fragment a datagram; the sender must keep it within the
peer's `max_datagram_size`. Receiving applications must tolerate loss and reordering.

## 12. Path validation and migration

After authenticated short-header traffic arrives from a different source address, the connection
retains the current path and sends an unpredictable eight-byte `PATH_CHALLENGE` to the candidate.
The candidate echoes it in `PATH_RESPONSE`. Only an exact response from the pending candidate
commits the new address. Challenges are retried using an RTT-derived timeout up to
`max_path_validation_retries`; failure abandons the candidate.

Packets from an unvalidated address do not immediately redirect ordinary transmission. This is
essential to prevent an attacker who can inject a packet from turning the endpoint into a
reflection source.

## 13. Path-MTU discovery

Connections begin at `mtu_min` (at least 1200 bytes). Periodic padded `MtuProbe` packets search up
to `mtu_max`. An acknowledged probe raises the working MTU; a failed probe narrows the search.
Repeated loss of ordinary packets sent above the base MTU triggers black-hole recovery: the
connection returns to the base MTU and restarts discovery below the failed size.

Applications should choose conservative limits for real networks. The configured MTU must leave
room within the maximum UDP payload, and application datagram limits are negotiated separately.

## 14. Connection termination and errors

`CONNECTION_CLOSE` represents a reasonless shutdown. `CONNECTION_CLOSE_V2` transports a 62-bit code
and a UTF-8 diagnostic reason. Idle timeout is a local terminal condition. Once terminal state is
published, pending stream, accept, and datagram operations are awakened.

The Rust convenience receive APIs return `None` for EOF or termination. Implementations that need
the cause should use the `*_result` forms, which preserve `StreamReset`, `ConnectionClosedByPeer`,
and `IdleTimeout`.

## 15. Implementation checklist

A compatible implementation should, at minimum:

1. enforce protocol version 2, header bounds, frame bounds, and checked integer arithmetic;
2. authenticate a packet before parsing frames or changing replay state;
3. reconstruct packet numbers and reject duplicates with a bounded replay window;
4. validate retry cookies, signed transcripts, ALPN equality, and application trust policy;
5. treat Initial encryption as public protection rather than peer authentication;
6. enforce stream direction, initiator parity, final size, byte windows, stream limits, and memory
   limits before buffering data;
7. never retransmit `DATAGRAM` frames;
8. couple all outgoing traffic to congestion control and pacing;
9. validate a changed address before migrating the active path; and
10. test truncation at every field boundary, varint edges, duplicates, reorderings, loss bursts,
    slow consumers, key-phase transitions, MTU black holes, and terminal-state wakeups.

For executable behavior, see the unit tests in `src/`, the adversarial integration scenarios in
`tests/`, and the fuzz target in `fuzz/fuzz_targets/frame_decode.rs`.
