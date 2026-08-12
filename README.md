# ZettaTransport

[![crates.io](https://img.shields.io/crates/v/zetta-transport.svg)](https://crates.io/crates/zetta-transport)
[![docs.rs](https://docs.rs/zetta-transport/badge.svg)](https://docs.rs/zetta-transport)
[![license](https://img.shields.io/crates/l/zetta-transport.svg)](#license)

ZettaTransport is an experimental encrypted and multiplexed transport protocol over UDP, written
in Rust. One connection carries independent reliable byte streams and unreliable messages while
sharing congestion control, pacing, flow control, path validation, and path-MTU discovery.

> [!WARNING]
> ZettaTransport is a research and learning project. It is a custom protocol—not QUIC—has not
> received an independent security audit, and is not production-ready. Use a standards-based QUIC
> implementation when interoperability or production assurance matters.

## What the crate provides

- Bidirectional and unidirectional reliable ordered streams
- Tokio `AsyncRead` and `AsyncWrite` integration
- Unordered, unretransmitted application datagrams
- ChaCha20-Poly1305 packet protection and ChaCha20 header protection
- Ephemeral X25519 key agreement and Ed25519 handshake signatures
- Optional 32-byte pre-shared key and application-defined public-key verification
- Signed transport-parameter negotiation and ALPN equality checking
- CUBIC or Reno congestion control with packet pacing
- Stream and connection flow control with receive-window auto-tuning
- Retry cookies, replay filtering, key updates, path validation, and PMTUD
- Typed peer-close and stream-reset errors plus connection telemetry

## Install

```toml
[dependencies]
zetta-transport = "0.1.26"
tokio = { version = "1", features = ["full"] }
bytes = "1"
```

The public API documentation is on [docs.rs](https://docs.rs/zetta-transport). Protocol version 2
is described in [DOCUMENTATION.md](DOCUMENTATION.md).

## Echo server

```rust,no_run
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = ZtEndpoint::bind("0.0.0.0:4433", None).await?;
    println!("listening on {}", endpoint.local_addr()?);

    while let Some(mut connection) = endpoint.accept().await {
        tokio::spawn(async move {
            while let Some(mut stream) = connection.accept_stream().await {
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 16 * 1024];
                    loop {
                        let read = match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => read,
                        };
                        if stream.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }
    Ok(())
}
```

## Client

```rust,no_run
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = ZtEndpoint::bind("0.0.0.0:0", None).await?;
    let connection = endpoint.connect("127.0.0.1:4433".parse()?).await?;
    let mut stream = connection.open_stream().await?;

    stream.write_all(b"hello").await?;
    stream.flush().await?;

    let mut reply = [0_u8; 5];
    stream.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"hello");
    Ok(())
}
```

`ZtStream` also offers `send`, `send_bytes`, and `recv_result`. The custom receive method is useful
when message chunks are more convenient than Tokio's byte-oriented traits; `recv_result` preserves
the peer's reset or close cause.

## Stream direction

`open_stream()` creates a bidirectional stream. To create a send-only stream:

```rust,no_run
# use zetta_transport::error::Result;
# use zetta_transport::stream::ZtConnectionHandle;
use zetta_transport::transport::StreamType;

# async fn example(connection: &ZtConnectionHandle) -> Result<()> {
let stream = connection
    .open_stream_with_type(StreamType::UnidirectionalOut)
    .await?;
stream.send(b"one-way payload").await?;
stream.close().await?;
# Ok(())
# }
```

The peer accepts the same stream as `UnidirectionalIn`. A local application cannot directly open
an incoming-only stream. Attempts to write to an incoming-only stream fail.

## Unreliable datagrams

Datagrams are encrypted, congestion-controlled, and paced, but they are not ordered or
retransmitted. Use them only when losing a complete message is acceptable.

```rust,no_run
# use zetta_transport::error::Result;
# use zetta_transport::stream::ZtConnectionHandle;
use bytes::Bytes;

# async fn example(mut connection: ZtConnectionHandle) -> Result<()> {
connection
    .send_datagram(Bytes::from_static(b"current position"))
    .await?;

if let Some(message) = connection.recv_datagram_result().await? {
    println!("{} bytes", message.len());
}
# Ok(())
# }
```

Payloads larger than the peer's negotiated datagram limit are rejected; ZettaTransport does not
fragment application datagrams.

## Configuration

Create `ZtConfig` with struct-update syntax. Endpoint binding validates all wire-format, timeout,
MTU, and resource-limit relationships before opening the socket.

```rust,no_run
use std::time::Duration;
use zetta_transport::config::ZtConfig;
use zetta_transport::transport::{CongestionControlAlgorithm, endpoint::ZtEndpoint};

# async fn example() -> zetta_transport::error::Result<()> {
let config = ZtConfig {
    alpn: b"my-application/1".to_vec(),
    idle_timeout: Duration::from_secs(30),
    max_concurrent_streams: 256,
    initial_stream_window: 2 * 1024 * 1024,
    initial_max_data: 8 * 1024 * 1024,
    cc_algorithm: CongestionControlAlgorithm::Cubic,
    ..ZtConfig::default()
};

let endpoint = ZtEndpoint::bind_with_zt_config("0.0.0.0:0", config).await?;
# drop(endpoint);
# Ok(())
# }
```

Important defaults are a 5-second connect timeout, 60-second idle timeout, 100 concurrent streams,
a 1 MiB initial stream window, a 1 MiB connection window, a 1200-byte initial MTU, and CUBIC.
See [`ZtConfig`](https://docs.rs/zetta-transport/latest/zetta_transport/config/struct.ZtConfig.html)
for every field and validation rule.

## Peer authentication

Each bound endpoint creates an Ed25519 identity. Signatures protect handshake integrity, but the
default policy accepts every valid identity: it does not associate a key with a hostname or user.
Install a verifier when the application already knows the expected 32-byte public key:

```rust,no_run
use std::sync::Arc;
use zetta_transport::transport::endpoint::{PeerKeyVerifier, ZtEndpoint};

# async fn example(expected_key: [u8; 32]) -> zetta_transport::error::Result<()> {
let endpoint = ZtEndpoint::bind("0.0.0.0:0", None).await?;
let verifier: PeerKeyVerifier = Arc::new(move |presented| presented == &expected_key);
endpoint.set_peer_key_verifier(Some(verifier));
# Ok(())
# }
```

The generated identity is currently ephemeral. Applications are responsible for distributing and
pinning keys. A matching PSK can be supplied to both peers through `ZtConfig::psk` (or the compact
`bind` constructor), but it is not a replacement for a complete identity lifecycle.

## Shutdown and error handling

- `ZtStream::close()` sends the final stream offset and permits the peer to consume reordered tail
  data before EOF.
- `ZtStream::reset(code)` aborts a stream and exposes `ZtError::StreamReset` to the peer.
- `ZtConnectionHandle::close()` performs a reasonless close.
- `close_with_error(code, reason)` exposes `ZtError::ConnectionClosedByPeer` to the peer.
- `recv_result`, `accept_stream_result`, and `recv_datagram_result` preserve termination causes.
  Their `Option` convenience counterparts intentionally collapse termination into `None`.

## Telemetry

```rust,no_run
# use zetta_transport::error::Result;
# use zetta_transport::stream::ZtConnectionHandle;
# async fn example(connection: &ZtConnectionHandle) -> Result<()> {
let stats = connection.stats().await?;
println!(
    "rtt={:?} cwnd={} in_flight={} mtu={} lost={}",
    stats.rtt, stats.cwnd, stats.bytes_in_flight, stats.mtu, stats.packets_lost
);
# Ok(())
# }
```

Snapshots also expose byte counters, RTT variance, active streams, key epoch, retransmissions,
PMTUD outcomes, and black-hole recovery events.

## Compatibility

Crate version 0.1.26 uses ZettaTransport wire protocol version 2. It is intentionally incompatible
with protocol version 1 because version 2 authenticates transport parameters, carries stream
direction on every stream frame, and includes the final byte offset in graceful stream closure.
No compatibility with QUIC, TCP, DTLS, or any other transport is implied. The wire format may
change again before a stable release.

## Development

```bash
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
cargo audit
```

The `testing` feature exposes deterministic endpoint-scoped loss, reordering, burst-loss, and MTU
black-hole injection. It is intended only for protocol tests. The repository also contains a
libFuzzer frame-decoder target under `fuzz/`.

## License

Licensed under either the [Apache License 2.0](LICENSE-APACHE) or the [MIT License](LICENSE-MIT), at
your option.
