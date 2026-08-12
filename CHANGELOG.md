# Changelog

All notable changes to ZettaTransport are documented here. This project does not promise wire
compatibility before a stable release.

## 0.1.26 - 2026-08-12

### Added

- Complete docs.rs crate guidance, copyable client/server examples, authentication guidance, and a
  protocol-version-2 implementation reference.
- Bidirectional and unidirectional stream semantics on the wire.
- Error-preserving stream, connection, and datagram receive APIs.
- Typed stream reset and connection-close propagation.
- Signed transport-parameter negotiation.
- Deterministic network-fault scenarios, adversarial protocol matrices, a benchmark, fuzzing, and
  continuous integration checks.
- Connection loss, retransmission, PMTUD, and MTU black-hole recovery telemetry.

### Changed

- Advanced the wire protocol to version 2; this release is not wire-compatible with version 1.
- Hardened handshake replay defense, endpoint identity use, flow-control accounting, stream final
  size handling, path validation, packet-number processing, loss recovery, and shutdown wakeups.
- Validated configuration and peer transport limits before resource allocation.
- Removed unused dependencies and made release metadata accurately describe the crate's
  experimental status.

### Fixed

- Reliable delivery under loss, reordering, burst loss, slow consumers, and congestion pressure.
- Concurrent stream limits, directional-stream permission checks, close/reset tail delivery, and
  blocked-writer termination.
- PMTUD probe accounting and recovery when a larger path MTU becomes a black hole.
