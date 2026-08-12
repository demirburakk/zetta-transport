//! Transport endpoint and policy types.
//!
//! Start with [`ZtEndpoint`](crate::transport::endpoint::ZtEndpoint).
//! [`CongestionControlAlgorithm`](crate::transport::CongestionControlAlgorithm) selects the
//! sender's congestion controller, while [`StreamType`](crate::transport::StreamType) describes
//! which directions are usable locally.

pub(crate) mod actor;
pub(crate) mod congestion;
pub(crate) mod connection;
pub(crate) mod cookie;
/// UDP endpoint creation, connection establishment, and peer authentication.
pub mod endpoint;
pub(crate) mod handshake;
pub(crate) mod state;

pub use congestion::CongestionControlAlgorithm;
pub use state::StreamType;
