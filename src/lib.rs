//! ZettaTransport is an industrial-grade, high-performance transport protocol built on top of UDP.
//! It is specifically engineered for high-throughput, low-latency, and high-security requirements.

mod connection;
mod crypto;
mod endpoint;
pub mod error;
mod fec;
mod packet;
pub mod stream;

pub use endpoint::{ReceivedData, ZtEndpoint};
pub use error::{Result, ZtError};
pub use stream::ZtStream;
