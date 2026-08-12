//! Application-facing connection and reliable stream handles.
//!
//! [`ZtConnectionHandle`](crate::stream::ZtConnectionHandle) multiplexes streams and datagrams
//! over one connection. [`ZtStream`](crate::stream::ZtStream) provides ordered reliable delivery
//! and integrates with Tokio's I/O traits.

mod connection_handle;
#[allow(clippy::module_inception)]
mod stream;
pub(crate) mod termination;

pub use connection_handle::ZtConnectionHandle;
pub use stream::ZtStream;
