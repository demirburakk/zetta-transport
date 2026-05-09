/// Lifecycle states of a connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ConnectionState {
    Handshaking,
    Active,
    Closing,
    Closed,
}
