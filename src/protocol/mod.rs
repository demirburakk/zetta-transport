pub(crate) mod frame;
pub(crate) mod packet;
pub(crate) mod packet_number;
pub(crate) mod routing;

/// Wire protocol version. Version 2 adds authenticated transport parameters,
/// directional stream metadata, and final-size stream closure semantics.
pub(crate) const PROTOCOL_VERSION: u32 = 2;
