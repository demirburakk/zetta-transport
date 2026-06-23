use crate::crypto::CryptoEngine;
use super::{ReplayWindow, UnackedWindow};

pub(crate) struct PacketSpace {
    pub(crate) next_packet_number: u64,
    pub(crate) unacked_packets: UnackedWindow,
    pub(crate) replay_window: ReplayWindow,
    pub(crate) crypto: Option<Box<dyn CryptoEngine>>,
}

impl PacketSpace {
    pub(crate) fn new() -> Self {
        Self {
            next_packet_number: 0,
            unacked_packets: UnackedWindow::new(),
            replay_window: ReplayWindow::new(),
            crypto: None,
        }
    }

    pub(crate) fn get_next_packet_number(&mut self) -> crate::error::Result<u64> {
        let n = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(crate::error::ZtError::PacketNumberOverflow)?;
        Ok(n)
    }
}
