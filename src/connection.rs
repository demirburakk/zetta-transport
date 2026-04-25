use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Represents the current state of a connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Handshaking,
    Active,
    Closed,
}

/// Manages the state of a single ZettaTransport connection.
pub struct ZtConnection {
    pub addr: SocketAddr,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub state: ConnectionState,
    pub next_packet_number: u64,
    pub last_activity: Instant,
    pub crypto: Option<CryptoContext>,

    // FEC Shards (Encrypted payloads)
    pub sent_shards: Vec<Bytes>,
    pub received_shards: BTreeMap<u64, Bytes>,

    // Reliability & Flow Control
    pub unacked_packets: HashMap<u64, (Bytes, Instant, u32)>,
    pub rtt: Duration,
    pub local_window: u32,
    pub remote_window: u32,

    // Congestion Control (AIMD) & MTU
    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub mtu: usize,

    // Replay Attack Protection
    pub processed_packets: HashSet<u64>,
    pub max_replay_window: u64,
    pub highest_processed_pn: u64,
}

impl ZtConnection {
    pub fn new(addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) -> Self {
        Self {
            addr,
            dcid,
            scid,
            state: ConnectionState::Handshaking,
            next_packet_number: 0,
            last_activity: Instant::now(),
            crypto: None,
            sent_shards: Vec::with_capacity(5),
            received_shards: BTreeMap::new(),
            unacked_packets: HashMap::new(),
            rtt: Duration::from_millis(100),

            local_window: 1024 * 1024,
            remote_window: 1024 * 1024,

            cwnd: 10 * 1200, // Initial window: 10 packets
            ssthresh: 64 * 1024,
            bytes_in_flight: 0,
            mtu: 1200,

            processed_packets: HashSet::with_capacity(1024),
            max_replay_window: 1024,
            highest_processed_pn: 0,
        }
    }

    pub fn is_replay(&self, pn: u64) -> bool {
        if self.highest_processed_pn > self.max_replay_window
            && pn < self.highest_processed_pn - self.max_replay_window
        {
            return true;
        }
        self.processed_packets.contains(&pn)
    }

    pub fn mark_processed(&mut self, pn: u64) {
        self.processed_packets.insert(pn);
        if pn > self.highest_processed_pn {
            self.highest_processed_pn = pn;
        }
        if self.processed_packets.len() > self.max_replay_window as usize * 2 {
            let threshold = self
                .highest_processed_pn
                .saturating_sub(self.max_replay_window);
            self.processed_packets.retain(|&p| p >= threshold);
        }
    }

    /// Increments and returns the next packet number.
    /// Defensively checks for 64-bit overflow.
    pub fn get_next_packet_number(&mut self) -> Result<u64> {
        let n = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(ZtError::Unknown)?; // Practically unreachable, but safe
        Ok(n)
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn handle_ack(&mut self, pn: u64, window_size: u32) {
        if let Some((packet, _, _)) = self.unacked_packets.remove(&pn) {
            self.bytes_in_flight = self.bytes_in_flight.saturating_sub(packet.len());
            
            // Congestion Control: AIMD
            if self.cwnd < self.ssthresh {
                // Slow Start
                self.cwnd += self.mtu;
            } else {
                // Congestion Avoidance
                self.cwnd += (self.mtu * self.mtu) / self.cwnd.max(self.mtu);
            }
        }
        self.remote_window = window_size;
    }

    pub fn handle_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_replay_protection() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut conn = ZtConnection::new(addr, vec![], vec![]);
        conn.max_replay_window = 10;
        
        conn.mark_processed(5);
        assert!(conn.is_replay(5));
        assert!(!conn.is_replay(6));

        conn.mark_processed(20);
        // Window is now 10..20, packets < 10 are replays
        assert!(conn.is_replay(5));
        assert!(conn.is_replay(9));
        assert!(!conn.is_replay(15));
        
        conn.mark_processed(15);
        assert!(conn.is_replay(15));
        
        // Trigger cleanup
        for i in 21..45 {
            conn.mark_processed(i);
        }
        
        // Window is 34..44
        assert!(conn.is_replay(20)); // Cleaned up, < 34
        assert!(conn.is_replay(40)); // In window, processed
        assert!(!conn.is_replay(45)); // Not processed
    }
}
