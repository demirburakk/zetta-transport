use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Handshaking,
    Active,
    Closing,
    Closed,
}

pub struct StreamState {
    pub expected_rx_offset: u64,
    pub next_tx_offset: u64,
    pub ring_buffer: Box<[u8]>,
    pub received_ranges: Vec<(u64, u64)>,
    pub window_size: u64,
    pub buffered_bytes: usize,
    pub window_opened: Arc<Notify>,
    pub last_acked_offset: u64,
    pub dup_ack_count: u8,
    pub app_tx: mpsc::Sender<Bytes>,
    pub unacked_pns: BTreeMap<u64, u64>,
}

impl StreamState {
    pub fn new(app_tx: mpsc::Sender<Bytes>, window_opened: Arc<Notify>) -> Self {
        Self {
            expected_rx_offset: 0,
            next_tx_offset: 0,
            ring_buffer: vec![0u8; 1024 * 1024].into_boxed_slice(),
            received_ranges: Vec::new(),
            window_size: 1024 * 1024,
            buffered_bytes: 0,
            window_opened,
            last_acked_offset: 0,
            dup_ack_count: 0,
            app_tx,
            unacked_pns: BTreeMap::new(),
        }
    }
}

pub struct ZtConnection {
    pub addr: SocketAddr,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub state: ConnectionState,
    pub next_packet_number: u64,
    pub last_activity: Instant,
    pub crypto: Option<CryptoContext>,

    pub streams: HashMap<u32, StreamState>,
    pub mtu_probes: HashMap<u64, usize>,
    
    pub unacked_packets: HashMap<u64, (Bytes, Instant, u32, u32, u64, u64)>, 
    
    pub rtt: Duration,
    pub rttvar: Duration,
    pub local_window: u32,
    pub remote_window: u32,

    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub mtu: usize,
    pub highest_processed_pn: u64,
    pub bytes_received: usize,
    pub bytes_sent: usize,

    pub replay_bitmask: u64,

    pub current_key_epoch: u64,
}

impl ZtConnection {
    pub const MAX_CONCURRENT_STREAMS: usize = 100;

    pub fn new(addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) -> Self {
        Self {
            addr,
            dcid,
            scid,
            state: ConnectionState::Handshaking,
            next_packet_number: 0,
            last_activity: Instant::now(),
            crypto: None,
            
            streams: HashMap::new(),
            mtu_probes: HashMap::new(),
            unacked_packets: HashMap::new(),
            
            rtt: Duration::from_millis(100),
            rttvar: Duration::from_millis(0),

            local_window: 1024 * 1024,
            remote_window: 1024 * 1024,

            cwnd: 10 * 1200, 
            ssthresh: 64 * 1024,
            bytes_in_flight: 0,
            mtu: 1200,
            highest_processed_pn: 0,
            bytes_received: 0,
            bytes_sent: 0,

            replay_bitmask: 0,

            current_key_epoch: 0,
        }
    }

    pub fn is_replay(&self, pn: u64) -> bool {
        if pn <= self.highest_processed_pn {
            let diff = self.highest_processed_pn - pn;
            if diff >= 64 {
                return true;
            }
            return (self.replay_bitmask & (1 << diff)) != 0;
        }
        false
    }

    pub fn mark_processed(&mut self, pn: u64) {
        if pn > self.highest_processed_pn {
            let diff = pn - self.highest_processed_pn;
            if diff >= 64 {
                self.replay_bitmask = 1;
            } else {
                self.replay_bitmask = (self.replay_bitmask << diff) | 1;
            }
            self.highest_processed_pn = pn;
        } else {
            let diff = self.highest_processed_pn - pn;
            if diff < 64 {
                self.replay_bitmask |= 1 << diff;
            }
        }
    }

    pub fn get_next_packet_number(&mut self) -> Result<u64> {
        let n = self.next_packet_number;
        self.next_packet_number = self.next_packet_number.checked_add(1).ok_or(ZtError::Unknown)?;
        Ok(n)
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn handle_ack(&mut self, largest_acked_pn: u64, window_size: u32) {
        let mut bytes_acked = 0usize;
        let mut sample_rtt = None;

        // PMTUD: if any probe packet number is cumulatively acked, it's safe to upgrade.
        let mut acked_probe_pns: Vec<u64> = self
            .mtu_probes
            .keys()
            .copied()
            .filter(|pn| *pn <= largest_acked_pn)
            .collect();
        acked_probe_pns.sort_unstable();
        for pn in acked_probe_pns {
            if let Some(probe_size) = self.mtu_probes.remove(&pn)
                && probe_size > self.mtu
            {
                self.mtu = probe_size;
                tracing::info!("MTU upgraded to {} via PMTUD", self.mtu);
            }
        }

        // Cumulative ACK by packet number: remove all unacked packets up to largest_acked_pn.
        let mut acked_pns: Vec<u64> = self
            .unacked_packets
            .keys()
            .copied()
            .filter(|pn| *pn <= largest_acked_pn)
            .collect();
        acked_pns.sort_unstable();

        for pn in acked_pns {
            if let Some((packet, sent_time, retries, _stream_id, _start_offset, _end_offset)) =
                self.unacked_packets.remove(&pn)
            {
                bytes_acked += packet.len();
                if retries == 0 && sample_rtt.is_none() {
                    sample_rtt = Some(sent_time.elapsed());
                }
            }
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if let Some(rtt) = sample_rtt {
            if self.rtt == Duration::from_millis(100) && self.rttvar == Duration::from_millis(0) {
                self.rtt = rtt;
                self.rttvar = rtt / 2;
            } else {
                let error = self.rtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + error) / 4;
                self.rtt = (self.rtt * 7 + rtt) / 8;
            }
        }

        if bytes_acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += bytes_acked;
            } else {
                self.cwnd += (self.mtu * bytes_acked) / self.cwnd.max(self.mtu);
            }
        }

        self.remote_window = window_size;

        // Unblock senders that are waiting on flow/cwnd to open.
        for stream in self.streams.values() {
            stream.window_opened.notify_waiters();
        }
    }

    pub fn handle_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh + 3 * self.mtu;
    }

    pub fn get_total_buffered_bytes(&self) -> usize {
        self.streams.values().map(|s| s.buffered_bytes).sum()
    }
}