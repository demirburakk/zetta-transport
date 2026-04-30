use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};

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
    pub ring_buffer: Option<Box<[u8]>>,
    pub received_ranges: BTreeMap<u64, u64>, // start -> end
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
            ring_buffer: None, // Lazy allocation
            received_ranges: BTreeMap::new(),
            window_size: 1024 * 1024,
            buffered_bytes: 0,
            window_opened,
            last_acked_offset: 0,
            dup_ack_count: 0,
            app_tx,
            unacked_pns: BTreeMap::new(),
        }
    }

    pub fn ensure_buffer(&mut self) -> &mut [u8] {
        if self.ring_buffer.is_none() {
            self.ring_buffer = Some(vec![0u8; self.window_size as usize].into_boxed_slice());
        }
        self.ring_buffer.as_mut().unwrap()
    }
}

pub struct UnackedPacket {
    pub data: Bytes,
    pub sent_at: Instant,
    pub retries: u32,
    pub stream_id: u32,
    pub start_offset: u64,
    pub end_offset: u64,
    pub is_mtu_probe: bool,
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

    pub unacked_packets: BTreeMap<u64, UnackedPacket>,

    pub rtt: Duration,
    pub rttvar: Duration,
    pub rtt_initialized: bool,
    pub local_window: u32,
    pub remote_window: u32,

    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub mtu: usize,
    pub highest_processed_pn: Option<u64>,
    pub bytes_received: usize,
    pub bytes_sent: usize,

    pub replay_bitmask: u128,

    pub current_key_epoch: u64,
}

impl ZtConnection {
    // Maximum concurrent streams allowed. With 1MB window_size, this limits total
    // stream buffer memory to ~100MB max per connection.
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
            unacked_packets: BTreeMap::new(),

            rtt: Duration::from_millis(333),
            rttvar: Duration::from_millis(166),
            rtt_initialized: false,

            local_window: 1024 * 1024,
            remote_window: 1024 * 1024,

            cwnd: 10 * 1200,
            ssthresh: 64 * 1024,
            bytes_in_flight: 0,
            mtu: 1200,
            highest_processed_pn: None,
            bytes_received: 0,
            bytes_sent: 0,

            replay_bitmask: 0,

            current_key_epoch: 0,
        }
    }

    pub fn is_replay(&self, pn: u64) -> bool {
        let Some(highest) = self.highest_processed_pn else {
            return false;
        };
        if pn <= highest {
            let diff = highest - pn;
            if diff >= 128 {
                return true;
            }
            return (self.replay_bitmask & (1 << diff)) != 0;
        }
        false
    }

    pub fn mark_processed(&mut self, pn: u64) {
        let Some(highest) = self.highest_processed_pn else {
            self.highest_processed_pn = Some(pn);
            self.replay_bitmask = 1;
            return;
        };

        if pn > highest {
            let diff = pn - highest;
            if diff >= 128 {
                self.replay_bitmask = 1;
            } else {
                self.replay_bitmask = (self.replay_bitmask << diff) | 1;
            }
            self.highest_processed_pn = Some(pn);
        } else {
            let diff = highest - pn;
            if diff < 128 {
                self.replay_bitmask |= 1 << diff;
            }
        }
    }

    pub fn get_ack_ranges(&self) -> Vec<(u64, u64)> {
        let Some(highest) = self.highest_processed_pn else {
            return vec![];
        };
        let mut ranges = Vec::new();

        let mut in_range = false;
        let mut current_end = 0;

        for i in 1..128 {
            if highest < i {
                break;
            }
            let pn = highest - i;
            let received = (self.replay_bitmask & (1 << i)) != 0;

            if received {
                if !in_range {
                    in_range = true;
                    current_end = pn;
                }
            } else {
                if in_range {
                    ranges.push((pn + 1, current_end));
                    in_range = false;
                }
            }
        }
        if in_range {
            let lowest_checked = highest.saturating_sub(127);
            ranges.push((lowest_checked, current_end));
        }

        ranges
    }
    pub fn get_next_packet_number(&mut self) -> Result<u64> {
        let n = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(ZtError::PacketNumberOverflow)?;
        Ok(n)
    }

    pub fn update_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn handle_ack(
        &mut self,
        largest_acked_pn: u64,
        window_size: u32,
        sack_ranges: &[(u64, u64)],
    ) {
        let mut bytes_acked = 0usize;
        let mut sample_rtt = None;

        // 1. Process SACK ranges first (Selective ACK)
        for &(start, end) in sack_ranges {
            let range = self
                .unacked_packets
                .range(start..=end)
                .map(|(&pn, _)| pn)
                .collect::<Vec<_>>();
            for pn in range {
                if let Some(up) = self.unacked_packets.remove(&pn) {
                    bytes_acked += up.data.len();
                    if up.retries == 0 && sample_rtt.is_none() {
                        sample_rtt = Some(up.sent_at.elapsed());
                    }
                    if up.is_mtu_probe
                        && self.mtu_probes.remove(&pn).is_some()
                        && up.data.len() > self.mtu
                    {
                        self.mtu = up.data.len();
                        tracing::info!("MTU upgraded to {} via SACK'd PMTUD", self.mtu);
                    }
                }
            }
        }

        // 2. Process cumulative ACK (everything <= largest_acked_pn)
        let acked_pns: Vec<u64> = self
            .unacked_packets
            .keys()
            .copied()
            .take_while(|&pn| pn <= largest_acked_pn)
            .collect();

        for pn in acked_pns {
            if let Some(up) = self.unacked_packets.remove(&pn) {
                bytes_acked += up.data.len();
                if up.retries == 0 && sample_rtt.is_none() {
                    sample_rtt = Some(up.sent_at.elapsed());
                }
                if up.is_mtu_probe
                    && self.mtu_probes.remove(&pn).is_some()
                    && up.data.len() > self.mtu
                {
                    self.mtu = up.data.len();
                    tracing::info!("MTU upgraded to {} via PMTUD", self.mtu);
                }
            }
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if let Some(rtt) = sample_rtt {
            if !self.rtt_initialized {
                self.rtt = rtt;
                self.rttvar = rtt / 2;
                self.rtt_initialized = true;
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
