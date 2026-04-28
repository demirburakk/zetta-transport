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
    pub reorder_buffer: BTreeMap<u64, Bytes>,
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
            reorder_buffer: BTreeMap::new(),
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

    pub replay_window: Box<[u64]>,
    pub max_replay_window: u64,

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

            replay_window: vec![u64::MAX; 8192].into_boxed_slice(),
            max_replay_window: 8192,

            current_key_epoch: 0,
        }
    }

    pub fn is_replay(&self, pn: u64) -> bool {
        if pn > self.highest_processed_pn + self.max_replay_window {
            return true;
        }
        if self.highest_processed_pn > self.max_replay_window
            && pn < self.highest_processed_pn - self.max_replay_window
        {
            return true;
        }
        let idx = (pn % self.max_replay_window) as usize;
        self.replay_window[idx] == pn
    }

    pub fn mark_processed(&mut self, pn: u64) {
        let idx = (pn % self.max_replay_window) as usize;
        self.replay_window[idx] = pn;
        if pn > self.highest_processed_pn {
            self.highest_processed_pn = pn;
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

    pub fn handle_ack(&mut self, acked_pn: u64, acked_stream_id: u32, acked_offset: u64, window_size: u32) {
        let mut bytes_acked = 0;
        let mut sample_rtt = None;

        if let Some(probe_size) = self.mtu_probes.remove(&acked_pn) {
            if probe_size > self.mtu {
                self.mtu = probe_size;
                tracing::info!("MTU upgraded to {} via PMTUD", self.mtu);
            }
        }

        if let Some(stream) = self.streams.get_mut(&acked_stream_id) {
            if acked_offset == stream.last_acked_offset {
                stream.dup_ack_count += 1;
            } else if acked_offset > stream.last_acked_offset {
                stream.last_acked_offset = acked_offset;
                stream.dup_ack_count = 0;
            }

            let mut acked_offsets = Vec::new();
            for (&start_offset, &_pn) in stream.unacked_pns.iter() {
                if start_offset < acked_offset {
                    acked_offsets.push(start_offset);
                } else {
                    break;
                }
            }

            for offset in acked_offsets {
                if let Some(pn) = stream.unacked_pns.remove(&offset) {
                    if let Some((packet, sent_time, retries, _, _, _)) = self.unacked_packets.remove(&pn) {
                        bytes_acked += packet.len();
                        if retries == 0 && sample_rtt.is_none() {
                            sample_rtt = Some(sent_time.elapsed());
                        }
                    }
                }
            }
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if let Some(rtt) = sample_rtt {
            if self.rtt == Duration::from_millis(100) && self.rttvar == Duration::from_millis(0) {
                self.rtt = rtt;
                self.rttvar = rtt / 2;
            } else {
                let error = if self.rtt > rtt { self.rtt - rtt } else { rtt - self.rtt };
                self.rttvar = (self.rttvar * 3 + error) / 4;
                self.rtt = (self.rtt * 7 + rtt) / 8;
            }
        }

        if bytes_acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += self.mtu;
            } else {
                self.cwnd += (self.mtu * self.mtu) / self.cwnd.max(self.mtu);
            }
            
            if let Some(stream) = self.streams.get(&acked_stream_id) {
                stream.window_opened.notify_waiters();
            }
        }
        
        self.remote_window = window_size;
    }

    pub fn handle_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh + 3 * self.mtu;
    }

    pub fn get_total_buffered_bytes(&self) -> usize {
        self.streams.values().map(|s| s.buffered_bytes).sum()
    }
}