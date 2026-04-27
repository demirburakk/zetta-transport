use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use bytes::Bytes;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Notify;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Handshaking,
    Active,
    Closing, // YENİ: TIME_WAIT / Teardown durumu
    Closed,
}

pub struct ZtConnection {
    pub addr: SocketAddr,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub state: ConnectionState,
    pub next_packet_number: u64,
    pub last_activity: Instant,
    pub crypto: Option<CryptoContext>,

    pub expected_rx_offset: u64,
    pub next_tx_offset: u64,
    pub reorder_buffer: BTreeMap<u64, Bytes>,
    pub buffered_bytes: usize,

    pub window_opened: Arc<Notify>, // YENİ: Backpressure Waker (Stream'i uyandırmak için)

    // ÇÖZÜM: TCP Tarzı Fast Retransmit
    pub unacked_packets: HashMap<u64, (Bytes, Instant, u32, u64, u64)>, // (packet, sent_time, retries, start_offset, end_offset)
    pub last_acked_offset: u64,
    pub dup_ack_count: u8,
    
    pub rtt: Duration,
    pub local_window: u32,
    pub remote_window: u32,

    pub cwnd: usize,
    pub ssthresh: usize,
    pub bytes_in_flight: usize,
    pub mtu: usize,
    pub highest_processed_pn: u64,

    pub replay_window: Box<[u64]>,
    pub max_replay_window: u64,
}

impl ZtConnection {
    pub fn new(addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>, window_opened: Arc<Notify>) -> Self {
        Self {
            addr,
            dcid,
            scid,
            state: ConnectionState::Handshaking,
            next_packet_number: 0,
            last_activity: Instant::now(),
            crypto: None,
            
            expected_rx_offset: 0,
            next_tx_offset: 0,
            reorder_buffer: BTreeMap::new(),
            buffered_bytes: 0,
            
            window_opened,

            unacked_packets: HashMap::new(),
            last_acked_offset: 0,
            dup_ack_count: 0,
            
            rtt: Duration::from_millis(100),

            local_window: 1024 * 1024,
            remote_window: 1024 * 1024,

            cwnd: 10 * 1200, 
            ssthresh: 64 * 1024,
            bytes_in_flight: 0,
            mtu: 1200,
            highest_processed_pn: 0,

            replay_window: vec![u64::MAX; 1024].into_boxed_slice(),
            max_replay_window: 1024,
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

    pub fn handle_ack(&mut self, acked_offset: u64, window_size: u32) {
        let mut bytes_acked = 0;
        let mut sample_rtt = None;

        // ÇÖZÜM: Fast Retransmit (3 Dup ACK) Hesaplaması
        if acked_offset == self.last_acked_offset {
            self.dup_ack_count += 1;
        } else if acked_offset > self.last_acked_offset {
            self.last_acked_offset = acked_offset;
            self.dup_ack_count = 0;
        }

        self.unacked_packets.retain(|_pn, (packet, sent_time, retries, _start_offset, end_offset)| {
            if *end_offset <= acked_offset {
                bytes_acked += packet.len();
                if *retries == 0 && sample_rtt.is_none() {
                    sample_rtt = Some(sent_time.elapsed());
                }
                false // Sil
            } else {
                true // Tut
            }
        });

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if let Some(rtt) = sample_rtt {
            self.rtt = (self.rtt * 7 + rtt) / 8;
        }

        if bytes_acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += self.mtu;
            } else {
                self.cwnd += (self.mtu * self.mtu) / self.cwnd.max(self.mtu);
            }
            
            // ÇÖZÜM: Backpressure'da bekleyen ZtStream send()'i uyandır.
            self.window_opened.notify_waiters();
        }
        
        self.remote_window = window_size;
    }

    pub fn handle_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh;
    }
}