use super::endpoint::ZtEndpoint;
use crate::protocol::packet::MAX_PACKET_SIZE;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const BUFFER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_EXPIRY_TIMEOUT: Duration = Duration::from_secs(3600);
const PRUNING_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) fn spawn_workers(endpoint: Arc<ZtEndpoint>) {
    // 1. Background Listener Task
    let endpoint_clone = endpoint.clone();
    let token_1 = endpoint.shutdown_token.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        loop {
            tokio::select! {
                _ = token_1.cancelled() => break,
                recv_res = endpoint_clone.socket.recv_from(&mut buf) => {
                    match recv_res {
                        Ok((len, addr)) => {
                            let data = &buf[..len];
                            if let Err(e) = endpoint_clone.handle_packet(data, addr).await {
                                tracing::debug!("Packet error from {:?}: {:?}", addr, e);
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // 2. Background Retransmission Task
    let endpoint_retransmit = endpoint.clone();
    let token_2 = endpoint.shutdown_token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token_2.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    let mut to_send_list: Vec<(SocketAddr, Bytes)> = Vec::new();
                    {
                        let conns = &endpoint_retransmit.connections;
                        for mut kv in conns.iter_mut() {
                            let conn = kv.value_mut();
                            let now = Instant::now();
                            let mut to_remove = Vec::new();
                            let mut loss_occurred = false;
                            for (pn, (full_packet, sent_time, retries)) in conn.unacked_packets.iter_mut() {
                                if now.duration_since(*sent_time) > conn.rtt * 4 {
                                    loss_occurred = true;
                                    if *retries > 10 {
                                        to_remove.push(*pn);
                                    } else {
                                        *sent_time = now;
                                        *retries += 1;
                                        to_send_list.push((conn.addr, full_packet.clone()));
                                    }
                                }
                            }
                            if loss_occurred {
                                conn.handle_loss();
                            }
                            for pn in to_remove {
                                if let Some((packet, _, _)) = conn.unacked_packets.remove(&pn) {
                                    conn.bytes_in_flight = conn.bytes_in_flight.saturating_sub(packet.len());
                                }
                            }
                        }
                    }
                    for (addr, packet) in to_send_list {
                        let _ = endpoint_retransmit.socket.send_to(&packet, addr).await;
                    }
                }
            }
        }
    });

    // 3. Background Pruning Task
    let endpoint_pruner = endpoint.clone();
    let token_3 = endpoint.shutdown_token.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token_3.cancelled() => break,
                _ = tokio::time::sleep(PRUNING_INTERVAL) => {
                    let conns = &endpoint_pruner.connections;
                    let now = Instant::now();
                    conns.retain(|_, conn| {
                        now.duration_since(conn.last_activity) < SESSION_EXPIRY_TIMEOUT
                    });
                    for mut kv in conns.iter_mut() {
                        let conn = kv.value_mut();
                        if now.duration_since(conn.last_activity) > BUFFER_CLEANUP_TIMEOUT {
                            conn.unacked_packets.clear();
                            conn.sent_shards.clear();
                        }
                    }
                }
            }
        }
    });
}