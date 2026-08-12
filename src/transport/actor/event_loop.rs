use super::ActorMessage;
use super::ZtConnectionActor;
use crate::protocol::frame::Frame;
use crate::stats::ConnectionStats;
use crate::stream::ZtStream;
use crate::transport::state::{ConnectionState, StreamState};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant as TokioInstant, sleep_until};

const SLEEP_FOREVER: Duration = Duration::from_secs(86400 * 365);

impl ZtConnectionActor {
    pub(crate) async fn run(mut self) {
        let rto_deadline = TokioInstant::now() + self.state.rtt;
        let mut idle_deadline = TokioInstant::now() + self.state.idle_timeout;
        let mut ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
        let mut mtu_probe_deadline = TokioInstant::now() + self.endpoint.config.mtu_probe_interval;
        let mut pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;
        let mut path_validation_deadline = TokioInstant::now() + SLEEP_FOREVER;

        let rto_timer = sleep_until(rto_deadline);
        let idle_timer = sleep_until(idle_deadline);
        let delayed_ack_timer = sleep_until(ack_deadline);
        let mtu_probe_timer = sleep_until(mtu_probe_deadline);
        let pacing_timer = sleep_until(pacing_deadline);
        let path_validation_timer = sleep_until(path_validation_deadline);

        tokio::pin!(rto_timer);
        tokio::pin!(idle_timer);
        tokio::pin!(delayed_ack_timer);
        tokio::pin!(mtu_probe_timer);
        tokio::pin!(pacing_timer);
        tokio::pin!(path_validation_timer);

        // Helper macro to reset the pacing timer after flushing the pacing queue.
        // Avoids duplicating the same if/else block across all select! branches.
        macro_rules! reset_pacing {
            () => {
                if let Some(wait) = self.flush_pacing_queue() {
                    pacing_deadline = TokioInstant::now() + wait;
                    pacing_timer.as_mut().reset(pacing_deadline);
                } else {
                    pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;
                    pacing_timer.as_mut().reset(pacing_deadline);
                }
            };
        }

        if self.is_client
            && self.state.state == ConnectionState::Handshaking
            && let Err(e) = self.send_initial_packet(None)
        {
            tracing::warn!("Failed to send initial packet: {:?}", e);
        }

        loop {
            if self.state.state == ConnectionState::Closed {
                let zombie_duration = self.state.rtt * 3;
                let _ = tokio::time::timeout(zombie_duration, async {
                    while self.receiver.recv().await.is_some() {
                        // In zombie state, just drain and drop messages
                    }
                })
                .await;
                break;
            }

            let mut unacked_changed = false;

            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                    idle_deadline = TokioInstant::now() + self.state.idle_timeout;
                    idle_timer.as_mut().reset(idle_deadline);

                    match msg {
                        ActorMessage::IncomingPacket { data, addr } => {
                            if let Err(error) = self.process_incoming_packet(data, addr) {
                                tracing::debug!("Dropping invalid incoming packet: {error}");
                            }
                            unacked_changed = true;
                            if self.pending_acks > 0 {
                                let next_ack = TokioInstant::now() + Duration::from_millis(25);
                                if ack_deadline > next_ack {
                                    ack_deadline = next_ack;
                                    delayed_ack_timer.as_mut().reset(ack_deadline);
                                }
                            }
                            reset_pacing!();
                        }
                        ActorMessage::OutgoingData { stream_id, data, respond_to } => {
                            self.last_active_stream_id = stream_id;
                            let result = self.process_outgoing_data(stream_id, data);
                            unacked_changed = true;
                            reset_pacing!();
                            let _ = respond_to.send(result);
                        }
                        ActorMessage::GetMtu { respond_to } => {
                            let _ = respond_to.send(self.state.mtu);
                        }
                        ActorMessage::CloseStream { stream_id } => {
                            if let Err(e) = self.send_stream_close(stream_id) {
                                tracing::warn!("Failed to send StreamClose: {}", e);
                            }
                            self.state.streams.remove(&stream_id);
                            unacked_changed = true;
                            reset_pacing!();
                        }
                        ActorMessage::ResetStream { stream_id, error_code } => {
                            if let Err(error) = self.reset_stream(stream_id, error_code) {
                                tracing::warn!("Failed to reset stream: {error}");
                            }
                            self.state.streams.remove(&stream_id);
                            unacked_changed = true;
                            reset_pacing!();
                        }
                        ActorMessage::OpenStream { stream_type, respond_to } => {
                            if stream_type == crate::transport::state::StreamType::UnidirectionalIn {
                                let _ = respond_to.send(Err(crate::error::ZtError::InvalidPacket(
                                    "receive-only streams are created by the peer".into(),
                                )));
                                continue;
                            }
                            let local_parity = if self.is_client { 0 } else { 1 };
                            let opened_count = self
                                .state
                                .streams
                                .keys()
                                .filter(|id| **id % 2 == local_parity)
                                .count() as u64;

                            if opened_count >= self.state.peer_max_streams {
                                let blocked_frame = Frame::StreamsBlocked { max_streams: self.state.peer_max_streams };
                                if let Err(e) = self.send_frame_immediate(blocked_frame, self.state.addr) {
                                    tracing::warn!("Failed to send StreamsBlocked frame: {:?}", e);
                                }
                                let _ = respond_to.send(Err(crate::error::ZtError::TooManyStreams {
                                    limit: self.state.peer_max_streams as usize,
                                }));
                                continue;
                            }

                            let stream_id = self.next_stream_id;
                            let Some(next_stream_id) = self.next_stream_id.checked_add(2) else {
                                let _ = respond_to.send(Err(crate::error::ZtError::ConnectionIdExhausted));
                                continue;
                            };
                            self.next_stream_id = next_stream_id;

                            let (data_tx, data_rx) = mpsc::channel(2048);
                            let window_opened = Arc::new(Notify::new());
                            let termination = Arc::new(
                                crate::stream::termination::Termination::default(),
                            );
                            self.state.streams.insert(
                                stream_id,
                                StreamState::new(
                                    data_tx,
                                    window_opened.clone(),
                                    stream_type,
                                    self.endpoint.config.initial_stream_window,
                                    self.state.peer_initial_stream_window,
                                    termination.clone(),
                                ),
                            );

                            let stream = ZtStream::new(
                                stream_id,
                                data_rx,
                                window_opened,
                                self.state.closed.clone(),
                                self.actor_tx.clone(),
                                self.state.shared_mtu.clone(),
                                stream_type,
                                self.state.idle_timeout,
                                termination,
                            );
                            let _ = respond_to.send(Ok(stream));
                        }
                        ActorMessage::SetHandshakePacket(hs) => {
                            self.state.handshake_packet = Some(hs);
                        }
                        ActorMessage::StreamDataRead { stream_id, bytes_read } => {
                            let _ = self.forward_stream_data(stream_id, bytes_read);
                            if bytes_read > 0 {
                                // ACK frames also carry the connection-level
                                // receive window. Emit an update immediately so
                                // a sender blocked at zero credit cannot deadlock.
                                self.pending_acks = self.pending_acks.max(1);
                                let _ = self.flush_acks();
                                unacked_changed = true;
                            }
                            reset_pacing!();
                        }
                        ActorMessage::GetStats { respond_to } => {
                            let stats = ConnectionStats {
                                rtt: self.state.rtt,
                                rttvar: self.state.rttvar,
                                cwnd: self.state.cc.cwnd(),
                                bytes_in_flight: self.state.bytes_in_flight,
                                bytes_sent: self.state.bytes_sent,
                                bytes_received: self.state.bytes_received,
                                active_streams: self.state.streams.len(),
                                key_epoch: self.state.current_key_epoch,
                                mtu: self.state.mtu,
                                cc_algorithm: self.endpoint.cc_algo,
                                packets_lost: self.state.packets_lost,
                                packets_retransmitted: self.state.packets_retransmitted,
                                mtu_probe_successes: self.state.mtu_probe_successes,
                                mtu_probe_failures: self.state.mtu_probe_failures,
                                mtu_blackhole_recoveries: self.state.mtu_blackhole_recoveries,
                            };
                            let _ = respond_to.send(stats);
                        }
                        ActorMessage::Close => {
                            let _ = self.initiate_close();
                            idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                            idle_timer.as_mut().reset(idle_deadline);
                            unacked_changed = true;
                            reset_pacing!();
                        }
                        ActorMessage::CloseWithError { error_code, reason } => {
                            let _ = self.initiate_close_with_error(error_code, reason);
                            idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                            idle_timer.as_mut().reset(idle_deadline);
                            unacked_changed = true;
                            reset_pacing!();
                        }
                        ActorMessage::SendDatagram { data, respond_to } => {
                            let data_len = data.len();
                            let max_datagram_payload = self
                                .state
                                .mtu
                                .saturating_sub(64)
                                .min(self.state.peer_max_datagram_size);
                            if data_len > max_datagram_payload {
                                let _ = respond_to.send(Err(crate::error::ZtError::InvalidPacket(
                                    format!(
                                        "Datagram payload exceeds current path limit ({max_datagram_payload} bytes)"
                                    ),
                                )));
                            } else if self.state.bytes_in_flight.saturating_add(data_len) > self.state.cc.cwnd() {
                                let _ = respond_to.send(Err(crate::error::ZtError::CongestionWindowFull));
                            } else {
                                let result = self.send_datagram_payload(data);
                                unacked_changed = true;
                                reset_pacing!();
                                let _ = respond_to.send(result);
                            }
                        }
                    }
                }

                _ = &mut delayed_ack_timer => {
                    if self.pending_acks > 0 {
                        let _ = self.flush_acks();
                        unacked_changed = true;
                    }
                    ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
                    delayed_ack_timer.as_mut().reset(ack_deadline);
                }

                _ = &mut rto_timer => {
                    if self.handle_retransmits().is_err() { break; }
                    unacked_changed = true;
                    reset_pacing!();
                }

                _ = &mut mtu_probe_timer => {
                    if let Err(e) = self.send_mtu_probe() {
                        tracing::debug!("Failed to send MTU probe: {}", e);
                    }
                    mtu_probe_deadline =
                        TokioInstant::now() + self.endpoint.config.mtu_probe_interval;
                    mtu_probe_timer.as_mut().reset(mtu_probe_deadline);
                    unacked_changed = true;
                }

                _ = &mut pacing_timer => {
                    reset_pacing!();
                    unacked_changed = true;
                }

                _ = self.socket.writable(), if self.socket_blocked => {
                    self.socket_blocked = false;
                    reset_pacing!();
                    unacked_changed = true;
                }

                _ = &mut path_validation_timer => {
                    if self.path_validation_retries
                        < self.endpoint.config.max_path_validation_retries
                    {
                        if let Some(addr) = self.pending_validation_addr
                            && let Some(token) = self.path_validation_token
                        {
                            self.path_validation_retries += 1;
                            self.path_validation_sent_at = Some(std::time::Instant::now());
                            let challenge = Frame::PathChallenge { data: token };
                            if let Err(error) = self.send_frame_immediate(challenge, addr) {
                                tracing::debug!("PathChallenge retransmit failed: {error}");
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Path validation failed after {} retries for address {:?}",
                            self.endpoint.config.max_path_validation_retries,
                            self.pending_validation_addr
                        );
                        self.pending_validation_addr = None;
                        self.path_validation_token = None;
                        self.path_validation_sent_at = None;
                        self.path_validation_retries = 0;
                    }
                }

                _ = &mut idle_timer => {
                    if self.state.state != ConnectionState::Closing {
                        self.state
                            .termination
                            .set(crate::stream::termination::TerminationReason::IdleTimeout);
                        for stream in self.state.streams.values() {
                            stream
                                .termination
                                .set(crate::stream::termination::TerminationReason::IdleTimeout);
                        }
                    }
                    break;
                }
            }

            path_validation_deadline = self.path_validation_sent_at.map_or_else(
                || TokioInstant::now() + SLEEP_FOREVER,
                |sent_at| {
                    let rtt = self.state.rtt.max(Duration::from_millis(50));
                    TokioInstant::from_std(sent_at + rtt * 2)
                },
            );
            path_validation_timer
                .as_mut()
                .reset(path_validation_deadline);

            if unacked_changed {
                self.update_rto_timer(rto_timer.as_mut());
            }
        }

        // Signal all streams that the connection is closed, preventing
        // silent deadlocks in ZtStream::send() (Fix #10).
        self.state
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        for stream in self.state.streams.values() {
            stream.signal_window_opened();
        }

        self.routing_table.remove(&self.scid);
    }

    pub(super) fn get_next_rto_deadline(&self) -> Option<tokio::time::Instant> {
        let rto = (self.state.rtt + self.state.rttvar * 4).max(Duration::from_millis(50));
        let mut min_deadline: Option<std::time::Instant> = None;

        for (_, up) in self.state.unacked_packets.iter() {
            let backoff_multiplier = 1_u32.checked_shl(up.retries).unwrap_or(64).min(64);
            let packet_rto = (rto * backoff_multiplier).min(Duration::from_secs(10));
            let deadline = up.sent_at + packet_rto;
            if let Some(min) = min_deadline {
                if deadline < min {
                    min_deadline = Some(deadline);
                }
            } else {
                min_deadline = Some(deadline);
            }
        }
        min_deadline.map(|d| d.into())
    }

    pub(super) fn update_rto_timer(&self, timer: std::pin::Pin<&mut tokio::time::Sleep>) {
        if let Some(deadline) = self.get_next_rto_deadline() {
            timer.reset(deadline);
        } else {
            timer.reset(tokio::time::Instant::now() + SLEEP_FOREVER);
        }
    }
}
