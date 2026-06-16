use super::ActorMessage;
use super::ZtConnectionActor;
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
        let mut idle_deadline = TokioInstant::now() + Duration::from_secs(60);
        let mut ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
        let mut mtu_probe_deadline = TokioInstant::now() + Duration::from_secs(15);
        let mut pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;

        let rto_timer = sleep_until(rto_deadline);
        let idle_timer = sleep_until(idle_deadline);
        let delayed_ack_timer = sleep_until(ack_deadline);
        let mtu_probe_timer = sleep_until(mtu_probe_deadline);
        let pacing_timer = sleep_until(pacing_deadline);

        tokio::pin!(rto_timer);
        tokio::pin!(idle_timer);
        tokio::pin!(delayed_ack_timer);
        tokio::pin!(mtu_probe_timer);
        tokio::pin!(pacing_timer);

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
                }).await;
                break;
            }

            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                    idle_deadline = TokioInstant::now() + Duration::from_secs(60);
                    idle_timer.as_mut().reset(idle_deadline);

                    match msg {
                        ActorMessage::IncomingPacket { data, addr } => {
                            let _ = self.process_incoming_packet(data, addr);
                            if self.pending_acks > 0 {
                                let next_ack = TokioInstant::now() + Duration::from_millis(25);
                                if ack_deadline > next_ack {
                                    ack_deadline = next_ack;
                                    delayed_ack_timer.as_mut().reset(ack_deadline);
                                }
                            }
                            if let Some(wait) = self.flush_pacing_queue() {
                                pacing_deadline = TokioInstant::now() + wait;
                                pacing_timer.as_mut().reset(pacing_deadline);
                            } else {
                                pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;
                                pacing_timer.as_mut().reset(pacing_deadline);
                            }
                        }
                        ActorMessage::OutgoingData { stream_id, data, respond_to } => {
                            self.last_active_stream_id = stream_id;
                            let result = self.process_outgoing_data(stream_id, data);
                            if let Some(wait) = self.flush_pacing_queue() {
                                pacing_deadline = TokioInstant::now() + wait;
                                pacing_timer.as_mut().reset(pacing_deadline);
                            } else {
                                pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;
                                pacing_timer.as_mut().reset(pacing_deadline);
                            }
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

                            if self.state.streams.is_empty() {
                                let _ = self.initiate_close();
                                idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                                idle_timer.as_mut().reset(idle_deadline);
                            }
                        }
                        ActorMessage::OpenStream { respond_to } => {
                            let stream_id = self.next_stream_id;
                            self.next_stream_id += 2;

                            let (data_tx, data_rx) = mpsc::channel(2048);
                            let window_opened = Arc::new(Notify::new());
                            self.state.streams.insert(
                                stream_id,
                                StreamState::new(data_tx, window_opened.clone()),
                            );

                            let stream = ZtStream::new(
                                self.endpoint.clone(),
                                self.scid.clone(),
                                stream_id,
                                data_rx,
                                window_opened,
                                self.state.closed.clone(),
                            );
                            let _ = respond_to.send(Ok(stream));
                        }
                        ActorMessage::SetHandshakePacket(hs) => {
                            self.state.handshake_packet = Some(hs);
                        }
                        ActorMessage::StreamDataRead { stream_id } => {
                            let _ = self.forward_stream_data(stream_id);
                        }
                        ActorMessage::Close => {
                            let _ = self.initiate_close();
                            idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                            idle_timer.as_mut().reset(idle_deadline);
                        }
                    }
                }

                _ = &mut delayed_ack_timer => {
                    if self.pending_acks > 0 { let _ = self.flush_acks(); }
                    ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
                    delayed_ack_timer.as_mut().reset(ack_deadline);
                }

                _ = &mut rto_timer => {
                    if self.handle_retransmits().is_err() { break; }
                }

                _ = &mut mtu_probe_timer => {
                    if let Err(e) = self.send_mtu_probe() {
                        tracing::debug!("Failed to send MTU probe: {}", e);
                    }
                    mtu_probe_deadline = TokioInstant::now() + Duration::from_secs(15);
                    mtu_probe_timer.as_mut().reset(mtu_probe_deadline);
                }

                _ = &mut pacing_timer => {
                    if let Some(wait) = self.flush_pacing_queue() {
                        pacing_deadline = TokioInstant::now() + wait;
                        pacing_timer.as_mut().reset(pacing_deadline);
                    } else {
                        pacing_deadline = TokioInstant::now() + SLEEP_FOREVER;
                        pacing_timer.as_mut().reset(pacing_deadline);
                    }
                }

                _ = &mut idle_timer => { break; }
            }
            self.update_rto_timer(rto_timer.as_mut());
        }

        // Signal all streams that the connection is closed, preventing
        // silent deadlocks in ZtStream::send() (Fix #10).
        self.state
            .closed
            .store(true, std::sync::atomic::Ordering::Release);
        for stream in self.state.streams.values() {
            stream.window_opened.notify_waiters();
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
