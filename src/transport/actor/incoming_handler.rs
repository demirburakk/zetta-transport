use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::stream::ZtStream;
use crate::transport::state::{ConnectionState, StreamState, StreamType, UnackedPayload};
use bytes::{Buf, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};
use rand::Rng;

impl ZtConnectionActor {
    pub(super) fn process_incoming_packet(
        &mut self,
        mut mutable_data: BytesMut,
        addr: SocketAddr,
    ) -> Result<()> {
        self.state.bytes_received += mutable_data.len();
        let is_short_header = !mutable_data.is_empty() && (mutable_data[0] & 0x80) == 0;

        if is_short_header {
            if let Some(crypto) = self.state.crypto.as_ref() {
                if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data) {
                    crypto.remove_header_protection(&mut mutable_data, offset)?;
                }
            } else {
                return Err(ZtError::Unauthorized);
            }
        } else if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data)
            && let Some(dcid) = crate::protocol::routing::extract_dcid_fast(&mutable_data)
        {
            let is_retry = ((mutable_data[0] >> 2) & 0x0F) == 0x0C;
            let _is_initial = ((mutable_data[0] >> 2) & 0x0F) == 0;
            if !is_retry {
                let crypto = crate::crypto::CryptoContext::initial(&dcid, true);
                crypto.remove_header_protection(&mut mutable_data, offset)?;
            }
        }

        let offset = PacketHeader::get_pn_offset(&mutable_data)
            .ok_or_else(|| ZtError::InvalidPacket("Malformed header offset".into()))?;
        let pn_len = (mutable_data[0] & 0x03) as usize + 1;
        let header_len = offset + pn_len;
        if mutable_data.len() < header_len {
            return Err(ZtError::InvalidPacket("Header truncated".into()));
        }

        let mut data_cursor = Bytes::copy_from_slice(&mutable_data[..header_len]);
        let mut header = PacketHeader::decode(&mut data_cursor)?;

        let mut payload_buf = mutable_data.split_off(header_len);
        let aad = mutable_data.freeze();

        if header.p_type == PacketType::Initial && !self.is_client {
            if let Some(hs) = self.state.handshake_packet.clone() {
                let _ = self.sendmsg_vectored(&[std::io::IoSlice::new(&hs)]);
            }
            return Ok(());
        }

        let highest = self.state.replay_window.highest_processed.unwrap_or(0);
        header.packet_number =
            crate::protocol::packet_number::expand_pn(header.packet_number, header.pn_len, highest);

        if self.state.is_replay(header.packet_number) {
            return Ok(());
        }
        let mut use_prev_key = false;
        let mut trial_rotate = false;

        let expected_kp = !self.state.current_key_epoch.is_multiple_of(2);
        if is_short_header && header.key_phase != expected_kp {
            if header.packet_number >= highest {
                trial_rotate = true;
            } else {
                use_prev_key = true;
            }
        }

        match header.p_type {
            PacketType::Handshake if self.state.state == ConnectionState::Handshaking => {
                self.handle_handshake_response(header, payload_buf.freeze(), &aad, addr)
            }
            PacketType::Retry if self.state.state == ConnectionState::Handshaking => {
                self.handle_retry_packet(header, payload_buf.freeze(), addr)
            }
            PacketType::Data | PacketType::MtuProbe | PacketType::Close
                if self.state.state == ConnectionState::Active
                    || (self.state.state == ConnectionState::Handshaking && !self.is_client) =>
            {
                let mut crypto = self.state.crypto.take().ok_or(ZtError::Unauthorized)?;
                if payload_buf.len() < 16 {
                    self.state.crypto = Some(crypto);
                    return Ok(());
                }
                let tag_idx = payload_buf.len() - 16;
                let tag_bytes = payload_buf.split_off(tag_idx);
                let tag: [u8; 16] = tag_bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| {
                        // Return unauthorized, we can't recover crypto context here without a workaround,
                        // but invalid tag size means protocol violation anyway.
                        ZtError::InvalidPacket("Invalid tag size".into())
                    })?;

                if trial_rotate {
                    if let Err(e) = crypto.trial_decrypt_and_rotate(
                        header.packet_number,
                        &aad,
                        &mut payload_buf,
                        &tag,
                    ) {
                        tracing::debug!("Key rotation trial decryption failed for pn={}", header.packet_number);
                        self.state.crypto = Some(crypto);
                        return Err(e);
                    }
                    self.state.current_key_epoch += 1;
                    self.state.packets_since_key_update = 0;
                } else {
                    if let Err(e) = crypto.decrypt_in_place(
                        header.packet_number,
                        &aad,
                        &mut payload_buf,
                        &tag,
                        use_prev_key,
                    ) {
                        self.state.crypto = Some(crypto);
                        return Err(e);
                    }
                }
                
                self.state.crypto = Some(crypto);

                // Transition server to Active upon successful decryption of 1-RTT packet.
                if self.state.state == ConnectionState::Handshaking && !self.is_client {
                    self.state.state = ConnectionState::Active;
                }

                if self.state.state == ConnectionState::Active && self.state.addr != addr {
                    if self.pending_validation_addr != Some(addr) {
                        let mut token = [0u8; 8];
                        rand::thread_rng().fill(&mut token);
                        self.pending_validation_addr = Some(addr);
                        self.path_validation_token = Some(token);
                        self.path_validation_sent_at = Some(std::time::Instant::now());
                        self.path_validation_retries = 0;
                        let challenge = Frame::PathChallenge { data: token };
                        let _ = self.send_frame_immediate(challenge, addr);
                    }
                } else if self.state.state == ConnectionState::Handshaking {
                    self.state.addr = addr;
                }
                self.state.mark_processed(header.packet_number);

                let mut payload_bytes = payload_buf.freeze();
                while payload_bytes.remaining() > 0 {
                    if let Ok(frame) = Frame::decode(&mut payload_bytes) {
                        self.handle_frame(frame, header.packet_number, addr)?;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_frame(&mut self, frame: Frame, _pn: u64, addr: SocketAddr) -> Result<()> {
        match frame {
            Frame::Stream { id, offset, data } => {
                if !self.state.streams.contains_key(&id) {
                    let expected_parity = if self.is_client { 1 } else { 0 };
                    if (id % 2) as u8 != expected_parity {
                        let _ = self.initiate_close();
                        return Err(ZtError::InvalidPacket(
                            "Invalid stream id parity".into(),
                        ));
                    }

                    if (self.state.streams.len() as u64) >= self.state.local_max_streams {
                        tracing::warn!(
                            "Peer exceeded local_max_streams ({}), dropping stream {}",
                            self.state.local_max_streams,
                            id
                        );
                        return Err(ZtError::TooManyStreams {
                            limit: self.state.local_max_streams as usize,
                        });
                    }

                    let (data_tx, data_rx) = mpsc::channel(2048);
                    let window_opened = Arc::new(Notify::new());
                    self.state
                        .streams
                        .insert(id, StreamState::new(data_tx, window_opened.clone(), StreamType::Bidirectional));

                    let stream = ZtStream::new(
                        id,
                        data_rx,
                        window_opened,
                        self.state.closed.clone(),
                        self.actor_tx.clone(),
                        self.state.shared_mtu.clone(),
                        StreamType::Bidirectional,
                    );
                    if let Err(e) = self.incoming_streams_tx.try_send(stream) {
                        tracing::error!("Failed to deliver incoming stream: {}. Closing connection.", e);
                        self.state.streams.remove(&id);
                        let _ = self.initiate_close();
                        return Err(ZtError::Io(std::io::Error::other("Application dropped connection handle")));
                    }
                }

                let Some(stream) = self.state.streams.get_mut(&id) else {
                    return Ok(());
                };

                // If the entire data payload is older than read_head, ignore.
                // Note: we can still receive overlapping packets. 
                // We'll let `StreamReceiveBuffer::write` handle writing. 
                // Wait, if offset + len <= read_head, it's fully duplicate.
                if offset + (data.len() as u64) <= stream.receive_buffer.read_head {
                    self.pending_acks += 1;
                    return Ok(());
                }
                
                // Truncate overlapping prefix if needed, to avoid writing before read_head
                let (write_offset, write_data) = if offset < stream.receive_buffer.read_head {
                    let diff = (stream.receive_buffer.read_head - offset) as usize;
                    (stream.receive_buffer.read_head, &data[diff..])
                } else {
                    (offset, data.as_ref())
                };

                if !write_data.is_empty() {
                    match stream.receive_buffer.write(write_offset, write_data) {
                        Some(added) => {
                            stream.buffered_bytes =
                                stream.buffered_bytes.saturating_add(added);
                        }
                        None => {
                        tracing::warn!(
                            "Stream {} buffered data exceeds window ({} bytes), dropping",
                            id,
                            stream.window_size
                        );
                        let _ = self.initiate_close();
                        return Err(ZtError::InvalidPacket(
                            "Stream receive window exceeded".into(),
                        ));
                        }
                    }
                }

                self.forward_stream_data(id)?;

                self.pending_acks += 1;
                if self.pending_acks >= 10 {
                    let _ = self.flush_acks();
                }
            }
            Frame::Ack {
                largest_acked,
                window_size,
                ack_delay,
                ack_ranges,
            } => {
                let mut fast_retransmits: Vec<(UnackedPayload, u32)> = Vec::new();
                self.state.handle_ack(
                    largest_acked,
                    window_size,
                    ack_delay,
                    &ack_ranges,
                    &mut fast_retransmits,
                );

                // Re-send the fast retransmits
                for (payload, retries) in fast_retransmits {
                    if let Err(e) = self.retransmit_payload(payload, retries) {
                        tracing::warn!("Fast retransmit failed: {}", e);
                    }
                }
            }
            Frame::ConnectionClose => {
                self.state.state = ConnectionState::Closed;
                // Signal all streams that the connection is closing so their
                // send() loops don't hang forever waiting for window_opened.
                self.state
                    .closed
                    .store(true, std::sync::atomic::Ordering::Release);
                for stream in self.state.streams.values() {
                    stream.window_opened.notify_waiters();
                }
            }
            Frame::StreamClose { id } => {
                self.state.streams.remove(&id);
            }
            Frame::MaxStreamData { id, max_data } => {
                if let Some(stream) = self.state.streams.get_mut(&id) {
                    let new_window = max_data.saturating_sub(stream.next_tx_offset);
                    let old_window = stream.tx_window;
                    stream.tx_window = new_window;
                    if new_window > old_window {
                        stream.window_opened.notify_waiters();
                    }
                }
            }
            Frame::MaxData { max_data } => {
                let new_window = max_data
                    .saturating_sub(self.state.conn_tx_offset)
                    .min(u32::MAX as u64) as u32;
                let old_window = self.state.remote_window;
                self.state.remote_window = new_window;
                if new_window > old_window {
                    for stream in self.state.streams.values() {
                        stream.window_opened.notify_waiters();
                    }
                }
            }
            Frame::Datagram { data } => {
                let _ = self.datagram_tx.try_send(data);
            }
            Frame::MaxStreams { max_streams } => {
                if max_streams > self.state.peer_max_streams {
                    self.state.peer_max_streams = max_streams;
                    for stream in self.state.streams.values() {
                        stream.window_opened.notify_waiters();
                    }
                }
            }
            Frame::StreamsBlocked { max_streams } => {
                tracing::info!("Peer signaled streams blocked at limit {}", max_streams);
            }
            Frame::PathChallenge { data } => {
                let response = Frame::PathResponse { data };
                let _ = self.send_frame_immediate(response, addr);
            }
            Frame::PathResponse { data } => {
                if Some(data) == self.path_validation_token
                    && let Some(a) = self.pending_validation_addr
                        && a == addr {
                            tracing::info!("Path validation succeeded for address {:?}", addr);
                            self.state.addr = addr;
                            self.pending_validation_addr = None;
                            self.path_validation_token = None;
                            self.path_validation_sent_at = None;
                            self.path_validation_retries = 0;
                        }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn forward_stream_data(&mut self, stream_id: u32) -> Result<()> {
        let mut forwarded = false;
        let mut bytes_forwarded = 0;
        let mut scale_up = false;
        let mut new_window = 0;
        let current_window_size;

        {
            let Some(stream) = self.state.streams.get_mut(&stream_id) else {
                return Ok(());
            };

            while let Some(chunk) = stream.receive_buffer.read_contiguous() {
                stream.buffered_bytes =
                    stream.buffered_bytes.saturating_sub(chunk.len());
                let chunk_len = chunk.len();
                if stream.app_tx.try_send(chunk).is_ok() {
                    forwarded = true;
                    bytes_forwarded += chunk_len;
                } else {
                    break;
                }
            }
            
            stream.expected_rx_offset = stream.receive_buffer.read_head;
            current_window_size = stream.window_size;

            if bytes_forwarded > 0 {
                stream.bytes_read_in_epoch += bytes_forwarded;
                if stream.bytes_read_in_epoch >= (stream.window_size / 2) as usize {
                    let elapsed = stream.last_window_update.elapsed();
                    let rtt = self.state.rtt;
                    if elapsed < rtt * 2 {
                        new_window = (stream.window_size * 2).min(16 * 1024 * 1024);
                        if new_window > stream.window_size {
                            scale_up = true;
                        }
                    }
                    stream.bytes_read_in_epoch = 0;
                    stream.last_window_update = std::time::Instant::now();
                }
            }
        }

        if scale_up {
            let current_total = self.state.total_allocated_buffer_size();
            let added_size = (new_window - current_window_size) as usize;
            if current_total + added_size <= crate::transport::connection::ZtConnection::MAX_CONNECTION_BUFFER_LIMIT {
                if let Some(stream) = self.state.streams.get_mut(&stream_id) {
                    tracing::info!("Auto-tuning: Scaling up stream {} window size from {} to {}", stream_id, stream.window_size, new_window);
                    stream.receive_buffer.resize(new_window as usize);
                    stream.window_size = new_window;
                }
            } else {
                tracing::warn!("Auto-tuning: Scaling up stream {} blocked (connection limit reached)", stream_id);
            }
        }

        if let Some(stream) = self.state.streams.get_mut(&stream_id) {
            let max_data = stream.expected_rx_offset + stream.window_size;
            // Only update peer with MAX_STREAM_DATA when the window can be extended
            // by a significant fraction (at least 1/4th of the window size, i.e., 256KB)
            // to avoid Silly Window Syndrome and massive packet volume.
            if forwarded && max_data.saturating_sub(stream.last_sent_max_data) >= stream.window_size / 4 {
                stream.last_sent_max_data = max_data;
                let payload = UnackedPayload::MaxStreamData {
                    stream_id,
                    max_data,
                };
                self.retransmit_payload(payload, 0)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::endpoint::ZtEndpoint;
    use crate::transport::connection::ZtConnection;
    use crate::protocol::frame::Frame;
    use crate::transport::state::ConnectionState;
    use std::net::SocketAddr;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_incoming_handler_path_validation() {
        let endpoint = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
        let socket = endpoint.socket.clone();
        
        let scid = vec![1, 2, 3, 4];
        let dcid = vec![5, 6, 7, 8];
        let original_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let migrated_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        
        let mut conn = ZtConnection::new(original_addr, scid.clone(), dcid.clone());
        conn.crypto = Some(Box::new(crate::crypto::CryptoContext::initial(&dcid, false)));
        
        let (_, rx) = mpsc::channel(1);
        let (stream_tx, _) = mpsc::channel(1);
        let (datagram_tx, _) = mpsc::channel(1);
        let (actor_tx, _) = mpsc::channel(1);
        
        let mut csprng = rand::rngs::OsRng;
        let (ephemeral_secret, ephemeral_public) = crate::crypto::keypair::generate_keypair();
        let client_ed_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let client_ed_public_key = client_ed_signing_key.verifying_key();
        
        let mut actor = ZtConnectionActor::new(
            endpoint.clone(),
            socket,
            rx,
            conn,
            ephemeral_public,
            Some(ephemeral_secret),
            Some(client_ed_signing_key),
            client_ed_public_key,
            None,
            None,
            endpoint.routing_table.clone(),
            scid,
            stream_tx,
            datagram_tx,
            false,
            actor_tx,
        );
        
        actor.state.state = ConnectionState::Active;
        
        // 1. Send PathChallenge from migrated address.
        let challenge_token = [0xAA; 8];
        let frame_challenge = Frame::PathChallenge { data: challenge_token };
        let res = actor.handle_frame(frame_challenge, 0, migrated_addr);
        assert!(res.is_ok());
        
        // 2. Set the pending validation parameters manually.
        actor.pending_validation_addr = Some(migrated_addr);
        actor.path_validation_token = Some(challenge_token);
        
        // Now receive PathResponse matching the token and address
        let frame_response = Frame::PathResponse { data: challenge_token };
        let res = actor.handle_frame(frame_response, 0, migrated_addr);
        assert!(res.is_ok());
        
        // Verify connection migrated!
        assert_eq!(actor.state.addr, migrated_addr);
        assert_eq!(actor.pending_validation_addr, None);
        assert_eq!(actor.path_validation_token, None);
    }

    #[tokio::test]
    async fn test_incoming_handler_max_streams_limit_update() {
        let endpoint = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
        let socket = endpoint.socket.clone();
        
        let scid = vec![1, 2, 3, 4];
        let dcid = vec![5, 6, 7, 8];
        let original_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        
        let conn = ZtConnection::new(original_addr, scid.clone(), dcid.clone());
        
        let (_, rx) = mpsc::channel(1);
        let (stream_tx, _) = mpsc::channel(1);
        let (datagram_tx, _) = mpsc::channel(1);
        let (actor_tx, _) = mpsc::channel(1);
        
        let mut csprng = rand::rngs::OsRng;
        let (ephemeral_secret, ephemeral_public) = crate::crypto::keypair::generate_keypair();
        let client_ed_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let client_ed_public_key = client_ed_signing_key.verifying_key();
        
        let mut actor = ZtConnectionActor::new(
            endpoint.clone(),
            socket,
            rx,
            conn,
            ephemeral_public,
            Some(ephemeral_secret),
            Some(client_ed_signing_key),
            client_ed_public_key,
            None,
            None,
            endpoint.routing_table.clone(),
            scid,
            stream_tx,
            datagram_tx,
            false,
            actor_tx,
        );
        
        assert_eq!(actor.state.peer_max_streams, 100);
        
        // Handle MaxStreams frame increasing peer_max_streams
        let frame = Frame::MaxStreams { max_streams: 150 };
        let res = actor.handle_frame(frame, 0, original_addr);
        assert!(res.is_ok());
        
        assert_eq!(actor.state.peer_max_streams, 150);
        
        // Handle MaxStreams frame trying to decrease peer_max_streams (should be ignored)
        let frame_low = Frame::MaxStreams { max_streams: 80 };
        let res = actor.handle_frame(frame_low, 0, original_addr);
        assert!(res.is_ok());
        
        assert_eq!(actor.state.peer_max_streams, 150);
    }
}
