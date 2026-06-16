use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::stream::ZtStream;
use crate::transport::connection::ZtConnection;
use crate::transport::state::{ConnectionState, StreamState, UnackedPayload};
use bytes::{Buf, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

impl ZtConnectionActor {
    pub(super) fn process_incoming_packet(
        &mut self,
        mut mutable_data: BytesMut,
        addr: SocketAddr,
    ) -> Result<()> {
        self.state.bytes_received += mutable_data.len();
        let is_short_header = !mutable_data.is_empty() && (mutable_data[0] & 0x80) == 0;

        // Phase hint from the first byte (before HP removal).
        let pre_hp_key_phase = is_short_header && (mutable_data[0] & 0x40) != 0;
        let expected_kp = !self.state.current_key_epoch.is_multiple_of(2);
        let hp_use_prev = is_short_header && pre_hp_key_phase != expected_kp;

        if is_short_header {
            if let Some(crypto) = self.state.crypto.as_ref() {
                if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data) {
                    crypto.remove_header_protection(&mut mutable_data, offset, hp_use_prev)?;
                }
            } else {
                return Err(ZtError::Unauthorized);
            }
        } else if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data)
            && let Some(dcid) = crate::protocol::routing::extract_dcid_fast(&mutable_data)
        {
            let is_retry = ((mutable_data[0] >> 2) & 0x0F) == 0x0C;
            let is_initial = ((mutable_data[0] >> 2) & 0x0F) == 0;
            if !is_retry && !is_initial {
                let crypto = crate::crypto::CryptoContext::initial(&dcid, true);
                crypto.remove_header_protection(&mut mutable_data, offset, false)?;
            } else if is_initial {
                let crypto = crate::crypto::CryptoContext::initial(&dcid, true);
                crypto.remove_header_protection(&mut mutable_data, offset, false)?;
            }
        }

        let mut data_cursor = Bytes::copy_from_slice(&mutable_data[..]);
        let initial_len = data_cursor.len();
        let mut header = PacketHeader::decode(&mut data_cursor)?;
        let header_len = initial_len - data_cursor.len();

        let mut payload_buf = mutable_data.split_off(header_len);
        let aad = mutable_data.freeze();

        if header.p_type == PacketType::Initial && self.state.state == ConnectionState::Active && !self.is_client {
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
                if self.state.state == ConnectionState::Active =>
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

                self.state.addr = addr;
                self.state.mark_processed(header.packet_number);

                let mut payload_bytes = payload_buf.freeze();
                while payload_bytes.remaining() > 0 {
                    if let Ok(frame) = Frame::decode(&mut payload_bytes) {
                        self.handle_frame(frame, header.packet_number)?;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_frame(&mut self, frame: Frame, _pn: u64) -> Result<()> {
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

                    if self.state.streams.len() >= ZtConnection::MAX_CONCURRENT_STREAMS {
                        tracing::warn!(
                            "Peer exceeded MAX_CONCURRENT_STREAMS ({}), dropping stream {}",
                            ZtConnection::MAX_CONCURRENT_STREAMS,
                            id
                        );
                        return Err(ZtError::TooManyStreams {
                            limit: ZtConnection::MAX_CONCURRENT_STREAMS,
                        });
                    }

                    let (data_tx, data_rx) = mpsc::channel(2048);
                    let window_opened = Arc::new(Notify::new());
                    self.state
                        .streams
                        .insert(id, StreamState::new(data_tx, window_opened.clone()));

                    let stream = ZtStream::new(
                        self.endpoint.clone(),
                        self.scid.clone(),
                        id,
                        data_rx,
                        window_opened,
                        self.state.closed.clone(),
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
                ack_ranges,
            } => {
                let mut fast_retransmits: Vec<(UnackedPayload, u32)> = Vec::new();
                self.state.handle_ack(
                    largest_acked,
                    window_size,
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
                    if new_window > stream.tx_window {
                        stream.tx_window = new_window;
                        stream.window_opened.notify_waiters();
                    }
                }
            }
            Frame::MaxData { max_data } => {
                let new_window = max_data
                    .saturating_sub(self.state.conn_tx_offset)
                    .min(u32::MAX as u64) as u32;
                if new_window > self.state.remote_window {
                    self.state.remote_window = new_window;
                    for stream in self.state.streams.values() {
                        stream.window_opened.notify_waiters();
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(super) fn forward_stream_data(&mut self, stream_id: u32) -> Result<()> {
        let Some(stream) = self.state.streams.get_mut(&stream_id) else {
            return Ok(());
        };

        let mut forwarded = false;
        while let Some(chunk) = stream.receive_buffer.read_contiguous() {
            stream.buffered_bytes =
                stream.buffered_bytes.saturating_sub(chunk.len());
            if stream.app_tx.try_send(chunk).is_ok() {
                forwarded = true;
            } else {
                break;
            }
        }
        
        stream.expected_rx_offset = stream.receive_buffer.read_head;

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
        Ok(())
    }
}
