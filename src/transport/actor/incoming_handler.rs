use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::stream::ZtStream;
use crate::transport::connection::ZtConnection;
use crate::transport::stream_state::{ConnectionState, StreamState};
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
            let is_retry = ((mutable_data[0] >> 2) & 0x0F) == 0x07;
            if !is_retry {
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

        let highest = self.state.replay_window.highest_processed.unwrap_or(0);
        header.packet_number =
            crate::protocol::packet_number::expand_pn(header.packet_number, header.pn_len, highest);

        if self.state.is_replay(header.packet_number) {
            return Ok(());
        }
        let use_prev_key;
        let mut rotated_this_packet = false;

        if is_short_header && header.key_phase != expected_kp {
            if header.packet_number >= highest {
                if let Some(crypto) = self.state.crypto.as_mut() {
                    crypto.rotate_keys();
                    self.state.current_key_epoch += 1;
                }
                use_prev_key = false;
                rotated_this_packet = true;
            } else {
                use_prev_key = true;
            }
        } else {
            use_prev_key = false;
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
                let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
                if payload_buf.len() < 16 {
                    return Ok(());
                }
                let tag_idx = payload_buf.len() - 16;
                let tag_bytes = payload_buf.split_off(tag_idx);
                let tag: [u8; 16] = tag_bytes.as_ref().try_into().unwrap();

                if let Err(e) = crypto.decrypt_in_place(
                    header.packet_number,
                    &aad,
                    &mut payload_buf,
                    &tag,
                    use_prev_key,
                ) {
                    if rotated_this_packet {
                        tracing::debug!(
                            "Key rotation triggered by pn={} but decryption failed; \
                             rotation will be re-applied when a valid packet arrives",
                            header.packet_number
                        );
                    }
                    return Err(e);
                }

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
                    );
                    let _ = self.incoming_streams_tx.try_send(stream);
                }

                let stream = self.state.streams.get_mut(&id).unwrap();
                if offset < stream.expected_rx_offset {
                    self.pending_acks += 1;
                    return Ok(());
                }

                if !data.is_empty() {
                    let window_size = stream.window_size;

                    if stream.buffered_bytes + data.len() > window_size as usize {
                        tracing::warn!(
                            "Stream {} buffered data exceeds window ({} bytes), dropping",
                            id,
                            window_size
                        );
                        self.pending_acks += 1;
                        return Ok(());
                    }

                    stream.chunks.insert(offset, data.clone());
                    stream.buffered_bytes += data.len();
                }

                loop {
                    let expected = stream.expected_rx_offset;
                    let maybe_chunk = stream
                        .chunks
                        .range(..=expected)
                        .next_back()
                        .map(|(&k, v)| (k, v.clone()));

                    if let Some((start_offset, chunk)) = maybe_chunk {
                        let end_offset = start_offset + chunk.len() as u64;
                        if end_offset > expected {
                            let data_to_send = if start_offset == expected {
                                chunk
                            } else {
                                chunk.slice((expected - start_offset) as usize..)
                            };

                            if stream.app_tx.try_send(data_to_send).is_ok() {
                                let sent_len = end_offset - expected;
                                stream.expected_rx_offset = end_offset;
                                stream.buffered_bytes =
                                    stream.buffered_bytes.saturating_sub(sent_len as usize);

                                let to_remove: Vec<_> = stream
                                    .chunks
                                    .range(..=stream.expected_rx_offset)
                                    .filter(|(k, v)| {
                                        **k + v.len() as u64 <= stream.expected_rx_offset
                                    })
                                    .map(|(&k, _)| k)
                                    .collect();
                                for k in to_remove {
                                    stream.chunks.remove(&k);
                                }
                            } else {
                                break;
                            }
                        } else {
                            stream.chunks.remove(&start_offset);
                        }
                    } else {
                        break;
                    }
                }
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
                let mut fast_retransmits = Vec::new();
                self.state.handle_ack(
                    largest_acked,
                    window_size,
                    &ack_ranges,
                    &mut fast_retransmits,
                );

                // Re-send the fast retransmits
                for payload in fast_retransmits {
                    if let Err(e) = self.retransmit_payload(payload) {
                        tracing::warn!("Fast retransmit failed: {}", e);
                    }
                }
            }
            Frame::ConnectionClose => {
                self.state.state = ConnectionState::Closed;
            }
            Frame::StreamClose { id } => {
                self.state.streams.remove(&id);
            }
            _ => {}
        }
        Ok(())
    }
}
