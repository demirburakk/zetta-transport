use crate::crypto::CryptoContext;
use crate::error::Result;
use crate::fec::FecEngine;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::transport::state::{ConnectionState, ZtConnection};
use crate::transport::endpoint::{ReceivedData, ZtEndpoint};
use bytes::{Buf, Bytes, BytesMut};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use x25519_dalek::PublicKey;

pub(crate) async fn process_packet(
    endpoint: &ZtEndpoint,
    data: &[u8],
    addr: SocketAddr,
) -> Result<()> {
    if endpoint.chaos_mode.load(Ordering::Relaxed) && rand::thread_rng().r#gen_ratio(2, 10) {
        return Ok(()); // Chaos mode: drop 20% of packets
    }

    let mut bytes = Bytes::copy_from_slice(data);
    let initial_len = bytes.remaining();
    let header = PacketHeader::decode(&mut bytes)?;
    let header_len = initial_len - bytes.remaining();
    let header_bytes = &data[..header_len];
    let payload = bytes;

    let mut conn_to_update = None;
    let mut handshake_response = None;
    let mut retry_response = None;

    {
        let conns = &endpoint.connections;
        if let Some(mut conn) = conns.get_mut(&header.dcid) {
            conn.update_activity();

            if !conn.is_replay(header.packet_number) {
                match header.p_type {
                    PacketType::Data if conn.state == ConnectionState::Active => {
                        if let Some(ref crypto) = conn.crypto {
                            let decoded =
                                crypto.decrypt(header.packet_number, &payload, header_bytes)?;
                            conn.addr = addr;
                            conn.mark_processed(header.packet_number);

                            conn.received_shards
                                .insert(header.packet_number, payload.clone());
                            if conn.received_shards.len() > 4
                                && let Some(min_pn) = conn.received_shards.keys().cloned().min()
                            {
                                conn.received_shards.remove(&min_pn);
                            }

                            conn_to_update =
                                Some((header.dcid.clone(), header.packet_number, decoded));
                        }
                    }
                    PacketType::Ack if conn.state == ConnectionState::Active => {
                        if let Some(ref crypto) = conn.crypto {
                            if crypto
                                .decrypt(header.packet_number, &payload, header_bytes)
                                .is_ok()
                            {
                                conn.addr = addr;
                                conn.handle_ack(header.packet_number, header.window_size);
                            }
                        }
                    }
                    PacketType::Fec if conn.state == ConnectionState::Active => {
                        let decrypted_fec = if let Some(ref crypto) = conn.crypto {
                            crypto.decrypt(header.packet_number, &payload, header_bytes).ok()
                        } else {
                            None
                        };

                        if let Some(decrypted_fec) = decrypted_fec {
                            conn.addr = addr;
                            conn.mark_processed(header.packet_number);

                            let expected_pns = [
                                header.packet_number.saturating_sub(4),
                                header.packet_number.saturating_sub(3),
                                header.packet_number.saturating_sub(2),
                                header.packet_number.saturating_sub(1),
                            ];

                            let mut missing_pn = None;
                            let mut shards_for_recovery = Vec::new();
                            for expected in &expected_pns {
                                if let Some(shard) = conn.received_shards.get(expected) {
                                    shards_for_recovery.push(shard.clone());
                                } else {
                                    missing_pn = Some(*expected);
                                }
                            }

                            if shards_for_recovery.len() == 3
                                && let Some(missing) = missing_pn
                                && !conn.is_replay(missing)
                            {
                                let recovered_ciphertext = FecEngine::recover(
                                    &shards_for_recovery,
                                    &bytes::Bytes::from(decrypted_fec),
                                );

                                let missing_header = PacketHeader {
                                    p_type: PacketType::Data,
                                    is_long: false,
                                    version: 0,
                                    dcid: header.dcid.clone(),
                                    scid: vec![],
                                    packet_number: missing,
                                    window_size: 0,
                                    stream_id: 0,
                                    offset: 0,
                                };
                                let mut buf = bytes::BytesMut::with_capacity(64);
                                missing_header.encode(&mut buf);
                                let reconstructed_aad = buf.freeze();

                                let dec_res = if let Some(ref crypto) = conn.crypto {
                                    crypto.decrypt(
                                        missing,
                                        &recovered_ciphertext,
                                        &reconstructed_aad,
                                    ).ok()
                                } else { None };

                                if let Some(dec) = dec_res {
                                    conn.mark_processed(missing);
                                    conn_to_update = Some((header.dcid.clone(), missing, dec));
                                }
                            }
                            conn.received_shards.clear();
                        }
                    }
                    PacketType::Handshake
                        if payload.len() >= 32
                            && conn.state == ConnectionState::Handshaking =>
                    {
                        let mut pk_bytes = [0u8; 32];
                        pk_bytes.copy_from_slice(&payload[..32]);
                        let shared = CryptoContext::compute_shared_secret(
                            endpoint.static_secret.clone(),
                            PublicKey::from(pk_bytes),
                        );
                        conn.dcid = header.scid.clone();
                        conn.crypto = Some(CryptoContext::from_shared_secret(
                            shared, &conn.scid, &conn.dcid, endpoint.psk,
                        ));
                        conn.addr = addr;
                        conn.state = ConnectionState::Active;
                        handshake_response = Some((header.dcid.clone(), header.packet_number));
                    }
                    PacketType::Retry if payload.len() == 32 && conn.state == ConnectionState::Handshaking => {
                        let pn = conn.get_next_packet_number().unwrap_or(0);
                        let initial_header = PacketHeader {
                            p_type: PacketType::Initial,
                            is_long: true,
                            version: 1,
                            dcid: vec![0; 8],
                            scid: conn.scid.clone(),
                            packet_number: pn,
                            window_size: conn.local_window,
                            stream_id: 0,
                            offset: 0,
                        };
                        let mut buf = bytes::BytesMut::with_capacity(128);
                        initial_header.encode(&mut buf);
                        buf.extend_from_slice(endpoint.public_key.as_bytes());
                        buf.extend_from_slice(&payload[..32]);
                        retry_response = Some((conn.addr, buf.freeze()));
                    }
                    PacketType::Close => {
                        if let Some(ref crypto) = conn.crypto
                            && crypto
                                .decrypt(header.packet_number, &payload, header_bytes)
                                .is_ok()
                        {
                            conn.addr = addr;
                            conn.mark_processed(header.packet_number);
                            conn.state = ConnectionState::Closed;
                        }
                    }
                    PacketType::MtuProbe if conn.state == ConnectionState::Active => {
                        if let Some(ref crypto) = conn.crypto {
                            if crypto
                                .decrypt(header.packet_number, &payload, header_bytes)
                                .is_ok()
                            {
                                conn.addr = addr;
                                conn.mark_processed(header.packet_number);
                                // Trigger an immediate Ack response
                                conn_to_update =
                                    Some((header.dcid.clone(), header.packet_number, vec![]));
                            }
                        }
                    }
                    _ => {}
                }
            }
        } else if header.is_long && header.p_type == PacketType::Initial && payload.len() >= 32 {
            let mut pk_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(&payload[..32]);

            let mut hasher = Sha256::new();
            hasher.update(&endpoint.static_secret.to_bytes());
            hasher.update(&addr.to_string().as_bytes());
            hasher.update(&header.scid);
            let expected_cookie = hasher.finalize();

            if payload.len() >= 64 && payload[32..64] == expected_cookie[..] {
                let shared = CryptoContext::compute_shared_secret(
                    endpoint.static_secret.clone(),
                    PublicKey::from(pk_bytes),
                );
                let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();

                let mut new_conn = ZtConnection::new(addr, scid.clone(), header.scid);
                new_conn.crypto = Some(CryptoContext::from_shared_secret(
                    shared,
                    &new_conn.scid,
                    &new_conn.dcid,
                    endpoint.psk,
                ));
                new_conn.state = ConnectionState::Active;
                conns.insert(scid.clone(), new_conn);

                handshake_response = Some((scid, header.packet_number));
            } else {
                let retry_header = PacketHeader {
                    p_type: PacketType::Retry,
                    is_long: true,
                    version: 1,
                    dcid: header.scid.clone(),
                    scid: vec![],
                    packet_number: header.packet_number,
                    window_size: 0,
                    stream_id: 0,
                    offset: 0,
                };
                let mut buf = BytesMut::with_capacity(128);
                retry_header.encode(&mut buf);
                buf.extend_from_slice(&expected_cookie);
                retry_response = Some((addr, buf.freeze()));
            }
        }
    }

    if let Some((addr, packet)) = retry_response {
        let _ = endpoint.socket.send_to(&packet, addr).await;
    }

    if let Some((cid, pn, decoded)) = conn_to_update {
        if !decoded.is_empty() {
            let _ = endpoint
                .app_tx
                .send(ReceivedData {
                    cid: cid.clone(),
                    data: Bytes::from(decoded),
                })
                .await;
        }
        endpoint.send_ack_internal(&cid, pn).await?;
    }

    if let Some((cid, pn)) = handshake_response {
        endpoint.send_handshake_internal(&cid).await?;
        endpoint.send_ack_internal(&cid, pn).await?;
    }

    Ok(())
}
