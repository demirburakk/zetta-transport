use crate::error::Result;
use bytes::{Bytes, BytesMut, Buf};
use std::sync::Arc;
use std::future::Future;
use tokio::sync::{Notify, mpsc};

/// Internal state machine for managing write backpressure, pacing, and acknowledgement
/// flow in the asynchronous stream writer.
enum WriteState {
    /// No outgoing write operation is currently in progress.
    Idle,
    /// An outgoing packet chunk has been sent to the connection actor, and we are waiting
    /// for the actor to ACK or reject (due to pacing/congestion) the write.
    Sending {
        /// Receiver side of the confirmation channel from the actor.
        resp_rx: tokio::sync::oneshot::Receiver<crate::error::Result<()>>,
        /// Length in bytes of the chunk currently in flight.
        chunk_len: usize,
    },
    /// The transmission was blocked because either the congestion window was full
    /// or the peer's flow control window was exhausted.
    Blocked {
        /// A future that resolves when the window opens again (e.g. via an ACK frame).
        notify_fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
        /// The buffered packet data waiting to be re-sent once the block is lifted.
        chunk: Bytes,
    },
    /// The transmission was blocked by pacing limits (to avoid burstiness).
    Pacing {
        /// A sleep timer future that resolves when the pacing delay expires.
        sleep_fut: std::pin::Pin<Box<tokio::time::Sleep>>,
        /// The buffered packet data waiting to be re-sent once the timer expires.
        chunk: Bytes,
    },
}

/// Represents a reliable, encrypted, and multiplexed data stream over a UDP connection.
/// Behaves similarly to a TCP stream but operates within the ZettaTransport protocol.
pub struct ZtStream {
    pub(crate) stream_id: u32,
    receiver: mpsc::Receiver<Bytes>,
    window_opened: Arc<Notify>,
    /// Shared closed signal. When the connection actor sets this to true,
    /// all pending `window_opened.notified()` calls are unblocked and the
    /// send loop returns `ActorFailed` instead of hanging forever.
    closed: Arc<std::sync::atomic::AtomicBool>,

    // Optimized fields to bypass global routing table DashMap lookups and oneshot channel allocations
    actor_tx: mpsc::Sender<crate::transport::actor::ActorMessage>,
    mtu: Arc<std::sync::atomic::AtomicUsize>,

    // Read buffering
    current_read_chunk: Option<Bytes>,

    // Write buffering and state machine
    write_buffer: BytesMut,
    write_state: WriteState,
}

impl ZtStream {
    pub(crate) fn new(
        stream_id: u32,
        receiver: mpsc::Receiver<Bytes>,
        window_opened: Arc<Notify>,
        closed: Arc<std::sync::atomic::AtomicBool>,
        actor_tx: mpsc::Sender<crate::transport::actor::ActorMessage>,
        mtu: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        Self {
            stream_id,
            receiver,
            window_opened,
            closed,
            actor_tx,
            mtu,
            current_read_chunk: None,
            write_buffer: BytesMut::new(),
            write_state: WriteState::Idle,
        }
    }

    /// Sends a payload reliably to the remote peer.
    ///
    /// Automatically handles backpressure: if the peer's flow-control window
    /// (`FlowControlBlocked`) or the local congestion window
    /// (`CongestionWindowFull`) is exhausted, the call yields until the
    /// respective window opens and then retries the chunk.
    ///
    /// Returns `ActorFailed` if the connection is closed while waiting,
    /// preventing silent deadlocks.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mtu = self.mtu.load(std::sync::atomic::Ordering::Relaxed);
        let chunk_size = mtu.saturating_sub(64).max(512);
        for chunk in data.chunks(chunk_size) {
            loop {
                // Check if the connection has been closed before waiting.
                if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(crate::error::ZtError::ActorFailed);
                }
                
                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                if self.actor_tx.send(crate::transport::actor::ActorMessage::OutgoingData {
                    stream_id: self.stream_id,
                    data: Bytes::copy_from_slice(chunk),
                    respond_to: resp_tx,
                })
                .await
                .is_err()
                {
                    return Err(crate::error::ZtError::ActorFailed);
                }

                match resp_rx.await.unwrap_or(Err(crate::error::ZtError::ActorFailed)) {
                    Ok(_) => break,
                    Err(crate::error::ZtError::FlowControlBlocked)
                    | Err(crate::error::ZtError::CongestionWindowFull) => {
                        // Wait until either the peer opens its window (ACK
                        // received), the congestion window grows, or the
                        // connection is closed.
                        if tokio::time::timeout(
                            std::time::Duration::from_secs(60),
                            self.window_opened.notified(),
                        )
                        .await
                        .is_err()
                        {
                            return Err(crate::error::ZtError::Timeout);
                        }
                    }
                    Err(crate::error::ZtError::PacingBlocked(duration)) => {
                        tokio::time::sleep(duration).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Sends a payload zero-copy by leveraging Bytes references.
    pub async fn send_bytes(&self, mut data: Bytes) -> Result<()> {
        let mtu = self.mtu.load(std::sync::atomic::Ordering::Relaxed);
        let chunk_size = mtu.saturating_sub(64).max(512);
        
        while !data.is_empty() {
            let to_send = if data.len() > chunk_size {
                data.split_to(chunk_size)
            } else {
                std::mem::take(&mut data)
            };
            
            loop {
                if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(crate::error::ZtError::ActorFailed);
                }
                
                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                if self.actor_tx.send(crate::transport::actor::ActorMessage::OutgoingData {
                    stream_id: self.stream_id,
                    data: to_send.clone(),
                    respond_to: resp_tx,
                })
                .await
                .is_err()
                {
                    return Err(crate::error::ZtError::ActorFailed);
                }

                match resp_rx.await.unwrap_or(Err(crate::error::ZtError::ActorFailed)) {
                    Ok(_) => break,
                    Err(crate::error::ZtError::FlowControlBlocked)
                    | Err(crate::error::ZtError::CongestionWindowFull) => {
                        if tokio::time::timeout(
                            std::time::Duration::from_secs(60),
                            self.window_opened.notified(),
                        )
                        .await
                        .is_err()
                        {
                            return Err(crate::error::ZtError::Timeout);
                        }
                    }
                    Err(crate::error::ZtError::PacingBlocked(duration)) => {
                        tokio::time::sleep(duration).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Option<Bytes> {
        if let Some(chunk) = self.current_read_chunk.take()
            && chunk.remaining() > 0 {
                let _ = self.actor_tx.send(crate::transport::actor::ActorMessage::StreamDataRead {
                    stream_id: self.stream_id,
                }).await;
                return Some(chunk);
            }
        let chunk = self.receiver.recv().await?;
        let _ = self.actor_tx.send(crate::transport::actor::ActorMessage::StreamDataRead {
            stream_id: self.stream_id,
        }).await;
        Some(chunk)
    }

    /// Gracefully closes the stream.
    pub async fn close(&self) -> Result<()> {
        let _ = self.actor_tx.send(crate::transport::actor::ActorMessage::CloseStream {
            stream_id: self.stream_id,
        }).await;
        Ok(())
    }
}

impl Drop for ZtStream {
    fn drop(&mut self) {
        let _ = self.actor_tx.try_send(crate::transport::actor::ActorMessage::CloseStream {
            stream_id: self.stream_id,
        });
    }
}

impl tokio::io::AsyncRead for ZtStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        loop {
            // 1. If we have a buffered read chunk from a previous socket read, consume from it.
            if let Some(ref mut chunk) = self.current_read_chunk {
                if chunk.remaining() > 0 {
                    let amt = std::cmp::min(chunk.remaining(), buf.remaining());
                    let slice = chunk.split_to(amt);
                    buf.put_slice(&slice);
                    return std::task::Poll::Ready(Ok(()));
                } else {
                    // Chunk is fully consumed, clear it.
                    self.current_read_chunk = None;
                }
            }

            // 2. No buffered data available. Poll the incoming packet receiver channel.
            match self.receiver.poll_recv(cx) {
                std::task::Poll::Ready(Some(bytes)) => {
                    // Cache the received chunk and retry the loop to copy it into the caller's buffer.
                    self.current_read_chunk = Some(bytes);
                }
                std::task::Poll::Ready(None) => {
                    // The channel was closed by the actor, signaling EOF.
                    return std::task::Poll::Ready(Ok(()));
                }
                std::task::Poll::Pending => {
                    // No data available yet; the caller's waker has been registered by poll_recv.
                    return std::task::Poll::Pending;
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for ZtStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        // Guard: check if connection closed.
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Connection closed",
            )));
        }

        let this = self.as_mut().get_mut();
        loop {
            match &mut this.write_state {
                // Idle means we can accept a new write payload from the user.
                WriteState::Idle => break,
                
                // A packet was already dispatched to the actor; we wait on the oneshot confirmation.
                WriteState::Sending { resp_rx, chunk_len } => {
                    let chunk_len = *chunk_len;
                    match std::pin::Pin::new(resp_rx).poll(cx) {
                        // The packet was successfully transmitted and acked/pushed.
                        std::task::Poll::Ready(Ok(Ok(()))) => {
                            this.write_state = WriteState::Idle;
                        }
                        // Flow/Congestion blocked: transition to Blocked and wait for the window to open.
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::FlowControlBlocked)))
                        | std::task::Poll::Ready(Ok(Err(crate::error::ZtError::CongestionWindowFull))) => {
                            let chunk = Bytes::copy_from_slice(&this.write_buffer[..chunk_len]);
                            this.write_buffer.advance(chunk_len);
                            let notify = this.window_opened.clone();
                            this.write_state = WriteState::Blocked {
                                notify_fut: Box::pin(async move { notify.notified().await }),
                                chunk,
                            };
                        }
                        // Pacing blocked: transition to Pacing and wait for the timer to elapse.
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::PacingBlocked(dur)))) => {
                            let chunk = Bytes::copy_from_slice(&this.write_buffer[..chunk_len]);
                            this.write_buffer.advance(chunk_len);
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(dur)),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(e))) => {
                            return std::task::Poll::Ready(Err(std::io::Error::other(
                                format!("Write failed: {:?}", e),
                             )));
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Oneshot channel closed",
                            )));
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
                // We are flow-control or congestion blocked. Poll the window open waker.
                WriteState::Blocked { notify_fut, chunk } => {
                    match notify_fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(()) => {
                            // Window has opened; attempt to re-transmit the same chunk.
                            let chunk = chunk.clone();
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            if this.actor_tx.try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            }).is_err() {
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionAborted,
                                    "Actor failed",
                                )));
                            }
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk_len: chunk.len(),
                            };
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
                // We are pacing-blocked. Poll the pacing sleep future.
                WriteState::Pacing { sleep_fut, chunk } => {
                    match sleep_fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(()) => {
                            // Pacing duration elapsed; attempt to re-transmit the same chunk.
                            let chunk = chunk.clone();
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            if this.actor_tx.try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            }).is_err() {
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionAborted,
                                    "Actor failed",
                                )));
                            }
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk_len: chunk.len(),
                            };
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
            }
        }

        // --- At this point, the state machine is Idle and ready to buffer new data ---
        
        let mtu = this.mtu.load(std::sync::atomic::Ordering::Relaxed);
        // Reserve 64 bytes for headers (e.g. packet number, connection ID, stream header, crypto tag).
        let chunk_size = mtu.saturating_sub(64).max(512);

        // Append the user's data to our local write buffer.
        this.write_buffer.extend_from_slice(buf);
        let written = buf.len();

        // If we accumulated enough bytes to form a full packet segment, dispatch it.
        if this.write_buffer.len() >= chunk_size {
            let chunk_data = this.write_buffer.clone().split_to(chunk_size).freeze();
            match this.actor_tx.try_reserve() {
                Ok(permit) => {
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    permit.send(crate::transport::actor::ActorMessage::OutgoingData {
                        stream_id: this.stream_id,
                        data: chunk_data,
                        respond_to: resp_tx,
                    });
                    this.write_state = WriteState::Sending {
                        resp_rx,
                        chunk_len: chunk_size,
                    };
                }
                Err(_) => {
                    // Actor queue is full; yield and ask caller to retry later.
                    return std::task::Poll::Pending;
                }
            }
        }

        // Return progress to the caller, even if we just buffered the bytes.
        std::task::Poll::Ready(Ok(written))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        loop {
            match &mut this.write_state {
                WriteState::Idle => {
                    if this.write_buffer.is_empty() {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    let chunk_len = this.write_buffer.len();
                    let chunk_data = this.write_buffer.clone().freeze();
                    match this.actor_tx.try_reserve() {
                        Ok(permit) => {
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            permit.send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk_data,
                                respond_to: resp_tx,
                            });
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk_len,
                            };
                        }
                        Err(_) => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Sending { resp_rx, chunk_len } => {
                    let chunk_len = *chunk_len;
                    match std::pin::Pin::new(resp_rx).poll(cx) {
                        std::task::Poll::Ready(Ok(Ok(()))) => {
                            this.write_buffer.advance(chunk_len);
                            this.write_state = WriteState::Idle;
                        }
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::FlowControlBlocked)))
                        | std::task::Poll::Ready(Ok(Err(crate::error::ZtError::CongestionWindowFull))) => {
                            let chunk = Bytes::copy_from_slice(&this.write_buffer[..chunk_len]);
                            this.write_buffer.advance(chunk_len);
                            let notify = this.window_opened.clone();
                            this.write_state = WriteState::Blocked {
                                notify_fut: Box::pin(async move { notify.notified().await }),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::PacingBlocked(dur)))) => {
                            let chunk = Bytes::copy_from_slice(&this.write_buffer[..chunk_len]);
                            this.write_buffer.advance(chunk_len);
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(dur)),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(e))) => {
                            return std::task::Poll::Ready(Err(std::io::Error::other(
                                format!("Flush failed: {:?}", e),
                            )));
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Oneshot channel closed",
                            )));
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Blocked { notify_fut, chunk } => {
                    match notify_fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(()) => {
                            let chunk = chunk.clone();
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            if this.actor_tx.try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            }).is_err() {
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionAborted,
                                    "Actor failed",
                                )));
                            }
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk_len: chunk.len(),
                            };
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Pacing { sleep_fut, chunk } => {
                    match sleep_fut.as_mut().poll(cx) {
                        std::task::Poll::Ready(()) => {
                            let chunk = chunk.clone();
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            if this.actor_tx.try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            }).is_err() {
                                return std::task::Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::ConnectionAborted,
                                    "Actor failed",
                                )));
                            }
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk_len: chunk.len(),
                            };
                        }
                        std::task::Poll::Pending => {
                            return std::task::Poll::Pending;
                        }
                    }
                }
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.as_mut().poll_flush(cx)?.is_pending() {
            return std::task::Poll::Pending;
        }

        let this = self.as_mut().get_mut();
        if this.actor_tx.try_send(crate::transport::actor::ActorMessage::CloseStream {
            stream_id: this.stream_id,
        }).is_err() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "Actor failed to close stream",
            )));
        }

        std::task::Poll::Ready(Ok(()))
    }
}
