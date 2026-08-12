use crate::error::Result;
use crate::transport::state::StreamType;
use bytes::{Buf, Bytes, BytesMut};
use std::future::Future;
use std::sync::Arc;
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
        /// The chunk currently in flight.
        chunk: Bytes,
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
///
/// `ZtStream` operates very similarly to a `TcpStream` but with the distinct advantage of being
/// multiplexed. You can open hundreds of independent `ZtStream` instances on a single
/// `ZtConnectionHandle` without suffering from Head-of-Line (HoL) blocking.
///
/// **Async I/O Integration:**
/// `ZtStream` natively implements `tokio::io::AsyncRead` and `tokio::io::AsyncWrite`. This allows
/// you to use it seamlessly with standard Tokio utilities like `tokio::io::copy`, `read_to_end`,
/// or `write_all`.
///
/// **Zero-Copy Transmissions:**
/// For maximum throughput, use the custom `send_bytes` method. By passing a `bytes::Bytes` buffer,
/// the stream will chunk and transmit the data directly at the MTU boundary without allocating
/// intermediate buffers or copying the payload memory.
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
    pending_read_credit: usize,

    // Write buffering and state machine
    write_buffer: BytesMut,
    write_state: WriteState,
    pub(crate) stream_type: StreamType,
    operation_timeout: std::time::Duration,
    termination: Arc<crate::stream::termination::Termination>,
}

impl ZtStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stream_id: u32,
        receiver: mpsc::Receiver<Bytes>,
        window_opened: Arc<Notify>,
        closed: Arc<std::sync::atomic::AtomicBool>,
        actor_tx: mpsc::Sender<crate::transport::actor::ActorMessage>,
        mtu: Arc<std::sync::atomic::AtomicUsize>,
        stream_type: StreamType,
        operation_timeout: std::time::Duration,
        termination: Arc<crate::stream::termination::Termination>,
    ) -> Self {
        Self {
            stream_id,
            receiver,
            window_opened,
            closed,
            actor_tx,
            mtu,
            current_read_chunk: None,
            pending_read_credit: 0,
            write_buffer: BytesMut::new(),
            write_state: WriteState::Idle,
            stream_type,
            operation_timeout,
            termination,
        }
    }

    /// Returns whether this endpoint may read, write, or do both on the stream.
    pub fn stream_type(&self) -> StreamType {
        self.stream_type
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
        if self.stream_type == StreamType::UnidirectionalIn {
            return Err(crate::error::ZtError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot write to a unidirectional incoming stream",
            )));
        }
        let mtu = self.mtu.load(std::sync::atomic::Ordering::Relaxed);
        let chunk_size = mtu.saturating_sub(64).max(512);
        for chunk in data.chunks(chunk_size) {
            loop {
                // Check if the connection has been closed before waiting.
                if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(self
                        .termination
                        .error()
                        .unwrap_or(crate::error::ZtError::ActorFailed));
                }

                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                if self
                    .actor_tx
                    .send(crate::transport::actor::ActorMessage::OutgoingData {
                        stream_id: self.stream_id,
                        data: Bytes::copy_from_slice(chunk),
                        respond_to: resp_tx,
                    })
                    .await
                    .is_err()
                {
                    return Err(crate::error::ZtError::ActorFailed);
                }

                match resp_rx
                    .await
                    .unwrap_or(Err(crate::error::ZtError::ActorFailed))
                {
                    Ok(_) => break,
                    Err(crate::error::ZtError::FlowControlBlocked)
                    | Err(crate::error::ZtError::CongestionWindowFull) => {
                        // Wait until either the peer opens its window (ACK
                        // received), the congestion window grows, or the
                        // connection is closed.
                        if tokio::time::timeout(
                            self.operation_timeout,
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
        if self.stream_type == StreamType::UnidirectionalIn {
            return Err(crate::error::ZtError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot write to a unidirectional incoming stream",
            )));
        }
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
                    return Err(self
                        .termination
                        .error()
                        .unwrap_or(crate::error::ZtError::ActorFailed));
                }

                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                if self
                    .actor_tx
                    .send(crate::transport::actor::ActorMessage::OutgoingData {
                        stream_id: self.stream_id,
                        data: to_send.clone(),
                        respond_to: resp_tx,
                    })
                    .await
                    .is_err()
                {
                    return Err(crate::error::ZtError::ActorFailed);
                }

                match resp_rx
                    .await
                    .unwrap_or(Err(crate::error::ZtError::ActorFailed))
                {
                    Ok(_) => break,
                    Err(crate::error::ZtError::FlowControlBlocked)
                    | Err(crate::error::ZtError::CongestionWindowFull) => {
                        if tokio::time::timeout(
                            self.operation_timeout,
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

    /// Receives the next chunk and preserves peer reset/close reasons.
    pub async fn recv_result(&mut self) -> Result<Option<Bytes>> {
        if self.stream_type == StreamType::UnidirectionalOut {
            return Ok(None);
        }
        if let Some(chunk) = self.current_read_chunk.take()
            && chunk.remaining() > 0
        {
            let bytes_read = chunk.len();
            let _ = self
                .actor_tx
                .send(crate::transport::actor::ActorMessage::StreamDataRead {
                    stream_id: self.stream_id,
                    bytes_read,
                })
                .await;
            return Ok(Some(chunk));
        }
        let Some(chunk) = self.receiver.recv().await else {
            return self.termination.error().map_or(Ok(None), Err);
        };
        let bytes_read = chunk.len();
        let _ = self
            .actor_tx
            .send(crate::transport::actor::ActorMessage::StreamDataRead {
                stream_id: self.stream_id,
                bytes_read,
            })
            .await;
        Ok(Some(chunk))
    }

    /// Receives the next chunk, returning `None` for EOF or peer termination.
    /// Use [`Self::recv_result`] when the peer's reset/close reason is needed.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.recv_result().await.ok().flatten()
    }

    /// Gracefully closes the stream.
    pub async fn close(&self) -> Result<()> {
        let _ = self
            .actor_tx
            .send(crate::transport::actor::ActorMessage::CloseStream {
                stream_id: self.stream_id,
            })
            .await;
        Ok(())
    }

    /// Abruptly terminates the stream and delivers `error_code` to the peer.
    pub async fn reset(&self, error_code: u64) -> Result<()> {
        self.actor_tx
            .send(crate::transport::actor::ActorMessage::ResetStream {
                stream_id: self.stream_id,
                error_code,
            })
            .await
            .map_err(|_| crate::error::ZtError::ActorFailed)
    }
}

impl Drop for ZtStream {
    fn drop(&mut self) {
        let _ = self
            .actor_tx
            .try_send(crate::transport::actor::ActorMessage::CloseStream {
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
        if self.stream_type == StreamType::UnidirectionalOut {
            return std::task::Poll::Ready(Ok(()));
        }
        if self.pending_read_credit > 0 {
            let bytes_read = self.pending_read_credit;
            if self
                .actor_tx
                .try_send(crate::transport::actor::ActorMessage::StreamDataRead {
                    stream_id: self.stream_id,
                    bytes_read,
                })
                .is_ok()
            {
                self.pending_read_credit = 0;
            }
        }
        loop {
            // 1. If we have a buffered read chunk from a previous socket read, consume from it.
            if let Some(ref mut chunk) = self.current_read_chunk {
                if chunk.remaining() > 0 {
                    let amt = std::cmp::min(chunk.remaining(), buf.remaining());
                    let slice = chunk.split_to(amt);
                    buf.put_slice(&slice);
                    self.pending_read_credit = self.pending_read_credit.saturating_add(amt);
                    let bytes_read = self.pending_read_credit;
                    if self
                        .actor_tx
                        .try_send(crate::transport::actor::ActorMessage::StreamDataRead {
                            stream_id: self.stream_id,
                            bytes_read,
                        })
                        .is_ok()
                    {
                        self.pending_read_credit = 0;
                    }
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
                    return self
                        .termination
                        .io_error()
                        .map_or(std::task::Poll::Ready(Ok(())), |error| {
                            std::task::Poll::Ready(Err(error))
                        });
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
        if self.stream_type == StreamType::UnidirectionalIn {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot write to a unidirectional incoming stream",
            )));
        }
        // Guard: check if connection closed.
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return std::task::Poll::Ready(Err(self.termination.io_error().unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "Connection closed")
            })));
        }

        let this = self.as_mut().get_mut();
        loop {
            let state = std::mem::replace(&mut this.write_state, WriteState::Idle);
            match state {
                WriteState::Idle => {
                    this.write_state = WriteState::Idle;
                    break;
                }
                WriteState::Sending { mut resp_rx, chunk } => {
                    match std::pin::Pin::new(&mut resp_rx).poll(cx) {
                        std::task::Poll::Ready(Ok(Ok(()))) => {
                            // Successfully sent chunk, state remains Idle
                        }
                        std::task::Poll::Ready(Ok(Err(
                            crate::error::ZtError::FlowControlBlocked,
                        )))
                        | std::task::Poll::Ready(Ok(Err(
                            crate::error::ZtError::CongestionWindowFull,
                        ))) => {
                            let notify = this.window_opened.clone();
                            this.write_state = WriteState::Blocked {
                                notify_fut: Box::pin(async move { notify.notified().await }),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::PacingBlocked(
                            dur,
                        )))) => {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(dur)),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(e))) => {
                            return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                                "Write failed: {:?}",
                                e
                            ))));
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Oneshot channel closed",
                            )));
                        }
                        std::task::Poll::Pending => {
                            this.write_state = WriteState::Sending { resp_rx, chunk };
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Blocked {
                    mut notify_fut,
                    chunk,
                } => match notify_fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(()) => {
                        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                        if this
                            .actor_tx
                            .try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            })
                            .is_err()
                        {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(1),
                                )),
                                chunk,
                            };
                            return std::task::Poll::Pending;
                        }
                        this.write_state = WriteState::Sending { resp_rx, chunk };
                    }
                    std::task::Poll::Pending => {
                        this.write_state = WriteState::Blocked { notify_fut, chunk };
                        return std::task::Poll::Pending;
                    }
                },
                WriteState::Pacing {
                    mut sleep_fut,
                    chunk,
                } => match sleep_fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(()) => {
                        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                        if this
                            .actor_tx
                            .try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            })
                            .is_err()
                        {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(1),
                                )),
                                chunk,
                            };
                            return std::task::Poll::Pending;
                        }
                        this.write_state = WriteState::Sending { resp_rx, chunk };
                    }
                    std::task::Poll::Pending => {
                        this.write_state = WriteState::Pacing { sleep_fut, chunk };
                        return std::task::Poll::Pending;
                    }
                },
            }
        }

        // --- At this point, the state machine is Idle and ready to buffer new data ---

        let mtu = this.mtu.load(std::sync::atomic::Ordering::Relaxed);
        let chunk_size = mtu.saturating_sub(64).max(512);

        // A previous call may have filled the bounded staging buffer while the
        // actor channel was busy. Dispatch it before accepting the caller's
        // bytes again; returning Pending must never consume or duplicate `buf`.
        if this.write_buffer.len() >= chunk_size {
            match this.actor_tx.try_reserve() {
                Ok(permit) => {
                    let chunk_data = this.write_buffer.split_to(chunk_size).freeze();
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    permit.send(crate::transport::actor::ActorMessage::OutgoingData {
                        stream_id: this.stream_id,
                        data: chunk_data.clone(),
                        respond_to: resp_tx,
                    });
                    this.write_state = WriteState::Sending {
                        resp_rx,
                        chunk: chunk_data,
                    };
                }
                Err(_) => {
                    cx.waker().wake_by_ref();
                    return std::task::Poll::Pending;
                }
            }
        }

        let available = chunk_size.saturating_sub(this.write_buffer.len());
        let written = available.min(buf.len());
        this.write_buffer.extend_from_slice(&buf[..written]);

        if this.write_buffer.len() >= chunk_size
            && let Ok(permit) = this.actor_tx.try_reserve()
        {
            let chunk_data = this.write_buffer.split_to(chunk_size).freeze();
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            permit.send(crate::transport::actor::ActorMessage::OutgoingData {
                stream_id: this.stream_id,
                data: chunk_data.clone(),
                respond_to: resp_tx,
            });
            this.write_state = WriteState::Sending {
                resp_rx,
                chunk: chunk_data,
            };
        }

        std::task::Poll::Ready(Ok(written))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.stream_type == StreamType::UnidirectionalIn {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot write/flush on a unidirectional incoming stream",
            )));
        }
        let this = self.as_mut().get_mut();
        loop {
            let state = std::mem::replace(&mut this.write_state, WriteState::Idle);
            match state {
                WriteState::Idle => {
                    if this.write_buffer.is_empty() {
                        this.write_state = WriteState::Idle;
                        return std::task::Poll::Ready(Ok(()));
                    }
                    match this.actor_tx.try_reserve() {
                        Ok(permit) => {
                            let chunk_data = this.write_buffer.split().freeze();
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                            permit.send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk_data.clone(),
                                respond_to: resp_tx,
                            });
                            this.write_state = WriteState::Sending {
                                resp_rx,
                                chunk: chunk_data,
                            };
                        }
                        Err(_) => {
                            this.write_state = WriteState::Idle;
                            cx.waker().wake_by_ref();
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Sending { mut resp_rx, chunk } => {
                    match std::pin::Pin::new(&mut resp_rx).poll(cx) {
                        std::task::Poll::Ready(Ok(Ok(()))) => {
                            // Successfully sent chunk, state remains Idle
                        }
                        std::task::Poll::Ready(Ok(Err(
                            crate::error::ZtError::FlowControlBlocked,
                        )))
                        | std::task::Poll::Ready(Ok(Err(
                            crate::error::ZtError::CongestionWindowFull,
                        ))) => {
                            let notify = this.window_opened.clone();
                            this.write_state = WriteState::Blocked {
                                notify_fut: Box::pin(async move { notify.notified().await }),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(crate::error::ZtError::PacingBlocked(
                            dur,
                        )))) => {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(dur)),
                                chunk,
                            };
                        }
                        std::task::Poll::Ready(Ok(Err(e))) => {
                            return std::task::Poll::Ready(Err(std::io::Error::other(format!(
                                "Flush failed: {:?}",
                                e
                            ))));
                        }
                        std::task::Poll::Ready(Err(_)) => {
                            return std::task::Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionAborted,
                                "Oneshot channel closed",
                            )));
                        }
                        std::task::Poll::Pending => {
                            this.write_state = WriteState::Sending { resp_rx, chunk };
                            return std::task::Poll::Pending;
                        }
                    }
                }
                WriteState::Blocked {
                    mut notify_fut,
                    chunk,
                } => match notify_fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(()) => {
                        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                        if this
                            .actor_tx
                            .try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            })
                            .is_err()
                        {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(1),
                                )),
                                chunk,
                            };
                            return std::task::Poll::Pending;
                        }
                        this.write_state = WriteState::Sending { resp_rx, chunk };
                    }
                    std::task::Poll::Pending => {
                        this.write_state = WriteState::Blocked { notify_fut, chunk };
                        return std::task::Poll::Pending;
                    }
                },
                WriteState::Pacing {
                    mut sleep_fut,
                    chunk,
                } => match sleep_fut.as_mut().poll(cx) {
                    std::task::Poll::Ready(()) => {
                        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                        if this
                            .actor_tx
                            .try_send(crate::transport::actor::ActorMessage::OutgoingData {
                                stream_id: this.stream_id,
                                data: chunk.clone(),
                                respond_to: resp_tx,
                            })
                            .is_err()
                        {
                            this.write_state = WriteState::Pacing {
                                sleep_fut: Box::pin(tokio::time::sleep(
                                    std::time::Duration::from_millis(1),
                                )),
                                chunk,
                            };
                            return std::task::Poll::Pending;
                        }
                        this.write_state = WriteState::Sending { resp_rx, chunk };
                    }
                    std::task::Poll::Pending => {
                        this.write_state = WriteState::Pacing { sleep_fut, chunk };
                        return std::task::Poll::Pending;
                    }
                },
            }
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.stream_type == StreamType::UnidirectionalIn {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Cannot shutdown/write on a unidirectional incoming stream",
            )));
        }
        if self.as_mut().poll_flush(cx)?.is_pending() {
            return std::task::Poll::Pending;
        }

        let this = self.as_mut().get_mut();
        if this
            .actor_tx
            .try_send(crate::transport::actor::ActorMessage::CloseStream {
                stream_id: this.stream_id,
            })
            .is_err()
        {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }

        std::task::Poll::Ready(Ok(()))
    }
}
