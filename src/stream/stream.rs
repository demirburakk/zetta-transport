use crate::error::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

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

    pub async fn recv(&mut self) -> Option<Bytes> {
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
