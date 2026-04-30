use crate::error::Result;
use crate::transport::endpoint::ZtEndpoint;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

/// Represents a connection handle to a remote peer.
pub struct ZtConnectionHandle {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
    incoming_streams: mpsc::Receiver<ZtStream>,
}

impl ZtConnectionHandle {
    pub(crate) fn new(
        endpoint: Arc<ZtEndpoint>,
        cid: Vec<u8>,
        incoming_streams: mpsc::Receiver<ZtStream>,
    ) -> Self {
        Self {
            endpoint,
            cid,
            incoming_streams,
        }
    }

    /// Opens a new stream to the remote peer.
    pub async fn open_stream(&self) -> Result<ZtStream> {
        self.endpoint.open_stream(&self.cid).await
    }

    /// Accepts an incoming stream initiated by the remote peer.
    pub async fn accept_stream(&mut self) -> Option<ZtStream> {
        self.incoming_streams.recv().await
    }

    /// Gracefully closes the connection.
    pub async fn close(&self) -> Result<()> {
        self.endpoint.close(&self.cid).await
    }
}

/// Represents a reliable, encrypted, and multiplexed data stream over a UDP connection.
/// Behaves similarly to a TCP stream but operates within the ZettaTransport protocol.
pub struct ZtStream {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
    pub stream_id: u32,
    receiver: mpsc::Receiver<Bytes>,
    window_opened: Arc<Notify>,
}

impl ZtStream {
    pub(crate) fn new(
        endpoint: Arc<ZtEndpoint>,
        cid: Vec<u8>,
        stream_id: u32,
        receiver: mpsc::Receiver<Bytes>,
        window_opened: Arc<Notify>,
    ) -> Self {
        Self {
            endpoint,
            cid,
            stream_id,
            receiver,
            window_opened,
        }
    }

    /// Sends a payload reliably to the remote peer.
    /// Automatically handles backpressure if the congestion or flow window is full
    /// by yielding execution until space becomes available.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mtu = self.endpoint.get_mtu(&self.cid).await;
        let chunk_size = mtu.saturating_sub(64).max(512); // Safe payload size accounting for UDP/IP/ZT headers
        for chunk in data.chunks(chunk_size) {
            loop {
                match self.endpoint.send(&self.cid, self.stream_id, chunk).await {
                    Ok(_) => break,
                    Err(crate::error::ZtError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        self.window_opened.notified().await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    /// Receives a decrypted, in-order chunk of data from the remote peer.
    /// Returns `None` if the stream is closed.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.receiver.recv().await
    }

    /// Gracefully closes the stream.
    pub async fn close(&self) -> Result<()> {
        self.endpoint.close_stream(&self.cid, self.stream_id).await
    }
}
