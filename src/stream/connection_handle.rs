use crate::error::Result;
use crate::stream::ZtStream;
use crate::transport::endpoint::ZtEndpoint;
use std::sync::Arc;
use tokio::sync::mpsc;
use bytes::Bytes;

/// Represents a connection handle to a remote peer.
pub struct ZtConnectionHandle {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
    incoming_streams: mpsc::Receiver<ZtStream>,
    /// Receiver queue for incoming unreliable datagrams received from the remote peer.
    incoming_datagrams: mpsc::Receiver<Bytes>,
}

impl ZtConnectionHandle {
    pub(crate) fn new(
        endpoint: Arc<ZtEndpoint>,
        cid: Vec<u8>,
        incoming_streams: mpsc::Receiver<ZtStream>,
        incoming_datagrams: mpsc::Receiver<Bytes>,
    ) -> Self {
        Self {
            endpoint,
            cid,
            incoming_streams,
            incoming_datagrams,
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

    /// Sends an unreliable datagram to the remote peer.
    ///
    /// Unlike streams, datagrams bypass stream sequencing, packet sorting, and
    /// retransmissions. They are ideal for loss-tolerant, low-latency applications.
    /// However, they are still subject to congestion control limits and pacing
    /// to avoid network congestion.
    pub async fn send_datagram(&self, data: Bytes) -> Result<()> {
        self.endpoint.send_datagram(&self.cid, data).await
    }

    /// Receives an unreliable datagram sent by the remote peer.
    ///
    /// Returns `None` if the connection has been terminated.
    pub async fn recv_datagram(&mut self) -> Option<Bytes> {
        self.incoming_datagrams.recv().await
    }
}
