use crate::error::Result;
use crate::stream::ZtStream;
use crate::transport::endpoint::ZtEndpoint;
use std::sync::Arc;
use tokio::sync::mpsc;

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
