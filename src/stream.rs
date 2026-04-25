use crate::endpoint::ZtEndpoint;
use crate::error::Result;
use std::sync::Arc;

/// A connection-oriented stream wrapper over ZtEndpoint.
/// This provides a socket-like interface for a single remote peer,
/// handling the underlying CID routing automatically.
pub struct ZtStream {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
}

impl ZtStream {
    pub fn new(endpoint: Arc<ZtEndpoint>, cid: Vec<u8>) -> Self {
        Self { endpoint, cid }
    }

    /// Sends data securely to the remote peer via ZettaTransport.
    /// Blocks if the flow control or congestion window is exhausted.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        // Implement auto-retry if window is full
        loop {
            match self.endpoint.send(&self.cid, data).await {
                Ok(_) => return Ok(()),
                Err(crate::error::ZtError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Backoff and wait for window to open
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Gracefully closes the stream.
    pub async fn close(&self) -> Result<()> {
        self.endpoint.close(&self.cid).await
    }
}
