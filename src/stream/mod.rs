use crate::transport::endpoint::ZtEndpoint;
use crate::error::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify};

pub struct ZtStream {
    endpoint: Arc<ZtEndpoint>,
    cid: Vec<u8>,
    receiver: mpsc::Receiver<Bytes>,
    window_opened: Arc<Notify>,
}

impl ZtStream {
    pub(crate) fn new(endpoint: Arc<ZtEndpoint>, cid: Vec<u8>, receiver: mpsc::Receiver<Bytes>, window_opened: Arc<Notify>) -> Self {
        Self { endpoint, cid, receiver, window_opened }
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        loop {
            match self.endpoint.send(&self.cid, data).await {
                Ok(_) => return Ok(()),
                Err(crate::error::ZtError::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // ÇÖZÜM: Meşgul döngü (Busy-Wait) yerine Event-Driven Uyku
                    // Aktör pencerede yer açıldığında bize Notify ile "Uyan ve yolla!" diyecek.
                    self.window_opened.notified().await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn recv(&mut self) -> Option<Bytes> {
        self.receiver.recv().await
    }

    pub async fn close(&self) -> Result<()> {
        self.endpoint.close(&self.cid).await
    }
}

impl Drop for ZtStream {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        let cid = self.cid.clone();
        tokio::spawn(async move {
            let _ = endpoint.close(&cid).await;
        });
    }
}