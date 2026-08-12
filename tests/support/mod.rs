#![cfg(feature = "testing")]

use std::time::Duration;
use zetta_transport::config::ZtConfig;
use zetta_transport::stats::ConnectionStats;
use zetta_transport::transport::endpoint::ZtEndpoint;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn deterministic_payload(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state as u8) ^ (index as u8).wrapping_mul(31)
        })
        .collect()
}

pub async fn echo_transfer(
    client_config: ZtConfig,
    server_config: ZtConfig,
    payload: Vec<u8>,
    deadline: Duration,
) -> TestResult<ConnectionStats> {
    tokio::time::timeout(deadline, async move {
        let expected_len = payload.len();
        let server = ZtEndpoint::bind_with_zt_config("127.0.0.1:0", server_config).await?;
        let server_addr = server.local_addr()?;

        let server_task = tokio::spawn(async move {
            let mut connection = server.accept().await.expect("server connection");
            let mut stream = connection.accept_stream().await.expect("incoming stream");
            let mut received = Vec::with_capacity(expected_len);
            while received.len() < expected_len {
                let chunk = stream
                    .recv_result()
                    .await
                    .expect("server receive failed")
                    .expect("unexpected stream EOF");
                received.extend_from_slice(&chunk);
            }
            stream.send(&received).await.expect("server echo failed");
            received
        });

        let client = ZtEndpoint::bind_with_zt_config("127.0.0.1:0", client_config).await?;
        let connection = client.connect(server_addr).await?;
        let mut stream = connection.open_stream().await?;
        stream.send(&payload).await?;

        let mut echoed = Vec::with_capacity(payload.len());
        while echoed.len() < payload.len() {
            let chunk = stream
                .recv_result()
                .await?
                .ok_or("unexpected client stream EOF")?;
            echoed.extend_from_slice(&chunk);
        }

        let server_received = server_task.await?;
        assert_eq!(server_received, payload, "server-side payload corruption");
        assert_eq!(echoed, payload, "echo payload corruption");
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(connection.stats().await?)
    })
    .await
    .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
        format!("scenario exceeded {deadline:?}").into()
    })?
}
