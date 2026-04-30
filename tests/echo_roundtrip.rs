use std::time::Duration;

use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_roundtrip_large_payload() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None)
        .await
        .expect("server bind");
    let server_addr = server.local_addr().expect("server local_addr");

    tokio::spawn({
        let server = server.clone();
        async move {
            if let Some(mut conn) = server.accept().await {
                if let Some(mut stream) = conn.accept_stream().await {
                    while let Some(data) = stream.recv().await {
                        // Echo what we got.
                        let _ = stream.send(&data).await;
                    }
                }
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None)
        .await
        .expect("client bind");

    let mut conn = client.connect(server_addr).await.expect("client connect");

    // The stream is pre-allocated by the client locally. We could call `open_stream()`
    // to match normal flow, or wait for stream 0. Since `connect` emits stream 0 internally:
    let mut stream = conn.accept_stream().await.expect("stream 0");

    // Large enough to exercise backpressure and cumulative ACK handling.
    let payload = vec![0x42u8; 200 * 1024];

    tokio::time::timeout(Duration::from_secs(10), stream.send(&payload))
        .await
        .expect("send timeout")
        .expect("send failed");

    let mut received = Vec::with_capacity(payload.len());
    while received.len() < payload.len() {
        let chunk = tokio::time::timeout(Duration::from_secs(10), stream.recv())
            .await
            .expect("recv timeout")
            .expect("stream closed unexpectedly");
        received.extend_from_slice(&chunk);
    }

    assert_eq!(received, payload);
}
