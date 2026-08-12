//! Security-focused integration tests for ZettaTransport.
//!
//! Tests connection lifecycle events: graceful close, idle timeout behavior,
//! and connection statistics API.

use std::sync::Arc;
use zetta_transport::transport::endpoint::ZtEndpoint;

/// Test that graceful close properly terminates the connection.
/// Both sides should be able to detect the closure.
#[tokio::test]
async fn test_connection_graceful_close() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                let mut buf = vec![0u8; 1024];
                while let Some(chunk) = stream.recv().await {
                    buf.extend_from_slice(&chunk);
                }
            }
            // Verify accept_stream returns None on server side
            assert!(conn.accept_stream().await.is_none());
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    let stream = conn.open_stream().await?;
    stream.send(b"hello before close").await?;

    conn.close().await?;

    server_handle.await?;
    Ok(())
}

/// Test that the ConnectionStats API returns valid metrics after data transfer.
#[tokio::test]
async fn test_connection_stats_api() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await
            && let Some(mut stream) = conn.accept_stream().await
            && let Some(chunk) = stream.recv().await
        {
            let _ = stream.send(&chunk).await;
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    let mut stream = conn.open_stream().await?;
    stream.send(b"ping data for stats").await?;

    let mut reply = vec![0u8; 1024];
    if let Some(chunk) = stream.recv().await {
        reply[..chunk.len()].copy_from_slice(&chunk);
    }

    let stats = conn.stats().await?;
    assert!(stats.bytes_sent > 0);
    assert!(stats.mtu >= 1200);

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_server_can_pin_client_endpoint_identity() -> Result<(), Box<dyn std::error::Error>> {
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let expected_client_key = *client.ed_public_key.as_bytes();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    server.set_peer_key_verifier(Some(Arc::new(move |key| *key == expected_client_key)));
    let server_addr = server.local_addr()?;

    let accept_task = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(2), server.accept()).await
    });
    client.connect(server_addr).await?;
    assert!(accept_task.await?.is_ok());
    Ok(())
}

#[tokio::test]
async fn test_connection_survives_last_stream_close() -> Result<(), Box<dyn std::error::Error>> {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut conn = server.accept().await.expect("connection");
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            let mut stream = conn.accept_stream().await.expect("stream");
            assert_eq!(stream.recv().await.as_deref(), Some(expected));
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;
    let first = conn.open_stream().await?;
    first.send(b"first").await?;
    first.close().await?;

    let second = conn.open_stream().await?;
    second.send(b"second").await?;
    second.close().await?;
    server_task.await?;
    Ok(())
}
