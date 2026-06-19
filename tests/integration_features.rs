use zetta_transport::transport::endpoint::ZtEndpoint;
use zetta_transport::transport::CongestionControlAlgorithm;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;

#[tokio::test]
async fn test_async_read_write_copy() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    // Bind server with Reno congestion control to test both pluggable CC and Async I/O
    let server = ZtEndpoint::bind_with_config("127.0.0.1:0", None, CongestionControlAlgorithm::Reno).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await
            && let Some(mut stream) = conn.accept_stream().await {
                // Use AsyncRead / AsyncWrite standard wrappers to copy
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"Hello Async I/O!");
                stream.write_all(b"Echo: Hello Async I/O!").await.unwrap();
                stream.flush().await.unwrap();
            }
    });

    let client = ZtEndpoint::bind_with_config("127.0.0.1:0", None, CongestionControlAlgorithm::Reno).await?;
    let conn = client.connect(server_addr).await?;
    let mut stream = conn.open_stream().await?;

    stream.write_all(b"Hello Async I/O!").await?;
    stream.flush().await?;

    let mut reply = vec![0u8; 1024];
    let n = stream.read(&mut reply).await?;
    assert_eq!(&reply[..n], b"Echo: Hello Async I/O!");

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_zero_copy_and_datagrams() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            // 1. Receive unreliable datagram
            let datagram = conn.recv_datagram().await.unwrap();
            assert_eq!(&datagram[..], b"unreliable payload");
            conn.send_datagram(Bytes::from_static(b"unreliable response")).await.unwrap();

            // 2. Receive zero-copy stream bytes
            if let Some(mut stream) = conn.accept_stream().await {
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"zero-copy stream data");
                stream.send_bytes(Bytes::from_static(b"stream response")).await.unwrap();
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let mut conn = client.connect(server_addr).await?;

    // Send unreliable datagram
    conn.send_datagram(Bytes::from_static(b"unreliable payload")).await?;
    let datagram_reply = conn.recv_datagram().await.unwrap();
    assert_eq!(&datagram_reply[..], b"unreliable response");

    // Open stream and send zero-copy bytes
    let mut stream = conn.open_stream().await?;
    stream.send_bytes(Bytes::from_static(b"zero-copy stream data")).await?;
    
    let mut stream_reply = vec![0u8; 1024];
    let n = stream.read(&mut stream_reply).await?;
    assert_eq!(&stream_reply[..n], b"stream response");

    server_handle.await?;
    Ok(())
}
