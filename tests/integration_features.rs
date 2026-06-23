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

#[tokio::test]
async fn test_unidirectional_streams() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            // Server accepts client-initiated unidirectional out stream
            if let Some(mut stream) = conn.accept_stream().await {
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"unidirectional outbound data");
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    // 1. Test UnidirectionalOut (Local writes only)
    let mut uni_out = conn.open_stream_with_type(zetta_transport::transport::StreamType::UnidirectionalOut).await?;
    
    // Writing should succeed
    uni_out.send(b"unidirectional outbound data").await?;
    
    // Reading should return EOF/None immediately
    let mut read_buf = vec![0u8; 10];
    let read_bytes = uni_out.read(&mut read_buf).await?;
    assert_eq!(read_bytes, 0); // EOF
    assert!(uni_out.recv().await.is_none());

    // 2. Test UnidirectionalIn (Local reads only)
    let mut uni_in = conn.open_stream_with_type(zetta_transport::transport::StreamType::UnidirectionalIn).await?;
    
    // Writing should fail with PermissionDenied
    let write_res = uni_in.send(b"data").await;
    assert!(write_res.is_err());
    let err_str = format!("{:?}", write_res.err().unwrap());
    assert!(err_str.contains("PermissionDenied"));

    // AsyncWrite poll_write should also fail
    let write_all_res = uni_in.write_all(b"data").await;
    assert!(write_all_res.is_err());
    assert_eq!(write_all_res.err().unwrap().kind(), std::io::ErrorKind::PermissionDenied);

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_alpn_negotiation_failure() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    // Server bound with custom ALPN
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    server.set_alpn(b"http3-server".to_vec());
    let server_addr = server.local_addr()?;

    // Client bound with different ALPN
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    client.set_alpn(b"http3-client".to_vec());

    // Connect should fail due to ALPN mismatch
    let connect_res = tokio::time::timeout(std::time::Duration::from_millis(500), client.connect(server_addr)).await;
    assert!(connect_res.is_err() || connect_res.unwrap().is_err());

    Ok(())
}

#[tokio::test]
async fn test_dynamic_stream_limits_and_blocked() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(_conn) = server.accept().await {
            // Keep server running to process incoming stream closes/limits
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    let mut streams = Vec::new();
    let mut reached_limit = false;
    for _ in 0..110 {
        match conn.open_stream().await {
            Ok(s) => streams.push(s),
            Err(e) => {
                let err_str = format!("{:?}", e);
                assert!(err_str.contains("TooManyStreams"));
                reached_limit = true;
                break;
            }
        }
    }
    assert!(reached_limit);

    server_handle.await?;
    Ok(())
}

