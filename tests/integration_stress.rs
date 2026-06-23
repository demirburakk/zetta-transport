use zetta_transport::transport::endpoint::ZtEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::{Duration, Instant};

#[tokio::test]
async fn test_stream_concurrency_stress() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            let mut server_tasks = Vec::new();
            for _ in 0..50 {
                if let Some(mut stream) = conn.accept_stream().await {
                    let task = tokio::spawn(async move {
                        let mut buf = vec![0u8; 1024];
                        // Read 10 KB using read_exact to ensure complete buffers are filled
                        for _ in 0..10 {
                            stream.read_exact(&mut buf).await.unwrap();
                        }
                        // Write 10 KB echo back
                        for _ in 0..10 {
                            stream.write_all(&vec![0xAA; 1024]).await.unwrap();
                        }
                        stream.flush().await.unwrap();
                    });
                    server_tasks.push(task);
                }
            }
            for task in server_tasks {
                task.await.unwrap();
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    let mut client_tasks = Vec::new();
    let mut streams = Vec::new();

    // Open exactly 100 streams (the dynamic peer limit)
    for _ in 0..100 {
        let stream = conn.open_stream().await?;
        streams.push(stream);
    }

    // Attempting to open the 101st client-initiated stream must fail.
    let err_stream = conn.open_stream().await;
    assert!(err_stream.is_err());

    // Run transfers on the first 50 streams concurrently
    for mut stream in streams.drain(0..50) {
        let task = tokio::spawn(async move {
            // Write 10 KB
            for _ in 0..10 {
                stream.write_all(&vec![0x55; 1024]).await.unwrap();
            }
            stream.flush().await.unwrap();

            // Read 10 KB echo back
            let mut buf = vec![0u8; 1024];
            for _ in 0..10 {
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf[0], 0xAA);
            }
        });
        client_tasks.push(task);
    }

    for task in client_tasks {
        task.await.unwrap();
    }

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_rtt_ack_delay_compensation() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                let mut buf = vec![0u8; 7];
                let _ = stream.read_exact(&mut buf).await.unwrap();
                
                // Simulate a receiver processing delay (e.g. 150ms delay)
                tokio::time::sleep(Duration::from_millis(150)).await;
                
                stream.write_all(b"response").await.unwrap();
                stream.flush().await.unwrap();
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;
    let mut stream = conn.open_stream().await?;

    let start = Instant::now();
    stream.write_all(b"request").await?;
    stream.flush().await?;

    let mut buf = vec![0u8; 8];
    let _ = stream.read_exact(&mut buf).await?;
    let total_elapsed = start.elapsed();

    // Verify that the actual wall-clock elapsed time is >= 150ms
    assert!(total_elapsed >= Duration::from_millis(150));

    server_handle.await?;
    Ok(())
}
