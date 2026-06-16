use zetta_transport::transport::endpoint::ZtEndpoint;
use rand::RngCore;

const LARGE_PAYLOAD_SIZE: usize = 500 * 1024;
const MULTI_PAYLOAD_SIZE: usize = 50 * 1024;

#[tokio::test]
async fn test_large_payload_transfer() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    println!("[TEST] Starting test_large_payload_transfer");

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    println!("[TEST] Server bound to {}", server_addr);

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            println!("[SERVER] Connection accepted");
            if let Some(mut stream) = conn.accept_stream().await {
                println!("[SERVER] Stream accepted");
                let mut received = Vec::new();
                while received.len() < LARGE_PAYLOAD_SIZE {
                    if let Some(chunk) = stream.recv().await {
                        received.extend_from_slice(&chunk);
                        println!("[SERVER] Received chunk of {} bytes, total {}/{}", chunk.len(), received.len(), LARGE_PAYLOAD_SIZE);
                    } else {
                        println!("[SERVER] Stream EOF");
                        break;
                    }
                }
                println!("[SERVER] Read loop finished. Echoing back {} bytes...", received.len());
                let send_res = stream.send(&received).await;
                println!("[SERVER] Echo send result: {:?}", send_res);
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;
    let mut stream = conn.open_stream().await?;

    let mut original_data = vec![0u8; LARGE_PAYLOAD_SIZE];
    rand::thread_rng().fill_bytes(&mut original_data);

    println!("[CLIENT] Sending {} bytes...", original_data.len());
    stream.send(&original_data).await?;
    println!("[CLIENT] Send complete, waiting for echo...");

    let mut received_data = Vec::new();
    while received_data.len() < LARGE_PAYLOAD_SIZE {
        if let Some(chunk) = stream.recv().await {
            received_data.extend_from_slice(&chunk);
            println!("[CLIENT] Received echo chunk of {} bytes, total {}/{}", chunk.len(), received_data.len(), LARGE_PAYLOAD_SIZE);
        } else {
            println!("[CLIENT] Client Stream EOF");
            break;
        }
    }

    println!("[CLIENT] Closing stream...");
    stream.close().await?;

    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_multi_stream_concurrency() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            let mut tasks = Vec::new();
            for _ in 0..5 {
                if let Some(mut stream) = conn.accept_stream().await {
                    let t = tokio::spawn(async move {
                        let mut received = Vec::new();
                        while received.len() < MULTI_PAYLOAD_SIZE {
                            if let Some(chunk) = stream.recv().await {
                                received.extend_from_slice(&chunk);
                            } else {
                                break;
                            }
                        }
                        let _ = stream.send(&received).await;
                    });
                    tasks.push(t);
                }
            }
            for t in tasks {
                let _ = t.await;
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;

    // Open 5 streams sequentially first
    let mut streams = Vec::new();
    for _ in 0..5 {
        let stream = conn.open_stream().await?;
        streams.push(stream);
    }

    let mut client_tasks = Vec::new();
    for (i, mut stream) in streams.into_iter().enumerate() {
        let t = tokio::spawn(async move {
            let mut data = vec![i as u8; MULTI_PAYLOAD_SIZE];
            rand::thread_rng().fill_bytes(&mut data);
            
            stream.send(&data).await.unwrap();

            let mut received = Vec::new();
            while received.len() < MULTI_PAYLOAD_SIZE {
                if let Some(chunk) = stream.recv().await {
                    received.extend_from_slice(&chunk);
                } else {
                    break;
                }
            }
            assert_eq!(data, received);
            stream.close().await.unwrap();
        });
        client_tasks.push(t);
    }

    for t in client_tasks {
        t.await?;
    }

    server_handle.await?;
    Ok(())
}
