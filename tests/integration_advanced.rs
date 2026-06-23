#![cfg(feature = "testing")]

use zetta_transport::transport::endpoint::ZtEndpoint;
use zetta_transport::transport::CongestionControlAlgorithm;
use zetta_transport::simulation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use bytes::Bytes;
use rand::RngCore;
use std::time::Instant;

const PAYLOAD_SIZE: usize = 150 * 1024; // 150 KB for extreme loss test

async fn run_extreme_loss_transfer(test_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[{}] Starting extreme transfer test...", test_name);

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await
            && let Some(mut stream) = conn.accept_stream().await {
                let mut received = Vec::new();
                while received.len() < PAYLOAD_SIZE {
                    if let Some(chunk) = stream.recv().await {
                        received.extend_from_slice(&chunk);
                    } else {
                        break;
                    }
                }
                // Echo back
                let _ = stream.send(&received).await;
                // Wait for EOF
                while stream.recv().await.is_some() {}
            }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let conn = client.connect(server_addr).await?;
    let mut stream = conn.open_stream().await?;

    let mut original_data = vec![0u8; PAYLOAD_SIZE];
    rand::thread_rng().fill_bytes(&mut original_data);

    stream.send(&original_data).await?;

    let mut received_data = Vec::new();
    while received_data.len() < PAYLOAD_SIZE {
        if let Some(chunk) = stream.recv().await {
            received_data.extend_from_slice(&chunk);
        } else {
            break;
        }
    }

    assert_eq!(original_data.len(), received_data.len(), "[{}] Data length mismatch", test_name);
    assert_eq!(original_data, received_data, "[{}] Content mismatch", test_name);
    stream.close().await?;
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_extreme_network_conditions_and_congestion_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    // --- Extreme Simulation Scenario: 25% Loss, 20% Reordering (30ms delay) ---
    println!("\n=== RUNNING EXTREME LOSS & REORDERING SCENARIO ===");
    simulation::set_loss_rate(25);
    simulation::set_reorder_rate(20);
    simulation::set_reorder_delay(30);

    let start = Instant::now();
    run_extreme_loss_transfer("ExtremeLossTest").await?;
    println!("=== EXTREME SCENARIO PASSED in {:?} ===\n", start.elapsed());

    // Reset simulation config to defaults
    simulation::set_loss_rate(0);
    simulation::set_reorder_rate(0);
    simulation::set_reorder_delay(0);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_different_congestion_control_algorithms() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        // Accept two connections
        let mut server_tasks = Vec::new();
        for _ in 0..2 {
            if let Some(mut conn) = server.accept().await {
                let task = tokio::spawn(async move {
                    if let Some(mut stream) = conn.accept_stream().await {
                        let mut buf = vec![0u8; 1024];
                        // Read 50 KB
                        for _ in 0..50 {
                            stream.read_exact(&mut buf).await.unwrap();
                        }
                        // Write 50 KB echo back
                        for _ in 0..50 {
                            stream.write_all(&vec![0xAA; 1024]).await.unwrap();
                        }
                        stream.flush().await.unwrap();
                    }
                });
                server_tasks.push(task);
            }
        }
        for task in server_tasks {
            task.await.unwrap();
        }
    });

    // Client 1 using Reno
    let client_reno = ZtEndpoint::bind_with_config("127.0.0.1:0", None, CongestionControlAlgorithm::Reno).await?;
    let conn_reno = client_reno.connect(server_addr).await?;

    // Client 2 using Cubic
    let client_cubic = ZtEndpoint::bind_with_config("127.0.0.1:0", None, CongestionControlAlgorithm::Cubic).await?;
    let conn_cubic = client_cubic.connect(server_addr).await?;

    let t1 = tokio::spawn(async move {
        let mut stream = conn_reno.open_stream().await.unwrap();
        // Write 50 KB
        for _ in 0..50 {
            stream.write_all(&vec![0x55; 1024]).await.unwrap();
        }
        stream.flush().await.unwrap();

        // Read 50 KB echo
        let mut buf = vec![0u8; 1024];
        for _ in 0..50 {
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0xAA);
        }
    });

    let t2 = tokio::spawn(async move {
        let mut stream = conn_cubic.open_stream().await.unwrap();
        // Write 50 KB
        for _ in 0..50 {
            stream.write_all(&vec![0x77; 1024]).await.unwrap();
        }
        stream.flush().await.unwrap();

        // Read 50 KB echo
        let mut buf = vec![0u8; 1024];
        for _ in 0..50 {
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0xAA);
        }
    });

    t1.await?;
    t2.await?;
    server_handle.await?;

    Ok(())
}

#[tokio::test]
async fn test_datagram_stream_interleaving_holb_mitigation() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;

    let server_handle = tokio::spawn(async move {
        println!("[SERVER] Waiting for connection...");
        if let Some(mut conn) = server.accept().await {
            println!("[SERVER] Accepted connection. Waiting for stream...");
            if let Some(mut stream) = conn.accept_stream().await {
                println!("[SERVER] Accepted stream. Starting datagram echo loop...");
                for i in 0..10 {
                    if let Some(dg) = conn.recv_datagram().await {
                        println!("[SERVER] Echoing datagram {}", i);
                        conn.send_datagram(dg).await.unwrap();
                    } else {
                        break;
                    }
                }
                
                println!("[SERVER] Datagram loop finished. Reading stream...");
                if let Some(chunk) = stream.recv().await {
                    println!("[SERVER] Received stream chunk: {:?}", chunk);
                    assert_eq!(chunk.len(), 67);
                } else {
                    panic!("[SERVER] Stream EOF without data!");
                }
                println!("[SERVER] Finished reading stream.");
            }
        }
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    println!("[CLIENT] Connecting to server...");
    let mut conn = client.connect(server_addr).await?;
    println!("[CLIENT] Connected. Opening stream...");

    // Open a stream and write some data (simulating blocked stream)
    let stream = conn.open_stream().await?;
    println!("[CLIENT] Stream opened. Sending stream payload...");
    stream.send(b"stream_blocked_payload_data_waiting_to_be_read_by_server_with_delay").await?;
    println!("[CLIENT] Stream payload sent. Starting datagram loop...");

    // Now, send unreliable datagrams concurrently
    let dg_payload = Bytes::from_static(b"unreliable_holb_test");
    for i in 0..10 {
        println!("[CLIENT] Sending datagram {}", i);
        conn.send_datagram(dg_payload.clone()).await?;
        let reply = conn.recv_datagram().await;
        assert!(reply.is_some());
        assert_eq!(reply.unwrap(), dg_payload);
    }
    println!("[CLIENT] Datagram loop finished. Waiting for server...");

    server_handle.await?;
    println!("[CLIENT] Done.");
    Ok(())
}
