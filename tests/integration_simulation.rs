#![cfg(feature = "testing")]

use zetta_transport::transport::endpoint::ZtEndpoint;
use zetta_transport::simulation;
use rand::RngCore;

const PAYLOAD_SIZE: usize = 100 * 1024; // 100 KB payload for simulation testing

async fn run_transfer_test(test_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[{}] Starting test...", test_name);

    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    println!("[{}] Server bound to {}", test_name, server_addr);

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
                // Wait for client to close the stream (EOF)
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

    println!("[{}] Expected {} bytes, received {} bytes", test_name, PAYLOAD_SIZE, received_data.len());
    assert_eq!(original_data.len(), received_data.len(), "[{}] Data length mismatch!", test_name);
    assert_eq!(original_data, received_data, "[{}] Data content mismatch!", test_name);
    stream.close().await?;
    server_handle.await?;
    Ok(())
}

#[tokio::test]
async fn test_network_simulations() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt::try_init();

    // --- SCENARIO 1: 10% PACKET LOSS ---
    println!("\n=== RUNNING SCENARIO 1: 10% PACKET LOSS ===");
    simulation::set_loss_rate(10);
    simulation::set_reorder_rate(0);
    simulation::set_reorder_delay(0);

    let start = std::time::Instant::now();
    run_transfer_test("LossTest_10pct").await?;
    println!("=== SCENARIO 1 PASSED in {:?} ===\n", start.elapsed());

    // --- SCENARIO 2: 20% REORDERING (50ms delay) ---
    println!("\n=== RUNNING SCENARIO 2: 20% REORDERING (50ms delay) ===");
    simulation::set_loss_rate(0);
    simulation::set_reorder_rate(20);
    simulation::set_reorder_delay(50);

    let start = std::time::Instant::now();
    run_transfer_test("ReorderTest_20pct_50ms").await?;
    println!("=== SCENARIO 2 PASSED in {:?} ===\n", start.elapsed());

    // --- SCENARIO 3: JOINT 5% LOSS & 15% REORDERING (30ms delay) ---
    println!("\n=== RUNNING SCENARIO 3: 5% LOSS & 15% REORDERING (30ms delay) ===");
    simulation::set_loss_rate(5);
    simulation::set_reorder_rate(15);
    simulation::set_reorder_delay(30);

    let start = std::time::Instant::now();
    run_transfer_test("JointTest_5pctLoss_15pctReorder").await?;
    println!("=== SCENARIO 3 PASSED in {:?} ===\n", start.elapsed());

    // Reset simulation config to default (0% loss/reorder)
    simulation::set_loss_rate(0);
    simulation::set_reorder_rate(0);
    simulation::set_reorder_delay(0);

    Ok(())
}
