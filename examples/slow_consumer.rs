use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- SLOW CONSUMER & BACKPRESSURE TEST STARTING ---");
    println!("Scenario: Server processes data very slowly, forcing flow control.");

    // 1. Start Server
    let server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Start slow reader task on server
    let server_clone = server.clone();
    tokio::spawn(async move {
        println!("[Server] Starting slow consumer (1 packet per second)...");
        while let Some(received) = server_clone.recv().await {
            println!(
                "[Server] Processed: {:?}",
                String::from_utf8_lossy(&received.data)
            );
            sleep(Duration::from_secs(1)).await; // Artificial slowness
        }
    });

    // 3. Start Client and Blast Data
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let cid = client.connect(server_addr).await?;
    sleep(Duration::from_millis(200)).await;

    println!("[Client] Starting high-speed data burst...");
    for i in 1..=20 {
        let msg = format!("Fast Packet #{}", i);
        match client.send(&cid, msg.as_bytes()).await {
            Ok(_) => println!("[Client] Sent {}", i),
            Err(e) => {
                println!("[Client] BACKPRESSURE detected at packet {}: {:?}", i, e);
                sleep(Duration::from_millis(500)).await;
            }
        }
    }

    sleep(Duration::from_secs(5)).await;
    println!("--- SLOW CONSUMER TEST FINISHED ---");
    Ok(())
}
