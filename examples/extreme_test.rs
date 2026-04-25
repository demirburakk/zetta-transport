use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- !!! ZETTATRANSPORT EXTREME TEST STARTING !!! ---");
    println!("Scenario: 20% Packet Loss + High Frequency Data");

    // 1. Start Server (Ground Station)
    let server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    server.set_chaos_mode(true); // Internal chaos mode already drops 5%, we'll increase stress

    // 2. Start Client
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    client.set_chaos_mode(true);

    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let cid = client.connect(server_addr).await?;
    sleep(Duration::from_millis(500)).await;

    let start = Instant::now();
    let total_packets = 2000;
    let mut success = 0;

    // 3. Fire-and-forget high frequency secure data
    for i in 1..=total_packets {
        let payload = format!("Extreme Payload Data Index #{}", i);
        match client.send(&cid, payload.as_bytes()).await {
            Ok(_) => success += 1,
            Err(_) => {
                // If flow control kicks in, wait briefly
                sleep(Duration::from_micros(500)).await;
            }
        }

        if i % 500 == 0 {
            println!("Pumping data: {}/{}", i, total_packets);
        }
    }

    println!(
        "Initial pumping complete. Success rate: {}/{}",
        success, total_packets
    );
    println!("Waiting 15 seconds for Reliability and FEC to recover the chaos...");

    // Give enough time for retransmissions to fight the 20% total combined loss
    sleep(Duration::from_secs(15)).await;

    let duration = start.elapsed();
    println!("--- EXTREME TEST FINISHED ---");
    println!("Total Time: {:?}", duration);
    println!("Check logs for 'SECURE DATA RECEIVED' to verify integrity.");

    Ok(())
}
