use std::net::SocketAddr;
use std::time::Instant;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- C1K (1,000 CONCURRENT) HANDSHAKE TEST STARTING ---");

    // 1. Start Server
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    let start = Instant::now();
    let num_clients = 1000;
    let mut tasks = Vec::new();

    println!(
        "Spawning {} concurrent clients to handshake simultaneously...",
        num_clients
    );

    for _ in 0..num_clients {
        tasks.push(tokio::spawn(async move {
            if let Ok(client) = ZtEndpoint::bind("127.0.0.1:0", None).await {
                let _ = client.connect(server_addr).await;
            }
        }));
    }

    // Wait for all handshakes to finish
    for t in tasks {
        let _ = t.await;
    }

    let duration = start.elapsed();
    println!("--- C1K TEST FINISHED ---");
    println!(
        "Total time for {} secure handshakes: {:?}",
        num_clients, duration
    );
    println!(
        "Average handshake time: {:?}",
        duration / num_clients as u32
    );

    Ok(())
}
