use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start logging with RUST_LOG=info to see the protocol action
    tracing_subscriber::fmt::init();

    println!("=== ZETTATRANSPORT IOT SIMULATION STARTING ===");

    // 1. Start Ground Station (Server)
    let ground_station = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    ground_station.set_chaos_mode(true); // Simulate real-world signal issues
    println!("[Station] Ground Station listening on 127.0.0.1:4433 (Chaos Mode: ON)");

    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Spawn 3 Drones with different identities
    let drones = vec!["Drone-Alpha", "Drone-Beta", "Drone-Gamma"];
    let mut drone_tasks = Vec::new();

    for drone_name in drones {
        let addr = server_addr;
        let name = drone_name.to_string();

        let task = tokio::spawn(async move {
            if let Ok(client) = ZtEndpoint::bind("127.0.0.1:0", None).await {
                client.set_chaos_mode(true);
                println!("[{}] Powering up and connecting...", name);

                if let Ok(cid) = client.connect(addr).await {
                    println!("[{}] Secure connection established!", name);

                    // Simulate sending 10 telemetry reports
                    for i in 1..=10 {
                        let telemetry = format!(
                            "Telemetry from {}: GPS[41.01, 28.97], Bat[%{}]",
                            name,
                            100 - i
                        );
                        if let Err(e) = client.send(&cid, telemetry.as_bytes()).await
                            && e.to_string().contains("Flow control")
                        {
                            sleep(Duration::from_millis(50)).await;
                        }
                        sleep(Duration::from_millis(300)).await; // Send every 300ms
                    }
                    println!("[{}] Mission complete, returning to base.", name);
                }
            }
        });
        drone_tasks.push(task);
    }

    // 3. Keep simulation running to observe background retransmissions and FEC
    println!("[Simulation] All drones launched. Monitoring traffic for 10 seconds...");
    sleep(Duration::from_secs(10)).await;

    println!("=== SIMULATION FINISHED ===");
    Ok(())
}
