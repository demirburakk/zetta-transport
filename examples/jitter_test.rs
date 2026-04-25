use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- EXTREME JITTER & OUT-OF-ORDER TEST STARTING ---");
    println!("Scenario: Packets are delayed and delivered in random order.");

    // 1. Start Server
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Start Client
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let cid = client.connect(server_addr).await?;
    sleep(Duration::from_millis(200)).await;

    // 3. Send 10 packets but with random simulated delays at the APPLICATION level
    // This will force retransmissions and test out-of-order handling.
    let mut tasks = Vec::new();

    for i in 1..=10 {
        let client_clone = client.clone();
        let cid_clone = cid.clone();
        let task = tokio::spawn(async move {
            let delay = rand::thread_rng().gen_range(0..1000);
            sleep(Duration::from_millis(delay)).await;
            let msg = format!("Jitter Packet #{}", i);
            let _ = client_clone.send(&cid_clone, msg.as_bytes()).await;
        });
        tasks.push(task);
    }

    for t in tasks {
        let _ = t.await;
    }

    sleep(Duration::from_secs(3)).await;
    println!("--- JITTER TEST FINISHED ---");
    Ok(())
}
