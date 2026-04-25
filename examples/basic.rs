use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging system.
    // Use RUST_LOG=info to see background protocol activity.
    tracing_subscriber::fmt::init();

    // 1. Start Server Endpoint (Listening on localhost:4433)
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    println!("Server listening on 127.0.0.1:4433...");

    // 2. Start Client Endpoint (Listening on a random local port)
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 3. Initiate Connection (Initial Handshake with Key Exchange)
    println!("Connecting to server...");
    let cid = client.connect(server_addr).await?;
    println!("Secure connection established! CID: {:?}", cid);

    // 4. Send encrypted data over the secure channel
    println!("Sending secure data...");
    for i in 1..=4 {
        let msg = format!("Paket #{}", i);
        client.send(&cid, msg.as_bytes()).await?;
        sleep(Duration::from_millis(100)).await;
    }

    // Wait for background tasks (ACKs, logging) to complete before exiting.
    sleep(Duration::from_secs(2)).await;

    Ok(())
}
