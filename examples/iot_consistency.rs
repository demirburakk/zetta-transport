use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- IOT SLEEP & RESUMPTION TEST STARTING ---");

    // 1. Start Server
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Start Client and Connect
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let cid = client.connect(server_addr).await?;
    println!("[Client] Connected. Sending first data...");
    client.send(&cid, b"Data before sleep").await?;

    // 3. Simulated Deep Sleep (70 seconds)
    // Server cleanup timeout is 60 seconds.
    println!("[Client] Entering deep sleep for 70 seconds...");
    sleep(Duration::from_secs(70)).await;

    // 4. Wake up and resume
    println!("[Client] Waking up! Attempting to send data without new handshake...");
    match client.send(&cid, b"Data after long sleep").await {
        Ok(_) => println!("[Client] Data sent successfully after sleep!"),
        Err(e) => println!("[Client] Failed to send: {:?}", e),
    }

    // Give server a moment to process and log
    sleep(Duration::from_secs(2)).await;
    println!("--- IOT CONSISTENCY TEST FINISHED ---");

    Ok(())
}
