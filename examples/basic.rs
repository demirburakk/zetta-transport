use zetta_transport::transport::endpoint::ZtEndpoint;
use std::net::SocketAddr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Start the Server
    let server_addr = "127.0.0.1:8080";
    let server = ZtEndpoint::bind(server_addr, None).await?;
    println!("📡 Server listening on {}", server_addr);

    // 2. Start the Client
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_socket_addr: SocketAddr = server_addr.parse()?;

    // 3. Client connects to Server
    println!("🔗 Client connecting to server...");
    let scid = client.connect(server_socket_addr).await?;
    
    // Wait for handshake to complete in the background
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. Client sends a message
    let message = b"Hello, ZettaTransport! This is a learning experiment.";
    client.send(&scid, message).await?;
    println!("📤 Client sent: {:?}", String::from_utf8_lossy(message));

    // 5. Server receives the message
    if let Some(received) = server.recv().await {
        println!("📥 Server received from {:?}: {:?}", received.cid, String::from_utf8_lossy(&received.data));
    }

    println!("✅ Experiment successful!");
    Ok(())
}
