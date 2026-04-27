use zetta_transport::transport::endpoint::ZtEndpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. SERVER SIDE
    let server_addr = "127.0.0.1:8080";
    let server = ZtEndpoint::bind(server_addr, None).await?;
    println!("Server started: {}", server_addr);

    // The server runs in a loop, accepting incoming connections
    tokio::spawn(async move {
        while let Some(mut stream) = server.accept().await {
            println!("New client connected!");
            tokio::spawn(async move {
                while let Some(data) = stream.recv().await {
                    println!("Server received: {:?}", String::from_utf8_lossy(&data));
                    let _ = stream.send(b"Message received!").await;
                }
            });
        }
    });

    // 2. CLIENT SIDE
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let target: SocketAddr = server_addr.parse()?;
    
    let stream = client.connect(target).await?;
    println!("Connecting to server...");

    stream.send(b"Hello ZettaTransport!").await?;
    
    let mut stream = stream; // Make it mutable to receive
    if let Some(reply) = stream.recv().await {
        println!("Client received reply: {:?}", String::from_utf8_lossy(&reply));
    }

    Ok(())
}
