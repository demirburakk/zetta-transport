use std::net::SocketAddr;
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    // 1. SERVER SIDE
    let server_addr = "127.0.0.1:8080";
    let server = ZtEndpoint::bind(server_addr, None).await?;
    println!("Server started: {}", server_addr);

    // The server runs in a loop, accepting incoming connections
    tokio::spawn(async move {
        while let Some(mut conn) = server.accept().await {
            println!("New client connected!");
            tokio::spawn(async move {
                while let Some(mut stream) = conn.accept_stream().await {
                    println!("New stream opened!");
                    while let Some(data) = stream.recv().await {
                        println!("Server received: {:?}", String::from_utf8_lossy(&data));
                        let _ = stream.send(b"Message received!").await;
                    }
                }
            });
        }
    });

    // 2. CLIENT SIDE
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let target: SocketAddr = server_addr.parse()?;

    let conn = client.connect(target).await?;
    println!("Connecting to server...");

    let mut stream = conn.open_stream().await.expect("Failed to open stream");

    stream.send(b"Hello ZettaTransport!").await?;

    if let Some(reply) = stream.recv().await {
        println!(
            "Client received reply: {:?}",
            String::from_utf8_lossy(&reply)
        );
    }

    Ok(())
}
