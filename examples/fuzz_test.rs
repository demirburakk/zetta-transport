use rand::Rng;
use std::net::SocketAddr;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- FUZZING & GARBAGE DATA TEST STARTING ---");
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;

    let target_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;

    println!("Bombarding server with 5000 random/malformed packets...");

    for i in 1..=5000 {
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(1..1500);
        let mut garbage = vec![0u8; size];
        rng.fill(&mut garbage[..]);

        let _ = socket.send_to(&garbage, target_addr).await;

        if i % 1000 == 0 {
            println!("Poured {} garbage packets...", i);
        }
    }

    println!("Checking if server is still alive...");
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    match client.connect(target_addr).await {
        Ok(_) => println!("SUCCESS: Server survived the garbage bombardment!"),
        Err(e) => println!("FAILURE: Server is unresponsive or crashed: {:?}", e),
    }

    Ok(())
}
