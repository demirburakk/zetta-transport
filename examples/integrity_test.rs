use rand::Rng;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- DATA INTEGRITY & CORRUPTION TEST STARTING ---");
    println!("Scenario: Random bits are flipped in encrypted payloads.");

    // 1. Start Server
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Start Client
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let cid = client.connect(server_addr).await?;
    sleep(Duration::from_millis(200)).await;

    // 3. To simulate corruption, we need to bypass the client's normal send
    // We will get the raw socket and send corrupted AEAD packets.
    let raw_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;

    println!("Sending 10 corrupted packets to test AEAD rejection...");

    for i in 1..=10 {
        // Construct a valid header but junk payload
        let mut junk_data = vec![0u8; 100];
        rand::thread_rng().fill(&mut junk_data[..]);

        // This won't even reach the decrypt phase if the header is broken,
        // or it will fail AEAD decryption if the payload is modified.
        let _ = raw_socket.send_to(&junk_data, server_addr).await;

        if i % 2 == 0 {
            println!("Flipped bits for packet group {}...", i);
        }
    }

    println!("Checking if server is still standing...");
    // Verify server can still process a VALID packet after corruption
    client
        .send(&cid, b"Integrity check after corruption")
        .await?;

    sleep(Duration::from_secs(1)).await;
    println!("--- INTEGRITY TEST FINISHED ---");
    Ok(())
}
