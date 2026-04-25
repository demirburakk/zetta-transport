use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("--- EXTREME MOBILITY TEST STARTING ---");
    println!("Scenario: Client changes ports multiple times mid-transmission.");

    // 1. Start Server
    let _server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // 2. Client Loop with Port Switching
    let mut current_cid: Option<Vec<u8>> = None;
    let mut saved_state: Option<(SocketAddr, Vec<u8>, Vec<u8>)> = None;

    for session in 1..=3 {
        println!(
            "\n[Mobility] Client starting from new port (Session {})",
            session
        );
        let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;

        if session == 1 {
            // Initial connection
            let cid = client.connect(server_addr).await?;
            println!("[Mobility] Connected. CID: {:?}", cid);

            // Save state for next port switch
            if let Some((addr, scid, dcid)) = client.get_connection_state(&cid).await {
                saved_state = Some((addr, scid, dcid));
                current_cid = Some(cid);
            }
        } else {
            // RESUME connection on the new endpoint/port
            if let Some((addr, scid, dcid)) = &saved_state {
                client
                    .resume_connection(*addr, scid.clone(), dcid.clone())
                    .await;
                println!("[Mobility] Session RESUMED on new port.");
            }
        }

        let cid = current_cid.as_ref().expect("Should have a CID");

        // Send packets from this port
        for i in 1..=3 {
            let msg = format!("Packet #{} from session {}", i, session);
            println!("[Mobility] Sending: {}", msg);
            match client.send(cid, msg.as_bytes()).await {
                Ok(_) => {}
                Err(e) => println!("[Mobility] Send error: {:?}", e),
            }
            sleep(Duration::from_millis(100)).await;
        }

        println!("[Mobility] Simulating IP/Port change...");
    }

    sleep(Duration::from_secs(2)).await;
    println!("--- MOBILITY TEST FINISHED ---");
    Ok(())
}
