use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use zetta_transport::ZtEndpoint;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    // 1. Sunucuyu baslat ve Chaos Mode ac
    let server = ZtEndpoint::bind("127.0.0.1:4433", None).await?;
    server.set_chaos_mode(true);
    println!("Sunucu kaosu baslatildi (%5 paket kaybi)...");

    // 2. Istemciyi baslat ve Chaos Mode ac
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    client.set_chaos_mode(true);
    println!("Istemci kaosu baslatildi (%5 paket kaybi)...");

    let server_addr: SocketAddr = "127.0.0.1:4433".parse()?;
    println!("--- STRES TESTI BASLIYOR (1000 Paket) ---");
    let start_time = Instant::now();

    // 3. Baglan
    let cid = client.connect(server_addr).await?;
    sleep(Duration::from_millis(200)).await;

    // 4. Binlerce paket gonder
    let packet_count = 1000;
    let mut sent_count = 0;

    for i in 1..=packet_count {
        let msg = format!("Stres Paketi #{}", i);
        loop {
            match client.send(&cid, msg.as_bytes()).await {
                Ok(_) => {
                    sent_count += 1;
                    break;
                }
                Err(_e) => {
                    // Flow Control aktifse bekle
                    sleep(Duration::from_millis(5)).await;
                }
            }
        }

        if i % 200 == 0 {
            println!("İlerleme: {}/{}", i, packet_count);
        }
    }

    println!(
        "Gonderim tamamlandi. {}/{} paket basariyla kuyruga eklendi.",
        sent_count, packet_count
    );
    println!("Tum paketlerin ulasmasi, ACK'lar ve FEC kurtarmalari icin bekleniyor...");
    sleep(Duration::from_secs(10)).await;

    let duration = start_time.elapsed();
    println!("--- STRES TESTI BITTI ---");
    println!("Toplam Sure: {:?}", duration);

    Ok(())
}
