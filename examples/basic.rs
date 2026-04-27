use zetta_transport::transport::endpoint::ZtEndpoint;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. SUNUCU TARAFI
    let server_addr = "127.0.0.1:8080";
    let server = ZtEndpoint::bind(server_addr, None).await?;
    println!("Sunucu başlatıldı: {}", server_addr);

    // Sunucu gelen bağlantıları kabul eden bir döngüde çalışır
    tokio::spawn(async move {
        while let Some(mut stream) = server.accept().await {
            println!("Yeni bir istemci bağlandı!");
            tokio::spawn(async move {
                while let Some(data) = stream.recv().await {
                    println!("Sunucu aldı: {:?}", String::from_utf8_lossy(&data));
                    let _ = stream.send(b"Mesajiniz alindi!").await;
                }
            });
        }
    });

    // 2. İSTEMCİ TARAFI
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let target: SocketAddr = server_addr.parse()?;
    
    let mut stream = client.connect(target).await?;
    println!("Sunucuya baglaniliyor...");

    stream.send(b"Merhaba ZettaTransport!").await?;
    
    if let Some(reply) = stream.recv().await {
        println!("İstemci yanit aldi: {:?}", String::from_utf8_lossy(&reply));
    }

    Ok(())
}