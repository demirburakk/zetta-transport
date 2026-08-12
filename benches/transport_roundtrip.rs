use std::time::{Duration, Instant};
use zetta_transport::transport::endpoint::ZtEndpoint;

const ITERATIONS: usize = 10;
const PAYLOAD_SIZE: usize = 1024 * 1024;

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime");
    runtime.block_on(async {
        let payload = vec![0x5a; PAYLOAD_SIZE];
        let server = ZtEndpoint::bind("127.0.0.1:0", None)
            .await
            .expect("server endpoint");
        let address = server.local_addr().expect("server address");
        let server_task = tokio::spawn(async move {
            let mut connection = server.accept().await.expect("connection");
            for _ in 0..ITERATIONS {
                let mut stream = connection.accept_stream().await.expect("stream");
                let mut received = Vec::with_capacity(PAYLOAD_SIZE);
                while received.len() < PAYLOAD_SIZE {
                    received
                        .extend_from_slice(&stream.recv().await.expect("unexpected stream EOF"));
                }
                stream.send(&received).await.expect("echo");
            }
        });

        let client = ZtEndpoint::bind("127.0.0.1:0", None)
            .await
            .expect("client endpoint");
        let connection = client.connect(address).await.expect("connect");
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let mut stream = connection.open_stream().await.expect("stream");
            stream.send(&payload).await.expect("send");
            let mut echoed = 0;
            while echoed < PAYLOAD_SIZE {
                echoed += stream.recv().await.expect("unexpected echo EOF").len();
            }
            stream.close().await.expect("close stream");
        }
        tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server benchmark timeout")
            .expect("server benchmark task");
        let elapsed = started.elapsed();
        let transferred = (ITERATIONS * PAYLOAD_SIZE * 2) as f64;
        println!(
            "roundtrip: {} MiB in {:?} ({:.2} MiB/s)",
            transferred / (1024.0 * 1024.0),
            elapsed,
            transferred / elapsed.as_secs_f64() / (1024.0 * 1024.0)
        );
    });
}
