use std::time::Duration;
use std::collections::VecDeque;
use rand::Rng;
use tokio::time::{sleep, timeout};
use tokio::net::UdpSocket;
use std::sync::Arc;
use zetta_transport::transport::endpoint::ZtEndpoint;

async fn run_proxy(
    proxy_addr: &str,
    server_addr: std::net::SocketAddr,
    drop_rate: f64,
    duplicate_rate: f64,
    reorder_prob: f64,
    latency_ms: u64,
    jitter_ms: u64,
) -> std::net::SocketAddr {
    let proxy = Arc::new(UdpSocket::bind(proxy_addr).await.unwrap());
    let local_addr = proxy.local_addr().unwrap();
    let proxy_clone = proxy.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client_addr = None;
        let mut reorder_buffer = VecDeque::new();

        loop {
            tokio::select! {
                Ok((len, src)) = proxy_clone.recv_from(&mut buf) => {
                    let mut rng = rand::thread_rng();

                    // 1. Packet Loss
                    if rng.gen_bool(drop_rate) {
                        continue;
                    }

                    let dest = if src != server_addr {
                        client_addr = Some(src);
                        server_addr
                    } else {
                        match client_addr {
                            Some(addr) => addr,
                            None => continue,
                        }
                    };

                    let packet = buf[..len].to_vec();
                    let proxy_for_send = proxy_clone.clone();

                    // Helper to send a packet with delay
                    let delay = if jitter_ms > 0 {
                        latency_ms + rng.gen_range(0..=jitter_ms)
                    } else {
                        latency_ms
                    };
                    
                    let send_task = async move {
                        if delay > 0 {
                            sleep(Duration::from_millis(delay)).await;
                        }

                        let _ = proxy_for_send.send_to(&packet, dest).await;
                    };

                    // 2. Reordering
                    if rng.gen_bool(reorder_prob) {
                        reorder_buffer.push_back(send_task);
                    } else {
                        tokio::spawn(send_task);

                        // If we didn't reorder, maybe flush some reordered packets out of order
                        if !reorder_buffer.is_empty() && rng.gen_bool(0.5) {
                            if let Some(task) = reorder_buffer.pop_front() {
                                tokio::spawn(task);
                            }
                        }
                    }

                    // 3. Duplication
                    if rng.gen_bool(duplicate_rate) {
                        let dup_delay = latency_ms + if jitter_ms > 0 { rng.gen_range(0..=jitter_ms) } else { 0 } + 10;
                        let packet_dup = buf[..len].to_vec();
                        let proxy_for_dup = proxy_clone.clone();
                        tokio::spawn(async move {
                            sleep(Duration::from_millis(dup_delay)).await;
                            let _ = proxy_for_dup.send_to(&packet_dup, dest).await;
                        });
                    }
                }
            }
        }
    });

    local_addr
}

#[tokio::test]
async fn chaos_high_packet_loss() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // 50% packet loss!
    let proxy_addr = run_proxy("127.0.0.1:0", server_addr, 0.5, 0.0, 0.0, 0, 0).await;

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                if let Ok(Some(data)) = timeout(Duration::from_secs(10), stream.recv()).await {
                    let _ = stream.send(&data).await;
                }
            }
        }
    });

    let client_task = async move {
        let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
        let mut client_stream = client_conn.accept_stream().await.unwrap();
        
        client_stream.send(b"survive this!").await.unwrap();
        let resp = timeout(Duration::from_secs(120), client_stream.recv()).await.unwrap().unwrap();
        
        resp.to_vec()
    };

    let res = timeout(Duration::from_secs(60), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "High packet loss caused the connection to fail entirely");
    let inner_res = res.unwrap();
    assert_eq!(&inner_res[..], b"survive this!", "Protocol failed under 50% packet loss");
}

#[tokio::test]
async fn chaos_reordering_and_duplication() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // 30% reorder, 30% duplication, 20ms base latency, 50ms jitter
    let proxy_addr = run_proxy("127.0.0.1:0", server_addr, 0.0, 0.3, 0.3, 20, 50).await;

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                // Expect a large payload to trigger multiple packets
                let mut received = Vec::new();
                while received.len() < 100 * 1024 { // 100 KB
                    if let Ok(Some(chunk)) = timeout(Duration::from_secs(15), stream.recv()).await {
                        received.extend_from_slice(&chunk);
                    } else {
                        break;
                    }
                }
                let _ = stream.send(b"got it").await;
            }
        }
    });

    let client_task = async move {
        let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
        let mut client_stream = client_conn.accept_stream().await.unwrap();
        
        let payload = vec![0xBB; 100 * 1024]; // 100 KB payload
        client_stream.send(&payload).await.unwrap();
        
        let resp = timeout(Duration::from_secs(120), client_stream.recv()).await.unwrap().unwrap();
        resp.to_vec()
    };

    let res = timeout(Duration::from_secs(180), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "Reordering/Duplication caused timeout");
    let inner_res = res.unwrap();
    assert_eq!(&inner_res[..], b"got it", "Protocol failed under reordering and duplication");
}

#[tokio::test]
async fn chaos_network_partition() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_clone = proxy.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client_addr = None;
        let start = std::time::Instant::now();

        loop {
            if let Ok((len, src)) = proxy_clone.recv_from(&mut buf).await {
                // Partition network between 2s and 7s
                let elapsed = start.elapsed().as_secs();
                if elapsed >= 2 && elapsed <= 7 {
                    continue; // blackhole
                }

                let dest = if src != server_addr {
                    client_addr = Some(src);
                    server_addr
                } else {
                    match client_addr {
                        Some(addr) => addr,
                        None => continue,
                    }
                };

                let _ = proxy_clone.send_to(&buf[..len], dest).await;
            }
        }
    });

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                // read a bunch of data over a long time
                for _ in 0..10 {
                    if let Ok(Some(_)) = timeout(Duration::from_secs(10), stream.recv()).await {
                        let _ = stream.send(b"ack").await;
                    } else {
                        break;
                    }
                }
            }
        }
    });

    let client_task = async move {
        let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
        let mut client_stream = client_conn.accept_stream().await.unwrap();
        
        for i in 0..10 {
            client_stream.send(format!("msg {}", i).as_bytes()).await.unwrap();
            let _ = timeout(Duration::from_secs(60), client_stream.recv()).await.unwrap().unwrap();
            sleep(Duration::from_millis(1000)).await; // send 1 msg per sec
        }
    };

    let res = timeout(Duration::from_secs(180), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "Network partition caused test timeout");
}

async fn run_asymmetric_proxy(
    proxy_addr: &str,
    server_addr: std::net::SocketAddr,
    client_to_server_drop: f64,
    server_to_client_drop: f64,
    latency_ms: u64,
) -> std::net::SocketAddr {
    let proxy = Arc::new(UdpSocket::bind(proxy_addr).await.unwrap());
    let local_addr = proxy.local_addr().unwrap();
    let proxy_clone = proxy.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client_addr = None;

        loop {
            if let Ok((len, src)) = proxy_clone.recv_from(&mut buf).await {
                let mut rng = rand::thread_rng();

                let (dest, drop_rate) = if src != server_addr {
                    client_addr = Some(src);
                    (server_addr, client_to_server_drop)
                } else {
                    match client_addr {
                        Some(addr) => (addr, server_to_client_drop),
                        None => continue,
                    }
                };

                if rng.gen_bool(drop_rate) {
                    continue;
                }

                let packet = buf[..len].to_vec();
                let proxy_for_send = proxy_clone.clone();

                tokio::spawn(async move {
                    if latency_ms > 0 {
                        sleep(Duration::from_millis(latency_ms)).await;
                    }
                    let _ = proxy_for_send.send_to(&packet, dest).await;
                });
            }
        }
    });

    local_addr
}

#[tokio::test]
async fn chaos_massive_jitter() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // 0% drop, 50ms base latency, 1500ms jitter!
    let proxy_addr = run_proxy("127.0.0.1:0", server_addr, 0.0, 0.0, 0.0, 50, 1500).await;

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                if let Ok(Some(data)) = timeout(Duration::from_secs(30), stream.recv()).await {
                    let _ = stream.send(&data).await;
                }
            }
        }
    });

    let client_task = async move {
        let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
        let mut client_stream = client_conn.accept_stream().await.unwrap();
        
        client_stream.send(b"jitter test").await.unwrap();
        let resp = timeout(Duration::from_secs(90), client_stream.recv()).await.unwrap().unwrap();
        resp.to_vec()
    };

    let res = timeout(Duration::from_secs(180), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "Massive jitter caused the connection to fail");
    let inner_res = res.unwrap();
    assert_eq!(&inner_res[..], b"jitter test", "Protocol failed under massive jitter");
}

#[tokio::test]
async fn chaos_asymmetric_links() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // Up: 0% drop, Down: 40% drop
    let proxy_addr = run_asymmetric_proxy("127.0.0.1:0", server_addr, 0.0, 0.4, 10).await;

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            if let Some(mut stream) = conn.accept_stream().await {
                if let Ok(Some(_data)) = timeout(Duration::from_secs(20), stream.recv()).await {
                    // Send a slightly larger payload to trigger multiple packets down the 40% loss link
                    let payload = vec![0xAA; 10 * 1024]; // 10 KB
                    let _ = stream.send(&payload).await;
                }
            }
        }
    });

    let client_task = async move {
        let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
        let mut client_stream = client_conn.accept_stream().await.unwrap();
        
        client_stream.send(b"request").await.unwrap();
        
        let mut received = Vec::new();
        while received.len() < 10 * 1024 {
            if let Ok(Some(chunk)) = timeout(Duration::from_secs(90), client_stream.recv()).await {
                received.extend_from_slice(&chunk);
            } else {
                break;
            }
        }
        received
    };

    let res = timeout(Duration::from_secs(300), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "Asymmetric link caused timeout");
    let inner_res = res.unwrap();
    assert_eq!(inner_res.len(), 10 * 1024, "Did not receive full payload under asymmetric link");
}

#[tokio::test]
async fn chaos_concurrent_streams_multiplexing() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // 20% drop, 10ms latency
    let proxy_addr = run_proxy("127.0.0.1:0", server_addr, 0.2, 0.0, 0.0, 10, 0).await;

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move {
        if let Some(mut conn) = server.accept().await {
            let mut handles = Vec::new();
            for _ in 0..10 {
                if let Some(mut stream) = conn.accept_stream().await {
                    handles.push(tokio::spawn(async move {
                        let mut received = Vec::new();
                        while received.len() < 10 * 1024 {
                            if let Ok(Some(chunk)) = timeout(Duration::from_secs(120), stream.recv()).await {
                                received.extend_from_slice(&chunk);
                            } else {
                                break;
                            }
                        }
                        let _ = stream.send(b"done").await;
                    }));
                }
            }
            for handle in handles {
                let _ = handle.await;
            }
        }
    });

    let client_task = async move {
        let client_conn = client_ep.connect(proxy_addr).await.unwrap();
        
        let mut handles = Vec::new();
        for _ in 0..10 {
            let mut stream = client_conn.open_stream().await.unwrap();
            handles.push(tokio::spawn(async move {
                let payload = vec![0xCC; 10 * 1024];
                stream.send(&payload).await.unwrap();
                
                let resp = timeout(Duration::from_secs(120), stream.recv()).await.unwrap().unwrap();
                resp.to_vec()
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }
        results
    };

    let res = timeout(Duration::from_secs(300), client_task).await;
    let _ = server_task.await;

    assert!(res.is_ok(), "Concurrent streams multiplexing caused timeout");
    let inner_res = res.unwrap();
    for r in inner_res {
        assert_eq!(&r[..], b"done", "Stream failed to receive 'done' ack");
    }
}
