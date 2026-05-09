use std::time::Duration;

use tokio::time::timeout;
use zetta_transport::transport::endpoint::ZtEndpoint;
use zetta_transport::stream::ZtConnectionHandle;

async fn make_connected_pair() -> (ZtConnectionHandle, ZtConnectionHandle) {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move { server.accept().await.unwrap() });

    let client_conn = client_ep.connect(server_addr).await.unwrap();
    let server_conn = timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();

    (client_conn, server_conn)
}

#[tokio::test]
async fn handshake_completes() {
    let (_client, _server) = make_connected_pair().await;
}

#[tokio::test]
async fn send_recv_small_message() {
    let (mut client_conn, mut server_conn) = make_connected_pair().await;

    let client_stream = client_conn.accept_stream().await.unwrap();
    let mut server_stream = server_conn.accept_stream().await.unwrap();

    client_stream.send(b"hello").await.unwrap();

    let received = timeout(Duration::from_secs(2), server_stream.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&received[..], b"hello");
}

#[tokio::test]
async fn send_recv_large_message() {
    let (mut client_conn, mut server_conn) = make_connected_pair().await;
    let client_stream = client_conn.accept_stream().await.unwrap();
    let mut server_stream = server_conn.accept_stream().await.unwrap();

    let big = vec![0xABu8; 64 * 1024];
    client_stream.send(&big).await.unwrap();

    let mut received = Vec::new();
    while received.len() < big.len() {
        let chunk = timeout(Duration::from_secs(3), server_stream.recv())
            .await
            .unwrap()
            .unwrap();
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, big);
}

#[tokio::test]
async fn multiple_streams() {
    let (mut client_conn, mut server_conn) = make_connected_pair().await;

    let s0_client = client_conn.accept_stream().await.unwrap();
    let mut s0_server = server_conn.accept_stream().await.unwrap();

    let s1_client = client_conn.open_stream().await.unwrap();
    s1_client.send(b"stream1").await.unwrap();

    let mut s1_server = timeout(Duration::from_secs(2), server_conn.accept_stream())
        .await
        .unwrap()
        .unwrap();

    s0_client.send(b"stream0").await.unwrap();

    let r0 = timeout(Duration::from_secs(2), s0_server.recv())
        .await
        .unwrap()
        .unwrap();
    let r1 = timeout(Duration::from_secs(2), s1_server.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&r0[..], b"stream0");
    assert_eq!(&r1[..], b"stream1");
}

#[tokio::test]
async fn bidirectional_send_recv() {
    let (mut client_conn, mut server_conn) = make_connected_pair().await;
    let mut cs = client_conn.accept_stream().await.unwrap();
    let mut ss = server_conn.accept_stream().await.unwrap();

    cs.send(b"ping").await.unwrap();
    let ping = timeout(Duration::from_secs(2), ss.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ping[..], b"ping");

    ss.send(b"pong").await.unwrap();
    let pong = timeout(Duration::from_secs(2), cs.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&pong[..], b"pong");
}

#[tokio::test]
async fn psk_mismatch_fails() {
    let server = ZtEndpoint::bind("127.0.0.1:0", Some([1u8; 32]))
        .await
        .unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_ep = ZtEndpoint::bind("127.0.0.1:0", Some([2u8; 32]))
        .await
        .unwrap();

    let server_task = tokio::spawn(async move { server.accept().await });

    let result = timeout(Duration::from_secs(2), client_ep.connect(server_addr)).await;
    let Ok(Ok(mut client_conn)) = result else {
        return;
    };

    let Ok(Ok(Some(mut server_conn))) = timeout(Duration::from_secs(2), server_task).await else {
        return;
    };

    let client_stream = match timeout(Duration::from_secs(2), client_conn.accept_stream()).await {
        Ok(Some(s)) => s,
        _ => return,
    };
    let mut server_stream = match timeout(Duration::from_secs(2), server_conn.accept_stream()).await
    {
        Ok(Some(s)) => s,
        _ => return,
    };

    client_stream.send(b"psk-test").await.unwrap();

    let recv_result = timeout(Duration::from_secs(2), server_stream.recv()).await;
    assert!(recv_result.is_err() || recv_result.unwrap().is_none());
}

#[tokio::test]
async fn packet_loss_retransmission() {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();
    let server_addr = server.local_addr().unwrap();

    // Create a simple UDP proxy that drops 20% of packets to test retransmission
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client_addr = None;
        let mut counter = 0;
        
        loop {
            if let Ok((len, src)) = proxy.recv_from(&mut buf).await {
                counter += 1;
                // Drop every 5th packet (20% loss)
                if counter % 5 == 0 {
                    continue;
                }
                
                if src != server_addr {
                    client_addr = Some(src);
                    let _ = proxy.send_to(&buf[..len], server_addr).await;
                } else if let Some(ca) = client_addr {
                    let _ = proxy.send_to(&buf[..len], ca).await;
                }
            }
        }
    });

    let client_ep = ZtEndpoint::bind("127.0.0.1:0", None).await.unwrap();

    let server_task = tokio::spawn(async move { 
        let mut conn = server.accept().await.unwrap();
        let mut stream = conn.accept_stream().await.unwrap();
        let data = timeout(Duration::from_secs(10), stream.recv()).await.unwrap().unwrap();
        assert_eq!(&data[..], b"lossy delivery success");
        stream.send(b"server ack").await.unwrap();
    });

    // Connect to proxy instead of server
    let mut client_conn = client_ep.connect(proxy_addr).await.unwrap();
    let mut client_stream = client_conn.accept_stream().await.unwrap();
    
    // This payload is small but because of the handshake and subsequent ACKs, 
    // packets will be dropped and must be retransmitted.
    client_stream.send(b"lossy delivery success").await.unwrap();

    let server_ack = timeout(Duration::from_secs(10), client_stream.recv())
        .await
        .expect("Timeout waiting for server ack")
        .expect("Connection closed before server ack");
    assert_eq!(&server_ack[..], b"server ack");

    let _ = timeout(Duration::from_secs(10), server_task).await.unwrap();
}
