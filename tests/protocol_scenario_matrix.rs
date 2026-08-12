#![cfg(feature = "testing")]

mod support;

use std::time::Duration;
use support::{TestResult, deterministic_payload, echo_transfer};
use zetta_transport::config::ZtConfig;
use zetta_transport::error::ZtError;
use zetta_transport::transport::StreamType;
use zetta_transport::transport::endpoint::ZtEndpoint;

#[tokio::test]
async fn boundary_payload_matrix_is_byte_exact() -> TestResult {
    for (case, size) in [1, 2, 63, 64, 511, 512, 1135, 1136, 1137, 4095, 4096, 65_537]
        .into_iter()
        .enumerate()
    {
        echo_transfer(
            ZtConfig::default(),
            ZtConfig::default(),
            deterministic_payload(size, case as u64 + 1),
            Duration::from_secs(10),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn asymmetric_transport_parameters_are_enforced() -> TestResult {
    let server_config = ZtConfig {
        max_concurrent_streams: 2,
        initial_stream_window: 4096,
        initial_max_data: 8192,
        idle_timeout: Duration::from_secs(5),
        ..ZtConfig::default()
    };
    let server = ZtEndpoint::bind_with_zt_config("127.0.0.1:0", server_config).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut connection = server.accept().await.expect("connection");
        for _ in 0..2 {
            let mut stream = connection.accept_stream().await.expect("stream");
            assert!(stream.recv_result().await.unwrap().is_some());
        }
    });

    let client = ZtEndpoint::bind_with_zt_config(
        "127.0.0.1:0",
        ZtConfig {
            max_concurrent_streams: 11,
            initial_stream_window: 32 * 1024,
            initial_max_data: 64 * 1024,
            idle_timeout: Duration::from_secs(30),
            ..ZtConfig::default()
        },
    )
    .await?;
    let connection = client.connect(server_addr).await?;
    let first = connection.open_stream().await?;
    let second = connection.open_stream().await?;
    assert!(matches!(
        connection.open_stream().await,
        Err(ZtError::TooManyStreams { limit: 2 })
    ));
    first.send(b"one").await?;
    second.send(b"two").await?;
    server_task.await?;
    Ok(())
}

#[tokio::test]
async fn unidirectional_wire_semantics_are_directional() -> TestResult {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut connection = server.accept().await.expect("connection");
        let mut incoming = connection.accept_stream().await.expect("stream");
        assert_eq!(incoming.stream_type(), StreamType::UnidirectionalIn);
        assert_eq!(
            incoming.recv_result().await.unwrap().unwrap(),
            b"client to server"[..]
        );
        assert!(incoming.send(b"forbidden").await.is_err());

        let outgoing = connection
            .open_stream_with_type(StreamType::UnidirectionalOut)
            .await
            .expect("server outgoing stream");
        outgoing.send(b"server to client").await.unwrap();
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let mut connection = client.connect(server_addr).await?;
    assert!(
        connection
            .open_stream_with_type(StreamType::UnidirectionalIn)
            .await
            .is_err()
    );
    let mut outgoing = connection
        .open_stream_with_type(StreamType::UnidirectionalOut)
        .await?;
    outgoing.send(b"client to server").await?;
    assert!(outgoing.recv_result().await?.is_none());

    let mut incoming = connection
        .accept_stream()
        .await
        .expect("client incoming stream");
    assert_eq!(incoming.stream_type(), StreamType::UnidirectionalIn);
    assert_eq!(
        incoming.recv_result().await?.unwrap(),
        b"server to client"[..]
    );
    server_task.await?;
    Ok(())
}

#[tokio::test]
async fn negotiated_idle_timeout_surfaces_as_typed_error() -> TestResult {
    let short_idle = ZtConfig {
        idle_timeout: Duration::from_secs(3),
        ..ZtConfig::default()
    };
    let server = ZtEndpoint::bind_with_zt_config("127.0.0.1:0", short_idle.clone()).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut connection = server.accept().await.expect("connection");
        connection.accept_stream_result().await
    });
    let client = ZtEndpoint::bind_with_zt_config("127.0.0.1:0", short_idle).await?;
    let mut connection = client.connect(server_addr).await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), connection.recv_datagram_result()).await?,
        Err(ZtError::IdleTimeout)
    ));
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), server_task).await??,
        Err(ZtError::IdleTimeout)
    ));
    Ok(())
}

#[tokio::test]
async fn stream_reset_error_code_reaches_the_reader() -> TestResult {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let mut connection = server.accept().await.expect("connection");
        let mut stream = connection.accept_stream().await.expect("stream");
        assert_eq!(stream.recv_result().await.unwrap().unwrap(), b"trigger"[..]);
        stream.reset(0xdead).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let connection = client.connect(server_addr).await?;
    let mut stream = connection.open_stream().await?;
    stream.send(b"trigger").await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), stream.recv_result()).await?,
        Err(ZtError::StreamReset {
            error_code: 0xdead,
            ..
        })
    ));
    server_task.await?;
    Ok(())
}

#[tokio::test]
async fn connection_close_reason_reaches_all_result_apis() -> TestResult {
    let server = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let server_addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let connection = server.accept().await.expect("connection");
        connection
            .close_with_error(77, "maintenance window")
            .await
            .unwrap();
    });

    let client = ZtEndpoint::bind("127.0.0.1:0", None).await?;
    let mut connection = client.connect(server_addr).await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), connection.recv_datagram_result()).await?,
        Err(ZtError::ConnectionClosedByPeer { error_code: 77, ref reason })
            if reason == "maintenance window"
    ));
    server_task.await?;
    Ok(())
}
