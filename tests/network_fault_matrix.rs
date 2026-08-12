#![cfg(feature = "testing")]

mod support;

use std::time::Duration;
use support::{TestResult, deterministic_payload, echo_transfer};
use zetta_transport::config::ZtConfig;
use zetta_transport::simulation::SimulationConfig;

async fn run_fault_case(simulation: SimulationConfig, size: usize, seed: u64) -> TestResult {
    let config = ZtConfig {
        simulation,
        idle_timeout: Duration::from_secs(20),
        ..ZtConfig::default()
    };
    let stats = echo_transfer(
        config.clone(),
        config,
        deterministic_payload(size, seed),
        Duration::from_secs(25),
    )
    .await?;
    assert!(stats.bytes_sent >= size);
    Ok(())
}

#[tokio::test]
async fn deterministic_loss_and_reordering_matrix_recovers() -> TestResult {
    for (seed, simulation) in [
        SimulationConfig::new(10, 0, 0).with_seed(1),
        SimulationConfig::new(0, 25, 35).with_seed(2),
        SimulationConfig::new(8, 20, 25).with_seed(3),
        SimulationConfig::new(0, 0, 0)
            .with_seed(4)
            .with_periodic_drop(7),
    ]
    .into_iter()
    .enumerate()
    {
        run_fault_case(simulation, 96 * 1024, seed as u64 + 10).await?;
    }
    Ok(())
}

#[tokio::test]
async fn burst_loss_recovery_preserves_order_and_content() -> TestResult {
    run_fault_case(
        SimulationConfig::new(0, 0, 0)
            .with_seed(0xbad5eed)
            .with_burst_loss(17, 3),
        192 * 1024,
        0x5151,
    )
    .await
}

#[tokio::test]
async fn pmtud_converges_below_a_silent_mtu_blackhole() -> TestResult {
    let simulation = SimulationConfig::new(0, 0, 0)
        .with_seed(99)
        .with_blackhole_mtu(1450);
    let config = ZtConfig {
        simulation,
        mtu_probe_interval: Duration::from_millis(40),
        idle_timeout: Duration::from_secs(10),
        ..ZtConfig::default()
    };
    let stats = echo_transfer(
        config.clone(),
        config,
        deterministic_payload(128 * 1024, 0xface),
        Duration::from_secs(20),
    )
    .await?;
    assert!(stats.mtu <= 1450);
    assert!(stats.mtu_probe_failures > 0);
    Ok(())
}
