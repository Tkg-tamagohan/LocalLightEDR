//! Layer 2 LocalEDR resident core daemon (Windows Service and foreground dev mode).

use ledr_proto::{
    ActiveDefenseController, ProcessIdentity, SensorBackend, SensorEvent, IPC_PIPE_NAME,
};
use ledr_rules::{engine_version, evaluate_stub};
use ledr_sensor_win::{crate_name, etw::NoopSensorBackend, NoopDefenseController};
use ledr_store::{default_retention_days, store_version};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _env_filter = tracing_subscriber::EnvFilter::new("info");
    let instance_uuid = uuid::Uuid::new_v4();

    let mut sensor = NoopSensorBackend;
    let _ = sensor.start();

    let defense = NoopDefenseController;
    let sample_target = ProcessIdentity {
        pid: 0,
        create_time_100ns: 0,
    };
    let _ = defense.resume_process(&sample_target);

    let probe_event = SensorEvent::ProcessStop {
        pid: 0,
        exit_time_100ns: 0,
        exit_code: 0,
    };
    let matched = evaluate_stub(&probe_event);
    let _ = sensor.stop();

    println!(
        "ledr-daemon (Phase 0 skeleton, id={}) | pipe={} | sensor={} | rules={} (probe_match={}) | store={} (ttl_days={})",
        instance_uuid,
        IPC_PIPE_NAME,
        crate_name(),
        engine_version(),
        matched,
        store_version(),
        default_retention_days(),
    );

    Ok(())
}
