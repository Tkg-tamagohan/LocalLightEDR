//! Harmless attack-simulation CLI for validating LocalEDR detection and active defense.

use ledr_proto::IPC_PIPE_NAME;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!(
        "ledr-sim (Phase 0 skeleton) — target daemon pipe: {}",
        IPC_PIPE_NAME
    );
    println!(
        "Planned scenarios (Phase 1+): lotl-powershell, dns-tcp-connect, canary-cookie-open, honeypot-write, motw-binary"
    );
    Ok(())
}
