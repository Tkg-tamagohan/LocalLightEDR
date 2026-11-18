//! Chrome Native Messaging host bridge forwarding 4-byte LE framed JSON to the LocalEDR Named Pipe.

use ledr_proto::{IPC_MAX_FRAME_BYTES, IPC_PIPE_NAME};

fn main() -> anyhow::Result<()> {
    let reg_key_type = std::any::type_name::<winreg::RegKey>();
    println!(
        "ledr-bridge-nm (Phase 0 skeleton) — pipe: {}, max_frame_bytes: {}, reg_type: {}",
        IPC_PIPE_NAME, IPC_MAX_FRAME_BYTES, reg_key_type
    );
    Ok(())
}
