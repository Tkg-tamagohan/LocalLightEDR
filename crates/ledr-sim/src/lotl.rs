//! Harmless Living-Off-The-Land (`cmd.exe -> powershell.exe -EncodedCommand`) simulator.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;

use super::types::LotlOutcome;

/// Harmless PowerShell command encoded into UTF-16LE Base64 for the LOTL scenario.
pub const LOTL_HARMLESS_SCRIPT: &str = "Write-Output LocalEDR-Sim-LOTL";
const LOTL_TIMEOUT: Duration = Duration::from_secs(20);

/// Encodes `script` into PowerShell `-EncodedCommand` UTF-16LE Base64 format.
pub fn encode_powershell_command_utf16le(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    base64_encode(&bytes)
}

/// Builds the argument vector passed to `cmd.exe` for the harmless LOTL simulation.
pub fn build_lotl_cmd_args() -> Vec<String> {
    let encoded = encode_powershell_command_utf16le(LOTL_HARMLESS_SCRIPT);
    vec![
        "/c".to_string(),
        "powershell.exe".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-EncodedCommand".to_string(),
        encoded,
    ]
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }

    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Spawns `cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand <b64>`.
pub async fn run_lotl_scenario() -> Result<LotlOutcome> {
    let args = build_lotl_cmd_args();
    let command_line = format!("cmd.exe {}", args.join(" "));

    let child = Command::new("cmd.exe")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn cmd.exe for LOTL simulation")?;

    let spawned_pid = child.id().unwrap_or(0);
    let output = tokio::time::timeout(LOTL_TIMEOUT, child.wait_with_output())
        .await
        .context("timed out waiting for harmless LOTL powershell command")?
        .context("failed waiting for cmd.exe child process")?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(LotlOutcome {
        spawned_pid,
        exit_code,
        command_line,
        stdout,
    })
}
