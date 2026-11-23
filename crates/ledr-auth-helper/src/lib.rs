//! Out-of-process Windows Authenticode verification helper (`FU-E2E-03` Track 2, Option 2-A).
//!
//! Isolates `wintrust.dll` and `crypt32.dll` (`raw-dylib` FFI) out of `ledr-daemon.exe` so the
//! resident daemon avoids permanent `MEM_IMAGE`/`MEM_MAPPED` DLL and `.cat` catalog bloat.

pub mod authenticode;
mod ffi;

use std::io::{self, Read, Write};

use ledr_proto::AuthenticodeInfo;
use serde::{Deserialize, Serialize};

pub use authenticode::{inspect_authenticode, LOCAL_CERT_CHAIN_FLAGS};

/// Maximum framed payload size (64 KiB) for stdin/stdout IPC between `ledr-daemon` and `ledr-auth-helper`.
pub const MAX_AUTH_FRAME_BYTES: usize = 64 * 1024;

/// Default idle timeout (15 seconds) before `ledr-auth-helper` exits cleanly.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 15_000;

/// Framed JSON request sent from `ledr-daemon` to `ledr-auth-helper` over anonymous stdin pipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyRequest {
    pub id: u64,
    pub exe_path: String,
}

/// Framed JSON response written by `ledr-auth-helper` to anonymous stdout pipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyResponse {
    pub id: u64,
    pub authenticode: Option<AuthenticodeInfo>,
}

/// Reads a single 4-byte little-endian length-prefixed JSON frame (bounded by [`MAX_AUTH_FRAME_BYTES`]).
pub fn read_framed_json<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AUTH_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("auth helper frame size {len} out of bounds (1..={MAX_AUTH_FRAME_BYTES})"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("invalid auth helper JSON: {err}")))
}

/// Writes a single 4-byte little-endian length-prefixed JSON frame (bounded by [`MAX_AUTH_FRAME_BYTES`]).
pub fn write_framed_json<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("failed serializing auth helper JSON: {err}")))?;
    if payload.is_empty() || payload.len() > MAX_AUTH_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "auth helper frame size {} out of bounds (1..={MAX_AUTH_FRAME_BYTES})",
                payload.len()
            ),
        ));
    }
    let len = u32::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "auth helper payload length overflows u32",
        )
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}
