//! Zero-parse 4-byte little-endian Native Messaging frame relay (`AUTO-11`).

use std::fmt;
use std::io::{ErrorKind, Read, Write};

use anyhow::Result;
use ledr_proto::{IpcResponse, IPC_MAX_FRAME_BYTES};

use crate::pipe_client::{BridgeTransportError, PipeClient};

/// Chunk size used when streaming Native Messaging payloads into memory (8 KiB).
pub const RELAY_READ_CHUNK_BYTES: usize = 8 * 1024;

/// Transport abstraction allowing unit tests to inject mock Named Pipe exchanges.
pub trait FrameExchange {
    fn exchange_raw_frame(&self, payload: &[u8]) -> Result<Vec<u8>, BridgeTransportError>;
}

impl FrameExchange for PipeClient {
    fn exchange_raw_frame(&self, payload: &[u8]) -> Result<Vec<u8>, BridgeTransportError> {
        PipeClient::exchange_raw_frame(self, payload)
    }
}

/// Errors raised while reading or writing raw 4-byte LE Native Messaging frames.
#[derive(Debug)]
pub enum RawFrameError {
    EmptyFrame,
    FrameTooLarge { size: usize, max: usize },
    TruncatedHeader { actual: usize },
    TruncatedPayload { expected: usize, actual: usize },
    Io(std::io::Error),
}

impl fmt::Display for RawFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFrame => write!(f, "empty Native Messaging frame (0-byte payload)"),
            Self::FrameTooLarge { size, max } => {
                write!(f, "Native Messaging frame {size} bytes exceeds max {max} bytes")
            }
            Self::TruncatedHeader { actual } => {
                write!(f, "truncated 4-byte frame header: got {actual} bytes")
            }
            Self::TruncatedPayload { expected, actual } => {
                write!(f, "truncated frame payload: expected {expected} bytes, got {actual}")
            }
            Self::Io(err) => write!(f, "frame I/O error: {err}"),
        }
    }
}

impl std::error::Error for RawFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RawFrameError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Summary counters returned when the relay loop reaches a clean `stdin` EOF.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub frames_relayed: u64,
    pub frames_errored: u64,
}

/// Reads one raw 4-byte LE length-prefixed payload without parsing JSON (`AUTO-11`).
///
/// Returns `Ok(None)` on clean EOF at the frame boundary.
pub fn read_raw_frame<R: Read>(
    reader: &mut R,
    max_bytes: usize,
) -> std::result::Result<Option<Vec<u8>>, RawFrameError> {
    let mut len_buf = [0u8; 4];
    let mut header_read = 0usize;
    while header_read < 4 {
        match reader.read(&mut len_buf[header_read..]) {
            Ok(0) => {
                if header_read == 0 {
                    return Ok(None);
                }
                return Err(RawFrameError::TruncatedHeader {
                    actual: header_read,
                });
            }
            Ok(n) => header_read += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(RawFrameError::Io(err)),
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(RawFrameError::EmptyFrame);
    }
    if len > max_bytes {
        return Err(RawFrameError::FrameTooLarge {
            size: len,
            max: max_bytes,
        });
    }

    let mut payload = Vec::with_capacity(len.min(RELAY_READ_CHUNK_BYTES));
    let mut chunk = [0u8; RELAY_READ_CHUNK_BYTES];
    while payload.len() < len {
        let to_read = (len - payload.len()).min(chunk.len());
        match reader.read(&mut chunk[..to_read]) {
            Ok(0) => {
                return Err(RawFrameError::TruncatedPayload {
                    expected: len,
                    actual: payload.len(),
                });
            }
            Ok(n) => payload.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(RawFrameError::Io(err)),
        }
    }

    Ok(Some(payload))
}

/// Writes one raw 4-byte LE length-prefixed payload and flushes immediately.
pub fn write_raw_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    max_bytes: usize,
) -> std::result::Result<(), RawFrameError> {
    if payload.is_empty() {
        return Err(RawFrameError::EmptyFrame);
    }
    if payload.len() > max_bytes {
        return Err(RawFrameError::FrameTooLarge {
            size: payload.len(),
            max: max_bytes,
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| RawFrameError::FrameTooLarge {
        size: payload.len(),
        max: max_bytes,
    })?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

/// Runs the Chrome Native Messaging stdio <-> Named Pipe zero-parse relay loop.
///
/// Logs are strictly written to `stderr`; `stdout` only ever receives valid 4-byte LE frames.
pub fn run_relay_loop<R: Read, W: Write, E: Write, X: FrameExchange>(
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
    exchange: &X,
) -> Result<RelayStats> {
    let mut stats = RelayStats::default();
    loop {
        let payload = match read_raw_frame(stdin, IPC_MAX_FRAME_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(stats),
            Err(err) => {
                let _ = writeln!(stderr, "[ledr-bridge-nm] stdin frame error: {err}");
                let _ = stderr.flush();
                return Err(err.into());
            }
        };

        match exchange.exchange_raw_frame(&payload) {
            Ok(resp_bytes) => {
                write_raw_frame(stdout, &resp_bytes, IPC_MAX_FRAME_BYTES)?;
                stats.frames_relayed += 1;
            }
            Err(err) => {
                let _ = writeln!(stderr, "[ledr-bridge-nm] pipe transport error: {err}");
                let _ = stderr.flush();
                let err_resp = IpcResponse::Error {
                    code: err.ipc_error_code().to_string(),
                    message: err.to_string(),
                };
                let json = serde_json::to_vec(&err_resp)?;
                write_raw_frame(stdout, &json, IPC_MAX_FRAME_BYTES)?;
                stats.frames_errored += 1;
            }
        }
    }
}
