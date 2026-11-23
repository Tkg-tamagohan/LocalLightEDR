//! Two-tier binary allowlist evaluation (`決定記録 L-04`) and streaming SHA-256 hashing.
//!
//! Windows Authenticode FFI (`wintrust.dll` / `crypt32.dll`) is intentionally isolated in the
//! out-of-process `ledr-auth-helper` crate (`FU-E2E-03` Track 2, Option 2-A) so `ledr-rules`
//! and `ledr-daemon` production builds never link `wintrust.dll` or `crypt32.dll`.

mod matcher;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use ledr_proto::AuthenticodeInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use matcher::{is_allowed_by_rules, matches_path_pattern, signer_subject_matches};

const SHA256_BUF_LEN: usize = 65_536;

/// Resolved identity of an executable binary used for two-tier allowlist checks (`L-04`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryIdentity {
    pub exe_path: String,
    pub sha256: Option<String>,
    pub authenticode: Option<AuthenticodeInfo>,
}

impl BinaryIdentity {
    /// Inspects `path` on disk for streaming SHA-256 only (`authenticode: None`), without
    /// loading `wintrust.dll` or `crypt32.dll` (`FU-E2E-03` Track 2).
    pub fn from_path_sha256_only(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        Self {
            exe_path: p.to_string_lossy().into_owned(),
            sha256: compute_file_sha256_hex(p).ok(),
            authenticode: None,
        }
    }

    /// Inspects `path` on disk in tests using `ledr-auth-helper`'s in-process Authenticode
    /// verifier (`dev-dependencies` only; never compiled into production `ledr-rules`).
    #[cfg(test)]
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        Self {
            exe_path: p.to_string_lossy().into_owned(),
            sha256: compute_file_sha256_hex(p).ok(),
            authenticode: ledr_auth_helper::inspect_authenticode(p),
        }
    }
}

/// Computes the streaming lowercase hex SHA-256 digest of the file at `path`.
pub fn compute_file_sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SHA256_BUF_LEN];
    loop {
        let read_bytes = file.read(&mut buf)?;
        if read_bytes == 0 {
            break;
        }
        hasher.update(&buf[..read_bytes]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_cancelled_err() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "SHA-256 hashing cancelled")
}

/// Computes the streaming lowercase hex SHA-256 digest from `reader` in 64 KiB chunks,
/// returning `Ok(None)` when cumulative bytes exceed `max_bytes` and aborting with
/// `ErrorKind::Interrupted` when `cancel` becomes `true`.
pub fn compute_reader_sha256_hex_cancellable<R: Read>(
    reader: &mut R,
    max_bytes: u64,
    cancel: &AtomicBool,
) -> Result<Option<String>, io::Error> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SHA256_BUF_LEN];
    let mut total: u64 = 0;

    loop {
        if cancel.load(Ordering::Acquire) {
            return Err(sha256_cancelled_err());
        }
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read_bytes) => {
                if cancel.load(Ordering::Acquire) {
                    return Err(sha256_cancelled_err());
                }
                let n_u64 = u64::try_from(read_bytes).unwrap_or(u64::MAX);
                total = total.saturating_add(n_u64);
                if total > max_bytes {
                    return Ok(None);
                }
                hasher.update(&buf[..read_bytes]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                if cancel.load(Ordering::Acquire) {
                    return Err(sha256_cancelled_err());
                }
            }
            Err(err) => return Err(err),
        }
    }

    Ok(Some(hex::encode(hasher.finalize())))
}

/// Computes the streaming lowercase hex SHA-256 digest of the regular file at `path` in
/// 64 KiB chunks, returning `Ok(None)` if not a regular file or larger than `max_bytes`,
/// `Err` if stat/open fails, and `ErrorKind::Interrupted` if cancelled via `cancel`.
pub fn compute_file_sha256_hex_cancellable(
    path: &Path,
    max_bytes: u64,
    cancel: &AtomicBool,
) -> Result<Option<String>, io::Error> {
    if cancel.load(Ordering::Acquire) {
        return Err(sha256_cancelled_err());
    }
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Ok(None);
    }
    let mut file = File::open(path)?;
    if file.metadata().is_ok_and(|m| m.len() > max_bytes) {
        return Ok(None);
    }
    compute_reader_sha256_hex_cancellable(&mut file, max_bytes, cancel)
}
