//! Two-tier binary allowlist evaluation (`決定記録 L-04`), streaming SHA-256 hashing,
//! and Windows Authenticode signature verification (`WinVerifyTrust` + `CryptQueryObject`).

mod authenticode;
mod ffi;
mod matcher;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use ledr_proto::AuthenticodeInfo;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use authenticode::inspect_authenticode;
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
    /// Inspects `path` on disk, collecting streaming SHA-256 and Authenticode metadata gracefully.
    pub fn from_path(path: impl AsRef<Path>) -> Self {
        let p = path.as_ref();
        Self {
            exe_path: p.to_string_lossy().into_owned(),
            sha256: compute_file_sha256_hex(p).ok(),
            authenticode: inspect_authenticode(p),
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
