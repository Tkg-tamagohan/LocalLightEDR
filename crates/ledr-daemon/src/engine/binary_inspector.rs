use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use ledr_proto::AuthenticodeInfo;
use ledr_rules::{compute_file_sha256_hex, inspect_authenticode, BinaryIdentity};

const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;

/// Abstraction for inspecting binary SHA-256 and Authenticode metadata (`L-04`).
pub trait BinaryInspector: Send + Sync {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity;
}

/// Default Windows binary inspector computing fresh streaming SHA-256 on every call
/// and caching only `Option<AuthenticodeInfo>` keyed by `(lowercase_exe_path, fresh_sha256)`
/// (`L-04`, `SEC_0005` — prevents size/mtime `SetFileTime` cache spoofing).
#[derive(Debug, Default)]
pub struct WindowsBinaryInspector {
    authenticode_cache: Mutex<HashMap<(String, String), Option<AuthenticodeInfo>>>,
}

impl WindowsBinaryInspector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BinaryInspector for WindowsBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        if exe_path.trim().is_empty() {
            return BinaryIdentity {
                exe_path: String::new(),
                sha256: None,
                authenticode: None,
            };
        }

        let path = Path::new(exe_path);
        let Ok(meta) = std::fs::metadata(path) else {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        };
        if !meta.is_file() {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        }

        // Always recompute SHA-256 directly from file contents (SEC_0005).
        let Some(fresh_sha256) = compute_file_sha256_hex(path).ok() else {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        };

        let cache_key = (exe_path.to_ascii_lowercase(), fresh_sha256.clone());
        if let Ok(guard) = self.authenticode_cache.lock() {
            if let Some(cached_auth) = guard.get(&cache_key) {
                return BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(fresh_sha256),
                    authenticode: cached_auth.clone(),
                };
            }
        }

        let authenticode = inspect_authenticode(path);
        if let Ok(mut guard) = self.authenticode_cache.lock() {
            if guard.len() >= BINARY_INSPECTOR_CACHE_CAPACITY {
                guard.clear();
            }
            guard.insert(cache_key, authenticode.clone());
        }

        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some(fresh_sha256),
            authenticode,
        }
    }
}
