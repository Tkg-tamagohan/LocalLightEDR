use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ledr_proto::AuthenticodeInfo;
use ledr_rules::{
    compute_file_sha256_hex, compute_file_sha256_hex_cancellable, inspect_authenticode,
    BinaryIdentity,
};

const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;

/// Abstraction for inspecting binary SHA-256 and Authenticode metadata (`L-04`).
pub trait BinaryInspector: Send + Sync {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity;

    /// Computes or returns only the SHA-256 hex digest of `exe_path` without Authenticode
    /// verification overhead (`Phase 4A` MOTW hot-path optimization).
    fn compute_sha256(&self, exe_path: &str) -> Option<String> {
        self.inspect(exe_path).sha256
    }

    /// Computes the SHA-256 hex digest of `exe_path` with a size cap (`max_bytes`) and
    /// cooperative cancellation (`cancel`).
    ///
    /// # Guarantee Scope
    ///
    /// - [`WindowsBinaryInspector`] streams the file in 64 KiB chunks via
    ///   [`ledr_rules::compute_file_sha256_hex_cancellable`], enforcing `max_bytes` before and
    ///   during reads and honoring `cancel` between chunks.
    /// - The default trait implementation delegates to [`Self::compute_sha256`] and therefore
    ///   cannot interrupt an in-flight custom implementation mid-read. It checks `cancel` before
    ///   and after calling [`Self::compute_sha256`], and when `exe_path` resolves to an existing
    ///   filesystem entry (`std::fs::metadata` succeeds), returns `Ok(None)` if the entry is not
    ///   a regular file or exceeds `max_bytes` (while allowing [`io::ErrorKind::NotFound`] paths
    ///   to pass through for in-memory test mocks). Custom production inspectors passed to
    ///   [`crate::DaemonEngine::start_with_dependencies`] or related constructors should override
    ///   this method when mid-read cancellation or custom size limits are required.
    fn compute_sha256_cancellable(
        &self,
        exe_path: &str,
        max_bytes: u64,
        cancel: &AtomicBool,
    ) -> io::Result<Option<String>> {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "SHA-256 hashing cancelled",
            ));
        }
        if exe_path.trim().is_empty() {
            return Ok(None);
        }
        match std::fs::metadata(Path::new(exe_path)) {
            Ok(meta) if !meta.is_file() || meta.len() > max_bytes => return Ok(None),
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let digest = self.compute_sha256(exe_path);
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "SHA-256 hashing cancelled",
            ));
        }
        Ok(digest)
    }
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

    fn compute_sha256(&self, exe_path: &str) -> Option<String> {
        if exe_path.trim().is_empty() {
            return None;
        }
        let path = Path::new(exe_path);
        let Ok(meta) = std::fs::metadata(path) else {
            return None;
        };
        if !meta.is_file() {
            return None;
        }
        compute_file_sha256_hex(path).ok()
    }

    fn compute_sha256_cancellable(
        &self,
        exe_path: &str,
        max_bytes: u64,
        cancel: &AtomicBool,
    ) -> io::Result<Option<String>> {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "SHA-256 hashing cancelled",
            ));
        }
        if exe_path.trim().is_empty() {
            return Ok(None);
        }
        compute_file_sha256_hex_cancellable(Path::new(exe_path), max_bytes, cancel)
    }
}

/// Abstraction for on-demand live OS process inspection used when `Kernel-File` delivers a
/// `CanaryFileAccess` event before `Kernel-Process` delivers `ProcessStart`.
pub trait LiveProcessInspector: Send + Sync {
    fn inspect_live_process(&self, pid: u32) -> Option<ledr_sensor_win::etw::LiveProcessInfo>;
}

/// Default Windows live-process inspector backed by [`ledr_sensor_win::etw::inspect_live_process`].
#[derive(Debug, Default)]
pub struct WindowsLiveProcessInspector;

impl WindowsLiveProcessInspector {
    pub fn new() -> Self {
        Self
    }
}

impl LiveProcessInspector for WindowsLiveProcessInspector {
    fn inspect_live_process(&self, pid: u32) -> Option<ledr_sensor_win::etw::LiveProcessInfo> {
        ledr_sensor_win::etw::inspect_live_process(pid)
    }
}
