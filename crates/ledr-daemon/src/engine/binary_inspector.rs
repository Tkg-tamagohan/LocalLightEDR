use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ledr_proto::AuthenticodeInfo;
use ledr_rules::{compute_file_sha256_hex, compute_file_sha256_hex_cancellable, BinaryIdentity};

use super::auth_worker::{AuthWorkerClient, AuthWorkerConfig, AuthWorkerError};

const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;

/// Explicit inspection outcome distinguishing cooperative shutdown cancellation from an
/// unsigned or unreadable binary (`FU-E2E-05`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectOutcome {
    Completed(BinaryIdentity),
    Cancelled,
}

/// Abstraction for inspecting binary SHA-256 and Authenticode metadata (`L-04`).
pub trait BinaryInspector: Send + Sync {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity;

    /// Inspects `exe_path` with cooperative cancellation (`cancel`) and optional fast shutdown
    /// skip of cold disk/Authenticode work (`fast_skip_on_shutdown`).
    fn inspect_cancellable(
        &self,
        exe_path: &str,
        cancel: &AtomicBool,
        _fast_skip_on_shutdown: bool,
    ) -> InspectOutcome {
        if cancel.load(Ordering::Acquire) {
            return InspectOutcome::Cancelled;
        }
        let id = self.inspect(exe_path);
        if cancel.load(Ordering::Acquire) {
            return InspectOutcome::Cancelled;
        }
        InspectOutcome::Completed(id)
    }

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

    /// Returns `true` if `pid` belongs to this inspector's active out-of-process Authenticode
    /// helper, preventing recursive self-inspection (`FU-E2E-03` Track 2).
    fn is_helper_pid(&self, _pid: u32) -> bool {
        false
    }

    /// Terminates any active out-of-process worker and rejects future worker spawns (`FU-E2E-03`).
    fn shutdown(&self) {}
}

#[derive(Debug)]
struct LruSlot<K, V> {
    key: K,
    value: V,
    prev: Option<usize>,
    next: Option<usize>,
}

/// Bounded O(1) LRU cache (`FU-E2E-03` Track 1d) preserving hot entries across 512-entry
/// capacity limits and evicting only the least-recently-used item.
#[derive(Debug)]
struct BoundedLruCache<K, V> {
    capacity: usize,
    index: HashMap<K, usize>,
    slots: Vec<LruSlot<K, V>>,
    head: Option<usize>,
    tail: Option<usize>,
}

impl<K: Eq + Hash + Clone, V> BoundedLruCache<K, V> {
    fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            index: HashMap::with_capacity(cap),
            slots: Vec::with_capacity(cap),
            head: None,
            tail: None,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.index.len()
    }

    fn detach(&mut self, idx: usize) {
        let prev = self.slots[idx].prev;
        let next = self.slots[idx].next;
        match prev {
            Some(p) => self.slots[p].next = next,
            None => self.head = next,
        }
        match next {
            Some(n) => self.slots[n].prev = prev,
            None => self.tail = prev,
        }
        self.slots[idx].prev = None;
        self.slots[idx].next = None;
    }

    fn attach_front(&mut self, idx: usize) {
        self.slots[idx].prev = None;
        self.slots[idx].next = self.head;
        if let Some(old_head) = self.head {
            self.slots[old_head].prev = Some(idx);
        }
        self.head = Some(idx);
        if self.tail.is_none() {
            self.tail = Some(idx);
        }
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        let idx = *self.index.get(key)?;
        if self.head != Some(idx) {
            self.detach(idx);
            self.attach_front(idx);
        }
        Some(&self.slots[idx].value)
    }

    fn insert(&mut self, key: K, value: V) {
        if let Some(&idx) = self.index.get(&key) {
            self.slots[idx].value = value;
            if self.head != Some(idx) {
                self.detach(idx);
                self.attach_front(idx);
            }
            return;
        }

        if self.slots.len() >= self.capacity {
            let lru_idx = self.tail.expect("non-empty bounded LRU has tail");
            self.detach(lru_idx);
            let old_key = std::mem::replace(&mut self.slots[lru_idx].key, key.clone());
            self.index.remove(&old_key);
            self.slots[lru_idx].value = value;
            self.attach_front(lru_idx);
            self.index.insert(key, lru_idx);
            return;
        }

        let idx = self.slots.len();
        self.slots.push(LruSlot {
            key: key.clone(),
            value,
            prev: None,
            next: None,
        });
        self.attach_front(idx);
        self.index.insert(key, idx);
    }
}

fn run_blocking_worker_call<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

/// Default Windows binary inspector computing fresh streaming SHA-256 on every call
/// and caching only verified `Option<AuthenticodeInfo>` outcomes in a bounded 512-entry LRU
/// keyed by `(lowercase_exe_path, fresh_sha256)` (`L-04`, `SEC_0005`, `FU-E2E-03`).
///
/// Cold Authenticode verification runs out-of-process in `ledr-auth-helper.exe` via
/// [`AuthWorkerClient`]; transient worker errors, timeouts, and cancellations are never cached,
/// and exhausted worker failures fail closed to `None` with a warning log (`Option X`).
#[derive(Debug)]
pub struct WindowsBinaryInspector {
    authenticode_cache: Mutex<BoundedLruCache<(String, String), Option<AuthenticodeInfo>>>,
    auth_worker: AuthWorkerClient,
}

impl Default for WindowsBinaryInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsBinaryInspector {
    pub fn new() -> Self {
        Self::with_auth_worker(AuthWorkerClient::new(AuthWorkerConfig::default()))
    }

    pub fn with_auth_helper_sha256(auth_helper_sha256: Option<String>) -> Self {
        let cfg = AuthWorkerConfig {
            auth_helper_sha256,
            ..AuthWorkerConfig::default()
        };
        Self::with_auth_worker(AuthWorkerClient::new(cfg))
    }

    pub fn with_auth_worker(auth_worker: AuthWorkerClient) -> Self {
        Self {
            authenticode_cache: Mutex::new(BoundedLruCache::new(BINARY_INSPECTOR_CACHE_CAPACITY)),
            auth_worker,
        }
    }
}

impl BinaryInspector for WindowsBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        let never_cancel = AtomicBool::new(false);
        match self.inspect_cancellable(exe_path, &never_cancel, false) {
            InspectOutcome::Completed(id) => id,
            InspectOutcome::Cancelled => BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            },
        }
    }

    fn inspect_cancellable(
        &self,
        exe_path: &str,
        cancel: &AtomicBool,
        fast_skip_on_shutdown: bool,
    ) -> InspectOutcome {
        if cancel.load(Ordering::Acquire) || fast_skip_on_shutdown {
            return InspectOutcome::Cancelled;
        }
        if exe_path.trim().is_empty() {
            return InspectOutcome::Completed(BinaryIdentity {
                exe_path: String::new(),
                sha256: None,
                authenticode: None,
            });
        }
        let path = Path::new(exe_path);
        let Ok(meta) = std::fs::metadata(path) else {
            return InspectOutcome::Completed(BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            });
        };
        if !meta.is_file() {
            return InspectOutcome::Completed(BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            });
        }
        // Always recompute SHA-256 directly from file contents (SEC_0005).
        let fresh_sha256 = match compute_file_sha256_hex_cancellable(path, u64::MAX, cancel) {
            Ok(Some(hash)) => hash,
            Ok(None) => {
                return InspectOutcome::Completed(BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: None,
                    authenticode: None,
                });
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                return InspectOutcome::Cancelled;
            }
            Err(_) => {
                return InspectOutcome::Completed(BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: None,
                    authenticode: None,
                });
            }
        };

        let cache_key = (exe_path.to_ascii_lowercase(), fresh_sha256.clone());
        if let Ok(mut guard) = self.authenticode_cache.lock() {
            if let Some(cached_auth) = guard.get(&cache_key) {
                return InspectOutcome::Completed(BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(fresh_sha256),
                    authenticode: cached_auth.clone(),
                });
            }
        }
        if cancel.load(Ordering::Acquire) {
            return InspectOutcome::Cancelled;
        }

        let worker_res =
            run_blocking_worker_call(|| self.auth_worker.verify_cancellable(exe_path, cancel));

        match worker_res {
            Ok(authenticode) => {
                if cancel.load(Ordering::Acquire) {
                    return InspectOutcome::Cancelled;
                }
                if let Ok(mut guard) = self.authenticode_cache.lock() {
                    guard.insert(cache_key, authenticode.clone());
                }
                InspectOutcome::Completed(BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(fresh_sha256),
                    authenticode,
                })
            }
            Err(AuthWorkerError::Cancelled) => InspectOutcome::Cancelled,
            Err(err) => {
                if cancel.load(Ordering::Acquire) {
                    return InspectOutcome::Cancelled;
                }
                // Option X (fail-closed): warn and return `None` WITHOUT caching transient error.
                tracing::warn!(
                    exe_path = %exe_path,
                    error = %err,
                    "out-of-process Authenticode verification failed; failing closed without caching (Option X)"
                );
                InspectOutcome::Completed(BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(fresh_sha256),
                    authenticode: None,
                })
            }
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

    fn is_helper_pid(&self, pid: u32) -> bool {
        self.auth_worker.is_helper_pid(pid)
    }

    fn shutdown(&self) {
        self.auth_worker.shutdown();
    }
}

/// Abstraction for on-demand live OS process inspection used when `Kernel-File` delivers a
/// `CanaryFileAccess` event before `Kernel-Process` delivers `ProcessStart`.
pub trait LiveProcessInspector: Send + Sync {
    fn inspect_live_process(&self, pid: u32) -> Option<ledr_sensor_win::etw::LiveProcessInfo>;

    /// Checks live OS processes for another active instance matching `exe_key` started at or
    /// before `max_created_at_ms` (`FU-E2E-05`).
    fn check_live_siblings_for_exe(
        &self,
        _exe_key: &str,
        _candidate: ledr_proto::ProcessIdentity,
        _max_created_at_ms: i64,
    ) -> ledr_sensor_win::etw::LiveSiblingCheck {
        ledr_sensor_win::etw::LiveSiblingCheck::NoneFound
    }
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

    fn check_live_siblings_for_exe(
        &self,
        exe_key: &str,
        candidate: ledr_proto::ProcessIdentity,
        max_created_at_ms: i64,
    ) -> ledr_sensor_win::etw::LiveSiblingCheck {
        ledr_sensor_win::etw::find_other_live_processes_for_exe_key(
            exe_path_pass_through(exe_key),
            candidate,
            max_created_at_ms,
        )
    }
}

#[inline]
fn exe_path_pass_through(exe_key: &str) -> &str {
    exe_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::auth_worker::{
        AuthVerifyRequest, AuthVerifyResponse, RecvError, WorkerProcessHandle, WorkerSpawner,
    };
    use std::collections::VecDeque;
    use std::fs::OpenOptions;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, AtomicUsize};
    use std::sync::Arc;
    use std::time::Duration;

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(1);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    enum CountingWorkerMode {
        Signed(String),
        TransientTimeoutThenSigned { fail_count: Arc<AtomicUsize>, target: usize },
    }

    struct CountingSpawner {
        calls: Arc<AtomicUsize>,
        mode: CountingWorkerMode,
    }

    struct CountingProcess {
        calls: Arc<AtomicUsize>,
        mode: Arc<CountingWorkerMode>,
        last_req: Option<AuthVerifyRequest>,
    }

    impl WorkerProcessHandle for CountingProcess {
        fn pid(&self) -> u32 {
            77_001
        }

        fn try_has_exited(&mut self) -> bool {
            false
        }

        fn kill_handle(&self) -> Option<Box<dyn FnOnce() + Send>> {
            None
        }

        fn send_request(&mut self, req: &AuthVerifyRequest) -> io::Result<()> {
            self.last_req = Some(req.clone());
            Ok(())
        }

        fn recv_response_timeout(&mut self, _timeout: Duration) -> Result<AuthVerifyResponse, RecvError> {
            let req = self.last_req.take().expect("req");
            self.calls.fetch_add(1, Ordering::AcqRel);
            match &*self.mode {
                CountingWorkerMode::Signed(label) => Ok(AuthVerifyResponse {
                    id: req.id,
                    authenticode: Some(AuthenticodeInfo {
                        signer_subject: format!("CN={label}"),
                        root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
                    }),
                }),
                CountingWorkerMode::TransientTimeoutThenSigned { fail_count, target } => {
                    let prev = fail_count.fetch_add(1, Ordering::AcqRel);
                    if prev < *target {
                        Err(RecvError::Protocol("transient worker error".to_string()))
                    } else {
                        Ok(AuthVerifyResponse {
                            id: req.id,
                            authenticode: Some(AuthenticodeInfo {
                                signer_subject: "CN=Recovered".to_string(),
                                root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
                            }),
                        })
                    }
                }
            }
        }

        fn force_kill(self: Box<Self>) {}
    }

    impl WorkerSpawner for CountingSpawner {
        fn spawn(&self, cancel: &AtomicBool) -> Result<Box<dyn WorkerProcessHandle>, AuthWorkerError> {
            if cancel.load(Ordering::Acquire) {
                return Err(AuthWorkerError::Cancelled);
            }
            let mode = match &self.mode {
                CountingWorkerMode::Signed(s) => Arc::new(CountingWorkerMode::Signed(s.clone())),
                CountingWorkerMode::TransientTimeoutThenSigned { fail_count, target } => {
                    Arc::new(CountingWorkerMode::TransientTimeoutThenSigned {
                        fail_count: Arc::clone(fail_count),
                        target: *target,
                    })
                }
            };
            Ok(Box::new(CountingProcess {
                calls: Arc::clone(&self.calls),
                mode,
                last_req: None,
            }))
        }
    }

    #[test]
    fn bin_mem_01_bounded_512_lru_sec_0005_and_no_negative_cache() {
        // 1. Bounded 512-entry LRU keeps hot entry #0 when 513th entry is inserted, evicting LRU #1.
        let tmp = TestTempDir::new("bin-mem-01");
        let calls = Arc::new(AtomicUsize::new(0));
        let spawner = Arc::new(CountingSpawner {
            calls: Arc::clone(&calls),
            mode: CountingWorkerMode::Signed("TestSigner".to_string()),
        });
        let worker = AuthWorkerClient::with_spawner(AuthWorkerConfig::default(), spawner);
        let inspector = WindowsBinaryInspector::with_auth_worker(worker);

        let mut paths = Vec::with_capacity(513);
        for i in 0..513usize {
            let p = tmp.path.join(format!("bin_{i:03}.exe"));
            std::fs::write(&p, format!("payload-{i:04}").as_bytes()).expect("write bin");
            paths.push(p.to_string_lossy().into_owned());
        }

        for p in &paths[..512] {
            let id = inspector.inspect(p);
            assert!(id.authenticode.is_some());
        }
        assert_eq!(calls.load(Ordering::Acquire), 512);
        assert_eq!(
            inspector.authenticode_cache.lock().expect("lock").len(),
            512
        );

        // Touch entry #0 -> cache hit, promotes #0 to MRU so #1 becomes LRU.
        let hit0 = inspector.inspect(&paths[0]);
        assert!(hit0.authenticode.is_some());
        assert_eq!(calls.load(Ordering::Acquire), 512);

        // Insert 513th entry -> cache stays capped at 512 and evicts #1 (NOT #0).
        let id512 = inspector.inspect(&paths[512]);
        assert!(id512.authenticode.is_some());
        assert_eq!(calls.load(Ordering::Acquire), 513);
        assert_eq!(
            inspector.authenticode_cache.lock().expect("lock").len(),
            512
        );

        // #0 is STILL cached (no worker call).
        let still_hot = inspector.inspect(&paths[0]);
        assert!(still_hot.authenticode.is_some());
        assert_eq!(calls.load(Ordering::Acquire), 513);

        // #1 was evicted (misses and triggers worker call).
        let evicted = inspector.inspect(&paths[1]);
        assert!(evicted.authenticode.is_some());
        assert_eq!(calls.load(Ordering::Acquire), 514);

        // 2. SEC_0005: In-place file modification with identical length and preserved mtime misses cache.
        let sec_target = tmp.path.join("mutated_same_mtime.exe");
        let payload_a = vec![0x41u8; 256];
        let payload_b = vec![0x42u8; 256];
        std::fs::write(&sec_target, &payload_a).expect("write A");
        let orig_mtime = std::fs::metadata(&sec_target)
            .expect("meta A")
            .modified()
            .expect("mtime A");
        let sec_str = sec_target.to_string_lossy().into_owned();
        let calls_before_sec = calls.load(Ordering::Acquire);
        let a_id = inspector.inspect(&sec_str);
        assert_eq!(calls.load(Ordering::Acquire), calls_before_sec + 1);
        {
            let mut f = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&sec_target)
                .expect("reopen");
            std::io::Write::write_all(&mut f, &payload_b).expect("write B");
            f.set_modified(orig_mtime).expect("restore mtime");
        }
        let b_id = inspector.inspect(&sec_str);
        assert_ne!(a_id.sha256, b_id.sha256);
        assert_eq!(calls.load(Ordering::Acquire), calls_before_sec + 2);

        // 3. Transient worker errors & Cancelled outcomes are NEVER negative-cached.
        let fail_count = Arc::new(AtomicUsize::new(0));
        let retry_calls = Arc::new(AtomicUsize::new(0));
        let transient_spawner = Arc::new(CountingSpawner {
            calls: Arc::clone(&retry_calls),
            mode: CountingWorkerMode::TransientTimeoutThenSigned {
                fail_count: Arc::clone(&fail_count),
                target: 1,
            },
        });
        let transient_inspector = WindowsBinaryInspector::with_auth_worker(
            AuthWorkerClient::with_spawner(AuthWorkerConfig::default(), transient_spawner),
        );

        let err_outcome = transient_inspector.inspect(&sec_str);
        assert_eq!(err_outcome.authenticode, None);
        assert_eq!(retry_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            transient_inspector.authenticode_cache.lock().expect("lock").len(),
            0,
            "transient worker error must NEVER be negative-cached"
        );

        // Cancelled call is also never cached.
        let cancel_flag = AtomicBool::new(true);
        assert_eq!(
            transient_inspector.inspect_cancellable(&sec_str, &cancel_flag, false),
            InspectOutcome::Cancelled
        );
        assert_eq!(
            transient_inspector.authenticode_cache.lock().expect("lock").len(),
            0
        );

        // Next non-cancelled call invokes worker again and caches the recovered result.
        let ok_outcome = transient_inspector.inspect(&sec_str);
        assert!(ok_outcome.authenticode.is_some());
        assert_eq!(retry_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            transient_inspector.authenticode_cache.lock().expect("lock").len(),
            1
        );
        let _ = VecDeque::<u8>::new();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bin_mem_01_multithread_block_in_place_does_not_panic() {
        let tmp = TestTempDir::new("bin-mem-mt");
        let p = tmp.path.join("sample.exe");
        std::fs::write(&p, b"sample-binary").expect("write");
        let calls = Arc::new(AtomicUsize::new(0));
        let spawner = Arc::new(CountingSpawner {
            calls,
            mode: CountingWorkerMode::Signed("MtSigner".to_string()),
        });
        let inspector = WindowsBinaryInspector::with_auth_worker(AuthWorkerClient::with_spawner(
            AuthWorkerConfig::default(),
            spawner,
        ));
        let id = inspector.inspect(&p.to_string_lossy());
        assert!(id.authenticode.is_some());
    }
}
