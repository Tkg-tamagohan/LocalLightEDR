//! Mark-of-the-Web (MOTW) 3-stage process attribution, download origin recording,
//! dedicated raw-OS-thread MOTW I/O worker pool, bounded Stage 2 cache, and
//! `LAYER_4_BROWSER` security event ingestion with bounded deduplication (`Phase 4A`).

use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle as ThreadJoinHandle;
use std::time::{Duration, Instant};

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, BrowserSecurityEventType, DownloadOriginRecord,
};
use ledr_rules::{classify_outbound_risk, OutboundRiskClass};
use ledr_sensor_win::MotwZoneInfo;
use ledr_store::{LedrStore, StoreError};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use super::{current_unix_ms, BinaryInspector, DaemonEngine};

/// Maximum file size (128 MiB) hashed with SHA-256 on `ReportDownloadOrigin` and Stage 2 lookup.
pub const MAX_DOWNLOAD_HASH_BYTES: u64 = 128 * 1024 * 1024;

/// Maximum byte length retained for `ReportBrowserEvent` `details` payload (8 KiB).
pub const MAX_BROWSER_EVENT_DETAILS_BYTES: usize = 8 * 1024;

pub(super) const BROWSER_EVENT_DEDUP_CAPACITY: usize = 256;
pub(super) const BROWSER_EVENT_DEDUP_WINDOW_MS: i64 = 30_000;
pub(super) const MOTW_STAGE2_CACHE_CAPACITY: usize = 512;
pub(super) const MOTW_STAGE2_CACHE_TTL_SECS: u64 = 300;
pub(super) const MOTW_IO_WORKERS: usize = 2;
pub(super) const MOTW_IO_QUEUE_CAPACITY: usize = 64;
const MOTW_PENDING_LATE_CAPACITY: usize = MOTW_IO_QUEUE_CAPACITY + MOTW_IO_WORKERS;
const LATE_WAIT_RETRY_SLICE: Duration = Duration::from_millis(5);

/// Abstraction for reading NTFS `:Zone.Identifier` MOTW metadata (`Phase 4A` DI boundary).
pub trait MotwInspector: Send + Sync {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo>;
}

/// Default Windows MOTW inspector backed by [`ledr_sensor_win::read_zone_identifier`].
#[derive(Debug, Default)]
pub struct WindowsMotwInspector;

impl WindowsMotwInspector {
    pub fn new() -> Self {
        Self
    }
}

impl MotwInspector for WindowsMotwInspector {
    fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
        ledr_sensor_win::read_zone_identifier(path)
    }
}

/// Attribution stage that matched a launched binary to a browser/Internet download origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MotwMatchStage {
    DownloadPath,
    DownloadSha256,
    ZoneIdentifierAds,
}

impl MotwMatchStage {
    /// Returns the canonical snake_case tag recorded in `alerts.context_json.motw_source`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DownloadPath => "download_path",
            Self::DownloadSha256 => "download_sha256",
            Self::ZoneIdentifierAds => "zone_identifier_ads",
        }
    }
}

/// Resolved MOTW provenance metadata for a launched process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MotwAttribution {
    pub origin_url: String,
    pub referrer_url: Option<String>,
    pub frame_url: Option<String>,
    pub sha256: Option<String>,
    pub zone_id: Option<u32>,
    pub stage: MotwMatchStage,
}

/// Result of reporting a `LAYER_4_BROWSER` security event via [`DaemonEngine::record_browser_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserEventOutcome {
    Recorded(AlertRecord),
    Deduplicated,
}

/// Errors returned when validating or persisting browser download origins or browser events.
#[derive(Debug)]
pub enum BrowserReportError {
    Invalid(String),
    Store(StoreError),
    Cancelled,
}

impl std::fmt::Display for BrowserReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Store(err) => write!(f, "{err}"),
            Self::Cancelled => f.write_str("browser report cancelled"),
        }
    }
}

impl std::error::Error for BrowserReportError {}

impl From<StoreError> for BrowserReportError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

/// Packs `(generation << 1) | has_bit` for lock-free cache invalidation and post-purge reset.
pub(super) fn initial_download_origin_state(has_any: bool) -> u64 {
    if has_any {
        1
    } else {
        0
    }
}

pub(super) const fn download_origin_has_any(state: u64) -> bool {
    (state & 1) != 0
}

pub(super) const fn download_origin_generation(state: u64) -> u64 {
    state >> 1
}

pub(super) fn mark_download_origin_recorded(state: &AtomicU64) {
    let mut cur = state.load(Ordering::Acquire);
    loop {
        let next = (((cur >> 1).wrapping_add(1)) << 1) | 1;
        match state.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
}

pub(super) fn refresh_download_origins_after_purge(
    state: &AtomicU64,
    store: &LedrStore,
    before_state: u64,
    downloads_deleted: usize,
) {
    if downloads_deleted == 0 && !download_origin_has_any(before_state) {
        return;
    }
    let table_now_empty = match store.has_any_download_origins() {
        Ok(false) => true,
        Ok(true) => false,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed checking download_origins existence after TTL purge"
            );
            false
        }
    };
    if downloads_deleted > 0 {
        // Atomically advance `generation` whenever at least one download row was purged so Stage 2
        // lookup entries for removed rows are immediately invalidated even if other rows remain.
        // Only clear the presence bit when SQLite is confirmed empty and no concurrent download
        // updated `state` since `before_state`.
        let mut cur = state.load(Ordering::Acquire);
        loop {
            let next_gen = (cur >> 1).wrapping_add(1);
            let next_has_bit = if table_now_empty && cur == before_state {
                0
            } else {
                cur & 1
            };
            let next = (next_gen << 1) | next_has_bit;
            match state.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(observed) => cur = observed,
            }
        }
    } else if table_now_empty {
        // Clear bit 0 only if no concurrent download incremented `generation`.
        let _ = state.compare_exchange(
            before_state,
            before_state & !1,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Stage2CacheKey {
    sha256: String,
    generation: u64,
}

#[derive(Debug, Clone)]
struct Stage2CacheEntry {
    record: Option<DownloadOriginRecord>,
    cached_at: Instant,
}

/// Bounded cache storing Stage 2 `download_origins` lookup outcomes keyed by
/// `(sha256, download_origin_generation)`.
///
/// The binary SHA-256 is always recomputed from current file contents (`BinaryInspector::compute_sha256`)
/// so same-size, same-mtime binary replacements never reuse stale hashes or download origins.
#[derive(Debug)]
pub(super) struct MotwStage2Cache {
    capacity: usize,
    ttl: Duration,
    entries: HashMap<Stage2CacheKey, Stage2CacheEntry>,
    fifo: VecDeque<Stage2CacheKey>,
    hits: u64,
}

impl MotwStage2Cache {
    pub(super) fn new(capacity: usize, ttl_secs: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl: Duration::from_secs(ttl_secs.max(1)),
            entries: HashMap::new(),
            fifo: VecDeque::new(),
            hits: 0,
        }
    }

    fn get(&mut self, key: &Stage2CacheKey) -> Option<Option<DownloadOriginRecord>> {
        let expired = self
            .entries
            .get(key)
            .is_some_and(|entry| entry.cached_at.elapsed() >= self.ttl);
        if expired {
            self.entries.remove(key);
            return None;
        }
        if let Some(entry) = self.entries.get(key) {
            self.hits = self.hits.saturating_add(1);
            return Some(entry.record.clone());
        }
        None
    }

    fn insert(&mut self, key: Stage2CacheKey, record: Option<DownloadOriginRecord>) {
        if !self.entries.contains_key(&key) {
            while self.entries.len() >= self.capacity {
                let Some(oldest) = self.fifo.pop_front() else {
                    self.entries.clear();
                    break;
                };
                self.entries.remove(&oldest);
            }
            self.fifo.push_back(key.clone());
            if self.fifo.len() > self.capacity * 2 {
                let entries = &self.entries;
                self.fifo.retain(|k| entries.contains_key(k));
            }
        }
        self.entries.insert(
            key,
            Stage2CacheEntry {
                record,
                cached_at: Instant::now(),
            },
        );
    }

    fn hits(&self) -> u64 {
        self.hits
    }
}

/// Delayed MOTW attribution sent from the worker pool when synchronous wait budget expired,
/// workers were saturated, or a startup seed executable group completed background lookup.
#[derive(Debug, Clone)]
pub(super) struct LateMotwAttribution {
    pub(super) instance_ids: Vec<String>,
    pub(super) attribution: MotwAttribution,
}

/// Deduplicated startup seed group sharing one case-preserving normalized executable path.
#[derive(Debug, Clone)]
pub(super) struct SeedMotwGroup {
    pub(super) exe_path: String,
    pub(super) instance_ids: Vec<String>,
}

#[derive(Debug, Clone)]
pub(super) struct DownloadFileIoResult {
    pub(super) sha256: Option<String>,
    pub(super) zone_info: Option<MotwZoneInfo>,
    pub(super) cancelled: bool,
}

pub(super) enum SubmitProcessMotwOutcome {
    Await(oneshot::Receiver<Option<MotwAttribution>>),
    QueuedAsync,
    Rejected,
}

pub(super) enum SubmitDownloadIoOutcome {
    Await(oneshot::Receiver<DownloadFileIoResult>),
    QueueFull,
    Cancelled,
}

struct DownloadInspectJob {
    normalized_path: String,
    max_hash_bytes: u64,
    cancel: Arc<AtomicBool>,
    reply: oneshot::Sender<DownloadFileIoResult>,
}

struct ProcessMotwJob {
    instance_id: String,
    exe_path: String,
    reply: Option<oneshot::Sender<Option<MotwAttribution>>>,
}

struct MotwIoQueueState {
    download_queue: VecDeque<DownloadInspectJob>,
    process_queue: VecDeque<ProcessMotwJob>,
    pending_late: VecDeque<LateMotwAttribution>,
    reserved_late_slots: usize,
    flushing_pending_late: usize,
    seed_backlog: VecDeque<SeedMotwGroup>,
    seed_backlog_capacity: usize,
    closed: bool,
}

enum WorkerAction {
    InspectDownload(DownloadInspectJob),
    FlushPendingLate(LateMotwAttribution),
    ResolveProcess(ProcessMotwJob),
    ResolveSeedGroup(SeedMotwGroup),
}

struct MotwWorkerHandle {
    join_handle: ThreadJoinHandle<()>,
    done_rx: oneshot::Receiver<()>,
}

/// Dedicated bounded raw-OS-thread pool offloading all filesystem I/O for MOTW resolution and
/// `ReportDownloadOrigin` so hung SMB/UNC paths neither stall `run_pipeline` nor block Tokio's
/// `spawn_blocking` pool during daemon shutdown (`R-11`).
pub(super) struct MotwIoWorkerPool {
    queue_pair: Arc<(Mutex<MotwIoQueueState>, Condvar)>,
    busy_workers: Arc<AtomicUsize>,
    late_send_waiters: Arc<AtomicUsize>,
    active_cancels: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    shutdown_requested: Arc<AtomicBool>,
    workers: Mutex<Vec<MotwWorkerHandle>>,
}

struct LateWaiterGuard<'a>(&'a AtomicUsize);

impl Drop for LateWaiterGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct LateSlotReservationGuard<'a> {
    queue_pair: &'a (Mutex<MotwIoQueueState>, Condvar),
    armed: bool,
}

impl<'a> LateSlotReservationGuard<'a> {
    fn armed(queue_pair: &'a (Mutex<MotwIoQueueState>, Condvar)) -> Self {
        Self {
            queue_pair,
            armed: true,
        }
    }

    fn consume_under_lock(&mut self, state: &mut MotwIoQueueState) {
        if self.armed {
            self.armed = false;
            state.reserved_late_slots = state.reserved_late_slots.saturating_sub(1);
        }
    }

    fn release_under_lock(&mut self, state: &mut MotwIoQueueState, cvar: &Condvar) {
        if self.armed {
            self.armed = false;
            state.reserved_late_slots = state.reserved_late_slots.saturating_sub(1);
            if !state.process_queue.is_empty() || !state.seed_backlog.is_empty() {
                cvar.notify_one();
            }
        }
    }
}

impl Drop for LateSlotReservationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let (lock, cvar) = self.queue_pair;
            let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
            self.release_under_lock(&mut state, cvar);
        }
    }
}

struct PendingFlushGuard<'a> {
    queue_pair: &'a (Mutex<MotwIoQueueState>, Condvar),
    armed: bool,
}

impl<'a> PendingFlushGuard<'a> {
    fn armed(queue_pair: &'a (Mutex<MotwIoQueueState>, Condvar)) -> Self {
        Self {
            queue_pair,
            armed: true,
        }
    }

    fn finish_under_lock(&mut self, state: &mut MotwIoQueueState, cvar: &Condvar) {
        if self.armed {
            self.armed = false;
            state.flushing_pending_late = state.flushing_pending_late.saturating_sub(1);
            if state.flushing_pending_late == 0
                && (!state.pending_late.is_empty()
                    || !state.process_queue.is_empty()
                    || !state.seed_backlog.is_empty())
            {
                cvar.notify_all();
            }
        }
    }
}

impl Drop for PendingFlushGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let (lock, cvar) = self.queue_pair;
            let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
            self.finish_under_lock(&mut state, cvar);
        }
    }
}

fn enqueue_late_attribution_reserved(
    late_tx: &mpsc::Sender<LateMotwAttribution>,
    item: LateMotwAttribution,
    mut reservation: LateSlotReservationGuard<'_>,
    shutdown_flag: &AtomicBool,
    queue_pair: &(Mutex<MotwIoQueueState>, Condvar),
) {
    if shutdown_flag.load(Ordering::Acquire) || late_tx.is_closed() {
        return;
    }
    let can_direct_send = {
        let (lock, cvar) = queue_pair;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || shutdown_flag.load(Ordering::Acquire) || late_tx.is_closed() {
            reservation.release_under_lock(&mut state, cvar);
            return;
        }
        if state.pending_late.is_empty()
            && state.flushing_pending_late == 0
            && late_tx.capacity() > 0
        {
            true
        } else {
            state.pending_late.push_back(item);
            reservation.consume_under_lock(&mut state);
            debug_assert!(
                state.pending_late.len() + state.reserved_late_slots <= MOTW_PENDING_LATE_CAPACITY
            );
            if late_tx.capacity() > 0 {
                cvar.notify_one();
            }
            return;
        }
    };
    if can_direct_send {
        match late_tx.try_send(item) {
            Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => {}
            Err(mpsc::error::TrySendError::Full(returned)) => {
                let (lock, cvar) = queue_pair;
                let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
                if state.closed || shutdown_flag.load(Ordering::Acquire) || late_tx.is_closed() {
                    reservation.release_under_lock(&mut state, cvar);
                    return;
                }
                state.pending_late.push_back(returned);
                reservation.consume_under_lock(&mut state);
                debug_assert!(
                    state.pending_late.len() + state.reserved_late_slots
                        <= MOTW_PENDING_LATE_CAPACITY
                );
                if late_tx.capacity() > 0 {
                    cvar.notify_one();
                }
            }
        }
    }
}

struct InFlightWorkerGuard {
    done_tx: Option<oneshot::Sender<()>>,
}

impl Drop for InFlightWorkerGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(());
        }
    }
}

struct BusyWorkerGuard<'a>(&'a AtomicUsize);

impl Drop for BusyWorkerGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CancelRegistrationGuard {
    active_cancels: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    cancel: Arc<AtomicBool>,
}

impl Drop for CancelRegistrationGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.active_cancels.lock() {
            guard.retain(|entry| !Arc::ptr_eq(entry, &self.cancel));
        }
    }
}

struct CancelOnDrop {
    cancel: Arc<AtomicBool>,
    armed: bool,
}

impl CancelOnDrop {
    fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            cancel,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.store(true, Ordering::Release);
        }
    }
}

impl MotwIoWorkerPool {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        store: LedrStore,
        inspector: Arc<dyn BinaryInspector>,
        motw_inspector: Arc<dyn MotwInspector>,
        download_origin_state: Arc<AtomicU64>,
        stage2_cache: Arc<Mutex<MotwStage2Cache>>,
        download_hash_max_bytes: u64,
        seed_backlog_capacity: usize,
        late_tx: mpsc::Sender<LateMotwAttribution>,
    ) -> Self {
        let queue_pair = Arc::new((
            Mutex::new(MotwIoQueueState {
                download_queue: VecDeque::new(),
                process_queue: VecDeque::new(),
                pending_late: VecDeque::new(),
                reserved_late_slots: 0,
                flushing_pending_late: 0,
                seed_backlog: VecDeque::new(),
                seed_backlog_capacity: seed_backlog_capacity.max(256),
                closed: false,
            }),
            Condvar::new(),
        ));
        let busy_workers = Arc::new(AtomicUsize::new(0));
        let late_send_waiters = Arc::new(AtomicUsize::new(0));
        let active_cancels = Arc::new(Mutex::new(Vec::<Arc<AtomicBool>>::new()));
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(MOTW_IO_WORKERS);

        for idx in 0..MOTW_IO_WORKERS {
            let qp = Arc::clone(&queue_pair);
            let busy = Arc::clone(&busy_workers);
            let late_waiters = Arc::clone(&late_send_waiters);
            let cancels = Arc::clone(&active_cancels);
            let shutdown_flag = Arc::clone(&shutdown_requested);
            let w_store = store.clone();
            let w_inspector = Arc::clone(&inspector);
            let w_motw = Arc::clone(&motw_inspector);
            let w_dl_state = Arc::clone(&download_origin_state);
            let w_cache = Arc::clone(&stage2_cache);
            let w_late_tx = late_tx.clone();
            let (done_tx, done_rx) = oneshot::channel();

            match std::thread::Builder::new()
                .name(format!("ledr-motw-io-{idx}"))
                .spawn(move || {
                    // Declare `_done_guard` before local bindings so all worker-owned resources
                    // drop before `done_tx.send(())` fires (`R-11`).
                    let _done_guard = InFlightWorkerGuard {
                        done_tx: Some(done_tx),
                    };
                    let (
                        qp,
                        busy,
                        late_waiters,
                        cancels,
                        shutdown_flag,
                        w_store,
                        w_inspector,
                        w_motw,
                        w_dl_state,
                        w_cache,
                        w_late_tx,
                    ) = (
                        qp,
                        busy,
                        late_waiters,
                        cancels,
                        shutdown_flag,
                        w_store,
                        w_inspector,
                        w_motw,
                        w_dl_state,
                        w_cache,
                        w_late_tx,
                    );

                    loop {
                        let action = {
                            let (lock, cvar) = &*qp;
                            let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
                            loop {
                                if state.closed || shutdown_flag.load(Ordering::Acquire) {
                                    break None;
                                }
                                // Priority 1: `InspectDownloadFile` (produces no late MOTW attribution).
                                if let Some(job) = state.download_queue.pop_front() {
                                    busy.fetch_add(1, Ordering::AcqRel);
                                    break Some(WorkerAction::InspectDownload(job));
                                }
                                // Priority 2: Flush already-resolved `pending_late` before starting new
                                // `ResolveProcess` or `ResolveSeedGroup` work when `w_late_tx` has room.
                                if w_late_tx.is_closed() {
                                    state.pending_late.clear();
                                    state.seed_backlog.clear();
                                    state.process_queue.retain(|job| job.reply.is_some());
                                } else if w_late_tx.capacity() > 0 {
                                    if let Some(item) = state.pending_late.pop_front() {
                                        // 1 popped + 1 reserved keeps `pending_late + reserved_late_slots` constant.
                                        state.reserved_late_slots += 1;
                                        state.flushing_pending_late += 1;
                                        break Some(WorkerAction::FlushPendingLate(item));
                                    }
                                }
                                // Priority 3: `process_queue` only when a late slot can be pre-reserved.
                                if state.pending_late.len() + state.reserved_late_slots
                                    < MOTW_PENDING_LATE_CAPACITY
                                {
                                    if let Some(job) = state.process_queue.pop_front() {
                                        busy.fetch_add(1, Ordering::AcqRel);
                                        state.reserved_late_slots += 1;
                                        break Some(WorkerAction::ResolveProcess(job));
                                    }
                                }
                                // Priority 4: `seed_backlog` only once `pending_late` is empty, no
                                // final flush is still in flight, and `w_late_tx` has capacity.
                                if !w_late_tx.is_closed()
                                    && w_late_tx.capacity() > 0
                                    && state.pending_late.is_empty()
                                    && state.flushing_pending_late == 0
                                    && state.pending_late.len() + state.reserved_late_slots
                                        < MOTW_PENDING_LATE_CAPACITY
                                {
                                    if let Some(group) = state.seed_backlog.pop_front() {
                                        busy.fetch_add(1, Ordering::AcqRel);
                                        state.reserved_late_slots += 1;
                                        break Some(WorkerAction::ResolveSeedGroup(group));
                                    }
                                }
                                if state.closed || shutdown_flag.load(Ordering::Acquire) {
                                    break None;
                                }
                                if !w_late_tx.is_closed()
                                    && (!state.pending_late.is_empty()
                                        || !state.process_queue.is_empty()
                                        || !state.seed_backlog.is_empty())
                                {
                                    if state.pending_late.is_empty()
                                        && state.process_queue.is_empty()
                                        && state.flushing_pending_late > 0
                                        && w_late_tx.capacity() > 0
                                    {
                                        // Wait for `PendingFlushGuard` completion notice instead of
                                        // spinning while `w_late_tx.capacity() > 0`.
                                        state = cvar.wait(state).unwrap_or_else(|e| e.into_inner());
                                    } else if state.pending_late.is_empty()
                                        && state.pending_late.len() + state.reserved_late_slots
                                            >= MOTW_PENDING_LATE_CAPACITY
                                    {
                                        // Wait for `LateSlotReservationGuard` release notification.
                                        state = cvar.wait(state).unwrap_or_else(|e| e.into_inner());
                                    } else {
                                        late_waiters.fetch_add(1, Ordering::SeqCst);
                                        let _waiter_guard = LateWaiterGuard(&late_waiters);
                                        if w_late_tx.capacity() > 0 || w_late_tx.is_closed() {
                                            continue;
                                        }
                                        let (next_state, _) = cvar
                                            .wait_timeout(state, LATE_WAIT_RETRY_SLICE)
                                            .unwrap_or_else(|e| e.into_inner());
                                        state = next_state;
                                    }
                                } else {
                                    state = cvar.wait(state).unwrap_or_else(|e| e.into_inner());
                                }
                            }
                        };
                        let Some(action) = action else {
                            break;
                        };

                        match action {
                            WorkerAction::FlushPendingLate(item) => {
                                // Declare `flush_guard` before `reservation` so LIFO drop releases
                                // the reserved slot before decrementing `flushing_pending_late`.
                                let mut flush_guard = PendingFlushGuard::armed(&qp);
                                let mut reservation = LateSlotReservationGuard::armed(&qp);
                                if shutdown_flag.load(Ordering::Acquire) {
                                    break;
                                }
                                match w_late_tx.try_send(item) {
                                    Ok(()) => {
                                        let (lock, cvar) = &*qp;
                                        let mut state =
                                            lock.lock().unwrap_or_else(|e| e.into_inner());
                                        reservation.release_under_lock(&mut state, cvar);
                                        flush_guard.finish_under_lock(&mut state, cvar);
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        let (lock, cvar) = &*qp;
                                        let mut state =
                                            lock.lock().unwrap_or_else(|e| e.into_inner());
                                        state.pending_late.clear();
                                        state.seed_backlog.clear();
                                        state.process_queue.retain(|job| job.reply.is_some());
                                        reservation.release_under_lock(&mut state, cvar);
                                        flush_guard.finish_under_lock(&mut state, cvar);
                                    }
                                    Err(mpsc::error::TrySendError::Full(returned)) => {
                                        let (lock, cvar) = &*qp;
                                        let mut state =
                                            lock.lock().unwrap_or_else(|e| e.into_inner());
                                        if !state.closed && !shutdown_flag.load(Ordering::Acquire) {
                                            state.pending_late.push_front(returned);
                                            reservation.consume_under_lock(&mut state);
                                            debug_assert!(
                                                state.pending_late.len()
                                                    + state.reserved_late_slots
                                                    <= MOTW_PENDING_LATE_CAPACITY
                                            );
                                        } else {
                                            reservation.release_under_lock(&mut state, cvar);
                                        }
                                        flush_guard.finish_under_lock(&mut state, cvar);
                                    }
                                }
                            }
                            WorkerAction::ResolveProcess(job) => {
                                let _busy_guard = BusyWorkerGuard(&busy);
                                let reservation = LateSlotReservationGuard::armed(&qp);
                                if shutdown_flag.load(Ordering::Acquire) {
                                    break;
                                }
                                let ProcessMotwJob {
                                    instance_id,
                                    exe_path,
                                    reply,
                                } = job;
                                let attr = resolve_process_motw_core(
                                    &w_store,
                                    &*w_inspector,
                                    &*w_motw,
                                    &w_dl_state,
                                    &w_cache,
                                    download_hash_max_bytes,
                                    &exe_path,
                                    None,
                                    false,
                                );
                                match reply {
                                    Some(tx) => {
                                        if let Err(Some(late_attr)) = tx.send(attr) {
                                            if !instance_id.is_empty() {
                                                enqueue_late_attribution_reserved(
                                                    &w_late_tx,
                                                    LateMotwAttribution {
                                                        instance_ids: vec![instance_id],
                                                        attribution: late_attr,
                                                    },
                                                    reservation,
                                                    &shutdown_flag,
                                                    &qp,
                                                );
                                            }
                                        }
                                    }
                                    None => {
                                        if let Some(late_attr) = attr {
                                            if !instance_id.is_empty() {
                                                enqueue_late_attribution_reserved(
                                                    &w_late_tx,
                                                    LateMotwAttribution {
                                                        instance_ids: vec![instance_id],
                                                        attribution: late_attr,
                                                    },
                                                    reservation,
                                                    &shutdown_flag,
                                                    &qp,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            WorkerAction::ResolveSeedGroup(group) => {
                                let _busy_guard = BusyWorkerGuard(&busy);
                                let reservation = LateSlotReservationGuard::armed(&qp);
                                if shutdown_flag.load(Ordering::Acquire) {
                                    break;
                                }
                                let SeedMotwGroup {
                                    exe_path,
                                    instance_ids,
                                } = group;
                                let attr = resolve_process_motw_core(
                                    &w_store,
                                    &*w_inspector,
                                    &*w_motw,
                                    &w_dl_state,
                                    &w_cache,
                                    download_hash_max_bytes,
                                    &exe_path,
                                    None,
                                    false,
                                );
                                if let Some(late_attr) = attr {
                                    enqueue_late_attribution_reserved(
                                        &w_late_tx,
                                        LateMotwAttribution {
                                            instance_ids,
                                            attribution: late_attr,
                                        },
                                        reservation,
                                        &shutdown_flag,
                                        &qp,
                                    );
                                }
                            }
                            WorkerAction::InspectDownload(job) => {
                                let _busy_guard = BusyWorkerGuard(&busy);
                                if shutdown_flag.load(Ordering::Acquire) {
                                    break;
                                }
                                let DownloadInspectJob {
                                    normalized_path,
                                    max_hash_bytes,
                                    cancel,
                                    reply,
                                } = job;
                                let _cancel_guard = {
                                    let mut guard =
                                        cancels.lock().unwrap_or_else(|e| e.into_inner());
                                    guard.push(Arc::clone(&cancel));
                                    CancelRegistrationGuard {
                                        active_cancels: Arc::clone(&cancels),
                                        cancel: Arc::clone(&cancel),
                                    }
                                };
                                if cancel.load(Ordering::Acquire)
                                    || shutdown_flag.load(Ordering::Acquire)
                                {
                                    let _ = reply.send(DownloadFileIoResult {
                                        sha256: None,
                                        zone_info: None,
                                        cancelled: true,
                                    });
                                    continue;
                                }

                                let sha256 = match w_inspector.compute_sha256_cancellable(
                                    &normalized_path,
                                    max_hash_bytes,
                                    &cancel,
                                ) {
                                    Ok(opt) => opt
                                        .map(|h| h.trim().to_ascii_lowercase())
                                        .filter(|h| !h.is_empty()),
                                    Err(err)
                                        if err.kind() == ErrorKind::Interrupted
                                            && (cancel.load(Ordering::Acquire)
                                                || shutdown_flag.load(Ordering::Acquire)) =>
                                    {
                                        let _ = reply.send(DownloadFileIoResult {
                                            sha256: None,
                                            zone_info: None,
                                            cancelled: true,
                                        });
                                        continue;
                                    }
                                    Err(err) => {
                                        tracing::debug!(
                                            file_path = %normalized_path,
                                            error = %err,
                                            "failed computing SHA-256 for downloaded file; recording origin without hash"
                                        );
                                        None
                                    }
                                };

                                if cancel.load(Ordering::Acquire)
                                    || shutdown_flag.load(Ordering::Acquire)
                                {
                                    let _ = reply.send(DownloadFileIoResult {
                                        sha256: None,
                                        zone_info: None,
                                        cancelled: true,
                                    });
                                    continue;
                                }

                                let zone_info =
                                    w_motw.read_zone_identifier(Path::new(&normalized_path));
                                let cancelled = cancel.load(Ordering::Acquire)
                                    || shutdown_flag.load(Ordering::Acquire);
                                let _ = reply.send(DownloadFileIoResult {
                                    sha256,
                                    zone_info,
                                    cancelled,
                                });
                            }
                        }
                    }
                }) {
                Ok(join_handle) => workers.push(MotwWorkerHandle {
                    join_handle,
                    done_rx,
                }),
                Err(err) => {
                    tracing::warn!(worker_idx = idx, error = %err, "failed spawning MOTW I/O worker thread");
                }
            }
        }

        Self {
            queue_pair,
            busy_workers,
            late_send_waiters,
            active_cancels,
            shutdown_requested,
            workers: Mutex::new(workers),
        }
    }

    pub(super) fn notify_late_result_consumed(&self) {
        if self.late_send_waiters.load(Ordering::SeqCst) > 0 {
            let (lock, cvar) = &*self.queue_pair;
            let _state = lock.lock().unwrap_or_else(|e| e.into_inner());
            cvar.notify_all();
        }
    }

    pub(super) fn submit_seed_motw_groups(&self, groups: Vec<SeedMotwGroup>) -> usize {
        if groups.is_empty() || self.shutdown_requested.load(Ordering::Acquire) {
            return 0;
        }
        let (lock, cvar) = &*self.queue_pair;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || self.shutdown_requested.load(Ordering::Acquire) {
            return 0;
        }
        let mut accepted = 0usize;
        let mut skipped = 0usize;
        for group in groups {
            if group.instance_ids.is_empty() || group.exe_path.is_empty() {
                continue;
            }
            if state.seed_backlog.len() >= state.seed_backlog_capacity {
                skipped += 1;
                continue;
            }
            state.seed_backlog.push_back(group);
            accepted += 1;
        }
        if skipped > 0 {
            tracing::warn!(
                accepted,
                skipped,
                seed_backlog_capacity = state.seed_backlog_capacity,
                "MOTW seed backlog reached capacity; skipping excess startup groups"
            );
        }
        if accepted > 0 {
            cvar.notify_all();
        }
        accepted
    }

    pub(super) fn submit_process_motw(
        &self,
        instance_id: String,
        exe_path: String,
        allow_sync_wait: bool,
    ) -> SubmitProcessMotwOutcome {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return SubmitProcessMotwOutcome::Rejected;
        }
        let (lock, cvar) = &*self.queue_pair;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || self.shutdown_requested.load(Ordering::Acquire) {
            return SubmitProcessMotwOutcome::Rejected;
        }
        if state.process_queue.len() >= MOTW_IO_QUEUE_CAPACITY {
            tracing::warn!(
                exe_path = %exe_path,
                queue_capacity = MOTW_IO_QUEUE_CAPACITY,
                "MOTW process I/O queue saturated; skipping deferred MOTW lookup"
            );
            return SubmitProcessMotwOutcome::Rejected;
        }

        let in_flight_and_queued = self.busy_workers.load(Ordering::Acquire)
            + state.download_queue.len()
            + state.process_queue.len();
        let has_late_slot =
            state.pending_late.len() + state.reserved_late_slots < MOTW_PENDING_LATE_CAPACITY;
        if allow_sync_wait && in_flight_and_queued < MOTW_IO_WORKERS && has_late_slot {
            let (tx, rx) = oneshot::channel();
            state.process_queue.push_back(ProcessMotwJob {
                instance_id,
                exe_path,
                reply: Some(tx),
            });
            cvar.notify_one();
            SubmitProcessMotwOutcome::Await(rx)
        } else {
            state.process_queue.push_back(ProcessMotwJob {
                instance_id,
                exe_path,
                reply: None,
            });
            cvar.notify_one();
            SubmitProcessMotwOutcome::QueuedAsync
        }
    }

    pub(super) fn submit_download_inspect(
        &self,
        normalized_path: String,
        max_hash_bytes: u64,
        cancel: Arc<AtomicBool>,
    ) -> SubmitDownloadIoOutcome {
        if cancel.load(Ordering::Acquire) || self.shutdown_requested.load(Ordering::Acquire) {
            return SubmitDownloadIoOutcome::Cancelled;
        }
        let (lock, cvar) = &*self.queue_pair;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed
            || cancel.load(Ordering::Acquire)
            || self.shutdown_requested.load(Ordering::Acquire)
        {
            return SubmitDownloadIoOutcome::Cancelled;
        }
        if state.download_queue.len() >= MOTW_IO_QUEUE_CAPACITY {
            return SubmitDownloadIoOutcome::QueueFull;
        }
        let (tx, rx) = oneshot::channel();
        state.download_queue.push_back(DownloadInspectJob {
            normalized_path,
            max_hash_bytes,
            cancel,
            reply: tx,
        });
        cvar.notify_one();
        SubmitDownloadIoOutcome::Await(rx)
    }

    pub(super) fn queue_counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        let state = self
            .queue_pair
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        (
            state.pending_late.len(),
            state.process_queue.len(),
            state.download_queue.len(),
            state.reserved_late_slots,
            self.busy_workers.load(Ordering::Acquire),
            state.seed_backlog.len(),
        )
    }

    pub(super) fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        if let Ok(guard) = self.active_cancels.lock() {
            for flag in guard.iter() {
                flag.store(true, Ordering::Release);
            }
        }
        let (lock, cvar) = &*self.queue_pair;
        let mut state = lock.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.download_queue.clear();
        state.process_queue.clear();
        state.pending_late.clear();
        state.seed_backlog.clear();
        cvar.notify_all();
    }

    pub(super) async fn shutdown_and_join(&self, deadline: tokio::time::Instant) {
        self.request_shutdown();
        let handles = {
            let mut guard = self.workers.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        for mut worker in handles {
            let mut completed = worker.join_handle.is_finished()
                || !matches!(
                    worker.done_rx.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                );
            if !completed {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if !remaining.is_zero() {
                    match tokio::time::timeout(remaining, &mut worker.done_rx).await {
                        Ok(Ok(())) | Ok(Err(_)) => {
                            completed = true;
                        }
                        Err(_) => {
                            completed = worker.join_handle.is_finished();
                        }
                    }
                }
            }
            if completed {
                if worker.join_handle.join().is_err() {
                    tracing::warn!("MOTW I/O worker thread panicked during shutdown");
                }
            } else {
                // Detach blocked raw OS thread without touching Tokio's `spawn_blocking` pool so
                // `Runtime::drop` cannot hang on wedged SMB/UNC I/O (`R-11`).
                tracing::warn!(
                    thread = worker.join_handle.thread().name().unwrap_or("ledr-motw-io"),
                    "shutdown budget exhausted waiting for MOTW I/O worker thread; detaching thread"
                );
            }
        }
    }
}

/// Bounded FIFO deduplication cache suppressing repeated `(BrowserSecurityEventType, normalized_url)`
/// reports within `window_ms` (30 seconds, max 256 keys).
#[derive(Debug, Default)]
pub(super) struct BrowserEventDedupCache {
    capacity: usize,
    window_ms: i64,
    last_seen: HashMap<(BrowserSecurityEventType, String), i64>,
    insertion_order: VecDeque<(BrowserSecurityEventType, String)>,
}

impl BrowserEventDedupCache {
    pub(super) fn new(capacity: usize, window_ms: i64) -> Self {
        Self {
            capacity: capacity.max(1),
            window_ms: window_ms.max(1),
            last_seen: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    pub(super) fn should_emit(
        &mut self,
        event_type: BrowserSecurityEventType,
        norm_url: &str,
        ts_ms: i64,
    ) -> bool {
        let key = (event_type, norm_url.to_string());
        if let Some(&prev_ts) = self.last_seen.get(&key) {
            if ts_ms >= prev_ts {
                if ts_ms.saturating_sub(prev_ts) < self.window_ms {
                    return false;
                }
                self.last_seen.insert(key, ts_ms);
                return true;
            }
            if prev_ts.saturating_sub(ts_ms) < self.window_ms {
                return false;
            }
            return true;
        }
        while self.last_seen.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                self.last_seen.clear();
                break;
            };
            self.last_seen.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.last_seen.insert(key, ts_ms);
        true
    }

    pub(super) fn remove_key(&mut self, event_type: BrowserSecurityEventType, norm_url: &str) {
        let key = (event_type, norm_url.to_string());
        if self.last_seen.remove(&key).is_some() {
            self.insertion_order.retain(|existing| existing != &key);
        }
    }
}

pub(super) fn normalize_windows_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let body = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\") || p.eq_ignore_ascii_case("//?/UNC/"))
    {
        format!(r"\\{}", &trimmed[8..])
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\") || p.eq_ignore_ascii_case("//?/"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed.to_string()
    };
    body.replace('/', "\\")
}

fn normalize_browser_event_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let before_frag = trimmed.split('#').next().unwrap_or(trimmed);
    if let Some(scheme_end) = before_frag.find("://") {
        let scheme = &before_frag[..scheme_end];
        let after_scheme = &before_frag[scheme_end + 3..];
        let auth_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
        let authority = &after_scheme[..auth_end];
        let rest = &after_scheme[auth_end..];
        format!(
            "{}://{}{}",
            scheme.to_ascii_lowercase(),
            authority.to_ascii_lowercase(),
            rest
        )
    } else {
        before_frag.to_ascii_lowercase()
    }
}

fn truncate_utf8_bytes(raw: &str, max_bytes: usize) -> (&str, bool) {
    if raw.len() <= max_bytes {
        return (raw, false);
    }
    let mut end = max_bytes;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    (&raw[..end], true)
}

fn clean_opt_str(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn build_download_origin_record(
    normalized_path: String,
    clean_tab_url: String,
    clean_frame_url: Option<String>,
    clean_referrer_url: Option<String>,
    effective_ts: i64,
    sha256: Option<String>,
    zone_info: Option<MotwZoneInfo>,
) -> DownloadOriginRecord {
    let mut frame_url = clean_frame_url;
    let mut referrer_url = clean_referrer_url;
    if let Some(zone) = zone_info {
        if referrer_url.is_none() {
            referrer_url = zone.referrer_url;
        }
        if frame_url.is_none() {
            frame_url = zone
                .host_url
                .filter(|host| !host.eq_ignore_ascii_case(&clean_tab_url));
        }
    }

    DownloadOriginRecord {
        id: None,
        file_path: normalized_path,
        sha256,
        tab_url: clean_tab_url,
        frame_url,
        referrer_url,
        downloaded_at_ms: effective_ts,
    }
}

fn persist_download_origin_idempotent(
    store: &LedrStore,
    download_origin_state: &AtomicU64,
    record: DownloadOriginRecord,
    cancel: Option<&AtomicBool>,
) -> Result<DownloadOriginRecord, BrowserReportError> {
    if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
        return Err(BrowserReportError::Cancelled);
    }
    if let Some(existing) = store.find_recent_identical_download_origin(
        &record.file_path,
        &record.tab_url,
        record.downloaded_at_ms,
    )? {
        mark_download_origin_recorded(download_origin_state);
        return Ok(existing);
    }
    if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
        return Err(BrowserReportError::Cancelled);
    }
    store.record_download_origin(&record)?;
    mark_download_origin_recorded(download_origin_state);
    Ok(record)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_process_motw_core(
    store: &LedrStore,
    inspector: &dyn BinaryInspector,
    motw_inspector: &dyn MotwInspector,
    download_origin_state: &AtomicU64,
    stage2_cache: &Mutex<MotwStage2Cache>,
    download_hash_max_bytes: u64,
    exe_path: &str,
    exited_at_ms: Option<i64>,
    skip_launch_guards: bool,
) -> Option<MotwAttribution> {
    if exited_at_ms.is_some() || skip_launch_guards {
        return None;
    }
    let normalized_exe = normalize_windows_path(exe_path);
    if normalized_exe.is_empty()
        || classify_outbound_risk(&normalized_exe) == OutboundRiskClass::ProtectedOs
    {
        return None;
    }

    let path = Path::new(&normalized_exe);
    let dl_state = download_origin_state.load(Ordering::Acquire);
    let has_downloads = download_origin_has_any(dl_state);
    let generation = download_origin_generation(dl_state);

    if has_downloads {
        let meta_res = std::fs::metadata(path);
        let can_hash_binary = match &meta_res {
            Ok(meta) => meta.is_file() && meta.len() <= download_hash_max_bytes,
            // Allow mocked BinaryInspector tests that do not create a backing file on disk,
            // while skipping real oversized or non-regular files.
            Err(err) if err.kind() == ErrorKind::NotFound => true,
            Err(_) => false,
        };

        let mut precomputed_stage2_sha: Option<String> = None;
        let mut stage2_allowed_after_stage1 = can_hash_binary;

        match store.find_download_origin_by_path(&normalized_exe) {
            Ok(Some(rec)) => match rec.sha256 {
                Some(ref recorded_sha) => {
                    if can_hash_binary {
                        let current_sha = inspector
                            .compute_sha256(&normalized_exe)
                            .map(|h| h.trim().to_ascii_lowercase())
                            .filter(|h| !h.is_empty());
                        match current_sha {
                            Some(cur) if cur.eq_ignore_ascii_case(recorded_sha) => {
                                let zone = motw_inspector.read_zone_identifier(path);
                                let zone_id = zone.as_ref().map(|z| z.zone_id);
                                let referrer_url =
                                    rec.referrer_url.or_else(|| zone.and_then(|z| z.referrer_url));
                                return Some(MotwAttribution {
                                    origin_url: rec.tab_url,
                                    referrer_url,
                                    frame_url: rec.frame_url,
                                    sha256: Some(cur),
                                    zone_id,
                                    stage: MotwMatchStage::DownloadPath,
                                });
                            }
                            Some(cur) => {
                                // Current binary hash does not match the recorded Stage 1 path
                                // entry: reject Stage 1 and reuse `cur` in Stage 2 without re-hashing.
                                precomputed_stage2_sha = Some(cur);
                            }
                            None => {
                                // Unverified current hash: never record historical `recorded_sha`.
                                stage2_allowed_after_stage1 = false;
                            }
                        }
                    } else {
                        // Oversized / non-regular replacement: reject Stage 1 and skip Stage 2.
                        stage2_allowed_after_stage1 = false;
                    }
                }
                None => {
                    let zone = motw_inspector.read_zone_identifier(path);
                    let zone_id = zone.as_ref().map(|z| z.zone_id);
                    let referrer_url =
                        rec.referrer_url.or_else(|| zone.and_then(|z| z.referrer_url));
                    return Some(MotwAttribution {
                        origin_url: rec.tab_url,
                        referrer_url,
                        frame_url: rec.frame_url,
                        sha256: None,
                        zone_id,
                        stage: MotwMatchStage::DownloadPath,
                    });
                }
            },
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(
                    exe_path = %normalized_exe,
                    error = %err,
                    "Stage 1 download origin path lookup failed"
                );
            }
        }

        if stage2_allowed_after_stage1 {
            let computed = precomputed_stage2_sha.or_else(|| {
                inspector
                    .compute_sha256(&normalized_exe)
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
            });

            let matched_stage2: Option<(String, DownloadOriginRecord)> =
                if let Some(clean_hash) = computed {
                    let cache_key = Stage2CacheKey {
                        sha256: clean_hash.clone(),
                        generation,
                    };
                    let cached_stage2 = stage2_cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&cache_key);
                    if let Some(cached_rec) = cached_stage2 {
                        cached_rec.map(|rec| (clean_hash, rec))
                    } else {
                        match store.find_download_origin_by_sha256(&clean_hash) {
                            Ok(rec_opt) => {
                                stage2_cache
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .insert(cache_key, rec_opt.clone());
                                rec_opt.map(|rec| (clean_hash, rec))
                            }
                            Err(err) => {
                                tracing::warn!(
                                    exe_path = %normalized_exe,
                                    error = %err,
                                    "Stage 2 download origin SHA-256 lookup failed"
                                );
                                None
                            }
                        }
                    }
                } else {
                    None
                };

            if let Some((clean_hash, rec)) = matched_stage2 {
                let zone = motw_inspector.read_zone_identifier(path);
                let zone_id = zone.as_ref().map(|z| z.zone_id);
                let referrer_url =
                    rec.referrer_url.or_else(|| zone.and_then(|z| z.referrer_url));
                return Some(MotwAttribution {
                    origin_url: rec.tab_url,
                    referrer_url,
                    frame_url: rec.frame_url,
                    sha256: rec.sha256.or(Some(clean_hash)),
                    zone_id,
                    stage: MotwMatchStage::DownloadSha256,
                });
            }
        }
    }

    if let Some(zone) = motw_inspector.read_zone_identifier(path) {
        if zone.is_internet_origin() {
            if let Some(origin_url) = zone.preferred_origin_url() {
                let frame_url = zone
                    .host_url
                    .filter(|h| !h.eq_ignore_ascii_case(&origin_url));
                return Some(MotwAttribution {
                    origin_url,
                    referrer_url: zone.referrer_url,
                    frame_url,
                    sha256: None,
                    zone_id: Some(zone.zone_id),
                    stage: MotwMatchStage::ZoneIdentifierAds,
                });
            }
        }
    }

    None
}

impl DaemonEngine {
    /// Returns whether any `download_origins` row is currently cached as existing (`Stage 1/2` gate).
    #[doc(hidden)]
    pub fn has_download_origins_cached(&self) -> bool {
        download_origin_has_any(self.download_origin_state.load(Ordering::Acquire))
    }

    /// Returns cumulative Stage 2 `(sha256, generation)` SQLite lookup cache hits.
    #[doc(hidden)]
    pub fn motw_stage2_cache_hits(&self) -> u64 {
        self.motw_stage2_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .hits()
    }

    /// Returns a diagnostic snapshot of the `MotwIoWorkerPool` queue depths and worker occupancy:
    /// `(pending_late, process_queue, download_queue, reserved_late_slots, busy_workers, seed_backlog)`.
    #[doc(hidden)]
    pub fn motw_pool_queue_counts(&self) -> (usize, usize, usize, usize, usize, usize) {
        self.motw_pool.queue_counts()
    }

    /// Synchronously records a completed browser download's origin metadata (`ReportDownloadOrigin`),
    /// computing SHA-256 without Authenticode overhead when size `<= download_hash_max_bytes`
    /// and deduplicating identical retries via `(file_path, tab_url, downloaded_at_ms)`.
    pub fn record_browser_download_origin(
        &self,
        file_path: &str,
        tab_url: &str,
        frame_url: Option<&str>,
        referrer_url: Option<&str>,
        downloaded_at_ms: i64,
    ) -> Result<DownloadOriginRecord, BrowserReportError> {
        let normalized_path = normalize_windows_path(file_path);
        if normalized_path.is_empty() {
            return Err(BrowserReportError::Invalid(
                "download file_path cannot be empty".to_string(),
            ));
        }
        let clean_tab_url = tab_url.trim().to_string();
        if clean_tab_url.is_empty() {
            return Err(BrowserReportError::Invalid(
                "download tab_url cannot be empty".to_string(),
            ));
        }
        let clean_frame_url = clean_opt_str(frame_url);
        let clean_referrer_url = clean_opt_str(referrer_url);
        let effective_ts = if downloaded_at_ms > 0 {
            downloaded_at_ms
        } else {
            current_unix_ms()
        };

        let never_cancel = AtomicBool::new(false);
        let sha256 = match self.inspector.compute_sha256_cancellable(
            &normalized_path,
            self.config.download_hash_max_bytes,
            &never_cancel,
        ) {
            Ok(opt) => opt
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty()),
            Err(err) => {
                tracing::debug!(
                    file_path = %normalized_path,
                    error = %err,
                    "failed computing SHA-256 for downloaded file; recording origin without hash"
                );
                None
            }
        };
        let zone_info = self
            .motw_inspector
            .read_zone_identifier(Path::new(&normalized_path));
        let record = build_download_origin_record(
            normalized_path,
            clean_tab_url,
            clean_frame_url,
            clean_referrer_url,
            effective_ts,
            sha256,
            zone_info,
        );
        let closed = self
            .store_write_gate
            .read()
            .unwrap_or_else(|e| e.into_inner());
        if *closed {
            return Err(BrowserReportError::Cancelled);
        }
        persist_download_origin_idempotent(&self.store, &self.download_origin_state, record, None)
    }

    /// Asynchronous IPC variant of [`Self::record_browser_download_origin`] offloading all
    /// filesystem I/O onto [`MotwIoWorkerPool`] with cooperative cancellation on timeout/shutdown
    /// and idempotent duplicate suppression in SQLite.
    pub(crate) async fn record_browser_download_origin_async(
        &self,
        file_path: &str,
        tab_url: &str,
        frame_url: Option<&str>,
        referrer_url: Option<&str>,
        downloaded_at_ms: i64,
        cancel: Arc<AtomicBool>,
    ) -> Result<DownloadOriginRecord, BrowserReportError> {
        let mut cancel_guard = CancelOnDrop::new(Arc::clone(&cancel));
        let normalized_path = normalize_windows_path(file_path);
        if normalized_path.is_empty() {
            cancel_guard.disarm();
            return Err(BrowserReportError::Invalid(
                "download file_path cannot be empty".to_string(),
            ));
        }
        let clean_tab_url = tab_url.trim().to_string();
        if clean_tab_url.is_empty() {
            cancel_guard.disarm();
            return Err(BrowserReportError::Invalid(
                "download tab_url cannot be empty".to_string(),
            ));
        }
        let clean_frame_url = clean_opt_str(frame_url);
        let clean_referrer_url = clean_opt_str(referrer_url);
        let effective_ts = if downloaded_at_ms > 0 {
            downloaded_at_ms
        } else {
            current_unix_ms()
        };

        let (sha256, zone_info) = match self.motw_pool.submit_download_inspect(
            normalized_path.clone(),
            self.config.download_hash_max_bytes,
            Arc::clone(&cancel),
        ) {
            SubmitDownloadIoOutcome::Await(rx) => match rx.await {
                Ok(res) if !res.cancelled && !cancel.load(Ordering::Acquire) => {
                    (res.sha256, res.zone_info)
                }
                Ok(_) | Err(_) => return Err(BrowserReportError::Cancelled),
            },
            SubmitDownloadIoOutcome::QueueFull => {
                tracing::warn!(
                    file_path = %normalized_path,
                    "MOTW I/O worker queue saturated during ReportDownloadOrigin; persisting URL without hash/ADS read"
                );
                (None, None)
            }
            SubmitDownloadIoOutcome::Cancelled => return Err(BrowserReportError::Cancelled),
        };

        if cancel.load(Ordering::Acquire) {
            return Err(BrowserReportError::Cancelled);
        }

        let record = build_download_origin_record(
            normalized_path,
            clean_tab_url,
            clean_frame_url,
            clean_referrer_url,
            effective_ts,
            sha256,
            zone_info,
        );
        let store = self.store.clone();
        let dl_state = Arc::clone(&self.download_origin_state);
        let write_cancel = Arc::clone(&cancel);
        let write_gate = Arc::clone(&self.store_write_gate);
        let persisted = tokio::task::spawn_blocking(move || {
            let closed = write_gate.read().unwrap_or_else(|e| e.into_inner());
            if *closed || write_cancel.load(Ordering::Acquire) {
                return Err(BrowserReportError::Cancelled);
            }
            persist_download_origin_idempotent(&store, &dl_state, record, Some(&write_cancel))
        })
        .await
        .map_err(|err| BrowserReportError::Invalid(format!("SQLite download persistence task failed: {err}")))??;

        cancel_guard.disarm();
        Ok(persisted)
    }

    /// Resolves MOTW provenance for a starting process in 3 stages:
    /// 1. Case-insensitive `download_origins.file_path` with current-binary SHA-256 verification
    /// 2. `download_origins.sha256` (when file size `<= download_hash_max_bytes`, computing fresh
    ///    SHA-256 and caching SQLite lookup results by `(sha256, generation)`)
    /// 3. NTFS `:Zone.Identifier` ADS (`ZoneId >= 3`)
    ///
    /// Skips exited snapshots, `skip_launch_guards` events, empty paths, and `ProtectedOs` binaries.
    pub fn resolve_process_motw(
        &self,
        exe_path: &str,
        exited_at_ms: Option<i64>,
        skip_launch_guards: bool,
    ) -> Option<MotwAttribution> {
        resolve_process_motw_core(
            &self.store,
            &*self.inspector,
            &*self.motw_inspector,
            &self.download_origin_state,
            &self.motw_stage2_cache,
            self.config.download_hash_max_bytes,
            exe_path,
            exited_at_ms,
            skip_launch_guards,
        )
    }

    pub(super) fn should_schedule_process_motw(
        exe_path: &str,
        exited_at_ms: Option<i64>,
        skip_launch_guards: bool,
    ) -> Option<String> {
        if exited_at_ms.is_some() || skip_launch_guards {
            return None;
        }
        let normalized = normalize_windows_path(exe_path);
        if normalized.is_empty()
            || classify_outbound_risk(&normalized) == OutboundRiskClass::ProtectedOs
        {
            return None;
        }
        Some(normalized)
    }

    pub(super) async fn resolve_process_motw_budgeted(
        &self,
        instance_id: Option<&str>,
        exe_path: &str,
        exited_at_ms: Option<i64>,
        skip_launch_guards: bool,
    ) -> Option<MotwAttribution> {
        let normalized_exe =
            Self::should_schedule_process_motw(exe_path, exited_at_ms, skip_launch_guards)?;
        let inst_id = instance_id.unwrap_or_default().to_string();
        let budget_ms = self.config.motw_sync_wait_budget_ms;
        match self.motw_pool.submit_process_motw(
            inst_id,
            normalized_exe,
            budget_ms > 0,
        ) {
            SubmitProcessMotwOutcome::Await(mut rx) => {
                match tokio::time::timeout(Duration::from_millis(budget_ms), &mut rx).await {
                    Ok(Ok(attr)) => attr,
                    Ok(Err(_)) => None,
                    Err(_) => {
                        // Close receiver and drain immediately in case worker just completed;
                        // otherwise the worker forwards any late result to `motw_result_tx`.
                        rx.close();
                        rx.try_recv().ok().flatten()
                    }
                }
            }
            SubmitProcessMotwOutcome::QueuedAsync | SubmitProcessMotwOutcome::Rejected => None,
        }
    }

    pub(super) fn submit_seed_motw_groups(&self, groups: Vec<SeedMotwGroup>) -> usize {
        self.motw_pool.submit_seed_motw_groups(groups)
    }

    /// Validates, deduplicates (30 s window, max 256 entries), and persists a `LAYER_4_BROWSER`
    /// security alert (`ReportBrowserEvent`). By default (`L-19`), suppresses OS toast notices.
    pub fn record_browser_event(
        &self,
        event_type: BrowserSecurityEventType,
        url: &str,
        details: Option<&str>,
        timestamp_ms: i64,
    ) -> Result<BrowserEventOutcome, BrowserReportError> {
        if self.is_shutdown_drain_cutoff() {
            return Err(BrowserReportError::Cancelled);
        }
        let clean_url = url.trim();
        if clean_url.is_empty() {
            return Err(BrowserReportError::Invalid(
                "browser event url cannot be empty".to_string(),
            ));
        }

        let (truncated_details, details_truncated) =
            match details.map(str::trim).filter(|s| !s.is_empty()) {
                Some(raw) => {
                    let (slice, truncated) =
                        truncate_utf8_bytes(raw, MAX_BROWSER_EVENT_DETAILS_BYTES);
                    (Some(slice.to_string()), truncated)
                }
                None => (None, false),
            };

        let effective_ts = if timestamp_ms > 0 {
            timestamp_ms
        } else {
            current_unix_ms()
        };
        let norm_url = normalize_browser_event_url(clean_url);

        {
            let mut dedup = self
                .browser_event_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.should_emit(event_type, &norm_url, effective_ts) {
                return Ok(BrowserEventOutcome::Deduplicated);
            }
        }

        let (severity, title) = match event_type {
            BrowserSecurityEventType::ClickFixPastejacking => (
                AlertSeverity::High,
                "Browser ClickFix / Pastejacking Detected",
            ),
            BrowserSecurityEventType::NrdPasswordWarning => (
                AlertSeverity::High,
                "Password Entry on Newly Registered Domain",
            ),
            BrowserSecurityEventType::HomographWarning => (
                AlertSeverity::High,
                "Password Entry on Homograph / Lookalike Domain",
            ),
            BrowserSecurityEventType::DnrBlockedRequest => (
                AlertSeverity::Medium,
                "Browser Blocked Request to Malicious Domain",
            ),
        };

        let context_json = serde_json::json!({
            "event_type": event_type,
            "url": clean_url,
            "details": truncated_details,
            "details_truncated": details_truncated,
        })
        .to_string();

        let alert = AlertRecord {
            alert_id: Uuid::new_v4().to_string(),
            timestamp_ms: effective_ts,
            severity,
            source_layer: "LAYER_4_BROWSER".to_string(),
            rule_id: format!("BROWSER-{event_type:?}"),
            title: title.to_string(),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        if let Err(err) = self.record_alert_checked(&alert) {
            self.browser_event_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove_key(event_type, &norm_url);
            return Err(BrowserReportError::Store(err));
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        if self.config.notify_browser_events {
            if let Err(err) = self.notifier.notify_alert(&alert) {
                tracing::warn!(
                    alert_id = %alert.alert_id,
                    error = %err,
                    "failed to dispatch toast notification for browser event alert"
                );
            }
        }

        Ok(BrowserEventOutcome::Recorded(alert))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use ledr_rules::BinaryIdentity;

    struct StaticTestBinaryInspector;

    impl BinaryInspector for StaticTestBinaryInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                authenticode: None,
            }
        }
    }

    struct StaticTestMotwInspector {
        seed_calls: AtomicUsize,
    }

    impl MotwInspector for StaticTestMotwInspector {
        fn read_zone_identifier(&self, path: &Path) -> Option<MotwZoneInfo> {
            let raw = path.display().to_string();
            if raw.contains("seed_") {
                self.seed_calls.fetch_add(1, Ordering::AcqRel);
            }
            Some(MotwZoneInfo {
                zone_id: 3,
                host_url: Some(format!("https://unit.example.invalid/{}", raw.replace('\\', "/"))),
                referrer_url: None,
            })
        }
    }

    #[tokio::test]
    async fn motw_pool_01_pending_late_preempted_by_download_inspect_and_cleared_on_shutdown() {
        let store = LedrStore::open_in_memory().expect("open store");
        let inspector: Arc<dyn BinaryInspector> = Arc::new(StaticTestBinaryInspector);
        let motw_impl = Arc::new(StaticTestMotwInspector {
            seed_calls: AtomicUsize::new(0),
        });
        let motw_inspector: Arc<dyn MotwInspector> = motw_impl.clone();
        let dl_state = Arc::new(AtomicU64::new(0));
        let stage2_cache = Arc::new(Mutex::new(MotwStage2Cache::new(16, 60)));
        let (late_tx, mut late_rx) = mpsc::channel(1);

        // Pre-fill the single slot of `late_tx` so `capacity() == 0`.
        late_tx
            .try_send(LateMotwAttribution {
                instance_ids: vec!["dummy-0".to_string()],
                attribution: MotwAttribution {
                    origin_url: "https://dummy.example.invalid/0".to_string(),
                    referrer_url: None,
                    frame_url: None,
                    sha256: None,
                    zone_id: Some(3),
                    stage: MotwMatchStage::ZoneIdentifierAds,
                },
            })
            .expect("pre-fill late_tx");

        let pool = MotwIoWorkerPool::new(
            store,
            inspector,
            motw_inspector,
            dl_state,
            stage2_cache,
            MAX_DOWNLOAD_HASH_BYTES,
            64,
            late_tx.clone(),
        );

        // Queue 3 real-time async ResolveProcess jobs + 2 startup seed groups while `late_tx` is full.
        for i in 0..3 {
            assert!(matches!(
                pool.submit_process_motw(
                    format!("rt-{i}"),
                    format!(r"C:\Apps\rt_{i}.exe"),
                    false,
                ),
                SubmitProcessMotwOutcome::QueuedAsync
            ));
        }
        assert_eq!(
            pool.submit_seed_motw_groups(vec![
                SeedMotwGroup {
                    exe_path: r"C:\Apps\seed_0.exe".to_string(),
                    instance_ids: vec!["seed-0".to_string()],
                },
                SeedMotwGroup {
                    exe_path: r"C:\Apps\seed_1.exe".to_string(),
                    instance_ids: vec!["seed-1".to_string()],
                },
            ]),
            2
        );

        // Wait until all 3 real-time jobs have been stashed into bounded `pending_late`
        // and all reservation slots have been released.
        let stash_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (pending_len, reserved_slots) = {
                let state = pool
                    .queue_pair
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                (state.pending_late.len(), state.reserved_late_slots)
            };
            if pending_len == 3 && reserved_slots == 0 {
                break;
            }
            assert!(
                Instant::now() < stash_deadline,
                "timed out waiting for 3 pending_late items (pending={pending_len}, reserved={reserved_slots})"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_eq!(
            motw_impl.seed_calls.load(Ordering::Acquire),
            0,
            "seed_backlog must remain gated while late_tx is full"
        );

        // `submit_download_inspect` must preempt both `pending_late` and `seed_backlog` immediately.
        let cancel = Arc::new(AtomicBool::new(false));
        let SubmitDownloadIoOutcome::Await(dl_rx) = pool.submit_download_inspect(
            r"C:\Apps\download_probe.exe".to_string(),
            MAX_DOWNLOAD_HASH_BYTES,
            cancel,
        ) else {
            panic!("expected SubmitDownloadIoOutcome::Await");
        };
        let dl_res = tokio::time::timeout(Duration::from_secs(1), dl_rx)
            .await
            .expect("download inspect must not block behind full late_tx")
            .expect("download inspect oneshot");
        assert!(!dl_res.cancelled);
        assert!(dl_res.sha256.is_some());
        assert_eq!(
            motw_impl.seed_calls.load(Ordering::Acquire),
            0,
            "seed_backlog must still stay gated after download inspect while late_tx is full"
        );

        // Drain dummy + 3 pending_late + 2 seed groups: `flushing_pending_late == 0` gate ensures
        // all 3 `pending_late` arrive before any `seed_backlog` starts, without depending on the
        // intra-group order across 2 concurrent workers.
        let dummy = late_rx.recv().await.expect("recv dummy");
        assert_eq!(dummy.instance_ids, vec!["dummy-0"]);
        pool.notify_late_result_consumed();

        let mut rt_received: HashSet<String> = HashSet::new();
        for idx in 0..3 {
            let item = tokio::time::timeout(Duration::from_secs(2), late_rx.recv())
                .await
                .expect("timed out draining pending_late")
                .expect("late_rx open");
            assert_eq!(item.instance_ids.len(), 1);
            let id = item.instance_ids[0].clone();
            assert!(
                id.starts_with("rt-"),
                "pending_late real-time results must flush before seed_backlog (idx={idx}, got={id})"
            );
            assert!(rt_received.insert(id), "duplicate rt id received");
            if idx < 2 {
                // While >= 1 pending_late remains (in queue, flushing, or occupying capacity-1 late_tx),
                // no seed_backlog group may start.
                assert_eq!(
                    motw_impl.seed_calls.load(Ordering::Acquire),
                    0,
                    "seed_backlog started before final pending_late was received (idx={idx})"
                );
            }
            pool.notify_late_result_consumed();
        }
        assert_eq!(
            rt_received,
            HashSet::from(["rt-0".to_string(), "rt-1".to_string(), "rt-2".to_string()])
        );

        let mut seed_received: HashSet<String> = HashSet::new();
        for _ in 0..2 {
            let item = tokio::time::timeout(Duration::from_secs(2), late_rx.recv())
                .await
                .expect("timed out draining seed_backlog")
                .expect("late_rx open");
            assert_eq!(item.instance_ids.len(), 1);
            let id = item.instance_ids[0].clone();
            assert!(
                id.starts_with("seed-"),
                "expected seed_backlog group after pending_late drained (got={id})"
            );
            assert!(seed_received.insert(id), "duplicate seed id received");
            pool.notify_late_result_consumed();
        }
        assert_eq!(
            seed_received,
            HashSet::from(["seed-0".to_string(), "seed-1".to_string()])
        );
        assert_eq!(motw_impl.seed_calls.load(Ordering::Acquire), 2);

        // Re-fill `late_tx` and enqueue one more pending_late item, then verify `request_shutdown`
        // clears all queues and joins cleanly with zero lingering reservations.
        late_tx
            .try_send(LateMotwAttribution {
                instance_ids: vec!["dummy-1".to_string()],
                attribution: MotwAttribution {
                    origin_url: "https://dummy.example.invalid/1".to_string(),
                    referrer_url: None,
                    frame_url: None,
                    sha256: None,
                    zone_id: Some(3),
                    stage: MotwMatchStage::ZoneIdentifierAds,
                },
            })
            .expect("refill late_tx");
        assert!(matches!(
            pool.submit_process_motw(
                "rt-shutdown".to_string(),
                r"C:\Apps\rt_shutdown.exe".to_string(),
                false,
            ),
            SubmitProcessMotwOutcome::QueuedAsync
        ));
        let shutdown_stash_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let pending_len = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pending_late
                .len();
            if pending_len >= 1 {
                break;
            }
            assert!(Instant::now() < shutdown_stash_deadline);
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        pool.request_shutdown();
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert!(state.closed);
            assert!(state.download_queue.is_empty());
            assert!(state.process_queue.is_empty());
            assert!(state.pending_late.is_empty());
            assert!(state.seed_backlog.is_empty());
        }
        pool.shutdown_and_join(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.reserved_late_slots, 0);
            assert_eq!(state.flushing_pending_late, 0);
        }
    }

    #[tokio::test]
    async fn motw_pool_02_reserved_late_slots_prevent_drop_and_keep_download_inspect_responsive() {
        let store = LedrStore::open_in_memory().expect("open store");
        let inspector: Arc<dyn BinaryInspector> = Arc::new(StaticTestBinaryInspector);
        let motw_inspector: Arc<dyn MotwInspector> = Arc::new(StaticTestMotwInspector {
            seed_calls: AtomicUsize::new(0),
        });
        let dl_state = Arc::new(AtomicU64::new(0));
        let stage2_cache = Arc::new(Mutex::new(MotwStage2Cache::new(16, 60)));
        let (late_tx, mut late_rx) = mpsc::channel(4);

        for i in 0..4 {
            late_tx
                .try_send(LateMotwAttribution {
                    instance_ids: vec![format!("dummy-{i}")],
                    attribution: MotwAttribution {
                        origin_url: format!("https://dummy.example.invalid/{i}"),
                        referrer_url: None,
                        frame_url: None,
                        sha256: None,
                        zone_id: Some(3),
                        stage: MotwMatchStage::ZoneIdentifierAds,
                    },
                })
                .expect("pre-fill late_tx");
        }

        let pool = MotwIoWorkerPool::new(
            store,
            inspector,
            motw_inspector,
            dl_state,
            stage2_cache,
            MAX_DOWNLOAD_HASH_BYTES,
            64,
            late_tx.clone(),
        );

        // Wave 1: Submit 64 real-time jobs while `late_tx` is full -> all stash into `pending_late`.
        for i in 0..64 {
            assert!(matches!(
                pool.submit_process_motw(
                    format!("rt-{i:03}"),
                    format!(r"C:\Apps\rt_{i:03}.exe"),
                    false,
                ),
                SubmitProcessMotwOutcome::QueuedAsync
            ));
        }
        let wave1_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (pending_len, proc_len, reserved, busy) = {
                let state = pool
                    .queue_pair
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                (
                    state.pending_late.len(),
                    state.process_queue.len(),
                    state.reserved_late_slots,
                    pool.busy_workers.load(Ordering::Acquire),
                )
            };
            if pending_len == 64 && proc_len == 0 && reserved == 0 && busy == 0 {
                break;
            }
            assert!(
                Instant::now() < wave1_deadline,
                "timed out waiting for wave 1 stash (pending={pending_len}, proc={proc_len}, reserved={reserved}, busy={busy})"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // Wave 2: Submit exactly 2 more jobs (`rt-064`, `rt-065`) so `pending_late` reaches
        // 66/66 while `process_queue`, `download_queue`, `reserved_late_slots`, and `busy_workers`
        // all return to 0.
        for i in 64..66 {
            assert!(matches!(
                pool.submit_process_motw(
                    format!("rt-{i:03}"),
                    format!(r"C:\Apps\rt_{i:03}.exe"),
                    false,
                ),
                SubmitProcessMotwOutcome::QueuedAsync
            ));
        }
        let wave2_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (pending_len, proc_len, dl_len, reserved, busy) = {
                let state = pool
                    .queue_pair
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                (
                    state.pending_late.len(),
                    state.process_queue.len(),
                    state.download_queue.len(),
                    state.reserved_late_slots,
                    pool.busy_workers.load(Ordering::Acquire),
                )
            };
            if pending_len == MOTW_PENDING_LATE_CAPACITY
                && proc_len == 0
                && dl_len == 0
                && reserved == 0
                && busy == 0
            {
                break;
            }
            assert!(
                Instant::now() < wave2_deadline,
                "timed out waiting for wave 2 saturation (pending={pending_len}, proc={proc_len}, dl={dl_len}, reserved={reserved}, busy={busy})"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        // Wave 3: With workers completely idle and queues empty (`in_flight_and_queued == 0 <
        // MOTW_IO_WORKERS`), submitting `rt-066` with `allow_sync_wait = true` must still return
        // `QueuedAsync` SOLELY because `has_late_slot == false`.
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let busy = pool.busy_workers.load(Ordering::Acquire);
            let in_flight_and_queued =
                busy + state.download_queue.len() + state.process_queue.len();
            assert_eq!(state.pending_late.len(), MOTW_PENDING_LATE_CAPACITY);
            assert!(state.process_queue.is_empty());
            assert!(state.download_queue.is_empty());
            assert_eq!(state.reserved_late_slots, 0);
            assert_eq!(busy, 0);
            assert!(
                in_flight_and_queued < MOTW_IO_WORKERS,
                "precondition failed: workers must be idle so only `has_late_slot == false` suppresses sync wait"
            );
        }
        assert!(matches!(
            pool.submit_process_motw(
                "rt-066".to_string(),
                r"C:\Apps\rt_066.exe".to_string(),
                true,
            ),
            SubmitProcessMotwOutcome::QueuedAsync
        ));
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.process_queue.len(), 1);
            assert_eq!(state.pending_late.len(), MOTW_PENDING_LATE_CAPACITY);
            assert_eq!(state.reserved_late_slots, 0);
        }

        // Wave 4: Fill the remaining 63 slots of `process_queue` (`rt-067`..`rt-129`, 130 accepted
        // total), verify the 131st is rejected at entry, and confirm `submit_download_inspect`
        // preempts all saturated process/late queues in under 1 second.
        for i in 67..130 {
            assert!(matches!(
                pool.submit_process_motw(
                    format!("rt-{i:03}"),
                    format!(r"C:\Apps\rt_{i:03}.exe"),
                    false,
                ),
                SubmitProcessMotwOutcome::QueuedAsync
            ));
        }
        assert!(matches!(
            pool.submit_process_motw(
                "rt-overflow".to_string(),
                r"C:\Apps\rt_overflow.exe".to_string(),
                false,
            ),
            SubmitProcessMotwOutcome::Rejected
        ));
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.process_queue.len(), MOTW_IO_QUEUE_CAPACITY);
            assert_eq!(state.pending_late.len(), MOTW_PENDING_LATE_CAPACITY);
            assert_eq!(state.reserved_late_slots, 0);
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let SubmitDownloadIoOutcome::Await(dl_rx) = pool.submit_download_inspect(
            r"C:\Apps\urgent_dl_during_saturation.exe".to_string(),
            MAX_DOWNLOAD_HASH_BYTES,
            cancel,
        ) else {
            panic!("expected SubmitDownloadIoOutcome::Await while process_queue is full");
        };
        let dl_res = tokio::time::timeout(Duration::from_secs(1), dl_rx)
            .await
            .expect("download inspect must preempt saturated process_queue and pending_late")
            .expect("download inspect oneshot");
        assert!(!dl_res.cancelled);
        assert!(dl_res.sha256.is_some());
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.process_queue.len(), MOTW_IO_QUEUE_CAPACITY);
            assert_eq!(state.pending_late.len(), MOTW_PENDING_LATE_CAPACITY);
        }

        // Wave 5: Drain the 4 dummies, then drain all 130 accepted `rt-*` items slowly and verify
        // the invariant `pending_late.len() + reserved_late_slots <= MOTW_PENDING_LATE_CAPACITY`
        // holds throughout and zero accepted attributions are dropped.
        for i in 0..4 {
            let dummy = late_rx.recv().await.expect("recv dummy");
            assert_eq!(dummy.instance_ids, vec![format!("dummy-{i}")]);
            pool.notify_late_result_consumed();
        }

        let mut received: HashSet<String> = HashSet::with_capacity(130);
        for i in 0..130 {
            let item = tokio::time::timeout(Duration::from_secs(5), late_rx.recv())
                .await
                .expect("timed out draining accepted MOTW attribution")
                .expect("late_rx open");
            assert_eq!(item.instance_ids.len(), 1);
            assert!(
                received.insert(item.instance_ids[0].clone()),
                "duplicate attribution received: {}",
                item.instance_ids[0]
            );
            pool.notify_late_result_consumed();
            {
                let state = pool
                    .queue_pair
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                assert!(
                    state.pending_late.len() + state.reserved_late_slots
                        <= MOTW_PENDING_LATE_CAPACITY,
                    "late reservation invariant violated: pending={} reserved={}",
                    state.pending_late.len(),
                    state.reserved_late_slots
                );
            }
            if i % 20 == 19 {
                tokio::task::yield_now().await;
            }
        }
        let expected: HashSet<String> = (0..130).map(|i| format!("rt-{i:03}")).collect();
        assert_eq!(received, expected);
        assert!(!received.contains("rt-overflow"));

        // Verify worker counters return to idle (0 reserved, 0 flushing) even before shutdown.
        let idle_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let (reserved, flushing, pending_len, proc_len) = {
                let state = pool
                    .queue_pair
                    .0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                (
                    state.reserved_late_slots,
                    state.flushing_pending_late,
                    state.pending_late.len(),
                    state.process_queue.len(),
                )
            };
            if reserved == 0 && flushing == 0 && pending_len == 0 && proc_len == 0 {
                break;
            }
            assert!(
                Instant::now() < idle_deadline,
                "timed out waiting for idle counters (reserved={reserved}, flushing={flushing}, pending={pending_len}, proc={proc_len})"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        pool.shutdown_and_join(tokio::time::Instant::now() + Duration::from_secs(2))
            .await;
        {
            let state = pool
                .queue_pair
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            assert_eq!(state.reserved_late_slots, 0);
            assert_eq!(state.flushing_pending_late, 0);
        }
    }
}
