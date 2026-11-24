//! Layer 3 embedded SQLite WAL time-series store, batch writer, and TTL purge engine.

mod alerts;
mod batch;
mod diagnostics;
mod honeypots;
mod maintenance;
mod queries;
mod rules;
mod schema;

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use ledr_proto::{
    AlertStatus, DownloadOriginRecord, SensorEvent, DEFAULT_TTL_RETENTION_DAYS,
};
use rusqlite::{params, Connection};
use thiserror::Error;

use schema::{
    apply_reader_pragmas, apply_writer_pragmas, reader_open_flags, writer_open_flags, SCHEMA_DDL,
};

/// Returns the store crate version string.
pub fn store_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the bundled SQLite engine version string via `rusqlite`.
pub fn sqlite_version() -> &'static str {
    tracing::trace!("querying bundled SQLite version");
    rusqlite::version()
}

/// Returns the default telemetry retention window in days (`ledr_proto::DEFAULT_TTL_RETENTION_DAYS`).
pub fn default_retention_days() -> u32 {
    DEFAULT_TTL_RETENTION_DAYS
}

/// Returns the initial status assigned to newly recorded alerts.
pub fn default_alert_status() -> AlertStatus {
    AlertStatus::Pending
}

/// Errors produced by [`LedrStore`] operations.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid database value for {field}: {value}")]
    InvalidValue { field: &'static str, value: String },
    #[error("internal mutex poisoned: {0}")]
    LockPoisoned(&'static str),
}

/// Row counts deleted during a [`LedrStore::purge_expired`] run (`L-11`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeStats {
    pub processes_deleted: usize,
    pub dns_deleted: usize,
    pub network_deleted: usize,
    pub canary_deleted: usize,
    pub alerts_deleted: usize,
    pub downloads_deleted: usize,
}

#[derive(Debug, Clone)]
struct BufferedEvent {
    event: SensorEvent,
    parent_instance_id: Option<String>,
    is_nrd: bool,
    action: String,
    received_at_ms: i64,
    /// Inferred exit time supplied by the daemon when a `ProcessStart` describes an older
    /// incarnation already superseded in memory; `None` for every other event.
    exited_at_ms: Option<i64>,
    /// Previous `(process_instance_id, exit_ms)` closed in memory when a `ProcessStart`
    /// supersedes an earlier active row (such as a `pid:0` snapshot placeholder); `None` for
    /// every other event.
    superseded_process_exit: Option<(String, i64)>,
    /// MOTW / browser origin URL attached on `ProcessStart`; `None` for every other event.
    origin_url: Option<String>,
    /// Lowercase hex SHA-256 attached on `ProcessStart` when known; `None` for every other event.
    sha256: Option<String>,
}

const MAX_PENDING_SUPERSEDED_EXITS: usize = 1_024;

#[derive(Default)]
struct BatchBuffer {
    events: Vec<BufferedEvent>,
    first_buffered_at: Option<Instant>,
}

/// Bounded map of superseded process exit timestamps whose target row has not yet been inserted
/// into SQLite due to concurrent startup snapshot / ETW persistence reordering.
#[derive(Default)]
struct PendingSupersededExits {
    by_id: HashMap<String, i64>,
    fifo: VecDeque<String>,
}

impl PendingSupersededExits {
    fn snapshot(&self) -> HashMap<String, i64> {
        self.by_id.clone()
    }

    fn get(&self, instance_id: &str) -> Option<i64> {
        self.by_id.get(instance_id).copied()
    }

    fn remove(&mut self, instance_id: &str) {
        self.by_id.remove(instance_id);
        self.compact_fifo_if_needed();
    }

    fn insert_bounded(&mut self, instance_id: String, exit_ms: i64) {
        if self.by_id.contains_key(&instance_id) {
            return;
        }
        self.by_id.insert(instance_id.clone(), exit_ms);
        self.fifo.push_back(instance_id);
        while self.by_id.len() > MAX_PENDING_SUPERSEDED_EXITS {
            let Some(oldest) = self.fifo.pop_front() else {
                break;
            };
            self.by_id.remove(&oldest);
        }
        self.compact_fifo_if_needed();
    }

    fn apply_delta(&mut self, consumed: &[String], inserted: Vec<(String, i64)>) {
        for id in consumed {
            self.by_id.remove(id);
        }
        for (id, exit_ms) in inserted {
            self.insert_bounded(id, exit_ms);
        }
        self.compact_fifo_if_needed();
    }

    fn compact_fifo_if_needed(&mut self) {
        if self.fifo.len() > MAX_PENDING_SUPERSEDED_EXITS * 2 {
            let by_id = &self.by_id;
            self.fifo.retain(|id| by_id.contains_key(id));
        }
    }
}

struct StoreInner {
    writer: Arc<Mutex<Connection>>,
    reader: Arc<Mutex<Connection>>,
    batch: Mutex<BatchBuffer>,
    pending_superseded_exits: Mutex<PendingSupersededExits>,
    shutdown_requested: AtomicBool,
    purge_batches_completed: AtomicUsize,
    purge_batch_delay_ms: AtomicU64,
    opened_at: Instant,
    last_reader_access_ns: AtomicU64,
    reader_shrunk_since_access: AtomicBool,
    #[cfg(test)]
    test_elapsed_offset_ns: AtomicU64,
}

/// Thread-safe embedded SQLite WAL store with separated write/read connections (`AUTO-09`).
#[derive(Clone)]
pub struct LedrStore {
    inner: Arc<StoreInner>,
}

impl LedrStore {
    /// Opens a file-backed SQLite store in WAL mode with dedicated writer and read-only query connections.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let writer = Connection::open_with_flags(path, writer_open_flags())?;
        apply_writer_pragmas(&writer)?;
        writer.execute_batch(SCHEMA_DDL)?;

        let reader = Connection::open_with_flags(path, reader_open_flags())?;
        apply_reader_pragmas(&reader)?;

        Ok(Self {
            inner: Arc::new(StoreInner {
                writer: Arc::new(Mutex::new(writer)),
                reader: Arc::new(Mutex::new(reader)),
                batch: Mutex::new(BatchBuffer::default()),
                pending_superseded_exits: Mutex::new(PendingSupersededExits::default()),
                shutdown_requested: AtomicBool::new(false),
                purge_batches_completed: AtomicUsize::new(0),
                purge_batch_delay_ms: AtomicU64::new(0),
                opened_at: Instant::now(),
                last_reader_access_ns: AtomicU64::new(0),
                reader_shrunk_since_access: AtomicBool::new(false),
                #[cfg(test)]
                test_elapsed_offset_ns: AtomicU64::new(0),
            }),
        })
    }

    /// Opens an in-memory SQLite store sharing a single connection between writer and reader.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        apply_writer_pragmas(&conn)?;
        conn.execute_batch(SCHEMA_DDL)?;

        let shared = Arc::new(Mutex::new(conn));
        Ok(Self {
            inner: Arc::new(StoreInner {
                writer: Arc::clone(&shared),
                reader: shared,
                batch: Mutex::new(BatchBuffer::default()),
                pending_superseded_exits: Mutex::new(PendingSupersededExits::default()),
                shutdown_requested: AtomicBool::new(false),
                purge_batches_completed: AtomicUsize::new(0),
                purge_batch_delay_ms: AtomicU64::new(0),
                opened_at: Instant::now(),
                last_reader_access_ns: AtomicU64::new(0),
                reader_shrunk_since_access: AtomicBool::new(false),
                #[cfg(test)]
                test_elapsed_offset_ns: AtomicU64::new(0),
            }),
        })
    }

    /// Signals that shutdown is in progress so batched TTL purges abort cleanly between batches (`BUG_0004`).
    pub fn request_shutdown(&self) {
        self.inner.shutdown_requested.store(true, Ordering::Release);
    }

    /// Clears the shutdown flag when a new engine instance starts on an existing [`LedrStore`]
    /// (`FU-E2E-05`).
    pub fn clear_shutdown_flag(&self) {
        self.inner.shutdown_requested.store(false, Ordering::Release);
    }

    /// Returns `true` after [`LedrStore::request_shutdown`] has been invoked (`BUG_0004`).
    pub fn is_shutdown_requested(&self) -> bool {
        self.inner.shutdown_requested.load(Ordering::Acquire)
    }

    /// Configures an optional per-batch sleep delay (in milliseconds) after each committed TTL purge batch.
    pub fn set_purge_batch_delay_ms(&self, delay_ms: u64) {
        self.inner
            .purge_batch_delay_ms
            .store(delay_ms, Ordering::Release);
    }

    /// Returns the number of non-empty TTL purge batches committed so far.
    pub fn purge_batches_completed(&self) -> usize {
        self.inner.purge_batches_completed.load(Ordering::Acquire)
    }

    fn elapsed_since_open_ns(&self) -> u64 {
        let base = u64::try_from(self.inner.opened_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        #[cfg(test)]
        {
            base.saturating_add(self.inner.test_elapsed_offset_ns.load(Ordering::Acquire))
        }
        #[cfg(not(test))]
        {
            base
        }
    }

    fn record_reader_access(&self) {
        let now_ns = self.elapsed_since_open_ns();
        self.inner
            .last_reader_access_ns
            .store(now_ns, Ordering::Release);
        self.inner
            .reader_shrunk_since_access
            .store(false, Ordering::Release);
    }

    fn reader_idle_ns(&self) -> u64 {
        let now_ns = self.elapsed_since_open_ns();
        let last_ns = self.inner.last_reader_access_ns.load(Ordering::Acquire);
        now_ns.saturating_sub(last_ns)
    }

    #[cfg(test)]
    pub(crate) fn advance_reader_idle_for_test(&self, delta: Duration) {
        let delta_ns = u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX);
        self.inner
            .test_elapsed_offset_ns
            .fetch_add(delta_ns, Ordering::AcqRel);
    }

    fn lock_writer(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.inner
            .writer
            .lock()
            .map_err(|_| StoreError::LockPoisoned("writer"))
    }

    fn lock_reader(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        let guard = self
            .inner
            .reader
            .lock()
            .map_err(|_| StoreError::LockPoisoned("reader"))?;
        self.record_reader_access();
        Ok(guard)
    }

    /// Executes `PRAGMA shrink_memory;` on the read-only connection when idle for at least
    /// `idle_threshold` and shutdown has not been requested. Non-blocking on lock contention.
    pub fn shrink_reader_memory_if_idle(
        &self,
        idle_threshold: Duration,
    ) -> Result<bool, StoreError> {
        if self.is_shutdown_requested() {
            return Ok(false);
        }
        if self
            .inner
            .reader_shrunk_since_access
            .load(Ordering::Acquire)
        {
            return Ok(false);
        }
        let threshold_ns = u64::try_from(idle_threshold.as_nanos()).unwrap_or(u64::MAX);
        if self.reader_idle_ns() < threshold_ns {
            return Ok(false);
        }

        let reader = match self.inner.reader.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Ok(false),
            Err(TryLockError::Poisoned(_)) => return Err(StoreError::LockPoisoned("reader")),
        };

        if self.is_shutdown_requested()
            || self
                .inner
                .reader_shrunk_since_access
                .load(Ordering::Acquire)
            || self.reader_idle_ns() < threshold_ns
        {
            return Ok(false);
        }

        reader.execute_batch("PRAGMA shrink_memory;")?;
        self.inner
            .reader_shrunk_since_access
            .store(true, Ordering::Release);
        Ok(true)
    }

    fn lock_batch(&self) -> Result<MutexGuard<'_, BatchBuffer>, StoreError> {
        self.inner
            .batch
            .lock()
            .map_err(|_| StoreError::LockPoisoned("batch"))
    }

    fn lock_pending_superseded_exits(
        &self,
    ) -> Result<MutexGuard<'_, PendingSupersededExits>, StoreError> {
        self.inner
            .pending_superseded_exits
            .lock()
            .map_err(|_| StoreError::LockPoisoned("pending_superseded_exits"))
    }

    /// Records a browser download origin entry into `download_origins`.
    pub fn record_download_origin(&self, origin: &DownloadOriginRecord) -> Result<(), StoreError> {
        let normalized_path = normalize_windows_path(&origin.file_path);
        let normalized_sha256 = normalize_sha256(origin.sha256.as_deref());
        let writer = self.lock_writer()?;
        writer.execute(
            "INSERT INTO download_origins (
                file_path, sha256, tab_url, frame_url, referrer_url, downloaded_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                normalized_path,
                normalized_sha256,
                origin.tab_url,
                origin.frame_url,
                origin.referrer_url,
                origin.downloaded_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Backfills missing MOTW `origin_url` and `sha256` on a `ProcessStart` without overwriting
    /// already-populated columns (`COALESCE`), updating both any pending batch buffer entry and
    /// committed `processes` row under the canonical `writer -> batch` lock order.
    pub fn update_process_motw_metadata(
        &self,
        process_instance_id: &str,
        origin_url: Option<&str>,
        sha256: Option<&str>,
    ) -> Result<bool, StoreError> {
        let clean_instance = process_instance_id.trim();
        let clean_origin = origin_url
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let clean_sha256 = normalize_sha256(sha256);
        if clean_instance.is_empty() || (clean_origin.is_none() && clean_sha256.is_none()) {
            return Ok(false);
        }

        let writer = self.lock_writer()?;
        let mut updated_in_batch = false;
        {
            let mut batch = self.lock_batch()?;
            for buffered in &mut batch.events {
                if let SensorEvent::ProcessStart { identity, .. } = &buffered.event {
                    if identity.instance_id() == clean_instance {
                        if buffered.origin_url.is_none() && clean_origin.is_some() {
                            buffered.origin_url = clean_origin.clone();
                            updated_in_batch = true;
                        }
                        if buffered.sha256.is_none() && clean_sha256.is_some() {
                            buffered.sha256 = clean_sha256.clone();
                            updated_in_batch = true;
                        }
                    }
                }
            }
        }

        let rows_affected = writer.execute(
            "UPDATE processes
             SET origin_url = COALESCE(origin_url, ?1),
                 sha256 = COALESCE(sha256, ?2)
             WHERE process_instance_id = ?3",
            params![clean_origin, clean_sha256, clean_instance],
        )?;

        Ok(updated_in_batch || rows_affected > 0)
    }

    /// Flushes all buffered events and executes `PRAGMA wal_checkpoint(TRUNCATE);` (`AUTO-10`).
    pub fn checkpoint_truncate(&self) -> Result<(), StoreError> {
        let _ = self.checkpoint_truncate_with_deadline(
            std::time::Instant::now() + std::time::Duration::from_millis(5_000),
        )?;
        Ok(())
    }

    /// Flushes all buffered events and executes `PRAGMA wal_checkpoint(TRUNCATE);`, capping
    /// SQLite's per-attempt `busy_timeout` and retrying briefly until `deadline` if SQLite
    /// reports `busy != 0` (`FU-E2E-05`).
    ///
    /// Returns `Ok(true)` if WAL truncation completed (`busy == 0`), or `Ok(false)` if
    /// `deadline` elapsed while another reader still held a WAL lock (`busy != 0`).
    pub fn checkpoint_truncate_with_deadline(
        &self,
        deadline: std::time::Instant,
    ) -> Result<bool, StoreError> {
        struct BusyTimeoutReset<'a>(&'a Connection);
        impl Drop for BusyTimeoutReset<'_> {
            fn drop(&mut self) {
                let _ = self.0.busy_timeout(Duration::from_millis(5_000));
            }
        }

        self.flush_batch()?;
        loop {
            let now = std::time::Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            let slice = if remaining.is_zero() {
                Duration::ZERO
            } else {
                remaining.min(Duration::from_millis(50))
            };
            let (busy, log_frames, checkpointed): (i64, i64, i64) = {
                let writer = self.lock_writer()?;
                let _reset = BusyTimeoutReset(&writer);
                writer.busy_timeout(slice)?;
                writer.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
            };
            if busy == 0 {
                tracing::debug!(
                    busy,
                    log_frames,
                    checkpointed,
                    "completed wal_checkpoint(TRUNCATE)"
                );
                return Ok(true);
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    busy,
                    log_frames,
                    checkpointed,
                    "wal_checkpoint(TRUNCATE) finished with busy flag at deadline"
                );
                return Ok(false);
            }
            let sleep_for = deadline
                .saturating_duration_since(std::time::Instant::now())
                .min(Duration::from_millis(10));
            if !sleep_for.is_zero() {
                std::thread::sleep(sleep_for);
            }
        }
    }
}

pub(crate) fn normalize_windows_path(raw: &str) -> String {
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

pub(crate) fn normalize_sha256(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
}

#[cfg(test)]
mod tests;
