//! Layer 3 embedded SQLite WAL time-series store, batch writer, and TTL purge engine.

mod alerts;
mod batch;
mod diagnostics;
mod maintenance;
mod queries;
mod rules;
mod schema;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ledr_proto::{
    AlertStatus, DownloadOriginRecord, SensorEvent, DEFAULT_TTL_RETENTION_DAYS,
};
use rusqlite::{params, Connection};
use thiserror::Error;

use schema::{apply_pragmas, reader_open_flags, writer_open_flags, SCHEMA_DDL};

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
}

#[derive(Default)]
struct BatchBuffer {
    events: Vec<BufferedEvent>,
    first_buffered_at: Option<Instant>,
}

struct StoreInner {
    writer: Arc<Mutex<Connection>>,
    reader: Arc<Mutex<Connection>>,
    batch: Mutex<BatchBuffer>,
    shutdown_requested: AtomicBool,
    purge_batches_completed: AtomicUsize,
    purge_batch_delay_ms: AtomicU64,
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
        apply_pragmas(&writer)?;
        writer.execute_batch(SCHEMA_DDL)?;

        let reader = Connection::open_with_flags(path, reader_open_flags())?;
        apply_pragmas(&reader)?;

        Ok(Self {
            inner: Arc::new(StoreInner {
                writer: Arc::new(Mutex::new(writer)),
                reader: Arc::new(Mutex::new(reader)),
                batch: Mutex::new(BatchBuffer::default()),
                shutdown_requested: AtomicBool::new(false),
                purge_batches_completed: AtomicUsize::new(0),
                purge_batch_delay_ms: AtomicU64::new(0),
            }),
        })
    }

    /// Opens an in-memory SQLite store sharing a single connection between writer and reader.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        apply_pragmas(&conn)?;
        conn.execute_batch(SCHEMA_DDL)?;

        let shared = Arc::new(Mutex::new(conn));
        Ok(Self {
            inner: Arc::new(StoreInner {
                writer: Arc::clone(&shared),
                reader: shared,
                batch: Mutex::new(BatchBuffer::default()),
                shutdown_requested: AtomicBool::new(false),
                purge_batches_completed: AtomicUsize::new(0),
                purge_batch_delay_ms: AtomicU64::new(0),
            }),
        })
    }

    /// Signals that shutdown is in progress so batched TTL purges abort cleanly between batches (`BUG_0004`).
    pub fn request_shutdown(&self) {
        self.inner.shutdown_requested.store(true, Ordering::Release);
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

    fn lock_writer(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.inner
            .writer
            .lock()
            .map_err(|_| StoreError::LockPoisoned("writer"))
    }

    fn lock_reader(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.inner
            .reader
            .lock()
            .map_err(|_| StoreError::LockPoisoned("reader"))
    }

    fn lock_batch(&self) -> Result<MutexGuard<'_, BatchBuffer>, StoreError> {
        self.inner
            .batch
            .lock()
            .map_err(|_| StoreError::LockPoisoned("batch"))
    }

    /// Records a browser download origin entry into `download_origins`.
    pub fn record_download_origin(&self, origin: &DownloadOriginRecord) -> Result<(), StoreError> {
        let writer = self.lock_writer()?;
        writer.execute(
            "INSERT INTO download_origins (
                file_path, sha256, tab_url, frame_url, referrer_url, downloaded_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                origin.file_path,
                origin.sha256,
                origin.tab_url,
                origin.frame_url,
                origin.referrer_url,
                origin.downloaded_at_ms,
            ],
        )?;
        Ok(())
    }

    /// Flushes all buffered events and executes `PRAGMA wal_checkpoint(TRUNCATE);` (`AUTO-10`).
    pub fn checkpoint_truncate(&self) -> Result<(), StoreError> {
        self.flush_batch()?;
        let writer = self.lock_writer()?;
        let (busy, log_frames, checkpointed): (i64, i64, i64) =
            writer.query_row("PRAGMA wal_checkpoint(TRUNCATE);", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        tracing::debug!(
            busy,
            log_frames,
            checkpointed,
            "completed wal_checkpoint(TRUNCATE)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests;
