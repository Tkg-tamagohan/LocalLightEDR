//! Layer 3 embedded SQLite WAL time-series store, batch writer, and TTL purge engine.

mod schema;

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    AlertRecord, AlertStatus, AllowlistRuleRecord, DownloadOriginRecord, FlightRecorderSnapshot,
    ProcessRecord, RuleScope, SensorEvent, DEFAULT_TTL_RETENTION_DAYS,
    STORE_BATCH_FLUSH_INTERVAL_MS, STORE_BATCH_MAX_EVENTS, TTL_PURGE_BATCH_LIMIT,
};
use rusqlite::{params, Connection, DatabaseName, OptionalExtension, Transaction};
use thiserror::Error;

use schema::{
    apply_pragmas, query_pragma_summary, reader_open_flags, row_to_alert, row_to_canary,
    row_to_dns, row_to_download, row_to_network, row_to_process, row_to_rule, writer_open_flags,
    SCHEMA_DDL,
};

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const MS_PER_DAY: i64 = 86_400_000;

const PROCESS_COLS: &str = "process_instance_id, pid, parent_instance_id, ppid, exe_path, command_line, sha256, signer_subject, is_trusted_os, user_sid, origin_url, created_at_ms, exited_at_ms";
const DNS_COLS: &str =
    "id, timestamp_ms, process_instance_id, query_name, query_type, resolved_ips, is_nrd";
const NETWORK_COLS: &str =
    "id, timestamp_ms, process_instance_id, protocol, dst_ip, dst_port, domain_hint, action";
const CANARY_COLS: &str =
    "id, timestamp_ms, process_instance_id, target_path, category, access_mask, action_taken";
const ALERT_COLS: &str = "alert_id, timestamp_ms, severity, source_layer, rule_id, title, process_instance_id, process_suspended, status, context_json, resolved_at_ms";
const RULE_COLS: &str = "rule_id, scope, exe_path_pattern, sha256, signer_subject, root_thumbprint, allowed_target, created_at_ms, created_by";
const DOWNLOAD_COLS: &str =
    "id, file_path, sha256, tab_url, frame_url, referrer_url, downloaded_at_ms";
const PID_TIME_WINDOW_LOOKUP_SQL: &str = "
SELECT process_instance_id FROM processes
WHERE pid = ?1
  AND created_at_ms <= ?2
  AND (exited_at_ms IS NULL OR exited_at_ms >= ?2)
ORDER BY created_at_ms DESC
LIMIT 1";

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

    /// Buffers a normalized sensor event for batched persistence, flushing immediately on
    /// `CanaryFileAccess`, when `STORE_BATCH_MAX_EVENTS` (500) is reached, or when
    /// `STORE_BATCH_FLUSH_INTERVAL_MS` (1000 ms) has elapsed since the oldest buffered event.
    ///
    /// Note on `SensorEvent::ScriptEvaluated`: script telemetry (AMSI / PowerShell 4104) is
    /// evaluated in-memory by `SigmaEngine` (`AUTO-06`, `L-12`) and persisted inside
    /// `alerts.context_json` upon rule match rather than in a dedicated telemetry table in the
    /// 7-table SQLite schema, so `ingest_event` skips buffering it and returns `Ok(false)`.
    ///
    /// Returns `Ok(true)` if an immediate flush occurred.
    pub fn ingest_event(
        &self,
        event: &SensorEvent,
        parent_instance_id: Option<&str>,
        is_nrd: bool,
        action: &str,
    ) -> Result<bool, StoreError> {
        if matches!(event, SensorEvent::ScriptEvaluated { .. }) {
            // Evaluated in-memory by Layer 2 SigmaEngine and stored in alerts.context_json on match.
            tracing::trace!("skipping direct telemetry table buffering for ScriptEvaluated");
            return Ok(false);
        }

        let is_canary = matches!(event, SensorEvent::CanaryFileAccess { .. });
        let buffered = BufferedEvent {
            event: event.clone(),
            parent_instance_id: parent_instance_id.map(str::to_owned),
            is_nrd,
            action: action.to_owned(),
            received_at_ms: current_unix_ms(),
        };

        let should_flush = {
            let mut batch = self.lock_batch()?;
            if batch.events.is_empty() {
                batch.first_buffered_at = Some(Instant::now());
            }
            batch.events.push(buffered);

            is_canary
                || batch.events.len() >= STORE_BATCH_MAX_EVENTS
                || batch.first_buffered_at.is_some_and(|t| {
                    t.elapsed() >= Duration::from_millis(STORE_BATCH_FLUSH_INTERVAL_MS)
                })
        };

        if should_flush {
            self.flush_batch()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Writes all currently buffered events in a single SQLite transaction and returns the count flushed.
    pub fn flush_batch(&self) -> Result<usize, StoreError> {
        let mut writer = self.lock_writer()?;
        if self.lock_batch()?.events.is_empty() {
            return Ok(0);
        }

        let tx = writer.transaction()?;
        let events = match self.drain_batch() {
            Ok(events) => events,
            Err(err) => {
                let _ = tx.rollback();
                return Err(err);
            }
        };
        if events.is_empty() {
            let _ = tx.rollback();
            return Ok(0);
        }

        let count = events.len();
        if let Err(err) = execute_batch_tx(tx, &events, None) {
            let _ = self.prepend_batch(events);
            return Err(err);
        }

        Ok(count)
    }

    /// Flushes buffered events if `STORE_BATCH_FLUSH_INTERVAL_MS` has elapsed since the oldest event arrived.
    pub fn flush_if_interval_elapsed(&self) -> Result<usize, StoreError> {
        let due = {
            let batch = self.lock_batch()?;
            !batch.events.is_empty()
                && batch.first_buffered_at.is_some_and(|t| {
                    t.elapsed() >= Duration::from_millis(STORE_BATCH_FLUSH_INTERVAL_MS)
                })
        };
        if due {
            self.flush_batch()
        } else {
            Ok(0)
        }
    }

    /// Returns the number of events currently queued in the write batch buffer.
    pub fn buffered_len(&self) -> usize {
        self.inner
            .batch
            .lock()
            .map(|batch| batch.events.len())
            .unwrap_or(0)
    }

    /// Upserts a full [`ProcessRecord`] immediately in a transaction (useful for hash/signer/origin enrichment).
    pub fn upsert_process_record(&self, process: &ProcessRecord) -> Result<(), StoreError> {
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        upsert_process_row(&tx, process)?;
        tx.commit()?;
        Ok(())
    }

    /// Records or updates an alert immediately in a transaction (flushing any pending batch first).
    pub fn record_alert(&self, alert: &AlertRecord) -> Result<(), StoreError> {
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let events = match self.drain_batch() {
            Ok(events) => events,
            Err(err) => {
                let _ = tx.rollback();
                return Err(err);
            }
        };

        if let Err(err) = execute_batch_tx(tx, &events, Some(alert)) {
            let _ = self.prepend_batch(events);
            return Err(err);
        }

        Ok(())
    }

    /// Updates an alert's lifecycle status and resolution timestamp; returns `true` if a row existed.
    pub fn update_alert_status(
        &self,
        alert_id: &str,
        status: AlertStatus,
        resolved_at_ms: Option<i64>,
    ) -> Result<bool, StoreError> {
        let writer = self.lock_writer()?;
        let updated = writer.execute(
            "UPDATE alerts SET status = ?1, resolved_at_ms = ?2 WHERE alert_id = ?3",
            params![status.as_db_str(), resolved_at_ms, alert_id],
        )?;
        Ok(updated > 0)
    }

    /// Lists alerts ordered by newest `timestamp_ms` first, optionally filtered by [`AlertStatus`].
    pub fn list_alerts(
        &self,
        status: Option<AlertStatus>,
        limit: usize,
    ) -> Result<Vec<AlertRecord>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let reader = self.lock_reader()?;
        let limit_i64 = clamp_limit(limit);
        let mut records = Vec::new();

        match status {
            Some(status_filter) => {
                let sql = format!(
                    "SELECT {ALERT_COLS} FROM alerts WHERE status = ?1 ORDER BY timestamp_ms DESC LIMIT ?2"
                );
                let mut stmt = reader.prepare(&sql)?;
                let mut rows = stmt.query(params![status_filter.as_db_str(), limit_i64])?;
                while let Some(row) = rows.next()? {
                    records.push(row_to_alert(row)?);
                }
            }
            None => {
                let sql =
                    format!("SELECT {ALERT_COLS} FROM alerts ORDER BY timestamp_ms DESC LIMIT ?1");
                let mut stmt = reader.prepare(&sql)?;
                let mut rows = stmt.query(params![limit_i64])?;
                while let Some(row) = rows.next()? {
                    records.push(row_to_alert(row)?);
                }
            }
        }

        Ok(records)
    }

    /// Queries a [`FlightRecorderSnapshot`] via the separated read-only connection.
    pub fn query_flight_recorder(
        &self,
        limit: usize,
        process_instance_id: Option<&str>,
    ) -> Result<FlightRecorderSnapshot, StoreError> {
        if limit == 0 {
            return Ok(FlightRecorderSnapshot::default());
        }
        let reader = self.lock_reader()?;
        let limit_i64 = clamp_limit(limit);

        let processes = query_table_rows(
            &reader,
            PROCESS_COLS,
            "processes",
            "created_at_ms DESC",
            process_instance_id,
            limit_i64,
            row_to_process,
        )?;
        let dns_queries = query_table_rows(
            &reader,
            DNS_COLS,
            "dns_queries",
            "timestamp_ms DESC, id DESC",
            process_instance_id,
            limit_i64,
            row_to_dns,
        )?;
        let network_events = query_table_rows(
            &reader,
            NETWORK_COLS,
            "network_events",
            "timestamp_ms DESC, id DESC",
            process_instance_id,
            limit_i64,
            row_to_network,
        )?;
        let file_canary_events = query_table_rows(
            &reader,
            CANARY_COLS,
            "file_canary_events",
            "timestamp_ms DESC, id DESC",
            process_instance_id,
            limit_i64,
            row_to_canary,
        )?;
        let download_origins =
            query_downloads(&reader, process_instance_id, processes.first(), limit_i64)?;

        Ok(FlightRecorderSnapshot {
            processes,
            dns_queries,
            network_events,
            file_canary_events,
            download_origins,
        })
    }

    /// Walks `parent_instance_id` upward (with cycle detection) and returns the root-to-leaf ancestor chain.
    pub fn get_process_lineage(
        &self,
        process_instance_id: &str,
    ) -> Result<Vec<ProcessRecord>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("SELECT {PROCESS_COLS} FROM processes WHERE process_instance_id = ?1");
        let mut stmt = reader.prepare(&sql)?;

        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = Some(process_instance_id.to_owned());

        while let Some(id) = current {
            if !visited.insert(id.clone()) {
                tracing::warn!(process_instance_id = %id, "detected cycle in process lineage");
                break;
            }
            let record = stmt
                .query_row(params![id], |row| Ok(row_to_process(row)))
                .optional()?
                .transpose()?;
            match record {
                Some(proc_row) => {
                    current = proc_row.parent_instance_id.clone();
                    chain.push(proc_row);
                }
                None => break,
            }
        }

        chain.reverse();
        Ok(chain)
    }

    /// Lists persisted allowlist/blocklist rules, optionally filtered by [`RuleScope`].
    pub fn list_rules(
        &self,
        scope: Option<RuleScope>,
    ) -> Result<Vec<AllowlistRuleRecord>, StoreError> {
        let reader = self.lock_reader()?;
        let mut rules = Vec::new();

        match scope {
            Some(scope_filter) => {
                let sql = format!(
                    "SELECT {RULE_COLS} FROM allowlist_rules WHERE scope = ?1 ORDER BY created_at_ms DESC, rule_id ASC"
                );
                let mut stmt = reader.prepare(&sql)?;
                let mut rows = stmt.query(params![scope_filter.as_db_str()])?;
                while let Some(row) = rows.next()? {
                    rules.push(row_to_rule(row)?);
                }
            }
            None => {
                let sql = format!(
                    "SELECT {RULE_COLS} FROM allowlist_rules ORDER BY created_at_ms DESC, rule_id ASC"
                );
                let mut stmt = reader.prepare(&sql)?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    rules.push(row_to_rule(row)?);
                }
            }
        }

        Ok(rules)
    }

    /// Inserts or updates an [`AllowlistRuleRecord`] keyed by `rule_id`.
    pub fn upsert_rule(&self, rule: &AllowlistRuleRecord) -> Result<(), StoreError> {
        let writer = self.lock_writer()?;
        writer.execute(
            "INSERT INTO allowlist_rules (
                rule_id, scope, exe_path_pattern, sha256, signer_subject,
                root_thumbprint, allowed_target, created_at_ms, created_by
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(rule_id) DO UPDATE SET
                scope = excluded.scope,
                exe_path_pattern = excluded.exe_path_pattern,
                sha256 = excluded.sha256,
                signer_subject = excluded.signer_subject,
                root_thumbprint = excluded.root_thumbprint,
                allowed_target = excluded.allowed_target,
                created_at_ms = excluded.created_at_ms,
                created_by = excluded.created_by",
            params![
                rule.rule_id,
                rule.scope.as_db_str(),
                rule.exe_path_pattern,
                rule.sha256,
                rule.signer_subject,
                rule.root_thumbprint,
                rule.allowed_target,
                rule.created_at_ms,
                rule.created_by,
            ],
        )?;
        Ok(())
    }

    /// Deletes an allowlist/blocklist rule by `rule_id`; returns `true` if a row was removed.
    pub fn delete_rule(&self, rule_id: &str) -> Result<bool, StoreError> {
        let writer = self.lock_writer()?;
        let deleted = writer.execute(
            "DELETE FROM allowlist_rules WHERE rule_id = ?1",
            params![rule_id],
        )?;
        Ok(deleted > 0)
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

    /// Purges expired records in batches of `TTL_PURGE_BATCH_LIMIT` (500) while preserving
    /// ancestor processes referenced by unpurged children or unresolved alerts (`L-11`).
    ///
    /// Releases the writer mutex between batches and exits early if [`LedrStore::request_shutdown`]
    /// has been signaled (`BUG_0004`).
    pub fn purge_expired(
        &self,
        now_ms: i64,
        retention_days: u32,
    ) -> Result<PurgeStats, StoreError> {
        let retention_ms = i64::from(retention_days).saturating_mul(MS_PER_DAY);
        let cutoff_ms = now_ms.saturating_sub(retention_ms);
        let batch_limit = i64::try_from(TTL_PURGE_BATCH_LIMIT).unwrap_or(500);

        let mut stats = PurgeStats::default();
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        stats.alerts_deleted = self.purge_in_batches(|tx| {
            tx.execute(
                "DELETE FROM alerts
                 WHERE alert_id IN (
                     SELECT alert_id FROM alerts
                     WHERE timestamp_ms < ?1
                       AND status NOT IN ('PENDING', 'EXPIRED_SUSPENDED')
                     LIMIT ?2
                 )",
                params![cutoff_ms, batch_limit],
            )
        })?;
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        stats.dns_deleted =
            self.purge_by_timestamp_id("dns_queries", "timestamp_ms", cutoff_ms, batch_limit)?;
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        stats.network_deleted =
            self.purge_by_timestamp_id("network_events", "timestamp_ms", cutoff_ms, batch_limit)?;
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        stats.canary_deleted = self.purge_by_timestamp_id(
            "file_canary_events",
            "timestamp_ms",
            cutoff_ms,
            batch_limit,
        )?;
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        stats.downloads_deleted = self.purge_by_timestamp_id(
            "download_origins",
            "downloaded_at_ms",
            cutoff_ms,
            batch_limit,
        )?;
        if self.is_shutdown_requested() {
            return Ok(stats);
        }

        // Bottom-up batched purge: each pass removes expired exited leaf processes that have
        // neither unpurged children nor unresolved (PENDING / EXPIRED_SUSPENDED) alerts.
        stats.processes_deleted = self.purge_in_batches(|tx| {
            tx.execute(
                "DELETE FROM processes
                 WHERE process_instance_id IN (
                     SELECT p.process_instance_id
                     FROM processes p
                     WHERE p.exited_at_ms IS NOT NULL
                       AND p.exited_at_ms < ?1
                       AND NOT EXISTS (
                           SELECT 1 FROM processes c
                           WHERE c.parent_instance_id = p.process_instance_id
                       )
                       AND NOT EXISTS (
                           SELECT 1 FROM alerts a
                           WHERE a.process_instance_id = p.process_instance_id
                             AND a.status IN ('PENDING', 'EXPIRED_SUSPENDED')
                       )
                     LIMIT ?2
                 )",
                params![cutoff_ms, batch_limit],
            )
        })?;

        Ok(stats)
    }

    /// Flushes buffered events and returns all `process_instance_id` values currently marked
    /// running (`exited_at_ms IS NULL`) in the store (`BUG_0001`).
    pub fn list_running_process_instance_ids(&self) -> Result<Vec<String>, StoreError> {
        self.flush_batch()?;
        let reader = self.lock_reader()?;
        let mut stmt = reader
            .prepare("SELECT process_instance_id FROM processes WHERE exited_at_ms IS NULL")?;
        let mut rows = stmt.query([])?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next()? {
            ids.push(row.get(0)?);
        }
        Ok(ids)
    }

    /// Marks stale running candidate processes (`process_instance_id` in `candidate_instance_ids`,
    /// absent from `active_instance_ids`, `exited_at_ms IS NULL`, and `created_at_ms <= reconciled_at_ms`)
    /// as exited at `reconciled_at_ms`, returning the updated row count (`BUG_0001`, `BUG_0002`).
    ///
    /// Immediately returns `Ok(0)` without updating any rows if `candidate_instance_ids` or
    /// `active_instance_ids` is empty.
    pub fn reconcile_stale_running_candidates(
        &self,
        candidate_instance_ids: &[String],
        active_instance_ids: &[String],
        reconciled_at_ms: i64,
    ) -> Result<usize, StoreError> {
        if candidate_instance_ids.is_empty() || active_instance_ids.is_empty() {
            return Ok(0);
        }
        self.flush_batch()?;

        let active_set: HashSet<&str> = active_instance_ids.iter().map(String::as_str).collect();
        let mut seen = HashSet::new();
        let stale_ids: Vec<&str> = candidate_instance_ids
            .iter()
            .map(String::as_str)
            .filter(|id| !active_set.contains(*id) && seen.insert(*id))
            .collect();
        if stale_ids.is_empty() {
            return Ok(0);
        }

        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let mut updated = 0usize;
        {
            let mut update_stmt = tx.prepare(
                "UPDATE processes SET exited_at_ms = ?1
                 WHERE process_instance_id = ?2
                   AND exited_at_ms IS NULL
                   AND created_at_ms <= ?1",
            )?;
            for id in stale_ids {
                updated += update_stmt.execute(params![reconciled_at_ms, id])?;
            }
        }
        tx.commit()?;
        Ok(updated)
    }

    /// Marks running processes (`exited_at_ms IS NULL` and `created_at_ms <= reconciled_at_ms`)
    /// whose `process_instance_id` is absent from `active_instance_ids` as exited at
    /// `reconciled_at_ms`, returning the updated row count.
    ///
    /// Immediately returns `Ok(0)` without updating any rows if `active_instance_ids` is empty.
    pub fn reconcile_stale_running_processes(
        &self,
        active_instance_ids: &[String],
        reconciled_at_ms: i64,
    ) -> Result<usize, StoreError> {
        if active_instance_ids.is_empty() {
            return Ok(0);
        }
        self.flush_batch()?;
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;

        let active_set: HashSet<&str> = active_instance_ids.iter().map(String::as_str).collect();
        let stale_ids: Vec<String> = {
            let mut select_stmt = tx.prepare(
                "SELECT process_instance_id FROM processes
                 WHERE exited_at_ms IS NULL AND created_at_ms <= ?1",
            )?;
            let mut rows = select_stmt.query(params![reconciled_at_ms])?;
            let mut stale = Vec::new();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                if !active_set.contains(id.as_str()) {
                    stale.push(id);
                }
            }
            stale
        };

        let mut updated = 0usize;
        if !stale_ids.is_empty() {
            let mut update_stmt = tx.prepare(
                "UPDATE processes SET exited_at_ms = ?1
                 WHERE process_instance_id = ?2 AND exited_at_ms IS NULL",
            )?;
            for id in &stale_ids {
                updated += update_stmt.execute(params![reconciled_at_ms, id])?;
            }
        }

        tx.commit()?;
        Ok(updated)
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

    /// Queries `(journal_mode, cache_size, mmap_size)` on the writer store connection.
    pub fn verify_pragmas(&self) -> Result<(String, i64, i64), StoreError> {
        let writer = self.lock_writer()?;
        query_pragma_summary(&writer)
    }

    /// Queries `(journal_mode, cache_size, mmap_size)` on the read-only query connection.
    pub fn verify_reader_pragmas(&self) -> Result<(String, i64, i64), StoreError> {
        let reader = self.lock_reader()?;
        query_pragma_summary(&reader)
    }

    /// Verifies that the dedicated reader handle is opened read-only and rejects SQL writes.
    pub fn verify_reader_rejects_writes(&self) -> Result<bool, StoreError> {
        let reader = self.lock_reader()?;
        if !reader.is_readonly(DatabaseName::Main)? {
            return Ok(false);
        }
        match reader.execute("CREATE TABLE __ledr_ro_probe (id INTEGER)", []) {
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ReadOnly =>
            {
                Ok(true)
            }
            Err(err) => Err(StoreError::Sqlite(err)),
            Ok(_) => {
                let _ = reader.execute("DROP TABLE IF EXISTS __ledr_ro_probe", []);
                Ok(false)
            }
        }
    }

    /// Returns SQLite `EXPLAIN QUERY PLAN` detail lines for the `(pid, event_ts_ms)` time-window
    /// lookup query used during process attribution (`BUG_0003`).
    pub fn explain_pid_lookup_plan(&self) -> Result<Vec<String>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("EXPLAIN QUERY PLAN\n{PID_TIME_WINDOW_LOOKUP_SQL}");
        let mut stmt = reader.prepare(&sql)?;
        let mut rows = stmt.query(params![4i64, 1_750_000_000_000i64])?;
        let mut details = Vec::new();
        while let Some(row) = rows.next()? {
            details.push(row.get::<_, String>(3)?);
        }
        Ok(details)
    }

    fn purge_in_batches<F>(&self, mut delete_batch: F) -> Result<usize, StoreError>
    where
        F: FnMut(&Transaction<'_>) -> rusqlite::Result<usize>,
    {
        let mut total_deleted = 0usize;
        loop {
            if self.is_shutdown_requested() {
                break;
            }
            let deleted = {
                let mut writer = self.lock_writer()?;
                let tx = writer.transaction()?;
                let deleted = delete_batch(&tx)?;
                tx.commit()?;
                deleted
            };
            total_deleted += deleted;
            if deleted == 0 {
                break;
            }
            self.inner
                .purge_batches_completed
                .fetch_add(1, Ordering::Release);
            let delay_ms = self.inner.purge_batch_delay_ms.load(Ordering::Acquire);
            if delay_ms > 0 && !self.is_shutdown_requested() {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }
        Ok(total_deleted)
    }

    fn purge_by_timestamp_id(
        &self,
        table: &str,
        ts_col: &str,
        cutoff_ms: i64,
        batch_limit: i64,
    ) -> Result<usize, StoreError> {
        let sql = format!(
            "DELETE FROM {table}
             WHERE id IN (
                 SELECT id FROM {table}
                 WHERE {ts_col} < ?1
                 LIMIT ?2
             )"
        );
        self.purge_in_batches(|tx| tx.execute(&sql, params![cutoff_ms, batch_limit]))
    }

    fn drain_batch(&self) -> Result<Vec<BufferedEvent>, StoreError> {
        let mut batch = self.lock_batch()?;
        batch.first_buffered_at = None;
        Ok(std::mem::take(&mut batch.events))
    }

    fn prepend_batch(&self, mut failed_events: Vec<BufferedEvent>) -> Result<(), StoreError> {
        if failed_events.is_empty() {
            return Ok(());
        }
        let mut batch = self.lock_batch()?;
        failed_events.append(&mut batch.events);
        batch.events = failed_events;
        if batch.first_buffered_at.is_none() {
            batch.first_buffered_at = Some(Instant::now());
        }
        Ok(())
    }
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn filetime_100ns_to_unix_ms(ticks: u64, fallback_now_ms: i64) -> i64 {
    if ticks >= WINDOWS_TO_UNIX_EPOCH_100NS {
        let unix_ms = (ticks - WINDOWS_TO_UNIX_EPOCH_100NS) / TICKS_PER_MS;
        i64::try_from(unix_ms).unwrap_or(fallback_now_ms)
    } else {
        fallback_now_ms
    }
}

fn clamp_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn insert_alert_row(tx: &Transaction<'_>, alert: &AlertRecord) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO alerts (
            alert_id, timestamp_ms, severity, source_layer, rule_id, title,
            process_instance_id, process_suspended, status, context_json, resolved_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(alert_id) DO UPDATE SET
            timestamp_ms = excluded.timestamp_ms,
            severity = excluded.severity,
            source_layer = excluded.source_layer,
            rule_id = excluded.rule_id,
            title = excluded.title,
            process_instance_id = excluded.process_instance_id,
            process_suspended = excluded.process_suspended,
            status = excluded.status,
            context_json = excluded.context_json,
            resolved_at_ms = excluded.resolved_at_ms",
        params![
            alert.alert_id,
            alert.timestamp_ms,
            alert.severity.as_db_str(),
            alert.source_layer,
            alert.rule_id,
            alert.title,
            alert.process_instance_id,
            i64::from(alert.process_suspended),
            alert.status.as_db_str(),
            alert.context_json,
            alert.resolved_at_ms,
        ],
    )?;
    Ok(())
}

fn execute_batch_tx(
    tx: Transaction<'_>,
    events: &[BufferedEvent],
    alert: Option<&AlertRecord>,
) -> Result<(), StoreError> {
    if !events.is_empty() {
        write_buffered_events(&tx, events)?;
    }
    if let Some(alert) = alert {
        insert_alert_row(&tx, alert)?;
    }
    tx.commit()?;
    Ok(())
}

fn upsert_process_row(tx: &Transaction<'_>, process: &ProcessRecord) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO processes (
            process_instance_id, pid, parent_instance_id, ppid, exe_path, command_line,
            sha256, signer_subject, is_trusted_os, user_sid, origin_url, created_at_ms, exited_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(process_instance_id) DO UPDATE SET
            pid = excluded.pid,
            parent_instance_id = COALESCE(excluded.parent_instance_id, processes.parent_instance_id),
            ppid = excluded.ppid,
            exe_path = excluded.exe_path,
            command_line = COALESCE(excluded.command_line, processes.command_line),
            sha256 = COALESCE(excluded.sha256, processes.sha256),
            signer_subject = COALESCE(excluded.signer_subject, processes.signer_subject),
            is_trusted_os = CASE
                WHEN excluded.is_trusted_os != 0 THEN 1
                ELSE processes.is_trusted_os
            END,
            user_sid = COALESCE(excluded.user_sid, processes.user_sid),
            origin_url = COALESCE(excluded.origin_url, processes.origin_url),
            exited_at_ms = COALESCE(processes.exited_at_ms, excluded.exited_at_ms)",
        params![
            process.process_instance_id,
            i64::from(process.pid),
            process.parent_instance_id,
            i64::from(process.ppid),
            process.exe_path,
            process.command_line,
            process.sha256,
            process.signer_subject,
            i64::from(process.is_trusted_os),
            process.user_sid,
            process.origin_url,
            process.created_at_ms,
            process.exited_at_ms,
        ],
    )?;
    Ok(())
}

fn instance_id_matches_pid(instance_id: &str, pid: u32) -> bool {
    let Some((pid_part, _)) = instance_id.split_once(':') else {
        return false;
    };
    pid_part.parse::<u32>().ok() == Some(pid)
}

fn resolve_process_instance_id(
    tx: &Transaction<'_>,
    pid: u32,
    event_ts_ms: i64,
    hint: Option<&str>,
) -> Result<String, StoreError> {
    if let Some(matched) = tx
        .query_row(
            PID_TIME_WINDOW_LOOKUP_SQL,
            params![i64::from(pid), event_ts_ms],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        return Ok(matched);
    }

    if let Some(h) = hint.filter(|id| instance_id_matches_pid(id, pid)) {
        let window: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT created_at_ms, exited_at_ms FROM processes
                 WHERE process_instance_id = ?1",
                params![h],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let hint_valid = match window {
            Some((created_at_ms, exited_at_ms)) => {
                created_at_ms <= event_ts_ms && exited_at_ms.is_none_or(|e| event_ts_ms <= e)
            }
            None => true,
        };
        if hint_valid {
            return Ok(h.to_owned());
        }
    }

    Ok(format!("{pid}:0"))
}

fn write_buffered_events(tx: &Transaction<'_>, events: &[BufferedEvent]) -> Result<(), StoreError> {
    for item in events {
        let hint = item.parent_instance_id.as_deref();
        match &item.event {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                user_sid,
            } => {
                let instance_id = identity.instance_id();
                let cmd = (!command_line.is_empty()).then(|| command_line.clone());
                let record = ProcessRecord {
                    process_instance_id: instance_id,
                    pid: identity.pid,
                    parent_instance_id: item.parent_instance_id.clone(),
                    ppid: *parent_pid,
                    exe_path: exe_path.clone(),
                    command_line: cmd,
                    sha256: None,
                    signer_subject: None,
                    is_trusted_os: false,
                    user_sid: user_sid.clone(),
                    origin_url: None,
                    created_at_ms: filetime_100ns_to_unix_ms(
                        identity.create_time_100ns,
                        item.received_at_ms,
                    ),
                    exited_at_ms: None,
                };
                upsert_process_row(tx, &record)?;
            }
            SensorEvent::ProcessStop {
                pid,
                exit_time_100ns,
                exit_code: _,
            } => {
                let exited_at_ms = filetime_100ns_to_unix_ms(*exit_time_100ns, item.received_at_ms);
                let mut handled_by_hint = false;
                if let Some(id) = hint.filter(|id| instance_id_matches_pid(id, *pid)) {
                    let existing: Option<(i64, Option<i64>)> = tx
                        .query_row(
                            "SELECT created_at_ms, exited_at_ms FROM processes
                             WHERE process_instance_id = ?1",
                            params![id],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )
                        .optional()?;
                    if let Some((created_at_ms, existing_exit)) = existing {
                        if created_at_ms <= exited_at_ms {
                            if existing_exit.is_none() {
                                tx.execute(
                                    "UPDATE processes SET exited_at_ms = ?1
                                     WHERE process_instance_id = ?2 AND exited_at_ms IS NULL",
                                    params![exited_at_ms, id],
                                )?;
                            }
                            handled_by_hint = true;
                        }
                    }
                }
                if !handled_by_hint {
                    tx.execute(
                        "UPDATE processes SET exited_at_ms = ?1
                         WHERE process_instance_id = (
                             SELECT process_instance_id
                             FROM processes
                             WHERE pid = ?2
                               AND exited_at_ms IS NULL
                               AND created_at_ms <= ?1
                             ORDER BY created_at_ms DESC
                             LIMIT 1
                         )",
                        params![exited_at_ms, i64::from(*pid)],
                    )?;
                }
            }
            SensorEvent::DnsQuery {
                pid,
                query_name,
                query_type,
                resolved_ips,
                timestamp_ms,
            } => {
                let process_instance_id =
                    resolve_process_instance_id(tx, *pid, *timestamp_ms, hint)?;
                let ip_strings: Vec<String> =
                    resolved_ips.iter().map(ToString::to_string).collect();
                let resolved_json = serde_json::to_string(&ip_strings)?;
                tx.execute(
                    "INSERT INTO dns_queries (
                        timestamp_ms, process_instance_id, query_name, query_type, resolved_ips, is_nrd
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        *timestamp_ms,
                        process_instance_id,
                        query_name,
                        i64::from(*query_type),
                        resolved_json,
                        i64::from(item.is_nrd),
                    ],
                )?;
            }
            SensorEvent::NetworkConnect {
                pid,
                protocol,
                dst_ip,
                dst_port,
                domain_hint,
                timestamp_ms,
            } => {
                let process_instance_id =
                    resolve_process_instance_id(tx, *pid, *timestamp_ms, hint)?;
                tx.execute(
                    "INSERT INTO network_events (
                        timestamp_ms, process_instance_id, protocol, dst_ip, dst_port, domain_hint, action
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        *timestamp_ms,
                        process_instance_id,
                        i64::from(*protocol),
                        dst_ip.to_string(),
                        i64::from(*dst_port),
                        domain_hint,
                        item.action,
                    ],
                )?;
            }
            SensorEvent::CanaryFileAccess {
                pid,
                target_path,
                category,
                access_mask,
                is_write_or_delete: _,
                timestamp_ms,
            } => {
                let process_instance_id =
                    resolve_process_instance_id(tx, *pid, *timestamp_ms, hint)?;
                tx.execute(
                    "INSERT INTO file_canary_events (
                        timestamp_ms, process_instance_id, target_path, category, access_mask, action_taken
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        *timestamp_ms,
                        process_instance_id,
                        target_path,
                        category.as_str(),
                        i64::from(*access_mask),
                        item.action,
                    ],
                )?;
            }
            // Evaluated in-memory by Layer 2 SigmaEngine and stored in alerts.context_json on match.
            SensorEvent::ScriptEvaluated { .. } => {}
        }
    }

    Ok(())
}

fn query_table_rows<T, F>(
    reader: &Connection,
    cols: &str,
    table: &str,
    order_by: &str,
    process_instance_id: Option<&str>,
    limit: i64,
    map_row: F,
) -> Result<Vec<T>, StoreError>
where
    F: Fn(&rusqlite::Row<'_>) -> Result<T, StoreError>,
{
    let mut out = Vec::new();
    match process_instance_id {
        Some(proc_id) => {
            let sql = format!(
                "SELECT {cols} FROM {table} WHERE process_instance_id = ?1 ORDER BY {order_by} LIMIT ?2"
            );
            let mut stmt = reader.prepare(&sql)?;
            let mut rows = stmt.query(params![proc_id, limit])?;
            while let Some(row) = rows.next()? {
                out.push(map_row(row)?);
            }
        }
        None => {
            let sql = format!("SELECT {cols} FROM {table} ORDER BY {order_by} LIMIT ?1");
            let mut stmt = reader.prepare(&sql)?;
            let mut rows = stmt.query(params![limit])?;
            while let Some(row) = rows.next()? {
                out.push(map_row(row)?);
            }
        }
    }
    Ok(out)
}

fn query_downloads(
    reader: &Connection,
    process_instance_id: Option<&str>,
    matched_process: Option<&ProcessRecord>,
    limit: i64,
) -> Result<Vec<DownloadOriginRecord>, StoreError> {
    let mut out = Vec::new();
    match process_instance_id {
        Some(_) => {
            let Some(proc_row) = matched_process else {
                return Ok(out);
            };
            let sql = format!(
                "SELECT {DOWNLOAD_COLS} FROM download_origins
                 WHERE file_path = ?1
                    OR (?2 IS NOT NULL AND sha256 = ?2)
                    OR (?3 IS NOT NULL AND tab_url = ?3)
                 ORDER BY downloaded_at_ms DESC, id DESC
                 LIMIT ?4"
            );
            let mut stmt = reader.prepare(&sql)?;
            let mut rows = stmt.query(params![
                proc_row.exe_path,
                proc_row.sha256,
                proc_row.origin_url,
                limit
            ])?;
            while let Some(row) = rows.next()? {
                out.push(row_to_download(row)?);
            }
        }
        None => {
            let sql = format!(
                "SELECT {DOWNLOAD_COLS} FROM download_origins ORDER BY downloaded_at_ms DESC, id DESC LIMIT ?1"
            );
            let mut stmt = reader.prepare(&sql)?;
            let mut rows = stmt.query(params![limit])?;
            while let Some(row) = rows.next()? {
                out.push(row_to_download(row)?);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledr_proto::{AlertSeverity, ProcessIdentity, ScriptSource};
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn unit_schema_tables_indexes_and_all_seven_pragmas() {
        assert_send_sync::<LedrStore>();

        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("schema_check.db");
        let store = LedrStore::open(&db_path).expect("open store");

        let expected_tables = [
            "alerts",
            "allowlist_rules",
            "dns_queries",
            "download_origins",
            "file_canary_events",
            "network_events",
            "processes",
        ];
        let expected_indexes = [
            "idx_alerts_proc_status",
            "idx_alerts_status_ts",
            "idx_canary_ts",
            "idx_dl_path",
            "idx_dl_sha256",
            "idx_dns_name",
            "idx_dns_ts_proc",
            "idx_net_ts_proc",
            "idx_processes_created",
            "idx_processes_parent",
            "idx_processes_pid_created",
            "idx_processes_sha256",
        ];

        let writer = store.lock_writer().expect("lock writer");
        {
            let mut tbl_stmt = writer
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                     ORDER BY name",
                )
                .expect("prepare tables query");
            let tables: Vec<String> = tbl_stmt
                .query_map([], |row| row.get(0))
                .expect("query tables")
                .map(|r| r.expect("table row"))
                .collect();
            assert_eq!(tables, expected_tables);

            let mut idx_stmt = writer
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'index' AND name LIKE 'idx_%'
                     ORDER BY name",
                )
                .expect("prepare indexes query");
            let indexes: Vec<String> = idx_stmt
                .query_map([], |row| row.get(0))
                .expect("query indexes")
                .map(|r| r.expect("index row"))
                .collect();
            assert_eq!(indexes, expected_indexes);
        }

        // Verify all 7 AUTO-09 PRAGMAs on both writer and reader connections.
        for conn_guard in [writer, store.lock_reader().expect("lock reader")] {
            let jm: String = conn_guard
                .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
                .expect("journal_mode");
            let sync: i64 = conn_guard
                .query_row("PRAGMA synchronous;", [], |r| r.get(0))
                .expect("synchronous");
            let cache: i64 = conn_guard
                .query_row("PRAGMA cache_size;", [], |r| r.get(0))
                .expect("cache_size");
            let temp: i64 = conn_guard
                .query_row("PRAGMA temp_store;", [], |r| r.get(0))
                .expect("temp_store");
            let mmap: i64 = conn_guard
                .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
                .expect("mmap_size");
            let auto_ckpt: i64 = conn_guard
                .query_row("PRAGMA wal_autocheckpoint;", [], |r| r.get(0))
                .expect("wal_autocheckpoint");
            let fk: i64 = conn_guard
                .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
                .expect("foreign_keys");

            assert_eq!(jm.to_ascii_lowercase(), "wal");
            assert_eq!(sync, 1); // NORMAL
            assert_eq!(cache, -2048);
            assert_eq!(temp, 2); // MEMORY
            assert_eq!(mmap, 0);
            assert_eq!(auto_ckpt, 1000);
            assert_eq!(fk, 1);
        }
    }

    #[test]
    fn unit_alerts_downloads_and_script_event_handling() {
        let store = LedrStore::open_in_memory().expect("open in memory");
        let (_, cache_size, mmap_size) = store.verify_pragmas().expect("verify in-memory pragmas");
        assert_eq!(cache_size, -2048);
        assert_eq!(mmap_size, 0);

        // ScriptEvaluated is not directly buffered into raw telemetry tables.
        let script = SensorEvent::ScriptEvaluated {
            pid: 55,
            source: ScriptSource::PowerShell4104,
            script_content: "Write-Output 'ok'".to_string(),
            timestamp_ms: 1_750_000_000_000,
        };
        assert!(!store
            .ingest_event(&script, None, false, "")
            .expect("script event ok"));
        assert_eq!(store.buffered_len(), 0);

        // ProcessStart buffered, then record_alert atomically flushes pending batch + alert.
        let proc_start = SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(55, 133_765_432_101_234_567),
            parent_pid: 4,
            exe_path: r"C:\Users\dev\Downloads\dropper.exe".to_string(),
            command_line: "dropper.exe --run".to_string(),
            user_sid: None,
        };
        assert!(!store
            .ingest_event(&proc_start, Some("4:1"), false, "")
            .expect("buffer process start"));
        assert_eq!(store.buffered_len(), 1);

        let alert = AlertRecord {
            alert_id: "alrt-unit-1".to_string(),
            timestamp_ms: 1_750_000_000_500,
            severity: AlertSeverity::Critical,
            source_layer: "layer2".to_string(),
            rule_id: "lotl_ps".to_string(),
            title: "Suspicious process".to_string(),
            process_instance_id: Some("55:133765432101234567".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: "{}".to_string(),
            resolved_at_ms: None,
        };
        store.record_alert(&alert).expect("record alert");
        assert_eq!(store.buffered_len(), 0);

        let pending = store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .expect("list pending alerts");
        assert_eq!(pending, vec![alert]);

        assert!(store
            .update_alert_status(
                "alrt-unit-1",
                AlertStatus::ApprovedRule,
                Some(1_750_000_001_000)
            )
            .expect("update status"));
        assert!(!store
            .update_alert_status("nonexistent", AlertStatus::Dismissed, None)
            .expect("missing alert returns false"));
        assert!(store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .expect("no pending left")
            .is_empty());

        store
            .record_download_origin(&DownloadOriginRecord {
                id: None,
                file_path: r"C:\Users\dev\Downloads\dropper.exe".to_string(),
                sha256: Some("cafebabe".to_string()),
                tab_url: "https://downloads.example.test/file".to_string(),
                frame_url: None,
                referrer_url: Some("https://downloads.example.test/".to_string()),
                downloaded_at_ms: 1_750_000_000_100,
            })
            .expect("record download origin");

        let snap = store
            .query_flight_recorder(20, Some("55:133765432101234567"))
            .expect("query scoped snapshot");
        assert_eq!(snap.processes.len(), 1);
        assert_eq!(snap.download_origins.len(), 1);
        assert_eq!(
            snap.download_origins[0].tab_url,
            "https://downloads.example.test/file"
        );
    }

    #[test]
    fn unit_concurrent_writer_and_reader_threads() {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("concurrent.db");
        let store = LedrStore::open(&db_path).expect("open store");

        let writer_store = store.clone();
        let writer_handle = std::thread::spawn(move || {
            for i in 0..200 {
                let dns = SensorEvent::DnsQuery {
                    pid: 777,
                    query_name: format!("concurrent-{i}.example.test"),
                    query_type: 1,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                    timestamp_ms: 1_750_000_000_000 + i,
                };
                writer_store
                    .ingest_event(&dns, Some("777:999"), false, "")
                    .expect("ingest dns");
                if i % 50 == 49 {
                    writer_store.flush_batch().expect("flush batch");
                }
            }
        });

        let reader_store = store.clone();
        let reader_handle = std::thread::spawn(move || {
            for _ in 0..40 {
                let _snap = reader_store
                    .query_flight_recorder(50, None)
                    .expect("concurrent flight recorder query");
            }
        });

        writer_handle.join().expect("writer thread");
        reader_handle.join().expect("reader thread");

        let final_snap = store
            .query_flight_recorder(500, None)
            .expect("final snapshot");
        assert_eq!(final_snap.dns_queries.len(), 200);
    }

    #[test]
    fn unit_resolve_process_instance_id_fast_hint_and_fallbacks() {
        let store = LedrStore::open_in_memory().expect("open in-memory store");

        let proc_old = ProcessRecord {
            process_instance_id: "42:1000".to_string(),
            pid: 42,
            parent_instance_id: Some("4:1".to_string()),
            ppid: 4,
            exe_path: r"C:\Temp\old.exe".to_string(),
            command_line: None,
            sha256: None,
            signer_subject: None,
            is_trusted_os: false,
            user_sid: None,
            origin_url: None,
            created_at_ms: 1000,
            exited_at_ms: Some(2000),
        };
        let proc_new = ProcessRecord {
            process_instance_id: "42:1500".to_string(),
            pid: 42,
            parent_instance_id: Some("4:1".to_string()),
            ppid: 4,
            exe_path: r"C:\Temp\new.exe".to_string(),
            command_line: None,
            sha256: None,
            signer_subject: None,
            is_trusted_os: false,
            user_sid: None,
            origin_url: None,
            created_at_ms: 1500,
            exited_at_ms: None,
        };
        store
            .upsert_process_record(&proc_old)
            .expect("upsert proc_old");
        store
            .upsert_process_record(&proc_new)
            .expect("upsert proc_new");

        let mut writer = store.lock_writer().expect("lock writer");
        let tx = writer.transaction().expect("begin tx");

        // Index-first priority: even when a stale hint ("42:1000") is valid at ts=1700/2000,
        // PID_TIME_WINDOW_LOOKUP_SQL selects the newest overlapping incarnation ("42:1500").
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 1700, Some("42:1000"))
                .expect("index-first selects newest overlapping mid"),
            "42:1500"
        );
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 2000, Some("42:1000"))
                .expect("index-first selects newest overlapping end"),
            "42:1500"
        );
        // Before proc_new starts at 1500, index selects proc_old ("42:1000") regardless of hint.
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 1000, Some("42:1000")).expect("index start"),
            "42:1000"
        );
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 1200, Some("42:1500"))
                .expect("index ignores future hint"),
            "42:1000"
        );

        // Post-exit of proc_old selects proc_new; pre-start falls back to "{pid}:0".
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 2500, Some("42:1000"))
                .expect("stale hint selects newer"),
            "42:1500"
        );
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 500, Some("42:1000"))
                .expect("early out-of-window hint"),
            "42:0"
        );

        // Unpersisted or PID-mismatched hint resolves persisted row via index first.
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 1700, Some("42:9999"))
                .expect("unpersisted hint resolves persisted row"),
            "42:1500"
        );
        assert_eq!(
            resolve_process_instance_id(&tx, 42, 1700, Some("999:1000"))
                .expect("mismatched pid hint resolves persisted row"),
            "42:1500"
        );
        // Hint fallback applies only when index query finds no row and hint PID/window matches.
        assert_eq!(
            resolve_process_instance_id(&tx, 88, 1700, Some("88:9999"))
                .expect("unpersisted hint fallback"),
            "88:9999"
        );
        assert_eq!(
            resolve_process_instance_id(&tx, 88, 1700, Some("999:1000"))
                .expect("mismatched pid hint fallback"),
            "88:0"
        );
    }

    #[test]
    fn unit_purge_in_batches_stops_between_batches_on_shutdown() {
        let store = LedrStore::open_in_memory().expect("open in-memory store");
        for i in 0..1_200u32 {
            let pid = 30_000 + i;
            store
                .upsert_process_record(&ProcessRecord {
                    process_instance_id: format!("{pid}:{}", 1000 + i),
                    pid,
                    parent_instance_id: None,
                    ppid: 4,
                    exe_path: r"C:\Temp\batch_test.exe".to_string(),
                    command_line: None,
                    sha256: None,
                    signer_subject: None,
                    is_trusted_os: false,
                    user_sid: None,
                    origin_url: None,
                    created_at_ms: 1000,
                    exited_at_ms: Some(2000),
                })
                .expect("seed expired process");
        }

        let mut batches_run = 0usize;
        let deleted = store
            .purge_in_batches(|tx| {
                batches_run += 1;
                let count = tx.execute(
                    "DELETE FROM processes
                     WHERE process_instance_id IN (
                         SELECT process_instance_id FROM processes
                         WHERE exited_at_ms < 5000
                         LIMIT 500
                     )",
                    [],
                )?;
                if batches_run == 1 {
                    store.request_shutdown();
                }
                Ok(count)
            })
            .expect("purge_in_batches stops after batch 1");

        assert_eq!(batches_run, 1);
        assert_eq!(deleted, 500);
        assert!(store.is_shutdown_requested());
        assert!(store.inner.writer.try_lock().is_ok());

        let remaining: i64 = store
            .lock_reader()
            .expect("lock reader")
            .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
            .expect("count remaining rows");
        assert_eq!(remaining, 700);
    }
}
