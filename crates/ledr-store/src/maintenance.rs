//! Batched TTL purge and startup stale-process reconciliation for [`LedrStore`].

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ledr_proto::TTL_PURGE_BATCH_LIMIT;
use rusqlite::{params, Transaction};

use crate::{LedrStore, PurgeStats, StoreError};

const MS_PER_DAY: i64 = 86_400_000;

impl LedrStore {
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

    pub(crate) fn purge_in_batches<F>(&self, mut delete_batch: F) -> Result<usize, StoreError>
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
}
