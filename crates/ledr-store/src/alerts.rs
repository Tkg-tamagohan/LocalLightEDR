//! Alert lifecycle, canary event recording, and alert query methods for [`LedrStore`].

use std::path::Path;

use ledr_proto::{AlertRecord, AlertStatus, CanaryCategory, FileCanaryEventRecord};
use rusqlite::{params, params_from_iter, types::Value, Connection, Transaction};

use crate::queries::{clamp_limit, collect_rows, query_optional_row};
use crate::schema::{
    reader_open_flags, row_to_alert, row_to_canary, ALERT_COLS, CANARY_COLS,
};
use crate::{LedrStore, StoreError};

impl LedrStore {
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

    /// Updates an alert's `process_suspended` flag and `context_json` atomically; returns `true`
    /// if a row existed (`BUG_0002`).
    pub fn update_alert_suspension_state(
        &self,
        alert_id: &str,
        process_suspended: bool,
        context_json: &str,
    ) -> Result<bool, StoreError> {
        let writer = self.lock_writer()?;
        let updated = writer.execute(
            "UPDATE alerts SET process_suspended = ?1, context_json = ?2 WHERE alert_id = ?3",
            params![i64::from(process_suspended), context_json, alert_id],
        )?;
        Ok(updated > 0)
    }

    /// Lists all unresolved (`PENDING` / `EXPIRED_SUSPENDED`) alerts that still record a suspended
    /// parent (`process_suspended = 1`) or non-empty top-level `$.suspended_children` array in
    /// `context_json`, using keyset pagination so large alert histories never truncate older
    /// suspended rows (`BUG_0003`, `PRRT_kwDOVyjVyM657t-x`).
    pub fn list_unresolved_suspended_alerts(&self) -> Result<Vec<AlertRecord>, StoreError> {
        let reader = self.lock_reader()?;
        query_unresolved_suspended_alerts(&reader)
    }

    /// Opens an existing SQLite store strictly read-only (compatible with WAL mode while the
    /// daemon may still be running, without mutating DB state or schema) and returns all
    /// unresolved (`PENDING` / `EXPIRED_SUSPENDED`) alerts that still record a suspended parent
    /// (`process_suspended = 1`) or non-empty `$.suspended_children` array.
    pub fn list_unresolved_suspended_alerts_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Vec<AlertRecord>, StoreError> {
        let conn = Connection::open_with_flags(path.as_ref(), reader_open_flags())?;
        conn.execute_batch("PRAGMA query_only = ON;\nPRAGMA busy_timeout = 5000;")?;
        query_unresolved_suspended_alerts(&conn)
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

    /// Lists alerts for a single `process_instance_id`, ordered by newest `timestamp_ms`
    /// first. When `unresolved_only` is set, only `PENDING`/`EXPIRED_SUSPENDED` rows are
    /// returned (`BUG_0005` — sibling lookups must not depend on global list limits).
    pub fn list_alerts_for_process(
        &self,
        process_instance_id: &str,
        unresolved_only: bool,
        limit: usize,
    ) -> Result<Vec<AlertRecord>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let reader = self.lock_reader()?;
        let limit_i64 = clamp_limit(limit);
        if unresolved_only {
            let sql = format!(
                "SELECT {ALERT_COLS} FROM alerts
                 WHERE process_instance_id = ?1 AND status IN (?2, ?3)
                 ORDER BY timestamp_ms DESC
                 LIMIT ?4"
            );
            collect_rows(
                &reader,
                &sql,
                params![
                    process_instance_id,
                    AlertStatus::Pending.as_db_str(),
                    AlertStatus::ExpiredSuspended.as_db_str(),
                    limit_i64
                ],
                row_to_alert,
            )
        } else {
            let sql = format!(
                "SELECT {ALERT_COLS} FROM alerts
                 WHERE process_instance_id = ?1
                 ORDER BY timestamp_ms DESC
                 LIMIT ?2"
            );
            collect_rows(&reader, &sql, params![process_instance_id, limit_i64], row_to_alert)
        }
    }

    /// Fetches a single [`AlertRecord`] by `alert_id` via the read-only query connection.
    pub fn get_alert(&self, alert_id: &str) -> Result<Option<AlertRecord>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("SELECT {ALERT_COLS} FROM alerts WHERE alert_id = ?1");
        query_optional_row(&reader, &sql, params![alert_id], row_to_alert)
    }

    /// Lists unresolved alerts (`PENDING` or `EXPIRED_SUSPENDED`) ordered by newest `timestamp_ms`
    /// first, bounded by `limit`.
    pub fn list_unresolved_alerts(&self, limit: usize) -> Result<Vec<AlertRecord>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let reader = self.lock_reader()?;
        let limit_i64 = clamp_limit(limit);
        let sql = format!(
            "SELECT {ALERT_COLS} FROM alerts
             WHERE status IN (?1, ?2)
             ORDER BY timestamp_ms DESC
             LIMIT ?3"
        );
        collect_rows(
            &reader,
            &sql,
            params![
                AlertStatus::Pending.as_db_str(),
                AlertStatus::ExpiredSuspended.as_db_str(),
                limit_i64
            ],
            row_to_alert,
        )
    }

    /// Atomically transitions overdue `PENDING` alerts (`timestamp_ms <= cutoff_timestamp_ms`) to
    /// `EXPIRED_SUSPENDED` while leaving `resolved_at_ms` untouched, returning updated row count (`L-07`).
    pub fn expire_pending_alerts(&self, cutoff_timestamp_ms: i64) -> Result<usize, StoreError> {
        let writer = self.lock_writer()?;
        let updated = writer.execute(
            "UPDATE alerts
             SET status = ?1
             WHERE status = ?2
               AND timestamp_ms <= ?3",
            params![
                AlertStatus::ExpiredSuspended.as_db_str(),
                AlertStatus::Pending.as_db_str(),
                cutoff_timestamp_ms,
            ],
        )?;
        Ok(updated)
    }

    /// Immediately inserts a [`FileCanaryEventRecord`] into `file_canary_events` via the writer
    /// connection and returns the generated `last_insert_rowid()`.
    pub fn record_file_canary_event(
        &self,
        record: &FileCanaryEventRecord,
    ) -> Result<i64, StoreError> {
        let writer = self.lock_writer()?;
        writer.execute(
            "INSERT INTO file_canary_events (
                timestamp_ms, process_instance_id, target_path, category, access_mask, action_taken
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.timestamp_ms,
                record.process_instance_id,
                record.target_path,
                record.category.as_str(),
                i64::from(record.access_mask),
                record.action_taken,
            ],
        )?;
        Ok(writer.last_insert_rowid())
    }

    /// Lists `file_canary_events` via the read-only connection, optionally filtered by
    /// [`CanaryCategory`] and `process_instance_id`, ordered by `timestamp_ms DESC, id DESC`.
    pub fn list_file_canary_events(
        &self,
        category: Option<CanaryCategory>,
        process_instance_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<FileCanaryEventRecord>, StoreError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let reader = self.lock_reader()?;
        let limit_i64 = clamp_limit(limit);
        let mut conditions = Vec::new();
        let mut bind_params: Vec<Value> = Vec::new();

        if let Some(cat) = category {
            bind_params.push(Value::from(cat.as_str().to_owned()));
            conditions.push(format!("category = ?{}", bind_params.len()));
        }
        if let Some(proc_id) = process_instance_id {
            bind_params.push(Value::from(proc_id.to_owned()));
            conditions.push(format!("process_instance_id = ?{}", bind_params.len()));
        }

        bind_params.push(Value::from(limit_i64));
        let limit_idx = bind_params.len();
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", conditions.join(" AND "))
        };
        let sql = format!(
            "SELECT {CANARY_COLS} FROM file_canary_events {where_clause}ORDER BY timestamp_ms DESC, id DESC LIMIT ?{limit_idx}"
        );

        collect_rows(&reader, &sql, params_from_iter(bind_params), row_to_canary)
    }
}

pub(crate) fn insert_alert_row(tx: &Transaction<'_>, alert: &AlertRecord) -> Result<(), StoreError> {
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

fn query_unresolved_suspended_alerts(conn: &Connection) -> Result<Vec<AlertRecord>, StoreError> {
    const PAGE_SIZE: usize = 500;
    // Guard `json_type` and `json_array_length` behind nested `CASE WHEN json_valid(...)`
    // so malformed legacy `context_json` rows never trigger a SQLite JSON runtime error.
    const SUSPENDED_PREDICATE: &str = "(
             process_suspended = 1
             OR CASE
                  WHEN json_valid(context_json) THEN
                    CASE
                      WHEN json_type(context_json, '$.suspended_children') = 'array'
                      THEN json_array_length(context_json, '$.suspended_children') > 0
                      ELSE 0
                    END
                  ELSE 0
                END
           )";
    let pending = AlertStatus::Pending.as_db_str();
    let expired = AlertStatus::ExpiredSuspended.as_db_str();
    let first_sql = format!(
        "SELECT {ALERT_COLS} FROM alerts
         WHERE status IN (?1, ?2)
           AND {SUSPENDED_PREDICATE}
         ORDER BY timestamp_ms ASC, alert_id ASC
         LIMIT ?3"
    );
    let next_sql = format!(
        "SELECT {ALERT_COLS} FROM alerts
         WHERE status IN (?1, ?2)
           AND {SUSPENDED_PREDICATE}
           AND (timestamp_ms > ?3 OR (timestamp_ms = ?3 AND alert_id > ?4))
         ORDER BY timestamp_ms ASC, alert_id ASC
         LIMIT ?5"
    );
    let mut first_stmt = conn.prepare(&first_sql)?;
    let mut next_stmt = conn.prepare(&next_sql)?;

    let mut all = Vec::new();
    let mut cursor: Option<(i64, String)> = None;
    loop {
        let mut page = Vec::new();
        match &cursor {
            None => {
                let mut rows = first_stmt.query(params![pending, expired, PAGE_SIZE as i64])?;
                while let Some(row) = rows.next()? {
                    page.push(row_to_alert(row)?);
                }
            }
            Some((last_ts, last_id)) => {
                let mut rows = next_stmt.query(params![
                    pending,
                    expired,
                    *last_ts,
                    last_id.as_str(),
                    PAGE_SIZE as i64
                ])?;
                while let Some(row) = rows.next()? {
                    page.push(row_to_alert(row)?);
                }
            }
        }
        let fetched = page.len();
        if let Some(last) = page.last() {
            cursor = Some((last.timestamp_ms, last.alert_id.clone()));
        }
        all.extend(page);
        if fetched < PAGE_SIZE {
            break;
        }
    }
    Ok(all)
}
