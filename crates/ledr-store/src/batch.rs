//! Write batch buffering, transactional flush, and PID time-window attribution.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    AlertRecord, ProcessRecord, SensorEvent, STORE_BATCH_FLUSH_INTERVAL_MS, STORE_BATCH_MAX_EVENTS,
};
use rusqlite::{params, OptionalExtension, Transaction};

use crate::alerts::insert_alert_row;
use crate::{BufferedEvent, LedrStore, StoreError};

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
pub(crate) const PID_TIME_WINDOW_LOOKUP_SQL: &str = "
SELECT process_instance_id FROM processes
WHERE pid = ?1
  AND created_at_ms <= ?2
  AND (exited_at_ms IS NULL OR exited_at_ms >= ?2)
ORDER BY created_at_ms DESC,
         CAST(substr(process_instance_id, instr(process_instance_id, ':') + 1) AS INTEGER) DESC
LIMIT 1";

impl LedrStore {
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
        self.ingest_event_with_exit(event, parent_instance_id, None, is_nrd, action)
    }

    /// Same as [`Self::ingest_event`] but also carries an inferred `exited_at_ms` for a
    /// `ProcessStart` that describes an older incarnation already superseded in memory, so the
    /// stored row is not left `exited_at_ms IS NULL` (running) forever.
    ///
    /// The parameter is ignored for non-`ProcessStart` events.
    pub fn ingest_event_with_exit(
        &self,
        event: &SensorEvent,
        parent_instance_id: Option<&str>,
        exited_at_ms: Option<i64>,
        is_nrd: bool,
        action: &str,
    ) -> Result<bool, StoreError> {
        self.ingest_event_with_lifecycle(event, parent_instance_id, exited_at_ms, None, is_nrd, action)
    }

    /// Same as [`Self::ingest_event_with_exit`] and additionally closes a superseded active
    /// process row (such as a `pid:0` snapshot placeholder) inside the same SQLite transaction
    /// as the superseding `ProcessStart`, clamping `exited_at_ms` to at least `created_at_ms`.
    ///
    /// Both `exited_at_ms` and `superseded_process_exit` are ignored for non-`ProcessStart` events.
    pub fn ingest_event_with_lifecycle(
        &self,
        event: &SensorEvent,
        parent_instance_id: Option<&str>,
        exited_at_ms: Option<i64>,
        superseded_process_exit: Option<(&str, i64)>,
        is_nrd: bool,
        action: &str,
    ) -> Result<bool, StoreError> {
        if matches!(event, SensorEvent::ScriptEvaluated { .. }) {
            // Evaluated in-memory by Layer 2 SigmaEngine and stored in alerts.context_json on match.
            tracing::trace!("skipping direct telemetry table buffering for ScriptEvaluated");
            return Ok(false);
        }

        let is_canary = matches!(event, SensorEvent::CanaryFileAccess { .. });
        let is_process_start = matches!(event, SensorEvent::ProcessStart { .. });
        let buffered = BufferedEvent {
            event: event.clone(),
            parent_instance_id: parent_instance_id.map(str::to_owned),
            is_nrd,
            action: action.to_owned(),
            received_at_ms: current_unix_ms(),
            exited_at_ms: if is_process_start { exited_at_ms } else { None },
            superseded_process_exit: if is_process_start {
                superseded_process_exit.map(|(id, exit_ms)| (id.to_owned(), exit_ms))
            } else {
                None
            },
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
    ///
    /// Unlike partial `SensorEvent::ProcessStart` batch ingestion, explicit `ppid` and `exe_path`
    /// values on the full record (including `0` and `""`) overwrite existing columns while still
    /// preserving any already-recorded `exited_at_ms` and `Option`-typed fields when `None`.
    pub fn upsert_process_record(&self, process: &ProcessRecord) -> Result<(), StoreError> {
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        upsert_process_row(&tx, process, false)?;
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

fn upsert_process_row(
    tx: &Transaction<'_>,
    process: &ProcessRecord,
    preserve_existing_identity_fields: bool,
) -> Result<(), StoreError> {
    let sql = if preserve_existing_identity_fields {
        "INSERT INTO processes (
            process_instance_id, pid, parent_instance_id, ppid, exe_path, command_line,
            sha256, signer_subject, is_trusted_os, user_sid, origin_url, created_at_ms, exited_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(process_instance_id) DO UPDATE SET
            pid = excluded.pid,
            parent_instance_id = COALESCE(excluded.parent_instance_id, processes.parent_instance_id),
            ppid = CASE
                WHEN excluded.ppid != 0 THEN excluded.ppid
                ELSE processes.ppid
            END,
            exe_path = CASE
                WHEN excluded.exe_path != '' THEN excluded.exe_path
                ELSE processes.exe_path
            END,
            command_line = COALESCE(excluded.command_line, processes.command_line),
            sha256 = COALESCE(excluded.sha256, processes.sha256),
            signer_subject = COALESCE(excluded.signer_subject, processes.signer_subject),
            is_trusted_os = CASE
                WHEN excluded.is_trusted_os != 0 THEN 1
                ELSE processes.is_trusted_os
            END,
            user_sid = COALESCE(excluded.user_sid, processes.user_sid),
            origin_url = COALESCE(excluded.origin_url, processes.origin_url),
            exited_at_ms = COALESCE(processes.exited_at_ms, excluded.exited_at_ms)"
    } else {
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
            exited_at_ms = COALESCE(processes.exited_at_ms, excluded.exited_at_ms)"
    };
    tx.execute(
        sql,
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

pub(crate) fn resolve_process_instance_id(
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
                    exited_at_ms: item.exited_at_ms,
                };
                upsert_process_row(tx, &record, true)?;
                if let Some((superseded_id, superseded_exit_ms)) = &item.superseded_process_exit {
                    if superseded_id != &record.process_instance_id {
                        tx.execute(
                            "UPDATE processes
                             SET exited_at_ms = MAX(created_at_ms, ?1)
                             WHERE process_instance_id = ?2
                               AND exited_at_ms IS NULL",
                            params![superseded_exit_ms, superseded_id],
                        )?;
                    }
                }
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
