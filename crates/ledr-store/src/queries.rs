//! Read-only query methods and shared query helpers for [`LedrStore`].

use std::collections::HashSet;

use ledr_proto::{DownloadOriginRecord, FlightRecorderSnapshot, ProcessRecord};
use rusqlite::{params, Connection, OptionalExtension};

use crate::schema::{
    row_to_canary, row_to_dns, row_to_download, row_to_network, row_to_process, CANARY_COLS,
    DNS_COLS, DOWNLOAD_COLS, NETWORK_COLS, PROCESS_COLS,
};
use crate::{LedrStore, StoreError};

impl LedrStore {
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

    /// Returns `true` if `query_name` (case-insensitive, with or without a trailing DNS root dot)
    /// already exists in local `dns_queries` history (`L-14` first-seen domain check).
    pub fn has_seen_dns_domain(&self, query_name: &str) -> Result<bool, StoreError> {
        let normalized = query_name.trim().trim_end_matches('.');
        if normalized.is_empty() {
            return Ok(false);
        }
        let with_dot = format!("{normalized}.");
        let reader = self.lock_reader()?;
        let found: Option<i64> = reader
            .query_row(
                "SELECT 1 FROM dns_queries WHERE query_name COLLATE NOCASE IN (?1, ?2) LIMIT 1",
                params![normalized, with_dot],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }
}

pub(crate) fn clamp_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

pub(crate) fn query_optional_row<T, P, M>(
    reader: &Connection,
    sql: &str,
    params: P,
    map_row: M,
) -> Result<Option<T>, StoreError>
where
    P: rusqlite::Params,
    M: FnOnce(&rusqlite::Row<'_>) -> Result<T, StoreError>,
{
    let mut stmt = reader.prepare(sql)?;
    stmt.query_row(params, |row| Ok(map_row(row)))
        .optional()?
        .transpose()
}

pub(crate) fn collect_rows<T, P, M>(
    reader: &Connection,
    sql: &str,
    params: P,
    mut map_row: M,
) -> Result<Vec<T>, StoreError>
where
    P: rusqlite::Params,
    M: FnMut(&rusqlite::Row<'_>) -> Result<T, StoreError>,
{
    let mut stmt = reader.prepare(sql)?;
    let mut rows = stmt.query(params)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(map_row(row)?);
    }
    Ok(records)
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
