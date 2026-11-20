use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, CanaryCategory, DnsQueryRecord,
    DownloadOriginRecord, FileCanaryEventRecord, NetworkEventRecord, ProcessRecord, RuleScope,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row};

use crate::StoreError;

pub(crate) const PRAGMAS_SQL: &str = "
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -2048;
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 0;
PRAGMA wal_autocheckpoint = 1000;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
";

pub(crate) const SCHEMA_DDL: &str = "
CREATE TABLE IF NOT EXISTS processes (
    process_instance_id TEXT PRIMARY KEY,
    pid                 INTEGER NOT NULL,
    parent_instance_id  TEXT,
    ppid                INTEGER NOT NULL,
    exe_path            TEXT NOT NULL,
    command_line        TEXT,
    sha256              TEXT,
    signer_subject      TEXT,
    is_trusted_os       INTEGER NOT NULL DEFAULT 0,
    user_sid            TEXT,
    origin_url          TEXT,
    created_at_ms       INTEGER NOT NULL,
    exited_at_ms        INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_processes_created     ON processes(created_at_ms);
CREATE INDEX IF NOT EXISTS idx_processes_parent      ON processes(parent_instance_id);
CREATE INDEX IF NOT EXISTS idx_processes_pid_created ON processes(pid, created_at_ms DESC);
CREATE INDEX IF NOT EXISTS idx_processes_sha256      ON processes(sha256);

CREATE TABLE IF NOT EXISTS dns_queries (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms        INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    query_name          TEXT NOT NULL,
    query_type          INTEGER NOT NULL,
    resolved_ips        TEXT,
    is_nrd              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dns_ts_proc     ON dns_queries(timestamp_ms, process_instance_id);
CREATE INDEX IF NOT EXISTS idx_dns_name        ON dns_queries(query_name);
CREATE INDEX IF NOT EXISTS idx_dns_name_nocase ON dns_queries(query_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS network_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms        INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    protocol            INTEGER NOT NULL,
    dst_ip              TEXT NOT NULL,
    dst_port            INTEGER NOT NULL,
    domain_hint         TEXT,
    action              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_net_ts_proc ON network_events(timestamp_ms, process_instance_id);

CREATE TABLE IF NOT EXISTS file_canary_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_ms        INTEGER NOT NULL,
    process_instance_id TEXT NOT NULL,
    target_path         TEXT NOT NULL,
    category            TEXT NOT NULL,
    access_mask         INTEGER NOT NULL,
    action_taken        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_canary_ts ON file_canary_events(timestamp_ms);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id            TEXT PRIMARY KEY,
    timestamp_ms        INTEGER NOT NULL,
    severity            TEXT NOT NULL,
    source_layer        TEXT NOT NULL,
    rule_id             TEXT NOT NULL,
    title               TEXT NOT NULL,
    process_instance_id TEXT,
    process_suspended   INTEGER NOT NULL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'PENDING',
    context_json        TEXT NOT NULL,
    resolved_at_ms      INTEGER
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_alerts_status_ts   ON alerts(status, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_proc_status ON alerts(process_instance_id, status);

CREATE TABLE IF NOT EXISTS allowlist_rules (
    rule_id             TEXT PRIMARY KEY,
    scope               TEXT NOT NULL,
    exe_path_pattern    TEXT NOT NULL,
    sha256              TEXT,
    signer_subject      TEXT,
    root_thumbprint     TEXT,
    allowed_target      TEXT,
    created_at_ms       INTEGER NOT NULL,
    created_by          TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_rules_scope_created ON allowlist_rules(scope, created_at_ms DESC, rule_id ASC);

CREATE TABLE IF NOT EXISTS default_rule_seeds (
    rule_id             TEXT PRIMARY KEY,
    seeded_at_ms        INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS download_origins (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path           TEXT NOT NULL,
    sha256              TEXT,
    tab_url             TEXT NOT NULL,
    frame_url           TEXT,
    referrer_url        TEXT,
    downloaded_at_ms    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dl_path   ON download_origins(file_path);
CREATE INDEX IF NOT EXISTS idx_dl_sha256 ON download_origins(sha256);
";

pub(crate) fn writer_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

pub(crate) fn reader_open_flags() -> OpenFlags {
    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
}

pub(crate) fn apply_pragmas(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(PRAGMAS_SQL)?;
    Ok(())
}

pub(crate) fn query_pragma_summary(conn: &Connection) -> Result<(String, i64, i64), StoreError> {
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .optional()?
        .unwrap_or_else(|| "memory".to_string());
    let cache_size: i64 = conn
        .query_row("PRAGMA cache_size;", [], |row| row.get(0))
        .optional()?
        .unwrap_or(0);
    let mmap_size: i64 = conn
        .query_row("PRAGMA mmap_size;", [], |row| row.get(0))
        .optional()?
        .unwrap_or(0);
    Ok((journal_mode, cache_size, mmap_size))
}

pub(crate) const PROCESS_COLS: &str = "process_instance_id, pid, parent_instance_id, ppid, exe_path, command_line, sha256, signer_subject, is_trusted_os, user_sid, origin_url, created_at_ms, exited_at_ms";
pub(crate) const DNS_COLS: &str =
    "id, timestamp_ms, process_instance_id, query_name, query_type, resolved_ips, is_nrd";
pub(crate) const NETWORK_COLS: &str =
    "id, timestamp_ms, process_instance_id, protocol, dst_ip, dst_port, domain_hint, action";
pub(crate) const CANARY_COLS: &str =
    "id, timestamp_ms, process_instance_id, target_path, category, access_mask, action_taken";
pub(crate) const ALERT_COLS: &str = "alert_id, timestamp_ms, severity, source_layer, rule_id, title, process_instance_id, process_suspended, status, context_json, resolved_at_ms";
pub(crate) const RULE_COLS: &str = "rule_id, scope, exe_path_pattern, sha256, signer_subject, root_thumbprint, allowed_target, created_at_ms, created_by";
pub(crate) const DOWNLOAD_COLS: &str =
    "id, file_path, sha256, tab_url, frame_url, referrer_url, downloaded_at_ms";

fn to_u32(val: i64, field: &'static str) -> Result<u32, StoreError> {
    u32::try_from(val).map_err(|_| StoreError::InvalidValue {
        field,
        value: val.to_string(),
    })
}

fn to_u16(val: i64, field: &'static str) -> Result<u16, StoreError> {
    u16::try_from(val).map_err(|_| StoreError::InvalidValue {
        field,
        value: val.to_string(),
    })
}

fn to_u8(val: i64, field: &'static str) -> Result<u8, StoreError> {
    u8::try_from(val).map_err(|_| StoreError::InvalidValue {
        field,
        value: val.to_string(),
    })
}

pub(crate) fn row_to_process(row: &Row<'_>) -> Result<ProcessRecord, StoreError> {
    let pid_i64: i64 = row.get(1)?;
    let ppid_i64: i64 = row.get(3)?;
    let is_trusted_i64: i64 = row.get(8)?;
    Ok(ProcessRecord {
        process_instance_id: row.get(0)?,
        pid: to_u32(pid_i64, "processes.pid")?,
        parent_instance_id: row.get(2)?,
        ppid: to_u32(ppid_i64, "processes.ppid")?,
        exe_path: row.get(4)?,
        command_line: row.get(5)?,
        sha256: row.get(6)?,
        signer_subject: row.get(7)?,
        is_trusted_os: is_trusted_i64 != 0,
        user_sid: row.get(9)?,
        origin_url: row.get(10)?,
        created_at_ms: row.get(11)?,
        exited_at_ms: row.get(12)?,
    })
}

pub(crate) fn row_to_dns(row: &Row<'_>) -> Result<DnsQueryRecord, StoreError> {
    let query_type_i64: i64 = row.get(4)?;
    let resolved_raw: Option<String> = row.get(5)?;
    let is_nrd_i64: i64 = row.get(6)?;
    let resolved_ips = match resolved_raw {
        None => Vec::new(),
        Some(s) if s.trim().is_empty() => Vec::new(),
        Some(s) => match serde_json::from_str::<Vec<String>>(&s) {
            Ok(ips) => ips,
            Err(_) => s
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect(),
        },
    };
    Ok(DnsQueryRecord {
        id: Some(row.get(0)?),
        timestamp_ms: row.get(1)?,
        process_instance_id: row.get(2)?,
        query_name: row.get(3)?,
        query_type: to_u16(query_type_i64, "dns_queries.query_type")?,
        resolved_ips,
        is_nrd: is_nrd_i64 != 0,
    })
}

pub(crate) fn row_to_network(row: &Row<'_>) -> Result<NetworkEventRecord, StoreError> {
    let protocol_i64: i64 = row.get(3)?;
    let dst_port_i64: i64 = row.get(5)?;
    Ok(NetworkEventRecord {
        id: Some(row.get(0)?),
        timestamp_ms: row.get(1)?,
        process_instance_id: row.get(2)?,
        protocol: to_u8(protocol_i64, "network_events.protocol")?,
        dst_ip: row.get(4)?,
        dst_port: to_u16(dst_port_i64, "network_events.dst_port")?,
        domain_hint: row.get(6)?,
        action: row.get(7)?,
    })
}

pub(crate) fn row_to_canary(row: &Row<'_>) -> Result<FileCanaryEventRecord, StoreError> {
    let cat_str: String = row.get(4)?;
    let category =
        CanaryCategory::parse_category(&cat_str).ok_or_else(|| StoreError::InvalidValue {
            field: "file_canary_events.category",
            value: cat_str,
        })?;
    let access_mask_i64: i64 = row.get(5)?;
    Ok(FileCanaryEventRecord {
        id: Some(row.get(0)?),
        timestamp_ms: row.get(1)?,
        process_instance_id: row.get(2)?,
        target_path: row.get(3)?,
        category,
        access_mask: to_u32(access_mask_i64, "file_canary_events.access_mask")?,
        action_taken: row.get(6)?,
    })
}

pub(crate) fn row_to_alert(row: &Row<'_>) -> Result<AlertRecord, StoreError> {
    let sev_str: String = row.get(2)?;
    let severity =
        AlertSeverity::from_db_str(&sev_str).ok_or_else(|| StoreError::InvalidValue {
            field: "alerts.severity",
            value: sev_str,
        })?;
    let suspended_i64: i64 = row.get(7)?;
    let status_str: String = row.get(8)?;
    let status = AlertStatus::from_db_str(&status_str).ok_or_else(|| StoreError::InvalidValue {
        field: "alerts.status",
        value: status_str,
    })?;
    Ok(AlertRecord {
        alert_id: row.get(0)?,
        timestamp_ms: row.get(1)?,
        severity,
        source_layer: row.get(3)?,
        rule_id: row.get(4)?,
        title: row.get(5)?,
        process_instance_id: row.get(6)?,
        process_suspended: suspended_i64 != 0,
        status,
        context_json: row.get(9)?,
        resolved_at_ms: row.get(10)?,
    })
}

pub(crate) fn row_to_rule(row: &Row<'_>) -> Result<AllowlistRuleRecord, StoreError> {
    let scope_str: String = row.get(1)?;
    let scope = RuleScope::from_db_str(&scope_str).ok_or_else(|| StoreError::InvalidValue {
        field: "allowlist_rules.scope",
        value: scope_str,
    })?;
    Ok(AllowlistRuleRecord {
        rule_id: row.get(0)?,
        scope,
        exe_path_pattern: row.get(2)?,
        sha256: row.get(3)?,
        signer_subject: row.get(4)?,
        root_thumbprint: row.get(5)?,
        allowed_target: row.get(6)?,
        created_at_ms: row.get(7)?,
        created_by: row.get(8)?,
    })
}

pub(crate) fn row_to_download(row: &Row<'_>) -> Result<DownloadOriginRecord, StoreError> {
    Ok(DownloadOriginRecord {
        id: Some(row.get(0)?),
        file_path: row.get(1)?,
        sha256: row.get(2)?,
        tab_url: row.get(3)?,
        frame_url: row.get(4)?,
        referrer_url: row.get(5)?,
        downloaded_at_ms: row.get(6)?,
    })
}
