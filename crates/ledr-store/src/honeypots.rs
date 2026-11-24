//! Tracked honeypot decoy file persistence for uninstall cleanup (`L-06`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::schema::reader_open_flags;
use crate::{LedrStore, StoreError};

/// Persisted honeypot decoy record with optional Windows volume serial and file index identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackedHoneypotRecord {
    pub file_path: PathBuf,
    pub volume_serial: Option<u32>,
    pub file_index: Option<u64>,
}

/// Normalizes a honeypot file path for case-insensitive Windows deduplication in `honeypot_files`.
pub(crate) fn normalize_honeypot_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn honeypot_table_columns(conn: &Connection) -> Result<HashSet<String>, StoreError> {
    let mut stmt = conn.prepare("PRAGMA table_info(honeypot_files)")?;
    let mut rows = stmt.query([])?;
    let mut cols = HashSet::new();
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        cols.insert(name);
    }
    Ok(cols)
}

pub(crate) fn ensure_honeypot_file_id_columns(conn: &Connection) -> Result<(), StoreError> {
    let cols = honeypot_table_columns(conn)?;
    if cols.is_empty() {
        return Ok(());
    }
    if !cols.contains("volume_serial") {
        conn.execute_batch("ALTER TABLE honeypot_files ADD COLUMN volume_serial INTEGER;")?;
    }
    if !cols.contains("file_index") {
        conn.execute_batch("ALTER TABLE honeypot_files ADD COLUMN file_index INTEGER;")?;
    }
    Ok(())
}

fn query_tracked_honeypot_records(
    conn: &Connection,
) -> Result<Vec<TrackedHoneypotRecord>, StoreError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'honeypot_files'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if exists.is_none() {
        return Ok(Vec::new());
    }

    let cols = honeypot_table_columns(conn)?;
    let has_identity_cols = cols.contains("volume_serial") && cols.contains("file_index");
    let mut records = Vec::new();
    if has_identity_cols {
        let mut stmt = conn.prepare(
            "SELECT file_path, volume_serial, file_index
             FROM honeypot_files
             ORDER BY normalized_path ASC",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            if raw.trim().is_empty() {
                continue;
            }
            let vol_i64: Option<i64> = row.get(1)?;
            let idx_i64: Option<i64> = row.get(2)?;
            records.push(TrackedHoneypotRecord {
                file_path: PathBuf::from(raw),
                volume_serial: vol_i64.and_then(|v| u32::try_from(v).ok()),
                file_index: idx_i64.map(|v| v as u64),
            });
        }
    } else {
        let mut stmt =
            conn.prepare("SELECT file_path FROM honeypot_files ORDER BY normalized_path ASC")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let raw: String = row.get(0)?;
            if raw.trim().is_empty() {
                continue;
            }
            records.push(TrackedHoneypotRecord {
                file_path: PathBuf::from(raw),
                volume_serial: None,
                file_index: None,
            });
        }
    }
    Ok(records)
}

impl LedrStore {
    /// Upserts tracked honeypot records (including Windows volume/file index identity) with the
    /// given observation timestamp (`seen_at_ms`).
    pub fn record_honeypot_records(
        &self,
        records: &[TrackedHoneypotRecord],
        seen_at_ms: i64,
    ) -> Result<usize, StoreError> {
        if records.is_empty() {
            return Ok(0);
        }
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO honeypot_files (
                 normalized_path, file_path, volume_serial, file_index, created_at_ms, last_seen_at_ms
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(normalized_path) DO UPDATE SET
                 file_path = excluded.file_path,
                 volume_serial = COALESCE(excluded.volume_serial, honeypot_files.volume_serial),
                 file_index = COALESCE(excluded.file_index, honeypot_files.file_index),
                 last_seen_at_ms = excluded.last_seen_at_ms",
        )?;
        let mut affected = 0usize;
        for record in records {
            let norm = normalize_honeypot_path_key(&record.file_path);
            if norm.is_empty() {
                continue;
            }
            let display = record.file_path.to_string_lossy().into_owned();
            let vol_i64 = record.volume_serial.map(i64::from);
            let idx_i64 = record.file_index.map(|v| v as i64);
            affected += stmt.execute(params![
                norm,
                display,
                vol_i64,
                idx_i64,
                seen_at_ms,
                seen_at_ms
            ])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(affected)
    }

    /// Upserts tracked honeypot file paths with the given observation timestamp (`seen_at_ms`).
    pub fn record_honeypot_paths(
        &self,
        paths: &[PathBuf],
        seen_at_ms: i64,
    ) -> Result<usize, StoreError> {
        let records: Vec<TrackedHoneypotRecord> = paths
            .iter()
            .map(|p| TrackedHoneypotRecord {
                file_path: p.clone(),
                volume_serial: None,
                file_index: None,
            })
            .collect();
        self.record_honeypot_records(&records, seen_at_ms)
    }

    /// Lists all tracked honeypot decoy records (including optional file identity) from the store.
    pub fn list_tracked_honeypot_records(&self) -> Result<Vec<TrackedHoneypotRecord>, StoreError> {
        let reader = self.lock_reader()?;
        query_tracked_honeypot_records(&reader)
    }

    /// Lists all tracked honeypot decoy file paths from the store.
    pub fn list_tracked_honeypot_paths(&self) -> Result<Vec<PathBuf>, StoreError> {
        Ok(self
            .list_tracked_honeypot_records()?
            .into_iter()
            .map(|r| r.file_path)
            .collect())
    }

    /// Opens an existing SQLite store strictly read-only and returns all tracked honeypot records.
    ///
    /// Returns `Ok(Vec::new())` if the database uses an older schema lacking `honeypot_files`,
    /// and returns `volume_serial = None, file_index = None` when reading legacy 4-column tables.
    pub fn list_tracked_honeypot_records_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Vec<TrackedHoneypotRecord>, StoreError> {
        let conn = Connection::open_with_flags(path.as_ref(), reader_open_flags())?;
        conn.execute_batch("PRAGMA query_only = ON;\nPRAGMA busy_timeout = 5000;")?;
        query_tracked_honeypot_records(&conn)
    }

    /// Opens an existing SQLite store strictly read-only and returns all tracked honeypot file paths.
    ///
    /// Returns `Ok(Vec::new())` if the database uses an older schema lacking `honeypot_files`.
    pub fn list_tracked_honeypot_paths_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Vec<PathBuf>, StoreError> {
        Ok(Self::list_tracked_honeypot_records_read_only(path)?
            .into_iter()
            .map(|r| r.file_path)
            .collect())
    }

    /// Deletes tracked honeypot records matching `paths` from `honeypot_files`.
    pub fn remove_tracked_honeypot_paths(&self, paths: &[PathBuf]) -> Result<usize, StoreError> {
        if paths.is_empty() {
            return Ok(0);
        }
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let mut stmt = tx.prepare("DELETE FROM honeypot_files WHERE normalized_path = ?1")?;
        let mut deleted = 0usize;
        for path in paths {
            let norm = normalize_honeypot_path_key(path);
            if norm.is_empty() {
                continue;
            }
            deleted += stmt.execute(params![norm])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_path(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "ledr-store-honeypot-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp db dir");
        dir.join("localedr.db")
    }

    struct TempDbCleanup(PathBuf);
    impl Drop for TempDbCleanup {
        fn drop(&mut self) {
            if let Some(parent) = self.0.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }

    #[test]
    fn honeypot_tracking_upsert_dedup_remove_and_ttl_preservation() {
        let db_path = temp_db_path("crud");
        let _cleanup = TempDbCleanup(db_path.clone());
        let store = LedrStore::open(&db_path).expect("open store");

        let p1 = PathBuf::from(r"C:\Users\Alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx");
        let p1_alt = PathBuf::from("c:/users/alice/documents/!00_LocalEDR_Canary_DoNotEdit.docx");
        let p2 = PathBuf::from(r"C:\Users\Alice\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx");

        assert_eq!(store.record_honeypot_records(&[], 1_000).unwrap(), 0);
        let rec1 = TrackedHoneypotRecord {
            file_path: p1.clone(),
            volume_serial: Some(0xABCD_1234),
            file_index: Some(0x8000_0000_0000_0042),
        };
        let rec2 = TrackedHoneypotRecord {
            file_path: p2.clone(),
            volume_serial: Some(0x1122_3344),
            file_index: Some(99),
        };
        store
            .record_honeypot_records(&[rec1, rec2.clone()], 1_000)
            .expect("initial record");
        // Same normalized path with different casing/slashes preserves existing identity when None.
        store
            .record_honeypot_paths(std::slice::from_ref(&p1_alt), 2_000)
            .expect("idempotent upsert");

        let listed = store.list_tracked_honeypot_records().expect("list");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[1].volume_serial, Some(0xABCD_1234));
        assert_eq!(listed[1].file_index, Some(0x8000_0000_0000_0042));

        let ro_listed =
            LedrStore::list_tracked_honeypot_records_read_only(&db_path).expect("ro list");
        assert_eq!(ro_listed, listed);

        // TTL purge must not drop tracked honeypot rows (retained until uninstall).
        let now_after_retention = 1_000 + 365 * 86_400_000_i64;
        store
            .purge_expired(now_after_retention, 7)
            .expect("purge expired");
        assert_eq!(
            store.list_tracked_honeypot_paths().expect("after purge").len(),
            2
        );

        let removed = store
            .remove_tracked_honeypot_paths(&[p1])
            .expect("remove tracked");
        assert_eq!(removed, 1);
        let remaining = store.list_tracked_honeypot_records().expect("remaining");
        assert_eq!(remaining, vec![rec2]);
    }

    #[test]
    fn read_only_query_handles_legacy_schema_and_auto_migrates_four_col_table() {
        let db_path = temp_db_path("legacy");
        let _cleanup = TempDbCleanup(db_path.clone());
        {
            let conn = Connection::open(&db_path).expect("create legacy db");
            conn.execute_batch("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY);")
                .expect("create legacy table");
        }
        let paths = LedrStore::list_tracked_honeypot_paths_read_only(&db_path)
            .expect("read-only query on legacy schema without honeypot_files");
        assert!(paths.is_empty());

        // Legacy 4-column honeypot_files table without volume_serial / file_index
        let four_col_db = temp_db_path("four-col");
        let _cleanup_four = TempDbCleanup(four_col_db.clone());
        {
            let conn = Connection::open(&four_col_db).expect("create 4-col db");
            conn.execute_batch(
                "CREATE TABLE honeypot_files (
                    normalized_path TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    last_seen_at_ms INTEGER NOT NULL
                ) WITHOUT ROWID;
                INSERT INTO honeypot_files VALUES (
                    'c:\\users\\bob\\documents\\!00_localedr_canary_donotedit.docx',
                    'C:\\Users\\Bob\\Documents\\!00_LocalEDR_Canary_DoNotEdit.docx',
                    100,
                    200
                );",
            )
            .expect("seed 4-col table");
        }
        let legacy_records = LedrStore::list_tracked_honeypot_records_read_only(&four_col_db)
            .expect("read legacy 4-col records");
        assert_eq!(
            legacy_records,
            vec![TrackedHoneypotRecord {
                file_path: PathBuf::from(
                    r"C:\Users\Bob\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"
                ),
                volume_serial: None,
                file_index: None,
            }]
        );

        // Opening with LedrStore::open migrates the 4-column table cleanly.
        let store = LedrStore::open(&four_col_db).expect("migrate 4-col db");
        store
            .record_honeypot_records(
                &[TrackedHoneypotRecord {
                    file_path: PathBuf::from(
                        r"C:\Users\Bob\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
                    ),
                    volume_serial: Some(42),
                    file_index: Some(777),
                }],
                300,
            )
            .expect("update migrated row with file identity");
        let migrated = store.list_tracked_honeypot_records().expect("read migrated");
        assert_eq!(migrated[0].volume_serial, Some(42));
        assert_eq!(migrated[0].file_index, Some(777));
    }
}
