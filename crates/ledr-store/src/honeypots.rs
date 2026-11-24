//! Tracked honeypot decoy file persistence for uninstall cleanup (`L-06`).

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::schema::reader_open_flags;
use crate::{LedrStore, StoreError};

/// Normalizes a honeypot file path for case-insensitive Windows deduplication in `honeypot_files`.
pub(crate) fn normalize_honeypot_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn query_tracked_honeypots(conn: &Connection) -> Result<Vec<PathBuf>, StoreError> {
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

    let mut stmt =
        conn.prepare("SELECT file_path FROM honeypot_files ORDER BY normalized_path ASC")?;
    let mut rows = stmt.query([])?;
    let mut paths = Vec::new();
    while let Some(row) = rows.next()? {
        let raw: String = row.get(0)?;
        if !raw.trim().is_empty() {
            paths.push(PathBuf::from(raw));
        }
    }
    Ok(paths)
}

impl LedrStore {
    /// Upserts tracked honeypot file paths with the given observation timestamp (`seen_at_ms`).
    pub fn record_honeypot_paths(
        &self,
        paths: &[PathBuf],
        seen_at_ms: i64,
    ) -> Result<usize, StoreError> {
        if paths.is_empty() {
            return Ok(0);
        }
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let mut stmt = tx.prepare(
            "INSERT INTO honeypot_files (normalized_path, file_path, created_at_ms, last_seen_at_ms)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(normalized_path) DO UPDATE SET
                 file_path = excluded.file_path,
                 last_seen_at_ms = excluded.last_seen_at_ms",
        )?;
        let mut affected = 0usize;
        for path in paths {
            let norm = normalize_honeypot_path_key(path);
            if norm.is_empty() {
                continue;
            }
            let display = path.to_string_lossy().into_owned();
            affected += stmt.execute(params![norm, display, seen_at_ms, seen_at_ms])?;
        }
        drop(stmt);
        tx.commit()?;
        Ok(affected)
    }

    /// Lists all tracked honeypot decoy file paths from the store.
    pub fn list_tracked_honeypot_paths(&self) -> Result<Vec<PathBuf>, StoreError> {
        let reader = self.lock_reader()?;
        query_tracked_honeypots(&reader)
    }

    /// Opens an existing SQLite store strictly read-only and returns all tracked honeypot file paths.
    ///
    /// Returns `Ok(Vec::new())` if the database uses an older schema lacking `honeypot_files`.
    pub fn list_tracked_honeypot_paths_read_only(
        path: impl AsRef<Path>,
    ) -> Result<Vec<PathBuf>, StoreError> {
        let conn = Connection::open_with_flags(path.as_ref(), reader_open_flags())?;
        conn.execute_batch("PRAGMA query_only = ON;\nPRAGMA busy_timeout = 5000;")?;
        query_tracked_honeypots(&conn)
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

        assert_eq!(store.record_honeypot_paths(&[], 1_000).unwrap(), 0);
        store
            .record_honeypot_paths(&[p1.clone(), p2.clone()], 1_000)
            .expect("initial record");
        // Same normalized path with different casing and forward slashes updates in place.
        store
            .record_honeypot_paths(std::slice::from_ref(&p1_alt), 2_000)
            .expect("idempotent upsert");

        let listed = store.list_tracked_honeypot_paths().expect("list");
        assert_eq!(listed.len(), 2);

        let ro_listed =
            LedrStore::list_tracked_honeypot_paths_read_only(&db_path).expect("ro list");
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
        let remaining = store.list_tracked_honeypot_paths().expect("remaining");
        assert_eq!(remaining, vec![p2]);
    }

    #[test]
    fn read_only_query_handles_legacy_schema_without_honeypot_table() {
        let db_path = temp_db_path("legacy");
        let _cleanup = TempDbCleanup(db_path.clone());
        {
            let conn = Connection::open(&db_path).expect("create legacy db");
            conn.execute_batch("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY);")
                .expect("create legacy table");
        }
        let paths = LedrStore::list_tracked_honeypot_paths_read_only(&db_path)
            .expect("read-only query on legacy schema");
        assert!(paths.is_empty());
    }
}
