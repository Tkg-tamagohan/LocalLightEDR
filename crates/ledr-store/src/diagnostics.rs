//! PRAGMA verification and `EXPLAIN QUERY PLAN` diagnostics for [`LedrStore`].

use ledr_proto::RuleScope;
use rusqlite::{params, MAIN_DB};

use crate::batch::PID_TIME_WINDOW_LOOKUP_SQL;
use crate::queries::{find_download_by_path_sql, find_download_by_sha256_sql};
use crate::schema::{query_pragma_summary, RULE_COLS};
use crate::{LedrStore, StoreError};

impl LedrStore {
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
        if !reader.is_readonly(MAIN_DB)? {
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

    /// Returns SQLite `EXPLAIN QUERY PLAN` detail lines for scope-filtered `allowlist_rules`
    /// queries used during startup firewall redeployment and policy lookups.
    pub fn explain_rules_scope_plan(&self) -> Result<Vec<String>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!(
            "EXPLAIN QUERY PLAN
             SELECT {RULE_COLS} FROM allowlist_rules
             WHERE scope = ?1
             ORDER BY created_at_ms DESC, rule_id ASC"
        );
        let mut stmt = reader.prepare(&sql)?;
        let mut rows = stmt.query(params![RuleScope::NetworkBlock.as_db_str()])?;
        let mut details = Vec::new();
        while let Some(row) = rows.next()? {
            details.push(row.get::<_, String>(3)?);
        }
        Ok(details)
    }

    /// Returns SQLite `EXPLAIN QUERY PLAN` detail lines for the case-insensitive local DNS
    /// history lookup used by [`LedrStore::has_seen_dns_domain`] (`L-14`).
    pub fn explain_dns_name_nocase_plan(&self) -> Result<Vec<String>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = "EXPLAIN QUERY PLAN
             SELECT 1 FROM dns_queries
             WHERE query_name COLLATE NOCASE IN (?1, ?2)
             LIMIT 1";
        let mut stmt = reader.prepare(sql)?;
        let mut rows = stmt.query(params!["example.com", "example.com."])?;
        let mut details = Vec::new();
        while let Some(row) = rows.next()? {
            details.push(row.get::<_, String>(3)?);
        }
        Ok(details)
    }

    /// Returns SQLite `EXPLAIN QUERY PLAN` detail lines for [`LedrStore::find_download_origin_by_path`].
    pub fn explain_download_path_lookup_plan(&self) -> Result<Vec<String>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("EXPLAIN QUERY PLAN\n{}", find_download_by_path_sql());
        let mut stmt = reader.prepare(&sql)?;
        let mut rows = stmt.query(params![r"C:\Users\alice\Downloads\sample.exe"])?;
        let mut details = Vec::new();
        while let Some(row) = rows.next()? {
            details.push(row.get::<_, String>(3)?);
        }
        Ok(details)
    }

    /// Returns SQLite `EXPLAIN QUERY PLAN` detail lines for [`LedrStore::find_download_origin_by_sha256`].
    pub fn explain_download_sha256_lookup_plan(&self) -> Result<Vec<String>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("EXPLAIN QUERY PLAN\n{}", find_download_by_sha256_sql());
        let mut stmt = reader.prepare(&sql)?;
        let mut rows = stmt.query(params![
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ])?;
        let mut details = Vec::new();
        while let Some(row) = rows.next()? {
            details.push(row.get::<_, String>(3)?);
        }
        Ok(details)
    }
}
