//! Allowlist and firewall policy rule CRUD methods for [`LedrStore`].

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use ledr_proto::{AllowlistRuleRecord, RuleScope};
use rusqlite::params;

use crate::queries::query_optional_row;
use crate::schema::{row_to_rule, RULE_COLS};
use crate::{LedrStore, StoreError};

impl LedrStore {
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

    /// Lists persisted firewall policy rules (`NetworkBlock` followed by `NetworkAllow`) for
    /// startup WFP redeployment and deny-overrides-allow evaluation (`L-03`, `L-04`).
    pub fn list_network_rules(&self) -> Result<Vec<AllowlistRuleRecord>, StoreError> {
        self.list_rules_by_scopes(&[RuleScope::NetworkBlock, RuleScope::NetworkAllow])
    }

    /// Lists persisted rules matching any scope in `scopes`, preserving the caller's scope
    /// priority order and ordering within each scope by `created_at_ms DESC, rule_id ASC`
    /// via `idx_rules_scope_created`.
    pub fn list_rules_by_scopes(
        &self,
        scopes: &[RuleScope],
    ) -> Result<Vec<AllowlistRuleRecord>, StoreError> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let reader = self.lock_reader()?;
        let sql = format!(
            "SELECT {RULE_COLS} FROM allowlist_rules WHERE scope = ?1 ORDER BY created_at_ms DESC, rule_id ASC"
        );
        let mut stmt = reader.prepare(&sql)?;
        let mut seen = HashSet::with_capacity(scopes.len());
        let mut rules = Vec::new();
        for &scope in scopes {
            if !seen.insert(scope) {
                continue;
            }
            let mut rows = stmt.query(params![scope.as_db_str()])?;
            while let Some(row) = rows.next()? {
                rules.push(row_to_rule(row)?);
            }
        }
        Ok(rules)
    }

    /// Fetches a single [`AllowlistRuleRecord`] by `rule_id` via the read-only query connection.
    pub fn get_rule(&self, rule_id: &str) -> Result<Option<AllowlistRuleRecord>, StoreError> {
        let reader = self.lock_reader()?;
        let sql = format!("SELECT {RULE_COLS} FROM allowlist_rules WHERE rule_id = ?1");
        query_optional_row(&reader, &sql, params![rule_id], row_to_rule)
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

    /// Seeds default allowlist rules at most once per database (`BUG_0004`).
    ///
    /// Any `rule_id` already recorded in `default_rule_seeds` is skipped even if the operator
    /// later deleted it from `allowlist_rules`. Existing rows in `allowlist_rules` with the same
    /// `rule_id` are preserved (`INSERT OR IGNORE`) without overwriting operator edits.
    /// Returns the number of rules newly inserted into `allowlist_rules`.
    pub fn seed_default_rules_once(
        &self,
        rules: &[AllowlistRuleRecord],
    ) -> Result<usize, StoreError> {
        if rules.is_empty() {
            return Ok(0);
        }
        let seeded_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        let mut writer = self.lock_writer()?;
        let tx = writer.transaction()?;
        let mut inserted = 0usize;
        {
            let mut seed_stmt = tx.prepare(
                "INSERT OR IGNORE INTO default_rule_seeds (rule_id, seeded_at_ms) VALUES (?1, ?2)",
            )?;
            let mut rule_stmt = tx.prepare(
                "INSERT OR IGNORE INTO allowlist_rules (
                    rule_id, scope, exe_path_pattern, sha256, signer_subject,
                    root_thumbprint, allowed_target, created_at_ms, created_by
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for rule in rules {
                let seed_added = seed_stmt.execute(params![rule.rule_id, seeded_at_ms])?;
                if seed_added > 0 {
                    inserted += rule_stmt.execute(params![
                        rule.rule_id,
                        rule.scope.as_db_str(),
                        rule.exe_path_pattern,
                        rule.sha256,
                        rule.signer_subject,
                        rule.root_thumbprint,
                        rule.allowed_target,
                        rule.created_at_ms,
                        rule.created_by,
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok(inserted)
    }
}
