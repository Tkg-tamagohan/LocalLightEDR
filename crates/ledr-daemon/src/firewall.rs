//! Dynamic WFP firewall rule manager with deny-overrides-allow reconciliation (`L-03`, `L-04`,
//! `AUTO-02`, `AUTO-04`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{
    is_never_suspend_process, ActiveDefenseController, AllowlistRuleRecord, RuleScope,
    ACTIVE_PROCESS_TABLE_CAPACITY,
};
use ledr_rules::{
    canonical_ip, evaluate_outbound_policy, matches_app_wide_network_allow,
    matches_app_wide_network_block, matches_network_allow_rule, matches_network_block_rule,
    matches_network_target, matches_path_pattern, parse_cidr_target, BinaryIdentity,
    OutboundDecision,
};

use crate::engine::BinaryInspector;

/// Upper bound on dynamically materialized domain-derived IP WFP filters to keep BFE handle
/// usage strictly bounded.
pub const MAX_DOMAIN_POLICY_FILTERS: usize = 512;

/// Origin tracking why a dynamic WFP filter is currently installed in BFE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WfpFilterOrigin {
    /// Installed directly to enforce a persisted concrete/IP `NetworkBlock` or `NetworkAllow` rule.
    PersistedPolicy,
    /// Installed for a concrete resolved IP matched by a persisted domain-scoped `NetworkBlock`
    /// or `NetworkAllow` rule (`domain_hint` retained so reconciliation keeps the filter while
    /// the backing rule stays active and removes it when deleted or overridden by deny).
    DomainPolicy { domain_hint: String },
    /// Installed proactively on `ProcessStart` for high-risk paths (`Downloads`/`Temp`) or
    /// script interpreters (`powershell`, `node`, `python`, etc.) (`L-03`).
    Preemptive,
    /// Installed dynamically during unknown-process first-connect containment (`NtSuspendProcess`
    /// + WFP block) while waiting for operator triage (`L-03`).
    TransientContainment,
}

/// Composite key identifying a concrete WFP filter target managed by the daemon (canonical IP).
pub type WfpTargetKey = (String, Option<IpAddr>);

/// Metadata for a live WFP rule handle registered via [`ActiveDefenseController`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledWfpFilter {
    pub handle: u64,
    pub exe_path: String,
    pub allow: bool,
    pub origin: WfpFilterOrigin,
}

/// Snapshot of a temporarily removed block filter used to compensate if alert resolution fails
/// during process resume or alert status persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedBlockSnapshot {
    pub key: WfpTargetKey,
    pub exe_path: String,
    pub origin: WfpFilterOrigin,
}

/// Individual WFP filter operation failure captured during reconciliation (`#4`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WfpFailedOp {
    pub exe_key: String,
    pub remote_ip: Option<IpAddr>,
    pub is_remove: bool,
    pub is_startup_preemptive: bool,
    pub source_rule_ids: Vec<String>,
    pub error: String,
}

/// Snapshot of a filter origin promoted/demoted during reconciliation (plus any alert containment
/// bindings cleared on promotion) so SQLite rollback can restore the exact pre-reconcile state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotedFilterSnapshot {
    pub key: WfpTargetKey,
    pub prev_origin: WfpFilterOrigin,
    pub bound_alert_ids: Vec<String>,
}

/// Snapshot of a [`WfpFilterOrigin::DomainPolicy`] filter removed during reconciliation so
/// SQLite rollback can re-install it in BFE (since `reconcile_persisted_rules` only rebuilds
/// static [`WfpFilterOrigin::PersistedPolicy`] filters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedDomainFilterSnapshot {
    pub exe_path: String,
    pub remote_ip: IpAddr,
    pub allow: bool,
    pub domain_hint: String,
}

/// Summary of a persisted-rule reconciliation pass against [`ActiveDefenseController`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WfpReconcileReport {
    pub applied: usize,
    pub removed: usize,
    pub promoted: usize,
    pub skipped_wildcard: usize,
    pub failed: usize,
    pub failed_ops: Vec<WfpFailedOp>,
    pub promoted_backups: Vec<PromotedFilterSnapshot>,
    pub removed_domain_filters: Vec<RemovedDomainFilterSnapshot>,
}

impl WfpReconcileReport {
    /// Returns `true` when any non-startup-preemptive WFP filter operation failed.
    ///
    /// Failures on unrelated startup-pinned interpreters (e.g., running non-elevated without
    /// BFE access on system paths) must not fail explicit user policy mutations.
    pub fn has_policy_failures(&self) -> bool {
        self.failed_ops.iter().any(|op| !op.is_startup_preemptive)
    }

    /// Formats a concise human-readable summary of all non-startup-preemptive WFP failures.
    pub fn policy_failure_summary(&self) -> String {
        Self::format_ops(self.failed_ops.iter().filter(|op| !op.is_startup_preemptive))
    }

    /// Returns a formatted error summary ONLY if this reconciliation encountered a non-startup
    /// WFP failure affecting at least one rule in `affected_rules` (ignoring failures on unrelated
    /// executables/targets while still surfacing repeated failures on any affected rule).
    pub fn failure_summary_for_rules(&self, affected_rules: &[&AllowlistRuleRecord]) -> Option<String> {
        let relevant: Vec<&WfpFailedOp> = self
            .failed_ops
            .iter()
            .filter(|op| {
                !op.is_startup_preemptive
                    && affected_rules.iter().any(|rule| Self::op_matches_rule(op, rule))
            })
            .collect();
        if relevant.is_empty() {
            None
        } else {
            Some(Self::format_ops(relevant.into_iter()))
        }
    }

    fn op_matches_rule(op: &WfpFailedOp, rule: &AllowlistRuleRecord) -> bool {
        if !op.is_remove && !op.source_rule_ids.is_empty() {
            return op.source_rule_ids.iter().any(|id| id == &rule.rule_id);
        }
        let pat = rule.exe_path_pattern.trim();
        if pat.is_empty() {
            return false;
        }
        let exe_matches = if !WfpRuleManager::is_wildcard_pattern(pat) {
            WfpRuleManager::exe_key(pat) == op.exe_key
        } else {
            matches_path_pattern(&op.exe_key, pat)
        };
        if !exe_matches {
            return false;
        }
        let target_opt = rule
            .allowed_target
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let Some(ip) = op.remote_ip else {
            return target_opt.is_none();
        };
        let Some(target) = target_opt else {
            return true;
        };
        if parse_literal_target_ip(target).is_some() || parse_cidr_target(target).is_ok() {
            return matches_network_target(target, ip, None);
        }
        // Domain / wildcard target rules only touch IP-specific WFP entries in reconciliation
        // when removing stale `DomainPolicy` filters; live additions report directly.
        op.is_remove
    }

    fn format_ops<'a>(ops: impl Iterator<Item = &'a WfpFailedOp>) -> String {
        let details: Vec<String> = ops
            .map(|op| {
                let verb = if op.is_remove { "remove" } else { "apply" };
                match op.remote_ip {
                    Some(ip) => format!("{verb} {} ({ip}): {}", op.exe_key, op.error),
                    None => format!("{verb} {}: {}", op.exe_key, op.error),
                }
            })
            .collect();
        details.join("; ")
    }
}

/// Tracks active dynamic WFP rule handles, alert containment bindings, wildcard/domain rule
/// presence, startup-pinned pre-restricted executables, and per-process `AllowOnce` grants.
#[derive(Debug, Default)]
pub struct WfpRuleManager {
    installed: HashMap<WfpTargetKey, InstalledWfpFilter>,
    bound_alerts: HashMap<String, WfpTargetKey>,
    once_allowed_processes: HashMap<String, String>,
    startup_preemptive_exes: HashMap<String, String>,
    has_wildcard_network_rules: bool,
    has_domain_network_rules: bool,
}

impl WfpRuleManager {
    /// Creates an empty [`WfpRuleManager`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures concrete executable paths that receive startup-pinned `Preemptive` WFP blocks
    /// before any `ProcessStart` event and remain protected across `ProcessStop` (`L-03`, `AUTO-02`).
    pub fn set_startup_preemptive_executables(&mut self, exes: &[String]) {
        self.startup_preemptive_exes.clear();
        for raw in exes {
            let trimmed = raw.trim();
            if trimmed.is_empty() || Self::is_wildcard_pattern(trimmed) {
                continue;
            }
            let clean = trimmed.trim_end_matches(['.', ' ']);
            if is_never_suspend_process(trimmed) || is_never_suspend_process(clean) {
                continue;
            }
            let key = Self::exe_key(trimmed);
            self.startup_preemptive_exes
                .entry(key)
                .or_insert_with(|| trimmed.to_string());
        }
    }

    /// Returns `true` when `exe_path` is a startup-pinned pre-restricted executable.
    pub fn is_startup_preemptive(&self, exe_path: &str) -> bool {
        self.startup_preemptive_exes
            .contains_key(&Self::exe_key(exe_path))
    }

    /// Normalizes a concrete executable path to its canonical lookup key.
    pub fn exe_key(exe_path: &str) -> String {
        let trimmed = exe_path.trim().replace('/', "\\");
        let stripped = if trimmed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        {
            format!(r"\\{}", &trimmed[8..])
        } else if trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
        {
            trimmed[4..].to_string()
        } else {
            trimmed
        };
        stripped.to_ascii_lowercase()
    }

    /// Builds a canonical [`WfpTargetKey`] (normalizing path casing/prefixes and unwrapping
    /// IPv4-mapped IPv6 addresses into IPv4).
    pub fn target_key(exe_path: &str, remote_ip: Option<IpAddr>) -> WfpTargetKey {
        (Self::exe_key(exe_path), remote_ip.map(canonical_ip))
    }

    /// Returns `true` if `exe_path_pattern` contains wildcard metacharacters (`*` or `?`).
    pub fn is_wildcard_pattern(pattern: &str) -> bool {
        pattern.contains('*') || pattern.contains('?')
    }

    /// Returns `true` when at least one persisted wildcard `NetworkBlock`/`NetworkAllow` rule
    /// was observed during the latest reconciliation pass.
    pub fn has_wildcard_network_rules(&self) -> bool {
        self.has_wildcard_network_rules
    }

    /// Returns `true` when at least one persisted `NetworkBlock`/`NetworkAllow` rule has a
    /// non-empty domain or wildcard `allowed_target` (excluding literal IPs and CIDRs) requiring
    /// `DnsQuery` high-priority lane promotion and WFP pre-materialization.
    pub fn has_domain_network_rules(&self) -> bool {
        self.has_domain_network_rules
    }

    /// Returns the tracking origin for an active WFP filter key if installed.
    pub fn filter_origin(&self, exe_path: &str, remote_ip: Option<IpAddr>) -> Option<&WfpFilterOrigin> {
        let key = Self::target_key(exe_path, remote_ip);
        self.installed.get(&key).map(|e| &e.origin)
    }

    /// Returns `true` when `alert_id` is currently bound to a non-persisted app-wide block.
    pub fn is_alert_bound(&self, alert_id: &str) -> bool {
        self.bound_alerts.contains_key(alert_id)
    }

    /// Returns `true` when `process_instance_id` received an `AllowOnce` network approval.
    pub fn is_once_allowed(&self, process_instance_id: &str) -> bool {
        self.once_allowed_processes
            .contains_key(process_instance_id)
    }

    /// Returns `true` when any active process of `exe_key` currently holds an `AllowOnce` grant.
    pub fn has_once_allowed_for_exe(&self, exe_key: &str) -> bool {
        self.once_allowed_processes.values().any(|k| k == exe_key)
    }

    /// Grants a one-time outbound network exemption for `process_instance_id` (bounded by
    /// `ACTIVE_PROCESS_TABLE_CAPACITY`).
    pub fn mark_once_allowed(&mut self, process_instance_id: &str, exe_path: &str) {
        if self.once_allowed_processes.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
            self.once_allowed_processes.clear();
        }
        self.once_allowed_processes
            .insert(process_instance_id.to_string(), Self::exe_key(exe_path));
    }

    /// Revokes a one-time outbound network exemption (used on resolution rollback).
    pub fn unmark_once_allowed(&mut self, process_instance_id: &str) {
        self.once_allowed_processes.remove(process_instance_id);
    }

    /// Cleans up per-process one-time grants when the process exits. Returns `true` if
    /// `process_instance_id` held an `AllowOnce` exemption.
    pub fn on_process_stop(&mut self, process_instance_id: &str) -> bool {
        self.once_allowed_processes
            .remove(process_instance_id)
            .is_some()
    }

    /// Removes a `Preemptive` app-wide WFP block when the last active instance of `exe_path`
    /// exits and no unresolved alert still references that block, preventing unbounded BFE
    /// filter growth from short-lived `Temp`/`Downloads` binaries.
    /// Never removes startup-pinned preemptive filters, `PersistedPolicy`, `DomainPolicy`,
    /// or `TransientContainment` filters.
    pub fn remove_preemptive_block_if_unused(
        &mut self,
        exe_path: &str,
        defense: &dyn ActiveDefenseController,
    ) -> bool {
        let key = Self::target_key(exe_path, None);
        if self.startup_preemptive_exes.contains_key(&key.0) {
            return false;
        }
        if self.bound_alerts.values().any(|k| k == &key) {
            return false;
        }
        let Some(entry) = self.installed.get(&key).cloned() else {
            return false;
        };
        if entry.allow || entry.origin != WfpFilterOrigin::Preemptive {
            return false;
        }
        if let Err(err) = defense.remove_wfp_rule(entry.handle) {
            tracing::warn!(
                exe_path = %exe_path,
                wfp_handle = entry.handle,
                error = %err,
                "failed to remove pre-emptive WFP block on ProcessStop"
            );
            return false;
        }
        self.installed.remove(&key);
        true
    }

    /// Returns the active app-wide block handle and origin for `exe_path`, if any.
    pub fn active_app_block(&self, exe_path: &str) -> Option<(u64, WfpFilterOrigin)> {
        let key = Self::target_key(exe_path, None);
        self.installed
            .get(&key)
            .filter(|entry| !entry.allow)
            .map(|entry| (entry.handle, entry.origin.clone()))
    }

    /// Returns `true` if any app-wide filter (Block or Permit) is currently active for `exe_path`.
    pub fn has_any_app_filter(&self, exe_path: &str) -> bool {
        let key = Self::target_key(exe_path, None);
        self.installed.contains_key(&key)
    }

    /// Returns `true` if a filter matching `(exe_path, canonical(remote_ip), allow)` is currently active.
    pub fn has_active_filter(&self, exe_path: &str, remote_ip: Option<IpAddr>, allow: bool) -> bool {
        let key = Self::target_key(exe_path, remote_ip);
        self.installed
            .get(&key)
            .is_some_and(|entry| entry.allow == allow)
    }

    /// Returns `true` if any live WFP Permit (`allow: true`) filter—app-wide or IP-scoped—is
    /// currently tracked for `exe_path`.
    pub fn has_any_permit_filter_for_exe(&self, exe_path: &str) -> bool {
        let exe_k = Self::exe_key(exe_path);
        self.installed
            .iter()
            .any(|((k_exe, _), entry)| k_exe == &exe_k && entry.allow)
    }

    /// Removes all live WFP Permit (`allow: true`) filters—app-wide and IP-scoped—for
    /// `exe_path`, returning the number of filters successfully removed.
    pub fn revoke_permits_for_exe(
        &mut self,
        exe_path: &str,
        defense: &dyn ActiveDefenseController,
    ) -> usize {
        let exe_k = Self::exe_key(exe_path);
        let permit_keys: Vec<WfpTargetKey> = self
            .installed
            .iter()
            .filter(|((k_exe, _), entry)| k_exe == &exe_k && entry.allow)
            .map(|(k, _)| k.clone())
            .collect();
        let mut removed = 0usize;
        for key in permit_keys {
            if let Some(entry) = self.installed.get(&key).cloned() {
                match defense.remove_wfp_rule(entry.handle) {
                    Ok(()) => {
                        self.installed.remove(&key);
                        removed += 1;
                    }
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %entry.exe_path,
                            remote_ip = ?key.1,
                            wfp_handle = entry.handle,
                            error = %err,
                            "failed to revoke stale WFP Permit filter"
                        );
                    }
                }
            }
        }
        removed
    }

    /// Removes a specific live WFP Permit (`allow: true`) filter for `(exe_path, remote_ip)`
    /// if present, returning `true` if a filter was removed.
    pub fn revoke_permit_for_target(
        &mut self,
        exe_path: &str,
        remote_ip: Option<IpAddr>,
        defense: &dyn ActiveDefenseController,
    ) -> bool {
        let key = Self::target_key(exe_path, remote_ip);
        let Some(entry) = self.installed.get(&key).cloned() else {
            return false;
        };
        if !entry.allow {
            return false;
        }
        match defense.remove_wfp_rule(entry.handle) {
            Ok(()) => {
                self.installed.remove(&key);
                true
            }
            Err(err) => {
                tracing::warn!(
                    exe_path = %entry.exe_path,
                    remote_ip = ?key.1,
                    wfp_handle = entry.handle,
                    error = %err,
                    "failed to revoke stale target WFP Permit filter"
                );
                false
            }
        }
    }

    /// Returns the total number of active WFP filter handles currently tracked.
    pub fn active_filter_count(&self) -> usize {
        self.installed.len()
    }

    /// Records a newly installed pre-emptive app-wide WFP Block handle.
    ///
    /// If another thread concurrently installed any filter for `exe_path` OR granted an `AllowOnce`
    /// exemption while `add_wfp_app_rule` was running, immediately removes the redundant `handle`
    /// so no BFE handle is leaked, no `PersistedPolicy` filter is overwritten, and no `AllowOnce`
    /// sibling instance is severed (`#2`).
    pub fn register_preemptive_block(
        &mut self,
        exe_path: &str,
        handle: u64,
        defense: &dyn ActiveDefenseController,
    ) -> bool {
        let key = Self::target_key(exe_path, None);
        if self.installed.contains_key(&key) || self.has_once_allowed_for_exe(&key.0) {
            if let Err(err) = defense.remove_wfp_rule(handle) {
                tracing::warn!(
                    exe_path = %exe_path,
                    wfp_handle = handle,
                    error = %err,
                    "failed removing redundant pre-emptive WFP handle after concurrent insert or AllowOnce"
                );
            }
            return false;
        }
        self.installed.insert(
            key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: false,
                origin: WfpFilterOrigin::Preemptive,
            },
        );
        true
    }

    /// Records a newly installed transient containment WFP Block handle bound to `alert_id`.
    ///
    /// If another thread concurrently installed a filter for `exe_path`, removes the redundant
    /// `handle` cleanly (binding `alert_id` to the existing non-persisted block if present) so
    /// zero BFE handles leak and no `PersistedPolicy` filter is clobbered.
    /// Returns `Some(handle)` if `handle` was newly inserted, or `None` if it was deduplicated.
    pub fn register_transient_containment(
        &mut self,
        alert_id: &str,
        exe_path: &str,
        handle: u64,
        defense: &dyn ActiveDefenseController,
    ) -> Option<u64> {
        let key = Self::target_key(exe_path, None);
        if let Some(existing) = self.installed.get(&key) {
            let bind_existing = !existing.allow
                && matches!(
                    existing.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                );
            if let Err(err) = defense.remove_wfp_rule(handle) {
                tracing::warn!(
                    alert_id = %alert_id,
                    exe_path = %exe_path,
                    wfp_handle = handle,
                    error = %err,
                    "failed removing redundant transient WFP handle after concurrent insert"
                );
            }
            if bind_existing {
                self.bound_alerts.insert(alert_id.to_string(), key);
            }
            return None;
        }
        self.installed.insert(
            key.clone(),
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: false,
                origin: WfpFilterOrigin::TransientContainment,
            },
        );
        self.bound_alerts.insert(alert_id.to_string(), key);
        Some(handle)
    }

    /// Binds `alert_id` to an existing non-persisted app-wide Block (`Preemptive` or
    /// `TransientContainment`) so sibling alerts keep the block active until all resolve.
    pub fn bind_alert_to_app_block(&mut self, alert_id: &str, exe_path: &str) -> bool {
        let key = Self::target_key(exe_path, None);
        if self.installed.get(&key).is_some_and(|e| {
            !e.allow
                && matches!(
                    e.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                )
        }) {
            self.bound_alerts.insert(alert_id.to_string(), key);
            true
        } else {
            false
        }
    }

    /// Removes `alert_id` from `bound_alerts` without modifying installed filters (compensation
    /// path when `record_alert` fails for a sibling alert sharing an existing block).
    pub fn unbind_alert(&mut self, alert_id: &str) {
        self.bound_alerts.remove(alert_id);
    }

    /// Removes and deletes a newly added transient containment filter when `record_alert` fails
    /// (compensation path).
    pub fn rollback_transient_containment(
        &mut self,
        alert_id: &str,
        exe_path: &str,
        expected_handle: u64,
        defense: &dyn ActiveDefenseController,
    ) {
        let key = Self::target_key(exe_path, None);
        self.bound_alerts.remove(alert_id);
        let still_referenced = self.bound_alerts.values().any(|k| k == &key);
        if !still_referenced {
            let should_remove = self.installed.get(&key).is_some_and(|entry| {
                entry.handle == expected_handle
                    && entry.origin == WfpFilterOrigin::TransientContainment
            });
            if should_remove {
                if let Err(err) = defense.remove_wfp_rule(expected_handle) {
                    tracing::warn!(
                        alert_id = %alert_id,
                        exe_path = %exe_path,
                        wfp_handle = expected_handle,
                        error = %err,
                        "compensation remove_wfp_rule failed after record_alert error"
                    );
                }
                self.installed.remove(&key);
            }
        }
    }

    /// Ensures a concrete app-wide or IP-specific WFP Block filter is active for a process that
    /// matched a persisted `NetworkBlock` rule (including wildcard `exe_path_pattern` rules).
    pub fn ensure_policy_block(
        &mut self,
        exe_path: &str,
        remote_ip: Option<IpAddr>,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let clean = exe_path.trim().trim_end_matches(['.', ' ']);
        if is_never_suspend_process(exe_path) || is_never_suspend_process(clean) {
            return Err(format!(
                "refusing WFP block for protected process `{exe_path}`"
            ));
        }
        let canon_ip = remote_ip.map(canonical_ip);
        let key = (Self::exe_key(exe_path), canon_ip);
        if let Some(existing) = self.installed.get_mut(&key) {
            if !existing.allow {
                existing.origin = WfpFilterOrigin::PersistedPolicy;
                self.bound_alerts.retain(|_, k| k != &key);
                return Ok(existing.handle);
            }
            // Replace conflicting Permit with Block (deny-overrides-allow).
            let old_handle = existing.handle;
            defense.remove_wfp_rule(old_handle)?;
            self.installed.remove(&key);
        }

        let handle = defense.add_wfp_app_rule(Path::new(exe_path), canon_ip, false)?;
        self.installed.insert(
            key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: false,
                origin: WfpFilterOrigin::PersistedPolicy,
            },
        );
        Ok(handle)
    }

    /// Materializes a domain-scoped persisted `NetworkBlock` rule onto a resolved destination IP
    /// so reconciliation preserves it while the backing domain block rule exists and removes it
    /// immediately once deleted.
    pub fn ensure_domain_policy_block(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hint: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let clean = exe_path.trim().trim_end_matches(['.', ' ']);
        if is_never_suspend_process(exe_path) || is_never_suspend_process(clean) {
            return Err(format!(
                "refusing WFP block for protected process `{exe_path}`"
            ));
        }
        let canon_ip = canonical_ip(dst_ip);
        let key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get(&key) {
            if !existing.allow {
                return Ok(existing.handle);
            }
            let old_handle = existing.handle;
            defense.remove_wfp_rule(old_handle)?;
            self.installed.remove(&key);
        }

        self.evict_domain_policy_if_full(defense);
        let handle = defense.add_wfp_app_rule(Path::new(exe_path), Some(canon_ip), false)?;
        self.installed.insert(
            key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: false,
                origin: WfpFilterOrigin::DomainPolicy {
                    domain_hint: domain_hint.trim().trim_end_matches('.').to_ascii_lowercase(),
                },
            },
        );
        Ok(handle)
    }

    /// Installs an IP-specific Permit filter when a domain-scoped `NetworkAllow` rule authorizes
    /// `(dst_ip, domain_hint)` while an app-wide pre-emptive block is active (weight 13 > weight 11).
    /// Tagged with [`WfpFilterOrigin::DomainPolicy`] so unrelated rule reconciliations preserve it
    /// while rule deletion or a conflicting `NetworkBlock` removes it immediately.
    pub fn ensure_ip_permit_for_domain_rule(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hint: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        let canon_ip = canonical_ip(dst_ip);
        let norm_dom = domain_hint.trim().trim_end_matches('.').to_ascii_lowercase();
        let ip_key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get_mut(&ip_key) {
            if existing.allow {
                if !norm_dom.is_empty() {
                    if let WfpFilterOrigin::DomainPolicy {
                        domain_hint: ref mut cur_hint,
                    } = existing.origin
                    {
                        if cur_hint.is_empty() {
                            *cur_hint = norm_dom;
                        }
                    }
                }
                return Ok(Some(existing.handle));
            }
            // Do not override an explicit/domain IP-specific Block filter (deny-overrides-allow).
            tracing::warn!(
                exe_path = %exe_path,
                dst_ip = %canon_ip,
                allowed_domain_hint = %domain_hint,
                existing_origin = ?existing.origin,
                "suppressing IP-level WFP Permit for allowed domain because an existing IP Block shares this destination IP (deny-overrides-allow)"
            );
            return Ok(None);
        }

        self.evict_domain_policy_if_full(defense);
        let handle = defense.add_wfp_app_rule(Path::new(exe_path), Some(canon_ip), true)?;
        self.installed.insert(
            ip_key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: true,
                origin: WfpFilterOrigin::DomainPolicy {
                    domain_hint: norm_dom,
                },
            },
        );
        Ok(Some(handle))
    }

    /// Lists active `DomainPolicy` Permit filters whose `domain_hint` was empty at installation
    /// time (e.g., CIDR permits created without inline DNS hints) so reconciliation can cross-check
    /// later DNS history against newly added domain block rules (`SEC_0001`).
    pub fn unnamed_domain_permits(&self) -> Vec<(String, String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if entry.allow
                    && matches!(
                        &entry.origin,
                        WfpFilterOrigin::DomainPolicy { domain_hint } if domain_hint.is_empty()
                    )
                {
                    Some((exe_k.clone(), entry.exe_path.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Removes a specific `DomainPolicy` Permit filter from BFE and local tracking, returning a
    /// rollback snapshot when removed.
    pub fn remove_domain_policy_permit(
        &mut self,
        exe_path: &str,
        ip: IpAddr,
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<RemovedDomainFilterSnapshot>, String> {
        let key = (Self::exe_key(exe_path), Some(canonical_ip(ip)));
        let Some(entry) = self.installed.get(&key).cloned() else {
            return Ok(None);
        };
        let WfpFilterOrigin::DomainPolicy { domain_hint } = entry.origin else {
            return Ok(None);
        };
        if !entry.allow {
            return Ok(None);
        }
        defense.remove_wfp_rule(entry.handle)?;
        self.installed.remove(&key);
        self.bound_alerts.retain(|_, k| k != &key);
        Ok(Some(RemovedDomainFilterSnapshot {
            exe_path: entry.exe_path,
            remote_ip: key.1.unwrap_or(ip),
            allow: true,
            domain_hint,
        }))
    }

    fn evict_domain_policy_if_full(&mut self, defense: &dyn ActiveDefenseController) {
        let domain_count = self
            .installed
            .values()
            .filter(|e| matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            .count();
        if domain_count < MAX_DOMAIN_POLICY_FILTERS {
            return;
        }
        // Prefer evicting an older DomainPolicy Permit before touching DomainPolicy Blocks.
        let victim = self
            .installed
            .iter()
            .find(|(_, e)| e.allow && matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            .or_else(|| {
                self.installed
                    .iter()
                    .find(|(_, e)| matches!(e.origin, WfpFilterOrigin::DomainPolicy { .. }))
            })
            .map(|(k, e)| (k.clone(), e.handle));
        if let Some((key, handle)) = victim {
            if let Err(err) = defense.remove_wfp_rule(handle) {
                tracing::debug!(
                    wfp_handle = handle,
                    error = %err,
                    "failed removing evicted DomainPolicy WFP filter"
                );
            } else {
                self.installed.remove(&key);
            }
        }
    }

    /// Lifts a transient or pre-emptive app-wide WFP Block for `AllowOnce` if no persisted
    /// `NetworkBlock` rule blocks `exe_path` and no other unresolved network alert requires it.
    ///
    /// Returns `(removed_snapshot, was_bound)` so callers can restore either the lifted filter
    /// or the alert's binding if process resume / status update subsequently fails.
    pub fn lift_block_for_allow_once(
        &mut self,
        alert_id: &str,
        exe_path: &str,
        has_persisted_block: bool,
        defense: &dyn ActiveDefenseController,
    ) -> Result<(Option<RemovedBlockSnapshot>, bool), String> {
        let key = Self::target_key(exe_path, None);
        let removed_binding = self.bound_alerts.remove(alert_id);
        let was_bound = removed_binding.is_some();

        if has_persisted_block {
            return Ok((None, was_bound));
        }
        let still_referenced = self.bound_alerts.values().any(|k| k == &key);
        if still_referenced {
            return Ok((None, was_bound));
        }

        let Some(entry) = self.installed.get(&key).cloned() else {
            return Ok((None, was_bound));
        };
        if entry.allow
            || matches!(
                entry.origin,
                WfpFilterOrigin::PersistedPolicy | WfpFilterOrigin::DomainPolicy { .. }
            )
        {
            return Ok((None, was_bound));
        }

        if let Err(err) = defense.remove_wfp_rule(entry.handle) {
            if let Some(bound_key) = removed_binding {
                self.bound_alerts.insert(alert_id.to_string(), bound_key);
            }
            return Err(format!(
                "remove_wfp_rule({}) failed while allowing alert {alert_id}: {err}",
                entry.handle
            ));
        }

        self.installed.remove(&key);
        Ok((
            Some(RemovedBlockSnapshot {
                key,
                exe_path: entry.exe_path,
                origin: entry.origin,
            }),
            was_bound,
        ))
    }

    /// Captures the current non-persisted app-wide block (`Preemptive` or `TransientContainment`)
    /// and all alert IDs currently bound to `exe_path` so a subsequent `AllowPermanent` rollback
    /// can restore both the block and any sibling alert bindings displaced by reconciliation.
    pub fn snapshot_app_block_and_bindings(
        &self,
        exe_path: &str,
    ) -> (Option<RemovedBlockSnapshot>, Vec<String>) {
        let key = Self::target_key(exe_path, None);
        let snap = self.installed.get(&key).and_then(|entry| {
            if !entry.allow
                && matches!(
                    entry.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                )
            {
                Some(RemovedBlockSnapshot {
                    key: key.clone(),
                    exe_path: entry.exe_path.clone(),
                    origin: entry.origin.clone(),
                })
            } else {
                None
            }
        });
        let bound_ids: Vec<String> = self
            .bound_alerts
            .iter()
            .filter(|(_, k)| *k == &key)
            .map(|(id, _)| id.clone())
            .collect();
        (snap, bound_ids)
    }

    /// Best-effort rollback restoring a lifted block filter (and optionally re-binding `alert_id`)
    /// when alert resolution subsequently fails to resume the process or update alert status.
    pub fn restore_lifted_block(
        &mut self,
        rebind_alert_id: Option<&str>,
        snapshot: RemovedBlockSnapshot,
        defense: &dyn ActiveDefenseController,
    ) {
        if let Some(existing) = self.installed.get(&snapshot.key) {
            if !existing.allow
                && matches!(
                    existing.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                )
            {
                if let Some(alert_id) = rebind_alert_id {
                    self.bound_alerts
                        .insert(alert_id.to_string(), snapshot.key);
                }
            }
            return;
        }
        match defense.add_wfp_app_rule(Path::new(&snapshot.exe_path), snapshot.key.1, false) {
            Ok(handle) => {
                let rebind = matches!(
                    snapshot.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                );
                self.installed.insert(
                    snapshot.key.clone(),
                    InstalledWfpFilter {
                        handle,
                        exe_path: snapshot.exe_path,
                        allow: false,
                        origin: snapshot.origin,
                    },
                );
                if rebind {
                    if let Some(alert_id) = rebind_alert_id {
                        self.bound_alerts
                            .insert(alert_id.to_string(), snapshot.key);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    alert_id = ?rebind_alert_id,
                    exe_path = %snapshot.exe_path,
                    error = %err,
                    "failed to restore WFP block filter after resolution rollback"
                );
            }
        }
    }

    /// Releases a `TransientContainment` app-wide WFP block for `alert_id` when resolving via
    /// `AllowPermanent` (scoped or unscoped) or `TerminateAndBlock { add_block_rule: false }`.
    /// Also unbinds `alert_id` from `Preemptive` blocks without deleting the `Preemptive` filter.
    ///
    /// Returns `(removed_snapshot, was_bound)` for rollback compensation.
    pub fn release_transient_containment_for_alert(
        &mut self,
        alert_id: &str,
        exe_path: Option<&str>,
        defense: &dyn ActiveDefenseController,
    ) -> Result<(Option<RemovedBlockSnapshot>, bool), String> {
        let removed_binding = self.bound_alerts.remove(alert_id);
        let was_bound = removed_binding.is_some();
        let bound_key = removed_binding.or_else(|| exe_path.map(|p| Self::target_key(p, None)));
        let Some(key) = bound_key else {
            return Ok((None, was_bound));
        };
        let still_referenced = self.bound_alerts.values().any(|k| k == &key);
        if still_referenced {
            return Ok((None, was_bound));
        }
        let Some(entry) = self.installed.get(&key).cloned() else {
            return Ok((None, was_bound));
        };
        if entry.allow || entry.origin != WfpFilterOrigin::TransientContainment {
            return Ok((None, was_bound));
        }
        if let Err(err) = defense.remove_wfp_rule(entry.handle) {
            self.bound_alerts.insert(alert_id.to_string(), key);
            return Err(format!(
                "remove_wfp_rule({}) failed while releasing containment for alert {alert_id}: {err}",
                entry.handle
            ));
        }
        self.installed.remove(&key);
        Ok((
            Some(RemovedBlockSnapshot {
                key,
                exe_path: entry.exe_path,
                origin: entry.origin,
            }),
            was_bound,
        ))
    }

    /// Reconciles live WFP dynamic filters against all persisted `NetworkBlock` and `NetworkAllow`
    /// rules in SQLite, enforcing **deny-overrides-allow** precedence (Decision #2) and
    /// re-validating materialized [`WfpFilterOrigin::DomainPolicy`] IP filters.
    pub fn reconcile_persisted_rules(
        &mut self,
        rules: &[AllowlistRuleRecord],
        active_concrete_exes: &[String],
        inspector: &dyn BinaryInspector,
        defense: &dyn ActiveDefenseController,
    ) -> WfpReconcileReport {
        let mut report = WfpReconcileReport::default();

        // 1. Collect candidate concrete executable paths from persisted rules, running processes,
        //    and startup-pinned pre-restricted executables.
        let mut candidate_exes: HashMap<String, String> = HashMap::new();
        let mut wildcard_rules: Vec<&AllowlistRuleRecord> = Vec::new();
        let mut has_domain_rules = false;
        for rule in rules {
            if !matches!(rule.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow) {
                continue;
            }
            let pat = rule.exe_path_pattern.trim();
            if pat.is_empty() {
                continue;
            }
            if rule
                .allowed_target
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some_and(|target| {
                    parse_literal_target_ip(target).is_none() && parse_cidr_target(target).is_err()
                })
            {
                has_domain_rules = true;
            }
            if Self::is_wildcard_pattern(pat) {
                wildcard_rules.push(rule);
            } else {
                candidate_exes
                    .entry(Self::exe_key(pat))
                    .or_insert_with(|| pat.to_string());
            }
        }
        self.has_wildcard_network_rules = !wildcard_rules.is_empty();
        self.has_domain_network_rules = has_domain_rules;
        report.skipped_wildcard = wildcard_rules.len();

        for active_exe in active_concrete_exes
            .iter()
            .chain(self.startup_preemptive_exes.values())
        {
            if active_exe.trim().is_empty() || Self::is_wildcard_pattern(active_exe) {
                continue;
            }
            if wildcard_rules
                .iter()
                .any(|r| matches_path_pattern(active_exe, &r.exe_path_pattern))
            {
                candidate_exes
                    .entry(Self::exe_key(active_exe))
                    .or_insert_with(|| active_exe.clone());
            }
        }

        // 2. Compute desired PersistedPolicy WFP filter set with strict deny-overrides-allow.
        let mut desired: HashMap<WfpTargetKey, (String, bool)> = HashMap::new();
        let mut desired_sources: HashMap<WfpTargetKey, Vec<String>> = HashMap::new();
        let mut identity_cache: HashMap<String, BinaryIdentity> = HashMap::new();
        for (exe_k, exe_path) in candidate_exes {
            let matching_rules: Vec<&AllowlistRuleRecord> = rules
                .iter()
                .filter(|r| {
                    matches!(r.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow)
                        && !r.exe_path_pattern.trim().is_empty()
                        && matches_path_pattern(&exe_path, &r.exe_path_pattern)
                })
                .collect();
            if matching_rules.is_empty() {
                continue;
            }

            let needs_inspection = matching_rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    || r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                    || r.signer_subject
                        .as_deref()
                        .is_some_and(|s| !s.trim().is_empty())
            });
            let identity = if needs_inspection {
                let id = inspector.inspect(&exe_path);
                identity_cache.insert(exe_k.clone(), id.clone());
                id
            } else {
                BinaryIdentity {
                    exe_path: exe_path.clone(),
                    sha256: None,
                    authenticode: None,
                }
            };

            let clean_exe = exe_path.trim().trim_end_matches(['.', ' ']);
            let protected =
                is_never_suspend_process(&exe_path) || is_never_suspend_process(clean_exe);

            // Check app-wide NetworkBlock first: if present, deny overrides ALL NetworkAllow rules.
            let app_block_ids: Vec<String> = if protected {
                Vec::new()
            } else {
                matching_rules
                    .iter()
                    .filter(|r| matches_app_wide_network_block(r, &identity))
                    .map(|r| r.rule_id.clone())
                    .collect()
            };
            if !app_block_ids.is_empty() {
                let target_key = (exe_k, None);
                desired.insert(target_key.clone(), (exe_path, false));
                desired_sources
                    .entry(target_key)
                    .or_default()
                    .extend(app_block_ids);
                continue;
            }

            // Collect IP-specific NetworkBlock rules.
            let mut blocked_ips: HashSet<IpAddr> = HashSet::new();
            if !protected {
                for rule in &matching_rules {
                    if rule.scope != RuleScope::NetworkBlock {
                        continue;
                    }
                    if let Some(ip) = rule
                        .allowed_target
                        .as_deref()
                        .and_then(parse_literal_target_ip)
                    {
                        if matches_network_block_rule(rule, &identity, ip, None) {
                            blocked_ips.insert(ip);
                            let target_key = (exe_k.clone(), Some(ip));
                            desired.insert(target_key.clone(), (exe_path.clone(), false));
                            desired_sources
                                .entry(target_key)
                                .or_default()
                                .push(rule.rule_id.clone());
                        }
                    }
                }
            }

            // Collect app-wide NetworkAllow rules (L-04 strict identity verification).
            let app_allow_ids: Vec<String> = matching_rules
                .iter()
                .filter(|r| matches_app_wide_network_allow(r, &identity))
                .map(|r| r.rule_id.clone())
                .collect();
            if !app_allow_ids.is_empty() {
                let target_key = (exe_k.clone(), None);
                desired.insert(target_key.clone(), (exe_path.clone(), true));
                desired_sources
                    .entry(target_key)
                    .or_default()
                    .extend(app_allow_ids);
            }

            // Collect IP-specific NetworkAllow rules unless overridden by an IP-specific Block.
            for rule in &matching_rules {
                if rule.scope != RuleScope::NetworkAllow {
                    continue;
                }
                if let Some(ip) = rule
                    .allowed_target
                    .as_deref()
                    .and_then(parse_literal_target_ip)
                {
                    if blocked_ips.contains(&ip) {
                        continue;
                    }
                    if matches_network_allow_rule(rule, &identity, ip, None) {
                        let target_key = (exe_k.clone(), Some(ip));
                        desired.insert(target_key.clone(), (exe_path.clone(), true));
                        desired_sources
                            .entry(target_key)
                            .or_default()
                            .push(rule.rule_id.clone());
                    }
                }
            }
        }

        // 3. Remove obsolete PersistedPolicy / DomainPolicy filters and conflicting
        //    Preemptive/Transient filters; promote matching filters in place without a gap;
        //    demote obsolete app-wide PersistedPolicy Blocks to Preemptive in place for
        //    startup-pinned interpreters so deleting a NetworkBlock leaves zero unprotected gap.
        let mut keys_to_remove: Vec<WfpTargetKey> = Vec::new();
        let mut keys_to_promote: Vec<WfpTargetKey> = Vec::new();
        let mut keys_to_demote_preemptive: Vec<WfpTargetKey> = Vec::new();
        for (key, entry) in &self.installed {
            match &entry.origin {
                WfpFilterOrigin::PersistedPolicy => match desired.get(key) {
                    Some((_, desired_allow)) if *desired_allow == entry.allow => {}
                    None if key.1.is_none()
                        && !entry.allow
                        && self.startup_preemptive_exes.contains_key(&key.0)
                        && !self.has_once_allowed_for_exe(&key.0) =>
                    {
                        keys_to_demote_preemptive.push(key.clone());
                    }
                    _ => keys_to_remove.push(key.clone()),
                },
                WfpFilterOrigin::DomainPolicy { domain_hint } => {
                    if let Some((_, desired_allow)) = desired.get(key) {
                        if *desired_allow == entry.allow {
                            keys_to_promote.push(key.clone());
                        } else {
                            keys_to_remove.push(key.clone());
                        }
                        continue;
                    }
                    let app_wide_blocked = desired
                        .get(&(key.0.clone(), None))
                        .is_some_and(|(_, allow)| !*allow);
                    if entry.allow && app_wide_blocked {
                        keys_to_remove.push(key.clone());
                        continue;
                    }
                    let Some(ip) = key.1 else {
                        keys_to_remove.push(key.clone());
                        continue;
                    };
                    let identity = identity_cache
                        .entry(key.0.clone())
                        .or_insert_with(|| inspector.inspect(&entry.exe_path));
                    let hint_opt = (!domain_hint.is_empty()).then_some(domain_hint.as_str());
                    let decision = evaluate_outbound_policy(identity, ip, hint_opt, rules);
                    let still_valid = matches!(
                        (entry.allow, decision),
                        (true, OutboundDecision::AllowedByRule { .. })
                            | (false, OutboundDecision::BlockedByRule { .. })
                    );
                    if !still_valid {
                        keys_to_remove.push(key.clone());
                    }
                }
                WfpFilterOrigin::Preemptive | WfpFilterOrigin::TransientContainment => {
                    if let Some((_, desired_allow)) = desired.get(key) {
                        if *desired_allow == entry.allow {
                            keys_to_promote.push(key.clone());
                        } else {
                            keys_to_remove.push(key.clone());
                        }
                    }
                }
            }
        }

        let mut failed_exe_keys: HashSet<String> = HashSet::new();

        for key in keys_to_remove {
            if let Some(entry) = self.installed.get(&key).cloned() {
                match defense.remove_wfp_rule(entry.handle) {
                    Ok(()) => {
                        if let WfpFilterOrigin::DomainPolicy { domain_hint } = &entry.origin {
                            if let Some(remote_ip) = key.1 {
                                report.removed_domain_filters.push(RemovedDomainFilterSnapshot {
                                    exe_path: entry.exe_path.clone(),
                                    remote_ip,
                                    allow: entry.allow,
                                    domain_hint: domain_hint.clone(),
                                });
                            }
                        }
                        self.installed.remove(&key);
                        self.bound_alerts.retain(|_, k| k != &key);
                        report.removed += 1;
                    }
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %entry.exe_path,
                            wfp_handle = entry.handle,
                            error = %err,
                            "failed to remove obsolete WFP rule during reconciliation"
                        );
                        failed_exe_keys.insert(key.0.clone());
                        report.failed += 1;
                        report.failed_ops.push(WfpFailedOp {
                            exe_key: key.0,
                            remote_ip: key.1,
                            is_remove: true,
                            is_startup_preemptive: false,
                            source_rule_ids: Vec::new(),
                            error: err,
                        });
                    }
                }
            }
        }

        // 4. Add missing desired PersistedPolicy filters (Block before Permit for fail-closed order).
        let mut desired_sorted: Vec<(WfpTargetKey, String, bool)> = desired
            .into_iter()
            .map(|(k, (exe, allow))| (k, exe, allow))
            .collect();
        desired_sorted.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));

        for (key, exe_path, allow) in desired_sorted {
            if let Some(existing) = self.installed.get(&key) {
                if existing.allow == allow {
                    continue;
                }
                // Obsolete filter removal in step 3 failed; do not overwrite the tracked handle
                // and leak a duplicate BFE filter (`report.failed_ops` already records the error).
                continue;
            }
            match defense.add_wfp_app_rule(Path::new(&exe_path), key.1, allow) {
                Ok(handle) => {
                    self.installed.insert(
                        key,
                        InstalledWfpFilter {
                            handle,
                            exe_path,
                            allow,
                            origin: WfpFilterOrigin::PersistedPolicy,
                        },
                    );
                    report.applied += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        exe_path = %exe_path,
                        remote_ip = ?key.1,
                        allow,
                        error = %err,
                        "failed to apply persisted WFP firewall rule"
                    );
                    let source_rule_ids = desired_sources.remove(&key).unwrap_or_default();
                    failed_exe_keys.insert(key.0.clone());
                    report.failed += 1;
                    report.failed_ops.push(WfpFailedOp {
                        exe_key: key.0,
                        remote_ip: key.1,
                        is_remove: false,
                        is_startup_preemptive: false,
                        source_rule_ids,
                        error: err,
                    });
                }
            }
        }

        // 4b. Promote/demote matching existing filters ONLY AFTER remove & add succeed for `exe_k`,
        //     capturing snapshots so any subsequent rollback restores pre-promote origins & bindings.
        for key in keys_to_promote {
            if failed_exe_keys.contains(&key.0) {
                continue;
            }
            if let Some(entry) = self.installed.get_mut(&key) {
                let bound_alert_ids: Vec<String> = self
                    .bound_alerts
                    .iter()
                    .filter(|(_, k)| *k == &key)
                    .map(|(alert_id, _)| alert_id.clone())
                    .collect();
                report.promoted_backups.push(PromotedFilterSnapshot {
                    key: key.clone(),
                    prev_origin: entry.origin.clone(),
                    bound_alert_ids,
                });
                entry.origin = WfpFilterOrigin::PersistedPolicy;
                report.promoted += 1;
            }
            self.bound_alerts.retain(|_, k| k != &key);
        }

        for key in keys_to_demote_preemptive {
            if failed_exe_keys.contains(&key.0) {
                continue;
            }
            if let Some(entry) = self.installed.get_mut(&key) {
                report.promoted_backups.push(PromotedFilterSnapshot {
                    key: key.clone(),
                    prev_origin: entry.origin.clone(),
                    bound_alert_ids: Vec::new(),
                });
                entry.origin = WfpFilterOrigin::Preemptive;
            }
        }

        // 5. Ensure startup-pinned pre-restricted executables (standard script interpreters)
        //    have an active Preemptive WFP Block whenever not already covered by an app-wide
        //    NetworkAllow/NetworkBlock or an active AllowOnce exemption (`L-03`).
        let mut startup_sorted: Vec<(String, String)> = self
            .startup_preemptive_exes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        startup_sorted.sort_by(|a, b| a.0.cmp(&b.0));

        for (exe_k, exe_path) in startup_sorted {
            let key = (exe_k.clone(), None);
            if self.installed.contains_key(&key) || self.has_once_allowed_for_exe(&exe_k) {
                continue;
            }
            match defense.add_wfp_app_rule(Path::new(&exe_path), None, false) {
                Ok(handle) => {
                    self.installed.insert(
                        key,
                        InstalledWfpFilter {
                            handle,
                            exe_path,
                            allow: false,
                            origin: WfpFilterOrigin::Preemptive,
                        },
                    );
                    report.applied += 1;
                }
                Err(err) => {
                    tracing::debug!(
                        exe_path = %exe_path,
                        error = %err,
                        "startup pre-emptive WFP block unavailable for interpreter"
                    );
                    report.failed += 1;
                    report.failed_ops.push(WfpFailedOp {
                        exe_key: exe_k,
                        remote_ip: None,
                        is_remove: false,
                        is_startup_preemptive: true,
                        source_rule_ids: Vec::new(),
                        error: err,
                    });
                }
            }
        }

        report
    }

    /// Restores filter origins and alert containment bindings overwritten during a failed
    /// reconciliation pass whose SQLite mutation was rolled back.
    pub fn restore_promoted_filter_states(&mut self, backups: &[PromotedFilterSnapshot]) {
        for snap in backups {
            if let Some(entry) = self.installed.get_mut(&snap.key) {
                entry.origin = snap.prev_origin.clone();
                for alert_id in &snap.bound_alert_ids {
                    self.bound_alerts
                        .insert(alert_id.clone(), snap.key.clone());
                }
            }
        }
    }

    /// Best-effort restoration of [`WfpFilterOrigin::DomainPolicy`] IP filters removed before a
    /// subsequent WFP failure caused SQLite rollback.
    pub fn restore_removed_domain_filters(
        &mut self,
        removed: &[RemovedDomainFilterSnapshot],
        defense: &dyn ActiveDefenseController,
    ) {
        for snap in removed {
            let key = Self::target_key(&snap.exe_path, Some(snap.remote_ip));
            if self.installed.contains_key(&key) {
                continue;
            }
            match defense.add_wfp_app_rule(Path::new(&snap.exe_path), Some(snap.remote_ip), snap.allow) {
                Ok(handle) => {
                    self.installed.insert(
                        key,
                        InstalledWfpFilter {
                            handle,
                            exe_path: snap.exe_path.clone(),
                            allow: snap.allow,
                            origin: WfpFilterOrigin::DomainPolicy {
                                domain_hint: snap.domain_hint.clone(),
                            },
                        },
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        exe_path = %snap.exe_path,
                        remote_ip = %snap.remote_ip,
                        allow = snap.allow,
                        error = %err,
                        "failed to restore removed DomainPolicy WFP filter during rollback"
                    );
                }
            }
        }
    }
}

/// Parses an optional `allowed_target` string into a canonical [`IpAddr`] when applicable
/// (unwrapping IPv4-mapped IPv6 addresses into IPv4).
pub fn parse_literal_target_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('*') {
        return None;
    }
    trimmed.parse::<IpAddr>().ok().map(canonical_ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledr_proto::ProcessIdentity;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    struct StubInspector(String);

    impl BinaryInspector for StubInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(self.0.clone()),
                authenticode: None,
            }
        }
    }

    #[derive(Default)]
    struct StubDefense {
        next_handle: AtomicU64,
        removed: Mutex<Vec<u64>>,
        fail_exes: Mutex<Vec<String>>,
        fail_removes: Mutex<bool>,
    }

    impl StubDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(1),
                ..Self::default()
            }
        }
    }

    impl ActiveDefenseController for StubDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            _allow: bool,
        ) -> Result<u64, String> {
            let s = exe_path.to_string_lossy().to_ascii_lowercase();
            if self
                .fail_exes
                .lock()
                .expect("lock fail_exes")
                .iter()
                .any(|pat| s.contains(pat))
            {
                return Err(format!("mock WFP add failure for {s}"));
            }
            Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if *self.fail_removes.lock().expect("lock fail_removes") {
                return Err(format!("mock WFP remove failure for {filter_id}"));
            }
            self.removed.lock().expect("lock removed").push(filter_id);
            Ok(())
        }
    }

    #[test]
    fn firewall_register_preemptive_block_respects_active_allow_once() {
        let mut fw = WfpRuleManager::new();
        let defense = StubDefense::new();
        let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        fw.mark_once_allowed("100:1", ps);
        let h = defense.add_wfp_app_rule(Path::new(ps), None, false).unwrap();
        assert!(!fw.register_preemptive_block(ps, h, &defense));
        assert!(!fw.has_any_app_filter(ps));
        assert_eq!(*defense.removed.lock().unwrap(), vec![h]);
    }

    #[test]
    fn firewall_reconcile_distinguishes_startup_preemptive_and_policy_failures() {
        let mut fw = WfpRuleManager::new();
        let defense = StubDefense::new();
        let inspector = StubInspector("a".repeat(64));
        let startup_ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let policy_app = r"C:\Tools\policy_app.exe";

        fw.set_startup_preemptive_executables(&[startup_ps.to_string()]);
        defense
            .fail_exes
            .lock()
            .unwrap()
            .push("powershell.exe".to_string());

        // Only startup-pinned interpreter fails -> has_policy_failures() MUST be false!
        let report1 = fw.reconcile_persisted_rules(
            &[AllowlistRuleRecord {
                rule_id: "R1".to_string(),
                scope: RuleScope::NetworkBlock,
                exe_path_pattern: policy_app.to_string(),
                sha256: None,
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: None,
                created_at_ms: 1,
                created_by: "test".to_string(),
            }],
            &[],
            &inspector,
            &defense,
        );
        assert_eq!(report1.applied, 1);
        assert_eq!(report1.failed, 1);
        assert!(!report1.has_policy_failures());
        assert!(report1.policy_failure_summary().is_empty());

        // Removing R1 fails when remove_wfp_rule fails -> has_policy_failures() MUST be true!
        *defense.fail_removes.lock().unwrap() = true;
        let report2 = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
        assert!(report2.has_policy_failures());
        assert!(report2.policy_failure_summary().contains("remove"));
        assert!(report2.policy_failure_summary().contains("policy_app.exe"));
    }

    #[test]
    fn firewall_shared_ip_deny_suppresses_permit_and_revoke_permits_clears_all() {
        let mut fw = WfpRuleManager::new();
        let defense = StubDefense::new();
        let app = r"C:\Tools\shared_cdn.exe";
        let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
        let other_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51));

        fw.ensure_domain_policy_block(app, shared_ip, "blocked.example", &defense)
            .expect("domain block");
        let permit_res = fw
            .ensure_ip_permit_for_domain_rule(app, shared_ip, "allowed.example", &defense)
            .expect("shared ip check");
        assert_eq!(permit_res, None, "existing IP block must suppress domain permit");
        assert!(fw.has_active_filter(app, Some(shared_ip), false));
        assert!(!fw.has_active_filter(app, Some(shared_ip), true));

        let p_handle = fw
            .ensure_ip_permit_for_domain_rule(app, other_ip, "allowed.example", &defense)
            .expect("other ip permit");
        assert!(p_handle.is_some());
        assert!(fw.has_any_permit_filter_for_exe(app));
        let revoked = fw.revoke_permits_for_exe(app, &defense);
        assert_eq!(revoked, 1);
        assert!(!fw.has_any_permit_filter_for_exe(app));
        assert!(fw.has_active_filter(app, Some(shared_ip), false));
    }

    #[test]
    fn firewall_reconcile_scoping_and_rollback_fidelity() {
        let mut fw = WfpRuleManager::new();
        let defense = StubDefense::new();
        let inspector = StubInspector("a".repeat(64));

        // 1. Pre-existing failure on broken.exe + CIDR rule does NOT flip `has_domain_network_rules`.
        let broken_exe = r"C:\Tools\broken.exe";
        let healthy_exe = r"C:\Tools\healthy.exe";
        let cidr_exe = r"C:\Tools\cidr.exe";
        defense.fail_exes.lock().unwrap().push("broken.exe".to_string());

        let broken_rule = AllowlistRuleRecord {
            rule_id: "R-broken".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: broken_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        let cidr_rule = AllowlistRuleRecord {
            rule_id: "R-cidr".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: cidr_exe.to_string(),
            sha256: Some("a".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.0/24".to_string()),
            created_at_ms: 2,
            created_by: "test".to_string(),
        };
        let r1 = fw.reconcile_persisted_rules(&[broken_rule.clone(), cidr_rule.clone()], &[], &inspector, &defense);
        assert!(!fw.has_domain_network_rules(), "CIDR rule must not count as domain rule");
        assert!(r1.failure_summary_for_rules(&[&broken_rule]).is_some());
        assert!(r1.failure_summary_for_rules(&[&cidr_rule]).is_none());

        // Subsequent unrelated healthy rule mutation ignores pre-existing `broken.exe` failure.
        let healthy_rule = AllowlistRuleRecord {
            rule_id: "R-healthy".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: healthy_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 3,
            created_by: "test".to_string(),
        };
        let r2 = fw.reconcile_persisted_rules(
            &[broken_rule.clone(), cidr_rule.clone(), healthy_rule.clone()],
            &[],
            &inspector,
            &defense,
        );
        assert!(
            r2.failure_summary_for_rules(&[&healthy_rule]).is_none(),
            "pre-existing unrelated failure must not fail healthy rule mutation"
        );
        assert!(
            r2.failure_summary_for_rules(&[&broken_rule]).is_some(),
            "repeated failure on affected rule must still surface via failure_summary_for_rules"
        );
        // Same exe, unrelated domain block rule must NOT be blocked by `broken_rule`'s app-wide failure.
        let same_exe_ads_block = AllowlistRuleRecord {
            rule_id: "R-broken-ads-block".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: broken_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("ads.example.com".to_string()),
            created_at_ms: 4,
            created_by: "test".to_string(),
        };
        let r2_dom = fw.reconcile_persisted_rules(
            &[
                broken_rule.clone(),
                cidr_rule.clone(),
                healthy_rule.clone(),
                same_exe_ads_block.clone(),
            ],
            &[],
            &inspector,
            &defense,
        );
        assert!(
            r2_dom
                .failure_summary_for_rules(&[&same_exe_ads_block])
                .is_none(),
            "unrelated pre-existing failure on same exe must NOT block domain rule mutation"
        );
        assert!(fw.has_active_filter(healthy_exe, None, false));

        // 2. Promotion / DomainPolicy remove rollback snapshots:
        //    Simulate `healthy_exe` having both a TransientContainment block bound to alert "AL-1"
        //    and a DomainPolicy IP block while removing `healthy_rule` fails on `remove_wfp_rule`.
        let transient_app = r"C:\Tools\transient.exe";
        let h_tr = defense.add_wfp_app_rule(Path::new(transient_app), None, false).unwrap();
        fw.register_transient_containment("AL-1", transient_app, h_tr, &defense);
        let dom_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
        fw.ensure_domain_policy_block(transient_app, dom_ip, "bad.example", &defense)
            .unwrap();
        let tr_rule = AllowlistRuleRecord {
            rule_id: "R-tr-block".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: transient_app.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 4,
            created_by: "test".to_string(),
        };
        let dom_rule = AllowlistRuleRecord {
            rule_id: "R-dom-block".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: transient_app.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("bad.example".to_string()),
            created_at_ms: 5,
            created_by: "test".to_string(),
        };

        // Reconcile succeeds: `TransientContainment` promoted to `PersistedPolicy` and `AL-1` unbound,
        // and `promoted_backups` records pre-promote snapshot.
        let r3 = fw.reconcile_persisted_rules(&[tr_rule.clone(), dom_rule], &[], &inspector, &defense);
        assert_eq!(fw.filter_origin(transient_app, None), Some(&WfpFilterOrigin::PersistedPolicy));
        assert!(!fw.is_alert_bound("AL-1"));
        assert_eq!(r3.promoted_backups.len(), 1);

        // Restoring promotion snapshot brings back TransientContainment + AL-1 binding.
        fw.restore_promoted_filter_states(&r3.promoted_backups);
        assert_eq!(
            fw.filter_origin(transient_app, None),
            Some(&WfpFilterOrigin::TransientContainment)
        );
        assert!(fw.is_alert_bound("AL-1"));

        // Removing `dom_rule` deletes `DomainPolicy` filter and captures `removed_domain_filters`;
        // rollback re-installs `DomainPolicy` filter into BFE + `WfpRuleManager`.
        let r4 = fw.reconcile_persisted_rules(&[], &[], &inspector, &defense);
        assert_eq!(r4.removed_domain_filters.len(), 1);
        assert!(!fw.has_active_filter(transient_app, Some(dom_ip), false));
        fw.restore_removed_domain_filters(&r4.removed_domain_filters, &defense);
        assert!(fw.has_active_filter(transient_app, Some(dom_ip), false));
        assert_eq!(
            fw.filter_origin(transient_app, Some(dom_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hint: "bad.example".to_string()
            })
        );
    }
}
