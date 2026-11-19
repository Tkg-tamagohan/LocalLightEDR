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

/// Upper bound on normalized domain hints retained per [`WfpFilterOrigin::DomainPolicy`] filter
/// to keep per-filter metadata strictly bounded (`L-10`).
pub const MAX_DOMAIN_HINTS_PER_FILTER: usize = 32;

/// Normalizes a domain hint (trim whitespace, strip trailing DNS dots, ASCII lowercase).
fn normalize_domain_hint(raw: &str) -> Option<String> {
    let norm = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    (!norm.is_empty()).then_some(norm)
}

/// Inserts a normalized domain hint into `hints` without duplicates while keeping the set bounded
/// by [`MAX_DOMAIN_HINTS_PER_FILTER`] (evicting the oldest hint FIFO on overflow).
fn merge_domain_hint(hints: &mut Vec<String>, raw: &str) {
    let Some(norm) = normalize_domain_hint(raw) else {
        return;
    };
    if hints.iter().any(|h| h == &norm) {
        return;
    }
    while hints.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
        hints.remove(0);
    }
    hints.push(norm);
}

/// Merges `authorizing_hints` (protected from eviction by co-hosted hints) and `cohosted_hints`
/// into `target` while keeping `target.len() <= MAX_DOMAIN_HINTS_PER_FILTER`.
///
/// Within the 32-hint cap, preserves insertion order (`authorizing_hints` followed by
/// `cohosted_hints` appended to existing hints without duplicates). On overflow, evicts the
/// oldest unprotected slot first so `authorizing_hints` are never pushed out by co-hosted hints
/// (`AUD-P3-02`).
fn merge_domain_hints_prioritized(
    target: &mut Vec<String>,
    authorizing_hints: &[String],
    cohosted_hints: &[String],
) {
    let protected: HashSet<&str> = authorizing_hints.iter().map(String::as_str).collect();

    for hint in authorizing_hints {
        if target.iter().any(|h| h == hint) {
            continue;
        }
        while target.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
            if let Some(evict_idx) = target
                .iter()
                .position(|existing| !protected.contains(existing.as_str()))
            {
                target.remove(evict_idx);
            } else {
                target.remove(0);
            }
        }
        target.push(hint.clone());
    }

    for hint in cohosted_hints {
        if target.iter().any(|h| h == hint) {
            continue;
        }
        if target.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
            let Some(evict_idx) = target
                .iter()
                .position(|existing| !protected.contains(existing.as_str()))
            else {
                // All slots are occupied by protected authorizing hints; do not evict them.
                continue;
            };
            target.remove(evict_idx);
        }
        target.push(hint.clone());
    }
}

/// Computes the pruned `domain_hints` for a [`WfpFilterOrigin::DomainPolicy`] IP Permit filter
/// given a retirement predicate `is_retired` (DNS migration or `superseded_permit_hints`).
///
/// Shared between [`WfpRuleManager::prune_migrated_domain_permit_hints_for_query`] and
/// [`WfpRuleManager::reconcile_persisted_rules_with_dns_context`] so both paths enforce identical
/// semantics:
/// - When surviving (non-retired) hints or `static_allowed` preserve `AllowedByRule`, prune all
///   retired hints.
/// - Otherwise prune retired unallowed co-hosted hints while retaining retired hints that still
///   match a persisted `NetworkAllow` rule (preserving round-robin/cached-IP permits and rule
///   attribution on subsequent block/delete).
/// - Never corrupt a non-static Permit into untagged `domain_hints: []`.
fn compute_pruned_permit_hints(
    domain_hints: &[String],
    identity: &BinaryIdentity,
    ip: IpAddr,
    rules: &[AllowlistRuleRecord],
    static_allowed: bool,
    mut is_retired: impl FnMut(&str) -> bool,
) -> Vec<String> {
    let mut normalized_all: Vec<String> = Vec::with_capacity(domain_hints.len());
    let mut surviving_hints: Vec<String> = Vec::with_capacity(domain_hints.len());
    let mut retired_flags: Vec<bool> = Vec::with_capacity(domain_hints.len());

    for raw in domain_hints {
        let Some(norm) = normalize_domain_hint(raw) else {
            continue;
        };
        if normalized_all.iter().any(|h| h == &norm) {
            continue;
        }
        let retired = is_retired(&norm);
        if !retired {
            surviving_hints.push(norm.clone());
        }
        normalized_all.push(norm);
        retired_flags.push(retired);
    }

    if !retired_flags.iter().any(|&r| r) {
        return normalized_all;
    }

    let surviving_preserves_allow = static_allowed
        || surviving_hints.iter().any(|hint| {
            matches!(
                evaluate_outbound_policy(identity, ip, Some(hint.as_str()), rules),
                OutboundDecision::AllowedByRule { .. }
            )
        });
    if surviving_preserves_allow {
        return surviving_hints;
    }

    let mut retained: Vec<String> = Vec::with_capacity(normalized_all.len());
    for (norm, retired) in normalized_all.iter().zip(retired_flags.iter()) {
        if !*retired
            || rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    && matches_network_allow_rule(r, identity, ip, Some(norm.as_str()))
                    && !matches_network_allow_rule(r, identity, ip, None)
            })
        {
            retained.push(norm.clone());
        }
    }

    if retained.is_empty() && !static_allowed {
        return normalized_all;
    }
    retained
}

/// Origin tracking why a dynamic WFP filter is currently installed in BFE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WfpFilterOrigin {
    /// Installed directly to enforce a persisted concrete/IP `NetworkBlock` or `NetworkAllow` rule.
    PersistedPolicy,
    /// Installed for a concrete resolved IP matched by persisted domain-scoped `NetworkBlock`
    /// or `NetworkAllow` rules (`domain_hints` retains the normalized, deduplicated, bounded set
    /// of domains backing this IP filter so shared-IP reconciliation and DNS migration cleanup
    /// stay accurate even across DNS history eviction).
    DomainPolicy { domain_hints: Vec<String> },
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
    pub newly_required: bool,
    pub source_rule_ids: Vec<String>,
    pub domain_hints: Vec<String>,
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
    pub domain_hints: Vec<String>,
}

/// Optional live DNS history context supplied during persisted-rule reconciliation so existing
/// [`WfpFilterOrigin::DomainPolicy`] Blocks retain active blocked domains added after DNS
/// resolution and [`WfpFilterOrigin::DomainPolicy`] Permits prune migrated/superseded hints
/// (`#1`, `#4`).
#[derive(Debug, Default)]
pub struct WfpReconcileDnsContext {
    /// Non-superseded active DNS domains per `(exe_key, canonical_ip)` for currently installed
    /// `DomainPolicy` Blocks.
    pub active_block_domains: HashMap<(String, IpAddr), Vec<String>>,
    /// Normalized `(exe_key, canonical_ip, domain_hint)` tuples known to be superseded in
    /// `ProcessDnsHistory` for currently installed `DomainPolicy` Permits.
    pub superseded_permit_hints: HashSet<(String, IpAddr, String)>,
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
    /// WFP failure affecting at least one rule in `affected_rules` or a filter that newly became
    /// required because of this policy mutation (ignoring pre-existing failures on unrelated rules
    /// while still surfacing repeated failures on any affected rule).
    pub fn failure_summary_for_rules(&self, affected_rules: &[&AllowlistRuleRecord]) -> Option<String> {
        let relevant: Vec<&WfpFailedOp> = self
            .failed_ops
            .iter()
            .filter(|op| {
                !op.is_startup_preemptive
                    && (op.newly_required
                        || affected_rules
                            .iter()
                            .any(|rule| Self::op_matches_rule(op, rule)))
            })
            .collect();
        if relevant.is_empty() {
            None
        } else {
            Some(Self::format_ops(relevant.into_iter()))
        }
    }

    fn op_matches_rule(op: &WfpFailedOp, rule: &AllowlistRuleRecord) -> bool {
        if !op.source_rule_ids.is_empty() {
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
        if op.is_remove {
            if op.domain_hints.is_empty() {
                return matches_network_target(target, ip, None);
            }
            return op
                .domain_hints
                .iter()
                .any(|hint| matches_network_target(target, ip, Some(hint.as_str())));
        }
        false
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

struct DesiredPersistedPlan {
    desired: HashMap<WfpTargetKey, (String, bool)>,
    desired_sources: HashMap<WfpTargetKey, Vec<String>>,
    skipped_wildcard: usize,
    has_wildcard_network_rules: bool,
    has_domain_network_rules: bool,
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
    /// immediately once deleted. When reusing an existing `DomainPolicy` Block filter on a shared
    /// IP, merges `domain_hint` into its bounded `domain_hints` set (`#4`).
    pub fn ensure_domain_policy_block(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hint: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        self.ensure_domain_policy_block_hints(exe_path, dst_ip, &[domain_hint], defense)
    }

    /// Like [`WfpRuleManager::ensure_domain_policy_block`], merging all non-empty
    /// `domain_hints` into the `DomainPolicy` Block metadata (deduplicated and bounded by
    /// [`MAX_DOMAIN_HINTS_PER_FILTER`]). Passing an empty slice creates or reuses an untagged
    /// (`domain_hints: []`) static/CIDR-backed `DomainPolicy` Block without polluting hints.
    pub fn ensure_domain_policy_block_hints<S: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hints: &[S],
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let clean = exe_path.trim().trim_end_matches(['.', ' ']);
        if is_never_suspend_process(exe_path) || is_never_suspend_process(clean) {
            return Err(format!(
                "refusing WFP block for protected process `{exe_path}`"
            ));
        }
        let canon_ip = canonical_ip(dst_ip);
        let mut normalized_hints = Vec::new();
        for raw in domain_hints {
            merge_domain_hint(&mut normalized_hints, raw.as_ref());
        }
        let key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get_mut(&key) {
            if !existing.allow {
                if let WfpFilterOrigin::DomainPolicy {
                    domain_hints: ref mut cur_hints,
                } = existing.origin
                {
                    for hint in &normalized_hints {
                        merge_domain_hint(cur_hints, hint);
                    }
                }
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
                    domain_hints: normalized_hints,
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
        self.ensure_ip_permit_for_domain_hints(exe_path, dst_ip, &[domain_hint], defense)
    }

    /// Like [`WfpRuleManager::ensure_ip_permit_for_domain_rule`], merging all non-empty
    /// `domain_hints` into the `DomainPolicy` Permit metadata (deduplicated and bounded by
    /// [`MAX_DOMAIN_HINTS_PER_FILTER`]).
    pub fn ensure_ip_permit_for_domain_hints<S: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        domain_hints: &[S],
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        self.ensure_ip_permit_for_domain_hints_prioritized(
            exe_path,
            dst_ip,
            &[] as &[&str],
            domain_hints,
            defense,
        )
    }

    /// Like [`WfpRuleManager::ensure_ip_permit_for_domain_hints`], protecting `authorizing_hints`
    /// from FIFO eviction by `cohosted_hints` when [`MAX_DOMAIN_HINTS_PER_FILTER`] is reached
    /// (`AUD-P3-02`). Within the 32-hint cap, preserves insertion order (`authorizing_hints`
    /// followed by `cohosted_hints`).
    pub fn ensure_ip_permit_for_domain_hints_prioritized<S1: AsRef<str>, S2: AsRef<str>>(
        &mut self,
        exe_path: &str,
        dst_ip: IpAddr,
        authorizing_hints: &[S1],
        cohosted_hints: &[S2],
        defense: &dyn ActiveDefenseController,
    ) -> Result<Option<u64>, String> {
        let canon_ip = canonical_ip(dst_ip);
        let mut norm_auth = Vec::new();
        for raw in authorizing_hints {
            merge_domain_hint(&mut norm_auth, raw.as_ref());
        }
        let mut norm_cohost = Vec::new();
        for raw in cohosted_hints {
            let Some(norm) = normalize_domain_hint(raw.as_ref()) else {
                continue;
            };
            if !norm_auth.iter().any(|h| h == &norm) && !norm_cohost.iter().any(|h| h == &norm) {
                norm_cohost.push(norm);
            }
        }

        let ip_key = (Self::exe_key(exe_path), Some(canon_ip));
        if let Some(existing) = self.installed.get_mut(&ip_key) {
            if existing.allow {
                if let WfpFilterOrigin::DomainPolicy {
                    domain_hints: ref mut cur_hints,
                } = existing.origin
                {
                    merge_domain_hints_prioritized(cur_hints, &norm_auth, &norm_cohost);
                }
                return Ok(Some(existing.handle));
            }
            // Do not override an explicit/domain IP-specific Block filter (deny-overrides-allow).
            let mut log_hints = Vec::new();
            merge_domain_hints_prioritized(&mut log_hints, &norm_auth, &norm_cohost);
            tracing::warn!(
                exe_path = %exe_path,
                dst_ip = %canon_ip,
                allowed_domain_hints = ?log_hints,
                existing_origin = ?existing.origin,
                "suppressing IP-level WFP Permit for allowed domain because an existing IP Block shares this destination IP (deny-overrides-allow)"
            );
            return Ok(None);
        }

        let mut normalized_hints = Vec::new();
        merge_domain_hints_prioritized(&mut normalized_hints, &norm_auth, &norm_cohost);
        self.evict_domain_policy_if_full(defense);
        let handle = defense.add_wfp_app_rule(Path::new(exe_path), Some(canon_ip), true)?;
        self.installed.insert(
            ip_key,
            InstalledWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                allow: true,
                origin: WfpFilterOrigin::DomainPolicy {
                    domain_hints: normalized_hints,
                },
            },
        );
        Ok(Some(handle))
    }

    /// Lists active `DomainPolicy` Permit filters whose `domain_hints` was empty at installation
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
                        WfpFilterOrigin::DomainPolicy { domain_hints } if domain_hints.is_empty()
                    )
                {
                    Some((exe_k.clone(), entry.exe_path.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Permit filters `(exe_key, exe_path, remote_ip)` so
    /// reconciliation can cross-check live DNS history against newly added domain block rules,
    /// including shared-IP permits tagged with another domain name (`#1`, `#4`).
    pub fn domain_policy_permits(&self) -> Vec<(String, String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if entry.allow && matches!(&entry.origin, WfpFilterOrigin::DomainPolicy { .. }) {
                    Some((exe_k.clone(), entry.exe_path.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Block filters `(exe_key, remote_ip)` across all executables
    /// so reconciliation can synchronize live DNS-history domains against newly added block rules.
    pub fn all_domain_policy_blocks(&self) -> Vec<(String, IpAddr)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if !entry.allow && matches!(&entry.origin, WfpFilterOrigin::DomainPolicy { .. }) {
                    Some((exe_k.clone(), ip))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Lists all active `DomainPolicy` Permit filters with non-empty `domain_hints` across all
    /// executables so reconciliation can prune migrated/superseded hints before evaluating blocks.
    pub fn all_domain_policy_permits_with_hints(&self) -> Vec<(String, IpAddr, Vec<String>)> {
        self.installed
            .iter()
            .filter_map(|((exe_k, ip_opt), entry)| {
                let ip = (*ip_opt)?;
                if !entry.allow {
                    return None;
                }
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                if domain_hints.is_empty() {
                    return None;
                }
                Some((exe_k.clone(), ip, domain_hints.clone()))
            })
            .collect()
    }

    /// Lists active `DomainPolicy` Permit filters with non-empty `domain_hints` for `exe_path`.
    pub fn domain_policy_permits_with_hints(&self, exe_path: &str) -> Vec<(IpAddr, Vec<String>)> {
        let exe_k = Self::exe_key(exe_path);
        let mut out: Vec<(IpAddr, Vec<String>)> = self
            .installed
            .iter()
            .filter_map(|((k_exe, ip_opt), entry)| {
                if k_exe != &exe_k || !entry.allow {
                    return None;
                }
                let ip = (*ip_opt)?;
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                if domain_hints.is_empty() {
                    return None;
                }
                Some((ip, domain_hints.clone()))
            })
            .collect();
        out.sort_by_key(|a| a.0.to_string());
        out
    }

    /// Returns the `domain_hints` of a live [`WfpFilterOrigin::DomainPolicy`] IP Permit filter
    /// for `(exe_path, remote_ip)` (canonicalizing `remote_ip`), or `None` when no live
    /// `DomainPolicy` IP Permit exists for that target (`AUD-P3-01`).
    pub fn domain_policy_permit_hints(
        &self,
        exe_path: &str,
        remote_ip: IpAddr,
    ) -> Option<Vec<String>> {
        let key = (Self::exe_key(exe_path), Some(canonical_ip(remote_ip)));
        let entry = self.installed.get(&key)?;
        if !entry.allow {
            return None;
        }
        match &entry.origin {
            WfpFilterOrigin::DomainPolicy { domain_hints } => Some(domain_hints.clone()),
            _ => None,
        }
    }

    /// Prunes migrated/superseded domains from [`WfpFilterOrigin::DomainPolicy`] IP Permit filters
    /// for `exe_path` using [`compute_pruned_permit_hints`]:
    /// - When surviving hints or static policy still satisfy `AllowedByRule`, prunes all migrated/
    ///   superseded hints so later blocks on a migrated domain cannot falsely revoke an active
    ///   shared-IP or CIDR Permit.
    /// - Otherwise prunes migrated unallowed co-hosted hints while retaining migrated authorizing
    ///   hints that match a persisted `NetworkAllow` rule so unrelated reconciliations do not
    ///   drop a cached-IP Permit (`PRRT_kwDOVyjVyM65e5kL`).
    /// - Never transitions a non-static Permit into an untagged `domain_hints: []` Permit.
    pub fn prune_migrated_domain_permit_hints_for_query(
        &mut self,
        exe_path: &str,
        query_name: &str,
        new_ips: &[IpAddr],
        identity: &BinaryIdentity,
        rules: &[AllowlistRuleRecord],
        superseded_pairs: &HashSet<(IpAddr, String)>,
    ) -> usize {
        let exe_k = Self::exe_key(exe_path);
        let Some(norm_query) = normalize_domain_hint(query_name) else {
            return 0;
        };
        let new_canon: HashSet<IpAddr> = new_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let has_v4 = new_canon.iter().any(IpAddr::is_ipv4);
        let has_v6 = new_canon.iter().any(IpAddr::is_ipv6);
        let norm_superseded: HashSet<(IpAddr, String)> = superseded_pairs
            .iter()
            .filter_map(|(ip, dom)| {
                normalize_domain_hint(dom).map(|norm| (canonical_ip(*ip), norm))
            })
            .collect();

        let mut updated_hints: Vec<(WfpTargetKey, Vec<String>)> = Vec::new();
        for (k, entry) in &self.installed {
            if k.0 != exe_k || !entry.allow {
                continue;
            }
            let Some(ip) = k.1 else {
                continue;
            };
            let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                continue;
            };
            if domain_hints.is_empty() {
                continue;
            }
            let same_family = (has_v4 && ip.is_ipv4()) || (has_v6 && ip.is_ipv6());
            let static_allowed = matches!(
                evaluate_outbound_policy(identity, ip, None, rules),
                OutboundDecision::AllowedByRule { .. }
            );
            let next_hints = compute_pruned_permit_hints(
                domain_hints,
                identity,
                ip,
                rules,
                static_allowed,
                |hint_norm| {
                    let is_domain_hint =
                        !hint_norm.contains('/') && parse_literal_target_ip(hint_norm).is_none();
                    let matches_migrated_query = !new_canon.contains(&ip)
                        && same_family
                        && is_domain_hint
                        && (hint_norm == norm_query
                            || (hint_norm.contains('*')
                                && matches_network_target(hint_norm, ip, Some(&norm_query))));
                    matches_migrated_query
                        || norm_superseded.contains(&(ip, hint_norm.to_string()))
                },
            );
            if &next_hints != domain_hints {
                updated_hints.push((k.clone(), next_hints));
            }
        }

        let updated = updated_hints.len();
        for (key, next_hints) in updated_hints {
            if let Some(entry) = self.installed.get_mut(&key) {
                entry.origin = WfpFilterOrigin::DomainPolicy {
                    domain_hints: next_hints,
                };
            }
        }
        updated
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
        let WfpFilterOrigin::DomainPolicy { domain_hints } = entry.origin else {
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
            domain_hints,
        }))
    }

    /// Prunes migrated/superseded domains from [`WfpFilterOrigin::DomainPolicy`] IP Block filters
    /// for `exe_path`, synchronizes active blocking reason domains from
    /// `active_blocking_domains_by_ip`, and removes any non-static domain block whose remaining
    /// `domain_hints` becomes empty (`BUG_..._0003`, `#4`).
    #[allow(clippy::too_many_arguments)]
    pub fn invalidate_stale_domain_blocks_for_query(
        &mut self,
        exe_path: &str,
        query_name: &str,
        new_ips: &[IpAddr],
        static_blocked_ips: &HashSet<IpAddr>,
        active_blocking_domains_by_ip: &HashMap<IpAddr, Vec<String>>,
        superseded_pairs: &HashSet<(IpAddr, String)>,
        defense: &dyn ActiveDefenseController,
    ) -> usize {
        let exe_k = Self::exe_key(exe_path);
        let Some(norm_query) = normalize_domain_hint(query_name) else {
            return 0;
        };
        let new_canon: HashSet<IpAddr> = new_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let has_v4 = new_canon.iter().any(IpAddr::is_ipv4);
        let has_v6 = new_canon.iter().any(IpAddr::is_ipv6);
        let static_blocked_canon: HashSet<IpAddr> = static_blocked_ips
            .iter()
            .map(|ip| canonical_ip(*ip))
            .collect();
        let mut active_by_ip_canon: HashMap<IpAddr, Vec<String>> =
            HashMap::with_capacity(active_blocking_domains_by_ip.len());
        for (ip, doms) in active_blocking_domains_by_ip {
            let entry = active_by_ip_canon.entry(canonical_ip(*ip)).or_default();
            for dom in doms {
                merge_domain_hint(entry, dom);
            }
        }
        let norm_superseded: HashSet<(IpAddr, String)> = superseded_pairs
            .iter()
            .filter_map(|(ip, dom)| {
                normalize_domain_hint(dom).map(|norm| (canonical_ip(*ip), norm))
            })
            .collect();

        let mut stale_keys: Vec<WfpTargetKey> = Vec::new();
        let mut updated_hints: Vec<(WfpTargetKey, Vec<String>)> = Vec::new();

        for (k, entry) in &self.installed {
            if k.0 != exe_k || entry.allow {
                continue;
            }
            let Some(ip) = k.1 else {
                continue;
            };
            let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                continue;
            };

            let had_non_empty_hints = !domain_hints.is_empty();
            let same_family = (has_v4 && ip.is_ipv4()) || (has_v6 && ip.is_ipv6());
            let mut next_hints: Vec<String> = Vec::with_capacity(domain_hints.len());

            // 1. Prune hints that migrated away in this query or are superseded in DNS history.
            if had_non_empty_hints {
                for raw_hint in domain_hints {
                    let Some(hint_norm) = normalize_domain_hint(raw_hint) else {
                        continue;
                    };
                    let is_domain_hint =
                        !hint_norm.contains('/') && parse_literal_target_ip(&hint_norm).is_none();
                    let matches_migrated_query = !new_canon.contains(&ip)
                        && same_family
                        && is_domain_hint
                        && (hint_norm == norm_query
                            || (hint_norm.contains('*')
                                && matches_network_target(&hint_norm, ip, Some(&norm_query))));
                    let is_superseded = norm_superseded.contains(&(ip, hint_norm.clone()));
                    if !matches_migrated_query && !is_superseded {
                        merge_domain_hint(&mut next_hints, &hint_norm);
                    }
                }
            }

            // 2. Synchronize currently active blocking domains so filter metadata tracks live
            //    blocking reasons even if the original domain later evicts from DNS history FIFO.
            if let Some(active_doms) = active_by_ip_canon.get(&ip) {
                for dom in active_doms {
                    merge_domain_hint(&mut next_hints, dom);
                }
            }

            // 3. Keep the filter if the IP is statically blocked, has any active blocking domain,
            //    originally had no domain hints (CIDR/untagged), or retains at least one
            //    non-migrated, non-superseded domain hint. Do NOT keep solely on
            //    `new_canon.contains(&ip)` because a non-blocked query resolving to an IP whose
            //    previous blocking hints are all superseded must remove the stale block rather
            //    than corrupting its origin to an untagged `domain_hints: []` block.
            let keep = static_blocked_canon.contains(&ip)
                || active_by_ip_canon.contains_key(&ip)
                || !had_non_empty_hints
                || !next_hints.is_empty();

            if keep {
                if &next_hints != domain_hints {
                    updated_hints.push((k.clone(), next_hints));
                }
            } else {
                stale_keys.push(k.clone());
            }
        }

        for (key, next_hints) in updated_hints {
            if let Some(entry) = self.installed.get_mut(&key) {
                entry.origin = WfpFilterOrigin::DomainPolicy {
                    domain_hints: next_hints,
                };
            }
        }

        let mut removed = 0usize;
        for key in stale_keys {
            if let Some(entry) = self.installed.get(&key).cloned() {
                match defense.remove_wfp_rule(entry.handle) {
                    Ok(()) => {
                        self.installed.remove(&key);
                        self.bound_alerts.retain(|_, k| k != &key);
                        removed += 1;
                    }
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %entry.exe_path,
                            remote_ip = ?key.1,
                            wfp_handle = entry.handle,
                            error = %err,
                            "failed removing stale DomainPolicy WFP block filter after domain IP migration"
                        );
                    }
                }
            }
        }
        removed
    }

    pub fn domain_policy_blocks(&self, exe_path: &str) -> Vec<(IpAddr, Vec<String>)> {
        let exe_k = Self::exe_key(exe_path);
        let mut out: Vec<(IpAddr, Vec<String>)> = self
            .installed
            .iter()
            .filter_map(|(k, entry)| {
                if k.0 != exe_k || entry.allow {
                    return None;
                }
                let ip = k.1?;
                let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin else {
                    return None;
                };
                Some((ip, domain_hints.clone()))
            })
            .collect();
        out.sort_by_key(|a| a.0.to_string());
        out
    }

    pub fn domain_policy_block_ips(&self, exe_path: &str) -> Vec<IpAddr> {
        let mut out: Vec<IpAddr> = self
            .domain_policy_blocks(exe_path)
            .into_iter()
            .map(|(ip, _)| ip)
            .collect();
        out.dedup();
        out
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

    fn build_desired_persisted_plan(
        &self,
        rules: &[AllowlistRuleRecord],
        active_concrete_exes: &[String],
        inspector: &dyn BinaryInspector,
        identity_cache: &mut HashMap<String, BinaryIdentity>,
    ) -> DesiredPersistedPlan {
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

        let mut desired: HashMap<WfpTargetKey, (String, bool)> = HashMap::new();
        let mut desired_sources: HashMap<WfpTargetKey, Vec<String>> = HashMap::new();
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
                identity_cache
                    .entry(exe_k.clone())
                    .or_insert_with(|| inspector.inspect(&exe_path))
                    .clone()
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
            // Also associate any matching literal-IP NetworkBlock rules for this executable so if
            // the app-wide block fails to install in WFP, saving a destination-specific block
            // never silently reports success while the app remains unblocked (`SEC_..._0001`).
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
                let mut combined_block_ids = app_block_ids;
                for rule in &matching_rules {
                    if rule.scope != RuleScope::NetworkBlock {
                        continue;
                    }
                    if let Some(ip) = rule
                        .allowed_target
                        .as_deref()
                        .and_then(parse_literal_target_ip)
                    {
                        if matches_network_block_rule(rule, &identity, ip, None)
                            && !combined_block_ids.contains(&rule.rule_id)
                        {
                            combined_block_ids.push(rule.rule_id.clone());
                        }
                    }
                }
                let target_key = (exe_k, None);
                desired.insert(target_key.clone(), (exe_path, false));
                desired_sources
                    .entry(target_key)
                    .or_default()
                    .extend(combined_block_ids);
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

        DesiredPersistedPlan {
            desired,
            desired_sources,
            skipped_wildcard: wildcard_rules.len(),
            has_wildcard_network_rules: !wildcard_rules.is_empty(),
            has_domain_network_rules: has_domain_rules,
        }
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
        self.reconcile_persisted_rules_with_baseline(
            rules,
            None,
            active_concrete_exes,
            inspector,
            defense,
        )
    }

    /// Like [`WfpRuleManager::reconcile_persisted_rules`], additionally comparing against
    /// `prev_rules` (the pre-mutation rule set) so any filter that newly became required due to a
    /// delete or scope/target narrowing is flagged `newly_required` on WFP failure (`PRRT_..._W1_R`).
    pub fn reconcile_persisted_rules_with_baseline(
        &mut self,
        rules: &[AllowlistRuleRecord],
        prev_rules: Option<&[AllowlistRuleRecord]>,
        active_concrete_exes: &[String],
        inspector: &dyn BinaryInspector,
        defense: &dyn ActiveDefenseController,
    ) -> WfpReconcileReport {
        self.reconcile_persisted_rules_with_dns_context(
            rules,
            prev_rules,
            active_concrete_exes,
            &WfpReconcileDnsContext::default(),
            inspector,
            defense,
        )
    }

    /// Like [`WfpRuleManager::reconcile_persisted_rules_with_baseline`], additionally using live
    /// DNS history (`dns_ctx`) so existing `DomainPolicy` Blocks retain active blocked domains
    /// added after DNS resolution and `DomainPolicy` Permits prune migrated/superseded hints.
    pub fn reconcile_persisted_rules_with_dns_context(
        &mut self,
        rules: &[AllowlistRuleRecord],
        prev_rules: Option<&[AllowlistRuleRecord]>,
        active_concrete_exes: &[String],
        dns_ctx: &WfpReconcileDnsContext,
        inspector: &dyn BinaryInspector,
        defense: &dyn ActiveDefenseController,
    ) -> WfpReconcileReport {
        let mut report = WfpReconcileReport::default();
        let mut identity_cache: HashMap<String, BinaryIdentity> = HashMap::new();

        let prev_plan = prev_rules.map(|prev| {
            self.build_desired_persisted_plan(
                prev,
                active_concrete_exes,
                inspector,
                &mut identity_cache,
            )
        });
        let mut plan = self.build_desired_persisted_plan(
            rules,
            active_concrete_exes,
            inspector,
            &mut identity_cache,
        );
        self.has_wildcard_network_rules = plan.has_wildcard_network_rules;
        self.has_domain_network_rules = plan.has_domain_network_rules;
        report.skipped_wildcard = plan.skipped_wildcard;

        // 3. Remove obsolete PersistedPolicy / DomainPolicy filters and conflicting
        //    Preemptive/Transient filters; promote matching filters in place without a gap;
        //    demote obsolete app-wide PersistedPolicy Blocks to Preemptive in place for
        //    startup-pinned interpreters so deleting a NetworkBlock leaves zero unprotected gap.
        let mut keys_to_remove: Vec<WfpTargetKey> = Vec::new();
        let mut removal_sources: HashMap<WfpTargetKey, Vec<String>> = HashMap::new();
        let mut removal_hints: HashMap<WfpTargetKey, Vec<String>> = HashMap::new();
        let mut keys_to_promote: Vec<WfpTargetKey> = Vec::new();
        let mut keys_to_demote_preemptive: Vec<WfpTargetKey> = Vec::new();
        let mut domain_hint_updates: Vec<(WfpTargetKey, Vec<String>)> = Vec::new();
        for (key, entry) in &self.installed {
            match &entry.origin {
                WfpFilterOrigin::PersistedPolicy => match plan.desired.get(key) {
                    Some((_, desired_allow)) if *desired_allow == entry.allow => {}
                    Some((_, _)) => {
                        let mut combined_srcs = plan
                            .desired_sources
                            .get(key)
                            .cloned()
                            .unwrap_or_default();
                        if let Some(prev) = prev_rules {
                            let identity = identity_cache
                                .entry(key.0.clone())
                                .or_insert_with(|| inspector.inspect(&entry.exe_path));
                            Self::collect_removed_prev_persisted_sources(
                                prev,
                                rules,
                                identity,
                                key.1,
                                entry.allow,
                                &mut combined_srcs,
                            );
                        }
                        if !combined_srcs.is_empty() {
                            removal_sources.insert(key.clone(), combined_srcs);
                        }
                        keys_to_remove.push(key.clone());
                    }
                    None if key.1.is_none()
                        && !entry.allow
                        && self.startup_preemptive_exes.contains_key(&key.0)
                        && !self.has_once_allowed_for_exe(&key.0) =>
                    {
                        keys_to_demote_preemptive.push(key.clone());
                    }
                    None => {
                        if let Some(prev) = prev_plan.as_ref() {
                            if let Some(srcs) = prev.desired_sources.get(key) {
                                removal_sources.insert(key.clone(), srcs.clone());
                            }
                        }
                        keys_to_remove.push(key.clone());
                    }
                },
                WfpFilterOrigin::DomainPolicy { domain_hints } => {
                    if let Some((_, desired_allow)) = plan.desired.get(key) {
                        if *desired_allow == entry.allow {
                            keys_to_promote.push(key.clone());
                        } else {
                            let mut combined_srcs = plan
                                .desired_sources
                                .get(key)
                                .cloned()
                                .unwrap_or_default();
                            if let (Some(prev), Some(ip)) = (prev_rules, key.1) {
                                let identity = identity_cache
                                    .entry(key.0.clone())
                                    .or_insert_with(|| inspector.inspect(&entry.exe_path));
                                Self::collect_removed_prev_domain_sources(
                                    prev,
                                    rules,
                                    identity,
                                    ip,
                                    domain_hints,
                                    entry.allow,
                                    &mut combined_srcs,
                                );
                            }
                            if !combined_srcs.is_empty() {
                                removal_sources.insert(key.clone(), combined_srcs);
                            }
                            if !domain_hints.is_empty() {
                                removal_hints.insert(key.clone(), domain_hints.clone());
                            }
                            keys_to_remove.push(key.clone());
                        }
                        continue;
                    }
                    let app_wide_blocked = plan
                        .desired
                        .get(&(key.0.clone(), None))
                        .is_some_and(|(_, allow)| !*allow);
                    if entry.allow && app_wide_blocked {
                        let mut combined_srcs = plan
                            .desired_sources
                            .get(&(key.0.clone(), None))
                            .cloned()
                            .unwrap_or_default();
                        if let (Some(prev), Some(ip)) = (prev_rules, key.1) {
                            let identity = identity_cache
                                .entry(key.0.clone())
                                .or_insert_with(|| inspector.inspect(&entry.exe_path));
                            Self::collect_removed_prev_domain_sources(
                                prev,
                                rules,
                                identity,
                                ip,
                                domain_hints,
                                true,
                                &mut combined_srcs,
                            );
                        }
                        if !combined_srcs.is_empty() {
                            removal_sources.insert(key.clone(), combined_srcs);
                        }
                        if !domain_hints.is_empty() {
                            removal_hints.insert(key.clone(), domain_hints.clone());
                        }
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
                    if !entry.allow {
                        // DomainPolicy Block: retain hints backed by a domain-specific
                        // `NetworkBlock` rule (including active live DNS-history domains for this
                        // `(exe_key, ip)` so post-DNS block rules survive deletion of co-blocking
                        // CIDR/domain rules), or keep untagged when statically blocked; remove
                        // only when neither static block nor any blocked hint remains (`#4`).
                        let static_blocked = matches!(
                            evaluate_outbound_policy(identity, ip, None, rules),
                            OutboundDecision::BlockedByRule { .. }
                        );
                        let mut surviving_hints: Vec<String> = Vec::with_capacity(domain_hints.len());
                        for hint in domain_hints {
                            let hint_opt = (!hint.is_empty()).then_some(hint.as_str());
                            let hint_still_blocked = if static_blocked {
                                matches!(
                                    evaluate_outbound_policy(identity, ip, hint_opt, rules),
                                    OutboundDecision::BlockedByRule { .. }
                                ) && rules.iter().any(|r| {
                                    matches_network_block_rule(r, identity, ip, hint_opt)
                                        && !matches_network_block_rule(r, identity, ip, None)
                                })
                            } else {
                                matches!(
                                    evaluate_outbound_policy(identity, ip, hint_opt, rules),
                                    OutboundDecision::BlockedByRule { .. }
                                )
                            };
                            if hint_still_blocked {
                                merge_domain_hint(&mut surviving_hints, hint);
                            }
                        }
                        if let Some(live_doms) = dns_ctx.active_block_domains.get(&(key.0.clone(), ip))
                        {
                            for dom in live_doms {
                                let Some(norm_dom) = normalize_domain_hint(dom) else {
                                    continue;
                                };
                                let domain_specifically_blocked = matches!(
                                    evaluate_outbound_policy(
                                        identity,
                                        ip,
                                        Some(norm_dom.as_str()),
                                        rules,
                                    ),
                                    OutboundDecision::BlockedByRule { .. }
                                ) && rules.iter().any(|r| {
                                    matches_network_block_rule(
                                        r,
                                        identity,
                                        ip,
                                        Some(norm_dom.as_str()),
                                    ) && !matches_network_block_rule(r, identity, ip, None)
                                });
                                if domain_specifically_blocked {
                                    merge_domain_hint(&mut surviving_hints, &norm_dom);
                                }
                            }
                        }
                        if surviving_hints.is_empty() && !static_blocked {
                            let mut combined_srcs: Vec<String> = Vec::new();
                            if let Some(prev) = prev_rules {
                                Self::collect_removed_prev_domain_sources(
                                    prev,
                                    rules,
                                    identity,
                                    ip,
                                    domain_hints,
                                    false,
                                    &mut combined_srcs,
                                );
                            }
                            if !combined_srcs.is_empty() {
                                removal_sources.insert(key.clone(), combined_srcs);
                            }
                            if !domain_hints.is_empty() {
                                removal_hints.insert(key.clone(), domain_hints.clone());
                            }
                            keys_to_remove.push(key.clone());
                        } else if &surviving_hints != domain_hints {
                            domain_hint_updates.push((key.clone(), surviving_hints));
                        }
                    } else if domain_hints.is_empty() {
                        let decision = evaluate_outbound_policy(identity, ip, None, rules);
                        if !matches!(decision, OutboundDecision::AllowedByRule { .. }) {
                            let mut combined_srcs: Vec<String> = Vec::new();
                            if matches!(decision, OutboundDecision::BlockedByRule { .. }) {
                                for r in rules {
                                    if r.scope == RuleScope::NetworkBlock
                                        && matches_network_block_rule(r, identity, ip, None)
                                        && !combined_srcs.contains(&r.rule_id)
                                    {
                                        combined_srcs.push(r.rule_id.clone());
                                    }
                                }
                            }
                            if let Some(prev) = prev_rules {
                                Self::collect_removed_prev_domain_sources(
                                    prev,
                                    rules,
                                    identity,
                                    ip,
                                    domain_hints,
                                    true,
                                    &mut combined_srcs,
                                );
                            }
                            if !combined_srcs.is_empty() {
                                removal_sources.insert(key.clone(), combined_srcs);
                            }
                            keys_to_remove.push(key.clone());
                        }
                    } else {
                        // DomainPolicy Permit: prune hints superseded in DNS history using the
                        // shared `compute_pruned_permit_hints` helper so DNS-time pruning and
                        // reconciliation stay strictly aligned (`PRRT_kwDOVyjVyM65e5kL`).
                        // Then if ANY remaining hint matches `BlockedByRule`, deny-overrides-allow
                        // revokes the Permit immediately; otherwise keep while at least one hint
                        // (or static allow when pruned to empty) stays `AllowedByRule`.
                        let static_allowed = matches!(
                            evaluate_outbound_policy(identity, ip, None, rules),
                            OutboundDecision::AllowedByRule { .. }
                        );
                        let effective_hints = compute_pruned_permit_hints(
                            domain_hints,
                            identity,
                            ip,
                            rules,
                            static_allowed,
                            |norm| {
                                dns_ctx.superseded_permit_hints.contains(&(
                                    key.0.clone(),
                                    ip,
                                    norm.to_string(),
                                ))
                            },
                        );

                        if effective_hints.is_empty() {
                            // Reachable only when `static_allowed == true` (so `None` is
                            // `AllowedByRule` and not `BlockedByRule`); prune stale hints to `[]`.
                            if &effective_hints != domain_hints {
                                domain_hint_updates.push((key.clone(), effective_hints));
                            }
                        } else {
                            let mut block_srcs: Vec<String> = Vec::new();
                            let mut blocked_hints: Vec<String> = Vec::new();
                            let mut any_allowed = false;
                            for hint in &effective_hints {
                                let hint_opt = (!hint.is_empty()).then_some(hint.as_str());
                                match evaluate_outbound_policy(identity, ip, hint_opt, rules) {
                                    OutboundDecision::BlockedByRule { .. } => {
                                        blocked_hints.push(hint.clone());
                                        for r in rules {
                                            if r.scope == RuleScope::NetworkBlock
                                                && matches_network_block_rule(
                                                    r, identity, ip, hint_opt,
                                                )
                                                && !block_srcs.contains(&r.rule_id)
                                            {
                                                block_srcs.push(r.rule_id.clone());
                                            }
                                        }
                                    }
                                    OutboundDecision::AllowedByRule { .. } => {
                                        any_allowed = true;
                                    }
                                    _ => {}
                                }
                            }
                            if !blocked_hints.is_empty() || !block_srcs.is_empty() || !any_allowed {
                                let mut combined_srcs = block_srcs;
                                if let Some(prev) = prev_rules {
                                    Self::collect_removed_prev_domain_sources(
                                        prev,
                                        rules,
                                        identity,
                                        ip,
                                        domain_hints,
                                        true,
                                        &mut combined_srcs,
                                    );
                                }
                                if !combined_srcs.is_empty() {
                                    removal_sources.insert(key.clone(), combined_srcs);
                                }
                                let hints_for_op = if !blocked_hints.is_empty() {
                                    blocked_hints
                                } else {
                                    domain_hints.clone()
                                };
                                removal_hints.insert(key.clone(), hints_for_op);
                                keys_to_remove.push(key.clone());
                            } else if &effective_hints != domain_hints {
                                domain_hint_updates.push((key.clone(), effective_hints));
                            }
                        }
                    }
                }
                WfpFilterOrigin::Preemptive | WfpFilterOrigin::TransientContainment => {
                    if let Some((_, desired_allow)) = plan.desired.get(key) {
                        if *desired_allow == entry.allow {
                            keys_to_promote.push(key.clone());
                        } else {
                            if let Some(srcs) = plan.desired_sources.get(key) {
                                removal_sources.insert(key.clone(), srcs.clone());
                            }
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
                        if let WfpFilterOrigin::DomainPolicy { domain_hints } = &entry.origin {
                            if let Some(remote_ip) = key.1 {
                                report.removed_domain_filters.push(RemovedDomainFilterSnapshot {
                                    exe_path: entry.exe_path.clone(),
                                    remote_ip,
                                    allow: entry.allow,
                                    domain_hints: domain_hints.clone(),
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
                        let source_rule_ids = removal_sources.remove(&key).unwrap_or_default();
                        let domain_hints = removal_hints.remove(&key).unwrap_or_default();
                        failed_exe_keys.insert(key.0.clone());
                        report.failed += 1;
                        report.failed_ops.push(WfpFailedOp {
                            exe_key: key.0,
                            remote_ip: key.1,
                            is_remove: true,
                            is_startup_preemptive: false,
                            newly_required: false,
                            source_rule_ids,
                            domain_hints,
                            error: err,
                        });
                    }
                }
            }
        }

        // 4. Add missing desired PersistedPolicy filters (Block before Permit for fail-closed order).
        let mut desired_sorted: Vec<(WfpTargetKey, String, bool)> = plan
            .desired
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
                    let newly_required = prev_plan.as_ref().is_some_and(|prev| {
                        prev.desired
                            .get(&key)
                            .is_none_or(|(_, prev_allow)| *prev_allow != allow)
                    });
                    let source_rule_ids = plan.desired_sources.remove(&key).unwrap_or_default();
                    failed_exe_keys.insert(key.0.clone());
                    report.failed += 1;
                    report.failed_ops.push(WfpFailedOp {
                        exe_key: key.0,
                        remote_ip: key.1,
                        is_remove: false,
                        is_startup_preemptive: false,
                        newly_required,
                        source_rule_ids,
                        domain_hints: Vec::new(),
                        error: err,
                    });
                }
            }
        }

        // 4b. Promote/demote matching existing filters and prune surviving `DomainPolicy` Block
        //     hints ONLY AFTER remove & add succeed for `exe_k`, capturing snapshots so any
        //     subsequent rollback restores pre-reconcile origins & bindings faithfully.
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

        for (key, surviving_hints) in domain_hint_updates {
            if failed_exe_keys.contains(&key.0) {
                continue;
            }
            if let Some(entry) = self.installed.get_mut(&key) {
                report.promoted_backups.push(PromotedFilterSnapshot {
                    key: key.clone(),
                    prev_origin: entry.origin.clone(),
                    bound_alert_ids: Vec::new(),
                });
                entry.origin = WfpFilterOrigin::DomainPolicy {
                    domain_hints: surviving_hints,
                };
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
                        newly_required: false,
                        source_rule_ids: Vec::new(),
                        domain_hints: Vec::new(),
                        error: err,
                    });
                }
            }
        }

        report
    }

    fn collect_removed_prev_persisted_sources(
        prev_rules: &[AllowlistRuleRecord],
        rules: &[AllowlistRuleRecord],
        identity: &BinaryIdentity,
        remote_ip: Option<IpAddr>,
        allow: bool,
        out: &mut Vec<String>,
    ) {
        let matches = |r: &AllowlistRuleRecord| match (remote_ip, allow) {
            (Some(ip), true) => matches_network_allow_rule(r, identity, ip, None),
            (Some(ip), false) => matches_network_block_rule(r, identity, ip, None),
            (None, true) => matches_app_wide_network_allow(r, identity),
            (None, false) => matches_app_wide_network_block(r, identity),
        };
        for r in prev_rules {
            if !matches(r) {
                continue;
            }
            let still_matched = rules
                .iter()
                .any(|cur| cur.rule_id == r.rule_id && matches(cur));
            if !still_matched && !out.contains(&r.rule_id) {
                out.push(r.rule_id.clone());
            }
        }
    }

    fn collect_removed_prev_domain_sources(
        prev_rules: &[AllowlistRuleRecord],
        rules: &[AllowlistRuleRecord],
        identity: &BinaryIdentity,
        ip: IpAddr,
        domain_hints: &[String],
        allow: bool,
        out: &mut Vec<String>,
    ) {
        let matches = |r: &AllowlistRuleRecord| {
            let static_hit = if allow {
                matches_network_allow_rule(r, identity, ip, None)
            } else {
                matches_network_block_rule(r, identity, ip, None)
            };
            static_hit
                || domain_hints.iter().any(|hint| {
                    let hint_opt = (!hint.is_empty()).then_some(hint.as_str());
                    if allow {
                        matches_network_allow_rule(r, identity, ip, hint_opt)
                    } else {
                        matches_network_block_rule(r, identity, ip, hint_opt)
                    }
                })
        };
        for r in prev_rules {
            if !matches(r) {
                continue;
            }
            let still_matched = rules
                .iter()
                .any(|cur| cur.rule_id == r.rule_id && matches(cur));
            if !still_matched && !out.contains(&r.rule_id) {
                out.push(r.rule_id.clone());
            }
        }
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
                                domain_hints: snap.domain_hints.clone(),
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
                domain_hints: vec!["bad.example".to_string()]
            })
        );
    }

    /// `FIREWALL-P3-47A` (`#4`, `#1`): Shared-IP `DomainPolicy` filters retain a bounded,
    /// normalized set of domain hints across reuse, prune migrated domains and sync active
    /// blocking reasons on migration so final migration removes the block even after earlier
    /// domains were evicted from DNS history FIFO, preserve dual-stack IPv6 blocks, enforce
    /// multi-domain Permit deny-overrides-allow reconciliation, and restore multi-domain
    /// `RemovedDomainFilterSnapshot` faithfully.
    #[test]
    fn firewall_p3_47a_domain_policy_hint_set_migration_cleanup_and_rollback_fidelity() {
        use std::net::Ipv6Addr;

        let mut fw = WfpRuleManager::new();
        let defense = StubDefense::new();
        let inspector = StubInspector("d".repeat(64));

        let app = r"C:\Tools\shared_blk_app.exe";
        let shared_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));
        let new_a_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let new_b_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let v6_a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x88));

        // 1. Reusing a shared-IP DomainPolicy Block merges distinct normalized hints without
        //    creating duplicate BFE handles or duplicate hint entries.
        let h1 = fw
            .ensure_domain_policy_block(app, shared_v4, "A.Example.", &defense)
            .expect("block a.example");
        let h2 = fw
            .ensure_domain_policy_block(app, shared_v4, "b.example", &defense)
            .expect("block b.example");
        let h3 = fw
            .ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
            .expect("dedup a.example");
        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
        assert_eq!(
            fw.filter_origin(app, Some(shared_v4)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["a.example".to_string(), "b.example".to_string()],
            })
        );

        // Dual-stack IPv6 block for `a.example` on a separate address family.
        fw.ensure_domain_policy_block(app, v6_a, "a.example", &defense)
            .expect("block a.example v6");

        // 2. `a.example` migrates off `shared_v4` while `b.example` still actively blocks it:
        //    `shared_v4` stays blocked with `domain_hints` synced to `["b.example"]`, and `v6_a`
        //    stays completely intact.
        let mut active_blocking: HashMap<IpAddr, Vec<String>> = HashMap::new();
        active_blocking.insert(shared_v4, vec!["b.example".to_string()]);
        let mut superseded: HashSet<(IpAddr, String)> = HashSet::new();
        superseded.insert((shared_v4, "a.example".to_string()));
        let removed_step1 = fw.invalidate_stale_domain_blocks_for_query(
            app,
            "a.example",
            &[new_a_v4],
            &HashSet::new(),
            &active_blocking,
            &superseded,
            &defense,
        );
        assert_eq!(removed_step1, 0);
        assert!(fw.has_active_filter(app, Some(shared_v4), false));
        assert_eq!(
            fw.filter_origin(app, Some(shared_v4)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["b.example".to_string()],
            })
        );
        assert_eq!(
            fw.filter_origin(app, Some(v6_a)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["a.example".to_string()],
            }),
            "IPv4 migration must not disturb IPv6 DomainPolicy Block"
        );

        // 3. Even after `a.example` is evicted from `latest_domain_by_exe` FIFO (so
        //    `superseded_pairs` is completely empty!), migrating `b.example` off `shared_v4`
        //    deterministically removes the retired `shared_v4` block while keeping `v6_a`.
        let removed_step2 = fw.invalidate_stale_domain_blocks_for_query(
            app,
            "b.example",
            &[new_b_v4],
            &HashSet::new(),
            &HashMap::new(),
            &HashSet::new(),
            &defense,
        );
        assert_eq!(removed_step2, 1);
        assert!(
            !fw.has_active_filter(app, Some(shared_v4), false),
            "shared_v4 block must be removed once final domain b.example migrates away"
        );
        assert!(
            fw.has_active_filter(app, Some(v6_a), false),
            "IPv6 block for a.example must remain unaffected by IPv4 migrations"
        );

        // 4. Even if `b.example` was NOT originally recorded on the filter before `a.example`
        //    migrated, syncing `active_blocking_domains_by_ip` during `a.example`'s migration
        //    transitions `domain_hints` to `["b.example"]` so `b.example`'s later migration still
        //    clears the filter with empty `superseded_pairs`.
        fw.ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
            .expect("re-block a.example only");
        assert_eq!(
            fw.invalidate_stale_domain_blocks_for_query(
                app,
                "a.example",
                &[new_a_v4],
                &HashSet::new(),
                &active_blocking,
                &HashSet::new(),
                &defense,
            ),
            0
        );
        assert_eq!(
            fw.filter_origin(app, Some(shared_v4)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["b.example".to_string()],
            })
        );
        assert_eq!(
            fw.invalidate_stale_domain_blocks_for_query(
                app,
                "b.example",
                &[new_b_v4],
                &HashSet::new(),
                &HashMap::new(),
                &HashSet::new(),
                &defense,
            ),
            1
        );
        assert!(!fw.has_active_filter(app, Some(shared_v4), false));

        // 5. Hint set is strictly bounded by `MAX_DOMAIN_HINTS_PER_FILTER` (32).
        let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        for idx in 0..(MAX_DOMAIN_HINTS_PER_FILTER + 8) {
            fw.ensure_domain_policy_block(app, cap_ip, &format!("d{idx}.example"), &defense)
                .expect("bounded hint merge");
        }
        let Some(WfpFilterOrigin::DomainPolicy { domain_hints }) =
            fw.filter_origin(app, Some(cap_ip))
        else {
            panic!("expected DomainPolicy origin for cap_ip");
        };
        assert_eq!(domain_hints.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert_eq!(domain_hints.first().map(String::as_str), Some("d8.example"));
        assert_eq!(
            domain_hints.last().map(String::as_str),
            Some("d39.example")
        );

        // 6. Multi-domain Permit accumulation, Block hint pruning, deny-overrides-allow removal,
        //    and `RemovedDomainFilterSnapshot` restore fidelity.
        let perm_app = r"C:\Tools\shared_perm_app.exe";
        let perm_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55));
        let blk_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 56));
        let sha = "d".repeat(64);
        let p_h1 = fw
            .ensure_ip_permit_for_domain_rule(perm_app, perm_ip, "good1.example", &defense)
            .expect("permit good1");
        let p_h2 = fw
            .ensure_ip_permit_for_domain_rule(perm_app, perm_ip, "good2.example", &defense)
            .expect("permit good2");
        assert_eq!(p_h1, p_h2);
        assert_eq!(
            fw.filter_origin(perm_app, Some(perm_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["good1.example".to_string(), "good2.example".to_string()],
            })
        );
        fw.ensure_domain_policy_block(perm_app, blk_ip, "blk1.example", &defense)
            .expect("blk1");
        fw.ensure_domain_policy_block(perm_app, blk_ip, "blk2.example", &defense)
            .expect("blk2");

        let allow_good1 = AllowlistRuleRecord {
            rule_id: "R-ALLOW-1".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good1.example".to_string()),
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        let block_blk2 = AllowlistRuleRecord {
            rule_id: "R-BLK-2".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("blk2.example".to_string()),
            created_at_ms: 2,
            created_by: "test".to_string(),
        };
        // Reconcile with only `good1` allowed and only `blk2` blocked:
        // - Permit stays alive because `good1` is still allowed and neither is blocked.
        // - Block stays alive and prunes `blk1.example`, retaining only `["blk2.example"]`
        //   (with rollback backup capturing `["blk1.example", "blk2.example"]`).
        let rep_keep = fw.reconcile_persisted_rules(
            &[allow_good1.clone(), block_blk2.clone()],
            &[],
            &inspector,
            &defense,
        );
        assert!(fw.has_active_filter(perm_app, Some(perm_ip), true));
        assert!(fw.has_active_filter(perm_app, Some(blk_ip), false));
        assert_eq!(
            fw.filter_origin(perm_app, Some(blk_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk2.example".to_string()],
            })
        );
        fw.restore_promoted_filter_states(&rep_keep.promoted_backups);
        assert_eq!(
            fw.filter_origin(perm_app, Some(blk_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk1.example".to_string(), "blk2.example".to_string()],
            }),
            "rollback of reconciled Block hint pruning must restore original hint set"
        );

        // Adding a block for `good2.example` revokes the multi-domain Permit (deny-overrides-allow)
        // and captures all `domain_hints` in `RemovedDomainFilterSnapshot`.
        let block_good2 = AllowlistRuleRecord {
            rule_id: "R-BLK-GOOD2".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some(sha),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good2.example".to_string()),
            created_at_ms: 3,
            created_by: "test".to_string(),
        };
        let rep_revoke = fw.reconcile_persisted_rules(
            &[allow_good1, block_blk2, block_good2],
            &[],
            &inspector,
            &defense,
        );
        assert!(
            !fw.has_active_filter(perm_app, Some(perm_ip), true),
            "blocking any domain in Permit hint set must revoke shared-IP Permit"
        );
        let perm_snap = rep_revoke
            .removed_domain_filters
            .iter()
            .find(|s| s.remote_ip == perm_ip && s.allow)
            .expect("removed Permit snapshot");
        assert_eq!(
            perm_snap.domain_hints,
            vec!["good1.example".to_string(), "good2.example".to_string()]
        );

        // Restoring the snapshot reproduces the exact multi-domain hint vector.
        fw.restore_removed_domain_filters(std::slice::from_ref(perm_snap), &defense);
        assert_eq!(
            fw.filter_origin(perm_app, Some(perm_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["good1.example".to_string(), "good2.example".to_string()],
            })
        );

        // 7. Non-blocked query resolving to an IP whose previous blocking hints are ALL superseded
        //    must REMOVE the stale block filter instead of keeping it on `new_canon.contains(&ip)`
        //    and corrupting `domain_hints` to empty `[]`.
        fw.ensure_domain_policy_block(app, shared_v4, "a.example", &defense)
            .expect("install block for a.example");
        let mut sup_a: HashSet<(IpAddr, String)> = HashSet::new();
        sup_a.insert((shared_v4, "a.example".to_string()));
        let removed_on_allowed_query = fw.invalidate_stale_domain_blocks_for_query(
            app,
            "allowed.example",
            &[shared_v4],
            &HashSet::new(),
            &HashMap::new(),
            &sup_a,
            &defense,
        );
        assert_eq!(
            removed_on_allowed_query, 1,
            "non-blocked query resolving to IP with superseded block must remove stale block"
        );
        assert!(!fw.has_active_filter(app, Some(shared_v4), false));

        // 8. Hybrid CIDR + domain Block reconciliation: deleting the domain block while the CIDR
        //    block stays active prunes the deleted domain hint to `[]` while keeping the filter
        //    alive, and rollback restores the pre-prune hint set.
        let cidr_block = AllowlistRuleRecord {
            rule_id: "R-BLK-CIDR".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.0/24".to_string()),
            created_at_ms: 4,
            created_by: "test".to_string(),
        };
        let rep_cidr_only = fw.reconcile_persisted_rules(
            std::slice::from_ref(&cidr_block),
            &[],
            &inspector,
            &defense,
        );
        assert!(fw.has_active_filter(perm_app, Some(blk_ip), false));
        assert_eq!(
            fw.filter_origin(perm_app, Some(blk_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: Vec::new(),
            }),
            "deleting domain block while CIDR block stays must prune deleted domain hints to empty"
        );
        fw.restore_promoted_filter_states(&rep_cidr_only.promoted_backups);
        assert_eq!(
            fw.filter_origin(perm_app, Some(blk_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk2.example".to_string()],
            })
        );

        // 9. Baseline (`prev_rules`) attribution on failed DomainPolicy removal: deleting `R-ALLOW-1`
        //    while `remove_wfp_rule` fails records `R-ALLOW-1` in `source_rule_ids` so it matches
        //    the deleted allow rule and does NOT match an unrelated rule on the same executable.
        fw.restore_removed_domain_filters(std::slice::from_ref(perm_snap), &defense);
        let prev_allow_good1 = AllowlistRuleRecord {
            rule_id: "R-ALLOW-1".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good1.example".to_string()),
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        let unrelated_rule = AllowlistRuleRecord {
            rule_id: "R-UNRELATED".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: perm_app.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("unrelated.example".to_string()),
            created_at_ms: 5,
            created_by: "test".to_string(),
        };
        *defense.fail_removes.lock().expect("lock fail_removes") = true;
        let rep_del_fail = fw.reconcile_persisted_rules_with_baseline(
            &[cidr_block],
            Some(std::slice::from_ref(&prev_allow_good1)),
            &[],
            &inspector,
            &defense,
        );
        *defense.fail_removes.lock().expect("lock fail_removes") = false;
        assert!(
            rep_del_fail
                .failure_summary_for_rules(&[&prev_allow_good1])
                .is_some(),
            "failed DomainPolicy Permit removal must stay attributed to deleted R-ALLOW-1"
        );
        assert!(
            rep_del_fail
                .failure_summary_for_rules(&[&unrelated_rule])
                .is_none(),
            "failed DomainPolicy Permit removal must not block unrelated rules on same exe"
        );

        // 10. `ensure_domain_policy_block_hints` supports empty untagged slices (CIDR-only blocks),
        //     multi-hint normalization/dedup merging on reuse, and conflicting Permit replacement.
        let hints_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 90));
        let h_empty = fw
            .ensure_domain_policy_block_hints(perm_app, hints_ip, &[] as &[&str], &defense)
            .expect("install untagged CIDR DomainPolicy block");
        assert_eq!(
            fw.filter_origin(perm_app, Some(hints_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: Vec::new(),
            })
        );
        let h_merged = fw
            .ensure_domain_policy_block_hints(
                perm_app,
                hints_ip,
                &["Blk1.Example.", "blk2.example", "blk1.example", ""],
                &defense,
            )
            .expect("merge multi-domain hints onto existing block");
        assert_eq!(h_empty, h_merged);
        assert_eq!(
            fw.filter_origin(perm_app, Some(hints_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk1.example".to_string(), "blk2.example".to_string()],
            })
        );
        let replace_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 91));
        fw.ensure_ip_permit_for_domain_rule(perm_app, replace_ip, "ok.example", &defense)
            .expect("install permit before block override");
        fw.ensure_domain_policy_block_hints(perm_app, replace_ip, &[] as &[&str], &defense)
            .expect("replace permit with untagged CIDR block");
        assert!(fw.has_active_filter(perm_app, Some(replace_ip), false));
        assert!(!fw.has_active_filter(perm_app, Some(replace_ip), true));
        assert_eq!(
            fw.filter_origin(perm_app, Some(replace_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: Vec::new(),
            })
        );

        // 11. `reconcile_persisted_rules_with_dns_context` synchronizes live DNS-history domains
        //     into existing `DomainPolicy` Blocks so deleting a co-blocking CIDR or first domain
        //     rule keeps the block alive for a post-DNS domain block rule, and rollback restores
        //     pre-sync `domain_hints`.
        let mut fw_sync = WfpRuleManager::new();
        let sync_exe = r"C:\Tools\sync_dns_ctx.exe";
        let sync_exe_k = WfpRuleManager::exe_key(sync_exe);
        let sync_ip_cidr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 120));
        let sync_ip_dom = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 121));
        fw_sync
            .ensure_domain_policy_block_hints(sync_exe, sync_ip_cidr, &[] as &[&str], &defense)
            .expect("untagged CIDR block");
        fw_sync
            .ensure_domain_policy_block(sync_exe, sync_ip_dom, "blk-old.example", &defense)
            .expect("old domain block");
        let blk_new_rule = AllowlistRuleRecord {
            rule_id: "R-BLK-NEW".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: sync_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("blk-new.example".to_string()),
            created_at_ms: 10,
            created_by: "test".to_string(),
        };
        let mut dns_ctx_sync = WfpReconcileDnsContext::default();
        dns_ctx_sync
            .active_block_domains
            .insert((sync_exe_k.clone(), sync_ip_cidr), vec!["blk-new.example".to_string()]);
        dns_ctx_sync
            .active_block_domains
            .insert((sync_exe_k.clone(), sync_ip_dom), vec!["blk-new.example".to_string()]);
        let rep_sync = fw_sync.reconcile_persisted_rules_with_dns_context(
            std::slice::from_ref(&blk_new_rule),
            None,
            &[],
            &dns_ctx_sync,
            &inspector,
            &defense,
        );
        assert_eq!(
            fw_sync.filter_origin(sync_exe, Some(sync_ip_cidr)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk-new.example".to_string()],
            }),
            "existing untagged CIDR Block must survive via active DNS-history domain block"
        );
        assert_eq!(
            fw_sync.filter_origin(sync_exe, Some(sync_ip_dom)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk-new.example".to_string()],
            }),
            "existing domain Block must transition to surviving active DNS-history domain block"
        );
        fw_sync.restore_promoted_filter_states(&rep_sync.promoted_backups);
        assert_eq!(
            fw_sync.filter_origin(sync_exe, Some(sync_ip_cidr)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: Vec::new(),
            })
        );
        assert_eq!(
            fw_sync.filter_origin(sync_exe, Some(sync_ip_dom)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["blk-old.example".to_string()],
            })
        );

        // 12. Migrated/superseded Permit hint pruning (`prune_migrated_domain_permit_hints_for_query`
        //     and `WfpReconcileDnsContext::superseded_permit_hints`):
        //     - Multi-domain Permit prunes migrated domain while keeping remaining domain intact.
        //     - Single-domain non-static Permit is NOT corrupted to empty `[]`.
        //     - CIDR Permit with superseded hint prunes to `[]` and survives when that domain is blocked.
        let mut fw_perm = WfpRuleManager::new();
        let perm_mig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 140));
        let solo_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 141));
        let cidr_mig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 142));
        let migrated_dest = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 199));
        fw_perm
            .ensure_ip_permit_for_domain_hints(
                sync_exe,
                perm_mig_ip,
                &["keep.example", "moved.example"],
                &defense,
            )
            .expect("multi-domain permit");
        fw_perm
            .ensure_ip_permit_for_domain_rule(sync_exe, solo_ip, "solo.example", &defense)
            .expect("single-domain permit");
        fw_perm
            .ensure_ip_permit_for_domain_rule(sync_exe, cidr_mig_ip, "cdn-moved.example", &defense)
            .expect("cidr-backed permit");

        let sync_identity = inspector.inspect(sync_exe);
        let allow_keep_mig = AllowlistRuleRecord {
            rule_id: "R-ALLOW-KEEP-MIG".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: sync_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("keep.example".to_string()),
            created_at_ms: 10,
            created_by: "test".to_string(),
        };
        let allow_solo_mig = AllowlistRuleRecord {
            rule_id: "R-ALLOW-SOLO-MIG".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: sync_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("solo.example".to_string()),
            created_at_ms: 10,
            created_by: "test".to_string(),
        };
        let mig_rules = [allow_keep_mig, allow_solo_mig];

        let pruned_multi = fw_perm.prune_migrated_domain_permit_hints_for_query(
            sync_exe,
            "moved.example",
            &[migrated_dest],
            &sync_identity,
            &mig_rules,
            &HashSet::new(),
        );
        assert_eq!(pruned_multi, 1);
        assert_eq!(
            fw_perm.filter_origin(sync_exe, Some(perm_mig_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["keep.example".to_string()],
            })
        );
        let pruned_solo = fw_perm.prune_migrated_domain_permit_hints_for_query(
            sync_exe,
            "solo.example",
            &[migrated_dest],
            &sync_identity,
            &mig_rules,
            &HashSet::new(),
        );
        assert_eq!(
            pruned_solo, 0,
            "single-domain non-static Permit must not be corrupted into untagged []"
        );
        assert_eq!(
            fw_perm.filter_origin(sync_exe, Some(solo_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["solo.example".to_string()],
            })
        );
        let allow_cidr_mig = AllowlistRuleRecord {
            rule_id: "R-ALLOW-CIDR-MIG".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: sync_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.142/32".to_string()),
            created_at_ms: 11,
            created_by: "test".to_string(),
        };
        let blk_cdn_moved = AllowlistRuleRecord {
            rule_id: "R-BLK-CDN-MOVED".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: sync_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("cdn-moved.example".to_string()),
            created_at_ms: 12,
            created_by: "test".to_string(),
        };
        let mut dns_ctx_perm = WfpReconcileDnsContext::default();
        dns_ctx_perm.superseded_permit_hints.insert((
            sync_exe_k.clone(),
            cidr_mig_ip,
            "cdn-moved.example".to_string(),
        ));
        let rep_cidr_survive = fw_perm.reconcile_persisted_rules_with_dns_context(
            &[allow_cidr_mig, blk_cdn_moved],
            None,
            &[],
            &dns_ctx_perm,
            &inspector,
            &defense,
        );
        assert!(
            fw_perm.has_active_filter(sync_exe, Some(cidr_mig_ip), true),
            "CIDR Permit must survive when superseded domain hint is blocked at its new IP"
        );
        assert_eq!(
            fw_perm.filter_origin(sync_exe, Some(cidr_mig_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: Vec::new(),
            })
        );
        fw_perm.restore_promoted_filter_states(&rep_cidr_survive.promoted_backups);
        assert_eq!(
            fw_perm.filter_origin(sync_exe, Some(cidr_mig_ip)),
            Some(&WfpFilterOrigin::DomainPolicy {
                domain_hints: vec!["cdn-moved.example".to_string()],
            })
        );

        // 13. Override-removal `prev_rules` attribution: when an app-wide or literal-IP Block
        //     already overrides a stuck DomainPolicy Permit (or PersistedPolicy Permit) and
        //     `remove_wfp_rule` still fails, deleting the Permit's rule MUST stay attributed to
        //     the deleted allow rule while not blocking unrelated rules on the same executable.
        let mut fw_ov = WfpRuleManager::new();
        let ov_exe = r"C:\Tools\override_attr.exe";
        let ov_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 150));
        let ov_lit_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 151));
        fw_ov
            .ensure_ip_permit_for_domain_rule(ov_exe, ov_ip, "good-ov.example", &defense)
            .expect("install stuck domain permit");
        let r_ov_allow_dom = AllowlistRuleRecord {
            rule_id: "R-OV-ALLOW-DOM".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("good-ov.example".to_string()),
            created_at_ms: 20,
            created_by: "test".to_string(),
        };
        let r_ov_allow_lit = AllowlistRuleRecord {
            rule_id: "R-OV-ALLOW-LIT".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(ov_lit_ip.to_string()),
            created_at_ms: 21,
            created_by: "test".to_string(),
        };
        // Materialize PersistedPolicy Permit for `ov_lit_ip`.
        fw_ov.reconcile_persisted_rules(
            &[r_ov_allow_dom.clone(), r_ov_allow_lit.clone()],
            &[],
            &inspector,
            &defense,
        );
        assert!(fw_ov.has_active_filter(ov_exe, Some(ov_lit_ip), true));
        let r_ov_blk_app = AllowlistRuleRecord {
            rule_id: "R-OV-BLK-APP".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 22,
            created_by: "test".to_string(),
        };
        let r_ov_blk_ip = AllowlistRuleRecord {
            rule_id: "R-OV-BLK-IP".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(ov_ip.to_string()),
            created_at_ms: 23,
            created_by: "test".to_string(),
        };
        let r_ov_blk_lit = AllowlistRuleRecord {
            rule_id: "R-OV-BLK-LIT".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(ov_lit_ip.to_string()),
            created_at_ms: 24,
            created_by: "test".to_string(),
        };
        let r_ov_unrelated = AllowlistRuleRecord {
            rule_id: "R-OV-UNRELATED".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ov_exe.to_string(),
            sha256: Some("d".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("unrelated-ov.example".to_string()),
            created_at_ms: 25,
            created_by: "test".to_string(),
        };

        *defense.fail_removes.lock().expect("lock fail_removes") = true;
        // 13a: App-wide block overrides stuck DomainPolicy Permit while deleting R-OV-ALLOW-DOM.
        let rep_app_ov = fw_ov.reconcile_persisted_rules_with_baseline(
            std::slice::from_ref(&r_ov_blk_app),
            Some(&[r_ov_blk_app.clone(), r_ov_allow_dom.clone()]),
            &[],
            &inspector,
            &defense,
        );
        assert!(
            rep_app_ov
                .failure_summary_for_rules(&[&r_ov_allow_dom])
                .is_some(),
            "deleting R-OV-ALLOW-DOM under app-wide block must surface stuck Permit removal failure"
        );
        assert!(
            rep_app_ov
                .failure_summary_for_rules(&[&r_ov_unrelated])
                .is_none(),
            "unrelated domain rule must remain unblocked"
        );
        // 13b: Literal-IP block overrides stuck DomainPolicy Permit AND PersistedPolicy Permit
        //      while deleting R-OV-ALLOW-DOM and R-OV-ALLOW-LIT.
        let rep_ip_ov = fw_ov.reconcile_persisted_rules_with_baseline(
            &[r_ov_blk_ip.clone(), r_ov_blk_lit.clone()],
            Some(&[
                r_ov_blk_ip,
                r_ov_blk_lit,
                r_ov_allow_dom.clone(),
                r_ov_allow_lit.clone(),
            ]),
            &[],
            &inspector,
            &defense,
        );
        *defense.fail_removes.lock().expect("lock fail_removes") = false;
        assert!(
            rep_ip_ov
                .failure_summary_for_rules(&[&r_ov_allow_dom])
                .is_some(),
            "deleting R-OV-ALLOW-DOM under literal-IP block must surface stuck DomainPolicy Permit failure"
        );
        assert!(
            rep_ip_ov
                .failure_summary_for_rules(&[&r_ov_allow_lit])
                .is_some(),
            "deleting R-OV-ALLOW-LIT under literal-IP block must surface stuck PersistedPolicy Permit failure"
        );
        assert!(
            rep_ip_ov
                .failure_summary_for_rules(&[&r_ov_unrelated])
                .is_none(),
            "unrelated rule must remain unblocked"
        );
    }

    /// `FIREWALL-P3-48A` (`PRRT_kwDOVyjVyM65e5kL` + `AUD-P3-02`):
    /// - Shared IP (`api.example` allowed + `other.example` unallowed) migrating `api.example`
    ///   retains the authorizing hint across DNS-time pruning and unrelated reconciliation;
    /// - Subsequent migration of unallowed `other.example` selectively prunes `other.example`
    ///   while keeping `api.example` (with rollback fidelity);
    /// - Multi-allow shared IP (`keep.example` + `api.example` + `other.example`) prunes the
    ///   migrating `api.example` so blocking `api.example` preserves `keep.example`'s Permit;
    /// - Post-migration blocks (`R-BLK-OTHER` and `R-BLK-API`) and allow-rule deletion
    ///   (`R-ALLOW-API`) revoke the Permit with exact sole rule attribution and rollback fidelity;
    /// - `ensure_ip_permit_for_domain_hints_prioritized` preserves insertion order within 32 hints
    ///   and protects authorizing hints from FIFO eviction on `MAX_DOMAIN_HINTS_PER_FILTER` overflow.
    #[test]
    fn firewall_p3_48a_shared_ip_authorizing_hint_retention_and_prioritized_cap() {
        let defense = StubDefense::new();
        let sha = "e".repeat(64);
        let inspector = StubInspector(sha.clone());
        let exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let exe_k = WfpRuleManager::exe_key(exe);
        let identity = inspector.inspect(exe);
        let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 160));
        let ip1_v6_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 160).to_ipv6_mapped());
        let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 161));
        let ip3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 162));

        let mk_rule = |id: &str, scope: RuleScope, target: &str| AllowlistRuleRecord {
            rule_id: id.to_string(),
            scope,
            exe_path_pattern: exe.to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(target.to_string()),
            created_at_ms: 100,
            created_by: "test".to_string(),
        };

        let r_allow_api = mk_rule("R-ALLOW-API", RuleScope::NetworkAllow, "api.example");
        let r_allow_keep = mk_rule("R-ALLOW-KEEP", RuleScope::NetworkAllow, "keep.example");
        let r_blk_other = mk_rule("R-BLK-OTHER", RuleScope::NetworkBlock, "other.example");
        let r_blk_api = mk_rule("R-BLK-API", RuleScope::NetworkBlock, "api.example");
        let r_unrelated = AllowlistRuleRecord {
            rule_id: "R-UNRELATED".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\other_unrelated.exe".to_string(),
            sha256: Some(sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("unrelated.example".to_string()),
            created_at_ms: 101,
            created_by: "test".to_string(),
        };

        // 1. Shared IP (`api.example` allowed + `other.example` unallowed): `api.example` moves to
        //    `ip2` -> authorizing hint `api.example` MUST be retained across DNS-time pruning and
        //    unrelated rule reconciliation.
        let mut fw = WfpRuleManager::new();
        fw.ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            ip1,
            &["api.example"],
            &["other.example"],
            &defense,
        )
        .expect("install shared-ip permit");
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()])
        );
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1_v6_mapped),
            Some(vec!["api.example".to_string(), "other.example".to_string()]),
            "domain_policy_permit_hints must canonicalize IPv4-mapped IPv6 addresses"
        );
        assert_eq!(fw.domain_policy_permit_hints(exe, ip2), None);

        let mut sup_api_only: HashSet<(IpAddr, String)> = HashSet::new();
        sup_api_only.insert((ip1, "api.example".to_string()));
        let pruned_on_api_move = fw.prune_migrated_domain_permit_hints_for_query(
            exe,
            "api.example",
            &[ip2],
            &identity,
            std::slice::from_ref(&r_allow_api),
            &sup_api_only,
        );
        assert_eq!(
            pruned_on_api_move, 0,
            "migrating the sole authorizing domain while unallowed co-hosted hint remains must keep authorizing hint"
        );
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()])
        );

        let mut dns_ctx_api_sup = WfpReconcileDnsContext::default();
        dns_ctx_api_sup
            .superseded_permit_hints
            .insert((exe_k.clone(), ip1, "api.example".to_string()));
        let rep_unrel = fw.reconcile_persisted_rules_with_dns_context(
            &[r_allow_api.clone(), r_unrelated.clone()],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep_unrel.removed, 0);
        assert!(
            fw.has_active_filter(exe, Some(ip1), true),
            "unrelated rule reconciliation must preserve cached-IP Permit after authorizing domain migration"
        );
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()])
        );

        // 2. Subsequent migration of unallowed `other.example` to `ip3`:
        //    2a. Via `reconcile_persisted_rules_with_dns_context` (selective pruning + rollback).
        let mut dns_ctx_both_sup = WfpReconcileDnsContext::default();
        dns_ctx_both_sup
            .superseded_permit_hints
            .insert((exe_k.clone(), ip1, "api.example".to_string()));
        dns_ctx_both_sup
            .superseded_permit_hints
            .insert((exe_k.clone(), ip1, "other.example".to_string()));
        let rep_other_sup = fw.reconcile_persisted_rules_with_dns_context(
            &[r_allow_api.clone(), r_blk_other.clone()],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_both_sup,
            &inspector,
            &defense,
        );
        assert!(
            fw.has_active_filter(exe, Some(ip1), true),
            "blocking unallowed co-hosted domain after it also migrated must NOT revoke Permit"
        );
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string()]),
            "reconcile must selectively prune retired unallowed co-hosted hint while retaining authorizing hint"
        );
        fw.restore_promoted_filter_states(&rep_other_sup.promoted_backups);
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()]),
            "rollback must faithfully restore pre-reconcile Permit hints"
        );

        //    2b. Via `prune_migrated_domain_permit_hints_for_query` on `other.example -> ip3`.
        let mut sup_both: HashSet<(IpAddr, String)> = HashSet::new();
        sup_both.insert((ip1, "api.example".to_string()));
        sup_both.insert((ip1, "other.example".to_string()));
        let pruned_other = fw.prune_migrated_domain_permit_hints_for_query(
            exe,
            "other.example",
            &[ip3],
            &identity,
            std::slice::from_ref(&r_allow_api),
            &sup_both,
        );
        assert_eq!(pruned_other, 1);
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string()]),
            "DNS-time pruning must selectively drop migrated unallowed other.example while keeping api.example"
        );

        // Re-restore `other.example` onto `ip1` Permit to test post-migration block & delete attribution.
        fw.ensure_ip_permit_for_domain_hints_prioritized(
            exe,
            ip1,
            &["api.example"],
            &["other.example"],
            &defense,
        )
        .expect("re-merge other.example");
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()])
        );

        // 3. Post-migration `R-BLK-OTHER` sole attribution and rollback fidelity.
        *defense.fail_removes.lock().expect("lock fail_removes") = true;
        let rep_blk_other_fail = fw.reconcile_persisted_rules_with_dns_context(
            &[r_allow_api.clone(), r_blk_other.clone()],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep_blk_other_fail.failed_ops.len(), 1);
        assert_eq!(
            rep_blk_other_fail.failed_ops[0].source_rule_ids,
            vec!["R-BLK-OTHER".to_string()],
            "blocking still-cohosted other.example must attribute solely to R-BLK-OTHER"
        );
        assert_eq!(
            rep_blk_other_fail.failed_ops[0].domain_hints,
            vec!["other.example".to_string()]
        );
        assert!(rep_blk_other_fail
            .failure_summary_for_rules(&[&r_blk_other])
            .is_some());
        assert!(rep_blk_other_fail
            .failure_summary_for_rules(&[&r_allow_api])
            .is_none());
        assert!(rep_blk_other_fail
            .failure_summary_for_rules(&[&r_unrelated])
            .is_none());

        // 4. Post-migration `R-BLK-API` sole attribution (even though `api.example` is superseded).
        let rep_blk_api_fail = fw.reconcile_persisted_rules_with_dns_context(
            &[r_allow_api.clone(), r_blk_api.clone()],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep_blk_api_fail.failed_ops.len(), 1);
        assert_eq!(
            rep_blk_api_fail.failed_ops[0].source_rule_ids,
            vec!["R-BLK-API".to_string()],
            "blocking migrated authorizing api.example must attribute solely to R-BLK-API"
        );
        assert_eq!(
            rep_blk_api_fail.failed_ops[0].domain_hints,
            vec!["api.example".to_string()]
        );
        assert!(rep_blk_api_fail
            .failure_summary_for_rules(&[&r_blk_api])
            .is_some());
        assert!(rep_blk_api_fail
            .failure_summary_for_rules(&[&r_allow_api])
            .is_none());
        assert!(rep_blk_api_fail
            .failure_summary_for_rules(&[&r_unrelated])
            .is_none());

        // 5. Post-migration deletion of `R-ALLOW-API` sole attribution + removal rollback fidelity.
        let rep_del_fail = fw.reconcile_persisted_rules_with_dns_context(
            &[],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep_del_fail.failed_ops.len(), 1);
        assert_eq!(
            rep_del_fail.failed_ops[0].source_rule_ids,
            vec!["R-ALLOW-API".to_string()],
            "deleting R-ALLOW-API after migration must attribute solely to R-ALLOW-API"
        );
        assert!(rep_del_fail
            .failure_summary_for_rules(&[&r_allow_api])
            .is_some());
        assert!(rep_del_fail
            .failure_summary_for_rules(&[&r_unrelated])
            .is_none());

        *defense.fail_removes.lock().expect("lock fail_removes") = false;
        let rep_del_ok = fw.reconcile_persisted_rules_with_dns_context(
            &[],
            Some(std::slice::from_ref(&r_allow_api)),
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert!(!fw.has_active_filter(exe, Some(ip1), true));
        assert_eq!(rep_del_ok.removed_domain_filters.len(), 1);
        assert_eq!(
            rep_del_ok.removed_domain_filters[0].domain_hints,
            vec!["api.example".to_string(), "other.example".to_string()]
        );
        fw.restore_removed_domain_filters(&rep_del_ok.removed_domain_filters, &defense);
        assert!(fw.has_active_filter(exe, Some(ip1), true));
        assert_eq!(
            fw.domain_policy_permit_hints(exe, ip1),
            Some(vec!["api.example".to_string(), "other.example".to_string()]),
            "restore_removed_domain_filters must restore exact pre-removal Permit hints"
        );

        // 6. Multiple allowed domains (`keep.example` + `api.example` + `other.example`) sharing
        //    `ip1`: when `api.example` moves to `ip2`, `keep.example` preserves `AllowedByRule`,
        //    so `api.example` IS pruned and later `R-BLK-API` preserves `ip1` Permit.
        let mut fw_multi = WfpRuleManager::new();
        fw_multi
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                ip1,
                &["keep.example", "api.example"],
                &["other.example"],
                &defense,
            )
            .expect("install multi-allow permit");
        let pruned_multi_allow = fw_multi.prune_migrated_domain_permit_hints_for_query(
            exe,
            "api.example",
            &[ip2],
            &identity,
            &[r_allow_keep.clone(), r_allow_api.clone()],
            &sup_api_only,
        );
        assert_eq!(pruned_multi_allow, 1);
        assert_eq!(
            fw_multi.domain_policy_permit_hints(exe, ip1),
            Some(vec!["keep.example".to_string(), "other.example".to_string()])
        );
        let rep_multi_blk_api = fw_multi.reconcile_persisted_rules_with_dns_context(
            &[r_allow_keep, r_allow_api.clone(), r_blk_api],
            None,
            &[],
            &dns_ctx_api_sup,
            &inspector,
            &defense,
        );
        assert_eq!(rep_multi_blk_api.removed, 0);
        assert!(
            fw_multi.has_active_filter(exe, Some(ip1), true),
            "blocking migrated api.example must preserve ip1 Permit when keep.example remains allowed"
        );

        // 7. `MAX_DOMAIN_HINTS_PER_FILTER` (32) overflow protection (`AUD-P3-02`):
        let mut fw_cap = WfpRuleManager::new();
        let cap_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 170));
        let cap_full_auth_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 171));
        let cap_blk_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 172));

        // 7a. Within 32 hints: preserves insertion order.
        fw_cap
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                cap_ip,
                &["api.example"],
                &["c00.example", "c01.example"],
                &defense,
            )
            .expect("install initial prioritized permit");
        assert_eq!(
            fw_cap.domain_policy_permit_hints(exe, cap_ip),
            Some(vec![
                "api.example".to_string(),
                "c00.example".to_string(),
                "c01.example".to_string(),
            ])
        );

        // 7b. Overflow with 40 co-hosted hints: len bounded at 32 and `api.example` is NEVER evicted.
        let many_cohosts: Vec<String> = (0..40).map(|i| format!("c{i:02}.example")).collect();
        fw_cap
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                cap_ip,
                &["api.example"],
                &many_cohosts,
                &defense,
            )
            .expect("merge 40 cohosted hints");
        let hints_after = fw_cap
            .domain_policy_permit_hints(exe, cap_ip)
            .expect("permit hints after overflow");
        assert_eq!(hints_after.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(
            hints_after.iter().any(|h| h == "api.example"),
            "authorizing hint api.example must never be FIFO-evicted by co-hosted hints"
        );
        assert_eq!(hints_after[0], "api.example");
        assert_eq!(hints_after[1], "c09.example");
        assert_eq!(hints_after[MAX_DOMAIN_HINTS_PER_FILTER - 1], "c39.example");

        // Re-merging additional co-hosted hints onto an already-full Permit still retains `api.example`.
        fw_cap
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                cap_ip,
                &["api.example"],
                &["c40.example", "c41.example"],
                &defense,
            )
            .expect("merge extra cohosted hints");
        let hints_after_extra = fw_cap
            .domain_policy_permit_hints(exe, cap_ip)
            .expect("permit hints after extra cohost merge");
        assert_eq!(hints_after_extra.len(), MAX_DOMAIN_HINTS_PER_FILTER);
        assert!(hints_after_extra.iter().any(|h| h == "api.example"));
        assert!(hints_after_extra.iter().any(|h| h == "c41.example"));
        assert!(!hints_after_extra.iter().any(|h| h == "c09.example"));

        // 7c. All 32 slots occupied by authorizing hints: co-hosted hints never evict any of them.
        let all_auth: Vec<String> = (0..MAX_DOMAIN_HINTS_PER_FILTER)
            .map(|i| format!("auth{i:02}.example"))
            .collect();
        fw_cap
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                cap_full_auth_ip,
                &all_auth,
                &["cohost-extra.example"],
                &defense,
            )
            .expect("install 32 authorizing hints");
        let full_auth_hints = fw_cap
            .domain_policy_permit_hints(exe, cap_full_auth_ip)
            .expect("32 auth permit hints");
        assert_eq!(full_auth_hints, all_auth);

        // 7d. Existing IP Block conflict still returns Ok(None) (deny-overrides-allow).
        fw_cap
            .ensure_domain_policy_block(exe, cap_blk_ip, "bad.example", &defense)
            .expect("install block");
        let suppressed = fw_cap
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                cap_blk_ip,
                &["api.example"],
                &["other.example"],
                &defense,
            )
            .expect("conflict returns Ok(None)");
        assert_eq!(suppressed, None);
        assert_eq!(fw_cap.domain_policy_permit_hints(exe, cap_blk_ip), None);

        // 8. Static CIDR `NetworkAllow` overridden by static CIDR `NetworkBlock`: retired
        //    unallowed co-hosted hint `other.example` must NOT be treated as domain-authorized
        //    by the CIDR allow rule, so `R-BLK-OTHER` is never falsely attributed on `ip1`.
        let mut fw_cidr_override = WfpRuleManager::new();
        fw_cidr_override
            .ensure_ip_permit_for_domain_hints_prioritized(
                exe,
                ip1,
                &[] as &[&str],
                &["api.example", "other.example"],
                &defense,
            )
            .expect("install cidr shared-ip permit");
        let r_allow_cidr = mk_rule("R-ALLOW-CIDR", RuleScope::NetworkAllow, "198.51.100.0/24");
        let r_blk_cidr = mk_rule("R-BLK-CIDR", RuleScope::NetworkBlock, "198.51.100.0/24");
        let mut dns_ctx_other_sup = WfpReconcileDnsContext::default();
        dns_ctx_other_sup
            .superseded_permit_hints
            .insert((exe_k.clone(), ip1, "other.example".to_string()));
        *defense.fail_removes.lock().expect("lock fail_removes") = true;
        let rep_cidr_blk_fail = fw_cidr_override.reconcile_persisted_rules_with_dns_context(
            &[r_allow_cidr.clone(), r_blk_cidr.clone(), r_blk_other.clone()],
            Some(&[r_allow_cidr, r_blk_other.clone()]),
            &[],
            &dns_ctx_other_sup,
            &inspector,
            &defense,
        );
        *defense.fail_removes.lock().expect("lock fail_removes") = false;
        assert_eq!(rep_cidr_blk_fail.failed_ops.len(), 1);
        assert_eq!(
            rep_cidr_blk_fail.failed_ops[0].source_rule_ids,
            vec!["R-BLK-CIDR".to_string()],
            "overridden static CIDR allow must not retain retired unallowed other.example or attribute R-BLK-OTHER"
        );
        assert_eq!(
            rep_cidr_blk_fail.failed_ops[0].domain_hints,
            vec!["api.example".to_string()]
        );
        assert!(rep_cidr_blk_fail
            .failure_summary_for_rules(&[&r_blk_cidr])
            .is_some());
        assert!(rep_cidr_blk_fail
            .failure_summary_for_rules(&[&r_blk_other])
            .is_none());
    }
}
