//! Core `WfpRuleManager` state definition, key normalization, `AllowOnce` tracking, and queries.

use std::collections::HashMap;
use std::net::IpAddr;

use ledr_proto::{
    is_never_suspend_process, ActiveDefenseController, ACTIVE_PROCESS_TABLE_CAPACITY,
};
use ledr_rules::canonical_ip;

use super::types::{InstalledWfpFilter, WfpFilterOrigin, WfpTargetKey};

/// Tracks active dynamic WFP rule handles, alert containment bindings, wildcard/domain rule
/// presence, startup-pinned pre-restricted executables, and per-process `AllowOnce` grants.
#[derive(Debug, Default)]
pub struct WfpRuleManager {
    pub(super) installed: HashMap<WfpTargetKey, InstalledWfpFilter>,
    pub(super) bound_alerts: HashMap<String, WfpTargetKey>,
    once_allowed_processes: HashMap<String, String>,
    pub(super) startup_preemptive_exes: HashMap<String, String>,
    /// Tracks handles of non-startup `Preemptive` app-wide WFP blocks whose removal explicitly
    /// failed in `remove_preemptive_block_if_unused` or `discard_obsolete_preemptive_block`,
    /// mapping `wfp_handle -> consecutive_sweep_failures` for periodic retry and exponential
    /// backoff warning throttling. Only handles present here are eligible for
    /// [`Self::sweep_unused_preemptive_blocks`], so active processes evicted from `ProcessTable`
    /// under capacity pressure never lose their live `Preemptive` block.
    pub(super) pending_preemptive_removals: HashMap<u64, u64>,
    pub(super) has_wildcard_network_rules: bool,
    pub(super) has_domain_network_rules: bool,
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
        self.prune_stale_pending_preemptive_removals();
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
                "failed to remove pre-emptive WFP block on ProcessStop; queuing handle for periodic sweep retry"
            );
            self.pending_preemptive_removals
                .entry(entry.handle)
                .or_insert(0);
            return false;
        }
        self.installed.remove(&key);
        self.pending_preemptive_removals.remove(&entry.handle);
        true
    }

    /// Returns `true` when the app-wide filter currently installed for `exe_path` is queued for
    /// periodic unused-preemptive removal retry.
    pub fn has_pending_preemptive_removal(&self, exe_path: &str) -> bool {
        if self.pending_preemptive_removals.is_empty() {
            return false;
        }
        let key = Self::target_key(exe_path, None);
        self.installed
            .get(&key)
            .is_some_and(|entry| self.pending_preemptive_removals.contains_key(&entry.handle))
    }

    /// Reclaims a pending-removal `Preemptive` app-wide block when a live process reuses it,
    /// clearing it from periodic sweep retry so subsequent `ProcessTable` capacity eviction cannot
    /// drop an active process's block. Returns `true` if a pending removal entry was cleared.
    pub fn clear_pending_preemptive_removal(&mut self, exe_path: &str) -> bool {
        if self.pending_preemptive_removals.is_empty() {
            return false;
        }
        let key = Self::target_key(exe_path, None);
        let Some(handle) = self.installed.get(&key).map(|entry| entry.handle) else {
            return false;
        };
        self.pending_preemptive_removals.remove(&handle).is_some()
    }

    fn is_sweepable_preemptive_entry(&self, key: &WfpTargetKey, entry: &InstalledWfpFilter) -> bool {
        key.1.is_none()
            && !entry.allow
            && entry.origin == WfpFilterOrigin::Preemptive
            && !self.startup_preemptive_exes.contains_key(&key.0)
            && !self.bound_alerts.values().any(|bound| bound == key)
    }

    fn prune_stale_pending_preemptive_removals(&mut self) {
        if self.pending_preemptive_removals.is_empty() {
            return;
        }
        let installed = &self.installed;
        let startup = &self.startup_preemptive_exes;
        let bound_alerts = &self.bound_alerts;
        self.pending_preemptive_removals.retain(|handle, _| {
            installed.iter().any(|(key, entry)| {
                entry.handle == *handle
                    && key.1.is_none()
                    && !entry.allow
                    && entry.origin == WfpFilterOrigin::Preemptive
                    && !startup.contains_key(&key.0)
                    && !bound_alerts.values().any(|bound| bound == key)
            })
        });
    }

    /// Periodically retries removing non-startup, unbound `Preemptive` app-wide WFP blocks that
    /// were explicitly queued after transient `remove_wfp_rule` failures in
    /// [`Self::remove_preemptive_block_if_unused`] or [`Self::discard_obsolete_preemptive_block`].
    ///
    /// Fast-paths in O(1) with zero `self.installed` scans, zero `is_exe_active` calls, and zero
    /// heap allocations when no pending removal exists. Never sweeps live `Preemptive` filters
    /// that were not queued for removal (protecting active processes even if evicted from
    /// `ProcessTable` under capacity pressure), and never removes startup-pinned preemptive
    /// filters, alert-bound filters, `PersistedPolicy`, `DomainPolicy`, or `TransientContainment`
    /// filters.
    ///
    /// On persistent `remove_wfp_rule` failure, emits `tracing::warn!` with exponential backoff
    /// (powers of two: 1, 2, 4, 8, ...) per handle and retains the filter for subsequent sweeps.
    pub fn sweep_unused_preemptive_blocks<F>(
        &mut self,
        mut is_exe_active: F,
        defense: &dyn ActiveDefenseController,
    ) -> usize
    where
        F: FnMut(&str) -> bool,
    {
        if self.pending_preemptive_removals.is_empty() {
            return 0;
        }
        self.prune_stale_pending_preemptive_removals();
        if self.pending_preemptive_removals.is_empty() {
            return 0;
        }

        let mut unused_candidates: Vec<(WfpTargetKey, u64, String)> = Vec::new();
        let mut reactivated_handles: Vec<u64> = Vec::new();
        for (key, entry) in &self.installed {
            if !self.pending_preemptive_removals.contains_key(&entry.handle)
                || !self.is_sweepable_preemptive_entry(key, entry)
            {
                continue;
            }
            if is_exe_active(&key.0) {
                reactivated_handles.push(entry.handle);
            } else {
                unused_candidates.push((key.clone(), entry.handle, entry.exe_path.clone()));
            }
        }
        for handle in reactivated_handles {
            self.pending_preemptive_removals.remove(&handle);
        }

        let mut removed = 0usize;
        for (key, handle, exe_path) in unused_candidates {
            match defense.remove_wfp_rule(handle) {
                Ok(()) => {
                    self.installed.remove(&key);
                    let prior_sweep_failures = self
                        .pending_preemptive_removals
                        .remove(&handle)
                        .unwrap_or(0);
                    tracing::info!(
                        exe_path = %exe_path,
                        wfp_handle = handle,
                        prior_sweep_failures,
                        "removed retained unused pre-emptive WFP block on periodic sweep retry"
                    );
                    removed += 1;
                }
                Err(err) => {
                    let failures = self
                        .pending_preemptive_removals
                        .entry(handle)
                        .or_insert(0);
                    *failures = failures.saturating_add(1);
                    let count = *failures;
                    if count.is_power_of_two() {
                        tracing::warn!(
                            exe_path = %exe_path,
                            wfp_handle = handle,
                            consecutive_failures = count,
                            error = %err,
                            "periodic sweep failed removing unused pre-emptive WFP block; retaining handle for retry"
                        );
                    } else {
                        tracing::debug!(
                            exe_path = %exe_path,
                            wfp_handle = handle,
                            consecutive_failures = count,
                            error = %err,
                            "periodic sweep retry still failing to remove unused pre-emptive WFP block"
                        );
                    }
                }
            }
        }

        self.prune_stale_pending_preemptive_removals();
        removed
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
}
