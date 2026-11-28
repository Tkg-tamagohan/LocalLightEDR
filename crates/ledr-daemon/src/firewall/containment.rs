//! App-wide preemptive blocking, transient containment, policy blocks, and `AllowOnce` lifting.

use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{is_never_suspend_process, ActiveDefenseController};
use ledr_rules::canonical_ip;

use super::manager::WfpRuleManager;
use super::types::{
    InstalledScopedWfpFilter, InstalledWfpFilter, RemovedBlockSnapshot, WfpFilterOrigin,
};

impl WfpRuleManager {
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
            if !self.has_once_allowed_for_exe(&key.0) {
                if let Some(existing) = self.installed.get(&key) {
                    self.pending_preemptive_removals.remove(&existing.handle);
                    self.deferred_preemptive_removals.remove(&existing.handle);
                }
            }
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

    /// Removes an obsolete pre-emptive app-wide WFP handle that became unnecessary before commit
    /// (for example, all qualifying process instances exited while `add_wfp_app_rule` was in
    /// flight).
    ///
    /// If `remove_wfp_rule` fails and no filter currently occupies `(exe_path, None)` in
    /// `self.installed`, retains `handle` as a tracked `Preemptive` filter (consistent with
    /// [`Self::remove_preemptive_block_if_unused`]) so periodic unused-block sweeps
    /// ([`Self::sweep_unused_preemptive_blocks`]), subsequent `ProcessStop`, `AllowOnce`,
    /// `TerminateAndBlock`, or app-wide `NetworkAllow` reconciliation can retry removal instead of
    /// leaking an untracked OS BFE block.
    pub fn discard_obsolete_preemptive_block(
        &mut self,
        exe_path: &str,
        handle: u64,
        defense: &dyn ActiveDefenseController,
    ) -> bool {
        match defense.remove_wfp_rule(handle) {
            Ok(()) => true,
            Err(err) => {
                let key = Self::target_key(exe_path, None);
                if let std::collections::hash_map::Entry::Vacant(slot) = self.installed.entry(key) {
                    tracing::warn!(
                        exe_path = %exe_path,
                        wfp_handle = handle,
                        error = %err,
                        "failed removing obsolete pre-emptive WFP handle after concurrent process exit; retaining handle in WfpRuleManager for retry"
                    );
                    slot.insert(InstalledWfpFilter {
                        handle,
                        exe_path: exe_path.to_string(),
                        allow: false,
                        origin: WfpFilterOrigin::Preemptive,
                    });
                    self.pending_preemptive_removals.entry(handle).or_insert(0);
                } else {
                    tracing::warn!(
                        exe_path = %exe_path,
                        wfp_handle = handle,
                        error = %err,
                        "failed removing obsolete pre-emptive WFP handle after concurrent process exit while another filter already occupies slot"
                    );
                }
                false
            }
        }
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
                let existing_handle = existing.handle;
                let existing_is_preemptive = existing.origin == WfpFilterOrigin::Preemptive;
                self.bound_alerts.insert(alert_id.to_string(), key.clone());
                if self.pending_preemptive_removals.remove(&existing_handle).is_some()
                    && existing_is_preemptive
                    && !self.startup_preemptive_exes.contains_key(&key.0)
                {
                    self.deferred_preemptive_removals.insert(existing_handle);
                }
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
        if let Some((existing_handle, existing_is_preemptive)) = self.installed.get(&key).and_then(|e| {
            (!e.allow
                && matches!(
                    e.origin,
                    WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                ))
            .then_some((e.handle, e.origin == WfpFilterOrigin::Preemptive))
        }) {
            self.bound_alerts.insert(alert_id.to_string(), key.clone());
            if self.pending_preemptive_removals.remove(&existing_handle).is_some()
                && existing_is_preemptive
                && !self.startup_preemptive_exes.contains_key(&key.0)
            {
                self.deferred_preemptive_removals.insert(existing_handle);
            }
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
                let existing_handle = existing.handle;
                existing.origin = WfpFilterOrigin::PersistedPolicy;
                self.bound_alerts.retain(|_, k| k != &key);
                self.pending_preemptive_removals.remove(&existing_handle);
                self.deferred_preemptive_removals.remove(&existing_handle);
                return Ok(existing_handle);
            }
            // Replace conflicting Permit with Block (deny-overrides-allow).
            let old_handle = existing.handle;
            defense.remove_wfp_rule(old_handle)?;
            self.installed.remove(&key);
            self.pending_preemptive_removals.remove(&old_handle);
            self.deferred_preemptive_removals.remove(&old_handle);
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

    /// Ensures a concrete app-wide WFP Permit filter is active for an executable authorized by an
    /// unscoped (`allowed_target == None`) persisted `NetworkAllow` rule (including wildcard
    /// default browser rules materialized after daemon startup). Never replaces an active Block.
    pub fn ensure_policy_permit(
        &mut self,
        exe_path: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let trimmed = exe_path.trim();
        if trimmed.is_empty() || Self::is_wildcard_pattern(trimmed) {
            return Err("refusing WFP permit for empty or wildcard executable path".to_string());
        }
        let key = (Self::exe_key(trimmed), None);
        if let Some(existing) = self.installed.get(&key) {
            if existing.allow {
                return Ok(existing.handle);
            }
            return Err(format!(
                "refusing WFP permit for `{trimmed}` while app-wide block filter is active"
            ));
        }

        let handle = defense.add_wfp_app_rule(Path::new(trimmed), None, true)?;
        self.installed.insert(
            key,
            InstalledWfpFilter {
                handle,
                exe_path: trimmed.to_string(),
                allow: true,
                origin: WfpFilterOrigin::PersistedPolicy,
            },
        );
        Ok(handle)
    }

    /// Ensures a package-scoped (`ALE_APP_ID` + `ALE_PACKAGE_ID`) WFP Block filter is active.
    pub fn ensure_scoped_policy_block(
        &mut self,
        exe_path: &str,
        package_sid: &str,
        remote_ip: Option<IpAddr>,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let clean = exe_path.trim().trim_end_matches(['.', ' ']);
        if is_never_suspend_process(exe_path) || is_never_suspend_process(clean) {
            return Err(format!(
                "refusing scoped WFP block for protected process `{exe_path}`"
            ));
        }
        let sid_trimmed = package_sid.trim();
        if sid_trimmed.is_empty() {
            return Err("refusing scoped WFP block with empty package_sid".to_string());
        }
        let canon_ip = remote_ip.map(canonical_ip);
        let key = Self::scoped_target_key(exe_path, sid_trimmed, canon_ip);
        if let Some(existing) = self.scoped_installed.get_mut(&key) {
            if !existing.allow {
                existing.origin = WfpFilterOrigin::PersistedPolicy;
                return Ok(existing.handle);
            }
            let old_handle = existing.handle;
            defense.remove_wfp_rule(old_handle)?;
            self.scoped_installed.remove(&key);
        }

        let handle =
            defense.add_wfp_scoped_app_rule(Path::new(exe_path), Some(sid_trimmed), canon_ip, false)?;
        self.scoped_installed.insert(
            key,
            InstalledScopedWfpFilter {
                handle,
                exe_path: exe_path.to_string(),
                package_sid: sid_trimmed.to_string(),
                package_family_name: None,
                allow: false,
                origin: WfpFilterOrigin::PersistedPolicy,
            },
        );
        Ok(handle)
    }

    /// Ensures a package-scoped (`ALE_APP_ID` + `ALE_PACKAGE_ID`) WFP Permit filter is active
    /// without overriding any unscoped or package-scoped Block filter (`FU-P4-03`).
    pub fn ensure_scoped_policy_permit(
        &mut self,
        exe_path: &str,
        package_sid: &str,
        defense: &dyn ActiveDefenseController,
    ) -> Result<u64, String> {
        let trimmed = exe_path.trim();
        if trimmed.is_empty() || Self::is_wildcard_pattern(trimmed) {
            return Err("refusing scoped WFP permit for empty or wildcard executable path".to_string());
        }
        let sid_trimmed = package_sid.trim();
        if sid_trimmed.is_empty() {
            return Err("refusing scoped WFP permit with empty package_sid".to_string());
        }
        if self.active_app_block(trimmed).is_some()
            || self.active_scoped_app_block(trimmed, sid_trimmed).is_some()
        {
            return Err(format!(
                "refusing scoped WFP permit for `{trimmed}` (pkg={sid_trimmed}) while block filter is active"
            ));
        }
        let key = Self::scoped_target_key(trimmed, sid_trimmed, None);
        if let Some(existing) = self.scoped_installed.get(&key) {
            if existing.allow {
                return Ok(existing.handle);
            }
            return Err(format!(
                "refusing scoped WFP permit for `{trimmed}` (pkg={sid_trimmed}) while block filter is active"
            ));
        }

        let handle =
            defense.add_wfp_scoped_app_rule(Path::new(trimmed), Some(sid_trimmed), None, true)?;
        self.scoped_installed.insert(
            key,
            InstalledScopedWfpFilter {
                handle,
                exe_path: trimmed.to_string(),
                package_sid: sid_trimmed.to_string(),
                package_family_name: None,
                allow: true,
                origin: WfpFilterOrigin::PersistedPolicy,
            },
        );
        Ok(handle)
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
        let prev_pending_removal_failures = self.pending_preemptive_removals.remove(&entry.handle);
        let prev_deferred_preemptive_removal =
            self.deferred_preemptive_removals.remove(&entry.handle);
        Ok((
            Some(RemovedBlockSnapshot {
                key,
                exe_path: entry.exe_path,
                origin: entry.origin,
                prev_pending_removal_failures,
                prev_deferred_preemptive_removal,
            }),
            was_bound,
        ))
    }

    /// Captures the current non-persisted app-wide block (`Preemptive` or `TransientContainment`)
    /// and all alert IDs currently bound to `exe_path` so a subsequent `AllowPermanent` rollback
    /// can restore both the block (including pending/deferred preemptive removal state) and any
    /// sibling alert bindings displaced by reconciliation (`PRRT_kwDOVyjVyM66ksZF`).
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
                    prev_pending_removal_failures: self
                        .pending_preemptive_removals
                        .get(&entry.handle)
                        .copied(),
                    prev_deferred_preemptive_removal: self
                        .deferred_preemptive_removals
                        .contains(&entry.handle),
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

    /// Best-effort rollback restoring a lifted block filter (and optionally re-binding `alert_id`,
    /// plus preserving any pending/deferred preemptive removal state) when alert resolution
    /// subsequently fails to resume the process or update alert status (`PRRT_kwDOVyjVyM66ksZF`).
    pub fn restore_lifted_block(
        &mut self,
        rebind_alert_id: Option<&str>,
        snapshot: RemovedBlockSnapshot,
        defense: &dyn ActiveDefenseController,
    ) {
        if let Some((existing_handle, existing_is_preemptive, can_bind)) =
            self.installed.get(&snapshot.key).map(|existing| {
                (
                    existing.handle,
                    existing.origin == WfpFilterOrigin::Preemptive,
                    !existing.allow
                        && matches!(
                            existing.origin,
                            WfpFilterOrigin::TransientContainment | WfpFilterOrigin::Preemptive
                        ),
                )
            })
        {
            if can_bind {
                if let Some(alert_id) = rebind_alert_id {
                    self.bound_alerts
                        .insert(alert_id.to_string(), snapshot.key.clone());
                }
                if existing_is_preemptive
                    && !self.startup_preemptive_exes.contains_key(&snapshot.key.0)
                {
                    let promoted_pending = rebind_alert_id.is_some()
                        && self
                            .pending_preemptive_removals
                            .remove(&existing_handle)
                            .is_some();
                    if promoted_pending || snapshot.prev_deferred_preemptive_removal {
                        self.deferred_preemptive_removals.insert(existing_handle);
                    }
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
                let is_non_startup_preemptive = snapshot.origin == WfpFilterOrigin::Preemptive
                    && !self.startup_preemptive_exes.contains_key(&snapshot.key.0);
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
                            .insert(alert_id.to_string(), snapshot.key.clone());
                    }
                }
                if is_non_startup_preemptive {
                    let has_bound = self.bound_alerts.values().any(|k| k == &snapshot.key);
                    if has_bound {
                        if snapshot.prev_deferred_preemptive_removal
                            || snapshot.prev_pending_removal_failures.is_some()
                        {
                            self.deferred_preemptive_removals.insert(handle);
                        }
                    } else {
                        if let Some(failures) = snapshot.prev_pending_removal_failures {
                            self.pending_preemptive_removals.insert(handle, failures);
                        }
                        if snapshot.prev_deferred_preemptive_removal {
                            self.deferred_preemptive_removals.insert(handle);
                        }
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
        let prev_pending_removal_failures = self.pending_preemptive_removals.remove(&entry.handle);
        let prev_deferred_preemptive_removal =
            self.deferred_preemptive_removals.remove(&entry.handle);
        Ok((
            Some(RemovedBlockSnapshot {
                key,
                exe_path: entry.exe_path,
                origin: entry.origin,
                prev_pending_removal_failures,
                prev_deferred_preemptive_removal,
            }),
            was_bound,
        ))
    }
}
