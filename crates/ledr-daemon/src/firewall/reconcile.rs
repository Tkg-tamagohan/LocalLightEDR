//! Persisted WFP rule reconciliation against BFE and rollback restoration helpers.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use ledr_proto::{ActiveDefenseController, AllowlistRuleRecord, RuleScope};
use ledr_rules::{
    evaluate_outbound_policy, matches_app_wide_network_allow, matches_app_wide_network_block,
    matches_network_block_rule, matches_path_pattern, BinaryIdentity, OutboundDecision,
};

use crate::engine::BinaryInspector;

use super::hints::{
    compute_pruned_permit_hints, merge_domain_hint, normalize_domain_hint,
};
use super::manager::WfpRuleManager;
use super::types::{
    InstalledWfpFilter, PromotedFilterSnapshot, RemovedAppBlockSnapshot, RemovedBlockSnapshot,
    RemovedDomainFilterSnapshot, WfpFailedOp, WfpFilterOrigin, WfpReconcileDnsContext,
    WfpReconcileReport, WfpTargetKey,
};

impl WfpRuleManager {
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
        let active_exe_keys: HashSet<String> = active_concrete_exes
            .iter()
            .map(|p| Self::exe_key(p))
            .collect();
        let mut deferred_handles_to_clear: Vec<u64> = Vec::new();
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
                    } else if matches!(entry.origin, WfpFilterOrigin::Preemptive)
                        && key.1.is_none()
                        && !entry.allow
                        && !self.startup_preemptive_exes.contains_key(&key.0)
                    {
                        let is_exe_live = active_exe_keys.contains(&key.0)
                            || dns_ctx.live_exe_overflow_any
                            || dns_ctx.overflow_live_exe_keys.contains(&key.0);
                        if active_exe_keys.contains(&key.0)
                            && self.deferred_preemptive_removals.contains(&entry.handle)
                        {
                            deferred_handles_to_clear.push(entry.handle);
                        }
                        let release_for_deferred_or_allow =
                            if !is_exe_live
                                && self.deferred_preemptive_removals.contains(&entry.handle)
                                && !self.bound_alerts.values().any(|k| k == key)
                            {
                                // Deferred removal whose bound alerts are all resolved and whose
                                // executable is confirmed inactive: remove without disk I/O or
                                // creating a PersistedPolicy Permit.
                                true
                            } else {
                                let has_app_wide_allow_path_match = rules.iter().any(|r| {
                                    r.scope == RuleScope::NetworkAllow
                                        && r.allowed_target
                                            .as_deref()
                                            .is_none_or(|s| s.trim().is_empty())
                                        && !r.exe_path_pattern.trim().is_empty()
                                        && matches_path_pattern(
                                            &entry.exe_path,
                                            &r.exe_path_pattern,
                                        )
                                });
                                if has_app_wide_allow_path_match {
                                    let identity = identity_cache
                                        .entry(key.0.clone())
                                        .or_insert_with(|| inspector.inspect(&entry.exe_path));
                                    rules
                                        .iter()
                                        .any(|r| matches_app_wide_network_allow(r, identity))
                                        && !rules
                                            .iter()
                                            .any(|r| matches_app_wide_network_block(r, identity))
                                } else {
                                    false
                                }
                            };
                        if release_for_deferred_or_allow {
                            keys_to_remove.push(key.clone());
                        }
                    }
                }
            }
        }
        for handle in deferred_handles_to_clear {
            self.deferred_preemptive_removals.remove(&handle);
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
                        let prev_pending_removal_failures =
                            self.pending_preemptive_removals.remove(&entry.handle);
                        let prev_deferred_preemptive_removal =
                            self.deferred_preemptive_removals.remove(&entry.handle);
                        let bound_alert_ids: Vec<String> = self
                            .bound_alerts
                            .iter()
                            .filter(|(_, k)| *k == &key)
                            .map(|(id, _)| id.clone())
                            .collect();
                        self.bound_alerts.retain(|_, k| k != &key);
                        if !entry.allow
                            && matches!(
                                entry.origin,
                                WfpFilterOrigin::Preemptive | WfpFilterOrigin::TransientContainment
                            )
                            && (prev_pending_removal_failures.is_none()
                                || !bound_alert_ids.is_empty())
                        {
                            report.removed_app_blocks.push(RemovedAppBlockSnapshot {
                                block: RemovedBlockSnapshot {
                                    key: key.clone(),
                                    exe_path: entry.exe_path.clone(),
                                    origin: entry.origin.clone(),
                                    prev_pending_removal_failures,
                                    prev_deferred_preemptive_removal,
                                },
                                bound_alert_ids,
                            });
                        }
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
                let promoted_handle = entry.handle;
                let prev_pending_removal_failures =
                    self.pending_preemptive_removals.remove(&promoted_handle);
                let prev_deferred_preemptive_removal =
                    self.deferred_preemptive_removals.remove(&promoted_handle);
                report.promoted_backups.push(PromotedFilterSnapshot {
                    key: key.clone(),
                    prev_origin: entry.origin.clone(),
                    bound_alert_ids,
                    prev_pending_removal_failures,
                    prev_deferred_preemptive_removal,
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
                    prev_pending_removal_failures: None,
                    prev_deferred_preemptive_removal: false,
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
                    prev_pending_removal_failures: None,
                    prev_deferred_preemptive_removal: false,
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

    /// Restores filter origins, alert containment bindings, and pending/deferred preemptive
    /// removal states overwritten during a failed reconciliation pass whose SQLite mutation was
    /// rolled back (`PRRT_kwDOVyjVyM66kfDu`).
    pub fn restore_promoted_filter_states(&mut self, backups: &[PromotedFilterSnapshot]) {
        for snap in backups {
            if let Some(entry) = self.installed.get_mut(&snap.key) {
                let handle = entry.handle;
                entry.origin = snap.prev_origin.clone();
                for alert_id in &snap.bound_alert_ids {
                    self.bound_alerts
                        .insert(alert_id.clone(), snap.key.clone());
                }
                if let Some(failures) = snap.prev_pending_removal_failures {
                    self.pending_preemptive_removals
                        .entry(handle)
                        .or_insert(failures);
                }
                if snap.prev_deferred_preemptive_removal {
                    self.deferred_preemptive_removals.insert(handle);
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

    /// Best-effort restoration of non-persisted app-wide block filters (`Preemptive` or
    /// `TransientContainment`) removed during reconciliation before a subsequent failure caused
    /// SQLite rollback, preserving alert containment bindings and pending/deferred preemptive
    /// removal state (`PRRT_kwDOVyjVyM66ksZF`, `PRRT_kwDOVyjVyM66k6kK`).
    ///
    /// For non-startup `Preemptive` blocks, re-verifies executable liveness via `is_exe_active`
    /// (called under `firewall -> process_table` order and releasing any `process_table` lock
    /// before BFE I/O):
    /// - if no active process remains and no alert is bound, skips restoration so an already-exited
    ///   executable does not resurrect an orphaned `Preemptive` block;
    /// - if no active process remains while alerts remain bound, restores the block with
    ///   `prev_deferred_preemptive_removal = true` so resolving the final bound alert cleans it up.
    pub fn restore_removed_app_blocks<F>(
        &mut self,
        removed: &[RemovedAppBlockSnapshot],
        mut is_exe_active: F,
        defense: &dyn ActiveDefenseController,
    ) where
        F: FnMut(&str) -> bool,
    {
        for snap in removed {
            let is_non_startup_preemptive = snap.block.origin == WfpFilterOrigin::Preemptive
                && !self.startup_preemptive_exes.contains_key(&snap.block.key.0);
            let mut block = snap.block.clone();
            if is_non_startup_preemptive {
                let has_bound_alerts = !snap.bound_alert_ids.is_empty()
                    || self.bound_alerts.values().any(|k| k == &snap.block.key);
                let still_active = is_exe_active(&snap.block.key.0);
                if !still_active {
                    if !has_bound_alerts {
                        continue;
                    }
                    block.prev_deferred_preemptive_removal = true;
                }
            }
            self.restore_lifted_block(None, block, defense);
            for alert_id in &snap.bound_alert_ids {
                self.bind_alert_to_app_block(alert_id, &snap.block.exe_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use ledr_proto::{
        ActiveDefenseController, AllowlistRuleRecord, AuthenticodeInfo, ProcessIdentity, RuleScope,
    };
    use ledr_rules::BinaryIdentity;

    use super::*;

    struct CountingInspector {
        identities: HashMap<String, BinaryIdentity>,
        calls: AtomicUsize,
    }

    impl CountingInspector {
        fn new(entries: Vec<BinaryIdentity>) -> Self {
            let mut identities = HashMap::new();
            for id in entries {
                identities.insert(WfpRuleManager::exe_key(&id.exe_path), id);
            }
            Self {
                identities,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Acquire)
        }
    }

    impl BinaryInspector for CountingInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.identities
                .get(&WfpRuleManager::exe_key(exe_path))
                .cloned()
                .unwrap_or_else(|| BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: None,
                    authenticode: None,
                })
        }
    }

    struct CountingDefense {
        next_handle: AtomicU64,
        adds: Mutex<Vec<(String, Option<IpAddr>, bool)>>,
        removes: Mutex<Vec<u64>>,
    }

    impl CountingDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(100),
                adds: Mutex::new(Vec::new()),
                removes: Mutex::new(Vec::new()),
            }
        }

        fn take_counts(&self) -> (usize, usize) {
            let mut adds = self.adds.lock().unwrap();
            let mut removes = self.removes.lock().unwrap();
            let res = (adds.len(), removes.len());
            adds.clear();
            removes.clear();
            res
        }
    }

    impl ActiveDefenseController for CountingDefense {
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
            remote_ip: Option<IpAddr>,
            allow: bool,
        ) -> Result<u64, String> {
            self.adds
                .lock()
                .unwrap()
                .push((exe_path.to_string_lossy().into_owned(), remote_ip, allow));
            Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            self.removes.lock().unwrap().push(filter_id);
            Ok(())
        }
    }

    fn wildcard_allow_rule(
        rule_id: &str,
        exe_pattern: &str,
        allowed_target: Option<&str>,
    ) -> AllowlistRuleRecord {
        AllowlistRuleRecord {
            rule_id: rule_id.to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe_pattern.to_string(),
            sha256: None,
            signer_subject: Some("CN=Contoso Store Publisher".to_string()),
            root_thumbprint: Some("0123456789ABCDEF0123456789ABCDEF01234567".to_string()),
            allowed_target: allowed_target.map(str::to_string),
            created_at_ms: 1_750_000_000_000,
            created_by: "user_triage".to_string(),
        }
    }

    #[test]
    fn reconcile_releases_deferred_unbound_preemptive_without_disk_io_and_zero_churn_next_pass() {
        let exe_old = r"C:\Program Files\WindowsApps\Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe\App.exe";
        let pattern = r"C:\Program Files\WindowsApps\Contoso.App_*_x64__8wekyb3d8bbwe\App.exe";
        let defense = CountingDefense::new();
        // Old binary already deleted on disk (inspector returns None) — must not even be inspected.
        let inspector = CountingInspector::new(Vec::new());
        let mut fw = WfpRuleManager::new();

        let h = defense
            .add_wfp_app_rule(Path::new(exe_old), None, false)
            .unwrap();
        assert!(fw.register_preemptive_block(exe_old, h, &defense));
        assert!(fw.bind_alert_to_app_block("ALT-DEFERRED-1", exe_old));
        // Process exits while alert is still bound -> marked deferred.
        assert!(!fw.remove_preemptive_block_if_unused(exe_old, &defense));
        assert!(fw.has_deferred_preemptive_removal(exe_old));
        let _ = defense.take_counts();

        let rules = vec![wildcard_allow_rule("R-WA-1", pattern, Some("api.contoso.example"))];

        // While alert is still bound, Pass must NOT release the deferred Preemptive block.
        let report_bound = fw.reconcile_persisted_rules(&rules, &[], &inspector, &defense);
        assert_eq!(report_bound.removed, 0);
        assert!(fw.active_app_block(exe_old).is_some());
        assert_eq!(defense.take_counts(), (0, 0));

        // Alert resolves (e.g. via release_transient_containment_for_alert unbinding `ALT-DEFERRED-1`).
        fw.unbind_alert("ALT-DEFERRED-1");

        // Pass N: releases the deferred unbound Preemptive block with ZERO disk I/O and NO PersistedPolicy Permit.
        let report_n = fw.reconcile_persisted_rules(&rules, &[], &inspector, &defense);
        assert_eq!(report_n.removed, 1);
        assert_eq!(report_n.applied, 0);
        assert_eq!(inspector.calls(), 0, "deferred unbound removal must not inspect disk");
        assert!(!fw.has_any_app_filter(exe_old));
        assert!(!fw.has_deferred_preemptive_removal(exe_old));
        assert_eq!(defense.take_counts(), (0, 1));

        // Pass N+1: completely stable with 0 BFE adds and 0 BFE removes.
        let report_n1 = fw.reconcile_persisted_rules(&rules, &[], &inspector, &defense);
        assert_eq!(report_n1.applied, 0);
        assert_eq!(report_n1.removed, 0);
        assert_eq!(defense.take_counts(), (0, 0));
    }

    #[test]
    fn reconcile_releases_non_deferred_exited_preemptive_only_for_app_wide_allow_without_churn() {
        let exe_exited =
            r"C:\Program Files\WindowsApps\Contoso.App_1.0.0.0_x64__8wekyb3d8bbwe\App.exe";
        let pattern =
            r"C:\Program Files\WindowsApps\Contoso.App_*_x64__8wekyb3d8bbwe\App.exe";
        let defense = CountingDefense::new();
        let inspector = CountingInspector::new(vec![BinaryIdentity {
            exe_path: exe_exited.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: "CN=Contoso Store Publisher".to_string(),
                root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
            }),
        }]);
        let mut fw = WfpRuleManager::new();

        let h = defense
            .add_wfp_app_rule(Path::new(exe_exited), None, false)
            .unwrap();
        assert!(fw.register_preemptive_block(exe_exited, h, &defense));
        let _ = defense.take_counts();

        // Destination-scoped wildcard NetworkAllow must NOT release non-deferred app-wide Preemptive block
        // and must not even perform disk inspection.
        let dest_scoped = vec![wildcard_allow_rule("R-WA-DEST", pattern, Some("203.0.113.10"))];
        let report_dest = fw.reconcile_persisted_rules(&dest_scoped, &[], &inspector, &defense);
        assert_eq!(report_dest.removed, 0);
        assert_eq!(report_dest.applied, 0);
        assert_eq!(inspector.calls(), 0);
        assert!(fw.active_app_block(exe_exited).is_some());
        assert_eq!(defense.take_counts(), (0, 0));

        // App-wide wildcard NetworkAllow + matching app-wide NetworkBlock must NOT release (deny-overrides-allow).
        let app_wide_allow = wildcard_allow_rule("R-WA-APP", pattern, None);
        let app_wide_block = AllowlistRuleRecord {
            rule_id: "R-WA-BLK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: pattern.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1_750_000_000_001,
            created_by: "user_quarantine".to_string(),
        };
        let report_blocked = fw.reconcile_persisted_rules(
            &[app_wide_allow.clone(), app_wide_block],
            &[],
            &inspector,
            &defense,
        );
        assert_eq!(report_blocked.removed, 0);
        assert!(fw.active_app_block(exe_exited).is_some());
        assert_eq!(defense.take_counts(), (0, 0));

        // App-wide wildcard NetworkAllow alone: Pass N removes Preemptive block without creating Permit.
        let rules_allow = vec![app_wide_allow];
        let report_n = fw.reconcile_persisted_rules(&rules_allow, &[], &inspector, &defense);
        assert_eq!(report_n.removed, 1);
        assert_eq!(report_n.applied, 0);
        assert!(!fw.has_any_app_filter(exe_exited));
        assert_eq!(defense.take_counts(), (0, 1));

        // Pass N+1: 0 BFE add/remove churn.
        let report_n1 = fw.reconcile_persisted_rules(&rules_allow, &[], &inspector, &defense);
        assert_eq!(report_n1.removed, 0);
        assert_eq!(report_n1.applied, 0);
        assert_eq!(defense.take_counts(), (0, 0));
    }

    #[test]
    fn reconcile_keeps_deferred_preemptive_block_when_exe_restarted_or_overflow_live() {
        let exe = r"C:\Users\Alice\Downloads\RestartedHelper.exe";
        let defense = CountingDefense::new();
        let inspector = CountingInspector::new(Vec::new());
        let mut fw = WfpRuleManager::new();

        let h = defense.add_wfp_app_rule(Path::new(exe), None, false).unwrap();
        assert!(fw.register_preemptive_block(exe, h, &defense));
        assert!(fw.bind_alert_to_app_block("ALT-OLD-1", exe));
        assert!(!fw.remove_preemptive_block_if_unused(exe, &defense));
        assert!(fw.has_deferred_preemptive_removal(exe));
        fw.unbind_alert("ALT-OLD-1");
        let _ = defense.take_counts();

        let dest_scoped = vec![AllowlistRuleRecord {
            rule_id: "R-DEST-ONLY".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe.to_string(),
            sha256: Some("c".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.50".to_string()),
            created_at_ms: 1_750_000_000_000,
            created_by: "user_triage".to_string(),
        }];

        // 1. Live in `active_concrete_exes`: keeps block AND clears stale deferred flag.
        let rep_live = fw.reconcile_persisted_rules(
            &dest_scoped,
            &[exe.to_string()],
            &inspector,
            &defense,
        );
        assert_eq!(rep_live.removed, 0);
        assert!(fw.active_app_block(exe).is_some());
        assert!(!fw.has_deferred_preemptive_removal(exe));
        assert_eq!(defense.take_counts(), (0, 0));

        // 2. Fail closed when overflow flags indicate unenumerated live processes.
        assert!(fw.bind_alert_to_app_block("ALT-OLD-2", exe));
        assert!(!fw.remove_preemptive_block_if_unused(exe, &defense));
        fw.unbind_alert("ALT-OLD-2");
        assert!(fw.has_deferred_preemptive_removal(exe));

        let mut overflow_ctx = WfpReconcileDnsContext::default();
        overflow_ctx.overflow_live_exe_keys.insert(WfpRuleManager::exe_key(exe));
        let rep_ov_key = fw.reconcile_persisted_rules_with_dns_context(
            &dest_scoped,
            None,
            &[],
            &overflow_ctx,
            &inspector,
            &defense,
        );
        assert_eq!(rep_ov_key.removed, 0);
        assert!(fw.active_app_block(exe).is_some());

        let overflow_any_ctx = WfpReconcileDnsContext {
            live_exe_overflow_any: true,
            ..Default::default()
        };
        let rep_ov_any = fw.reconcile_persisted_rules_with_dns_context(
            &dest_scoped,
            None,
            &[],
            &overflow_any_ctx,
            &inspector,
            &defense,
        );
        assert_eq!(rep_ov_any.removed, 0);
        assert!(fw.active_app_block(exe).is_some());
    }
}
