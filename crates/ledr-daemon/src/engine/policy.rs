use std::net::IpAddr;

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope};
use ledr_rules::{
    classify_outbound_risk, matches_network_block_rule, validate_policy_rule, OutboundRiskClass,
};
use ledr_store::StoreError;

use crate::firewall::{WfpFailedOp, WfpReconcileDnsContext, WfpReconcileReport};

use super::DaemonEngine;

/// Errors returned when validating or persisting a policy rule via [`DaemonEngine::upsert_policy_rule`].
#[derive(Debug)]
pub enum PolicyRuleError {
    /// Rule violated `L-04` identity constraints or `AUTO-02` Never-Block protection.
    Invalid(String),
    /// Underlying SQLite store failure.
    Store(StoreError),
    /// Live WFP firewall synchronization failed; SQLite change was rolled back (`#4`).
    FirewallSync(String),
}

impl std::fmt::Display for PolicyRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Store(err) => write!(f, "{err}"),
            Self::FirewallSync(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PolicyRuleError {}

impl From<StoreError> for PolicyRuleError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
    }
}

impl DaemonEngine {
    /// Reconciles live WFP dynamic filters against persisted `NetworkBlock` and `NetworkAllow`
    /// rules in SQLite with deny-overrides-allow precedence (`L-03`, `L-04`).
    pub fn deploy_persisted_network_rules(&self) -> WfpReconcileReport {
        self.deploy_persisted_network_rules_with_baseline(None)
    }

    pub(super) fn deploy_persisted_network_rules_with_baseline(
        &self,
        prev_rules: Option<&[AllowlistRuleRecord]>,
    ) -> WfpReconcileReport {
        if !self.config.outbound_firewall_enabled {
            self.outbound_classifier.set_has_domain_rules(false);
            return WfpReconcileReport::default();
        }
        if self.config.outbound_enforcement_mode == super::OutboundEnforcementMode::Audit {
            match self.store.list_network_rules() {
                Ok(rules) => {
                    let has_domain_rules = rules.iter().any(|rule| {
                        matches!(rule.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow)
                            && !rule.exe_path_pattern.trim().is_empty()
                            && rule
                                .allowed_target
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .is_some_and(|target| {
                                    crate::firewall::parse_literal_target_ip(target).is_none()
                                        && ledr_rules::parse_cidr_target(target).is_err()
                                })
                    });
                    self.outbound_classifier
                        .set_has_domain_rules(has_domain_rules);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "failed to load persisted network rules in audit mode; preserving previous has_domain_rules state"
                    );
                }
            }
            return WfpReconcileReport::default();
        }
        let rules = match self.store.list_network_rules() {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(error = %err, "failed to load persisted network rules for WFP reconciliation");
                return WfpReconcileReport {
                    failed: 1,
                    failed_ops: vec![WfpFailedOp {
                        exe_key: "<store>".to_string(),
                        remote_ip: None,
                        is_remove: false,
                        is_startup_preemptive: false,
                        newly_required: false,
                        source_rule_ids: Vec::new(),
                        domain_hints: Vec::new(),
                        error: format!("failed to load persisted network rules: {err}"),
                    }],
                    ..Default::default()
                };
            }
        };
        let active_exes = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_exe_paths();
        let (report, has_domain_rules) = {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            let dns_ctx = {
                let blocks = fw.all_domain_policy_blocks();
                let permits = fw.all_domain_policy_permits_with_hints();
                if blocks.is_empty() && permits.is_empty() {
                    WfpReconcileDnsContext::default()
                } else {
                    let dns_hist = self
                        .process_dns_history
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let mut ctx = WfpReconcileDnsContext::default();
                    for (exe_k, ip) in blocks {
                        let doms = dns_hist.domains_for_exe_ip(&exe_k, ip);
                        if !doms.is_empty() {
                            ctx.active_block_domains.insert((exe_k, ip), doms);
                        }
                    }
                    for (exe_k, ip, hints) in permits {
                        for hint in hints {
                            if dns_hist.is_domain_ip_superseded(&exe_k, &hint, ip) {
                                ctx.superseded_permit_hints.insert((exe_k.clone(), ip, hint));
                            }
                        }
                    }
                    ctx
                }
            };
            let mut rep = fw.reconcile_persisted_rules_with_dns_context(
                &rules,
                prev_rules,
                &active_exes,
                &dns_ctx,
                &*self.inspector,
                &*self.defense,
            );
            let domain_permits = fw.domain_policy_permits();
            if !domain_permits.is_empty() {
                let dns_hist = self
                    .process_dns_history
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                for (exe_k, exe_path, ip) in domain_permits {
                    let clean_exe = exe_path.trim().trim_end_matches(['.', ' ']);
                    if classify_outbound_risk(&exe_path) == OutboundRiskClass::ProtectedOs
                        || is_never_suspend_process(clean_exe)
                    {
                        continue;
                    }
                    let doms = dns_hist.domains_for_exe_ip(&exe_k, ip);
                    if doms.is_empty() {
                        continue;
                    }
                    let identity = self.inspector.inspect(&exe_path);
                    let mut blocking_rule_ids: Vec<String> = Vec::new();
                    let mut matched_doms: Vec<String> = Vec::new();
                    for dom in &doms {
                        let mut dom_blocked = false;
                        for rule in &rules {
                            if rule.scope == RuleScope::NetworkBlock
                                && matches_network_block_rule(rule, &identity, ip, Some(dom))
                            {
                                dom_blocked = true;
                                if !blocking_rule_ids.contains(&rule.rule_id) {
                                    blocking_rule_ids.push(rule.rule_id.clone());
                                }
                            }
                        }
                        if dom_blocked {
                            matched_doms.push(dom.clone());
                        }
                    }
                    if !blocking_rule_ids.is_empty() {
                        // Avoid duplicating a removal attempt or failure count when step 3
                        // (`reconcile_persisted_rules_with_baseline`) already failed removing this
                        // exact `(exe_k, Some(ip))` filter, while still attributing newly
                        // discovered blocking rule IDs / domains to that failed op (`#1`, `#4`).
                        if let Some(existing_op) = rep.failed_ops.iter_mut().find(|op| {
                            op.is_remove && op.exe_key == exe_k && op.remote_ip == Some(ip)
                        }) {
                            for rid in blocking_rule_ids {
                                if !existing_op.source_rule_ids.contains(&rid) {
                                    existing_op.source_rule_ids.push(rid);
                                }
                            }
                            for dom in matched_doms {
                                if !existing_op.domain_hints.contains(&dom) {
                                    existing_op.domain_hints.push(dom);
                                }
                            }
                            continue;
                        }
                        match fw.remove_domain_policy_permit(&exe_path, ip, &*self.defense) {
                            Ok(Some(snap)) => {
                                rep.removed += 1;
                                rep.removed_domain_filters.push(snap);
                            }
                            Ok(None) => {}
                            Err(err) => {
                                rep.failed += 1;
                                rep.failed_ops.push(WfpFailedOp {
                                    exe_key: exe_k,
                                    remote_ip: Some(ip),
                                    is_remove: true,
                                    is_startup_preemptive: false,
                                    newly_required: false,
                                    source_rule_ids: blocking_rule_ids,
                                    domain_hints: matched_doms,
                                    error: err,
                                });
                            }
                        }
                    }
                }
            }
            (rep, fw.has_domain_network_rules())
        };
        self.outbound_classifier
            .set_has_domain_rules(has_domain_rules);
        report
    }

    pub(super) fn compensate_failed_wfp_report(&self, report: &WfpReconcileReport) {
        if !report.promoted_backups.is_empty() {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            fw.restore_promoted_filter_states(&report.promoted_backups);
        }
        let _ = self.deploy_persisted_network_rules();
        if !report.removed_domain_filters.is_empty() {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            fw.restore_removed_domain_filters(&report.removed_domain_filters, &*self.defense);
        }
    }

    /// Validates (`L-04`, `AUTO-02`) and persists an allowlist/blocklist rule via SQLite, then
    /// immediately reconciles live WFP filters when either the previous or new scope is a
    /// firewall scope (`NetworkBlock` / `NetworkAllow`).
    ///
    /// On target-relevant live WFP synchronization failure, restores the prior SQLite rule state,
    /// restores promoted/removed WFP filters, re-reconciles WFP, and returns
    /// [`PolicyRuleError::FirewallSync`] (`#4`, `Thread 10`, `Thread 18`).
    /// When an existing rule moves OUT of a network scope (`Analysis #7`), re-evaluates
    /// pre-emptive restrictions for all active executables.
    pub fn upsert_policy_rule(
        &self,
        rule: &AllowlistRuleRecord,
    ) -> Result<WfpReconcileReport, PolicyRuleError> {
        validate_policy_rule(rule).map_err(PolicyRuleError::Invalid)?;
        let _policy_guard = self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
        let previous = self.store.get_rule(&rule.rule_id)?;
        let previous_was_network = previous
            .as_ref()
            .is_some_and(|r| matches!(r.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow));
        let new_is_network = matches!(rule.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow);
        let prev_network_rules =
            (self.config.outbound_firewall_enabled && (previous_was_network || new_is_network))
                .then(|| self.store.list_network_rules())
                .transpose()?;

        self.store.upsert_rule(rule)?;
        if let Some(ref prev_rules) = prev_network_rules {
            let report = self.deploy_persisted_network_rules_with_baseline(Some(prev_rules));
            let mut affected: Vec<&AllowlistRuleRecord> = Vec::with_capacity(2);
            if new_is_network {
                affected.push(rule);
            }
            if let Some(ref prev) = previous {
                if previous_was_network {
                    affected.push(prev);
                }
            }
            if let Some(err_summary) = report.failure_summary_for_rules(&affected) {
                let comp_res = match previous {
                    Some(ref prev) => self.store.upsert_rule(prev),
                    None => self.store.delete_rule(&rule.rule_id).map(|_| ()),
                };
                if let Err(comp_err) = comp_res {
                    tracing::warn!(
                        rule_id = %rule.rule_id,
                        error = %comp_err,
                        "failed compensating SQLite after WFP sync failure in upsert_policy_rule"
                    );
                } else {
                    self.compensate_failed_wfp_report(&report);
                    if previous_was_network {
                        let active_exes = self
                            .process_table
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .active_exe_paths();
                        for exe in active_exes {
                            self.maybe_apply_preemptive_wfp_block(&exe);
                        }
                    }
                }
                return Err(PolicyRuleError::FirewallSync(err_summary));
            }

            self.invalidate_non_protected_steady_pids();
            if previous_was_network {
                let active_exes = self
                    .process_table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .active_exe_paths();
                for exe in active_exes {
                    self.maybe_apply_preemptive_wfp_block(&exe);
                }
            }
            Ok(report)
        } else {
            Ok(WfpReconcileReport::default())
        }
    }

    /// Deletes a policy rule from SQLite and immediately reconciles live WFP filters (including
    /// restoring any shadowed `NetworkAllow` or re-applying pre-emptive restrictions for active
    /// high-risk/script processes).
    ///
    /// On target-relevant live WFP synchronization failure, re-inserts the deleted rule into
    /// SQLite, restores promoted/removed WFP filters, re-reconciles WFP, and returns
    /// [`PolicyRuleError::FirewallSync`] (`#4`, `Thread 10`, `Thread 18`).
    pub fn delete_policy_rule(
        &self,
        rule_id: &str,
    ) -> Result<(bool, WfpReconcileReport), PolicyRuleError> {
        let _policy_guard = self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
        let existing = self.store.get_rule(rule_id)?;
        let existing_is_network = existing.as_ref().is_some_and(|r| {
            matches!(r.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow)
        });
        let prev_network_rules = (self.config.outbound_firewall_enabled && existing_is_network)
            .then(|| self.store.list_network_rules())
            .transpose()?;
        let deleted = self.store.delete_rule(rule_id)?;
        if deleted {
            if let Some(ref prev_rules) = prev_network_rules {
                let report = self.deploy_persisted_network_rules_with_baseline(Some(prev_rules));
                let err_summary = existing
                    .as_ref()
                    .and_then(|prev| report.failure_summary_for_rules(&[prev]));
                if let Some(err_summary) = err_summary {
                    if let Some(ref prev) = existing {
                        if let Err(comp_err) = self.store.upsert_rule(prev) {
                            tracing::warn!(
                                rule_id = %rule_id,
                                error = %comp_err,
                                "failed compensating SQLite after WFP sync failure in delete_policy_rule"
                            );
                        } else {
                            self.compensate_failed_wfp_report(&report);
                        }
                    }
                    return Err(PolicyRuleError::FirewallSync(err_summary));
                }
                self.invalidate_non_protected_steady_pids();
                let active_exes = self
                    .process_table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .active_exe_paths();
                for exe in active_exes {
                    self.maybe_apply_preemptive_wfp_block(&exe);
                }
                return Ok((true, report));
            }
        }
        Ok((deleted, WfpReconcileReport::default()))
    }

    /// Returns the number of live WFP dynamic rule handles currently tracked by the daemon.
    pub fn active_wfp_rule_count(&self) -> usize {
        self.firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_filter_count()
    }

    /// Returns `true` if the daemon currently tracks an active WFP filter for
    /// `(exe_path, remote_ip, allow)`.
    pub fn has_active_wfp_filter(
        &self,
        exe_path: &str,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> bool {
        self.firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_active_filter(exe_path, remote_ip, allow)
    }
}
