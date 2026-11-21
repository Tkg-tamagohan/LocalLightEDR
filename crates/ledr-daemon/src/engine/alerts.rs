use std::collections::HashSet;
use std::net::IpAddr;

use ledr_proto::{
    AlertDecision, AlertRecord, AlertStatus, AllowlistRuleRecord, ProcessIdentity, RuleScope,
};
use ledr_rules::{
    matches_app_wide_network_block, matches_network_block_rule, matches_network_target,
    matches_path_pattern, parse_cidr_target, BinaryIdentity, OutboundDecision,
};
use uuid::Uuid;

use crate::firewall::{parse_literal_target_ip, WfpReconcileReport, WfpRuleManager};

use super::domain_policy::{
    extend_authorizing_hints_from_existing_permit, partition_permit_hints,
    select_outbound_decision_for_domains,
};
use super::{current_unix_ms, DaemonEngine, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS};

/// Outcome of a successful [`DaemonEngine::resolve_alert_with_outcome`] call.
#[derive(Debug)]
pub struct ResolvedAlertOutcome {
    /// The alert after its status transition.
    pub alert: AlertRecord,
    /// `rule_id` of the allowlist/block rule persisted by this decision, or `None`
    /// when no rule was stored (e.g. `AllowOnce`, or `add_block_rule` requested but
    /// the executable path could not be resolved — `ANALYSIS_0001`).
    pub saved_rule_id: Option<String>,
}

impl DaemonEngine {
    /// Applies a user triage decision (`AllowOnce`, `AllowPermanent`, `TerminateAndBlock`)
    /// to an unresolved (`Pending` or `ExpiredSuspended`) alert (`L-04`, `L-07`).
    pub fn resolve_alert(
        &self,
        alert_id: &str,
        decision: AlertDecision,
    ) -> Result<AlertRecord, String> {
        self.resolve_alert_with_outcome(alert_id, decision)
            .map(|outcome| outcome.alert)
    }

    /// Like [`DaemonEngine::resolve_alert`], additionally reporting whether the
    /// requested allowlist/block rule was actually persisted (`ANALYSIS_0001`).
    pub fn resolve_alert_with_outcome(
        &self,
        alert_id: &str,
        decision: AlertDecision,
    ) -> Result<ResolvedAlertOutcome, String> {
        let _resolve_guard = self.resolve_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut saved_rule_id: Option<String> = None;
        let mut alert = self
            .store
            .get_alert(alert_id)
            .map_err(|err| format!("failed to query alert {alert_id}: {err}"))?
            .ok_or_else(|| format!("alert {alert_id} not found"))?;

        if !alert.status.is_unresolved() {
            return Err(format!(
                "alert {alert_id} is already resolved ({})",
                alert.status.as_db_str()
            ));
        }

        if alert.source_layer == "LAYER_4_BROWSER" && alert.process_instance_id.is_none() {
            let now_ms = current_unix_ms();
            return match decision {
                AlertDecision::AllowOnce
                | AlertDecision::TerminateAndBlock {
                    add_block_rule: false,
                } => {
                    let new_status = decision.resulting_status();
                    let updated = self
                        .store
                        .update_alert_status(alert_id, new_status, Some(now_ms))
                        .map_err(|err| format!("failed to update alert status: {err}"))?;
                    if !updated {
                        return Err(format!("alert {alert_id} not found"));
                    }
                    alert.status = new_status;
                    alert.resolved_at_ms = Some(now_ms);
                    Ok(ResolvedAlertOutcome {
                        alert,
                        saved_rule_id: None,
                    })
                }
                AlertDecision::AllowPermanent { .. } => Err(format!(
                    "LAYER_4_BROWSER alert {alert_id} has no associated process and cannot create a permanent rule"
                )),
                AlertDecision::TerminateAndBlock {
                    add_block_rule: true,
                } => Err(format!(
                    "LAYER_4_BROWSER alert {alert_id} has no associated process and cannot create a block rule"
                )),
            };
        }

        let ctx_val: serde_json::Value =
            serde_json::from_str(&alert.context_json).unwrap_or(serde_json::Value::Null);

        let identity = alert
            .process_instance_id
            .as_deref()
            .and_then(ProcessIdentity::from_instance_id)
            .filter(|id| id.create_time_100ns != 0);

        let mut seen_own_children = HashSet::new();
        let mut own_suspended_children = Vec::new();
        collect_suspended_children_from_ctx(
            &ctx_val,
            if alert.process_suspended {
                identity
            } else {
                None
            },
            &mut seen_own_children,
            &mut own_suspended_children,
        );

        let mut seen_children = seen_own_children;
        let mut suspended_children = own_suspended_children.clone();
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            if let Ok(all_alerts) = self.store.list_alerts_for_process(proc_inst_id, false, 1000) {
                for other in all_alerts {
                    if other.alert_id != alert_id {
                        if let Ok(other_ctx) =
                            serde_json::from_str::<serde_json::Value>(&other.context_json)
                        {
                            collect_suspended_children_from_ctx(
                                &other_ctx,
                                identity,
                                &mut seen_children,
                                &mut suspended_children,
                            );
                        }
                    }
                }
            }
        }

        let mut exe_path = json_non_empty_str(&ctx_val, "/exe_path")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/ProcessStart/exe_path"))
            .or_else(|| {
                alert
                    .process_instance_id
                    .as_deref()
                    .and_then(|inst_id| {
                        self.process_table
                            .lock()
                            .ok()
                            .and_then(|t| t.get_by_instance_id(inst_id).map(|e| e.exe_path.clone()))
                    })
                    .filter(|s| !s.trim().is_empty())
            });
        if exe_path.is_none() {
            if let Some(ref inst_id) = alert.process_instance_id {
                if let Ok(snap) = self.store.query_flight_recorder(1, Some(inst_id)) {
                    exe_path = snap
                        .processes
                        .into_iter()
                        .next()
                        .map(|p| p.exe_path)
                        .filter(|s| !s.trim().is_empty());
                }
            }
        }

        let mut sha256 = json_non_empty_str(&ctx_val, "/sha256");
        let mut signer_subject = json_non_empty_str(&ctx_val, "/signer_subject");
        let mut root_thumbprint = json_non_empty_str(&ctx_val, "/root_thumbprint")
            .filter(|tp| !tp.trim().is_empty() && !tp.trim().chars().all(|c| c == '0'));

        if (sha256.is_none() || (signer_subject.is_some() && root_thumbprint.is_none()))
            && exe_path.is_some()
        {
            if let Some(ref exe) = exe_path {
                let inspected = self.inspector.inspect(exe);
                if sha256.is_none() {
                    sha256 = inspected.sha256;
                }
                if signer_subject.is_none() || root_thumbprint.is_none() {
                    if let Some(auth) = inspected.authenticode {
                        if signer_subject.is_none() {
                            signer_subject = Some(auth.signer_subject);
                        }
                        if root_thumbprint.is_none() {
                            let tp = auth.root_thumbprint.trim();
                            if !tp.is_empty() && !tp.chars().all(|c| c == '0') {
                                root_thumbprint = Some(auth.root_thumbprint);
                            }
                        }
                    }
                }
            }
        }

        let now_ms = current_unix_ms();
        let new_status = decision.resulting_status();
        let is_terminate = matches!(decision, AlertDecision::TerminateAndBlock { .. });
        let is_network_alert = alert.source_layer == "LAYER_3_NETWORK"
            || ctx_val.pointer("/event/NetworkConnect").is_some();
        let alert_dst_ip: Option<IpAddr> = json_non_empty_str(&ctx_val, "/dst_ip")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/NetworkConnect/dst_ip"))
            .and_then(|s| s.parse::<IpAddr>().ok());
        let alert_domain_hint = json_non_empty_str(&ctx_val, "/domain_hint")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/NetworkConnect/domain_hint"));

        let mut lifted_wfp_block = None;
        let mut rebind_alert_exe: Option<String> = None;
        let mut displaced_bound_alerts: Vec<String> = Vec::new();
        let mut marked_once_allowed_procs: Vec<String> = Vec::new();
        let mut applied_wfp_report: Option<WfpReconcileReport> = None;

        match decision {
            AlertDecision::AllowOnce => {
                if is_network_alert && self.config.outbound_firewall_enabled {
                    if let Some(ref exe) = exe_path {
                        let block_check_domains: Vec<String> = if let Some(dst_ip) = alert_dst_ip {
                            let exe_k = WfpRuleManager::exe_key(exe);
                            let mut doms: Vec<String> = Vec::new();
                            if let Some(hint) = alert_domain_hint
                                .as_deref()
                                .map(str::trim)
                                .map(|s| s.trim_end_matches('.'))
                                .filter(|s| !s.is_empty())
                            {
                                doms.push(hint.to_ascii_lowercase());
                            }
                            let history = self
                                .process_dns_history
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Some(inst_id) = alert.process_instance_id.as_deref() {
                                for (dom, _) in history.lookup_domains_for_process(inst_id, dst_ip)
                                {
                                    if !doms.iter().any(|existing| existing == &dom) {
                                        doms.push(dom);
                                    }
                                }
                            } else if let Some(cand_ids) = ctx_val
                                .pointer("/candidate_instance_ids")
                                .and_then(|v| v.as_array())
                            {
                                for raw_id in cand_ids {
                                    if let Some(inst_id) = raw_id.as_str() {
                                        for (dom, _) in history.lookup_fresh_domains_for_process(
                                            inst_id,
                                            dst_ip,
                                            alert.timestamp_ms,
                                            AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
                                        ) {
                                            if !doms.iter().any(|existing| existing == &dom) {
                                                doms.push(dom);
                                            }
                                        }
                                    }
                                }
                            }
                            for dom in history.domains_for_exe_ip(&exe_k, dst_ip) {
                                if !doms.iter().any(|existing| existing == &dom) {
                                    doms.push(dom);
                                }
                            }
                            doms
                        } else {
                            alert_domain_hint
                                .as_deref()
                                .map(str::trim)
                                .map(|s| s.trim_end_matches('.'))
                                .filter(|s| !s.is_empty())
                                .map(|s| vec![s.to_ascii_lowercase()])
                                .unwrap_or_default()
                        };
                        let has_persisted_block = self.has_matching_persisted_network_block(
                            exe,
                            alert_dst_ip,
                            &block_check_domains,
                        );
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        let (lifted, was_bound) = fw.lift_block_for_allow_once(
                            alert_id,
                            exe,
                            has_persisted_block,
                            &*self.defense,
                        )?;
                        lifted_wfp_block = lifted;
                        if was_bound {
                            rebind_alert_exe = Some(exe.clone());
                        }
                        if !has_persisted_block {
                            if let Some(ref proc_inst_id) = alert.process_instance_id {
                                fw.mark_once_allowed(proc_inst_id, exe);
                                marked_once_allowed_procs.push(proc_inst_id.clone());
                            } else if let Some(cand_ids) =
                                ctx_val.pointer("/candidate_instance_ids").and_then(|v| v.as_array())
                            {
                                let table = self
                                    .process_table
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                for raw_id in cand_ids {
                                    if let Some(inst_id) = raw_id.as_str() {
                                        if table
                                            .get_by_instance_id(inst_id)
                                            .is_some_and(|e| e.exited_at_ms.is_none())
                                        {
                                            fw.mark_once_allowed(inst_id, exe);
                                            marked_once_allowed_procs.push(inst_id.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if let Err(err) = self.resume_alert_targets_if_unblocked(
                    &alert,
                    identity,
                    &own_suspended_children,
                    &suspended_children,
                ) {
                    self.rollback_allow_once_wfp(
                        alert_id,
                        lifted_wfp_block.take(),
                        rebind_alert_exe.take(),
                        Vec::new(),
                        std::mem::take(&mut marked_once_allowed_procs),
                    );
                    return Err(err);
                }
            }
            AlertDecision::AllowPermanent {
                use_signer_if_available,
                allow_dest,
            } => {
                let exe = exe_path.clone().ok_or_else(|| {
                    format!("missing executable path to create allowlist rule for alert {alert_id}")
                })?;

                let scope = if is_network_alert {
                    RuleScope::NetworkAllow
                } else {
                    RuleScope::FileCanaryAllow
                };

                let valid_root_thumbprint = root_thumbprint
                    .filter(|tp| !tp.trim().is_empty() && !tp.trim().chars().all(|c| c == '0'));

                let (rule_sha256, rule_signer, rule_thumbprint) =
                    if use_signer_if_available
                        && signer_subject.is_some()
                        && valid_root_thumbprint.is_some()
                    {
                        (None, signer_subject, valid_root_thumbprint)
                    } else {
                        let hash = sha256.ok_or_else(|| {
                            format!(
                                "cannot create unsigned allowlist rule without SHA-256 digest for {exe} (L-04)"
                            )
                        })?;
                        (Some(hash), None, None)
                    };

                let rule = AllowlistRuleRecord {
                    rule_id: format!("RULE-ALLOW-{}", Uuid::new_v4()),
                    scope,
                    exe_path_pattern: exe.clone(),
                    sha256: rule_sha256,
                    signer_subject: rule_signer,
                    root_thumbprint: rule_thumbprint,
                    allowed_target: allow_dest
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    created_at_ms: now_ms,
                    created_by: "user_triage".to_string(),
                };

                let _policy_guard = self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                let prev_network_rules = (scope == RuleScope::NetworkAllow
                    && self.config.outbound_firewall_enabled)
                    .then(|| self.store.list_network_rules().unwrap_or_default());
                self.store
                    .upsert_rule(&rule)
                    .map_err(|err| format!("failed to store permanent allowlist rule: {err}"))?;
                saved_rule_id = Some(rule.rule_id.clone());

                if scope == RuleScope::NetworkAllow && self.config.outbound_firewall_enabled {
                    let release_res = {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.release_transient_containment_for_alert(
                            alert_id,
                            Some(&exe),
                            &*self.defense,
                        )
                    };
                    match release_res {
                        Ok((snap, was_bound)) => {
                            lifted_wfp_block = snap;
                            if was_bound {
                                rebind_alert_exe = Some(exe.clone());
                            }
                        }
                        Err(err) => {
                            self.rollback_saved_rule(&rule.rule_id);
                            return Err(err);
                        }
                    }

                    // Snapshot any remaining Preemptive/TransientContainment app-wide block and
                    // sibling alert bindings before reconciliation potentially replaces it with a
                    // PersistedPolicy Permit so a subsequent resume/status rollback can restore
                    // both the block and every displaced alert binding.
                    {
                        let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        let (snap, sibs) = fw.snapshot_app_block_and_bindings(&exe);
                        if lifted_wfp_block.is_none() {
                            lifted_wfp_block = snap;
                        }
                        displaced_bound_alerts = sibs;
                    }

                    let sync_res =
                        (|| -> Result<WfpReconcileReport, Box<(String, WfpReconcileReport)>> {
                            let report = self.deploy_persisted_network_rules_with_baseline(
                                prev_network_rules.as_deref(),
                            );
                            if let Some(summary) = report.failure_summary_for_rules(&[&rule]) {
                                return Err(Box::new((
                                    format!(
                                        "failed synchronizing WFP firewall rule for NetworkAllow {}: {}",
                                        rule.rule_id, summary
                                    ),
                                    report,
                                )));
                            }

                            // If the user allowed a domain/CIDR target (not a literal IP) for an exe
                            // that still has a pre-emptive app-wide block, evaluate all known
                            // candidate domains (including exe-wide active DNS records sharing
                            // `dst_ip`) via the shared priority helper (`#2`) and install a
                            // DomainPolicy IP-specific Permit carrying known domain hints so
                            // traffic flows upon resume and survives unrelated reconciliations while
                            // respecting deny-overrides-allow across every candidate domain.
                            if let (Some(target_pat), Some(dst_ip)) =
                                (rule.allowed_target.as_deref(), alert_dst_ip)
                            {
                                if parse_literal_target_ip(target_pat).is_none() {
                                    let exe_k = WfpRuleManager::exe_key(&exe);
                                    let mut domain_candidates: Vec<(String, i64)> = Vec::new();
                                    if let Some(hint) = alert_domain_hint
                                        .as_deref()
                                        .map(str::trim)
                                        .map(|s| s.trim_end_matches('.'))
                                        .filter(|s| !s.is_empty())
                                    {
                                        domain_candidates.push((hint.to_ascii_lowercase(), now_ms));
                                    }
                                    let exe_domains: Vec<String> = {
                                        let history = self
                                            .process_dns_history
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        if let Some(inst_id) = alert.process_instance_id.as_deref()
                                        {
                                            for (dom, ts) in
                                                history.lookup_domains_for_process(inst_id, dst_ip)
                                            {
                                                if !domain_candidates
                                                    .iter()
                                                    .any(|(existing, _)| existing == &dom)
                                                {
                                                    domain_candidates.push((dom, ts));
                                                }
                                            }
                                        } else if let Some(cand_ids) = ctx_val
                                            .pointer("/candidate_instance_ids")
                                            .and_then(|v| v.as_array())
                                        {
                                            for raw_id in cand_ids {
                                                if let Some(inst_id) = raw_id.as_str() {
                                                    for (dom, ts) in history
                                                        .lookup_domains_for_process(inst_id, dst_ip)
                                                    {
                                                        if !domain_candidates
                                                            .iter()
                                                            .any(|(existing, _)| existing == &dom)
                                                        {
                                                            domain_candidates.push((dom, ts));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        history.domains_for_exe_ip(&exe_k, dst_ip)
                                    };
                                    let target_matches = matches_network_target(
                                        target_pat,
                                        dst_ip,
                                        None,
                                    ) || domain_candidates.iter().any(|(dom, _)| {
                                        matches_network_target(
                                            target_pat,
                                            dst_ip,
                                            Some(dom.as_str()),
                                        )
                                    }) || exe_domains.iter().any(|dom| {
                                        matches_network_target(
                                            target_pat,
                                            dst_ip,
                                            Some(dom.as_str()),
                                        )
                                    });
                                    if target_matches {
                                        let mut eval_candidates = domain_candidates.clone();
                                        for dom in &exe_domains {
                                            if !eval_candidates
                                                .iter()
                                                .any(|(existing, _)| existing == dom)
                                            {
                                                eval_candidates.push((dom.clone(), 0));
                                            }
                                        }
                                        let current_rules =
                                            self.store.list_network_rules().unwrap_or_default();
                                        let bin_identity = self.inspector.inspect(&exe);
                                        let (decision, _) = select_outbound_decision_for_domains(
                                            &bin_identity,
                                            dst_ip,
                                            &eval_candidates,
                                            &current_rules,
                                        );
                                        if matches!(decision, OutboundDecision::AllowedByRule { .. })
                                        {
                                            let mut known_domains: Vec<String> = domain_candidates
                                                .into_iter()
                                                .map(|(dom, _)| dom)
                                                .collect();
                                            for dom in exe_domains {
                                                if !known_domains
                                                    .iter()
                                                    .any(|existing| existing == &dom)
                                                {
                                                    known_domains.push(dom);
                                                }
                                            }
                                            let (mut authorizing_hints, cohosted_hints) =
                                                partition_permit_hints(
                                                    &bin_identity,
                                                    dst_ip,
                                                    &known_domains,
                                                    &current_rules,
                                                );
                                            if authorizing_hints.is_empty()
                                                && cohosted_hints.is_empty()
                                            {
                                                let fallback_domain = (parse_cidr_target(target_pat)
                                                    .is_err()
                                                    && !matches_network_target(
                                                        target_pat, dst_ip, None,
                                                    ))
                                                .then_some(target_pat);
                                                if let Some(dom) = fallback_domain {
                                                    authorizing_hints.push(dom.to_string());
                                                }
                                            }
                                            let mut fw = self
                                                .firewall
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            if fw.active_app_block(&exe).is_some() {
                                                extend_authorizing_hints_from_existing_permit(
                                                    &fw,
                                                    &exe,
                                                    dst_ip,
                                                    &bin_identity,
                                                    &current_rules,
                                                    &mut authorizing_hints,
                                                );
                                                let permit_res = fw
                                                    .ensure_ip_permit_for_domain_hints_prioritized(
                                                        &exe,
                                                        dst_ip,
                                                        &authorizing_hints,
                                                        &cohosted_hints,
                                                        &*self.defense,
                                                    );
                                                if let Err(err) = permit_res {
                                                    return Err(Box::new((
                                                        format!(
                                                            "failed installing IP permit for domain-scoped NetworkAllow {}: {err}",
                                                            rule.rule_id
                                                        ),
                                                        report,
                                                    )));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(report)
                        })();

                    match sync_res {
                        Ok(report) => applied_wfp_report = Some(report),
                        Err(boxed) => {
                            let (err, failed_report) = *boxed;
                            self.rollback_saved_rule(&rule.rule_id);
                            self.compensate_failed_wfp_report(&failed_report);
                            self.maybe_apply_preemptive_wfp_block(&exe);
                            self.rollback_allow_once_wfp(
                                alert_id,
                                lifted_wfp_block.take(),
                                rebind_alert_exe.take(),
                                std::mem::take(&mut displaced_bound_alerts),
                                Vec::new(),
                            );
                            return Err(err);
                        }
                    }
                    self.invalidate_non_protected_steady_pids();
                }
                drop(_policy_guard);

                if let Err(err) = self.resume_alert_targets_if_unblocked(
                    &alert,
                    identity,
                    &own_suspended_children,
                    &suspended_children,
                ) {
                    {
                        let _policy_guard =
                            self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                        self.rollback_saved_rule(&rule.rule_id);
                        if scope == RuleScope::NetworkAllow && self.config.outbound_firewall_enabled
                        {
                            // Reconcile first so any newly added PersistedPolicy/DomainPolicy
                            // Permit is removed, then restore any promoted/removed filter state and
                            // re-arm any Preemptive Block BEFORE rebinding `alert_id`.
                            if let Some(rep) = applied_wfp_report.take() {
                                self.compensate_failed_wfp_report(&rep);
                            } else {
                                let _ = self.deploy_persisted_network_rules();
                            }
                            self.maybe_apply_preemptive_wfp_block(&exe);
                        }
                    }
                    self.rollback_allow_once_wfp(
                        alert_id,
                        lifted_wfp_block.take(),
                        rebind_alert_exe.take(),
                        std::mem::take(&mut displaced_bound_alerts),
                        Vec::new(),
                    );
                    return Err(err);
                }
            }
            AlertDecision::TerminateAndBlock { add_block_rule } => {
                if let Some(ident) = identity {
                    if let Err(err) = self.defense.terminate_process(&ident, true) {
                        if is_protected_process_refusal(&err) {
                            return Err(err);
                        }
                        // A suspended alert tolerates the target already being gone: a
                        // previous attempt may have terminated the process and then
                        // failed the status update (rolling back the block rule), so a
                        // retry must reach the rule save instead of erroring again.
                        // A failure on a still-running process stays fatal.
                        if alert.process_suspended && !is_process_gone_or_replaced(&err, ident.pid) {
                            for child in &suspended_children {
                                let _ = self.defense.terminate_process(child, true);
                            }
                            return Err(err);
                        }
                        tracing::warn!(
                            alert_id = %alert_id,
                            pid = ident.pid,
                            error = %err,
                            "terminate_process failed (target already terminated or PID reused); continuing block rule and alert resolution"
                        );
                    }
                } else if alert.process_suspended {
                    return Err(format!(
                        "missing process identity to terminate suspended alert {alert_id}"
                    ));
                }

                // Attempt every recorded child and defer the first real failure: a live
                // or unverifiable child keeps the alert unresolved, but remaining
                // descendants must still get their terminate attempt — once the parent
                // is gone, a recorded identifier is the only way to reach them.
                let mut child_terminate_err: Option<String> = None;
                for child in &suspended_children {
                    match self.defense.terminate_process(child, true) {
                        Ok(()) => {}
                        Err(err)
                            if is_protected_process_refusal(&err)
                                || !is_process_gone_or_replaced(&err, child.pid) =>
                        {
                            child_terminate_err.get_or_insert(err);
                        }
                        Err(err) => {
                            // Only tolerate a child confirmed gone or PID-reused
                            // (`BUG_0001`).
                            tracing::warn!(
                                alert_id = %alert_id,
                                child_pid = child.pid,
                                error = %err,
                                "terminate_process failed for suspended child (already exited); continuing"
                            );
                        }
                    }
                }
                if let Some(err) = child_terminate_err {
                    return Err(err);
                }

                if add_block_rule {
                    if let Some(exe) = exe_path.clone() {
                        let block_rule = AllowlistRuleRecord {
                            rule_id: format!("RULE-BLOCK-{}", Uuid::new_v4()),
                            scope: RuleScope::NetworkBlock,
                            exe_path_pattern: exe,
                            sha256,
                            signer_subject: None,
                            root_thumbprint: None,
                            allowed_target: None,
                            created_at_ms: now_ms,
                            created_by: "user_quarantine".to_string(),
                        };
                        let _policy_guard =
                            self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                        let prev_network_rules = self
                            .config
                            .outbound_firewall_enabled
                            .then(|| self.store.list_network_rules().unwrap_or_default());
                        self.store
                            .upsert_rule(&block_rule)
                            .map_err(|err| format!("failed to store block rule: {err}"))?;
                        saved_rule_id = Some(block_rule.rule_id.clone());
                        if self.config.outbound_firewall_enabled {
                            let report = self.deploy_persisted_network_rules_with_baseline(
                                prev_network_rules.as_deref(),
                            );
                            if let Some(summary) = report.failure_summary_for_rules(&[&block_rule]) {
                                self.rollback_saved_rule(&block_rule.rule_id);
                                self.compensate_failed_wfp_report(&report);
                                return Err(format!(
                                    "failed synchronizing WFP firewall rule for NetworkBlock {}: {summary}",
                                    block_rule.rule_id
                                ));
                            }
                            applied_wfp_report = Some(report);
                            self.invalidate_non_protected_steady_pids();
                        }
                    }
                } else if is_network_alert && self.config.outbound_firewall_enabled {
                    let release_res = {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.release_transient_containment_for_alert(
                            alert_id,
                            exe_path.as_deref(),
                            &*self.defense,
                        )
                    };
                    if let Err(err) = release_res {
                        tracing::warn!(
                            alert_id = %alert_id,
                            error = %err,
                            "best-effort transient WFP release after terminate without block failed"
                        );
                    }
                    if let Some(ref exe) = exe_path {
                        let target_key = WfpRuleManager::exe_key(exe);
                        let still_active = self
                            .process_table
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .has_active_exe_key(&target_key);
                        if !still_active {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            fw.remove_preemptive_block_if_unused(exe, &*self.defense);
                        }
                    }
                }
            }
        }

        let status_result = self
            .store
            .update_alert_status(alert_id, new_status, Some(now_ms))
            .map_err(|err| format!("failed to update alert status: {err}"))
            .and_then(|updated| {
                if updated {
                    Ok(())
                } else {
                    Err(format!("alert {alert_id} not found"))
                }
            });
        if let Err(err) = status_result {
            if let Some(rule_id) = saved_rule_id.take() {
                let _policy_guard = self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                self.rollback_saved_rule(&rule_id);
                if self.config.outbound_firewall_enabled {
                    if let Some(rep) = applied_wfp_report.take() {
                        self.compensate_failed_wfp_report(&rep);
                    } else {
                        let _ = self.deploy_persisted_network_rules();
                    }
                }
            }
            if is_network_alert && self.config.outbound_firewall_enabled {
                if let Some(ref exe) = exe_path {
                    self.maybe_apply_preemptive_wfp_block(exe);
                }
            }
            self.rollback_allow_once_wfp(
                alert_id,
                lifted_wfp_block.take(),
                rebind_alert_exe.take(),
                std::mem::take(&mut displaced_bound_alerts),
                std::mem::take(&mut marked_once_allowed_procs),
            );
            return Err(err);
        }

        if is_network_alert {
            if let (Some(ref exe), Some(dst_ip)) = (&exe_path, alert_dst_ip) {
                self.app_wfp_alert_dedup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_key(&WfpRuleManager::exe_key(exe), dst_ip);
            }
        }
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            self.clear_alert_dedup_from_context_val(proc_inst_id, &alert.source_layer, &ctx_val);
            if is_terminate {
                self.resolve_sibling_alerts_as_terminated(alert_id, proc_inst_id, now_ms);
            }
        }

        alert.status = new_status;
        alert.resolved_at_ms = Some(now_ms);
        Ok(ResolvedAlertOutcome {
            alert,
            saved_rule_id,
        })
    }

    /// Inspects all other unresolved suspended alerts to collect unresolved sibling alerts still
    /// holding `process_instance_id` suspended as a parent, along with every specific
    /// [`ProcessIdentity`] still held suspended (as parent or in `suspended_children`) by another
    /// unresolved alert.
    fn other_unresolved_containment(
        &self,
        alert_id: &str,
        process_instance_id: Option<&str>,
    ) -> Result<(Vec<AlertRecord>, HashSet<ProcessIdentity>), String> {
        let unresolved = self
            .store
            .list_unresolved_suspended_alerts()
            .map_err(|err| format!("failed to query unresolved alerts: {err}"))?;

        let mut parent_holding_siblings = Vec::new();
        let mut other_held_identities = HashSet::new();

        for other in unresolved {
            if other.alert_id == alert_id {
                continue;
            }
            let other_parent = other
                .process_instance_id
                .as_deref()
                .and_then(ProcessIdentity::from_instance_id)
                .filter(|id| id.create_time_100ns != 0);

            let holds_target_parent = other.process_suspended
                && matches!(
                    (process_instance_id, other.process_instance_id.as_deref()),
                    (Some(target_proc), Some(other_proc)) if target_proc == other_proc
                );

            if other.process_suspended {
                if let Some(id) = other_parent {
                    other_held_identities.insert(id);
                }
            }

            if let Ok(other_ctx) = serde_json::from_str::<serde_json::Value>(&other.context_json) {
                let mut other_children = Vec::new();
                collect_suspended_children_from_ctx(
                    &other_ctx,
                    if other.process_suspended {
                        other_parent
                    } else {
                        None
                    },
                    &mut other_held_identities,
                    &mut other_children,
                );
            }

            if holds_target_parent {
                parent_holding_siblings.push(other);
            }
        }

        if !parent_holding_siblings.is_empty() {
            tracing::info!(
                alert_id = %alert_id,
                process_instance_id = process_instance_id.unwrap_or("<none>"),
                sibling_count = parent_holding_siblings.len(),
                "keeping process suspended because another unresolved suspended alert exists"
            );
        }

        Ok((parent_holding_siblings, other_held_identities))
    }

    /// Transfers deferred `suspended_children` from an alert being allowed onto unresolved sibling
    /// alert(s) that still hold the same parent suspended, so neither a subsequent shutdown
    /// (`list_unresolved_suspended_alerts`) nor a post-partial-shutdown allow on the surviving
    /// sibling can orphan frozen children.
    fn transfer_deferred_suspended_children(
        &self,
        source_alert_id: &str,
        parent_holding_siblings: &[AlertRecord],
        deferred_children: &[ProcessIdentity],
    ) -> Result<(), String> {
        if deferred_children.is_empty() {
            return Ok(());
        }

        let mut adopted_count = 0usize;
        let mut last_err: Option<String> = None;

        for sibling in parent_holding_siblings {
            let mut ctx_val = match serde_json::from_str::<serde_json::Value>(&sibling.context_json)
            {
                Ok(val) => val,
                Err(err) => {
                    last_err = Some(format!(
                        "sibling alert {} has invalid context_json: {err}",
                        sibling.alert_id
                    ));
                    continue;
                }
            };
            let Some(obj) = ctx_val.as_object_mut() else {
                last_err = Some(format!(
                    "sibling alert {} context_json is not a JSON object",
                    sibling.alert_id
                ));
                continue;
            };

            let mut merged_entries: Vec<serde_json::Value> = match obj.get("suspended_children") {
                Some(serde_json::Value::Array(arr)) => arr.clone(),
                None | Some(serde_json::Value::Null) => Vec::new(),
                Some(_) => {
                    last_err = Some(format!(
                        "sibling alert {} has non-array suspended_children field",
                        sibling.alert_id
                    ));
                    continue;
                }
            };

            let mut existing_ids: HashSet<ProcessIdentity> = merged_entries
                .iter()
                .filter_map(|v| v.as_str())
                .filter_map(ProcessIdentity::from_instance_id)
                .filter(|id| id.create_time_100ns != 0)
                .collect();

            let mut changed = false;
            for child in deferred_children {
                if existing_ids.insert(*child) {
                    merged_entries.push(serde_json::Value::String(child.instance_id()));
                    changed = true;
                }
            }

            if !changed {
                adopted_count += 1;
                continue;
            }

            obj.insert(
                "suspended_children".to_string(),
                serde_json::Value::Array(merged_entries),
            );
            match self.store.update_alert_suspension_state(
                &sibling.alert_id,
                sibling.process_suspended,
                &ctx_val.to_string(),
            ) {
                Ok(true) => {
                    adopted_count += 1;
                }
                Ok(false) => {
                    last_err = Some(format!(
                        "sibling alert {} disappeared while transferring suspended_children",
                        sibling.alert_id
                    ));
                }
                Err(err) => {
                    last_err = Some(format!(
                        "failed updating sibling alert {} suspended_children: {err}",
                        sibling.alert_id
                    ));
                }
            }
        }

        if adopted_count == 0 {
            return Err(format!(
                "failed to preserve {} deferred suspended child(ren) from alert {source_alert_id} onto unresolved sibling alert(s): {}",
                deferred_children.len(),
                last_err.unwrap_or_else(|| "no eligible unresolved sibling alert".to_string())
            ));
        }

        Ok(())
    }

    /// Resumes the parent and/or recorded `suspended_children` for `alert` on an allow decision
    /// (`AllowOnce` / `AllowPermanent`), handling parent and child suspension states
    /// independently so children left suspended after a partial shutdown resume are still
    /// resumed when `alert.process_suspended` is already `false`, while preserving containment
    /// required by any other unresolved suspended alert (including transferring deferred
    /// `suspended_children` onto surviving parent-holding sibling alerts).
    fn resume_alert_targets_if_unblocked(
        &self,
        alert: &AlertRecord,
        identity: Option<ProcessIdentity>,
        own_suspended_children: &[ProcessIdentity],
        all_suspended_children: &[ProcessIdentity],
    ) -> Result<(), String> {
        let alert_id = &alert.alert_id;
        let resume_parent = alert.process_suspended;
        let children_to_check: &[ProcessIdentity] = if resume_parent {
            all_suspended_children
        } else {
            own_suspended_children
        };

        if !resume_parent && children_to_check.is_empty() {
            return Ok(());
        }

        let parent_ident = if resume_parent {
            Some(identity.ok_or_else(|| {
                format!("missing process identity to resume suspended alert {alert_id}")
            })?)
        } else {
            None
        };

        let (parent_holding_siblings, other_held_identities) =
            self.other_unresolved_containment(alert_id, alert.process_instance_id.as_deref())?;

        if !parent_holding_siblings.is_empty() {
            let deferred_children: Vec<ProcessIdentity> = own_suspended_children
                .iter()
                .copied()
                .filter(|child| !other_held_identities.contains(child))
                .collect();
            self.transfer_deferred_suspended_children(
                alert_id,
                &parent_holding_siblings,
                &deferred_children,
            )?;
            return Ok(());
        }

        if let Some(ident) = parent_ident {
            if other_held_identities.contains(&ident) {
                tracing::info!(
                    alert_id = %alert_id,
                    pid = ident.pid,
                    create_time_100ns = ident.create_time_100ns,
                    "keeping parent suspended because another unresolved alert still holds its identity"
                );
            } else {
                self.resume_single_process(alert_id, &ident, false)?;
            }
        }

        for child in children_to_check {
            if other_held_identities.contains(child) {
                tracing::info!(
                    alert_id = %alert_id,
                    child_pid = child.pid,
                    child_create_time_100ns = child.create_time_100ns,
                    "keeping suspended child frozen because another unresolved alert still holds it"
                );
                continue;
            }
            self.resume_single_process(alert_id, child, true)?;
        }

        Ok(())
    }

    /// Best-effort rollback of a rule stored by a failed
    /// [`DaemonEngine::resolve_alert_with_outcome`] call so a rejected resume or status update
    /// cannot leave a permanent allow/block rule active (BUG_0001).
    fn rollback_saved_rule(&self, rule_id: &str) {
        if let Err(err) = self.store.delete_rule(rule_id) {
            tracing::warn!(
                rule_id = %rule_id,
                error = %err,
                "failed to roll back allowlist rule after resolve error"
            );
        }
    }

    fn resume_single_process(
        &self,
        alert_id: &str,
        ident: &ProcessIdentity,
        is_child: bool,
    ) -> Result<(), String> {
        if let Err(err) = self.defense.resume_process(ident) {
            if is_protected_process_refusal(&err) {
                return Err(err);
            }
            // BUG_0004: only swallow the failure when the target is actually gone
            // (exited or PID reused). A live process that failed to resume must keep
            // the alert unresolved so the operator can retry.
            if !is_process_gone_or_replaced(&err, ident.pid) {
                return if is_child {
                    Err(format!(
                        "resume_process failed for suspended child PID {} of alert {alert_id}: {err}",
                        ident.pid
                    ))
                } else {
                    Err(format!(
                        "resume_process failed for alert {alert_id} (PID {} still running): {err}",
                        ident.pid
                    ))
                };
            }
            if is_child {
                tracing::warn!(
                    alert_id = %alert_id,
                    child_pid = ident.pid,
                    error = %err,
                    "resume_process failed for suspended child (already exited); continuing"
                );
            } else {
                tracing::warn!(
                    alert_id = %alert_id,
                    pid = ident.pid,
                    error = %err,
                    "resume_process failed for parent (process already exited or PID reused); continuing child resume and alert resolution"
                );
            }
        }
        Ok(())
    }

    fn resolve_sibling_alerts_as_terminated(
        &self,
        resolved_alert_id: &str,
        proc_inst_id: &str,
        now_ms: i64,
    ) {
        let Ok(unresolved) = self.store.list_alerts_for_process(proc_inst_id, true, 1000) else {
            return;
        };
        for other in unresolved {
            if other.alert_id != resolved_alert_id {
                match self.store.update_alert_status(
                    &other.alert_id,
                    AlertStatus::TerminatedBlocked,
                    Some(now_ms),
                ) {
                    Ok(true) => {
                        let ctx: serde_json::Value = serde_json::from_str(&other.context_json)
                            .unwrap_or(serde_json::Value::Null);
                        self.clear_alert_dedup_from_context_val(
                            proc_inst_id,
                            &other.source_layer,
                            &ctx,
                        );
                        if other.source_layer == "LAYER_3_NETWORK"
                            && self.config.outbound_firewall_enabled
                        {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = fw.release_transient_containment_for_alert(
                                &other.alert_id,
                                json_non_empty_str(&ctx, "/exe_path").as_deref(),
                                &*self.defense,
                            );
                        }
                    }
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(
                            sibling_alert_id = %other.alert_id,
                            error = %err,
                            "failed to mark sibling alert as TerminatedBlocked"
                        );
                    }
                }
            }
        }
    }

    fn clear_alert_dedup_from_context_val(
        &self,
        instance_id: &str,
        source_layer: &str,
        ctx_val: &serde_json::Value,
    ) {
        if let (Some(category), Some(target_path)) = (
            json_non_empty_str(ctx_val, "/category"),
            json_non_empty_str(ctx_val, "/target_path"),
        ) {
            let dedup_key = format!(
                "CANARY:{}:{}",
                category.to_ascii_lowercase(),
                target_path.trim().replace('/', "\\").to_ascii_lowercase()
            );
            self.clear_rule_alert(instance_id, &dedup_key);
        }
        if source_layer == "LAYER_3_NETWORK" || ctx_val.pointer("/event/NetworkConnect").is_some() {
            self.clear_rule_alert(instance_id, super::outbound::NET_OUTBOUND_ENFORCE_DEDUP_KEY);
            self.clear_rule_alert(instance_id, super::outbound::NET_OUTBOUND_OBSERVE_DEDUP_KEY);
            self.clear_rule_alert(instance_id, "NET_POLICY_BLOCK");
        }
    }

    fn rollback_allow_once_wfp(
        &self,
        alert_id: &str,
        lifted_wfp_block: Option<crate::firewall::RemovedBlockSnapshot>,
        rebind_alert_exe: Option<String>,
        displaced_bound_alerts: Vec<String>,
        marked_once_allowed_procs: Vec<String>,
    ) {
        if lifted_wfp_block.is_none()
            && rebind_alert_exe.is_none()
            && displaced_bound_alerts.is_empty()
            && marked_once_allowed_procs.is_empty()
        {
            return;
        }
        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
        for proc_inst_id in marked_once_allowed_procs {
            fw.unmark_once_allowed(&proc_inst_id);
        }
        let rebind_self = rebind_alert_exe.is_some().then_some(alert_id);
        let sib_exe = lifted_wfp_block
            .as_ref()
            .map(|s| s.exe_path.clone())
            .or_else(|| rebind_alert_exe.clone());
        if let Some(snap) = lifted_wfp_block {
            fw.restore_lifted_block(rebind_self, snap, &*self.defense);
        } else if let Some(exe) = rebind_alert_exe {
            fw.bind_alert_to_app_block(alert_id, &exe);
        }
        if let Some(exe) = sib_exe {
            for sib_id in displaced_bound_alerts {
                fw.bind_alert_to_app_block(&sib_id, &exe);
            }
        }
    }

    fn has_matching_persisted_network_block(
        &self,
        exe_path: &str,
        dst_ip: Option<IpAddr>,
        domain_hints: &[String],
    ) -> bool {
        let rules = self
            .store
            .list_rules(Some(RuleScope::NetworkBlock))
            .unwrap_or_default();
        let matching_path: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
            })
            .collect();
        if matching_path.is_empty() {
            return false;
        }
        let needs_inspect = matching_path.iter().any(|r| {
            r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                || r.signer_subject
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
        });
        let identity = if needs_inspect {
            self.inspector.inspect(exe_path)
        } else {
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            }
        };
        matching_path.into_iter().any(|rule| match dst_ip {
            Some(ip) => {
                matches_network_block_rule(rule, &identity, ip, None)
                    || domain_hints.iter().any(|hint| {
                        let trimmed = hint.trim().trim_end_matches('.');
                        !trimmed.is_empty()
                            && matches_network_block_rule(rule, &identity, ip, Some(trimmed))
                    })
            }
            None => matches_app_wide_network_block(rule, &identity),
        })
    }
}

pub(super) fn collect_suspended_children_from_ctx(
    ctx_val: &serde_json::Value,
    parent_identity: Option<ProcessIdentity>,
    seen: &mut HashSet<ProcessIdentity>,
    out: &mut Vec<ProcessIdentity>,
) {
    if let Some(arr) = ctx_val.get("suspended_children").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(id) = item
                .as_str()
                .and_then(ProcessIdentity::from_instance_id)
                .filter(|id| id.create_time_100ns != 0 && Some(*id) != parent_identity)
            {
                if seen.insert(id) {
                    out.push(id);
                }
            }
        }
    }
}

pub(super) fn is_protected_process_refusal(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("refusing to act on") || lower.contains("never-suspend")
}

/// Returns `true` when a failed suspend/resume/terminate target is confirmed gone —
/// the snapshot positively reports the PID absent or its PID was reused (CreationTime
/// mismatch). Live processes and unverifiable states are genuine failures the caller
/// must surface (`BUG_0004`, `BUG_0002`).
pub(super) fn is_process_gone_or_replaced(err: &str, pid: u32) -> bool {
    tolerate_missing_target(err, ledr_sensor_win::defense::process_liveness(pid))
}

/// `true` only when the failed suspend/resume/terminate target is confirmed gone: a
/// `CreationTime mismatch` proves PID reuse, or the snapshot positively reports the
/// PID absent. An unconfirmed absence (`Unknown` — snapshot/enumeration failed) is NOT
/// tolerated, so the caller surfaces the error and the operation stays retryable
/// (`BUG_0002`).
pub(super) fn tolerate_missing_target(
    err: &str,
    liveness: ledr_sensor_win::defense::ProcessLiveness,
) -> bool {
    err.contains("CreationTime mismatch")
        || matches!(liveness, ledr_sensor_win::defense::ProcessLiveness::Gone)
}

fn json_non_empty_str(val: &serde_json::Value, pointer: &str) -> Option<String> {
    val.pointer(pointer)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
