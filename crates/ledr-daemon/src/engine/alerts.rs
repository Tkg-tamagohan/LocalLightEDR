use std::collections::HashSet;
use std::net::IpAddr;

use ledr_proto::{
    build_windows_apps_version_wildcard_pattern, AlertDecision, AlertRecord, AlertStatus,
    AllowPermanentPathMode, AllowlistRuleRecord, ProcessIdentity, RuleScope,
    ScopedPolicyRuleRecord,
};
use ledr_rules::{
    is_valid_app_container_sid, matches_app_wide_network_block, matches_network_block_rule,
    matches_network_target, matches_package_wide_network_block, matches_path_pattern,
    matches_scoped_network_block_rule, parse_cidr_target, validate_scoped_policy_rule,
    BinaryIdentity, OutboundDecision, ProcessScopeContext,
};
use uuid::Uuid;

use crate::firewall::{parse_literal_target_ip, WfpReconcileReport, WfpRuleManager};

use super::domain_policy::{
    extend_authorizing_hints_from_existing_permit, partition_permit_hints,
    select_outbound_decision_for_domains, select_outbound_decision_for_domains_with_scoped,
};
use super::{
    current_unix_ms, DaemonEngine, StoreWriteGate, WriteOpGuard, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
};

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
        self.resolve_alert_with_options_and_outcome(
            alert_id,
            decision,
            AllowPermanentPathMode::Exact,
        )
    }

    /// Like [`DaemonEngine::resolve_alert_with_outcome`], with explicit
    /// [`AllowPermanentPathMode`] control for `AllowPermanent` decisions.
    pub fn resolve_alert_with_options_and_outcome(
        &self,
        alert_id: &str,
        decision: AlertDecision,
        path_mode: AllowPermanentPathMode,
    ) -> Result<ResolvedAlertOutcome, String> {
        let _resolve_guard = self.resolve_lock.lock().unwrap_or_else(|e| e.into_inner());
        let write_guard = StoreWriteGate::enter_op(&self.store_write_gate)
            .ok_or_else(|| "daemon store writes closed for shutdown".to_string())?;
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

        if path_mode != AllowPermanentPathMode::Exact
            && !matches!(decision, AlertDecision::AllowPermanent { .. })
        {
            return Err(format!(
                "path_mode {:?} is only valid with AllowPermanent decision for alert {alert_id}",
                path_mode
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
                    let updated = write_guard
                        .write(&self.store, |s| {
                            s.update_alert_status(alert_id, new_status, Some(now_ms))
                        })
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
                            .and_then(|t| t.get_by_instance_id(inst_id).map(|e| e.exe_path.to_string()))
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

        let needs_wildcard_signer = path_mode == AllowPermanentPathMode::WindowsAppsVersionWildcard
            && (signer_subject.is_none() || root_thumbprint.is_none());
        if (sha256.is_none()
            || (signer_subject.is_some() && root_thumbprint.is_none())
            || needs_wildcard_signer)
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
                            let subj = auth.signer_subject.trim();
                            if !subj.is_empty() {
                                signer_subject = Some(subj.to_string());
                            }
                        }
                        if root_thumbprint.is_none() {
                            let tp = auth.root_thumbprint.trim();
                            if !tp.is_empty() && !tp.chars().all(|c| c == '0') {
                                root_thumbprint = Some(tp.to_string());
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
                    &write_guard,
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

                let valid_signer_subject = signer_subject
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let valid_root_thumbprint = root_thumbprint
                    .map(|tp| tp.trim().to_string())
                    .filter(|tp| !tp.is_empty() && !tp.chars().all(|c| c == '0'));

                let (exe_path_pattern, rule_sha256, rule_signer, rule_thumbprint) = match path_mode
                {
                    AllowPermanentPathMode::Exact => {
                        if use_signer_if_available
                            && valid_signer_subject.is_some()
                            && valid_root_thumbprint.is_some()
                        {
                            (exe.clone(), None, valid_signer_subject, valid_root_thumbprint)
                        } else {
                            let hash = sha256.ok_or_else(|| {
                                format!(
                                    "cannot create unsigned allowlist rule without SHA-256 digest for {exe} (L-04)"
                                )
                            })?;
                            (exe.clone(), Some(hash), None, None)
                        }
                    }
                    AllowPermanentPathMode::WindowsAppsVersionWildcard => {
                        if !use_signer_if_available {
                            return Err(format!(
                                "WindowsApps version wildcard rule for alert {alert_id} requires use_signer_if_available=true (L-04)"
                            ));
                        }
                        let signer = valid_signer_subject.ok_or_else(|| {
                            format!(
                                "cannot create WindowsApps version wildcard allowlist rule without verified Authenticode signer_subject for {exe} (L-04)"
                            )
                        })?;
                        let thumbprint = valid_root_thumbprint.ok_or_else(|| {
                            format!(
                                "cannot create WindowsApps version wildcard allowlist rule without non-zero root_thumbprint for {exe} (L-04)"
                            )
                        })?;
                        let pattern = build_windows_apps_version_wildcard_pattern(&exe)
                            .ok_or_else(|| {
                                format!(
                                    "executable path `{exe}` is not a valid WindowsApps package executable for version wildcard"
                                )
                            })?;
                        (pattern, None, Some(signer), Some(thumbprint))
                    }
                };

                let rule = AllowlistRuleRecord {
                    rule_id: format!("RULE-ALLOW-{}", Uuid::new_v4()),
                    scope,
                    exe_path_pattern,
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
                write_guard
                    .write(&self.store, |s| s.upsert_rule(&rule))
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
                            self.rollback_saved_rule(&write_guard, &rule.rule_id);
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
                            self.rollback_saved_rule(&write_guard, &rule.rule_id);
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
                    &write_guard,
                    &alert,
                    identity,
                    &own_suspended_children,
                    &suspended_children,
                ) {
                    {
                        let _policy_guard =
                            self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                        self.rollback_saved_rule(&write_guard, &rule.rule_id);
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
                self.terminate_alert_targets_for_resolution(
                    alert_id,
                    &alert,
                    identity,
                    &suspended_children,
                )?;

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
                        write_guard
                            .write(&self.store, |s| s.upsert_rule(&block_rule))
                            .map_err(|err| format!("failed to store block rule: {err}"))?;
                        saved_rule_id = Some(block_rule.rule_id.clone());
                        if self.config.outbound_firewall_enabled {
                            let report = self.deploy_persisted_network_rules_with_baseline(
                                prev_network_rules.as_deref(),
                            );
                            if let Some(summary) = report.failure_summary_for_rules(&[&block_rule]) {
                                self.rollback_saved_rule(&write_guard, &block_rule.rule_id);
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
                    self.release_transient_wfp_after_terminate_without_block(
                        alert_id,
                        exe_path.as_deref(),
                    );
                }
            }
        }

        let status_result = write_guard
            .write(&self.store, |s| {
                s.update_alert_status(alert_id, new_status, Some(now_ms))
            })
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
                self.rollback_saved_rule(&write_guard, &rule_id);
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
                let alert_pkg_sid = ctx_val.get("package_sid").and_then(|v| v.as_str());
                self.app_wfp_alert_dedup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_key(&WfpRuleManager::exe_key(exe), alert_pkg_sid, dst_ip);
            }
            if self.config.outbound_firewall_enabled {
                if let Some(ref exe) = exe_path {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    self.retry_deferred_preemptive_removal_locked(&mut fw, exe);
                }
            }
        }
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            self.clear_alert_dedup_from_context_val(proc_inst_id, &alert.source_layer, &ctx_val);
            if is_terminate {
                self.resolve_sibling_alerts_as_terminated(
                    &write_guard,
                    alert_id,
                    proc_inst_id,
                    now_ms,
                );
            }
        }

        alert.status = new_status;
        alert.resolved_at_ms = Some(now_ms);
        Ok(ResolvedAlertOutcome {
            alert,
            saved_rule_id,
        })
    }

    /// Resolves `alert_id` with optional package-level scoping (`FU-P4-03` Track B-2).
    ///
    /// When `scope_to_package` is `false`, delegates directly to
    /// [`Self::resolve_alert_with_options_and_outcome`] with [`AllowPermanentPathMode::Exact`].
    /// When `scope_to_package` is `true`:
    /// - `AllowPermanent` on Layer 3 requires `L-04` Authenticode signing, non-empty
    ///   `package_family_name`, and valid AppContainer `package_sid`, storing a
    ///   [`ScopedPolicyRuleRecord`] into `scoped_policy_rules` and synchronizing package-scoped WFP
    ///   filters with full compensation rollback on failure.
    /// - `TerminateAndBlock { add_block_rule: true }` stores a package-scoped `NetworkBlock` rule
    ///   only when `package_sid` is present; for non-AppContainer processes (including
    ///   `PFN_ONLY_NON_APPCONTAINER`), persistent block rule creation is skipped to prevent locking
    ///   out the shared host executable across all packages.
    pub fn resolve_alert_scoped_with_outcome(
        &self,
        alert_id: &str,
        decision: AlertDecision,
        scope_to_package: bool,
    ) -> Result<ResolvedAlertOutcome, String> {
        if !scope_to_package {
            return self.resolve_alert_with_options_and_outcome(
                alert_id,
                decision,
                AllowPermanentPathMode::Exact,
            );
        }

        let _resolve_guard = self.resolve_lock.lock().unwrap_or_else(|e| e.into_inner());
        let write_guard = StoreWriteGate::enter_op(&self.store_write_gate)
            .ok_or_else(|| "daemon store writes closed for shutdown".to_string())?;
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
                    let updated = write_guard
                        .write(&self.store, |s| {
                            s.update_alert_status(alert_id, new_status, Some(now_ms))
                        })
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
                            .and_then(|t| t.get_by_instance_id(inst_id).map(|e| e.exe_path.to_string()))
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

        if (sha256.is_none()
            || signer_subject.is_none()
            || root_thumbprint.is_none())
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
                            let subj = auth.signer_subject.trim();
                            if !subj.is_empty() {
                                signer_subject = Some(subj.to_string());
                            }
                        }
                        if root_thumbprint.is_none() {
                            let tp = auth.root_thumbprint.trim();
                            if !tp.is_empty() && !tp.chars().all(|c| c == '0') {
                                root_thumbprint = Some(tp.to_string());
                            }
                        }
                    }
                }
            }
        }

        let (pkg_pfn, pkg_sid) =
            self.resolve_alert_package_attributes(&ctx_val, alert.process_instance_id.as_deref());
        let valid_pkg_sid = pkg_sid
            .as_deref()
            .map(str::trim)
            .filter(|s| is_valid_app_container_sid(s))
            .map(str::to_string);

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
                        let scope_ctx = ProcessScopeContext {
                            package_family_name: pkg_pfn.as_deref(),
                            package_sid: valid_pkg_sid.as_deref(),
                            command_line: None,
                        };
                        let has_persisted_block = self
                            .has_matching_persisted_network_block_with_scoped(
                                exe,
                                &scope_ctx,
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
                    &write_guard,
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
                    format!("missing executable path to create scoped allowlist rule for alert {alert_id}")
                })?;
                let scope = if is_network_alert {
                    RuleScope::NetworkAllow
                } else if alert.source_layer == "LAYER_2_RULES" {
                    RuleScope::ProcessAllow
                } else {
                    RuleScope::FileCanaryAllow
                };

                let valid_signer_subject = signer_subject
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let valid_root_thumbprint = root_thumbprint
                    .map(|tp| tp.trim().to_string())
                    .filter(|tp| !tp.is_empty() && !tp.chars().all(|c| c == '0'));

                let (rule_sha256, rule_signer, rule_thumbprint, rule_pfn, rule_sid) =
                    if scope == RuleScope::NetworkAllow {
                        if !use_signer_if_available {
                            return Err(format!(
                                "package-scoped NetworkAllow for alert {alert_id} requires use_signer_if_available=true (FU-P4-03)"
                            ));
                        }
                        let signer = valid_signer_subject.ok_or_else(|| {
                            format!(
                                "cannot create package-scoped NetworkAllow without verified Authenticode signer_subject for {exe} (L-04, FU-P4-03)"
                            )
                        })?;
                        let thumbprint = valid_root_thumbprint.ok_or_else(|| {
                            format!(
                                "cannot create package-scoped NetworkAllow without non-zero root_thumbprint for {exe} (L-04, FU-P4-03)"
                            )
                        })?;
                        let pfn = pkg_pfn.clone().ok_or_else(|| {
                            format!(
                                "cannot create package-scoped NetworkAllow without non-empty package_family_name for alert {alert_id} (FU-P4-03)"
                            )
                        })?;
                        let sid = valid_pkg_sid.clone().ok_or_else(|| {
                            format!(
                                "cannot create package-scoped NetworkAllow without valid AppContainer package_sid for alert {alert_id} (FU-P4-03)"
                            )
                        })?;
                        (None, Some(signer), Some(thumbprint), Some(pfn), Some(sid))
                    } else {
                        if pkg_pfn.is_none() && valid_pkg_sid.is_none() {
                            return Err(format!(
                                "cannot create package-scoped {:?} rule without package_family_name or package_sid for alert {alert_id}",
                                scope
                            ));
                        }
                        if use_signer_if_available
                            && valid_signer_subject.is_some()
                            && valid_root_thumbprint.is_some()
                        {
                            (
                                None,
                                valid_signer_subject,
                                valid_root_thumbprint,
                                pkg_pfn.clone(),
                                valid_pkg_sid.clone(),
                            )
                        } else {
                            let hash = sha256.ok_or_else(|| {
                                format!(
                                    "cannot create unsigned scoped allowlist rule without SHA-256 digest for {exe} (L-04)"
                                )
                            })?;
                            (
                                Some(hash),
                                None,
                                None,
                                pkg_pfn.clone(),
                                valid_pkg_sid.clone(),
                            )
                        }
                    };

                let rule = ScopedPolicyRuleRecord {
                    rule_id: format!("RULE-SCOPED-ALLOW-{}", Uuid::new_v4()),
                    scope,
                    exe_path_pattern: exe.clone(),
                    sha256: rule_sha256,
                    signer_subject: rule_signer,
                    root_thumbprint: rule_thumbprint,
                    allowed_target: allow_dest
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    package_family_name: rule_pfn,
                    package_sid: rule_sid,
                    command_line_pattern: None,
                    created_at_ms: now_ms,
                    created_by: "user_triage".to_string(),
                };
                validate_scoped_policy_rule(&rule)?;

                let _policy_guard = self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                let prev_scoped_rules = (scope == RuleScope::NetworkAllow
                    && self.config.outbound_firewall_enabled)
                    .then(|| self.store.list_scoped_network_rules().unwrap_or_default());
                write_guard
                    .write(&self.store, |s| s.upsert_scoped_rule(&rule))
                    .map_err(|err| format!("failed to store scoped permanent allowlist rule: {err}"))?;
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
                            self.rollback_saved_scoped_rule(&write_guard, &rule.rule_id);
                            return Err(err);
                        }
                    }

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
                            let report = self.deploy_persisted_network_rules_with_scoped_baseline(
                                None,
                                prev_scoped_rules.as_deref(),
                            );
                            if let Some(summary) =
                                report.failure_summary_for_scoped_rules(&[&rule])
                            {
                                return Err(Box::new((
                                    format!(
                                        "failed synchronizing scoped WFP firewall rule for NetworkAllow {}: {}",
                                        rule.rule_id, summary
                                    ),
                                    report,
                                )));
                            }
                            if let (Some(target_pat), Some(dst_ip), Some(pkg_sid)) = (
                                rule.allowed_target.as_deref(),
                                alert_dst_ip,
                                rule.package_sid.as_deref(),
                            ) {
                                if parse_literal_target_ip(target_pat).is_none() {
                                    let needs_ip_permit = {
                                        let fw =
                                            self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                                        fw.active_app_block(&exe).is_some()
                                            || fw.active_scoped_app_block(&exe, pkg_sid).is_some()
                                    };
                                    if needs_ip_permit {
                                        let current_rules =
                                            self.store.list_network_rules().unwrap_or_default();
                                        let current_scoped = self
                                            .store
                                            .list_scoped_network_rules()
                                            .unwrap_or_default();
                                        let bin_identity = self.inspector.inspect(&exe);
                                        let scope_ctx = ProcessScopeContext {
                                            package_family_name: rule
                                                .package_family_name
                                                .as_deref(),
                                            package_sid: Some(pkg_sid),
                                            command_line: None,
                                        };
                                        let mut eval_cands: Vec<(String, i64)> = Vec::new();
                                        if let Some(hint) = alert_domain_hint
                                            .as_deref()
                                            .map(str::trim)
                                            .map(|s| s.trim_end_matches('.'))
                                            .filter(|s| !s.is_empty())
                                        {
                                            eval_cands.push((hint.to_ascii_lowercase(), now_ms));
                                        }
                                        let (eff_dec, _) =
                                            select_outbound_decision_for_domains_with_scoped(
                                                &bin_identity,
                                                &scope_ctx,
                                                dst_ip,
                                                &eval_cands,
                                                &current_rules,
                                                &current_scoped,
                                            );
                                        if matches!(eff_dec, OutboundDecision::AllowedByRule { .. })
                                        {
                                            let hints: Vec<String> = eval_cands
                                                .into_iter()
                                                .map(|(d, _)| d)
                                                .collect();
                                            let mut fw = self
                                                .firewall
                                                .lock()
                                                .unwrap_or_else(|e| e.into_inner());
                                            if let Err(err) = fw.ensure_scoped_ip_permit(
                                                &exe,
                                                pkg_sid,
                                                rule.package_family_name.as_deref(),
                                                dst_ip,
                                                &hints,
                                                &[] as &[&str],
                                                &*self.defense,
                                            ) {
                                                return Err(Box::new((
                                                    format!(
                                                        "failed installing scoped IP permit for NetworkAllow {}: {err}",
                                                        rule.rule_id
                                                    ),
                                                    report,
                                                )));
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
                            self.rollback_saved_scoped_rule(&write_guard, &rule.rule_id);
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
                    &write_guard,
                    &alert,
                    identity,
                    &own_suspended_children,
                    &suspended_children,
                ) {
                    {
                        let _policy_guard =
                            self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                        self.rollback_saved_scoped_rule(&write_guard, &rule.rule_id);
                        if scope == RuleScope::NetworkAllow && self.config.outbound_firewall_enabled
                        {
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
                self.terminate_alert_targets_for_resolution(
                    alert_id,
                    &alert,
                    identity,
                    &suspended_children,
                )?;

                if add_block_rule {
                    if let (Some(exe), Some(pkg_sid)) = (exe_path.clone(), valid_pkg_sid.clone()) {
                        let block_rule = ScopedPolicyRuleRecord {
                            rule_id: format!("RULE-SCOPED-BLOCK-{}", Uuid::new_v4()),
                            scope: RuleScope::NetworkBlock,
                            exe_path_pattern: exe,
                            sha256: None,
                            signer_subject: None,
                            root_thumbprint: None,
                            allowed_target: None,
                            package_family_name: pkg_pfn.clone(),
                            package_sid: Some(pkg_sid),
                            command_line_pattern: None,
                            created_at_ms: now_ms,
                            created_by: "user_quarantine".to_string(),
                        };
                        validate_scoped_policy_rule(&block_rule)?;
                        let _policy_guard =
                            self.policy_lock.lock().unwrap_or_else(|e| e.into_inner());
                        let prev_scoped_rules = self
                            .config
                            .outbound_firewall_enabled
                            .then(|| self.store.list_scoped_network_rules().unwrap_or_default());
                        write_guard
                            .write(&self.store, |s| s.upsert_scoped_rule(&block_rule))
                            .map_err(|err| format!("failed to store scoped block rule: {err}"))?;
                        saved_rule_id = Some(block_rule.rule_id.clone());
                        if self.config.outbound_firewall_enabled {
                            let report = self.deploy_persisted_network_rules_with_scoped_baseline(
                                None,
                                prev_scoped_rules.as_deref(),
                            );
                            if let Some(summary) =
                                report.failure_summary_for_scoped_rules(&[&block_rule])
                            {
                                self.rollback_saved_scoped_rule(&write_guard, &block_rule.rule_id);
                                self.compensate_failed_wfp_report(&report);
                                return Err(format!(
                                    "failed synchronizing scoped WFP firewall rule for NetworkBlock {}: {summary}",
                                    block_rule.rule_id
                                ));
                            }
                            applied_wfp_report = Some(report);
                            self.invalidate_non_protected_steady_pids();
                            if is_network_alert {
                                let release_res = {
                                    let mut fw =
                                        self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                                    fw.release_transient_containment_for_alert(
                                        alert_id,
                                        Some(&block_rule.exe_path_pattern),
                                        &*self.defense,
                                    )
                                };
                                match release_res {
                                    Ok((snap, was_bound)) => {
                                        lifted_wfp_block = snap;
                                        if was_bound {
                                            rebind_alert_exe =
                                                Some(block_rule.exe_path_pattern.clone());
                                        }
                                    }
                                    Err(err) => {
                                        self.rollback_saved_scoped_rule(
                                            &write_guard,
                                            &block_rule.rule_id,
                                        );
                                        if let Some(rep) = applied_wfp_report.take() {
                                            self.compensate_failed_wfp_report(&rep);
                                        }
                                        return Err(err);
                                    }
                                }
                            }
                        }
                    } else {
                        tracing::info!(
                            alert_id = %alert_id,
                            exe_path = ?exe_path,
                            package_family_name = ?pkg_pfn,
                            "skipping persistent scoped NetworkBlock for non-AppContainer or unresolved process (FU-P4-03)"
                        );
                        if is_network_alert && self.config.outbound_firewall_enabled {
                            self.release_transient_wfp_after_terminate_without_block(
                                alert_id,
                                exe_path.as_deref(),
                            );
                        }
                    }
                } else if is_network_alert && self.config.outbound_firewall_enabled {
                    self.release_transient_wfp_after_terminate_without_block(
                        alert_id,
                        exe_path.as_deref(),
                    );
                }
            }
        }

        let status_result = write_guard
            .write(&self.store, |s| {
                s.update_alert_status(alert_id, new_status, Some(now_ms))
            })
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
                self.rollback_saved_scoped_rule(&write_guard, &rule_id);
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
                let alert_pkg_sid = valid_pkg_sid
                    .as_deref()
                    .or_else(|| ctx_val.get("package_sid").and_then(|v| v.as_str()));
                self.app_wfp_alert_dedup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_key(&WfpRuleManager::exe_key(exe), alert_pkg_sid, dst_ip);
            }
            if self.config.outbound_firewall_enabled {
                if let Some(ref exe) = exe_path {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    self.retry_deferred_preemptive_removal_locked(&mut fw, exe);
                }
            }
        }
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            self.clear_alert_dedup_from_context_val(proc_inst_id, &alert.source_layer, &ctx_val);
            if is_terminate {
                self.resolve_sibling_alerts_as_terminated(
                    &write_guard,
                    alert_id,
                    proc_inst_id,
                    now_ms,
                );
            }
        }

        alert.status = new_status;
        alert.resolved_at_ms = Some(now_ms);
        Ok(ResolvedAlertOutcome {
            alert,
            saved_rule_id,
        })
    }

    fn terminate_alert_targets_for_resolution(
        &self,
        alert_id: &str,
        alert: &AlertRecord,
        identity: Option<ProcessIdentity>,
        suspended_children: &[ProcessIdentity],
    ) -> Result<(), String> {
        if let Some(ident) = identity {
            if let Err(err) = self.defense.terminate_process(&ident, true) {
                if is_protected_process_refusal(&err) {
                    return Err(err);
                }
                if alert.process_suspended && !is_process_gone_or_replaced(&err, ident.pid) {
                    for child in suspended_children {
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

        let mut child_terminate_err: Option<String> = None;
        for child in suspended_children {
            match self.defense.terminate_process(child, true) {
                Ok(()) => {}
                Err(err)
                    if is_protected_process_refusal(&err)
                        || !is_process_gone_or_replaced(&err, child.pid) =>
                {
                    child_terminate_err.get_or_insert(err);
                }
                Err(err) => {
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
        Ok(())
    }

    fn release_transient_wfp_after_terminate_without_block(
        &self,
        alert_id: &str,
        exe_path: Option<&str>,
    ) {
        let (release_res, bound_exe) = {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            let bound_exe = fw.bound_alert_exe_path(alert_id);
            let res = fw.release_transient_containment_for_alert(
                alert_id,
                exe_path,
                &*self.defense,
            );
            (res, bound_exe)
        };
        if let Err(err) = release_res {
            tracing::warn!(
                alert_id = %alert_id,
                error = %err,
                "best-effort transient WFP release after terminate without block failed"
            );
        }
        if let Some(exe) = exe_path.or(bound_exe.as_deref()) {
            let target_key = WfpRuleManager::exe_key(exe);
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            let still_active = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .has_active_exe_key(&target_key);
            if !still_active {
                fw.remove_preemptive_block_if_unused(exe, &*self.defense);
            }
        }
    }

    fn resolve_alert_package_attributes(
        &self,
        ctx_val: &serde_json::Value,
        process_instance_id: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        let ctx_pfn = json_non_empty_str(ctx_val, "/package_family_name");
        let ctx_sid = json_non_empty_str(ctx_val, "/package_sid");
        let mut pfn = ctx_pfn;
        let mut sid = ctx_sid.clone();

        if pfn.is_none() || sid.is_none() {
            if let Some(inst_id) = process_instance_id {
            let tbl_pkg = self
                .process_table
                .lock()
                .ok()
                .and_then(|t| {
                    t.get_by_instance_id(inst_id)
                        .map(|e| (e.package_family_name.clone(), e.package_sid.clone()))
                });
            if let Some((tbl_pfn, tbl_sid)) = tbl_pkg {
                let sid_conflict = matches!(
                    (ctx_sid.as_deref(), tbl_sid.as_deref()),
                    (Some(a), Some(b)) if !a.trim().eq_ignore_ascii_case(b.trim())
                );
                if sid.is_none() {
                    sid = tbl_sid.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                }
                if pfn.is_none() && !sid_conflict {
                    pfn = tbl_pfn.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
                }
            }
            if pfn.is_none() || sid.is_none() {
                if let Ok(Some(rec)) = self.store.get_process_package_info(inst_id) {
                    let sid_conflict = matches!(
                        (ctx_sid.as_deref(), rec.package_sid.as_deref()),
                        (Some(a), Some(b)) if !a.trim().eq_ignore_ascii_case(b.trim())
                    );
                    if sid.is_none() {
                        sid = rec
                            .package_sid
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                    }
                    if pfn.is_none() && !sid_conflict {
                        pfn = rec
                            .package_family_name
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty());
                    }
                }
            }
            }
        }

        (pfn, sid)
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
        write_guard: &WriteOpGuard,
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
            match write_guard.write(&self.store, |s| {
                s.update_alert_suspension_state(
                    &sibling.alert_id,
                    sibling.process_suspended,
                    &ctx_val.to_string(),
                )
            }) {
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
        write_guard: &WriteOpGuard,
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
                write_guard,
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
    fn rollback_saved_rule(&self, write_guard: &WriteOpGuard, rule_id: &str) {
        if let Err(err) = write_guard.write(&self.store, |s| s.delete_rule(rule_id)) {
            tracing::warn!(
                rule_id = %rule_id,
                error = %err,
                "failed to roll back allowlist rule after resolve error"
            );
        }
    }

    fn rollback_saved_scoped_rule(&self, write_guard: &WriteOpGuard, rule_id: &str) {
        if let Err(err) = write_guard.write(&self.store, |s| s.delete_scoped_rule(rule_id)) {
            tracing::warn!(
                rule_id = %rule_id,
                error = %err,
                "failed to roll back scoped policy rule after resolve error"
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

    /// Retries removal of a non-startup `Preemptive` app-wide WFP block whose `ProcessStop`
    /// cleanup was deferred while unresolved alerts still referenced it (`PRRT_kwDOVyjVyM66kfDX`).
    ///
    /// Only acts when `has_deferred_preemptive_removal` is set, all bound alerts for `exe_path`
    /// have been released, and `process_table.has_active_exe_key` (which also tracks live
    /// instances displaced from `entries` into `evicted_live` / overflow fail-closed sets,
    /// `PRRT_kwDOVyjVyM66ksZW`) confirms no live instance remains.
    /// Lock order: caller holds `firewall` -> briefly acquires and drops `process_table` before
    /// calling `remove_wfp_rule`.
    pub(super) fn retry_deferred_preemptive_removal_locked(
        &self,
        fw: &mut WfpRuleManager,
        exe_path: &str,
    ) {
        if !self.config.outbound_firewall_enabled
            || !fw.has_deferred_preemptive_removal(exe_path)
            || fw.has_any_bound_alerts_for_exe(exe_path)
        {
            return;
        }
        let target_key = WfpRuleManager::exe_key(exe_path);
        let still_active = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_active_exe_key(&target_key);
        if still_active {
            fw.clear_deferred_preemptive_removal(exe_path);
        } else {
            fw.remove_preemptive_block_if_unused(exe_path, &*self.defense);
        }
    }

    fn resolve_sibling_alerts_as_terminated(
        &self,
        write_guard: &WriteOpGuard,
        resolved_alert_id: &str,
        proc_inst_id: &str,
        now_ms: i64,
    ) {
        let Ok(unresolved) = self.store.list_alerts_for_process(proc_inst_id, true, 1000) else {
            return;
        };
        for other in unresolved {
            if other.alert_id != resolved_alert_id {
                let update_res = write_guard.write(&self.store, |s| {
                    s.update_alert_status(
                        &other.alert_id,
                        AlertStatus::TerminatedBlocked,
                        Some(now_ms),
                    )
                });
                match update_res {
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
                            let exe_opt = json_non_empty_str(&ctx, "/exe_path");
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            let bound_exe = fw.bound_alert_exe_path(&other.alert_id);
                            let _ = fw.release_transient_containment_for_alert(
                                &other.alert_id,
                                exe_opt.as_deref(),
                                &*self.defense,
                            );
                            if let Some(ref exe) = exe_opt.or(bound_exe) {
                                self.retry_deferred_preemptive_removal_locked(&mut fw, exe);
                            }
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
        self.has_matching_persisted_network_block_with_scoped(
            exe_path,
            &ProcessScopeContext::default(),
            dst_ip,
            domain_hints,
        )
    }

    fn has_matching_persisted_network_block_with_scoped(
        &self,
        exe_path: &str,
        scope_ctx: &ProcessScopeContext<'_>,
        dst_ip: Option<IpAddr>,
        domain_hints: &[String],
    ) -> bool {
        let rules = self
            .store
            .list_rules(Some(RuleScope::NetworkBlock))
            .unwrap_or_default();
        let scoped_rules = self
            .store
            .list_scoped_rules(Some(RuleScope::NetworkBlock))
            .unwrap_or_default();
        let matching_path: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
            })
            .collect();
        let matching_scoped_path: Vec<&ScopedPolicyRuleRecord> = scoped_rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
                    && r.package_sid
                        .as_deref()
                        .zip(scope_ctx.package_sid)
                        .is_some_and(|(a, b)| a.trim().eq_ignore_ascii_case(b.trim()))
            })
            .collect();
        if matching_path.is_empty() && matching_scoped_path.is_empty() {
            return false;
        }
        let needs_inspect = matching_path.iter().any(|r| {
            r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                || r.signer_subject
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
        }) || matching_scoped_path.iter().any(|r| {
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
        }) || matching_scoped_path.into_iter().any(|rule| match dst_ip {
            Some(ip) => {
                matches_scoped_network_block_rule(rule, &identity, scope_ctx, ip, None)
                    || domain_hints.iter().any(|hint| {
                        let trimmed = hint.trim().trim_end_matches('.');
                        !trimmed.is_empty()
                            && matches_scoped_network_block_rule(
                                rule,
                                &identity,
                                scope_ctx,
                                ip,
                                Some(trimmed),
                            )
                    })
            }
            None => matches_package_wide_network_block(rule, &identity),
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, RwLock};

    use ledr_proto::{
        ActiveDefenseController, AlertDecision, AlertRecord, AlertSeverity, AlertStatus,
        AllowPermanentPathMode, AuthenticodeInfo, ProcessIdentity, RuleScope, SensorEvent,
    };
    use ledr_rules::{
        evaluate_outbound_policy, is_allowed_by_rules, BinaryIdentity, EarlyPruner,
        OutboundDecision, SigmaEngine,
    };
    use ledr_store::LedrStore;

    use crate::engine::{BinaryInspector, DaemonConfig, DaemonEngine, EventLane, NotificationDispatcher};
    use crate::firewall::WfpRuleManager;

    struct MapInspector {
        entries: RwLock<HashMap<String, BinaryIdentity>>,
    }

    impl MapInspector {
        fn new() -> Self {
            Self {
                entries: RwLock::new(HashMap::new()),
            }
        }

        fn insert(&self, id: BinaryIdentity) {
            self.entries
                .write()
                .unwrap()
                .insert(WfpRuleManager::exe_key(&id.exe_path), id);
        }
    }

    impl BinaryInspector for MapInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            self.entries
                .read()
                .unwrap()
                .get(&WfpRuleManager::exe_key(exe_path))
                .cloned()
                .unwrap_or_else(|| BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: None,
                    authenticode: None,
                })
        }
    }

    struct StubNotifier;
    impl NotificationDispatcher for StubNotifier {
        fn notify_alert(&self, _: &AlertRecord) -> Result<(), String> {
            Ok(())
        }
    }

    struct MockDefense {
        next_handle: AtomicU64,
        fail_add_for: Mutex<Option<String>>,
        terminated_calls: AtomicUsize,
        fail_removes: AtomicBool,
    }

    impl MockDefense {
        fn new() -> Self {
            Self {
                next_handle: AtomicU64::new(10),
                fail_add_for: Mutex::new(None),
                terminated_calls: AtomicUsize::new(0),
                fail_removes: AtomicBool::new(false),
            }
        }

        fn set_fail_add_for(&self, pat: Option<&str>) {
            *self.fail_add_for.lock().unwrap() = pat.map(|s| s.to_ascii_lowercase());
        }

        fn terminated_calls(&self) -> usize {
            self.terminated_calls.load(Ordering::Acquire)
        }
    }

    impl ActiveDefenseController for MockDefense {
        fn suspend_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn resume_process(&self, _: &ProcessIdentity) -> Result<(), String> {
            Ok(())
        }
        fn terminate_process(&self, _: &ProcessIdentity, _: bool) -> Result<(), String> {
            self.terminated_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        fn add_wfp_app_rule(
            &self,
            exe_path: &Path,
            _remote_ip: Option<IpAddr>,
            _allow: bool,
        ) -> Result<u64, String> {
            let lower = exe_path.to_string_lossy().to_ascii_lowercase();
            if let Some(ref pat) = *self.fail_add_for.lock().unwrap() {
                if lower.contains(pat) {
                    return Err(format!("mock WFP add error for {lower}"));
                }
            }
            Ok(self.next_handle.fetch_add(1, Ordering::Relaxed))
        }
        fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
            if self.fail_removes.load(Ordering::Acquire) {
                return Err(format!("mock WFP remove error for {filter_id}"));
            }
            Ok(())
        }
    }

    async fn build_engine(
        defense: Arc<MockDefense>,
        inspector: Arc<MapInspector>,
        outbound_firewall_enabled: bool,
    ) -> Arc<DaemonEngine> {
        let store = LedrStore::open_in_memory().expect("in-memory store");
        let engine = DaemonEngine::start_with_dependencies(
            store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled,
                ..DaemonConfig::default()
            },
            defense,
            Arc::new(StubNotifier),
            inspector,
        );
        if let Some(h) = engine.worker_handle.lock().await.take() {
            h.abort();
            let _ = h.await;
        }
        engine
    }

    fn auth_info(signer: &str, thumbprint: &str) -> AuthenticodeInfo {
        AuthenticodeInfo {
            signer_subject: signer.to_string(),
            root_thumbprint: thumbprint.to_string(),
        }
    }

    fn make_alert(
        alert_id: &str,
        source_layer: &str,
        proc_inst: Option<&str>,
        context_json: serde_json::Value,
    ) -> AlertRecord {
        AlertRecord {
            alert_id: alert_id.to_string(),
            timestamp_ms: 1_750_000_000_000,
            severity: AlertSeverity::Medium,
            source_layer: source_layer.to_string(),
            rule_id: "TEST_RULE".to_string(),
            title: "Test alert".to_string(),
            process_instance_id: proc_inst.map(str::to_string),
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json: context_json.to_string(),
            resolved_at_ms: None,
        }
    }

    #[tokio::test]
    async fn wildcard_network_allow_unlimited_and_dest_scoped_allow_new_version_and_reject_spoofed_or_other_pkg() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let signer = "CN=Contoso Store Publisher";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        let exe_v1 = r"C:\Program Files\WindowsApps\Contoso.StoreApp_1.0.0.0_x64__8wekyb3d8bbwe\StoreApp.exe";
        let exe_v2 = r"C:\Program Files\WindowsApps\Contoso.StoreApp_2.0.0.0_x64__8wekyb3d8bbwe\StoreApp.exe";
        let other_pkg_exe =
            r"C:\Program Files\WindowsApps\Other.StoreApp_1.0.0.0_x64__8wekyb3d8bbwe\StoreApp.exe";
        let expected_pattern =
            r"C:\Program Files\WindowsApps\Contoso.StoreApp_*_x64__8wekyb3d8bbwe\StoreApp.exe";

        // 1. Unlimited NetworkAllow
        let alert_unlim = make_alert(
            "ALT-NET-UNLIM",
            "LAYER_3_NETWORK",
            Some("1101:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_v1,
                "sha256": "a".repeat(64),
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.10"
            }),
        );
        engine
            .store()
            .record_alert(&alert_unlim)
            .expect("record alert_unlim");

        let outcome = engine
            .resolve_alert_with_options_and_outcome(
                "ALT-NET-UNLIM",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("unlimited wildcard NetworkAllow succeeds");
        assert!(outcome.saved_rule_id.is_some());

        let rules = engine
            .store()
            .list_rules(Some(RuleScope::NetworkAllow))
            .expect("list rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].exe_path_pattern, expected_pattern);
        assert_eq!(rules[0].sha256, None);
        assert_eq!(rules[0].signer_subject.as_deref(), Some(signer));
        assert_eq!(rules[0].root_thumbprint.as_deref(), Some(root_tp));
        assert_eq!(rules[0].allowed_target, None);

        let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50));
        // New version with matching signer + thumbprint is ALLOWED.
        let v2_valid = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        };
        assert!(matches!(
            evaluate_outbound_policy(&v2_valid, dst_ip, None, &rules),
            OutboundDecision::AllowedByRule { .. }
        ));

        // Same wildcard path with UNSIGNED binary -> REJECTED.
        let v2_unsigned = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: None,
        };
        assert!(matches!(
            evaluate_outbound_policy(&v2_unsigned, dst_ip, None, &rules),
            OutboundDecision::UnknownFirstConnect
        ));

        // Same wildcard path with DIFFERENT signer_subject -> REJECTED.
        let v2_wrong_signer = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(auth_info("CN=Evil Spoofer", root_tp)),
        };
        assert!(matches!(
            evaluate_outbound_policy(&v2_wrong_signer, dst_ip, None, &rules),
            OutboundDecision::UnknownFirstConnect
        ));

        // Same wildcard path with DIFFERENT root_thumbprint -> REJECTED.
        let v2_wrong_tp = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(auth_info(signer, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")),
        };
        assert!(matches!(
            evaluate_outbound_policy(&v2_wrong_tp, dst_ip, None, &rules),
            OutboundDecision::UnknownFirstConnect
        ));

        // Different package even with identical signer + thumbprint -> REJECTED.
        let other_pkg = BinaryIdentity {
            exe_path: other_pkg_exe.to_string(),
            sha256: Some("c".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        };
        assert!(matches!(
            evaluate_outbound_policy(&other_pkg, dst_ip, None, &rules),
            OutboundDecision::UnknownFirstConnect
        ));

        // 2. Destination-scoped NetworkAllow
        engine
            .store()
            .delete_rule(&rules[0].rule_id)
            .expect("clear unlimited rule");
        let alert_dest = make_alert(
            "ALT-NET-DEST",
            "LAYER_3_NETWORK",
            Some("1102:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_v1,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.77",
                "domain_hint": "api.contoso.example"
            }),
        );
        engine
            .store()
            .record_alert(&alert_dest)
            .expect("record alert_dest");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-NET-DEST",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("api.contoso.example".to_string()),
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("dest-scoped wildcard NetworkAllow succeeds");
        let dest_rules = engine
            .store()
            .list_rules(Some(RuleScope::NetworkAllow))
            .expect("list dest rules");
        assert_eq!(dest_rules.len(), 1);
        assert_eq!(dest_rules[0].exe_path_pattern, expected_pattern);
        assert_eq!(
            dest_rules[0].allowed_target.as_deref(),
            Some("api.contoso.example")
        );
        assert_eq!(dest_rules[0].sha256, None);
        assert!(matches!(
            evaluate_outbound_policy(&v2_valid, dst_ip, Some("api.contoso.example"), &dest_rules),
            OutboundDecision::AllowedByRule { .. }
        ));
        assert!(matches!(
            evaluate_outbound_policy(&v2_valid, dst_ip, Some("other.example"), &dest_rules),
            OutboundDecision::UnknownFirstConnect
        ));
        assert!(matches!(
            evaluate_outbound_policy(&v2_wrong_signer, dst_ip, Some("api.contoso.example"), &dest_rules),
            OutboundDecision::UnknownFirstConnect
        ));

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_file_canary_allow_unlimited_and_dest_scoped_work_and_reject_mismatches() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let signer = "CN=Contoso Store Publisher";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        let exe_v1 = r"C:\Program Files\WindowsApps\Contoso.Editor_1.2.0.0_arm64__8wekyb3d8bbwe\Editor.exe";
        let exe_v2 = r"C:\Program Files\WindowsApps\Contoso.Editor_1.3.0.0_arm64__8wekyb3d8bbwe\Editor.exe";
        let other_pkg = r"C:\Program Files\WindowsApps\Other.Editor_1.3.0.0_arm64__8wekyb3d8bbwe\Editor.exe";
        let target_decoy = r"C:\Users\alice\Documents\decoy.docx";

        let alert_unlim = make_alert(
            "ALT-CANARY-UNLIM",
            "LAYER_2_BEHAVIOR",
            Some("1201:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_v1,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "category": "DECOY_MODIFIED",
                "target_path": target_decoy
            }),
        );
        engine
            .store()
            .record_alert(&alert_unlim)
            .expect("record alert_unlim");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-CANARY-UNLIM",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("wildcard FileCanaryAllow succeeds");

        let rules = engine
            .store()
            .list_rules(Some(RuleScope::FileCanaryAllow))
            .expect("list FileCanaryAllow");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].exe_path_pattern,
            r"C:\Program Files\WindowsApps\Contoso.Editor_*_arm64__8wekyb3d8bbwe\Editor.exe"
        );
        assert_eq!(rules[0].sha256, None);
        assert_eq!(rules[0].signer_subject.as_deref(), Some(signer));
        assert_eq!(rules[0].root_thumbprint.as_deref(), Some(root_tp));

        let v2_valid = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: None,
            authenticode: Some(auth_info(signer, root_tp)),
        };
        assert!(is_allowed_by_rules(
            &v2_valid,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &rules
        ));

        let v2_unsigned = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("d".repeat(64)),
            authenticode: None,
        };
        assert!(!is_allowed_by_rules(
            &v2_unsigned,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &rules
        ));

        let v2_wrong_signer = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: None,
            authenticode: Some(auth_info("CN=Other", root_tp)),
        };
        assert!(!is_allowed_by_rules(
            &v2_wrong_signer,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &rules
        ));

        let v2_wrong_tp = BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: None,
            authenticode: Some(auth_info(signer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
        };
        assert!(!is_allowed_by_rules(
            &v2_wrong_tp,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &rules
        ));

        let other = BinaryIdentity {
            exe_path: other_pkg.to_string(),
            sha256: None,
            authenticode: Some(auth_info(signer, root_tp)),
        };
        assert!(!is_allowed_by_rules(
            &other,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &rules
        ));

        // Scoped FileCanaryAllow (`allow_dest: Some(...)`)
        engine
            .store()
            .delete_rule(&rules[0].rule_id)
            .expect("delete unlim");
        let alert_scoped = make_alert(
            "ALT-CANARY-SCOPED",
            "LAYER_2_BEHAVIOR",
            Some("1202:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_v1,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "category": "DECOY_MODIFIED",
                "target_path": target_decoy
            }),
        );
        engine
            .store()
            .record_alert(&alert_scoped)
            .expect("record alert_scoped");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-CANARY-SCOPED",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some(target_decoy.to_string()),
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("scoped FileCanaryAllow succeeds");
        let scoped_rules = engine
            .store()
            .list_rules(Some(RuleScope::FileCanaryAllow))
            .expect("list scoped FileCanaryAllow");
        assert_eq!(scoped_rules.len(), 1);
        assert_eq!(scoped_rules[0].allowed_target.as_deref(), Some(target_decoy));
        assert!(is_allowed_by_rules(
            &v2_valid,
            Some(target_decoy),
            RuleScope::FileCanaryAllow,
            &scoped_rules
        ));
        assert!(!is_allowed_by_rules(
            &v2_valid,
            Some(r"C:\Users\alice\Documents\other.docx"),
            RuleScope::FileCanaryAllow,
            &scoped_rules
        ));

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_signer_lookup_prefers_context_json_and_falls_back_to_inspector() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe_ctx = r"C:\Program Files\WindowsApps\Contoso.CtxPref_1.0.0.0_x64__8wekyb3d8bbwe\App.exe";
        let exe_fb = r"C:\Program Files\WindowsApps\Contoso.Fallback_1.0.0.0_x64__8wekyb3d8bbwe\App.exe";

        // Disk inspector has a DIFFERENT signer for exe_ctx, but context_json must win.
        inspector.insert(BinaryIdentity {
            exe_path: exe_ctx.to_string(),
            sha256: Some("1".repeat(64)),
            authenticode: Some(auth_info(
                "CN=Disk Signer Should Not Override",
                "1111111111111111111111111111111111111111",
            )),
        });
        // Disk inspector has valid signer for exe_fb; context_json has sha256 only (no signer).
        inspector.insert(BinaryIdentity {
            exe_path: exe_fb.to_string(),
            sha256: Some("2".repeat(64)),
            authenticode: Some(auth_info(
                "CN=Fallback Disk Signer",
                "2222222222222222222222222222222222222222",
            )),
        });

        let a_ctx = make_alert(
            "ALT-CTX-PREF",
            "LAYER_2_BEHAVIOR",
            Some("1301:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_ctx,
                "signer_subject": "CN=Context Recorded Signer",
                "root_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }),
        );
        let a_fb = make_alert(
            "ALT-CTX-FB",
            "LAYER_2_BEHAVIOR",
            Some("1302:133000000000000000"),
            serde_json::json!({
                "exe_path": exe_fb,
                "sha256": "2".repeat(64)
            }),
        );
        engine.store().record_alert(&a_ctx).expect("record a_ctx");
        engine.store().record_alert(&a_fb).expect("record a_fb");

        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-CTX-PREF",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("context_json signer wins");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-CTX-FB",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("fallback inspector fills missing signer even when sha256 was in context_json");

        let rules = engine
            .store()
            .list_rules(Some(RuleScope::FileCanaryAllow))
            .expect("list rules");
        assert_eq!(rules.len(), 2);
        let r_ctx = rules
            .iter()
            .find(|r| r.exe_path_pattern.contains("Contoso.CtxPref_*"))
            .expect("r_ctx");
        assert_eq!(
            r_ctx.signer_subject.as_deref(),
            Some("CN=Context Recorded Signer")
        );
        assert_eq!(
            r_ctx.root_thumbprint.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
        let r_fb = rules
            .iter()
            .find(|r| r.exe_path_pattern.contains("Contoso.Fallback_*"))
            .expect("r_fb");
        assert_eq!(
            r_fb.signer_subject.as_deref(),
            Some("CN=Fallback Disk Signer")
        );
        assert_eq!(
            r_fb.root_thumbprint.as_deref(),
            Some("2222222222222222222222222222222222222222")
        );

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_fail_closed_rejects_invalid_inputs_without_saving_rule_or_mutating_alert() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let wa_exe =
            r"C:\Program Files\WindowsApps\Contoso.StoreApp_1.0.0.0_x64__8wekyb3d8bbwe\StoreApp.exe";
        let non_wa_exe = r"C:\Tools\app.exe";
        let alias_exe = r"C:\Users\alice\AppData\Local\Microsoft\WindowsApps\StoreApp.exe";
        let valid_signer = "CN=Contoso Store Publisher";
        let valid_tp = "0123456789ABCDEF0123456789ABCDEF01234567";

        let cases: Vec<(&str, AlertRecord, AlertDecision)> = vec![
            (
                "use_signer_if_available_false",
                make_alert(
                    "FC-1",
                    "LAYER_3_NETWORK",
                    Some("2001:133000000000000000"),
                    serde_json::json!({
                        "exe_path": wa_exe,
                        "sha256": "a".repeat(64),
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: None,
                },
            ),
            (
                "unsigned_binary_with_sha256_must_not_fallback",
                make_alert(
                    "FC-2",
                    "LAYER_3_NETWORK",
                    Some("2002:133000000000000000"),
                    serde_json::json!({
                        "exe_path": wa_exe,
                        "sha256": "a".repeat(64)
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
            ),
            (
                "signer_with_all_zero_root_thumbprint",
                make_alert(
                    "FC-3",
                    "LAYER_3_NETWORK",
                    Some("2003:133000000000000000"),
                    serde_json::json!({
                        "exe_path": wa_exe,
                        "sha256": "a".repeat(64),
                        "signer_subject": valid_signer,
                        "root_thumbprint": "0".repeat(40)
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
            ),
            (
                "non_windowsapps_path",
                make_alert(
                    "FC-4",
                    "LAYER_3_NETWORK",
                    Some("2004:133000000000000000"),
                    serde_json::json!({
                        "exe_path": non_wa_exe,
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
            ),
            (
                "localappdata_execution_alias_path",
                make_alert(
                    "FC-5",
                    "LAYER_3_NETWORK",
                    Some("2005:133000000000000000"),
                    serde_json::json!({
                        "exe_path": alias_exe,
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
            ),
            (
                "allow_once_rejected_with_wildcard_mode",
                make_alert(
                    "FC-6",
                    "LAYER_3_NETWORK",
                    Some("2006:133000000000000000"),
                    serde_json::json!({
                        "exe_path": wa_exe,
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::AllowOnce,
            ),
            (
                "terminate_and_block_rejected_with_wildcard_mode",
                make_alert(
                    "FC-7",
                    "LAYER_3_NETWORK",
                    Some("2007:133000000000000000"),
                    serde_json::json!({
                        "exe_path": wa_exe,
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::TerminateAndBlock {
                    add_block_rule: true,
                },
            ),
            (
                "processless_layer_4_browser_rejected",
                make_alert(
                    "FC-8",
                    "LAYER_4_BROWSER",
                    None,
                    serde_json::json!({
                        "url": "https://example.invalid/phish",
                        "exe_path": wa_exe,
                        "signer_subject": valid_signer,
                        "root_thumbprint": valid_tp
                    }),
                ),
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
            ),
        ];

        for (label, alert, decision) in cases {
            let aid = alert.alert_id.clone();
            engine.store().record_alert(&alert).expect("record alert");
            let res = engine.resolve_alert_with_options_and_outcome(
                &aid,
                decision,
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            );
            assert!(res.is_err(), "{label} must fail closed");
            let persisted = engine
                .store()
                .get_alert(&aid)
                .expect("query alert")
                .expect("alert exists");
            assert_eq!(
                persisted.status,
                AlertStatus::Pending,
                "{label} must leave alert Pending"
            );
        }

        assert!(
            engine
                .store()
                .list_rules(None)
                .expect("list_rules")
                .is_empty(),
            "no rules may be persisted on fail-closed rejections"
        );
        assert_eq!(
            defense.terminated_calls(),
            0,
            "TerminateAndBlock with wildcard path_mode must reject before terminating"
        );

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_approval_succeeds_when_old_binary_deleted_and_releases_transient_containment() {
        let defense = Arc::new(MockDefense::new());
        // Empty inspector simulates old version folder already deleted from disk before approval.
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let signer = "CN=Contoso Store Publisher";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";

        // Case A: Running process, unlimited wildcard approval, old binary deleted on disk.
        let exe_running =
            r"C:\Program Files\WindowsApps\Contoso.RunApp_1.0.0.0_x64__8wekyb3d8bbwe\RunApp.exe";
        let p_run = ProcessIdentity::new(3001, 133_000_000_000_000_001);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p_run,
                parent_pid: 4,
                exe_path: exe_running.to_string(),
                command_line: exe_running.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        {
            let mut fw = engine.firewall.lock().unwrap();
            let h = defense
                .add_wfp_app_rule(Path::new(exe_running), None, false)
                .unwrap();
            assert!(fw
                .register_transient_containment("ALT-TC-RUN", exe_running, h, &*defense)
                .is_some());
        }
        let alert_run = make_alert(
            "ALT-TC-RUN",
            "LAYER_3_NETWORK",
            Some(&p_run.instance_id()),
            serde_json::json!({
                "exe_path": exe_running,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.80"
            }),
        );
        engine.store().record_alert(&alert_run).expect("record run");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-TC-RUN",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("deleted old binary running wildcard approval succeeds");
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(fw.active_app_block(exe_running).is_none());
            assert!(!fw.is_alert_bound("ALT-TC-RUN"));
        }

        // Case B: Exited process, destination-scoped wildcard approval, old binary deleted on disk.
        let exe_exited =
            r"C:\Program Files\WindowsApps\Contoso.ExitApp_1.0.0.0_x64__8wekyb3d8bbwe\ExitApp.exe";
        let p_exit = ProcessIdentity::new(3002, 133_000_000_000_000_002);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p_exit,
                parent_pid: 4,
                exe_path: exe_exited.to_string(),
                command_line: exe_exited.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        {
            let mut fw = engine.firewall.lock().unwrap();
            let h = defense
                .add_wfp_app_rule(Path::new(exe_exited), None, false)
                .unwrap();
            assert!(fw
                .register_transient_containment("ALT-TC-EXIT", exe_exited, h, &*defense)
                .is_some());
        }
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStop {
                pid: p_exit.pid,
                exit_time_100ns: p_exit.create_time_100ns + 10_000,
                exit_code: 0,
            },
            EventLane::HighPriority,
        );
        let alert_exit = make_alert(
            "ALT-TC-EXIT",
            "LAYER_3_NETWORK",
            Some(&p_exit.instance_id()),
            serde_json::json!({
                "exe_path": exe_exited,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.81",
                "domain_hint": "api.contoso.example"
            }),
        );
        engine
            .store()
            .record_alert(&alert_exit)
            .expect("record exit");
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-TC-EXIT",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("api.contoso.example".to_string()),
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("deleted old binary exited dest-scoped wildcard approval succeeds");
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(!fw.has_any_app_filter(exe_exited));
            assert!(!fw.is_alert_bound("ALT-TC-EXIT"));
        }

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_wfp_sync_failure_rolls_back_saved_rule() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe =
            r"C:\Program Files\WindowsApps\Contoso.FailSync_1.0.0.0_x64__8wekyb3d8bbwe\FailSync.exe";
        let signer = "CN=Contoso Store Publisher";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        inspector.insert(BinaryIdentity {
            exe_path: exe.to_string(),
            sha256: Some("f".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });

        let proc_id = ProcessIdentity::new(3003, 133_000_000_000_000_003);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );

        let alert = make_alert(
            "ALT-WFP-SYNC-FAIL",
            "LAYER_3_NETWORK",
            Some(&proc_id.instance_id()),
            serde_json::json!({
                "exe_path": exe,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.82"
            }),
        );
        engine.store().record_alert(&alert).expect("record alert");

        defense.set_fail_add_for(Some("contoso.failsync"));
        let res = engine.resolve_alert_with_options_and_outcome(
            "ALT-WFP-SYNC-FAIL",
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
            AllowPermanentPathMode::WindowsAppsVersionWildcard,
        );
        assert!(res.is_err(), "WFP sync failure must return Err");
        assert!(
            engine
                .store()
                .list_rules(None)
                .expect("list_rules")
                .is_empty(),
            "compensating rollback_saved_rule must delete saved wildcard rule on WFP failure"
        );
        assert_eq!(
            engine
                .store()
                .get_alert("ALT-WFP-SYNC-FAIL")
                .expect("get_alert")
                .expect("alert exists")
                .status,
            AlertStatus::Pending
        );

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn wildcard_allows_app_level_layer3_alert_without_process_instance_id() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe_v1 =
            r"C:\Program Files\WindowsApps\Contoso.AppLevel_1.0.0.0_x64__8wekyb3d8bbwe\App.exe";
        let exe_v2 =
            r"C:\Program Files\WindowsApps\Contoso.AppLevel_2.0.0.0_x64__8wekyb3d8bbwe\App.exe";
        let signer = "CN=Contoso Store Publisher";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        inspector.insert(BinaryIdentity {
            exe_path: exe_v2.to_string(),
            sha256: Some("2".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });

        // App-level LAYER_3_NETWORK alert (`process_instance_id: None`, e.g., ambiguous WFP drop)
        // succeeds when `exe_path` and verified signer/root_thumbprint are present, unlike
        // `LAYER_4_BROWSER` processless alerts.
        let alert = make_alert(
            "ALT-L3-NO-PROC",
            "LAYER_3_NETWORK",
            None,
            serde_json::json!({
                "exe_path": exe_v1,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.90"
            }),
        );
        engine.store().record_alert(&alert).expect("record alert");

        let outcome = engine
            .resolve_alert_with_options_and_outcome(
                "ALT-L3-NO-PROC",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: None,
                },
                AllowPermanentPathMode::WindowsAppsVersionWildcard,
            )
            .expect("app-level LAYER_3_NETWORK wildcard approval succeeds");
        assert!(outcome.saved_rule_id.is_some());

        let rules = engine.store().list_network_rules().expect("list_network_rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].exe_path_pattern,
            r"C:\Program Files\WindowsApps\Contoso.AppLevel_*_x64__8wekyb3d8bbwe\App.exe"
        );
        assert!(matches!(
            evaluate_outbound_policy(
                &inspector.inspect(exe_v2),
                "198.51.100.90".parse().unwrap(),
                None,
                &rules,
            ),
            OutboundDecision::AllowedByRule { .. }
        ));

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn restarted_app_keeps_preemptive_block_when_old_alert_receives_dest_scoped_allow() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe = r"C:\Users\Alice\Downloads\ContosoRestartable.exe";
        let signer = "CN=Contoso Tools";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        inspector.insert(BinaryIdentity {
            exe_path: exe.to_string(),
            sha256: Some("a".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });

        // 1. First instance starts (`HighRiskPath` -> Preemptive block) and gets bound alert.
        let p1 = ProcessIdentity::new(4101, 133_000_000_000_000_101);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p1,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        let alert_old = make_alert(
            "ALT-RESTART-OLD",
            "LAYER_3_NETWORK",
            Some(&p1.instance_id()),
            serde_json::json!({
                "exe_path": exe,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.10"
            }),
        );
        engine.store().record_alert(&alert_old).expect("record alert");
        {
            let mut fw = engine.firewall.lock().unwrap();
            assert!(fw.bind_alert_to_app_block("ALT-RESTART-OLD", exe));
        }

        // 2. First instance exits while `ALT-RESTART-OLD` is unresolved -> deferred_preemptive_removals set.
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStop {
                pid: p1.pid,
                exit_time_100ns: p1.create_time_100ns + 10_000,
                exit_code: 0,
            },
            EventLane::HighPriority,
        );
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(fw.has_deferred_preemptive_removal(exe));
            assert!(fw.active_app_block(exe).is_some());
        }

        // 3. Same executable restarts while old alert is still pending -> must reclaim & clear deferred.
        let p2 = ProcessIdentity::new(4102, 133_000_000_000_000_202);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p2,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(
                !fw.has_deferred_preemptive_removal(exe),
                "restarted live process must clear deferred_preemptive_removals"
            );
            assert!(fw.active_app_block(exe).is_some());
        }

        // 4. Resolve the old alert with destination-scoped AllowPermanent (`198.51.100.10` only).
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-RESTART-OLD",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("198.51.100.10".to_string()),
                },
                AllowPermanentPathMode::Exact,
            )
            .expect("dest-scoped approval succeeds");

        // 5. App-wide Preemptive block must remain active while Permit exists only for `198.51.100.10`.
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(
                fw.active_app_block(exe).is_some(),
                "restarted app must keep its app-wide Preemptive block after dest-scoped approval"
            );
            assert!(fw.has_active_filter(exe, Some("198.51.100.10".parse().unwrap()), true));
            assert!(!fw.has_active_filter(exe, Some("203.0.113.99".parse().unwrap()), true));
        }

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test]
    async fn unrelated_policy_upsert_preserves_deferred_preemptive_removal_and_dest_allow_cleans_stopped_app() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe_a = r"C:\Users\Alice\Downloads\ContosoAppA.exe";
        let exe_b = r"C:\Users\Alice\Downloads\ContosoAppB.exe";
        let signer = "CN=Contoso Tools";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        inspector.insert(BinaryIdentity {
            exe_path: exe_a.to_string(),
            sha256: Some("a".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });
        inspector.insert(BinaryIdentity {
            exe_path: exe_b.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });

        let p_a = ProcessIdentity::new(4201, 133_000_000_000_000_301);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p_a,
                parent_pid: 4,
                exe_path: exe_a.to_string(),
                command_line: exe_a.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        let alert_a = make_alert(
            "ALT-DEFERRED-A",
            "LAYER_3_NETWORK",
            Some(&p_a.instance_id()),
            serde_json::json!({
                "exe_path": exe_a,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.10"
            }),
        );
        engine.store().record_alert(&alert_a).expect("record alert");
        {
            let mut fw = engine.firewall.lock().unwrap();
            assert!(fw.bind_alert_to_app_block("ALT-DEFERRED-A", exe_a));
        }
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStop {
                pid: p_a.pid,
                exit_time_100ns: p_a.create_time_100ns + 10_000,
                exit_code: 0,
            },
            EventLane::HighPriority,
        );

        // Unrelated View 3 policy rule save for App B while App A is stopped with a bound alert.
        engine
            .upsert_policy_rule(&ledr_proto::AllowlistRuleRecord {
                rule_id: "RULE-UNRELATED-B".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: exe_b.to_string(),
                sha256: Some("b".repeat(64)),
                signer_subject: Some(signer.to_string()),
                root_thumbprint: Some(root_tp.to_string()),
                allowed_target: Some("198.51.100.20".to_string()),
                created_at_ms: 1_750_000_000_000,
                created_by: "user_manual".to_string(),
            })
            .expect("unrelated upsert succeeds");
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(
                fw.has_deferred_preemptive_removal(exe_a),
                "unrelated policy sync must preserve deferred_preemptive_removals for stopped App A"
            );
        }

        // Resolving App A's final alert with dest-scoped AllowPermanent removes App A's Preemptive block.
        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-DEFERRED-A",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("198.51.100.10".to_string()),
                },
                AllowPermanentPathMode::Exact,
            )
            .expect("dest-scoped approval succeeds");
        {
            let fw = engine.firewall.lock().unwrap();
            assert!(
                fw.active_app_block(exe_a).is_none(),
                "stopped App A must release its Preemptive block after final alert resolves"
            );
            assert!(!fw.has_deferred_preemptive_removal(exe_a));
        }

        engine.shutdown_and_flush().await.expect("shutdown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_policy_upsert_and_process_stop_preserves_deferred_preemptive_removal() {
        let defense = Arc::new(MockDefense::new());
        let inspector = Arc::new(MapInspector::new());
        let engine = build_engine(Arc::clone(&defense), Arc::clone(&inspector), true).await;

        let exe_a = r"C:\Users\Alice\Downloads\ContosoConcurrentA.exe";
        let exe_b = r"C:\Users\Alice\Downloads\ContosoConcurrentB.exe";
        let signer = "CN=Contoso Tools";
        let root_tp = "0123456789ABCDEF0123456789ABCDEF01234567";
        inspector.insert(BinaryIdentity {
            exe_path: exe_a.to_string(),
            sha256: Some("a".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });
        inspector.insert(BinaryIdentity {
            exe_path: exe_b.to_string(),
            sha256: Some("b".repeat(64)),
            authenticode: Some(auth_info(signer, root_tp)),
        });

        let p_a = ProcessIdentity::new(4301, 133_000_000_000_000_401);
        let _ = engine.process_event_with_lane(
            &SensorEvent::ProcessStart {
                identity: p_a,
                parent_pid: 4,
                exe_path: exe_a.to_string(),
                command_line: exe_a.to_string(),
                user_sid: None,
            },
            EventLane::HighPriority,
        );
        let alert_a = make_alert(
            "ALT-CONC-A",
            "LAYER_3_NETWORK",
            Some(&p_a.instance_id()),
            serde_json::json!({
                "exe_path": exe_a,
                "signer_subject": signer,
                "root_thumbprint": root_tp,
                "dst_ip": "198.51.100.10"
            }),
        );
        engine.store().record_alert(&alert_a).expect("record alert");
        {
            let mut fw = engine
                .firewall
                .try_lock()
                .expect("firewall try_lock before concurrent race");
            assert!(fw.bind_alert_to_app_block("ALT-CONC-A", exe_a));
        }

        // Hold `firewall` inside `spawn_blocking` while a second thread executes
        // `upsert_policy_rule` for unrelated App B. Because
        // `deploy_persisted_network_rules_with_baseline` must acquire `firewall` BEFORE snapshotting
        // `process_table`, the second thread blocks before taking its liveness snapshot and cannot
        // wipe `deferred_preemptive_removals` created during `ProcessStop`.
        let engine_race = Arc::clone(&engine);
        let defense_race = Arc::clone(&defense);
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "concurrent lock race test requires multi-threaded Tokio runtime"
        );
        tokio::task::spawn_blocking(move || {
            let mut fw_guard = engine_race
                .firewall
                .try_lock()
                .expect("acquire firewall guard for deterministic interleaving");

            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let engine_bg = Arc::clone(&engine_race);
            let rule_b = ledr_proto::AllowlistRuleRecord {
                rule_id: "RULE-CONC-B".to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: exe_b.to_string(),
                sha256: Some("b".repeat(64)),
                signer_subject: Some(signer.to_string()),
                root_thumbprint: Some(root_tp.to_string()),
                allowed_target: Some("198.51.100.20".to_string()),
                created_at_ms: 1_750_000_000_000,
                created_by: "user_manual".to_string(),
            };
            let bg_handle = std::thread::spawn(move || {
                let res = engine_bg.upsert_policy_rule(&rule_b);
                let _ = done_tx.send(res);
            });

            let wait_dl = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while engine_race
                .store()
                .get_rule("RULE-CONC-B")
                .expect("query RULE-CONC-B")
                .is_none()
            {
                assert!(
                    std::time::Instant::now() < wait_dl,
                    "timed out waiting for upsert_policy_rule to enter WFP reconciliation"
                );
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            // Allow the background thread to reach `deploy_persisted_network_rules_with_baseline`.
            std::thread::sleep(std::time::Duration::from_millis(20));

            // Simulate `ProcessStop` completing under `firewall -> process_table` lock order while
            // the background sync waits on `firewall`.
            {
                let mut table = engine_race
                    .process_table
                    .try_lock()
                    .expect("process_table must not be locked ahead of firewall by policy sync");
                let stopped = table.on_process_stop(p_a.pid, crate::engine::current_unix_ms());
                assert!(stopped.is_some());
            }
            assert!(!fw_guard.remove_preemptive_block_if_unused(exe_a, &*defense_race));
            assert!(fw_guard.has_deferred_preemptive_removal(exe_a));
            drop(fw_guard);

            let upsert_res = done_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("upsert_policy_rule must finish within bounded timeout");
            assert!(upsert_res.is_ok(), "upsert_policy_rule failed: {upsert_res:?}");
            bg_handle.join().expect("join background upsert thread");

            let check_dl = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                match engine_race.firewall.try_lock() {
                    Ok(fw) => {
                        assert!(
                            fw.has_deferred_preemptive_removal(exe_a),
                            "concurrent policy sync must preserve deferred_preemptive_removals for stopped App A"
                        );
                        assert!(fw.active_app_block(exe_a).is_some());
                        break;
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        assert!(
                            std::time::Instant::now() < check_dl,
                            "timed out acquiring firewall lock"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(std::sync::TryLockError::Poisoned(e)) => {
                        panic!("firewall poisoned: {e}")
                    }
                }
            }
        })
        .await
        .expect("spawn_blocking race task panicked");

        engine
            .resolve_alert_with_options_and_outcome(
                "ALT-CONC-A",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some("198.51.100.10".to_string()),
                },
                AllowPermanentPathMode::Exact,
            )
            .expect("dest-scoped approval succeeds");

        {
            let fw = engine
                .firewall
                .try_lock()
                .expect("firewall try_lock after alert resolve");
            assert!(
                fw.active_app_block(exe_a).is_none(),
                "stopped App A must release its Preemptive block after final alert resolves"
            );
            assert!(!fw.has_deferred_preemptive_removal(exe_a));
        }

        engine.shutdown_and_flush().await.expect("shutdown");
    }
}
