use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope};
use ledr_rules::{
    canonical_ip, classify_outbound_risk, evaluate_outbound_policy, is_external_ip,
    matches_app_wide_network_allow, matches_app_wide_network_block, matches_network_block_rule,
    matches_network_target, matches_path_pattern, parse_cidr_target, BinaryIdentity,
    OutboundDecision, OutboundRiskClass,
};

use crate::firewall::{parse_literal_target_ip, WfpRuleManager};

use super::domain_policy::{
    collect_domain_specific_blocked_hints, extend_authorizing_hints_from_existing_permit,
    network_allow_rule_identity_matches, partition_permit_hints,
    select_outbound_decision_for_domains,
};
use super::events::ResolvedProcessContext;
use super::DaemonEngine;

impl DaemonEngine {
    pub(super) fn prematerialize_domain_wfp_filters(
        &self,
        query_name: &str,
        resolved_ips: &[IpAddr],
        proc_ctx: &ResolvedProcessContext,
    ) {
        if !self.config.outbound_firewall_enabled
            || self.config.outbound_enforcement_mode == super::OutboundEnforcementMode::Audit
        {
            return;
        }
        let norm_query = query_name.trim().trim_end_matches('.');
        if norm_query.is_empty() {
            return;
        }
        let Some(exe_path) = proc_ctx
            .proc_exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !WfpRuleManager::is_wildcard_pattern(s))
        else {
            return;
        };
        let clean_exe = exe_path.trim_end_matches(['.', ' ']);
        if classify_outbound_risk(exe_path) == OutboundRiskClass::ProtectedOs
            || is_never_suspend_process(clean_exe)
        {
            return;
        }

        // Zero-overhead fast path when neither domain-scoped persisted network rules nor existing
        // `DomainPolicy` filters for `exe_path` exist.
        let (has_domain_rules, candidate_blocks, candidate_permits) = {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            (
                fw.has_domain_network_rules(),
                fw.domain_policy_blocks(exe_path),
                fw.domain_policy_permits_with_hints(exe_path),
            )
        };
        if !has_domain_rules && candidate_blocks.is_empty() && candidate_permits.is_empty() {
            return;
        }

        let mut all_canon_ips: Vec<IpAddr> = Vec::with_capacity(resolved_ips.len());
        let mut external_ips: Vec<IpAddr> = Vec::new();
        for &ip in resolved_ips {
            let canon = canonical_ip(ip);
            if !all_canon_ips.contains(&canon) {
                all_canon_ips.push(canon);
            }
            if is_external_ip(canon) && !external_ips.contains(&canon) {
                external_ips.push(canon);
            }
        }

        // When a domain moves to a new IP set, purge any stale `DomainPolicy` Block filter
        // left behind by an earlier resolution of `norm_query` (or a previously superseded domain)
        // unless the old IP is still blocked by a static rule or another active DNS record
        // (`BUG_..._0003`), and prune migrated/superseded hints from existing `DomainPolicy`
        // Permits so later blocks on the migrated domain cannot falsely revoke unrelated Permits.
        let exe_k = WfpRuleManager::exe_key(exe_path);
        let mut cached_rules: Option<Vec<AllowlistRuleRecord>> = None;
        let mut cached_identity: Option<BinaryIdentity> = None;
        if !candidate_blocks.is_empty() || !candidate_permits.is_empty() {
            let rules = self.store.list_network_rules().unwrap_or_default();
            let bin_identity = self.inspector.inspect(exe_path);
            let (active_dns_entries, superseded_block_pairs, current_domain_entries, superseded_permit_pairs) = {
                let history = self
                    .process_dns_history
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let active = if candidate_blocks.is_empty() {
                    Vec::new()
                } else {
                    history.active_domains_by_ip_for_exe(&exe_k)
                };
                let mut sup_blocks: HashSet<(IpAddr, String)> = HashSet::new();
                let mut cand_ips: Vec<IpAddr> = Vec::with_capacity(candidate_blocks.len());
                for (cand_ip, cand_hints) in &candidate_blocks {
                    for cand_hint in cand_hints {
                        let norm_hint = cand_hint.trim().trim_end_matches('.').to_ascii_lowercase();
                        if !norm_hint.is_empty()
                            && history.is_domain_ip_superseded(&exe_k, &norm_hint, *cand_ip)
                        {
                            sup_blocks.insert((*cand_ip, norm_hint));
                        }
                    }
                    if !cand_ips.contains(cand_ip) {
                        cand_ips.push(*cand_ip);
                    }
                }
                let current = if cand_ips.is_empty() {
                    Vec::new()
                } else {
                    history.current_domains_by_ip_for_exe(&exe_k, &cand_ips)
                };
                let mut sup_permits: HashSet<(IpAddr, String)> = HashSet::new();
                for (perm_ip, perm_hints) in &candidate_permits {
                    for perm_hint in perm_hints {
                        let norm_hint = perm_hint.trim().trim_end_matches('.').to_ascii_lowercase();
                        if !norm_hint.is_empty()
                            && history.is_domain_ip_superseded(&exe_k, &norm_hint, *perm_ip)
                        {
                            sup_permits.insert((*perm_ip, norm_hint));
                        }
                    }
                }
                (active, sup_blocks, current, sup_permits)
            };

            let mut static_blocked_ips: HashSet<IpAddr> = HashSet::new();
            for (cand_ip, _) in &candidate_blocks {
                if matches!(
                    evaluate_outbound_policy(&bin_identity, *cand_ip, None, &rules),
                    OutboundDecision::BlockedByRule { .. }
                ) {
                    static_blocked_ips.insert(*cand_ip);
                }
            }
            let mut active_blocking_domains_by_ip: HashMap<IpAddr, Vec<String>> = HashMap::new();
            for (entry_ip, entry_dom) in current_domain_entries
                .into_iter()
                .chain(active_dns_entries)
            {
                let matches_domain_block = rules.iter().any(|r| {
                    matches_network_block_rule(r, &bin_identity, entry_ip, Some(&entry_dom))
                        && !matches_network_block_rule(r, &bin_identity, entry_ip, None)
                });
                if matches_domain_block {
                    let list = active_blocking_domains_by_ip.entry(entry_ip).or_default();
                    if !list.iter().any(|existing| existing == &entry_dom) {
                        list.push(entry_dom);
                    }
                }
            }

            {
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if !candidate_blocks.is_empty() {
                    fw.invalidate_stale_domain_blocks_for_query(
                        exe_path,
                        norm_query,
                        &all_canon_ips,
                        &static_blocked_ips,
                        &active_blocking_domains_by_ip,
                        &superseded_block_pairs,
                        &*self.defense,
                    );
                }
                if !candidate_permits.is_empty() {
                    fw.prune_migrated_domain_permit_hints_for_query(
                        exe_path,
                        norm_query,
                        &all_canon_ips,
                        &bin_identity,
                        &rules,
                        &superseded_permit_pairs,
                    );
                }
            }
            cached_rules = Some(rules);
            cached_identity = Some(bin_identity);
        }

        if !has_domain_rules || external_ips.is_empty() {
            return;
        }

        let rules = cached_rules.unwrap_or_else(|| self.store.list_network_rules().unwrap_or_default());
        let matching_path_rules: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
            })
            .collect();
        if matching_path_rules.is_empty() {
            return;
        }

        let any_domain_target_matches = matching_path_rules.iter().any(|r| {
            r.allowed_target
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && parse_literal_target_ip(s).is_none())
                .is_some_and(|pat| {
                    external_ips
                        .iter()
                        .any(|ip| matches_network_target(pat, *ip, Some(norm_query)))
                })
        });
        if !any_domain_target_matches {
            return;
        }

        let bin_identity = cached_identity.unwrap_or_else(|| self.inspector.inspect(exe_path));
        for ip in external_ips {
            let decision = evaluate_outbound_policy(&bin_identity, ip, Some(norm_query), &rules);
            match decision {
                OutboundDecision::BlockedByRule { rule_id } => {
                    let matched_target = rules
                        .iter()
                        .find(|r| r.rule_id == rule_id)
                        .and_then(|r| r.allowed_target.as_deref())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let needs_domain_block = matched_target
                        .is_some_and(|target_pat| parse_literal_target_ip(target_pat).is_none());
                    let domain_blocked_hints = if needs_domain_block {
                        let mut block_hint_candidates =
                            vec![(norm_query.to_ascii_lowercase(), i64::MAX)];
                        {
                            let history = self
                                .process_dns_history
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            for dom in history.domains_for_exe_ip(&exe_k, ip) {
                                if !block_hint_candidates
                                    .iter()
                                    .any(|(existing, _)| existing.eq_ignore_ascii_case(&dom))
                                {
                                    block_hint_candidates.push((dom, 0));
                                }
                            }
                        }
                        collect_domain_specific_blocked_hints(
                            &bin_identity,
                            ip,
                            &block_hint_candidates,
                            &rules,
                        )
                    } else {
                        Vec::new()
                    };
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let res = match matched_target {
                        None => fw.ensure_policy_block(exe_path, None, &*self.defense),
                        Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                            fw.ensure_policy_block(exe_path, Some(ip), &*self.defense)
                        }
                        Some(target_pat)
                            if parse_cidr_target(target_pat).is_ok()
                                || matches_network_target(target_pat, ip, None) =>
                        {
                            fw.ensure_domain_policy_block_hints(
                                exe_path,
                                ip,
                                &domain_blocked_hints,
                                &*self.defense,
                            )
                        }
                        Some(_) => {
                            if !domain_blocked_hints.is_empty() {
                                fw.ensure_domain_policy_block_hints(
                                    exe_path,
                                    ip,
                                    &domain_blocked_hints,
                                    &*self.defense,
                                )
                            } else {
                                fw.ensure_domain_policy_block(
                                    exe_path,
                                    ip,
                                    norm_query,
                                    &*self.defense,
                                )
                            }
                        }
                    };
                    if let Err(err) = res {
                        tracing::debug!(
                            exe_path = %exe_path,
                            query_name = %norm_query,
                            dst_ip = %ip,
                            error = %err,
                            "failed pre-materializing DomainPolicy WFP Block on DnsQuery"
                        );
                    }
                }
                OutboundDecision::AllowedByRule { .. } => {
                    // Enforce deny-overrides-allow across all currently active domains sharing
                    // `(exe_k, ip)` before pre-materializing an IP-level WFP Permit (`#2`).
                    let shared_candidates: Vec<(String, i64)> = {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let mut cands = Vec::new();
                        cands.push((norm_query.to_ascii_lowercase(), i64::MAX));
                        for dom in history.domains_for_exe_ip(&exe_k, ip) {
                            if !cands.iter().any(|(existing, _)| existing == &dom) {
                                cands.push((dom, 0));
                            }
                        }
                        cands
                    };
                    let (effective_decision, blocking_hint) = select_outbound_decision_for_domains(
                        &bin_identity,
                        ip,
                        &shared_candidates,
                        &rules,
                    );
                    if matches!(effective_decision, OutboundDecision::BlockedByRule { .. }) {
                        tracing::warn!(
                            exe_path = %exe_path,
                            query_name = %norm_query,
                            blocking_domain = ?blocking_hint,
                            dst_ip = %ip,
                            "suppressing DomainPolicy WFP Permit pre-materialization because another active domain on this shared IP is blocked (deny-overrides-allow)"
                        );
                        continue;
                    }
                    let permit_candidates: Vec<&str> = shared_candidates
                        .iter()
                        .map(|(dom, _)| dom.as_str())
                        .collect();
                    let (mut authorizing_hints, cohosted_hints) =
                        partition_permit_hints(&bin_identity, ip, &permit_candidates, &rules);
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    if fw.active_app_block(exe_path).is_some() {
                        extend_authorizing_hints_from_existing_permit(
                            &fw,
                            exe_path,
                            ip,
                            &bin_identity,
                            &rules,
                            &mut authorizing_hints,
                        );
                        if let Err(err) = fw.ensure_ip_permit_for_domain_hints_prioritized(
                            exe_path,
                            ip,
                            &authorizing_hints,
                            &cohosted_hints,
                            &*self.defense,
                        ) {
                            tracing::debug!(
                                exe_path = %exe_path,
                                query_name = %norm_query,
                                dst_ip = %ip,
                                error = %err,
                                "failed pre-materializing DomainPolicy WFP Permit on DnsQuery"
                            );
                        }
                    }
                }
                OutboundDecision::ProtectedOs
                | OutboundDecision::PreemptiveRestrict(_)
                | OutboundDecision::UnknownFirstConnect => {}
            }
        }
    }

    fn has_active_motw_for_exe(&self, exe_path: &str) -> bool {
        let trimmed = exe_path.trim();
        if trimmed.is_empty() {
            return false;
        }
        let exe_key = WfpRuleManager::exe_key(trimmed);
        self.process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_active_motw_for_exe_key(&exe_key)
    }

    pub(super) fn maybe_apply_preemptive_wfp_block(&self, exe_path: &str) {
        let has_motw = self.has_active_motw_for_exe(exe_path);
        self.maybe_apply_preemptive_wfp_block_with_motw(exe_path, has_motw);
    }

    pub(super) fn maybe_apply_preemptive_wfp_block_with_motw(&self, exe_path: &str, has_motw: bool) {
        if self.config.outbound_enforcement_mode == super::OutboundEnforcementMode::Audit {
            return;
        }
        let trimmed = exe_path.trim();
        if trimmed.is_empty() || WfpRuleManager::is_wildcard_pattern(trimmed) {
            return;
        }
        let risk = classify_outbound_risk(trimmed);
        if risk == OutboundRiskClass::ProtectedOs {
            return;
        }

        // Security #8: Before fast-returning on an existing WFP filter, re-verify the binary's
        // identity on disk (fresh SHA-256 via `SEC_0005`) whenever any Permit filter is live.
        // If the binary was overwritten or no longer authorized, immediately revoke stale Permit
        // filters and re-evaluate normal block/pre-emptive rules.
        let (has_permit, has_app_wide_permit) = {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            (
                fw.has_any_permit_filter_for_exe(trimmed),
                fw.has_active_filter(trimmed, None, true),
            )
        };
        if has_permit {
            let rules = self.store.list_network_rules().unwrap_or_default();
            let identity = self.inspector.inspect(trimmed);
            let still_authorized = if has_app_wide_permit {
                rules
                    .iter()
                    .any(|r| matches_app_wide_network_allow(r, &identity))
            } else {
                rules
                    .iter()
                    .any(|r| network_allow_rule_identity_matches(r, &identity))
            };
            if !still_authorized {
                tracing::warn!(
                    exe_path = %trimmed,
                    sha256 = ?identity.sha256,
                    "binary identity no longer matches persisted NetworkAllow rule on ProcessStart; revoking stale WFP permit(s)"
                );
                self.invalidate_non_protected_steady_pids();
                let _ = self.deploy_persisted_network_rules();
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if fw.has_any_permit_filter_for_exe(trimmed) {
                    fw.revoke_permits_for_exe(trimmed, &*self.defense);
                }
            }
        }

        let exe_key = WfpRuleManager::exe_key(trimmed);
        let (has_wildcards, is_startup_pinned) = {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            if fw.has_any_app_filter(trimmed) {
                return;
            }
            (
                fw.has_wildcard_network_rules(),
                fw.is_startup_preemptive(trimmed),
            )
        };
        let is_preemptive_risk = is_startup_pinned
            || has_motw
            || matches!(
                risk,
                OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter
            );
        if !is_preemptive_risk && !has_wildcards {
            return;
        }

        // Only run BinaryInspector on ProcessStart when a persisted network rule matches
        // `exe_path_pattern`, keeping the high-priority ProcessStart hot path I/O-free
        // when no matching rules exist (`ANALYSIS_0002`).
        let rules = self.store.list_network_rules().unwrap_or_default();
        let matching_rules: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(trimmed, &r.exe_path_pattern)
            })
            .collect();

        if !matching_rules.is_empty() {
            let needs_inspect = matching_rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    || r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                    || r.signer_subject
                        .as_deref()
                        .is_some_and(|s| !s.trim().is_empty())
            });
            let identity = if needs_inspect {
                self.inspector.inspect(trimmed)
            } else {
                BinaryIdentity {
                    exe_path: trimmed.to_string(),
                    sha256: None,
                    authenticode: None,
                }
            };

            if matching_rules
                .iter()
                .any(|r| matches_app_wide_network_block(r, &identity))
            {
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(err) = fw.ensure_policy_block(trimmed, None, &*self.defense) {
                    tracing::warn!(
                        exe_path = %trimmed,
                        error = %err,
                        "failed to apply persisted NetworkBlock WFP filter on ProcessStart"
                    );
                }
                return;
            }

            // Apply any literal IP-specific NetworkBlock rules matching this newly started
            // concrete executable (e.g. from wildcard `exe_path_pattern` rules).
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
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        if let Err(err) = fw.ensure_policy_block(trimmed, Some(ip), &*self.defense) {
                            tracing::warn!(
                                exe_path = %trimmed,
                                remote_ip = %ip,
                                error = %err,
                                "failed to apply IP-scoped NetworkBlock WFP filter on ProcessStart"
                            );
                        }
                    }
                }
            }

            if matching_rules
                .iter()
                .any(|r| matches_app_wide_network_allow(r, &identity))
            {
                // App-wide NetworkAllow suppresses pre-emptive block.
                return;
            }
        }

        if !is_preemptive_risk {
            return;
        }

        let has_static_risk = matches!(
            risk,
            OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter
        );
        let is_preemptive_still_needed = |fw: &WfpRuleManager| -> bool {
            if fw.is_startup_preemptive(trimmed) {
                return true;
            }
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if has_static_risk {
                table.has_active_exe_key(&exe_key)
            } else {
                table.has_active_motw_for_exe_key(&exe_key)
            }
        };

        // Bug #2 & PRRT_kwDOVyjVyM66jl1W: Do not re-apply an app-wide automatic Preemptive WFP
        // block while another running sibling instance holds an active AllowOnce grant, and avoid
        // installing a fresh BFE handle when no qualifying active process remains (unless
        // startup-pinned). Lock order: `firewall` -> `process_table`.
        {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            if fw.has_any_app_filter(trimmed) || fw.has_once_allowed_for_exe(&exe_key) {
                tracing::debug!(
                    exe_path = %trimmed,
                    "deferring automatic pre-emptive WFP block while existing filter or AllowOnce is active"
                );
                return;
            }
            if !is_preemptive_still_needed(&fw) {
                tracing::debug!(
                    exe_path = %trimmed,
                    "skipping automatic pre-emptive WFP block because no qualifying active instance remains"
                );
                return;
            }
        }

        match self.defense.add_wfp_app_rule(Path::new(trimmed), None, false) {
            Ok(handle) => {
                // Re-verify process liveness atomically under `firewall` -> `process_table` before
                // committing `handle` so a concurrent `ProcessStop` cleanup cannot leave an
                // orphaned preemptive block for an already-exited executable. If removal fails
                // while the slot is vacant, `discard_obsolete_preemptive_block` retains `handle`
                // in `WfpRuleManager` so periodic unused-preemptive sweeps, subsequent
                // `ProcessStop`, `AllowOnce`, or app-wide `NetworkAllow` reconciliation can retry.
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if !is_preemptive_still_needed(&fw) {
                    fw.discard_obsolete_preemptive_block(trimmed, handle, &*self.defense);
                } else if fw.register_preemptive_block(trimmed, handle, &*self.defense) {
                    tracing::info!(
                        exe_path = %trimmed,
                        risk = ?risk,
                        wfp_handle = handle,
                        "applied pre-emptive WFP dynamic outbound block"
                    );
                }
            }
            Err(err) => {
                tracing::debug!(
                    exe_path = %trimmed,
                    risk = ?risk,
                    error = %err,
                    "pre-emptive WFP block unavailable on ProcessStart"
                );
            }
        }
    }

    /// Periodically retries removing unused non-startup `Preemptive` WFP blocks (for example,
    /// handles retained after transient `remove_wfp_rule` failures during `ProcessStop` or
    /// `discard_obsolete_preemptive_block`) without waiting for process relaunch or an app-wide
    /// `NetworkAllow` reconciliation (`PRRT_kwDOVyjVyM66kD_M`).
    ///
    /// Lock order: `firewall` -> `process_table` (unified with
    /// `maybe_apply_preemptive_wfp_block_with_motw`, `events.rs`, and `alerts.rs`). Fast-paths
    /// with zero `process_table` locks when no sweepable `Preemptive` filter is installed.
    pub(super) fn sweep_unused_preemptive_wfp_blocks(&self) -> usize {
        if !self.config.outbound_firewall_enabled {
            return 0;
        }
        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
        fw.sweep_unused_preemptive_blocks(
            |exe_key| {
                self.process_table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .has_active_exe_key(exe_key)
            },
            &*self.defense,
        )
    }
}
