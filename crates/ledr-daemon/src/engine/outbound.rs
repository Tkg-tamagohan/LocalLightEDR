use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::Ordering;

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, RuleScope, SensorEvent,
};
use ledr_rules::{
    classify_outbound_risk, evaluate_outbound_policy, is_external_ip,
    matches_app_wide_network_allow, matches_network_target, matches_path_pattern,
    parse_cidr_target, BinaryIdentity, OutboundDecision, OutboundRiskClass,
};
use uuid::Uuid;

#[cfg(doc)]
use crate::firewall::WfpFilterOrigin;
use crate::firewall::{parse_literal_target_ip, WfpRuleManager};

use super::config::OutboundEnforcementMode;
use super::domain_policy::{
    collect_domain_specific_blocked_hints, extend_authorizing_hints_from_existing_permit,
    network_allow_rule_identity_matches, outbound_alert_title, partition_permit_hints,
    select_outbound_decision_for_domains,
};
use super::events::ResolvedProcessContext;
use super::DaemonEngine;

/// Maximum number of verified process instances cached for app-wide `NetworkAllow` fast path.
pub(super) const VERIFIED_APP_WIDE_ALLOW_CAPACITY: usize = 4_096;

/// Cached verification proof for a concrete process instance (`create_time_100ns != 0`) that
/// passed full `BinaryInspector` (`SEC_0005` SHA-256 + Authenticode) against an unscoped
/// app-wide `NetworkAllow` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedAppWideAllowEntry {
    pub(super) exe_key: String,
    pub(super) authorizing_rule: AllowlistRuleRecord,
}

/// Bounded FIFO cache mapping `process_instance_id` (`create_time_100ns != 0` only) to its
/// verified app-wide `NetworkAllow` entry so steady browser connections avoid re-hashing the
/// executable on disk while `WindowsBinaryInspector::inspect` stays strictly uncached (`SEC_0005`).
#[derive(Debug)]
pub(super) struct VerifiedAppWideAllowCache {
    capacity: usize,
    next_gen: u64,
    entries: HashMap<String, (VerifiedAppWideAllowEntry, u64)>,
    order: VecDeque<(String, u64)>,
}

impl VerifiedAppWideAllowCache {
    pub(super) fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            next_gen: 1,
            entries: HashMap::with_capacity(cap.min(256)),
            order: VecDeque::with_capacity(cap.min(256)),
        }
    }

    pub(super) fn get(&self, instance_id: &str) -> Option<&VerifiedAppWideAllowEntry> {
        self.entries.get(instance_id).map(|(entry, _)| entry)
    }

    pub(super) fn insert(&mut self, instance_id: String, entry: VerifiedAppWideAllowEntry) {
        if let Some((existing, _)) = self.entries.get_mut(&instance_id) {
            *existing = entry;
            return;
        }
        while self.entries.len() >= self.capacity {
            let Some((oldest_id, oldest_gen)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&oldest_id)
                .is_some_and(|(_, cur_gen)| *cur_gen == oldest_gen)
            {
                self.entries.remove(&oldest_id);
            }
        }
        let gen_id = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        self.entries.insert(instance_id.clone(), (entry, gen_id));
        self.order.push_back((instance_id, gen_id));
        if self.order.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.order
                .retain(|(id, g)| entries.get(id).is_some_and(|(_, cur_gen)| cur_gen == g));
        }
    }

    pub(super) fn remove(&mut self, instance_id: &str) -> bool {
        self.entries.remove(instance_id).is_some()
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(super) fn order_len(&self) -> usize {
        self.order.len()
    }
}

/// Per-process alert deduplication key for enforced (suspension/WFP-containment) outbound alerts.
pub(super) const NET_OUTBOUND_ENFORCE_DEDUP_KEY: &str = "NET_OUTBOUND";

/// Per-process alert deduplication key for observe-only outbound alerts (e.g. `Audit` mode or
/// non-MOTW `GeneralUnknown` processes in `PreemptiveOnly` mode before delayed MOTW elevation).
pub(super) const NET_OUTBOUND_OBSERVE_DEDUP_KEY: &str = "NET_OUTBOUND_OBSERVE";

impl DaemonEngine {
    pub(super) fn resolve_effective_domain_candidates(
        &self,
        proc_instance_id: Option<&str>,
        exe_path: Option<&str>,
        dst_ip: IpAddr,
        raw_domain_hint: Option<&str>,
        event_ts_ms: i64,
    ) -> Vec<(String, i64)> {
        let clean_raw = raw_domain_hint
            .map(str::trim)
            .map(|s| s.trim_end_matches('.'))
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);
        let history = self
            .process_dns_history
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut own_candidates = proc_instance_id
            .map(|id| history.lookup_domains_for_process(id, dst_ip))
            .unwrap_or_default();
        let Some(hint) = clean_raw else {
            return own_candidates;
        };
        if own_candidates
            .iter()
            .any(|(d, _)| d.eq_ignore_ascii_case(&hint))
        {
            return own_candidates;
        }
        if history.another_process_resolved(proc_instance_id, &hint, dst_ip, event_ts_ms) {
            if let Some((own_domain, _)) = own_candidates.first() {
                tracing::debug!(
                    process_instance_id = ?proc_instance_id,
                    dst_ip = %dst_ip,
                    dropped_domain_hint = %hint,
                    own_domain = %own_domain,
                    "replacing cross-process domain_hint with process instance's own DNS record (SEC_0009)"
                );
            } else {
                tracing::debug!(
                    process_instance_id = ?proc_instance_id,
                    dst_ip = %dst_ip,
                    dropped_domain_hint = %hint,
                    "dropping cross-process domain_hint not resolved by connecting process instance (SEC_0009)"
                );
            }
            return own_candidates;
        }
        if exe_path.is_some_and(|p| {
            history.is_domain_ip_superseded_at_or_before(
                &WfpRuleManager::exe_key(p),
                &hint,
                dst_ip,
                event_ts_ms,
            )
        }) {
            tracing::debug!(
                process_instance_id = ?proc_instance_id,
                dst_ip = %dst_ip,
                dropped_domain_hint = %hint,
                "dropping stale sensor domain_hint superseded by newer DNS migration for executable"
            );
            return own_candidates;
        }
        // Raw hint was not resolved by another process (e.g. pre-daemon DNS or direct event hint);
        // keep it alongside the process's own candidates so common priority evaluation sees all.
        own_candidates.push((hint, event_ts_ms));
        own_candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        own_candidates
    }

    pub(super) fn handle_network_connect(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        event_ts_ms: i64,
    ) -> (&'static str, bool) {
        let SensorEvent::NetworkConnect {
            pid,
            protocol,
            dst_ip,
            dst_port,
            domain_hint,
            ..
        } = event
        else {
            return ("OBSERVED", false);
        };

        if !is_external_ip(*dst_ip) {
            return ("OBSERVED", false);
        }

        let Some(exe_path) = proc_ctx
            .proc_exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return ("OBSERVED", false);
        };

        let risk = classify_outbound_risk(exe_path);
        if risk == OutboundRiskClass::ProtectedOs {
            self.outbound_classifier.mark_protected_os(*pid);
            return ("OBSERVED", false);
        }

        let domain_candidates = self.resolve_effective_domain_candidates(
            proc_ctx.proc_instance_id.as_deref(),
            Some(exe_path),
            *dst_ip,
            domain_hint.as_deref(),
            event_ts_ms,
        );

        self.evaluate_and_handle_outbound_connect(
            Some(event),
            proc_ctx,
            exe_path,
            *pid,
            *protocol,
            *dst_ip,
            *dst_port,
            &domain_candidates,
            event_ts_ms,
        )
    }

    /// Re-validates whether a live [`WfpFilterOrigin::DomainPolicy`] IP Permit for
    /// `(exe_path, dst_ip)` remains authorized under the latest `bin_identity` and current `rules`
    /// with zero conflicting `NetworkBlock` matches across static policy, stored Permit hints,
    /// current `domain_candidates`, and active exe-wide DNS history (`AUD-P3-01`).
    ///
    /// When `ambiguous_freshness` is `Some((event_ts_ms, max_age_ms))` (multi-instance WFP drops
    /// with `candidates.len() > 1`), requires static allow or at least one authorizing Permit hint
    /// to have a fresh DNS record in `ProcessDnsHistory` within `[event_ts_ms - max_age_ms,
    /// event_ts_ms + 60_000]`, keeping `AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS` symmetric across
    /// `on_wfp_drop_dequeued`, `flush_ready_pending_wfp_drops`, and `handle_ambiguous_wfp_drop`.
    ///
    /// Releases `self.firewall` before locking `self.process_dns_history` (no nested locks).
    pub(super) fn has_valid_live_domain_policy_permit(
        &self,
        exe_path: &str,
        bin_identity: &BinaryIdentity,
        dst_ip: IpAddr,
        domain_candidates: &[(String, i64)],
        rules: &[AllowlistRuleRecord],
        ambiguous_freshness: Option<(i64, i64)>,
    ) -> bool {
        let Some(permit_hints) = ({
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            fw.domain_policy_permit_hints(exe_path, dst_ip)
        }) else {
            return false;
        };

        let static_allowed = match evaluate_outbound_policy(bin_identity, dst_ip, None, rules) {
            OutboundDecision::BlockedByRule { .. } => return false,
            OutboundDecision::AllowedByRule { .. } => true,
            _ => false,
        };

        let mut allowed_hints: Vec<&str> = Vec::new();
        for hint in &permit_hints {
            let norm = hint.trim().trim_end_matches('.');
            if norm.is_empty() {
                continue;
            }
            match evaluate_outbound_policy(bin_identity, dst_ip, Some(norm), rules) {
                OutboundDecision::BlockedByRule { .. } => return false,
                OutboundDecision::AllowedByRule { .. } => allowed_hints.push(norm),
                _ => {}
            }
        }
        if !static_allowed && allowed_hints.is_empty() {
            return false;
        }

        for (dom, _) in domain_candidates {
            let norm = dom.trim().trim_end_matches('.');
            if norm.is_empty() {
                continue;
            }
            if matches!(
                evaluate_outbound_policy(bin_identity, dst_ip, Some(norm), rules),
                OutboundDecision::BlockedByRule { .. }
            ) {
                return false;
            }
        }

        let exe_k = WfpRuleManager::exe_key(exe_path);
        let (exe_domains, freshness_ok) = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let exe_domains = history.domains_for_exe_ip(&exe_k, dst_ip);
            let freshness_ok = match ambiguous_freshness {
                None => true,
                Some((event_ts_ms, max_age_ms)) => {
                    static_allowed
                        || allowed_hints.iter().any(|hint| {
                            history.has_fresh_domain_record_for_family(
                                &exe_k,
                                hint,
                                dst_ip,
                                event_ts_ms,
                                max_age_ms,
                                |k_dom| {
                                    matches!(
                                        evaluate_outbound_policy(
                                            bin_identity,
                                            dst_ip,
                                            Some(k_dom),
                                            rules,
                                        ),
                                        OutboundDecision::AllowedByRule { .. }
                                    )
                                },
                            )
                        })
                }
            };
            (exe_domains, freshness_ok)
        };
        if !freshness_ok {
            return false;
        }
        for dom in &exe_domains {
            let norm = dom.trim().trim_end_matches('.');
            if norm.is_empty() {
                continue;
            }
            if matches!(
                evaluate_outbound_policy(bin_identity, dst_ip, Some(norm), rules),
                OutboundDecision::BlockedByRule { .. }
            ) {
                return false;
            }
        }

        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn evaluate_and_handle_outbound_connect(
        &self,
        event: Option<&SensorEvent>,
        proc_ctx: &ResolvedProcessContext,
        exe_path: &str,
        pid: u32,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        domain_candidates: &[(String, i64)],
        event_ts_ms: i64,
    ) -> (&'static str, bool) {
        let risk = classify_outbound_risk(exe_path);
        let is_motw_origin = proc_ctx.origin_url.is_some();
        let effective_risk = if is_motw_origin && risk == OutboundRiskClass::GeneralUnknown {
            OutboundRiskClass::HighRiskPath
        } else {
            risk
        };

        let should_enforce_for_path = match self.config.outbound_enforcement_mode {
            OutboundEnforcementMode::Enforce => true,
            OutboundEnforcementMode::PreemptiveOnly => {
                matches!(
                    effective_risk,
                    OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter
                )
            }
            OutboundEnforcementMode::Audit => false,
        };
        let path_dedup_key = if should_enforce_for_path {
            NET_OUTBOUND_ENFORCE_DEDUP_KEY
        } else {
            NET_OUTBOUND_OBSERVE_DEDUP_KEY
        };
        let already_outbound_alerted = proc_ctx
            .proc_instance_id
            .as_deref()
            .is_some_and(|inst_id| self.has_rule_alert_emitted(inst_id, path_dedup_key));
        let (rules, rules_loaded) = match self.store.list_network_rules() {
            Ok(rules) => (rules, true),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to load network rules during outbound evaluation"
                );
                (Vec::new(), false)
            }
        };
        let has_potentially_matching_rule = rules.iter().any(|r| {
            let pat = r.exe_path_pattern.trim();
            pat.is_empty() || matches_path_pattern(exe_path, pat)
        });
        // Fast path (`ANALYSIS_0001`): when already alerted and no persisted network rule can
        // match this executable path, avoid re-running BinaryInspector (full SHA-256) on every
        // repeated connect in a burst. When any rule could match `exe_path` (or rule loading
        // failed), always evaluate policy first so explicit NetworkBlock / NetworkAllow rules are
        // never bypassed by NET_OUTBOUND alert deduplication.
        if rules_loaded && !has_potentially_matching_rule {
            let once_allowed = proc_ctx.proc_instance_id.as_deref().is_some_and(|inst_id| {
                self.firewall
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_once_allowed(inst_id)
            });
            if once_allowed {
                self.outbound_classifier.mark_steady(pid);
                return ("ALLOWED", false);
            }
            if already_outbound_alerted {
                self.outbound_classifier.mark_steady(pid);
                return ("DEDUP_SUPPRESSED", false);
            }
        }

        let has_block_rule_for_exe = rules.iter().any(|r| {
            r.scope == RuleScope::NetworkBlock
                && (r.exe_path_pattern.trim().is_empty()
                    || matches_path_pattern(exe_path, &r.exe_path_pattern))
        });
        let has_target_scoped_rule_for_exe = rules.iter().any(|r| {
            matches!(r.scope, RuleScope::NetworkAllow | RuleScope::NetworkBlock)
                && r.allowed_target
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
                && (r.exe_path_pattern.trim().is_empty()
                    || matches_path_pattern(exe_path, &r.exe_path_pattern))
        });
        let verified_inst_id = proc_ctx
            .proc_identity
            .filter(|id| id.create_time_100ns != 0)
            .and_then(|id| {
                proc_ctx
                    .proc_instance_id
                    .as_deref()
                    .filter(|inst_id| *inst_id == id.instance_id())
            });
        let is_audit_mode =
            self.config.outbound_enforcement_mode == OutboundEnforcementMode::Audit;

        // Verified app-wide `NetworkAllow` fast path: for a concrete process instance
        // (`create_time_100ns != 0`) already verified once against an unscoped app-wide allow
        // rule, skip redundant `inspector.inspect` (disk SHA-256 + Authenticode) only when the
        // live rules snapshot has no `NetworkBlock` or target-scoped rule for `exe_path`, the
        // authorizing rule's ID and full content are unchanged, and (outside Audit mode) an
        // app-wide WFP Permit filter is active with no app-wide block.
        if rules_loaded {
            if let Some(inst_id) = verified_inst_id {
                let exe_k = WfpRuleManager::exe_key(exe_path);
                let cached_rule_valid = {
                    let mut cache = self
                        .verified_app_wide_allows
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    match cache.get(inst_id) {
                        Some(entry)
                            if entry.exe_key == exe_k
                                && !has_block_rule_for_exe
                                && !has_target_scoped_rule_for_exe
                                && rules.iter().any(|r| {
                                    r.scope == RuleScope::NetworkAllow
                                        && r.allowed_target
                                            .as_deref()
                                            .is_none_or(|s| s.trim().is_empty())
                                        && r == &entry.authorizing_rule
                                }) =>
                        {
                            true
                        }
                        Some(_) => {
                            cache.remove(inst_id);
                            false
                        }
                        None => false,
                    }
                };
                if cached_rule_valid {
                    let wfp_ok = {
                        let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.active_app_block(exe_path).is_none()
                            && (is_audit_mode || fw.has_active_filter(exe_path, None, true))
                    };
                    if wfp_ok {
                        if !is_audit_mode {
                            self.outbound_classifier.mark_steady(pid);
                        }
                        return ("ALLOWED", false);
                    }
                    self.verified_app_wide_allows
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(inst_id);
                }
            }
        }

        let bin_identity = self.inspector.inspect(exe_path);
        let (decision, effective_domain_hint) = select_outbound_decision_for_domains(
            &bin_identity,
            dst_ip,
            domain_candidates,
            &rules,
        );
        let synthetic_event;
        let alert_event: &SensorEvent = match event {
            Some(ev) => ev,
            None => {
                synthetic_event = SensorEvent::NetworkConnect {
                    pid,
                    protocol,
                    dst_ip,
                    dst_port,
                    domain_hint: effective_domain_hint.clone(),
                    timestamp_ms: event_ts_ms,
                };
                &synthetic_event
            }
        };
        let has_domain_rules_for_exe = rules.iter().any(|r| {
            matches!(r.scope, RuleScope::NetworkAllow | RuleScope::NetworkBlock)
                && r.allowed_target
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| {
                        !s.is_empty()
                            && parse_literal_target_ip(s).is_none()
                            && parse_cidr_target(s).is_err()
                    })
                && !r.exe_path_pattern.trim().is_empty()
                && matches_path_pattern(exe_path, &r.exe_path_pattern)
        });

        match decision {
            OutboundDecision::ProtectedOs => {
                self.outbound_classifier.mark_protected_os(pid);
                ("OBSERVED", false)
            }
            OutboundDecision::AllowedByRule { rule_id } => {
                let authorizing_app_wide_rule = rules.iter().find(|r| {
                    r.rule_id == rule_id
                        && r.scope == RuleScope::NetworkAllow
                        && r.allowed_target
                            .as_deref()
                            .is_none_or(|s| s.trim().is_empty())
                });
                // Serialize app-wide WFP Permit materialization, steady-PID promotion, and
                // `verified_app_wide_allows` caching with `upsert_policy_rule`/`delete_policy_rule`
                // (`policy_lock -> store/firewall -> verified_app_wide_allows`) and re-verify
                // against the latest persisted rules so a rule deleted while `inspector.inspect`
                // was running can never resurrect a stale WFP Permit (`SEC_0001`).
                let app_wide_candidate = rules_loaded
                    && authorizing_app_wide_rule.is_some()
                    && !has_block_rule_for_exe
                    && !has_target_scoped_rule_for_exe;
                let _policy_guard = app_wide_candidate
                    .then(|| self.policy_lock.lock().unwrap_or_else(|e| e.into_inner()));
                let fresh_app_wide_rule: Option<AllowlistRuleRecord> = if app_wide_candidate {
                    self.store.list_network_rules().ok().and_then(|fresh_rules| {
                        let fresh_has_block = fresh_rules.iter().any(|r| {
                            r.scope == RuleScope::NetworkBlock
                                && (r.exe_path_pattern.trim().is_empty()
                                    || matches_path_pattern(exe_path, &r.exe_path_pattern))
                        });
                        let fresh_has_scoped = fresh_rules.iter().any(|r| {
                            matches!(r.scope, RuleScope::NetworkAllow | RuleScope::NetworkBlock)
                                && r.allowed_target
                                    .as_deref()
                                    .is_some_and(|s| !s.trim().is_empty())
                                && (r.exe_path_pattern.trim().is_empty()
                                    || matches_path_pattern(exe_path, &r.exe_path_pattern))
                        });
                        if fresh_has_block || fresh_has_scoped {
                            return None;
                        }
                        fresh_rules
                            .into_iter()
                            .find(|r| matches_app_wide_network_allow(r, &bin_identity))
                    })
                } else {
                    None
                };

                // If an app-wide pre-emptive block is active (e.g. script interpreter with a
                // domain/CIDR-scoped NetworkAllow), install an IP-specific Permit so this
                // destination flows cleanly through WFP and survives rule reconciliations —
                // UNLESS another active domain for this executable on the same shared IP is
                // blocked (deny-overrides-allow across exe-wide DNS history, matching
                // `prematerialize_domain_wfp_filters`).
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if fw.active_app_block(exe_path).is_some() {
                    let exe_k = WfpRuleManager::exe_key(exe_path);
                    let (shared_cands, shared_blocking_hint): (
                        Vec<(String, i64)>,
                        Option<Option<String>>,
                    ) = {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        let mut shared_cands: Vec<(String, i64)> = domain_candidates.to_vec();
                        for dom in history.domains_for_exe_ip(&exe_k, dst_ip) {
                            if !shared_cands
                                .iter()
                                .any(|(existing, _)| existing.eq_ignore_ascii_case(&dom))
                            {
                                shared_cands.push((dom, 0));
                            }
                        }
                        let (eff_decision, blocking_hint) = select_outbound_decision_for_domains(
                            &bin_identity,
                            dst_ip,
                            &shared_cands,
                            &rules,
                        );
                        let blocking = matches!(eff_decision, OutboundDecision::BlockedByRule { .. })
                            .then_some(blocking_hint);
                        (shared_cands, blocking)
                    };
                    if let Some(blocking_hint) = shared_blocking_hint {
                        tracing::warn!(
                            exe_path = %exe_path,
                            dst_ip = %dst_ip,
                            blocking_domain = ?blocking_hint,
                            "suppressing DomainPolicy WFP Permit installation on outbound connect because another active domain on this shared IP is blocked (deny-overrides-allow)"
                        );
                    } else {
                        let matched_target = rules
                            .iter()
                            .find(|r| r.rule_id == rule_id)
                            .and_then(|r| r.allowed_target.as_deref())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        // Propagate all active shared-IP domains (already verified free of
                        // `BlockedByRule` above) onto the Permit while protecting authorizing
                        // hints from FIFO eviction at `MAX_DOMAIN_HINTS_PER_FILTER` (`#1`, `#2`,
                        // `#4`, `AUD-P3-02`).
                        let permit_candidates: Vec<&str> = shared_cands
                            .iter()
                            .map(|(dom, _)| dom.as_str())
                            .collect();
                        let (mut authorizing_hints, cohosted_hints) = partition_permit_hints(
                            &bin_identity,
                            dst_ip,
                            &permit_candidates,
                            &rules,
                        );
                        if authorizing_hints.is_empty() && cohosted_hints.is_empty() {
                            let fallback_domain = matched_target.filter(|t| {
                                parse_literal_target_ip(t).is_none()
                                    && parse_cidr_target(t).is_err()
                                    && !matches_network_target(t, dst_ip, None)
                            });
                            let domain_label = effective_domain_hint
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .or(fallback_domain);
                            if let Some(label) = domain_label {
                                authorizing_hints.push(label.to_string());
                            }
                        }
                        extend_authorizing_hints_from_existing_permit(
                            &fw,
                            exe_path,
                            dst_ip,
                            &bin_identity,
                            &rules,
                            &mut authorizing_hints,
                        );
                        let permit_res = fw.ensure_ip_permit_for_domain_hints_prioritized(
                            exe_path,
                            dst_ip,
                            &authorizing_hints,
                            &cohosted_hints,
                            &*self.defense,
                        );
                        if let Err(err) = permit_res {
                            tracing::debug!(
                                exe_path = %exe_path,
                                dst_ip = %dst_ip,
                                error = %err,
                                "could not install IP-specific WFP permit for allowed domain"
                            );
                        }
                    }
                } else if !is_audit_mode
                    && self.config.outbound_firewall_enabled
                    && fresh_app_wide_rule.is_some()
                    && !fw.has_active_filter(exe_path, None, true)
                {
                    // Materialize the concrete app-wide WFP Permit for wildcard app-wide allow
                    // rules (e.g. default browser rules when Chrome/Edge starts after daemon boot)
                    // so steady-PID promotion, Security #8 Permit revocation, and the
                    // `verified_app_wide_allows` fast path all engage consistently.
                    if let Err(err) = fw.ensure_policy_permit(exe_path, &*self.defense) {
                        tracing::debug!(
                            exe_path = %exe_path,
                            error = %err,
                            "could not install app-wide WFP permit for allowed executable"
                        );
                    }
                }
                let has_app_wide_permit = fw.has_active_filter(exe_path, None, true);
                let has_app_block = fw.active_app_block(exe_path).is_some();
                drop(fw);
                if has_app_wide_permit
                    && !has_block_rule_for_exe
                    && !has_domain_rules_for_exe
                    && (!app_wide_candidate || fresh_app_wide_rule.is_some())
                {
                    self.outbound_classifier.mark_steady(pid);
                }
                if !has_app_block && (is_audit_mode || has_app_wide_permit) {
                    if let (Some(inst_id), Some(auth_rule)) =
                        (verified_inst_id, fresh_app_wide_rule)
                    {
                        self.verified_app_wide_allows
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(
                                inst_id.to_string(),
                                VerifiedAppWideAllowEntry {
                                    exe_key: WfpRuleManager::exe_key(exe_path),
                                    authorizing_rule: auth_rule,
                                },
                            );
                    }
                }
                drop(_policy_guard);
                ("ALLOWED", false)
            }
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
                    let mut block_hint_candidates: Vec<(String, i64)> = domain_candidates.to_vec();
                    let exe_k = WfpRuleManager::exe_key(exe_path);
                    {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        for dom in history.domains_for_exe_ip(&exe_k, dst_ip) {
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
                        dst_ip,
                        &block_hint_candidates,
                        &rules,
                    )
                } else {
                    Vec::new()
                };
                let is_audit_mode =
                    self.config.outbound_enforcement_mode == OutboundEnforcementMode::Audit;
                let wfp_handle = if is_audit_mode {
                    None
                } else {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let res = match matched_target {
                        None => fw.ensure_policy_block(exe_path, None, &*self.defense),
                        Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                            fw.ensure_policy_block(exe_path, Some(dst_ip), &*self.defense)
                        }
                        Some(target_pat)
                            if parse_cidr_target(target_pat).is_ok()
                                || matches_network_target(target_pat, dst_ip, None) =>
                        {
                            fw.ensure_domain_policy_block_hints(
                                exe_path,
                                dst_ip,
                                &domain_blocked_hints,
                                &*self.defense,
                            )
                        }
                        Some(target_pat) => {
                            if !domain_blocked_hints.is_empty() {
                                fw.ensure_domain_policy_block_hints(
                                    exe_path,
                                    dst_ip,
                                    &domain_blocked_hints,
                                    &*self.defense,
                                )
                            } else {
                                let label = effective_domain_hint
                                    .as_deref()
                                    .map(str::trim)
                                    .filter(|s| !s.is_empty())
                                    .unwrap_or(target_pat);
                                fw.ensure_domain_policy_block(
                                    exe_path,
                                    dst_ip,
                                    label,
                                    &*self.defense,
                                )
                            }
                        }
                    };
                    match res {
                        Ok(h) => Some(h),
                        Err(err) => {
                            tracing::warn!(
                                exe_path = %exe_path,
                                rule_id = %rule_id,
                                error = %err,
                                "failed to ensure WFP block filter for matched NetworkBlock rule"
                            );
                            None
                        }
                    }
                };
                let is_new_block_alert = proc_ctx
                    .proc_instance_id
                    .as_deref()
                    .is_none_or(|inst_id| self.is_new_rule_alert(inst_id, "NET_POLICY_BLOCK"));
                if !is_new_block_alert {
                    return (if is_audit_mode { "ALERTED" } else { "BLOCKED" }, false);
                }

                let domain_risk = effective_domain_hint
                    .as_deref()
                    .map(|d| self.assess_domain(d));
                let is_first_seen_domain = effective_domain_hint
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some_and(|d| !self.store.has_seen_dns_domain(d).unwrap_or(false));
                let context_json = serde_json::json!({
                    "event": alert_event,
                    "dst_ip": dst_ip.to_string(),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain_hint": effective_domain_hint,
                    "matched_rule_id": rule_id,
                    "risk_class": format!("{effective_risk:?}"),
                    "wfp_blocked": wfp_handle.is_some(),
                    "wfp_filter_id": wfp_handle,
                    "pid": pid,
                    "exe_path": exe_path,
                    "command_line": proc_ctx.proc_command_line,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "sha256": bin_identity.sha256,
                    "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
                    "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
                    "is_nrd": domain_risk.as_ref().is_some_and(|r| r.is_nrd),
                    "is_homograph": domain_risk.as_ref().is_some_and(|r| r.is_homograph),
                    "matched_brand": domain_risk.and_then(|r| r.matched_brand),
                    "is_first_seen_domain": is_first_seen_domain,
                    "origin_url": proc_ctx.origin_url,
                    "motw_source": proc_ctx.motw_source,
                    "motw_referrer": proc_ctx.motw_referrer,
                    "motw_frame_url": proc_ctx.motw_frame_url,
                    "motw_zone_id": proc_ctx.motw_zone_id,
                })
                .to_string();
                let alert = AlertRecord {
                    alert_id: Uuid::new_v4().to_string(),
                    timestamp_ms: event_ts_ms,
                    severity: AlertSeverity::High,
                    source_layer: "LAYER_3_NETWORK".to_string(),
                    rule_id: "LEDR-NET-POLICY-BLOCK".to_string(),
                    title: outbound_alert_title(
                        "Blocked Outbound Policy Match",
                        exe_path,
                        dst_ip,
                        dst_port,
                        effective_domain_hint.as_deref(),
                    ),
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended: false,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };
                if let Err(err) = self.record_alert_checked(&alert) {
                    tracing::warn!(error = %err, "failed to record network policy block alert");
                    if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                        self.clear_rule_alert(inst_id, "NET_POLICY_BLOCK");
                    }
                    return (if is_audit_mode { "ALERTED" } else { "BLOCKED" }, false);
                }
                self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                (if is_audit_mode { "ALERTED" } else { "BLOCKED" }, true)
            }
            OutboundDecision::PreemptiveRestrict(_) | OutboundDecision::UnknownFirstConnect => {
                let should_enforce = match self.config.outbound_enforcement_mode {
                    OutboundEnforcementMode::Enforce => true,
                    OutboundEnforcementMode::PreemptiveOnly => {
                        matches!(decision, OutboundDecision::PreemptiveRestrict(_))
                            || is_motw_origin
                    }
                    OutboundEnforcementMode::Audit => false,
                };
                let outbound_dedup_key = if should_enforce {
                    NET_OUTBOUND_ENFORCE_DEDUP_KEY
                } else {
                    NET_OUTBOUND_OBSERVE_DEDUP_KEY
                };
                // Respect per-process AllowOnce grant (only when no NetworkBlock matched above).
                if let Some(inst_id) = proc_ctx.proc_instance_id.as_deref() {
                    if self
                        .firewall
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_once_allowed(inst_id)
                    {
                        if !has_block_rule_for_exe {
                            self.outbound_classifier.mark_steady(pid);
                        }
                        return ("ALLOWED", false);
                    }
                }
                // Re-validate a live `DomainPolicy` IP Permit (e.g., an allowed domain that
                // migrated to a new IP while clients connect to its cached old IP) against the
                // latest binary identity, current rules, and active exe-wide DNS history before
                // falling through to Permit revocation and containment (`AUD-P3-01`).
                if self.has_valid_live_domain_policy_permit(
                    exe_path,
                    &bin_identity,
                    dst_ip,
                    domain_candidates,
                    &rules,
                    None,
                ) {
                    return ("ALLOWED", false);
                }
                if let Some(inst_id) = proc_ctx.proc_instance_id.as_deref() {
                    let already_alerted_for_mode = if outbound_dedup_key == path_dedup_key {
                        already_outbound_alerted
                    } else {
                        self.has_rule_alert_emitted(inst_id, outbound_dedup_key)
                    };
                    if already_alerted_for_mode {
                        return ("DEDUP_SUPPRESSED", false);
                    }
                    let _ = self.is_new_rule_alert(inst_id, outbound_dedup_key);
                }

                // Security #8: If a stale WFP Permit filter remains in `firewall` (e.g., binary
                // replaced on disk after ProcessStart), revoke it before registering transient
                // containment so `register_transient_containment` is never shadowed by a stale Permit.
                if should_enforce {
                    let any_allow_identity_valid = rules
                        .iter()
                        .any(|r| network_allow_rule_identity_matches(r, &bin_identity));
                    let revoked_permits = {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        if !any_allow_identity_valid {
                            fw.revoke_permits_for_exe(exe_path, &*self.defense)
                        } else {
                            let mut count = 0usize;
                            if fw.revoke_permit_for_target(exe_path, None, &*self.defense) {
                                count += 1;
                            }
                            if fw.revoke_permit_for_target(exe_path, Some(dst_ip), &*self.defense) {
                                count += 1;
                            }
                            count
                        }
                    };
                    if revoked_permits > 0 {
                        tracing::warn!(
                            exe_path = %exe_path,
                            revoked_permits,
                            "revoked stale WFP Permit filter(s) before applying outbound containment"
                        );
                        self.invalidate_non_protected_steady_pids();
                    }
                }

                let alert_id = Uuid::new_v4().to_string();
                let verified_ident = proc_ctx
                    .proc_identity
                    .filter(|id| id.create_time_100ns != 0);

                let exe_key = WfpRuleManager::exe_key(exe_path);
                let (existing_preemptive, shared_allow_once_active) = if should_enforce {
                    let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    (
                        fw.active_app_block(exe_path),
                        fw.has_once_allowed_for_exe(&exe_key),
                    )
                } else {
                    (None, false)
                };

                let mut process_suspended = false;
                let mut wfp_filter_id: Option<u64> = None;
                let mut newly_added_transient: Option<u64> = None;
                let mut bound_existing_alert = false;
                let mut wfp_shared_allow_once_deferred = false;

                if !should_enforce {
                    tracing::info!(
                        pid,
                        exe_path = %exe_path,
                        dst_ip = %dst_ip,
                        dst_port,
                        risk_class = ?risk,
                        outbound_mode = self.config.outbound_enforcement_mode.as_str(),
                        "observed outbound connection without containment due to outbound enforcement mode"
                    );
                } else if let Some((existing_handle, _existing_origin)) = existing_preemptive {
                    wfp_filter_id = Some(existing_handle);
                    bound_existing_alert = self
                        .firewall
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .bind_alert_to_app_block(&alert_id, exe_path);
                    if let Some(ident) = verified_ident {
                        match self.defense.suspend_process(&ident, false) {
                            Ok(()) => process_suspended = true,
                            Err(err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    error = %err,
                                    "suspend_process failed on pre-emptively blocked outbound connect"
                                );
                            }
                        }
                    }
                } else if shared_allow_once_active {
                    // Bug #2: Another running sibling instance of `exe_path` currently holds an
                    // AllowOnce exemption. Suspend this new instance and emit the alert while
                    // deferring an app-wide WFP block so the AllowOnce sibling is not severed.
                    wfp_shared_allow_once_deferred = true;
                    if let Some(ident) = verified_ident {
                        match self.defense.suspend_process(&ident, false) {
                            Ok(()) => process_suspended = true,
                            Err(err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    error = %err,
                                    "suspend_process failed on outbound connect with deferred AllowOnce WFP block"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            pid,
                            exe_path = %exe_path,
                            "skipping process suspension on outbound connect with deferred AllowOnce: missing non-zero ProcessIdentity create_time_100ns"
                        );
                    }
                } else if let Some(ident) = verified_ident {
                    // Coupled containment (`L-03`, `active-defense-guards.md` #5):
                    // Add dynamic WFP block first, then suspend process; if either side fails,
                    // roll back immediately so neither an orphaned WFP filter nor an isolated
                    // suspended process remains.
                    match self.defense.add_wfp_app_rule(Path::new(exe_path), None, false) {
                        Ok(handle) => match self.defense.suspend_process(&ident, false) {
                            Ok(()) => {
                                process_suspended = true;
                                let registered = self
                                    .firewall
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .register_transient_containment(
                                        &alert_id,
                                        exe_path,
                                        handle,
                                        &*self.defense,
                                    );
                                match registered {
                                    Some(h) => {
                                        wfp_filter_id = Some(h);
                                        newly_added_transient = Some(h);
                                    }
                                    None => {
                                        wfp_filter_id = self
                                            .firewall
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .active_app_block(exe_path)
                                            .map(|(h, _)| h);
                                        bound_existing_alert = wfp_filter_id.is_some();
                                    }
                                }
                            }
                            Err(susp_err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    wfp_handle = handle,
                                    error = %susp_err,
                                    "suspend_process failed during coupled outbound containment; rolling back WFP block filter"
                                );
                                if let Err(rm_err) = self.defense.remove_wfp_rule(handle) {
                                    tracing::warn!(
                                        pid,
                                        exe_path = %exe_path,
                                        wfp_handle = handle,
                                        error = %rm_err,
                                        "compensation remove_wfp_rule failed after suspend_process error"
                                    );
                                }
                            }
                        },
                        Err(wfp_err) => {
                            tracing::warn!(
                                pid,
                                exe_path = %exe_path,
                                error = %wfp_err,
                                "add_wfp_app_rule failed during coupled outbound containment; skipping suspend to avoid orphaned state"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        pid,
                        exe_path = %exe_path,
                        "skipping coupled outbound containment: missing non-zero ProcessIdentity create_time_100ns"
                    );
                }

                let domain_risk = effective_domain_hint
                    .as_deref()
                    .map(|d| self.assess_domain(d));
                let is_first_seen_domain = effective_domain_hint
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some_and(|d| !self.store.has_seen_dns_domain(d).unwrap_or(false));
                let is_nrd_or_homograph = domain_risk
                    .as_ref()
                    .is_some_and(|r| r.is_nrd || r.is_homograph);

                let (rule_id, severity, label) = match effective_risk {
                    OutboundRiskClass::HighRiskPath => (
                        "LEDR-NET-HIGH-RISK-PATH",
                        AlertSeverity::High,
                        "High-Risk Path Outbound Connection",
                    ),
                    OutboundRiskClass::ScriptInterpreter => (
                        "LEDR-NET-SCRIPT-INTERPRETER",
                        AlertSeverity::High,
                        "Script Interpreter Outbound Connection",
                    ),
                    _ => (
                        "LEDR-NET-UNKNOWN-OUTBOUND",
                        if is_nrd_or_homograph {
                            AlertSeverity::High
                        } else {
                            AlertSeverity::Medium
                        },
                        "Unknown Process Outbound Connection",
                    ),
                };

                let context_json = serde_json::json!({
                    "event": alert_event,
                    "dst_ip": dst_ip.to_string(),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain_hint": effective_domain_hint,
                    "risk_class": format!("{effective_risk:?}"),
                    "wfp_blocked": wfp_filter_id.is_some(),
                    "wfp_filter_id": wfp_filter_id,
                    "wfp_shared_allow_once_deferred": wfp_shared_allow_once_deferred,
                    "pid": pid,
                    "exe_path": exe_path,
                    "command_line": proc_ctx.proc_command_line,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "sha256": bin_identity.sha256,
                    "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
                    "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
                    "is_nrd": domain_risk.as_ref().is_some_and(|r| r.is_nrd),
                    "is_homograph": domain_risk.as_ref().is_some_and(|r| r.is_homograph),
                    "matched_brand": domain_risk.and_then(|r| r.matched_brand),
                    "is_first_seen_domain": is_first_seen_domain,
                    "origin_url": proc_ctx.origin_url,
                    "motw_source": proc_ctx.motw_source,
                    "motw_referrer": proc_ctx.motw_referrer,
                    "motw_frame_url": proc_ctx.motw_frame_url,
                    "motw_zone_id": proc_ctx.motw_zone_id,
                })
                .to_string();

                let alert = AlertRecord {
                    alert_id: alert_id.clone(),
                    timestamp_ms: event_ts_ms,
                    severity,
                    source_layer: "LAYER_3_NETWORK".to_string(),
                    rule_id: rule_id.to_string(),
                    title: outbound_alert_title(
                        label,
                        exe_path,
                        dst_ip,
                        dst_port,
                        effective_domain_hint.as_deref(),
                    ),
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };

                if let Err(err) = self.record_alert_checked(&alert) {
                    tracing::warn!(
                        error = %err,
                        alert_id = %alert.alert_id,
                        "failed to record outbound alert; compensating suspension, transient WFP block, and dedup state"
                    );
                    if process_suspended {
                        if let Some(ident) = verified_ident {
                            if let Err(resume_err) = self.defense.resume_process(&ident) {
                                tracing::warn!(
                                    pid = ident.pid,
                                    error = %resume_err,
                                    "compensation resume_process failed after outbound record_alert error"
                                );
                            }
                        }
                    }
                    if let Some(handle) = newly_added_transient {
                        self.firewall
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .rollback_transient_containment(
                                &alert_id,
                                exe_path,
                                handle,
                                &*self.defense,
                            );
                    } else if bound_existing_alert {
                        self.firewall
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .unbind_alert(&alert_id);
                    }
                    if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                        self.clear_rule_alert(inst_id, outbound_dedup_key);
                    }
                    return ("ALERT_RECORD_FAILED", false);
                }

                self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                if should_enforce {
                    if let Err(err) = self.notifier.notify_alert(&alert) {
                        tracing::warn!(
                            alert_id = %alert.alert_id,
                            error = %err,
                            "failed to dispatch toast notification for outbound alert"
                        );
                    }
                }

                let action = match (process_suspended, wfp_filter_id.is_some()) {
                    (true, true) => "SUSPENDED_BLOCKED",
                    (false, true) => "BLOCKED",
                    (true, false) => "SUSPENDED",
                    (false, false) => "ALERTED",
                };
                (action, true)
            }
        }
    }
}
