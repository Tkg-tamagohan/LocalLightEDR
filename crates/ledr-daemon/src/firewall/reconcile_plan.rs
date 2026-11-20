//! Read-only desired persisted WFP plan construction, failure attribution, and report formatting.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope};
use ledr_rules::{
    matches_app_wide_network_allow, matches_app_wide_network_block, matches_network_allow_rule,
    matches_network_block_rule, matches_network_target, matches_path_pattern, parse_cidr_target,
    BinaryIdentity,
};

use crate::engine::BinaryInspector;

use super::manager::WfpRuleManager;
use super::types::{
    parse_literal_target_ip, WfpFailedOp, WfpReconcileReport, WfpTargetKey,
};

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

pub(super) struct DesiredPersistedPlan {
    pub(super) desired: HashMap<WfpTargetKey, (String, bool)>,
    pub(super) desired_sources: HashMap<WfpTargetKey, Vec<String>>,
    pub(super) skipped_wildcard: usize,
    pub(super) has_wildcard_network_rules: bool,
    pub(super) has_domain_network_rules: bool,
}

impl WfpRuleManager {
    pub(super) fn build_desired_persisted_plan(
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

    pub(super) fn collect_removed_prev_persisted_sources(
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

    pub(super) fn collect_removed_prev_domain_sources(
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
}
