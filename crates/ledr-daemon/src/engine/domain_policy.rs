use std::net::IpAddr;

use ledr_proto::{AllowlistRuleRecord, RuleScope, ScopedPolicyRuleRecord};
use ledr_rules::{
    evaluate_outbound_policy, evaluate_outbound_policy_with_scoped,
    matches_app_wide_network_allow, matches_network_allow_rule, matches_network_block_rule,
    matches_path_pattern, matches_scoped_network_block_rule, parse_cidr_target, BinaryIdentity,
    OutboundDecision, ProcessScopeContext,
};

use crate::firewall::{parse_literal_target_ip, WfpRuleManager};

pub(super) fn outbound_alert_title(
    label: &str,
    exe_path: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    domain_hint: Option<&str>,
) -> String {
    let exe_name = exe_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(exe_path);
    match domain_hint.map(str::trim).filter(|s| !s.is_empty()) {
        Some(domain) => format!("{label}: {exe_name} -> {domain} ({dst_ip}:{dst_port})"),
        None => format!("{label}: {exe_name} -> {dst_ip}:{dst_port}"),
    }
}

pub(super) fn has_domain_allow_rule_for_exe(exe_path: &str, rules: &[AllowlistRuleRecord]) -> bool {
    rules.iter().any(|r| {
        r.scope == RuleScope::NetworkAllow
            && !r.exe_path_pattern.trim().is_empty()
            && matches_path_pattern(exe_path, &r.exe_path_pattern)
            && r.allowed_target
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .is_some_and(|t| {
                    parse_literal_target_ip(t).is_none() && parse_cidr_target(t).is_err()
                })
    })
}

pub(super) fn has_domain_allow_rule_for_exe_with_scoped(
    exe_path: &str,
    rules: &[AllowlistRuleRecord],
    scoped_rules: &[ScopedPolicyRuleRecord],
    package_sid: Option<&str>,
) -> bool {
    if has_domain_allow_rule_for_exe(exe_path, rules) {
        return true;
    }
    let norm_sid = package_sid.map(str::trim).filter(|s| !s.is_empty());
    scoped_rules.iter().any(|r| {
        r.scope == RuleScope::NetworkAllow
            && !r.exe_path_pattern.trim().is_empty()
            && matches_path_pattern(exe_path, &r.exe_path_pattern)
            && norm_sid.is_none_or(|sid| {
                r.package_sid
                    .as_deref()
                    .is_some_and(|rule_sid| rule_sid.trim().eq_ignore_ascii_case(sid))
            })
            && r.allowed_target
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .is_some_and(|t| {
                    parse_literal_target_ip(t).is_none() && parse_cidr_target(t).is_err()
                })
    })
}

/// Evaluates outbound policy across all non-superseded domain candidates sharing `dst_ip` with a
/// single consistent precedence used by WFP pre-materialization, WFP drop triage, `NetworkConnect`,
/// and `AllowPermanent` (`#2`):
/// 1. `ProtectedOs` always wins immediately (`(ProtectedOs, None)`).
/// 2. Any candidate matching `BlockedByRule` wins over every allow rule (`deny-overrides-allow`).
/// 3. Otherwise any candidate matching `AllowedByRule` wins over unallowed candidates.
/// 4. Otherwise returns the base decision paired with the newest candidate domain (or `None` when
///    no non-empty candidate exists).
pub(super) fn select_outbound_decision_for_domains(
    bin_identity: &BinaryIdentity,
    dst_ip: IpAddr,
    candidates: &[(String, i64)],
    rules: &[AllowlistRuleRecord],
) -> (OutboundDecision, Option<String>) {
    select_outbound_decision_for_domains_with_scoped(
        bin_identity,
        &ProcessScopeContext::default(),
        dst_ip,
        candidates,
        rules,
        &[],
    )
}

pub(super) fn select_outbound_decision_for_domains_with_scoped(
    bin_identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    dst_ip: IpAddr,
    candidates: &[(String, i64)],
    rules: &[AllowlistRuleRecord],
    scoped_rules: &[ScopedPolicyRuleRecord],
) -> (OutboundDecision, Option<String>) {
    let base_decision = evaluate_outbound_policy_with_scoped(
        bin_identity,
        scope_ctx,
        dst_ip,
        None,
        rules,
        scoped_rules,
    );
    if matches!(base_decision, OutboundDecision::ProtectedOs) {
        return (OutboundDecision::ProtectedOs, None);
    }

    let mut ordered: Vec<(String, i64)> = Vec::with_capacity(candidates.len());
    for (dom, ts) in candidates {
        let norm = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if let Some(existing) = ordered.iter_mut().find(|(d, _)| d == &norm) {
            existing.1 = existing.1.max(*ts);
        } else {
            ordered.push((norm, *ts));
        }
    }
    if ordered.is_empty() {
        return (base_decision, None);
    }
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut first_allow: Option<(OutboundDecision, String)> = None;
    let mut first_decision: Option<OutboundDecision> = None;

    for (dom, _) in &ordered {
        let decision = evaluate_outbound_policy_with_scoped(
            bin_identity,
            scope_ctx,
            dst_ip,
            Some(dom.as_str()),
            rules,
            scoped_rules,
        );
        match decision {
            OutboundDecision::ProtectedOs => return (OutboundDecision::ProtectedOs, None),
            OutboundDecision::BlockedByRule { .. } => {
                return (decision, Some(dom.clone()));
            }
            OutboundDecision::AllowedByRule { .. } => {
                if first_allow.is_none() {
                    first_allow = Some((decision.clone(), dom.clone()));
                }
                if first_decision.is_none() {
                    first_decision = Some(decision);
                }
            }
            other => {
                if first_decision.is_none() {
                    first_decision = Some(other);
                }
            }
        }
    }

    if let Some((allow_decision, allow_dom)) = first_allow {
        return (allow_decision, Some(allow_dom));
    }

    (
        first_decision.unwrap_or(base_decision),
        Some(ordered[0].0.clone()),
    )
}

/// Collects all distinct normalized domain hints from `candidates` that match at least one
/// domain-specific `NetworkBlock` rule (excluding rules that already match `dst_ip` statically
/// with `domain_hint = None`, such as app-wide, literal-IP, CIDR, or wildcard-IP rules).
pub(super) fn collect_domain_specific_blocked_hints(
    bin_identity: &BinaryIdentity,
    dst_ip: IpAddr,
    candidates: &[(String, i64)],
    rules: &[AllowlistRuleRecord],
) -> Vec<String> {
    let mut ordered: Vec<(String, i64)> = Vec::with_capacity(candidates.len());
    for (dom, ts) in candidates {
        let norm = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if let Some(existing) = ordered.iter_mut().find(|(d, _)| d == &norm) {
            existing.1 = existing.1.max(*ts);
        } else {
            ordered.push((norm, *ts));
        }
    }
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut hints = Vec::new();
    for (norm, _) in ordered {
        let matches_domain_block = rules.iter().any(|r| {
            r.scope == RuleScope::NetworkBlock
                && matches_network_block_rule(r, bin_identity, dst_ip, Some(norm.as_str()))
                && !matches_network_block_rule(r, bin_identity, dst_ip, None)
        });
        if matches_domain_block && !hints.iter().any(|existing| existing == &norm) {
            hints.push(norm);
        }
    }
    hints
}

pub(super) fn collect_scoped_domain_specific_blocked_hints(
    bin_identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    dst_ip: IpAddr,
    candidates: &[(String, i64)],
    scoped_rules: &[ScopedPolicyRuleRecord],
) -> Vec<String> {
    let mut ordered: Vec<(String, i64)> = Vec::with_capacity(candidates.len());
    for (dom, ts) in candidates {
        let norm = dom.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if let Some(existing) = ordered.iter_mut().find(|(d, _)| d == &norm) {
            existing.1 = existing.1.max(*ts);
        } else {
            ordered.push((norm, *ts));
        }
    }
    ordered.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut hints = Vec::new();
    for (norm, _) in ordered {
        let matches_domain_block = scoped_rules.iter().any(|r| {
            r.scope == RuleScope::NetworkBlock
                && matches_scoped_network_block_rule(
                    r,
                    bin_identity,
                    scope_ctx,
                    dst_ip,
                    Some(norm.as_str()),
                )
                && !matches_scoped_network_block_rule(r, bin_identity, scope_ctx, dst_ip, None)
        });
        if matches_domain_block && !hints.iter().any(|existing| existing == &norm) {
            hints.push(norm);
        }
    }
    hints
}

/// Partitions normalized candidate domain hints for `(bin_identity, dst_ip)` into
/// `(authorizing_hints, cohosted_hints)` so `MAX_DOMAIN_HINTS_PER_FILTER` overflow never evicts
/// hints backed by a domain-specific `NetworkAllow` rule (`AUD-P3-02`).
pub(super) fn partition_permit_hints<S: AsRef<str>>(
    bin_identity: &BinaryIdentity,
    dst_ip: IpAddr,
    candidates: &[S],
    rules: &[AllowlistRuleRecord],
) -> (Vec<String>, Vec<String>) {
    let mut authorizing_hints: Vec<String> = Vec::new();
    let mut cohosted_hints: Vec<String> = Vec::new();
    for raw in candidates {
        let norm = raw
            .as_ref()
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if norm.is_empty()
            || authorizing_hints.iter().any(|h| h == &norm)
            || cohosted_hints.iter().any(|h| h == &norm)
        {
            continue;
        }
        let is_domain_authorizing = matches!(
            evaluate_outbound_policy(bin_identity, dst_ip, Some(norm.as_str()), rules),
            OutboundDecision::AllowedByRule { .. }
        ) && rules.iter().any(|r| {
            r.scope == RuleScope::NetworkAllow
                && matches_network_allow_rule(r, bin_identity, dst_ip, Some(norm.as_str()))
                && !matches_network_allow_rule(r, bin_identity, dst_ip, None)
        });
        if is_domain_authorizing {
            authorizing_hints.push(norm);
        } else {
            cohosted_hints.push(norm);
        }
    }
    (authorizing_hints, cohosted_hints)
}

/// Prepends any already-stored domain-authorizing hints from an existing `DomainPolicy` IP Permit
/// for `(exe_path, dst_ip)` into `authorizing_hints` (preserving chronological oldest-first order
/// without duplicates) so subsequent merges after DNS-history eviction or under a co-existing
/// CIDR/second allow rule never FIFO-evict an existing authorizing hint (`AUD-P3-02`).
pub(super) fn extend_authorizing_hints_from_existing_permit(
    fw: &WfpRuleManager,
    exe_path: &str,
    dst_ip: IpAddr,
    bin_identity: &BinaryIdentity,
    rules: &[AllowlistRuleRecord],
    authorizing_hints: &mut Vec<String>,
) {
    let Some(existing_hints) = fw.domain_policy_permit_hints(exe_path, dst_ip) else {
        return;
    };
    let (existing_auth, _) =
        partition_permit_hints(bin_identity, dst_ip, &existing_hints, rules);
    if existing_auth.is_empty() {
        return;
    }
    let mut merged = existing_auth;
    for hint in authorizing_hints.drain(..) {
        if !merged.iter().any(|h| h == &hint) {
            merged.push(hint);
        }
    }
    *authorizing_hints = merged;
}

pub(super) fn network_allow_rule_identity_matches(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkAllow {
        return false;
    }
    if rule
        .allowed_target
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
    {
        return matches_app_wide_network_allow(rule, identity);
    }
    let mut probe = rule.clone();
    probe.allowed_target = None;
    matches_app_wide_network_allow(&probe, identity)
}
