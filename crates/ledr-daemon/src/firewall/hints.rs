//! Stateless domain hint normalization, prioritized merging, and migration pruning.

use std::collections::HashSet;
use std::net::IpAddr;

use ledr_proto::{AllowlistRuleRecord, RuleScope};
use ledr_rules::{
    evaluate_outbound_policy, matches_network_allow_rule, BinaryIdentity, OutboundDecision,
};

#[cfg(doc)]
use super::manager::WfpRuleManager;
#[cfg(doc)]
use super::types::WfpFilterOrigin;
use super::types::MAX_DOMAIN_HINTS_PER_FILTER;

/// Normalizes a domain hint (trim whitespace, strip trailing DNS dots, ASCII lowercase).
pub(super) fn normalize_domain_hint(raw: &str) -> Option<String> {
    let norm = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    (!norm.is_empty()).then_some(norm)
}

/// Inserts a normalized domain hint into `hints` without duplicates while keeping the set bounded
/// by [`MAX_DOMAIN_HINTS_PER_FILTER`] (evicting the oldest hint FIFO on overflow).
pub(super) fn merge_domain_hint(hints: &mut Vec<String>, raw: &str) {
    let Some(norm) = normalize_domain_hint(raw) else {
        return;
    };
    if hints.iter().any(|h| h == &norm) {
        return;
    }
    while hints.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
        hints.remove(0);
    }
    hints.push(norm);
}

/// Merges `authorizing_hints` (protected from eviction by co-hosted hints) and `cohosted_hints`
/// into `target` while keeping `target.len() <= MAX_DOMAIN_HINTS_PER_FILTER`.
///
/// Within the 32-hint cap, preserves insertion order (`authorizing_hints` followed by
/// `cohosted_hints` appended to existing hints without duplicates). On overflow, evicts the
/// oldest unprotected slot first so `authorizing_hints` are never pushed out by co-hosted hints
/// (`AUD-P3-02`).
pub(super) fn merge_domain_hints_prioritized(
    target: &mut Vec<String>,
    authorizing_hints: &[String],
    cohosted_hints: &[String],
) {
    let protected: HashSet<&str> = authorizing_hints.iter().map(String::as_str).collect();

    for hint in authorizing_hints {
        if target.iter().any(|h| h == hint) {
            continue;
        }
        while target.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
            if let Some(evict_idx) = target
                .iter()
                .position(|existing| !protected.contains(existing.as_str()))
            {
                target.remove(evict_idx);
            } else {
                target.remove(0);
            }
        }
        target.push(hint.clone());
    }

    for hint in cohosted_hints {
        if target.iter().any(|h| h == hint) {
            continue;
        }
        if target.len() >= MAX_DOMAIN_HINTS_PER_FILTER {
            let Some(evict_idx) = target
                .iter()
                .position(|existing| !protected.contains(existing.as_str()))
            else {
                // All slots are occupied by protected authorizing hints; do not evict them.
                continue;
            };
            target.remove(evict_idx);
        }
        target.push(hint.clone());
    }
}

/// Computes the pruned `domain_hints` for a [`WfpFilterOrigin::DomainPolicy`] IP Permit filter
/// given a retirement predicate `is_retired` (DNS migration or `superseded_permit_hints`).
///
/// Shared between [`WfpRuleManager::prune_migrated_domain_permit_hints_for_query`] and
/// [`WfpRuleManager::reconcile_persisted_rules_with_dns_context`] so both paths enforce identical
/// semantics:
/// - When surviving (non-retired) hints or `static_allowed` preserve `AllowedByRule`, prune all
///   retired hints.
/// - Otherwise prune retired unallowed co-hosted hints while retaining retired hints that still
///   match a persisted `NetworkAllow` rule (preserving round-robin/cached-IP permits and rule
///   attribution on subsequent block/delete).
/// - Never corrupt a non-static Permit into untagged `domain_hints: []`.
pub(super) fn compute_pruned_permit_hints(
    domain_hints: &[String],
    identity: &BinaryIdentity,
    ip: IpAddr,
    rules: &[AllowlistRuleRecord],
    static_allowed: bool,
    mut is_retired: impl FnMut(&str) -> bool,
) -> Vec<String> {
    let mut normalized_all: Vec<String> = Vec::with_capacity(domain_hints.len());
    let mut surviving_hints: Vec<String> = Vec::with_capacity(domain_hints.len());
    let mut retired_flags: Vec<bool> = Vec::with_capacity(domain_hints.len());

    for raw in domain_hints {
        let Some(norm) = normalize_domain_hint(raw) else {
            continue;
        };
        if normalized_all.iter().any(|h| h == &norm) {
            continue;
        }
        let retired = is_retired(&norm);
        if !retired {
            surviving_hints.push(norm.clone());
        }
        normalized_all.push(norm);
        retired_flags.push(retired);
    }

    if !retired_flags.iter().any(|&r| r) {
        return normalized_all;
    }

    let surviving_preserves_allow = static_allowed
        || surviving_hints.iter().any(|hint| {
            matches!(
                evaluate_outbound_policy(identity, ip, Some(hint.as_str()), rules),
                OutboundDecision::AllowedByRule { .. }
            )
        });
    if surviving_preserves_allow {
        return surviving_hints;
    }

    let mut retained: Vec<String> = Vec::with_capacity(normalized_all.len());
    for (norm, retired) in normalized_all.iter().zip(retired_flags.iter()) {
        if !*retired
            || rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    && matches_network_allow_rule(r, identity, ip, Some(norm.as_str()))
                    && !matches_network_allow_rule(r, identity, ip, None)
            })
        {
            retained.push(norm.clone());
        }
    }

    if retained.is_empty() && !static_allowed {
        return normalized_all;
    }
    retained
}
