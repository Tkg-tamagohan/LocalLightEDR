//! Outbound firewall rule validation and deny-overrides-allow policy evaluation.

use std::net::IpAddr;

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope};

use crate::allowlist::{matches_path_pattern, signer_subject_matches, BinaryIdentity};

use super::classifier::classify_outbound_risk;
use super::ip_target::{matches_network_target, parse_cidr_target};
use super::{OutboundDecision, OutboundRiskClass};

/// Validates a policy rule (`L-04`, `AUTO-02`) before persistence via IPC or management APIs.
///
/// Enforces:
/// - non-empty `rule_id` and `exe_path_pattern`,
/// - valid 64-char hex `sha256` whenever specified,
/// - consistent `(signer_subject, non-zero root_thumbprint)` pairing whenever either is specified,
/// - `L-04` identity requirement on all `*Allow` scopes (`sha256` or `signer_subject` + non-zero `root_thumbprint`),
/// - `AUTO-02` Never-Block protection rejecting concrete `NetworkBlock` rules for protected OS / LocalEDR binaries,
/// - valid IPv4/IPv6 CIDR syntax when `NetworkAllow` / `NetworkBlock` specifies a `/prefix` target.
pub fn validate_policy_rule(rule: &AllowlistRuleRecord) -> Result<(), String> {
    if rule.rule_id.trim().is_empty() {
        return Err("rule_id cannot be empty".to_string());
    }
    let exe_pat = rule.exe_path_pattern.trim();
    if exe_pat.is_empty() {
        return Err("exe_path_pattern cannot be empty".to_string());
    }

    let sha = rule
        .sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(hex_str) = sha {
        if hex_str.len() != 64 || !hex_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("sha256 must be a 64-character hexadecimal digest".to_string());
        }
    }

    let signer = rule
        .signer_subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let thumbprint = rule
        .root_thumbprint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(tp) = thumbprint {
        if tp.chars().all(|c| c == '0') {
            return Err("root_thumbprint cannot be all zeros (L-04)".to_string());
        }
    }
    if signer.is_some() && thumbprint.is_none() {
        return Err("signer_subject requires a non-zero root_thumbprint (L-04)".to_string());
    }
    if thumbprint.is_some() && signer.is_none() {
        return Err("root_thumbprint requires signer_subject (L-04)".to_string());
    }

    if matches!(rule.scope, RuleScope::NetworkAllow | RuleScope::NetworkBlock) {
        if let Some(target) = rule
            .allowed_target
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if target.contains('/') {
                parse_cidr_target(target)?;
            }
        }
    }

    match rule.scope {
        RuleScope::NetworkAllow | RuleScope::FileCanaryAllow | RuleScope::ProcessAllow => {
            if sha.is_none() && (signer.is_none() || thumbprint.is_none()) {
                return Err(format!(
                    "{:?} rule requires sha256 or signer_subject + root_thumbprint (L-04)",
                    rule.scope
                ));
            }
        }
        RuleScope::NetworkBlock => {
            let clean = exe_pat.trim_end_matches(['.', ' ']);
            if !exe_pat.contains('*')
                && !exe_pat.contains('?')
                && (is_never_suspend_process(exe_pat) || is_never_suspend_process(clean))
            {
                return Err(format!(
                    "refusing NetworkBlock rule for protected process `{exe_pat}` (AUTO-02)"
                ));
            }
        }
    }

    Ok(())
}

/// Checks whether a single [`RuleScope::NetworkAllow`] rule authorizes `(identity, dst_ip, domain_hint)`
/// under strict `L-04` two-tier verification (signed tier requires non-zero `root_thumbprint`;
/// unsigned tier requires non-empty matching `sha256`).
pub fn matches_network_allow_rule(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    if rule.scope != RuleScope::NetworkAllow {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    if let Some(target_pat) = rule
        .allowed_target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !matches_network_target(target_pat, dst_ip, domain_hint) {
            return false;
        }
    }
    matches_strict_l04_identity(rule, identity)
}

/// Checks whether a single [`RuleScope::NetworkBlock`] rule blocks `(identity, dst_ip, domain_hint)`.
///
/// Unlike allow rules, a block rule with neither `signer_subject` nor `sha256` matches by
/// `exe_path_pattern` (plus optional `allowed_target`) so user path blocks and quarantine rules
/// saved after a binary is deleted remain effective.
pub fn matches_network_block_rule(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    if rule.scope != RuleScope::NetworkBlock {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    if let Some(target_pat) = rule
        .allowed_target
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !matches_network_target(target_pat, dst_ip, domain_hint) {
            return false;
        }
    }
    matches_block_rule_identity(rule, identity)
}

/// Checks whether a [`RuleScope::NetworkAllow`] rule matches `identity` for app-wide (unscoped)
/// outbound access — used to avoid placing a pre-emptive WFP block on already-permitted apps.
pub fn matches_app_wide_network_allow(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkAllow {
        return false;
    }
    if rule
        .allowed_target
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    matches_strict_l04_identity(rule, identity)
}

/// Checks whether a [`RuleScope::NetworkBlock`] rule applies app-wide to `identity`.
pub fn matches_app_wide_network_block(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkBlock {
        return false;
    }
    if rule
        .allowed_target
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    matches_block_rule_identity(rule, identity)
}

/// Evaluates effective outbound firewall policy for `(identity, dst_ip, domain_hint)` against
/// persisted `rules`, enforcing **deny-overrides-allow** precedence and `AUTO-02` Never-Block.
pub fn evaluate_outbound_policy(
    identity: &BinaryIdentity,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
    rules: &[AllowlistRuleRecord],
) -> OutboundDecision {
    let risk = classify_outbound_risk(&identity.exe_path);
    if risk == OutboundRiskClass::ProtectedOs {
        return OutboundDecision::ProtectedOs;
    }

    // Deny-overrides-allow: any matching NetworkBlock beats every NetworkAllow.
    if let Some(block_rule) = rules
        .iter()
        .find(|rule| matches_network_block_rule(rule, identity, dst_ip, domain_hint))
    {
        return OutboundDecision::BlockedByRule {
            rule_id: block_rule.rule_id.clone(),
        };
    }

    if let Some(allow_rule) = rules
        .iter()
        .find(|rule| matches_network_allow_rule(rule, identity, dst_ip, domain_hint))
    {
        return OutboundDecision::AllowedByRule {
            rule_id: allow_rule.rule_id.clone(),
        };
    }

    match risk {
        OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter => {
            OutboundDecision::PreemptiveRestrict(risk)
        }
        OutboundRiskClass::GeneralUnknown => OutboundDecision::UnknownFirstConnect,
        OutboundRiskClass::ProtectedOs => OutboundDecision::ProtectedOs,
    }
}

fn matches_strict_l04_identity(rule: &AllowlistRuleRecord, identity: &BinaryIdentity) -> bool {
    let expected_signer = rule
        .signer_subject
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    match expected_signer {
        Some(rule_signer) => {
            let Some(auth) = identity.authenticode.as_ref() else {
                return false;
            };
            if !signer_subject_matches(&auth.signer_subject, rule_signer) {
                return false;
            }
            let Some(rule_tp) = rule
                .root_thumbprint
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.chars().all(|c| c == '0'))
            else {
                return false;
            };
            let actual_tp = auth.root_thumbprint.trim();
            if actual_tp.is_empty()
                || actual_tp.chars().all(|c| c == '0')
                || !actual_tp.eq_ignore_ascii_case(rule_tp)
            {
                return false;
            }
            if let Some(rule_sha) = rule
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let matches_sha = identity
                    .sha256
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| s.eq_ignore_ascii_case(rule_sha));
                if !matches_sha {
                    return false;
                }
            }
            true
        }
        None => {
            let Some(rule_sha) = rule
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            else {
                return false;
            };
            identity
                .sha256
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty() && s.eq_ignore_ascii_case(rule_sha))
        }
    }
}

fn matches_block_rule_identity(rule: &AllowlistRuleRecord, identity: &BinaryIdentity) -> bool {
    let has_signer = rule
        .signer_subject
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_sha = rule.sha256.as_deref().is_some_and(|s| !s.trim().is_empty());

    if has_signer {
        return matches_strict_l04_identity(rule, identity);
    }
    if has_sha {
        let expected_sha = rule.sha256.as_deref().unwrap_or("").trim();
        return identity
            .sha256
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty() && s.eq_ignore_ascii_case(expected_sha));
    }
    // Path-only NetworkBlock rule (e.g. user path block or quarantine after binary deletion).
    true
}
