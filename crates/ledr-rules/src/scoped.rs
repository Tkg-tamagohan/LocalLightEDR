//! Scoped policy rule validation and Layer 1/2/3 evaluation (`FU-P4-03`).

use std::net::IpAddr;

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope, ScopedPolicyRuleRecord};

use crate::allowlist::{matches_path_pattern, signer_subject_matches, BinaryIdentity};
use crate::outbound::{
    classify_outbound_risk, evaluate_outbound_policy, matches_network_target, parse_cidr_target,
    OutboundDecision, OutboundRiskClass,
};

/// Maximum UTF-8 character length permitted for `command_line_pattern` (`FU-P4-03`).
pub const MAX_COMMAND_LINE_PATTERN_CHARS: usize = 512;

/// Maximum byte length permitted for `package_family_name` and `package_sid`.
const MAX_PACKAGE_ATTR_LEN: usize = 256;

/// Runtime process attributes supplied when evaluating [`ScopedPolicyRuleRecord`] entries.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProcessScopeContext<'a> {
    pub package_family_name: Option<&'a str>,
    pub package_sid: Option<&'a str>,
    pub command_line: Option<&'a str>,
}

/// Returns `true` if `raw` is a well-formed Windows AppContainer SID (`S-1-15-2-<u32>...`).
pub fn is_valid_app_container_sid(raw: &str) -> bool {
    if raw.is_empty() || raw != raw.trim() || raw.len() > MAX_PACKAGE_ATTR_LEN || !raw.is_ascii() {
        return false;
    }
    let Some(rest) = raw
        .get(..9)
        .filter(|prefix| prefix.eq_ignore_ascii_case("S-1-15-2-"))
        .map(|_| &raw[9..])
    else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('-')
        .all(|sub| !sub.is_empty() && sub.bytes().all(|b| b.is_ascii_digit()) && sub.parse::<u32>().is_ok())
}

/// Validates a Layer 1/2 `command_line_pattern` (`1..=512` chars, non-blank, no ASCII control
/// characters; unescaped `*` wildcard, ASCII case-insensitive).
pub fn validate_command_line_pattern(pattern: &str) -> Result<(), String> {
    let char_len = pattern.chars().count();
    if !(1..=MAX_COMMAND_LINE_PATTERN_CHARS).contains(&char_len) {
        return Err(format!(
            "command_line_pattern length must be 1..={MAX_COMMAND_LINE_PATTERN_CHARS} characters"
        ));
    }
    if pattern.trim().is_empty() {
        return Err("command_line_pattern cannot be whitespace-only".to_string());
    }
    if pattern.chars().any(|ch| ch.is_ascii_control()) {
        return Err("command_line_pattern cannot contain ASCII control characters".to_string());
    }
    Ok(())
}

/// Performs unescaped `*` wildcard matching (ASCII case-insensitive) for `command_line` against
/// `pattern` without path normalization or `?` interpretation.
pub fn matches_command_line_pattern(command_line: &str, pattern: &str) -> bool {
    if validate_command_line_pattern(pattern).is_err() {
        return false;
    }
    let s: Vec<char> = command_line.chars().map(|c| c.to_ascii_lowercase()).collect();
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_lowercase()).collect();

    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut match_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            match_si = si;
            pi += 1;
        } else if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            match_si += 1;
            si = match_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Validates a [`ScopedPolicyRuleRecord`] against `FU-P4-03`, `L-04`, and `AUTO-02` invariants
/// before persistence via IPC or management APIs.
pub fn validate_scoped_policy_rule(rule: &ScopedPolicyRuleRecord) -> Result<(), String> {
    if rule.rule_id.trim().is_empty() {
        return Err("rule_id cannot be empty".to_string());
    }
    let exe_pat = rule.exe_path_pattern.trim();
    if exe_pat.is_empty() {
        return Err("exe_path_pattern cannot be empty".to_string());
    }

    if let Some(raw_sha) = rule.sha256.as_deref() {
        if raw_sha.trim().is_empty() {
            return Err("sha256 cannot be empty when specified".to_string());
        }
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

    if let Some(pfn) = rule.package_family_name.as_deref() {
        if pfn.trim().is_empty() {
            return Err("package_family_name cannot be empty when specified".to_string());
        }
        if pfn.len() > MAX_PACKAGE_ATTR_LEN
            || pfn.chars().any(|c| c.is_whitespace() || c.is_ascii_control())
        {
            return Err("package_family_name contains invalid characters or exceeds 256 bytes".to_string());
        }
    }

    if let Some(sid) = rule.package_sid.as_deref() {
        if sid.trim().is_empty() {
            return Err("package_sid cannot be empty when specified".to_string());
        }
        if !is_valid_app_container_sid(sid) {
            return Err(format!(
                "package_sid `{sid}` is not a valid AppContainer SID (S-1-15-2-...)"
            ));
        }
    }

    if let Some(cmd_pat) = rule.command_line_pattern.as_deref() {
        validate_command_line_pattern(cmd_pat)?;
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
        RuleScope::NetworkAllow => {
            if rule.command_line_pattern.is_some() {
                return Err(
                    "command_line_pattern is forbidden for Layer 3 NetworkAllow rules (FU-P4-03)"
                        .to_string(),
                );
            }
            if signer.is_none() || thumbprint.is_none() {
                return Err(
                    "scoped NetworkAllow rule requires L-04 Authenticode signer_subject + non-zero root_thumbprint (FU-P4-03)"
                        .to_string(),
                );
            }
            if rule.package_family_name.is_none() {
                return Err(
                    "scoped NetworkAllow rule requires non-empty package_family_name (FU-P4-03)"
                        .to_string(),
                );
            }
            if rule.package_sid.is_none() {
                return Err(
                    "scoped NetworkAllow rule requires valid AppContainer package_sid (FU-P4-03)"
                        .to_string(),
                );
            }
        }
        RuleScope::NetworkBlock => {
            if rule.command_line_pattern.is_some() {
                return Err(
                    "command_line_pattern is forbidden for Layer 3 NetworkBlock rules (FU-P4-03)"
                        .to_string(),
                );
            }
            if rule.package_sid.is_none() {
                return Err(
                    "scoped NetworkBlock rule requires valid AppContainer package_sid (FU-P4-03)"
                        .to_string(),
                );
            }
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
        RuleScope::ProcessAllow | RuleScope::FileCanaryAllow => {
            if rule.scope == RuleScope::ProcessAllow
                && rule
                    .allowed_target
                    .as_deref()
                    .is_some_and(|t| !t.trim().is_empty())
            {
                return Err(
                    "allowed_target is forbidden for Layer 1 ProcessAllow rules (FU-P4-03)"
                        .to_string(),
                );
            }
            if sha.is_none() && (signer.is_none() || thumbprint.is_none()) {
                return Err(format!(
                    "{:?} scoped rule requires sha256 or signer_subject + root_thumbprint (L-04)",
                    rule.scope
                ));
            }
            if rule.package_family_name.is_none()
                && rule.package_sid.is_none()
                && rule.command_line_pattern.is_none()
            {
                return Err(format!(
                    "{:?} scoped rule requires at least one of package_family_name, package_sid, or command_line_pattern",
                    rule.scope
                ));
            }
        }
    }

    Ok(())
}

/// Evaluates whether `identity` + `scope_ctx` (optionally accessing `target`) is permitted by any
/// Layer 1/2 rule in `rules` under `scope` (`ProcessAllow` or `FileCanaryAllow`).
pub fn is_allowed_by_scoped_rules(
    identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    target: Option<&str>,
    scope: RuleScope,
    rules: &[ScopedPolicyRuleRecord],
) -> bool {
    if !matches!(scope, RuleScope::ProcessAllow | RuleScope::FileCanaryAllow) {
        return false;
    }
    rules
        .iter()
        .any(|rule| rule.scope == scope && scoped_layer12_rule_matches(rule, identity, scope_ctx, target))
}

fn scoped_layer12_rule_matches(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    target: Option<&str>,
) -> bool {
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    if let Some(allowed_target) = rule.allowed_target.as_deref() {
        let Some(actual_target) = target else {
            return false;
        };
        if !matches_path_pattern(actual_target, allowed_target) {
            return false;
        }
    }
    if rule.package_family_name.is_none()
        && rule.package_sid.is_none()
        && rule.command_line_pattern.is_none()
    {
        return false;
    }
    if !matches_required_pfn(rule.package_family_name.as_deref(), scope_ctx.package_family_name) {
        return false;
    }
    if let Some(rule_sid) = rule.package_sid.as_deref() {
        if !matches_required_sid(rule_sid, scope_ctx.package_sid) {
            return false;
        }
    }
    if let Some(cmd_pat) = rule.command_line_pattern.as_deref() {
        let Some(actual_cmd) = scope_ctx.command_line else {
            return false;
        };
        if !matches_command_line_pattern(actual_cmd, cmd_pat) {
            return false;
        }
    }
    matches_strict_l04_scoped_identity(
        rule.sha256.as_deref(),
        rule.signer_subject.as_deref(),
        rule.root_thumbprint.as_deref(),
        identity,
    )
}

/// Checks whether a single scoped [`RuleScope::NetworkAllow`] rule authorizes
/// `(identity, scope_ctx, dst_ip, domain_hint)`.
pub fn matches_scoped_network_allow_rule(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    if !matches_scoped_network_allow_base(rule, identity) {
        return false;
    }
    let Some(rule_pfn) = rule.package_family_name.as_deref() else {
        return false;
    };
    let Some(rule_sid) = rule.package_sid.as_deref() else {
        return false;
    };
    if !matches_required_pfn(Some(rule_pfn), scope_ctx.package_family_name)
        || !matches_required_sid(rule_sid, scope_ctx.package_sid)
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
    true
}

/// Checks whether a single scoped [`RuleScope::NetworkBlock`] rule blocks
/// `(identity, scope_ctx, dst_ip, domain_hint)`.
pub fn matches_scoped_network_block_rule(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    if !matches_scoped_network_block_base(rule, identity) {
        return false;
    }
    let Some(rule_sid) = rule.package_sid.as_deref() else {
        return false;
    };
    if !matches_required_sid(rule_sid, scope_ctx.package_sid) {
        return false;
    }
    // Enforce PFN match when both sides carry a non-empty PFN; if `scope_ctx.package_family_name`
    // is `None` (e.g., kernel WFP drop with SID only), SID match still blocks fail-closed.
    if let (Some(rule_pfn), Some(actual_pfn)) = (
        rule.package_family_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        scope_ctx
            .package_family_name
            .map(str::trim)
            .filter(|s| !s.is_empty()),
    ) {
        if !actual_pfn.eq_ignore_ascii_case(rule_pfn) {
            return false;
        }
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
    true
}

/// Checks whether a scoped [`RuleScope::NetworkAllow`] rule applies package-wide (no
/// `allowed_target`) for the executable `identity` (WFP reconciliation helper).
pub fn matches_package_wide_network_allow(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule
        .allowed_target
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    matches_scoped_network_allow_base(rule, identity)
}

/// Checks whether a scoped [`RuleScope::NetworkBlock`] rule applies package-wide (no
/// `allowed_target`) for the executable `identity` (WFP reconciliation helper).
pub fn matches_package_wide_network_block(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule
        .allowed_target
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    matches_scoped_network_block_base(rule, identity)
}

/// Evaluates effective outbound firewall policy across both legacy `rules` (`allowlist_rules`) and
/// `scoped_rules` (`scoped_policy_rules`), preserving **deny-overrides-allow** and `AUTO-02`.
pub fn evaluate_outbound_policy_with_scoped(
    identity: &BinaryIdentity,
    scope_ctx: &ProcessScopeContext<'_>,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
    rules: &[AllowlistRuleRecord],
    scoped_rules: &[ScopedPolicyRuleRecord],
) -> OutboundDecision {
    let base = evaluate_outbound_policy(identity, dst_ip, domain_hint, rules);
    match base {
        OutboundDecision::ProtectedOs | OutboundDecision::BlockedByRule { .. } => return base,
        _ => {}
    }

    if let Some(block_rule) = scoped_rules
        .iter()
        .find(|r| matches_scoped_network_block_rule(r, identity, scope_ctx, dst_ip, domain_hint))
    {
        return OutboundDecision::BlockedByRule {
            rule_id: block_rule.rule_id.clone(),
        };
    }

    if matches!(base, OutboundDecision::AllowedByRule { .. }) {
        return base;
    }

    if let Some(allow_rule) = scoped_rules
        .iter()
        .find(|r| matches_scoped_network_allow_rule(r, identity, scope_ctx, dst_ip, domain_hint))
    {
        return OutboundDecision::AllowedByRule {
            rule_id: allow_rule.rule_id.clone(),
        };
    }

    let risk = classify_outbound_risk(&identity.exe_path);
    match risk {
        OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter => {
            OutboundDecision::PreemptiveRestrict(risk)
        }
        OutboundRiskClass::GeneralUnknown => OutboundDecision::UnknownFirstConnect,
        OutboundRiskClass::ProtectedOs => OutboundDecision::ProtectedOs,
    }
}

fn matches_scoped_network_allow_base(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkAllow || rule.command_line_pattern.is_some() {
        return false;
    }
    let has_pfn = rule
        .package_family_name
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_valid_sid = rule
        .package_sid
        .as_deref()
        .is_some_and(is_valid_app_container_sid);
    if !has_pfn || !has_valid_sid {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    // Signed tier mandatory for scoped NetworkAllow.
    let has_signer = rule
        .signer_subject
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    if !has_signer {
        return false;
    }
    matches_strict_l04_scoped_identity(
        rule.sha256.as_deref(),
        rule.signer_subject.as_deref(),
        rule.root_thumbprint.as_deref(),
        identity,
    )
}

fn matches_scoped_network_block_base(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkBlock || rule.command_line_pattern.is_some() {
        return false;
    }
    if !rule
        .package_sid
        .as_deref()
        .is_some_and(is_valid_app_container_sid)
    {
        return false;
    }
    if rule.exe_path_pattern.trim().is_empty()
        || !matches_path_pattern(&identity.exe_path, &rule.exe_path_pattern)
    {
        return false;
    }
    let clean = identity.exe_path.trim().trim_end_matches(['.', ' ']);
    if is_never_suspend_process(&identity.exe_path) || is_never_suspend_process(clean) {
        return false;
    }
    matches_scoped_block_identity(rule, identity)
}

fn matches_required_pfn(rule_pfn: Option<&str>, actual_pfn: Option<&str>) -> bool {
    let Some(expected) = rule_pfn.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    actual_pfn
        .map(str::trim)
        .is_some_and(|actual| !actual.is_empty() && actual.eq_ignore_ascii_case(expected))
}

fn matches_required_sid(rule_sid: &str, actual_sid: Option<&str>) -> bool {
    if !is_valid_app_container_sid(rule_sid) {
        return false;
    }
    actual_sid
        .map(str::trim)
        .is_some_and(|actual| is_valid_app_container_sid(actual) && actual.eq_ignore_ascii_case(rule_sid))
}

fn matches_strict_l04_scoped_identity(
    rule_sha: Option<&str>,
    rule_signer: Option<&str>,
    rule_thumbprint: Option<&str>,
    identity: &BinaryIdentity,
) -> bool {
    let expected_signer = rule_signer.map(str::trim).filter(|s| !s.is_empty());

    match expected_signer {
        Some(signer) => {
            let Some(auth) = identity.authenticode.as_ref() else {
                return false;
            };
            if !signer_subject_matches(&auth.signer_subject, signer) {
                return false;
            }
            let Some(rule_tp) = rule_thumbprint
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
            if let Some(sha) = rule_sha.map(str::trim).filter(|s| !s.is_empty()) {
                let matches_sha = identity
                    .sha256
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| s.eq_ignore_ascii_case(sha));
                if !matches_sha {
                    return false;
                }
            }
            true
        }
        None => {
            let Some(sha) = rule_sha.map(str::trim).filter(|s| !s.is_empty()) else {
                return false;
            };
            identity
                .sha256
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty() && s.eq_ignore_ascii_case(sha))
        }
    }
}

fn matches_scoped_block_identity(
    rule: &ScopedPolicyRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    let has_signer = rule
        .signer_subject
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let has_sha = rule.sha256.as_deref().is_some_and(|s| !s.trim().is_empty());

    if has_signer || has_sha {
        matches_strict_l04_scoped_identity(
            rule.sha256.as_deref(),
            rule.signer_subject.as_deref(),
            rule.root_thumbprint.as_deref(),
            identity,
        )
    } else {
        true
    }
}
