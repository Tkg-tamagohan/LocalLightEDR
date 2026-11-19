//! Pure path-pattern and L-04 two-tier allowlist matching logic.

use ledr_proto::{AllowlistRuleRecord, RuleScope};

use super::BinaryIdentity;

/// Performs ASCII case-insensitive wildcard (`*`) matching with `/` and `\` normalization.
pub fn matches_path_pattern(exe_path: &str, pattern: &str) -> bool {
    let s: Vec<char> = exe_path.chars().map(normalize_path_char).collect();
    let p: Vec<char> = pattern.chars().map(normalize_path_char).collect();

    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut match_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            match_si = si;
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

#[inline]
fn normalize_path_char(ch: char) -> char {
    if ch == '/' {
        '\\'
    } else {
        ch.to_ascii_lowercase()
    }
}

/// Evaluates whether `identity` (optionally accessing `target`) is permitted by `rules`
/// under `scope` using the `L-04` two-tier model:
/// - **Signed tier**: when `rule.signer_subject` is present and non-empty, requires
///   `identity.authenticode` present, matching `signer_subject` (case-insensitive exact or CN),
///   a non-empty non-all-zero `rule.root_thumbprint` matching `authenticode.root_thumbprint`
///   case-insensitively, optional `rule.sha256` match if set, `exe_path_pattern` match, and
///   optional `allowed_target` match. Signed rules with missing, empty, or all-zero
///   `root_thumbprint` never match.
/// - **Unsigned tier**: when `rule.signer_subject` is absent/empty, requires `exe_path_pattern`
///   match, non-empty `rule.sha256` matching `identity.sha256`, and optional `allowed_target` match.
///   Never allows an unsigned rule with `sha256: None` or empty.
pub fn is_allowed_by_rules(
    identity: &BinaryIdentity,
    target: Option<&str>,
    scope: RuleScope,
    rules: &[AllowlistRuleRecord],
) -> bool {
    rules
        .iter()
        .any(|rule| rule.scope == scope && rule_matches_identity(rule, identity, target))
}

fn rule_matches_identity(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
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
                // L-04: Unsigned rule MUST specify a non-empty SHA-256 digest.
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

/// Checks case-insensitive exact DN match or CN match between an actual Authenticode
/// `signer_subject` and an expected `signer_subject` pattern.
pub fn signer_subject_matches(actual: &str, expected: &str) -> bool {
    let actual_t = actual.trim();
    let expected_t = expected.trim();
    if actual_t.is_empty() || expected_t.is_empty() {
        return false;
    }
    if actual_t.eq_ignore_ascii_case(expected_t) {
        return true;
    }

    let actual_parts = split_rdns(actual_t);
    let expected_parts = split_rdns(expected_t);

    if actual_parts.len() == expected_parts.len()
        && actual_parts.len() > 1
        && actual_parts
            .iter()
            .zip(expected_parts.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return true;
    }

    // Allow CN match when at least one side specifies only a CN / simple display name.
    if actual_parts.len() <= 1 || expected_parts.len() <= 1 {
        if let (Some(a_cn), Some(e_cn)) = (extract_cn(&actual_parts), extract_cn(&expected_parts)) {
            return a_cn.eq_ignore_ascii_case(e_cn);
        }
    }

    false
}

fn split_rdns(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut escaped = false;

    for ch in dn.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            cur.push(ch);
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            cur.push(ch);
            continue;
        }
        if ch == ',' && !in_quotes {
            let trimmed = cur.trim().to_string();
            if !trimmed.is_empty() {
                parts.push(trimmed);
            }
            cur.clear();
            continue;
        }
        cur.push(ch);
    }

    let trimmed = cur.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }
    parts
}

fn extract_cn(rdns: &[String]) -> Option<&str> {
    for part in rdns {
        if let Some((key, val)) = part.split_once('=') {
            if key.trim().eq_ignore_ascii_case("CN") {
                let unquoted = val.trim().trim_matches('"').trim();
                if !unquoted.is_empty() {
                    return Some(unquoted);
                }
            }
        }
    }
    if rdns.len() == 1 && !rdns[0].contains('=') {
        let s = rdns[0].trim();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}
