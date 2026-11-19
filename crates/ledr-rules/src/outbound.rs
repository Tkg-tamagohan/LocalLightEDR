//! Outbound firewall risk classification and deny-overrides-allow policy evaluation
//! (`決定記録 L-03`, `決定記録 L-04`, `AUTO-02`).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use ledr_proto::{is_never_suspend_process, AllowlistRuleRecord, RuleScope};

use crate::allowlist::{matches_path_pattern, signer_subject_matches, BinaryIdentity};

/// Risk classification of an executable initiating outbound network traffic (`L-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutboundRiskClass {
    /// Protected Windows OS or LocalEDR binary (`AUTO-02`): never blocked or suspended.
    ProtectedOs,
    /// Executable located under `Downloads`, `Temp`, or `Tmp` directories (`L-03`).
    HighRiskPath,
    /// Script interpreter (`powershell`, `pwsh`, `node`, `python`, `wscript`, etc., `L-03`).
    ScriptInterpreter,
    /// General-path binary requiring first-connect containment unless allowlisted (`L-03`).
    GeneralUnknown,
}

/// Effective outbound policy decision evaluated with deny-overrides-allow precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundDecision {
    ProtectedOs,
    BlockedByRule { rule_id: String },
    AllowedByRule { rule_id: String },
    PreemptiveRestrict(OutboundRiskClass),
    UnknownFirstConnect,
}

const SCRIPT_INTERPRETER_EXES: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "node.exe",
    "deno.exe",
    "bun.exe",
    "python.exe",
    "pythonw.exe",
    "python3.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "ruby.exe",
    "perl.exe",
    "php.exe",
];

/// Canonicalizes an [`IpAddr`] by unwrapping IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`)
/// into their underlying [`IpAddr::V4`].
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Returns `true` when `ip` is a publicly routable / external destination (excluding loopback,
/// RFC1918 private LAN, link-local, multicast, broadcast, unspecified, IPv6 ULA, and IPv4-mapped
/// local IPv6 addresses).
pub fn is_external_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => is_external_ipv4(v4),
        IpAddr::V6(v6) => is_external_ipv6(v6),
    }
}

fn is_external_ipv4(v4: Ipv4Addr) -> bool {
    !v4.is_loopback()
        && !v4.is_private()
        && !v4.is_link_local()
        && !v4.is_broadcast()
        && !v4.is_multicast()
        && !v4.is_unspecified()
}

fn is_external_ipv6(v6: Ipv6Addr) -> bool {
    let seg0 = v6.segments()[0];
    let is_ula = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    let is_unicast_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    !v6.is_loopback()
        && !v6.is_unspecified()
        && !v6.is_multicast()
        && !is_ula
        && !is_unicast_link_local
}

/// Returns `true` when `exe_path` resides beneath a high-risk user-writable directory segment
/// (`Downloads`, `Temp`, or `Tmp`, `L-03`).
pub fn is_high_risk_executable_path(exe_path: &str) -> bool {
    let trimmed = exe_path.trim();
    if trimmed.is_empty() {
        return false;
    }
    let normalized = strip_extended_prefix(trimmed);
    let mut parts: Vec<&str> = normalized
        .split(['\\', '/'])
        .filter(|seg| !seg.is_empty())
        .collect();
    // Ignore the final filename segment so `C:\Tools\downloader.exe` or `C:\Tools\template.exe`
    // is never misclassified as residing inside `Downloads` or `Temp`.
    if parts.len() <= 1 {
        return false;
    }
    parts.pop();
    parts.into_iter().any(|dir| {
        dir.eq_ignore_ascii_case("downloads")
            || dir.eq_ignore_ascii_case("temp")
            || dir.eq_ignore_ascii_case("tmp")
    })
}

/// Returns `true` when the filename component of `exe_path` is a known script interpreter
/// (`powershell`, `pwsh`, `node`, `python` including versioned names, `wscript`, `cscript`,
/// `mshta`, `ruby`, `perl`, `php`, `deno`, `bun`) (`L-03`).
pub fn is_script_interpreter(exe_path: &str) -> bool {
    let file_name = exe_path
        .trim()
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim();
    if file_name.is_empty() {
        return false;
    }
    if SCRIPT_INTERPRETER_EXES
        .iter()
        .any(|name| file_name.eq_ignore_ascii_case(name))
    {
        return true;
    }
    is_versioned_python_exe(file_name)
}

fn is_versioned_python_exe(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    let Some(stem) = lower.strip_suffix(".exe") else {
        return false;
    };
    let rest = if let Some(r) = stem.strip_prefix("pythonw") {
        r
    } else if let Some(r) = stem.strip_prefix("python") {
        r
    } else {
        return false;
    };
    !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && rest.bytes().any(|b| b.is_ascii_digit())
}

const SYSTEM_ROOT_PRERESTRICTED_INTERPRETERS: &[&str] = &[
    r"System32\WindowsPowerShell\v1.0\powershell.exe",
    r"SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
    r"System32\wscript.exe",
    r"System32\cscript.exe",
    r"System32\mshta.exe",
];

const PATH_PRERESTRICTED_INTERPRETERS: &[&str] = &[
    "pwsh.exe",
    "node.exe",
    "python.exe",
    "python3.exe",
];

/// Discovers existing concrete Windows script interpreter executables to pre-restrict at daemon
/// startup (`L-03`, `AUTO-02`).
///
/// Checks standard Windows built-in interpreters under `%SystemRoot%` (`powershell.exe` 64-bit
/// and 32-bit, `wscript.exe`, `cscript.exe`, `mshta.exe`) plus existing `pwsh.exe`, `node.exe`,
/// `python.exe`, and `python3.exe` discovered via `PATH`. Results are deduplicated
/// case-insensitively and exclude any `AUTO-02` protected process.
pub fn discover_default_prerestricted_interpreters() -> Vec<String> {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let path_env = std::env::var_os("PATH");
    discover_prerestricted_interpreters_from(Some(system_root.as_path()), path_env.as_deref())
}

pub(crate) fn discover_prerestricted_interpreters_from(
    system_root: Option<&Path>,
    path_env: Option<&OsStr>,
) -> Vec<String> {
    let mut results = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut push_if_eligible = |candidate: PathBuf| {
        if !candidate.is_file() {
            return;
        }
        let raw = candidate.to_string_lossy();
        let trimmed = raw.trim().replace('/', "\\");
        let normalized = if trimmed
            .get(..8)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
        {
            format!(r"\\{}", &trimmed[8..])
        } else if trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
        {
            trimmed[4..].to_string()
        } else {
            trimmed
        };
        if normalized.is_empty() || normalized.contains('*') || normalized.contains('?') {
            return;
        }
        let clean = normalized.trim_end_matches(['.', ' ']);
        if is_never_suspend_process(&normalized) || is_never_suspend_process(clean) {
            return;
        }
        let key = normalized.to_ascii_lowercase();
        if seen.insert(key) {
            results.push(normalized);
        }
    };

    if let Some(root) = system_root {
        if !root.as_os_str().is_empty() {
            for rel in SYSTEM_ROOT_PRERESTRICTED_INTERPRETERS {
                push_if_eligible(root.join(rel));
            }
        }
    }

    if let Some(raw_path) = path_env {
        for dir in std::env::split_paths(raw_path) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            for exe_name in PATH_PRERESTRICTED_INTERPRETERS {
                push_if_eligible(dir.join(exe_name));
            }
        }
    }

    results
}

/// Classifies `exe_path` into its outbound firewall risk tier (`L-03`, `AUTO-02`).
pub fn classify_outbound_risk(exe_path: &str) -> OutboundRiskClass {
    if is_never_suspend_process(exe_path) {
        return OutboundRiskClass::ProtectedOs;
    }
    if is_high_risk_executable_path(exe_path) {
        return OutboundRiskClass::HighRiskPath;
    }
    if is_script_interpreter(exe_path) {
        return OutboundRiskClass::ScriptInterpreter;
    }
    OutboundRiskClass::GeneralUnknown
}

/// Matches a network rule target pattern (`allowed_target`) against `dst_ip` and optional
/// `domain_hint` (canonical IP comparison supporting IPv4-mapped IPv6 and uncompressed IPv6,
/// plus ASCII case-insensitive wildcard `*` matching normalizing trailing DNS dots).
pub fn matches_network_target(
    pattern: &str,
    dst_ip: IpAddr,
    domain_hint: Option<&str>,
) -> bool {
    let pat = pattern.trim().trim_end_matches('.');
    if pat.is_empty() {
        return true;
    }
    let canon_dst = canonical_ip(dst_ip);
    if !pat.contains('*') {
        if let Ok(pat_ip) = pat.parse::<IpAddr>() {
            if canonical_ip(pat_ip) == canon_dst {
                return true;
            }
        }
    }
    let ip_str = canon_dst.to_string();
    if matches_wildcard_ascii_ci(&ip_str, pat) {
        return true;
    }
    if let Some(domain) = domain_hint {
        let norm_domain = domain.trim().trim_end_matches('.');
        if !norm_domain.is_empty() && matches_wildcard_ascii_ci(norm_domain, pat) {
            return true;
        }
    }
    false
}

/// Validates a policy rule (`L-04`, `AUTO-02`) before persistence via IPC or management APIs.
///
/// Enforces:
/// - non-empty `rule_id` and `exe_path_pattern`,
/// - valid 64-char hex `sha256` whenever specified,
/// - consistent `(signer_subject, non-zero root_thumbprint)` pairing whenever either is specified,
/// - `L-04` identity requirement on all `*Allow` scopes (`sha256` or `signer_subject` + non-zero `root_thumbprint`),
/// - `AUTO-02` Never-Block protection rejecting concrete `NetworkBlock` rules for protected OS / LocalEDR binaries.
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

fn strip_extended_prefix(path: &str) -> &str {
    if path
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        &path[8..]
    } else if path.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\")) {
        &path[4..]
    } else {
        path
    }
}

fn matches_wildcard_ascii_ci(haystack: &str, pattern: &str) -> bool {
    let s: Vec<u8> = haystack
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .collect();
    let p: Vec<u8> = pattern
        .bytes()
        .map(|b| b.to_ascii_lowercase())
        .collect();

    let (mut si, mut pi) = (0usize, 0usize);
    let (mut star_pi, mut match_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && p[pi] == s[si] {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
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

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}
