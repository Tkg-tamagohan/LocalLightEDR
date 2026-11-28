//! Layer 2 early pruning, Sigma subset rule engine, Authenticode verification,
//! and newly-registered domain (NRD) / homograph detection crate.

pub mod allowlist;
pub mod domain;
pub mod nrd;
pub mod outbound;
pub mod pruner;
pub mod scoped;
pub mod sigma;

use std::fs;
use std::path::Path;

use ledr_proto::{AllowlistRuleRecord, RuleScope, SensorEvent};
pub use ledr_proto::{build_windows_apps_version_wildcard_pattern, AllowPermanentPathMode};
use sha2::Digest as _;
use thiserror::Error;

pub use allowlist::{
    compute_file_sha256_hex, compute_file_sha256_hex_cancellable,
    compute_reader_sha256_hex_cancellable, is_allowed_by_rules, matches_path_pattern,
    signer_subject_matches, BinaryIdentity,
};
pub use domain::{assess_domain_risk, assess_domain_risk_with_cache, DomainRiskAssessment};
pub use nrd::{
    fetch_nrd_feed_url, fetch_nrd_feed_url_cancellable, normalize_nrd_domain, parse_file_url,
    parse_http_url, parse_nrd_feed_bytes, parse_nrd_line, refresh_nrd_cache,
    refresh_nrd_cache_cancellable, NrdCache, NrdCancelToken, NrdRefreshStats, ParsedHttpUrl,
    DEFAULT_NRD_FEED_URLS, NRD_MAX_ENTRIES, NRD_MAX_RESPONSE_BYTES, NRD_REFRESH_INTERVAL_MS,
};
pub use outbound::{
    canonical_ip, classify_outbound_risk, discover_default_prerestricted_interpreters,
    evaluate_outbound_policy, is_external_ip, is_high_risk_executable_path, is_script_interpreter,
    matches_app_wide_network_allow, matches_app_wide_network_block, matches_network_allow_rule,
    matches_network_block_rule, matches_network_target, parse_cidr_target, validate_policy_rule,
    OutboundDecision, OutboundRiskClass,
};
pub use pruner::{AllowlistConfig, EarlyPruner, EarlyPrunerConfig};
pub use scoped::{
    evaluate_outbound_policy_with_scoped, is_allowed_by_scoped_rules, is_valid_app_container_sid,
    matches_command_line_pattern, matches_package_wide_network_allow,
    matches_package_wide_network_block, matches_scoped_network_allow_rule,
    matches_scoped_network_block_rule, validate_command_line_pattern, validate_scoped_policy_rule,
    ProcessScopeContext, MAX_COMMAND_LINE_PATTERN_CHARS,
};
pub use sigma::{
    EventContext, FieldCondition, MatchModifier, SigmaEngine, SigmaField, SigmaMatch, SigmaRule,
};

/// Errors produced when loading, parsing, or compiling rule sets and allowlists.
#[derive(Debug, Error)]
pub enum RulesError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid regex in rule {rule_id}: {source}")]
    InvalidRegex {
        rule_id: String,
        #[source]
        source: regex::Error,
    },
    #[error("Aho-Corasick build error: {0}")]
    AhoCorasick(#[from] aho_corasick::BuildError),
    #[error("invalid rule definition {rule_id}: {reason}")]
    InvalidRule { rule_id: String, reason: String },
}

/// Structured output of [`load_rules_dir`], distinguishing shipped default allowlist rules
/// from operator-managed policy rules.
#[derive(Debug, Default)]
pub struct LoadedRulesDir {
    pub sigma: SigmaEngine,
    pub pruner: EarlyPruner,
    /// Shipped default allowlist rules from `default_allowlist.json` (`created_by == "default_allowlist"`,
    /// non-`NetworkBlock`) intended for one-time seeding via `seed_default_rules_once`.
    pub default_allowlists: Vec<AllowlistRuleRecord>,
    /// Operator-managed rules (separate JSON policy files, `NetworkBlock` entries, or rules with
    /// non-default `created_by`) whose file edits must be upserted on startup.
    pub managed_rules: Vec<AllowlistRuleRecord>,
}

fn is_shipped_default_rule(path: &Path, rule: &AllowlistRuleRecord) -> bool {
    let is_default_file = path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("default_allowlist.json"));
    if !is_default_file {
        return false;
    }
    rule.scope != RuleScope::NetworkBlock
        && rule.created_by.trim().eq_ignore_ascii_case("default_allowlist")
}

/// Loads all Sigma rules (`lotl_core.json`, etc.), early pruner configuration, shipped default
/// allowlists (`default_allowlist.json`), and operator-managed rule files from `dir`.
pub fn load_rules_dir(dir: impl AsRef<Path>) -> Result<LoadedRulesDir, RulesError> {
    let mut paths: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();
    paths.sort();

    let mut rules = Vec::new();
    let mut pruner = EarlyPruner::default();
    let mut default_allowlists = Vec::new();
    let mut managed_rules = Vec::new();

    for path in paths {
        let raw_file = fs::read_to_string(&path)?;
        let raw = raw_file.strip_prefix('\u{feff}').unwrap_or(&raw_file);
        let value: serde_json::Value = serde_json::from_str(raw)?;
        if value.is_array() || value.get("rules").is_some() {
            rules.extend(sigma::parse_sigma_rules_json(raw)?);
        } else if value.get("early_pruner").is_some() || value.get("allowlist_rules").is_some() {
            let cfg = AllowlistConfig::from_json_str(raw)?;
            if value.get("early_pruner").is_some() {
                pruner = EarlyPruner::new(cfg.early_pruner);
            }
            for rule in cfg.allowlist_rules {
                if is_shipped_default_rule(&path, &rule) {
                    default_allowlists.push(rule);
                } else {
                    managed_rules.push(rule);
                }
            }
        }
    }

    let sigma = SigmaEngine::from_rules(rules)?;
    Ok(LoadedRulesDir {
        sigma,
        pruner,
        default_allowlists,
        managed_rules,
    })
}

/// Loads all Sigma rules (`lotl_core.json`, etc.) and allowlist / pruner configuration
/// (`default_allowlist.json`) from `dir`, combining shipped default allowlists and
/// operator-managed rules into a single list.
pub fn load_rules_and_pruner_from_dir(
    dir: impl AsRef<Path>,
) -> Result<(SigmaEngine, EarlyPruner, Vec<AllowlistRuleRecord>), RulesError> {
    let loaded = load_rules_dir(dir)?;
    let mut allowlists = loaded.default_allowlists;
    allowlists.extend(loaded.managed_rules);
    Ok((loaded.sigma, loaded.pruner, allowlists))
}

/// Returns the rule engine implementation version string.
pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Placeholder rule match descriptor for Phase 0 scaffolding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatch {
    pub rule_id: String,
    pub title: String,
}

/// Phase 0 stub evaluator that inspects a normalized [`SensorEvent`] and returns `false`.
pub fn evaluate_stub(_event: &SensorEvent) -> bool {
    false
}

/// Computes lowercase hex-encoded SHA-256 of `bytes` for binary allowlist verification.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    hex::encode(digest)
}

/// Computes Levenshtein edit distance between two domain labels for homograph detection.
pub fn label_edit_distance(a: &str, b: &str) -> usize {
    strsim::levenshtein(a, b)
}

/// Compiles a rule regular expression, returning a diagnostic string on invalid syntax.
pub fn compile_rule_regex(pattern: &str) -> Result<regex::Regex, String> {
    regex::Regex::new(pattern).map_err(|err| err.to_string())
}


#[cfg(test)]
mod tests;
