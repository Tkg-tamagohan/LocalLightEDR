//! Layer 2 early pruning, Sigma subset rule engine, Authenticode verification,
//! and newly-registered domain (NRD) / homograph detection crate.

use ledr_proto::SensorEvent;
use sha2::Digest as _;

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
