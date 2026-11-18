//! Layer 2 early pruning, Sigma subset rule engine, Authenticode verification,
//! and newly-registered domain (NRD) / homograph detection crate.

pub mod domain;
pub mod pruner;
pub mod sigma;

use std::fs;
use std::path::Path;

use ledr_proto::{AllowlistRuleRecord, SensorEvent};
use sha2::Digest as _;
use thiserror::Error;

pub use domain::{assess_domain_risk, DomainRiskAssessment};
pub use pruner::{AllowlistConfig, EarlyPruner, EarlyPrunerConfig};
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

/// Loads all Sigma rules (`lotl_core.json`, etc.) and allowlist / pruner configuration
/// (`default_allowlist.json`) from `dir`.
pub fn load_rules_and_pruner_from_dir(
    dir: impl AsRef<Path>,
) -> Result<(SigmaEngine, EarlyPruner, Vec<AllowlistRuleRecord>), RulesError> {
    let mut paths: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();

    let mut rules = Vec::new();
    let mut pruner = EarlyPruner::default();
    let mut allowlists = Vec::new();

    for path in paths {
        let raw = fs::read_to_string(&path)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        if value.is_array() || value.get("rules").is_some() {
            rules.extend(sigma::parse_sigma_rules_json(&raw)?);
        } else if value.get("early_pruner").is_some() || value.get("allowlist_rules").is_some() {
            let cfg = AllowlistConfig::from_json_str(&raw)?;
            pruner = EarlyPruner::new(cfg.early_pruner);
            allowlists.extend(cfg.allowlist_rules);
        }
    }

    let engine = SigmaEngine::from_rules(rules)?;
    Ok((engine, pruner, allowlists))
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
mod tests {
    use super::*;
    use ledr_proto::{AlertSeverity, CanaryCategory, ProcessIdentity, ScriptSource};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn rules_01_aho_corasick_prefilter_and_lotl_conjunction() {
        let lotl_json = include_str!("../../../rules/lotl_core.json");
        let engine = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");
        assert!(engine.rule_count() >= 4);
        assert!(engine.aho_corasick_pattern_count() > 0);

        let ps_start = SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4000, 1000),
            parent_pid: 3000,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAA=="
                .to_string(),
            user_sid: None,
        };
        let cmd_parent_ctx = EventContext::with_parent(
            &ps_start,
            Some(r"C:\Windows\System32\cmd.exe"),
            Some("cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand ..."),
        );
        let matches = engine.evaluate(&cmd_parent_ctx);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "LEDR-LOTL-001");
        assert_eq!(matches[0].severity, AlertSeverity::High);

        // Explorer launching encoded PowerShell should NOT trigger the cmd->powershell rule.
        let explorer_parent_ctx = EventContext::with_parent(
            &ps_start,
            Some(r"C:\Windows\explorer.exe"),
            Some("explorer.exe"),
        );
        assert!(engine.evaluate(&explorer_parent_ctx).is_empty());

        // Also explicitly verify ContainsAll multi-term conjunction with EndsWith literals.
        let custom_rule = SigmaRule {
            id: "CUSTOM-CONJ-001".to_string(),
            title: "Custom Multi-Token All Conjunction".to_string(),
            severity: AlertSeverity::High,
            description: None,
            conditions: vec![
                FieldCondition {
                    field: SigmaField::ParentImage,
                    modifier: MatchModifier::EndsWith,
                    values: vec![r"\cmd.exe".to_string()],
                },
                FieldCondition {
                    field: SigmaField::Image,
                    modifier: MatchModifier::EndsWith,
                    values: vec![r"\powershell.exe".to_string(), r"\pwsh.exe".to_string()],
                },
                FieldCondition {
                    field: SigmaField::CommandLine,
                    modifier: MatchModifier::ContainsAll,
                    values: vec!["-noprofile".to_string(), "-encodedcommand".to_string()],
                },
            ],
        };
        let custom_engine = SigmaEngine::from_rules(vec![custom_rule]).expect("compile custom");
        assert_eq!(custom_engine.evaluate(&cmd_parent_ctx).len(), 1);

        let missing_second_token = SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4001, 1001),
            parent_pid: 3000,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: "powershell.exe -NoProfile -Command Get-Date".to_string(),
            user_sid: None,
        };
        let missing_ctx =
            EventContext::with_parent(&missing_second_token, Some(r"C:\Windows\System32\cmd.exe"), None);
        assert!(custom_engine.evaluate(&missing_ctx).is_empty());

        let benign_event = SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(5000, 2000),
            parent_pid: 100,
            exe_path: r"C:\Windows\System32\notepad.exe".to_string(),
            command_line: "notepad.exe notes.txt".to_string(),
            user_sid: None,
        };
        assert!(engine.evaluate(&EventContext::new(&benign_event)).is_empty());
    }

    #[test]
    fn rules_02_regex_modifiers_and_field_coverage() {
        let lotl_json = include_str!("../../../rules/lotl_core.json");
        let engine = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");

        let script_event = SensorEvent::ScriptEvaluated {
            pid: 777,
            source: ScriptSource::Amsi,
            script_content: "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aGk='))"
                .to_string(),
            timestamp_ms: 1_700_000_000_000,
        };
        let script_matches = engine.evaluate(&EventContext::new(&script_event));
        assert_eq!(script_matches.len(), 1);
        assert_eq!(script_matches[0].rule_id, "LEDR-SCRIPT-001");
        assert_eq!(script_matches[0].severity, AlertSeverity::Critical);

        let custom_rules = vec![
            SigmaRule {
                id: "NET-IP-EXACT".to_string(),
                title: "Exact C2 IP Match".to_string(),
                severity: AlertSeverity::Medium,
                description: None,
                conditions: vec![FieldCondition {
                    field: SigmaField::DestinationIp,
                    modifier: MatchModifier::Exact,
                    values: vec!["203.0.113.50".to_string()],
                }],
            },
            SigmaRule {
                id: "DNS-REGEX".to_string(),
                title: "Suspicious DGA Domain".to_string(),
                severity: AlertSeverity::Medium,
                description: None,
                conditions: vec![FieldCondition {
                    field: SigmaField::QueryName,
                    modifier: MatchModifier::Regex,
                    values: vec![r"(?i)^[a-z0-9]{16,}\.top$".to_string()],
                }],
            },
            SigmaRule {
                id: "CANARY-PREFIX".to_string(),
                title: "Canary Target Prefix".to_string(),
                severity: AlertSeverity::High,
                description: None,
                conditions: vec![FieldCondition {
                    field: SigmaField::TargetFilename,
                    modifier: MatchModifier::StartsWith,
                    values: vec![r"C:\Users\".to_string()],
                }],
            },
        ];
        let custom_engine = SigmaEngine::from_rules(custom_rules).expect("compile custom rules");

        let net_ev = SensorEvent::NetworkConnect {
            pid: 10,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: 10,
        };
        assert_eq!(custom_engine.evaluate(&EventContext::new(&net_ev))[0].rule_id, "NET-IP-EXACT");

        let dns_ev = SensorEvent::DnsQuery {
            pid: 10,
            query_name: "a9b8c7d6e5f4a1b2c3.top".to_string(),
            query_type: 1,
            resolved_ips: vec![],
            timestamp_ms: 11,
        };
        assert_eq!(custom_engine.evaluate(&EventContext::new(&dns_ev))[0].rule_id, "DNS-REGEX");

        let canary_ev = SensorEvent::CanaryFileAccess {
            pid: 10,
            target_path: r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies"
                .to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: 12,
        };
        assert_eq!(
            custom_engine.evaluate(&EventContext::new(&canary_ev))[0].rule_id,
            "CANARY-PREFIX"
        );

        let bad_regex_rule = SigmaRule {
            id: "BAD-RE".to_string(),
            title: "Invalid".to_string(),
            severity: AlertSeverity::Low,
            description: None,
            conditions: vec![FieldCondition {
                field: SigmaField::CommandLine,
                modifier: MatchModifier::Regex,
                values: vec!["[unclosed".to_string()],
            }],
        };
        assert!(matches!(
            SigmaEngine::from_rules(vec![bad_regex_rule]),
            Err(RulesError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn rules_03_early_pruner_behavior() {
        let allowlist_json = include_str!("../../../rules/default_allowlist.json");
        let allowlist_cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse allowlist");
        assert!(!allowlist_cfg.allowlist_rules.is_empty());

        let pruner = EarlyPruner::from_json_str(allowlist_json).expect("build pruner");

        // Loopback network connections are pruned as benign noise.
        let loopback_v4 = SensorEvent::NetworkConnect {
            pid: 123,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: 8080,
            domain_hint: None,
            timestamp_ms: 1,
        };
        assert!(pruner.should_prune(&EventContext::new(&loopback_v4)));

        let loopback_v6 = SensorEvent::NetworkConnect {
            pid: 123,
            protocol: 6,
            dst_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            dst_port: 8080,
            domain_hint: None,
            timestamp_ms: 2,
        };
        assert!(pruner.should_prune(&EventContext::new(&loopback_v6)));

        // External IP from non-allowlisted process is NOT pruned.
        let ext_net = SensorEvent::NetworkConnect {
            pid: 123,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("example.com".to_string()),
            timestamp_ms: 3,
        };
        assert!(!pruner.should_prune_with_image(&EventContext::new(&ext_net), Some(r"C:\Temp\evil.exe")));

        // Configured local DNS noise is pruned; external DNS is not.
        let local_dns = SensorEvent::DnsQuery {
            pid: 123,
            query_name: "mybox.local".to_string(),
            query_type: 1,
            resolved_ips: vec![],
            timestamp_ms: 4,
        };
        assert!(pruner.should_prune(&EventContext::new(&local_dns)));

        let ext_dns = SensorEvent::DnsQuery {
            pid: 123,
            query_name: "api.example.com".to_string(),
            query_type: 1,
            resolved_ips: vec![],
            timestamp_ms: 5,
        };
        assert!(!pruner.should_prune(&EventContext::new(&ext_dns)));

        // CanaryFileAccess and ScriptEvaluated are NEVER pruned, even for trusted OS images.
        let canary = SensorEvent::CanaryFileAccess {
            pid: 999,
            target_path: r"C:\Users\bob\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 2,
            is_write_or_delete: true,
            timestamp_ms: 6,
        };
        assert!(!pruner.should_prune_with_image(
            &EventContext::new(&canary),
            Some(r"C:\Windows\System32\svchost.exe"),
        ));

        let script = SensorEvent::ScriptEvaluated {
            pid: 999,
            source: ScriptSource::PowerShell4104,
            script_content: "Invoke-Expression $payload".to_string(),
            timestamp_ms: 7,
        };
        assert!(!pruner.should_prune_with_image(
            &EventContext::new(&script),
            Some(r"C:\Windows\System32\svchost.exe"),
        ));
    }
}
