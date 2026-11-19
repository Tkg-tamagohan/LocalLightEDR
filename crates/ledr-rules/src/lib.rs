//! Layer 2 early pruning, Sigma subset rule engine, Authenticode verification,
//! and newly-registered domain (NRD) / homograph detection crate.

pub mod allowlist;
pub mod domain;
pub mod nrd;
pub mod outbound;
pub mod pruner;
pub mod sigma;

use std::fs;
use std::path::Path;

use ledr_proto::{AllowlistRuleRecord, SensorEvent};
use sha2::Digest as _;
use thiserror::Error;

pub use allowlist::{
    compute_file_sha256_hex, inspect_authenticode, is_allowed_by_rules, matches_path_pattern,
    signer_subject_matches, BinaryIdentity,
};
pub use domain::{assess_domain_risk, DomainRiskAssessment};
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
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_DIR_SEQ: AtomicU32 = AtomicU32::new(1);

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create test temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

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

    #[test]
    fn rules_p2_01_streaming_sha256_and_path_pattern_normalization() {
        let tmp_dir = TestTempDir::new("ledr-rules-p2-01");
        let file_path = tmp_dir.path().join("payload.bin");
        // > 64 KiB to exercise multi-chunk streaming read.
        let payload = vec![0xA5u8; 200_000];
        std::fs::write(&file_path, &payload).expect("write payload");

        let streamed = compute_file_sha256_hex(&file_path).expect("compute streaming sha256");
        let expected = sha256_hex(&payload);
        assert_eq!(streamed.len(), 64);
        assert!(streamed.chars().all(|c| !c.is_ascii_uppercase()));
        assert_eq!(streamed, expected);

        let missing = tmp_dir.path().join("missing.exe");
        assert!(compute_file_sha256_hex(&missing).is_err());

        // Wildcard `*`, slash normalization (`/` vs `\`), and ASCII case-insensitivity.
        assert!(matches_path_pattern(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe",
            r"c:/programdata/microsoft/windows defender/platform/*/msmpeng.exe"
        ));
        assert!(matches_path_pattern(
            r"C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            r"*\Google\Chrome\User Data\*\Cookies"
        ));
        assert!(!matches_path_pattern(
            r"C:\Tools\evil.exe",
            r"C:\Windows\System32\*.exe"
        ));
        assert!(!matches_path_pattern(r"C:\Tools\evil.exe", ""));
    }

    #[test]
    fn rules_p2_02_authenticode_verification_signed_unsigned_and_missing() {
        let tmp_dir = TestTempDir::new("ledr-rules-p2-02");

        // Missing file returns None without panicking.
        assert_eq!(
            inspect_authenticode(&tmp_dir.path().join("does_not_exist.exe")),
            None
        );

        // Unsigned file returns None without panicking.
        let unsigned_path = tmp_dir.path().join("unsigned.exe");
        std::fs::write(&unsigned_path, b"MZ-not-signed-pe-content").expect("write unsigned");
        assert_eq!(inspect_authenticode(&unsigned_path), None);

        // Real Windows OS binary (`SearchIndexer.exe` or `svchost.exe` or `explorer.exe`).
        let search_indexer = Path::new(r"C:\Windows\System32\SearchIndexer.exe");
        if search_indexer.is_file() {
            let auth = inspect_authenticode(search_indexer)
                .expect("SearchIndexer.exe should verify via Authenticode/catalog");
            assert!(
                signer_subject_matches(&auth.signer_subject, "CN=Microsoft Windows"),
                "unexpected signer_subject: {}",
                auth.signer_subject
            );
            assert_eq!(auth.root_thumbprint.len(), 40);
            assert!(auth
                .root_thumbprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));

            // Also confirm it matches `ALLOW-OS-SEARCH-INDEXER` from `default_allowlist.json`.
            let allowlist_json = include_str!("../../../rules/default_allowlist.json");
            let cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse default allowlist");
            let identity = BinaryIdentity::from_path(search_indexer);
            assert!(is_allowed_by_rules(
                &identity,
                Some(r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
                ledr_proto::RuleScope::FileCanaryAllow,
                &cfg.allowlist_rules
            ));
        }

        // Also test an embedded-signed Windows binary if present (`git.exe`).
        let git_exe = Path::new(r"C:\Program Files\Git\cmd\git.exe");
        if git_exe.is_file() {
            let auth = inspect_authenticode(git_exe)
                .expect("git.exe should verify via embedded Authenticode");
            assert!(!auth.signer_subject.is_empty());
            assert_eq!(auth.root_thumbprint.len(), 40);
        }

        // Also test a catalog-signed Windows binary (`explorer.exe`).
        let explorer = Path::new(r"C:\Windows\explorer.exe");
        if explorer.is_file() {
            let auth = inspect_authenticode(explorer)
                .expect("explorer.exe should verify via Authenticode");
            assert!(!auth.signer_subject.is_empty());
            assert_eq!(auth.root_thumbprint.len(), 40);
        }
    }

    #[test]
    fn rules_p2_03_signed_tier_allowlist_rules_and_target_constraints() {
        use ledr_proto::{AuthenticodeInfo, RuleScope};

        let signed_identity = BinaryIdentity {
            exe_path: r"C:\Program Files\Example\BackupAgent.exe".to_string(),
            sha256: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: "CN=Example Vendor, O=Example Corp, C=US".to_string(),
                root_thumbprint: "3B1EFD3A66EA28B16697394703A72CA340A05BD5".to_string(),
            }),
        };

        let rule_exact_dn = AllowlistRuleRecord {
            rule_id: "SIGNED-EXACT".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: r"C:\Program Files\Example\*.exe".to_string(),
            sha256: None,
            signer_subject: Some("cn=example vendor, o=example corp, c=us".to_string()),
            root_thumbprint: Some("3b1efd3a66ea28b16697394703a72ca340a05bd5".to_string()),
            allowed_target: Some(r"C:\Users\*\.ssh\*".to_string()),
            created_at_ms: 1,
            created_by: "test".to_string(),
        };

        assert!(is_allowed_by_rules(
            &signed_identity,
            Some(r"c:/users/alice/.ssh/id_rsa"),
            RuleScope::FileCanaryAllow,
            std::slice::from_ref(&rule_exact_dn)
        ));
        // Wrong target rejected.
        assert!(!is_allowed_by_rules(
            &signed_identity,
            Some(r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies"),
            RuleScope::FileCanaryAllow,
            std::slice::from_ref(&rule_exact_dn)
        ));
        // Missing target rejected when allowed_target is set.
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            std::slice::from_ref(&rule_exact_dn)
        ));
        // Wrong scope rejected.
        assert!(!is_allowed_by_rules(
            &signed_identity,
            Some(r"C:\Users\alice\.ssh\id_rsa"),
            RuleScope::ProcessAllow,
            std::slice::from_ref(&rule_exact_dn)
        ));

        // CN-only rule matches full DN; mismatched root thumbprint is rejected.
        let cn_only_rule = AllowlistRuleRecord {
            signer_subject: Some("CN=Example Vendor".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[cn_only_rule]
        ));

        let wrong_root_rule = AllowlistRuleRecord {
            root_thumbprint: Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[wrong_root_rule]
        ));

        // Missing, empty, or all-zero root thumbprints MUST be rejected (SEC_0006 / L-04).
        let zero_root_rule = AllowlistRuleRecord {
            root_thumbprint: Some("0000000000000000000000000000000000000000".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[zero_root_rule]
        ));

        let none_root_rule = AllowlistRuleRecord {
            root_thumbprint: None,
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[none_root_rule]
        ));

        let empty_root_rule = AllowlistRuleRecord {
            root_thumbprint: Some(String::new()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[empty_root_rule]
        ));

        let blank_root_rule = AllowlistRuleRecord {
            root_thumbprint: Some("   ".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[blank_root_rule]
        ));

        // Optional sha256 on signed rule enforces hash match too.
        let signed_with_bad_hash = AllowlistRuleRecord {
            sha256: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(!is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[signed_with_bad_hash]
        ));

        // Unsigned binary must NEVER satisfy a signed rule.
        let unsigned_same_path = BinaryIdentity {
            authenticode: None,
            ..signed_identity
        };
        assert!(!is_allowed_by_rules(
            &unsigned_same_path,
            Some(r"C:\Users\alice\.ssh\id_rsa"),
            RuleScope::FileCanaryAllow,
            &[rule_exact_dn]
        ));
    }

    #[test]
    fn rules_p2_04_unsigned_tier_requires_non_empty_sha256() {
        use ledr_proto::RuleScope;

        let valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let unsigned_identity = BinaryIdentity {
            exe_path: r"C:\Tools\local_sync.exe".to_string(),
            sha256: Some(valid_hash.to_string()),
            authenticode: None,
        };

        // Unsigned rule WITHOUT sha256 must NEVER allow anything (L-04).
        let no_hash_rule = AllowlistRuleRecord {
            rule_id: "UNSIGNED-NO-HASH".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: r"C:\Tools\*".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        assert!(!is_allowed_by_rules(
            &unsigned_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[no_hash_rule]
        ));

        // Unsigned rule with empty sha256 must NEVER allow anything.
        let empty_hash_rule = AllowlistRuleRecord {
            rule_id: "UNSIGNED-EMPTY-HASH".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: r"C:\Tools\*".to_string(),
            sha256: Some("   ".to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        assert!(!is_allowed_by_rules(
            &unsigned_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[empty_hash_rule]
        ));

        // Unsigned rule with matching path and matching SHA-256 allows access.
        let valid_unsigned_rule = AllowlistRuleRecord {
            rule_id: "UNSIGNED-VALID".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: r"c:/tools/local_sync.exe".to_string(),
            sha256: Some(valid_hash.to_ascii_uppercase()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(r"E:\dev\proj\.env*".to_string()),
            created_at_ms: 2,
            created_by: "test".to_string(),
        };
        assert!(is_allowed_by_rules(
            &unsigned_identity,
            Some(r"E:\dev\proj\.env.local"),
            RuleScope::FileCanaryAllow,
            std::slice::from_ref(&valid_unsigned_rule)
        ));

        // Tampered binary (hash mismatch) rejected.
        let tampered_identity = BinaryIdentity {
            sha256: Some("deadbeef".repeat(8)),
            ..unsigned_identity.clone()
        };
        assert!(!is_allowed_by_rules(
            &tampered_identity,
            Some(r"E:\dev\proj\.env.local"),
            RuleScope::FileCanaryAllow,
            std::slice::from_ref(&valid_unsigned_rule)
        ));

        // Missing binary hash (unreadable file) rejected.
        let missing_hash_identity = BinaryIdentity {
            sha256: None,
            ..unsigned_identity
        };
        assert!(!is_allowed_by_rules(
            &missing_hash_identity,
            Some(r"E:\dev\proj\.env.local"),
            RuleScope::FileCanaryAllow,
            &[valid_unsigned_rule]
        ));
    }

    #[test]
    fn rules_p2_05_default_allowlist_browsers_and_openssh_on_disk() {
        use ledr_proto::RuleScope;

        let allowlist_json = include_str!("../../../rules/default_allowlist.json");
        let cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse default allowlist");

        // Every signed rule in default_allowlist.json must pin a non-empty, non-zero root thumbprint.
        for rule in &cfg.allowlist_rules {
            if rule.signer_subject.as_deref().is_some_and(|s| !s.trim().is_empty()) {
                let tp = rule
                    .root_thumbprint
                    .as_deref()
                    .map(str::trim)
                    .expect("signed default rule must set root_thumbprint");
                assert!(
                    !tp.is_empty() && !tp.chars().all(|c| c == '0'),
                    "default rule {} has invalid all-zero/empty root_thumbprint",
                    rule.rule_id
                );
            }
        }

        let candidates: &[(&[&str], &str, &str)] = &[
            (
                &[
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                ],
                r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
                r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
            ),
            (
                &[
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                ],
                r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
                r"C:\Users\alice\.ssh\id_ed25519",
            ),
            (
                &[
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                ],
                r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abc.default\cookies.sqlite",
                r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
            ),
            (
                &[r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"],
                r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
                r"C:\Users\alice\.aws\credentials",
            ),
            (
                &[r"C:\Windows\System32\OpenSSH\ssh.exe"],
                r"C:\Users\alice\.ssh\id_ed25519",
                r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            ),
        ];

        for (exe_candidates, allowed_target, disallowed_target) in candidates {
            for exe in *exe_candidates {
                let path = Path::new(exe);
                if path.is_file() {
                    let identity = BinaryIdentity::from_path(path);
                    assert!(
                        identity.authenticode.is_some(),
                        "expected valid Authenticode on {exe}"
                    );
                    assert!(
                        is_allowed_by_rules(
                            &identity,
                            Some(allowed_target),
                            RuleScope::FileCanaryAllow,
                            &cfg.allowlist_rules
                        ),
                        "expected {exe} ({:?}) to be allowed for {allowed_target}",
                        identity.authenticode
                    );
                    assert!(
                        !is_allowed_by_rules(
                            &identity,
                            Some(disallowed_target),
                            RuleScope::FileCanaryAllow,
                            &cfg.allowlist_rules
                        ),
                        "expected {exe} NOT to be allowed for {disallowed_target}"
                    );
                }
            }
        }
    }

    /// `RULES-P2-06` (`BUG_0006`): the `ALLOW-BROWSER-BRAVE` signer subject contains a
    /// comma and must stay quoted in `default_allowlist.json`; unquoted, `split_rdns`
    /// would split it into two RDNs and the rule could never match.
    #[test]
    fn rules_p2_06_default_allowlist_brave_signer_subject_with_comma_matches() {
        use ledr_proto::{AuthenticodeInfo, RuleScope};

        let allowlist_json = include_str!("../../../rules/default_allowlist.json");
        let cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse default allowlist");

        let brave_auth = AuthenticodeInfo {
            signer_subject:
                "CN=\"Brave Software, Inc.\", O=\"Brave Software, Inc.\", L=San Francisco, S=California, C=US"
                    .to_string(),
            root_thumbprint: "7B0F360B775F76C94A12CA48445AA2D2A875701C".to_string(),
        };
        let identity = BinaryIdentity {
            exe_path: r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
                .to_string(),
            sha256: None,
            authenticode: Some(brave_auth),
        };
        assert!(
            is_allowed_by_rules(
                &identity,
                Some(
                    r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies"
                ),
                RuleScope::FileCanaryAllow,
                &cfg.allowlist_rules
            ),
            "Brave signed identity must match ALLOW-BROWSER-BRAVE"
        );
    }

    #[test]
    fn rules_p3_01_outbound_risk_classification_and_external_ip_checks() {
        // Protected OS & LocalEDR binaries (AUTO-02).
        assert_eq!(
            classify_outbound_risk(r"C:\Windows\System32\svchost.exe"),
            OutboundRiskClass::ProtectedOs
        );
        assert_eq!(
            classify_outbound_risk(r"C:\Program Files\LocalEDR\ledr-daemon.exe"),
            OutboundRiskClass::ProtectedOs
        );

        // High-risk paths: Downloads, Temp, Tmp (L-03).
        assert_eq!(
            classify_outbound_risk(r"C:\Users\alice\Downloads\setup.exe"),
            OutboundRiskClass::HighRiskPath
        );
        assert_eq!(
            classify_outbound_risk(r"C:\Users\alice\AppData\Local\Temp\sub\dropper.exe"),
            OutboundRiskClass::HighRiskPath
        );
        assert_eq!(
            classify_outbound_risk(r"\\?\D:/TMP/tool.exe"),
            OutboundRiskClass::HighRiskPath
        );
        // Non-high-risk lookalikes must stay GeneralUnknown.
        assert_eq!(
            classify_outbound_risk(r"C:\Program Files\TemplateApp\downloader.exe"),
            OutboundRiskClass::GeneralUnknown
        );

        // Script interpreters (L-03).
        for script in [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Python312\python.exe",
            r"C:\Python312\python3.12.exe",
            r"C:\Python312\pythonw.exe",
            r"C:\Windows\System32\wscript.exe",
            r"C:\Windows\System32\cscript.exe",
            r"C:\Windows\System32\mshta.exe",
        ] {
            assert_eq!(
                classify_outbound_risk(script),
                OutboundRiskClass::ScriptInterpreter,
                "expected ScriptInterpreter for {script}"
            );
        }

        // External IP classification (IPv4, IPv6, IPv4-mapped IPv6).
        assert!(is_external_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(is_external_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946
        ))));
        for local in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 10, 2)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V6("::ffff:192.168.1.5".parse().unwrap()),
        ] {
            assert!(!is_external_ip(local), "expected local/non-external: {local}");
        }
        assert!(is_external_ip(IpAddr::V6("::ffff:93.184.216.34".parse().unwrap())));
    }

    #[test]
    fn rules_p3_02_outbound_policy_deny_overrides_allow_and_l04_tiers() {
        use ledr_proto::{AuthenticodeInfo, RuleScope};

        let dst_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let identity = BinaryIdentity {
            exe_path: r"C:\Tools\client.exe".to_string(),
            sha256: Some(sha.to_string()),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: "CN=Example Corp".to_string(),
                root_thumbprint: "3B1EFD3A66EA28B16697394703A72CA340A05BD5".to_string(),
            }),
        };

        // Unsigned NetworkAllow WITHOUT sha256 fails closed (`L-04`).
        let invalid_allow = AllowlistRuleRecord {
            rule_id: "ALLOW-INVALID".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\client.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        assert_eq!(
            evaluate_outbound_policy(&identity, dst_ip, Some("api.example.com"), &[invalid_allow]),
            OutboundDecision::UnknownFirstConnect
        );

        // Valid signed NetworkAllow scoped by wildcard domain allows matching connection.
        let valid_allow = AllowlistRuleRecord {
            rule_id: "ALLOW-CLIENT".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\client.exe".to_string(),
            sha256: None,
            signer_subject: Some("CN=Example Corp".to_string()),
            root_thumbprint: Some("3B1EFD3A66EA28B16697394703A72CA340A05BD5".to_string()),
            allowed_target: Some("*.example.com".to_string()),
            created_at_ms: 2,
            created_by: "test".to_string(),
        };
        assert_eq!(
            evaluate_outbound_policy(
                &identity,
                dst_ip,
                Some("api.example.com."),
                std::slice::from_ref(&valid_allow),
            ),
            OutboundDecision::AllowedByRule {
                rule_id: "ALLOW-CLIENT".to_string()
            }
        );
        assert_eq!(
            evaluate_outbound_policy(
                &identity,
                dst_ip,
                Some("evil.other.org"),
                std::slice::from_ref(&valid_allow),
            ),
            OutboundDecision::UnknownFirstConnect
        );

        // Deny-overrides-allow: path-only NetworkBlock overrides even when placed AFTER NetworkAllow.
        let path_block = AllowlistRuleRecord {
            rule_id: "BLOCK-CLIENT".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Tools\client.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 3,
            created_by: "user_quarantine".to_string(),
        };
        assert_eq!(
            evaluate_outbound_policy(
                &identity,
                dst_ip,
                Some("api.example.com"),
                &[valid_allow, path_block],
            ),
            OutboundDecision::BlockedByRule {
                rule_id: "BLOCK-CLIENT".to_string()
            }
        );

        // Protected OS process is NEVER blocked even if a wildcard NetworkBlock matches its path.
        let svchost = BinaryIdentity {
            exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
            sha256: None,
            authenticode: None,
        };
        let catch_all_block = AllowlistRuleRecord {
            rule_id: "BLOCK-ALL".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Windows\System32\*.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 4,
            created_by: "test".to_string(),
        };
        assert_eq!(
            evaluate_outbound_policy(&svchost, dst_ip, None, &[catch_all_block]),
            OutboundDecision::ProtectedOs
        );
    }

    #[test]
    fn rules_p3_03_nrd_feed_parser_caps_and_disk_cache_roundtrip() {
        let tmp = TestTempDir::new("ledr-rules-p3-nrd");
        let raw_feed = "\
# HaGeZi NRD 7-day sample
! comment
; comment
fresh-login.xyz
0.0.0.0   Phish-Bank.TOP.  # inline comment
||c2-drop.click^
127.0.0.1 localhost
203.0.113.5
not a valid line
-badlabel.com
brand-new.org
";
        let mut set = std::collections::HashSet::new();
        let (added, truncated) = parse_nrd_feed_bytes(raw_feed.as_bytes(), &mut set, 100);
        assert_eq!(added, 4);
        assert!(!truncated);
        assert!(set.contains("fresh-login.xyz"));
        assert!(set.contains("phish-bank.top"));
        assert!(set.contains("c2-drop.click"));
        assert!(set.contains("brand-new.org"));

        // Entry cap enforcement.
        let mut capped = std::collections::HashSet::new();
        let (capped_added, capped_trunc) = parse_nrd_feed_bytes(raw_feed.as_bytes(), &mut capped, 2);
        assert_eq!(capped_added, 2);
        assert!(capped_trunc);
        assert_eq!(capped.len(), 2);

        // Save/load roundtrip + staleness + exact & subdomain lookup (bare TLD never matches).
        let cache_path = tmp.path().join("nrd-cache.txt");
        let cache = NrdCache::from_domains(set.iter(), Some(1_760_000_000_000), NRD_MAX_ENTRIES);
        cache.save_to_file(&cache_path).expect("save NRD cache");

        let loaded = NrdCache::load_from_file(&cache_path, NRD_MAX_ENTRIES).expect("load NRD cache");
        assert_eq!(loaded.len(), 4);
        assert_eq!(loaded.updated_at_ms(), Some(1_760_000_000_000));
        assert!(!loaded.is_stale(1_760_000_000_000 + 1_000, NRD_REFRESH_INTERVAL_MS));
        assert!(loaded.is_stale(
            1_760_000_000_000 + i64::try_from(NRD_REFRESH_INTERVAL_MS).unwrap(),
            NRD_REFRESH_INTERVAL_MS
        ));
        assert!(loaded.contains("fresh-login.xyz"));
        assert!(loaded.contains("Sub.Fresh-Login.XYZ."));
        assert!(!loaded.contains("xyz"));
        assert!(!loaded.contains("not-fresh-login.xyz"));

        // Verify assess_domain_risk integrates subdomain NRD + homograph detection.
        let sub_risk = assess_domain_risk("login.phish-bank.top", Some(loaded.domains()));
        assert!(sub_risk.is_nrd);
        assert!(!sub_risk.is_homograph);

        let typo_risk = assess_domain_risk("micros0ft.com", Some(loaded.domains()));
        assert!(!typo_risk.is_nrd);
        assert!(typo_risk.is_homograph);
        assert_eq!(typo_risk.matched_brand.as_deref(), Some("microsoft"));
    }

    #[test]
    fn rules_p3_04_nrd_url_parsing_file_refresh_and_byte_cap() {
        // HTTP/HTTPS URL parser edge cases.
        let https = parse_http_url(DEFAULT_NRD_FEED_URLS[0]).expect("parse default nrd7 URL");
        assert!(https.is_https);
        assert_eq!(https.host, "raw.githubusercontent.com");
        assert_eq!(https.port, 443);
        assert_eq!(
            https.path_and_query,
            "/hagezi/nrd/main/domains/nrd7.txt"
        );
        let https_14 = parse_http_url(DEFAULT_NRD_FEED_URLS[1]).expect("parse default nrd14-8 URL");
        assert!(https_14.is_https);
        assert_eq!(https_14.host, "raw.githubusercontent.com");
        assert_eq!(
            https_14.path_and_query,
            "/hagezi/nrd/main/domains/nrd14-8.txt"
        );

        let v6_url = parse_http_url("http://[::1]:8080/feeds/nrd.txt?v=1").expect("parse v6 url");
        assert!(!v6_url.is_https);
        assert_eq!(v6_url.host, "::1");
        assert_eq!(v6_url.port, 8080);
        assert_eq!(v6_url.path_and_query, "/feeds/nrd.txt?v=1");

        assert!(parse_http_url("ftp://example.com/list.txt").is_err());
        assert!(parse_http_url("https://user:pass@example.com/list.txt").is_err());
        assert!(parse_http_url("https://example.com/bad path").is_err());

        // file:// refresh across two feeds + partial failure tolerance + response byte cap.
        let tmp = TestTempDir::new("ledr-rules-p3-file-feed");
        let feed1 = tmp.path().join("nrd7.txt");
        let feed2 = tmp.path().join("nrd14-8.txt");
        let missing = tmp.path().join("missing.txt");
        std::fs::write(&feed1, "alpha-new.xyz\nbeta-new.xyz\n").expect("write feed1");
        std::fs::write(&feed2, "gamma-new.top\ndelta-new.top\nepsilon-new.top\n")
            .expect("write feed2");

        let to_file_url = |p: &Path| -> String {
            format!("file:///{}", p.to_string_lossy().replace('\\', "/"))
        };
        let urls = vec![
            to_file_url(&feed1),
            to_file_url(&missing),
            to_file_url(&feed2),
        ];
        let (cache, stats) =
            refresh_nrd_cache(&urls, NRD_MAX_ENTRIES, NRD_MAX_RESPONSE_BYTES, 1_760_000_123_000)
                .expect("refresh succeeds when at least one feed succeeds");
        assert_eq!(stats.feeds_succeeded, 2);
        assert_eq!(stats.feeds_failed, 1);
        assert_eq!(stats.total_entries, 5);
        assert!(!stats.truncated);
        assert!(cache.contains("alpha-new.xyz"));
        assert!(cache.contains("epsilon-new.top"));

        // Byte cap trims cleanly at newline boundary without emitting half a domain.
        let (capped_cache, capped_stats) =
            refresh_nrd_cache(&[to_file_url(&feed2)], NRD_MAX_ENTRIES, 20, 1_760_000_123_000)
                .expect("byte-capped refresh");
        assert!(capped_stats.truncated);
        assert!(capped_cache.is_truncated());
        assert!(capped_cache.contains("gamma-new.top"));
        assert!(!capped_cache.contains("delta-new.top"));

        // All feeds failing returns Err so callers preserve their prior cache.
        assert!(
            refresh_nrd_cache(
                &[to_file_url(&missing)],
                NRD_MAX_ENTRIES,
                NRD_MAX_RESPONSE_BYTES,
                1_760_000_123_000
            )
            .is_err()
        );
    }

    #[test]
    fn rules_p3_05_canonical_ip_matching_policy_validation_and_nrd_truncation_edge_cases() {
        use ledr_proto::RuleScope;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // IPv4-mapped IPv6 matches plain IPv4 target and wildcard IPv4 target (no bypass).
        let mapped_v6 = IpAddr::V6(Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped());
        assert!(matches_network_target("93.184.216.34", mapped_v6, None));
        assert!(matches_network_target("93.184.*", mapped_v6, None));
        assert!(matches_network_target(
            "::ffff:93.184.216.34",
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            None
        ));

        // Uncompressed IPv6 rule target matches compressed IPv6 destination address.
        let v6_dst = IpAddr::V6(
            "2606:2800:220:1:248:1893:25c8:1946"
                .parse::<Ipv6Addr>()
                .expect("valid v6"),
        );
        assert!(matches_network_target(
            "2606:2800:0220:0001:0248:1893:25c8:1946",
            v6_dst,
            None
        ));

        // Server-side policy rule validator enforces L-04 & AUTO-02.
        let valid_sha = "a".repeat(64);
        let mk_rule = |scope: RuleScope| AllowlistRuleRecord {
            rule_id: "R-1".to_string(),
            scope,
            exe_path_pattern: r"C:\Tools\app.exe".to_string(),
            sha256: Some(valid_sha.clone()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: 1,
            created_by: "test".to_string(),
        };
        assert!(validate_policy_rule(&mk_rule(RuleScope::NetworkAllow)).is_ok());

        // Allow rule missing both sha256 and signer+thumbprint is rejected.
        let mut no_id = mk_rule(RuleScope::NetworkAllow);
        no_id.sha256 = None;
        assert!(validate_policy_rule(&no_id).is_err());

        // Signer without thumbprint (even if sha256 is set) is rejected.
        let mut signer_no_tp = mk_rule(RuleScope::NetworkAllow);
        signer_no_tp.signer_subject = Some("CN=Vendor".to_string());
        assert!(validate_policy_rule(&signer_no_tp).is_err());

        // All-zero root_thumbprint is rejected.
        let mut zero_tp = signer_no_tp.clone();
        zero_tp.root_thumbprint = Some("0".repeat(40));
        assert!(validate_policy_rule(&zero_tp).is_err());

        // Bad SHA-256 length/chars rejected.
        let mut bad_sha = mk_rule(RuleScope::NetworkAllow);
        bad_sha.sha256 = Some("not-a-valid-sha256".to_string());
        assert!(validate_policy_rule(&bad_sha).is_err());

        // Concrete NetworkBlock targeting AUTO-02 protected process (including trailing dot) rejected.
        let mut block_lsass = mk_rule(RuleScope::NetworkBlock);
        block_lsass.sha256 = None;
        block_lsass.exe_path_pattern = r"C:\Windows\System32\lsass.exe.".to_string();
        assert!(validate_policy_rule(&block_lsass).is_err());

        // Path-only NetworkBlock for non-protected app is valid.
        let mut block_app = mk_rule(RuleScope::NetworkBlock);
        block_app.sha256 = None;
        assert!(validate_policy_rule(&block_app).is_ok());

        // Single-line feed truncated BEFORE first newline must NOT emit a corrupted half-domain!
        let tmp = TestTempDir::new("ledr-rules-p3-single-line-trunc");
        let long_feed = tmp.path().join("single.txt");
        std::fs::write(&long_feed, "super-long-domain.example\n").expect("write single line");
        let mixed_file_url = format!("File:///{}", long_feed.to_string_lossy().replace('\\', "/"));
        let (bytes, truncated) =
            fetch_nrd_feed_url(&mixed_file_url, 22).expect("fetch truncated single-line feed");
        assert!(truncated);
        assert!(
            bytes.is_empty(),
            "truncated single line without newline must be discarded, got: {:?}",
            String::from_utf8_lossy(&bytes)
        );

        // Mixed-case HTTPS scheme + #fragment stripping + UNC file:// parsing.
        let upper_https =
            parse_http_url("HTTPS://example.com/nrd.txt?v=2#frag").expect("mixed-case https");
        assert!(upper_https.is_https);
        assert_eq!(upper_https.path_and_query, "/nrd.txt?v=2");
        assert_eq!(
            parse_file_url("file://fileserver/share/nrd7.txt").expect("UNC file url"),
            Path::new(r"\\fileserver\share\nrd7.txt")
        );
    }

    #[test]
    fn rules_p3_06_bounded_chunk_reader_handles_exact_cap_and_midline_overflow() {
        use std::collections::VecDeque;

        // 1. Exact cap with clean EOF (no extra bytes) -> not truncated, full body preserved.
        let mut exact_eof = VecDeque::from(vec![b"alpha.xyz\n".to_vec(), b"beta.xyz\n".to_vec()]);
        let (body, trunc) = crate::nrd::read_bounded_chunks(19, |_| Ok(exact_eof.pop_front()))
            .expect("exact EOF");
        assert!(!trunc);
        assert_eq!(String::from_utf8_lossy(&body), "alpha.xyz\nbeta.xyz\n");

        // 2. Chunk 1 fills exact cap (22 bytes) ending mid-domain, chunk 2 has remaining bytes ->
        //    MUST trim the partial second line even when hitting the `remaining_budget == 0` path!
        let mut exact_then_more = VecDeque::from(vec![
            b"first-ok.xyz\nsecond-ha".to_vec(),
            b"lf.xyz\n".to_vec(),
        ]);
        let (body, trunc) =
            crate::nrd::read_bounded_chunks(22, |_| Ok(exact_then_more.pop_front()))
                .expect("exact cap then more");
        assert!(trunc);
        assert_eq!(
            String::from_utf8_lossy(&body),
            "first-ok.xyz\n",
            "exact-cap boundary with trailing data must trim partial trailing domain"
        );

        // 3. Overflow mid-chunk with no newline anywhere -> buffer cleared cleanly.
        let mut no_nl = VecDeque::from(vec![b"very-long-single-line-domain.example".to_vec()]);
        let (body, trunc) =
            crate::nrd::read_bounded_chunks(18, |_| Ok(no_nl.pop_front())).expect("no newline");
        assert!(trunc);
        assert!(body.is_empty());
    }

    /// `RULES-P3-07`: `DEFAULT_NRD_FEED_URLS` targets `hagezi/nrd` over HTTPS, and
    /// `fetch_nrd_feed_url` rejects unencrypted remote `http://` URLs while recognizing
    /// loopback-only HTTP hosts for local tests.
    #[test]
    fn rules_p3_07_default_nrd_repo_urls_and_plaintext_remote_http_rejected() {
        assert_eq!(
            DEFAULT_NRD_FEED_URLS,
            &[
                "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt",
                "https://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd14-8.txt",
            ]
        );

        for remote_http in [
            "http://raw.githubusercontent.com/hagezi/nrd/main/domains/nrd7.txt",
            "HTTP://example.com/nrd7.txt",
            "http://192.168.1.10:8080/nrd7.txt",
            "http://localhost.evil.example/nrd7.txt",
            "http://[2001:db8::1]/nrd7.txt",
        ] {
            let err = fetch_nrd_feed_url(remote_http, 1024)
                .expect_err("unencrypted remote http:// NRD URL must be rejected");
            assert!(
                err.contains("unencrypted remote HTTP"),
                "unexpected error for `{remote_http}`: {err}"
            );
        }

        // Loopback classification accepts localhost / 127.0.0.0/8 / ::1 and rejects remote hosts.
        assert!(crate::nrd::is_loopback_http_host("localhost"));
        assert!(crate::nrd::is_loopback_http_host("LOCALHOST."));
        assert!(crate::nrd::is_loopback_http_host("127.0.0.1"));
        assert!(crate::nrd::is_loopback_http_host("127.10.20.30"));
        assert!(crate::nrd::is_loopback_http_host("::1"));
        assert!(crate::nrd::is_loopback_http_host("::ffff:127.0.0.1"));
        assert!(!crate::nrd::is_loopback_http_host("localhost.evil.example"));
        assert!(!crate::nrd::is_loopback_http_host("192.168.1.1"));
        assert!(!crate::nrd::is_loopback_http_host("93.184.216.34"));
    }

    /// `RULES-P3-08`: Startup script-interpreter discovery collects existing `%SystemRoot%`
    /// interpreters and `PATH`-installed `pwsh`/`node`/`python`/`python3`, deduplicated
    /// case-insensitively and excluding protected processes.
    #[test]
    fn rules_p3_08_discover_default_prerestricted_interpreters() {
        let tmp = TestTempDir::new("ledr-rules-p3-interpreters");
        let fake_sysroot = tmp.path().join("Windows");
        let ps64 = fake_sysroot.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
        let ps32 = fake_sysroot.join(r"SysWOW64\WindowsPowerShell\v1.0\powershell.exe");
        let wscript = fake_sysroot.join(r"System32\wscript.exe");
        let mshta = fake_sysroot.join(r"System32\mshta.exe");
        let bin_dir = tmp.path().join("Tools");
        let bin_dir_alt_case = tmp.path().join("tools");
        let node_exe = bin_dir.join("node.exe");
        let python_exe = bin_dir.join("python.exe");
        let pwsh_exe = bin_dir.join("pwsh.exe");

        for p in [&ps64, &ps32, &wscript, &mshta, &node_exe, &python_exe, &pwsh_exe] {
            std::fs::create_dir_all(p.parent().unwrap()).expect("create parent");
            std::fs::write(p, b"MZ").expect("write stub exe");
        }
        // Duplicate directory entry with different casing in PATH to test case-insensitive dedup.
        let joined_path = std::env::join_paths([bin_dir.as_path(), bin_dir_alt_case.as_path()])
            .expect("join PATH");
        let discovered = crate::outbound::discover_prerestricted_interpreters_from(
            Some(fake_sysroot.as_path()),
            Some(joined_path.as_os_str()),
        );
        assert_eq!(discovered.len(), 7, "discovered={discovered:?}");
        for expected in [&ps64, &ps32, &wscript, &mshta, &node_exe, &python_exe, &pwsh_exe] {
            let exp_str = expected.to_string_lossy().replace('/', "\\");
            assert!(
                discovered.iter().any(|p| p.eq_ignore_ascii_case(&exp_str)),
                "missing expected interpreter `{exp_str}` in {discovered:?}"
            );
        }
        // Non-existent cscript.exe and python3.exe must NOT be included.
        assert!(!discovered
            .iter()
            .any(|p| p.to_ascii_lowercase().ends_with("cscript.exe")));
        assert!(!discovered
            .iter()
            .any(|p| p.to_ascii_lowercase().ends_with("python3.exe")));

        // Real host smoke check: every returned path exists and is never a protected OS binary.
        let host_list = discover_default_prerestricted_interpreters();
        for p in &host_list {
            assert!(Path::new(p).is_file(), "discovered path must exist: {p}");
            assert!(
                !ledr_proto::is_never_suspend_process(p),
                "protected OS binary must never be pre-restricted: {p}"
            );
        }
    }

    #[test]
    fn rules_p3_09_nrd_cancel_token_aborts_in_flight_winhttp_and_chunks() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::{mpsc, Arc};
        use std::time::{Duration, Instant};

        // 1. Pre-cancelled token immediately aborts file://, http://, refresh, and chunk reader.
        let pre_cancelled = NrdCancelToken::new();
        assert!(!pre_cancelled.is_cancelled());
        pre_cancelled.cancel();
        assert!(pre_cancelled.is_cancelled());
        // Calling cancel() multiple times is idempotent and safe.
        pre_cancelled.cancel();

        let tmp = TestTempDir::new("ledr-rules-p3-cancel");
        let feed_file = tmp.path().join("feed.txt");
        std::fs::write(&feed_file, "example.xyz\n").expect("write feed");
        let file_url = format!("file:///{}", feed_file.to_string_lossy().replace('\\', "/"));

        let err = fetch_nrd_feed_url_cancellable(&file_url, 1024, &pre_cancelled)
            .expect_err("pre-cancelled file:// fetch must fail");
        assert!(err.contains("cancelled"), "{err}");

        let err = refresh_nrd_cache_cancellable(
            &[file_url],
            NRD_MAX_ENTRIES,
            NRD_MAX_RESPONSE_BYTES,
            1_760_000_000_000,
            &pre_cancelled,
        )
        .expect_err("pre-cancelled refresh_nrd_cache_cancellable must fail");
        assert!(err.contains("cancelled"), "{err}");

        let mid_cancel = NrdCancelToken::new();
        let mut chunk_idx = 0usize;
        let err = crate::nrd::read_bounded_chunks_cancellable(1024, &mid_cancel, |_| {
            chunk_idx += 1;
            if chunk_idx == 1 {
                Ok(Some(b"first.xyz\n".to_vec()))
            } else {
                mid_cancel.cancel();
                Ok(Some(b"second.xyz\n".to_vec()))
            }
        })
        .expect_err("chunk reader must abort promptly once token is cancelled");
        assert!(err.contains("cancelled"), "{err}");

        // 2. Uncancelled loopback HTTP 200 OK fetch succeeds.
        let ok_listener = TcpListener::bind("127.0.0.1:0").expect("bind ok listener");
        let ok_addr = ok_listener.local_addr().unwrap();
        let ok_server = std::thread::spawn(move || {
            let (mut stream, _) = ok_listener.accept().expect("accept ok client");
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let body = "new-phish.xyz\nfresh-c2.top\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).expect("write response");
            stream.flush().expect("flush");
        });
        let ok_url = format!("http://127.0.0.1:{}/nrd.txt", ok_addr.port());
        let ok_token = NrdCancelToken::new();
        let (bytes, trunc) = fetch_nrd_feed_url_cancellable(&ok_url, 1024, &ok_token)
            .expect("loopback HTTP fetch should succeed");
        assert!(!trunc);
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "new-phish.xyz\nfresh-c2.top\n"
        );
        ok_server.join().expect("join ok server");

        // 3. Hanging TCP server (accepts request and never sends response headers):
        //    calling NrdCancelToken::cancel() aborts in-flight fetch well under 1 second.
        let hang_listener = TcpListener::bind("127.0.0.1:0").expect("bind hang listener");
        let hang_addr = hang_listener.local_addr().unwrap();
        let (req_seen_tx, req_seen_rx) = mpsc::channel::<()>();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let hang_server = std::thread::spawn(move || {
            let (mut stream, _) = hang_listener.accept().expect("accept hang client");
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let _ = req_seen_tx.send(());
            // Keep socket open up to 10s unless test finishes early.
            let _ = release_rx.recv_timeout(Duration::from_secs(10));
        });

        let hang_url = format!("http://127.0.0.1:{}/hang.txt", hang_addr.port());
        let cancel_token = Arc::new(NrdCancelToken::new());
        let worker_token = Arc::clone(&cancel_token);
        let fetch_handle = std::thread::spawn(move || {
            fetch_nrd_feed_url_cancellable(&hang_url, NRD_MAX_RESPONSE_BYTES, &worker_token)
        });

        req_seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("WinHTTP client should connect and send GET to hanging server");
        // Small grace period so WinHTTP enters WinHttpReceiveResponse.
        std::thread::sleep(Duration::from_millis(30));

        let cancel_started = Instant::now();
        cancel_token.cancel();
        let fetch_res = fetch_handle.join().expect("fetch thread must not panic");
        let elapsed = cancel_started.elapsed();
        let _ = release_tx.send(());
        hang_server.join().expect("join hang server");

        let cancel_err = fetch_res.expect_err("cancelled in-flight HTTP fetch must return Err");
        assert!(
            cancel_err.contains("cancelled"),
            "unexpected error after cancel: {cancel_err}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "in-flight NRD fetch took too long to abort after cancel(): {elapsed:?}"
        );

        // 4. Mid-body hanging TCP server (sends 200 OK + partial body, then stalls):
        //    cancel() aborts WinHttpQueryDataAvailable / WinHttpReadData well under 1 second.
        let body_listener = TcpListener::bind("127.0.0.1:0").expect("bind body hang listener");
        let body_addr = body_listener.local_addr().unwrap();
        let (body_seen_tx, body_seen_rx) = mpsc::channel::<()>();
        let (body_release_tx, body_release_rx) = mpsc::channel::<()>();
        let body_server = std::thread::spawn(move || {
            let (mut stream, _) = body_listener.accept().expect("accept body hang client");
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial-one.xyz\n",
            );
            let _ = stream.flush();
            let _ = body_seen_tx.send(());
            let _ = body_release_rx.recv_timeout(Duration::from_secs(10));
        });

        let body_url = format!("http://127.0.0.1:{}/mid-body-hang.txt", body_addr.port());
        let body_token = Arc::new(NrdCancelToken::new());
        let body_worker_token = Arc::clone(&body_token);
        let body_fetch = std::thread::spawn(move || {
            fetch_nrd_feed_url_cancellable(&body_url, NRD_MAX_RESPONSE_BYTES, &body_worker_token)
        });

        body_seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("body hang server should flush initial chunk");
        std::thread::sleep(Duration::from_millis(50));

        let body_cancel_started = Instant::now();
        body_token.cancel();
        let body_res = body_fetch.join().expect("body fetch thread must not panic");
        let body_elapsed = body_cancel_started.elapsed();
        let _ = body_release_tx.send(());
        body_server.join().expect("join body hang server");

        let body_err = body_res.expect_err("cancelled mid-body HTTP fetch must return Err");
        assert!(
            body_err.contains("cancelled"),
            "unexpected error after mid-body cancel: {body_err}"
        );
        assert!(
            body_elapsed < Duration::from_secs(1),
            "mid-body NRD fetch took too long to abort after cancel(): {body_elapsed:?}"
        );
    }

    #[test]
    fn rules_p3_10_cidr_matching_and_validation() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use ledr_proto::{AllowlistRuleRecord, RuleScope};

        // IPv4 CIDR parsing and host-bit normalization.
        assert_eq!(
            parse_cidr_target("198.51.100.42/24").expect("valid IPv4 CIDR"),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24)
        );
        assert_eq!(
            parse_cidr_target("0.0.0.0/0").expect("valid /0 IPv4 CIDR"),
            (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
        );
        assert_eq!(
            parse_cidr_target("::ffff:198.51.100.42/120").expect("valid mapped IPv6 CIDR"),
            (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)), 24)
        );
        assert_eq!(
            parse_cidr_target("2001:db8:0:1::abcd/48").expect("valid IPv6 CIDR"),
            (
                IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()),
                48
            )
        );

        // Malformed CIDRs must fail validation.
        for bad in [
            "198.51.100.0",
            "198.51.100.0/",
            "198.51.100.0/33",
            "198.51.100.0/+24",
            "198.51.100.0/-1",
            "198.51.100.0/24/8",
            "2001:db8::/129",
            "not-an-ip/24",
            "198.*.100.0/24",
        ] {
            assert!(parse_cidr_target(bad).is_err(), "expected invalid CIDR: {bad}");
        }

        // CIDR matching including IPv4-mapped IPv6 canonicalization.
        assert!(matches_network_target(
            "198.51.100.0/24",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200)),
            None
        ));
        assert!(matches_network_target(
            "198.51.100.0/24",
            IpAddr::V6("::ffff:198.51.100.77".parse().unwrap()),
            None
        ));
        assert!(!matches_network_target(
            "198.51.100.0/24",
            IpAddr::V4(Ipv4Addr::new(198, 51, 101, 1)),
            None
        ));
        assert!(matches_network_target(
            "0.0.0.0/0",
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            None
        ));
        assert!(!matches_network_target(
            "0.0.0.0/0",
            IpAddr::V6("2001:4860:4860::8888".parse().unwrap()),
            None
        ));
        assert!(matches_network_target(
            "2001:db8::/32",
            IpAddr::V6("2001:0db8:85a3::8a2e".parse().unwrap()),
            None
        ));
        assert!(!matches_network_target(
            "2001:db8::/32",
            IpAddr::V6("2001:0db9::1".parse().unwrap()),
            None
        ));
        // Invalid CIDR in pattern must never fall through to wildcard matching.
        assert!(!matches_network_target(
            "198.51.100.0/99",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            Some("198.51.100.0/99")
        ));

        // validate_policy_rule rejects malformed CIDR on NetworkAllow / NetworkBlock.
        let valid_rule = AllowlistRuleRecord {
            rule_id: "net-cidr-allow".to_string(),
            exe_path_pattern: r"c:\tools\client.exe".to_string(),
            sha256: Some("a".repeat(64)),
            signer_subject: None,
            root_thumbprint: None,
            scope: RuleScope::NetworkAllow,
            allowed_target: Some("203.0.113.0/24".to_string()),
            created_by: "test".to_string(),
            created_at_ms: 1,
        };
        assert!(validate_policy_rule(&valid_rule).is_ok());

        let mut bad_allow = valid_rule.clone();
        bad_allow.allowed_target = Some("203.0.113.0/33".to_string());
        assert!(validate_policy_rule(&bad_allow).is_err());

        let bad_block = AllowlistRuleRecord {
            rule_id: "net-cidr-block".to_string(),
            exe_path_pattern: r"c:\tools\client.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            scope: RuleScope::NetworkBlock,
            allowed_target: Some("10.0.0.0/+8".to_string()),
            created_by: "test".to_string(),
            created_at_ms: 1,
        };
        assert!(validate_policy_rule(&bad_block).is_err());
    }

    #[test]
    fn rules_p3_11_async_winhttp_multi_chunk_and_http_errors() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        // 1. Multi-chunk streaming body exercises repeated async WinHttpQueryDataAvailable /
        //    WinHttpReadData cycles plus truncation trimming on a partial line.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind multi-chunk listener");
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept multi-chunk client");
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let _ = stream.flush();
            let c1 = b"alpha-one.xyz\nbeta-two.top\n";
            let _ = write!(stream, "{:x}\r\n", c1.len());
            let _ = stream.write_all(c1);
            let _ = stream.write_all(b"\r\n");
            let _ = stream.flush();
            std::thread::sleep(Duration::from_millis(20));

            let c2 = b"gamma-three.club\ndelta-four.site\n";
            let _ = write!(stream, "{:x}\r\n", c2.len());
            let _ = stream.write_all(c2);
            let _ = stream.write_all(b"\r\n0\r\n\r\n");
            let _ = stream.flush();
        });

        let url = format!("http://127.0.0.1:{}/chunked.txt", addr.port());
        let token = NrdCancelToken::new();
        let (full_bytes, full_trunc) = fetch_nrd_feed_url_cancellable(&url, 4096, &token)
            .expect("multi-chunk async WinHTTP fetch must succeed");
        assert!(!full_trunc);
        assert_eq!(
            String::from_utf8_lossy(&full_bytes),
            "alpha-one.xyz\nbeta-two.top\ngamma-three.club\ndelta-four.site\n"
        );
        server.join().expect("join multi-chunk server");

        // 2. Non-2xx status code fails cleanly.
        let err_listener = TcpListener::bind("127.0.0.1:0").expect("bind 503 listener");
        let err_addr = err_listener.local_addr().unwrap();
        let err_server = std::thread::spawn(move || {
            let (mut stream, _) = err_listener.accept().expect("accept 503 client");
            let mut req_buf = [0u8; 512];
            let _ = stream.read(&mut req_buf);
            let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        let err_url = format!("http://127.0.0.1:{}/fail.txt", err_addr.port());
        let status_err = fetch_nrd_feed_url_cancellable(&err_url, 1024, &token)
            .expect_err("HTTP 503 must error");
        assert!(status_err.contains("503"), "{status_err}");
        err_server.join().expect("join 503 server");
    }

    #[test]
    fn rules_p3_12_async_winhttp_concurrent_cancel_stress() {
        use std::io::Read;
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind cancel stress listener");
        listener.set_nonblocking(true).expect("set_nonblocking");
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let reqs_received = Arc::new(AtomicUsize::new(0));
        let stop_bg = Arc::clone(&stop);
        let reqs_bg = Arc::clone(&reqs_received);
        let srv = std::thread::spawn(move || {
            let mut held = Vec::new();
            while !stop_bg.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
                        let mut buf = [0u8; 512];
                        if let Ok(n) = s.read(&mut buf) {
                            if buf[..n].starts_with(b"GET ") {
                                reqs_bg.fetch_add(1, Ordering::AcqRel);
                            }
                        }
                        held.push(s);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        let url = format!("http://127.0.0.1:{port}/stress.txt");
        // Deterministic mid-flight cancel checks: wait until the HTTP GET request reaches the
        // hanging server before signalling cancellation and verifying a cancel error returns.
        for iter in 0..3u64 {
            let before = reqs_received.load(Ordering::Acquire);
            let token = Arc::new(NrdCancelToken::new());
            let worker_token = Arc::clone(&token);
            let url_c = url.clone();
            let handle = std::thread::spawn(move || {
                fetch_nrd_feed_url_cancellable(&url_c, NRD_MAX_RESPONSE_BYTES, &worker_token)
            });
            let wait_deadline = Instant::now() + Duration::from_secs(2);
            while reqs_received.load(Ordering::Acquire) == before && Instant::now() < wait_deadline
            {
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(
                reqs_received.load(Ordering::Acquire) > before,
                "midflight iter {iter}: server must receive HTTP GET before cancel"
            );
            let started = Instant::now();
            token.cancel();
            let err = handle
                .join()
                .expect("fetch thread must not panic")
                .expect_err("midflight cancelled fetch must fail");
            let elapsed = started.elapsed();
            assert!(
                err.to_ascii_lowercase().contains("cancel"),
                "midflight iter {iter}: expected cancellation error, got {err}"
            );
            assert!(
                elapsed < Duration::from_secs(1),
                "midflight iter {iter}: cancel took too long ({elapsed:?})"
            );
        }

        // Tight timing sweep across 0..14 ms to stress handle registration and WinHTTP async races.
        for iter in 0..20u64 {
            let token = Arc::new(NrdCancelToken::new());
            let worker_token = Arc::clone(&token);
            let url_c = url.clone();
            let handle = std::thread::spawn(move || {
                fetch_nrd_feed_url_cancellable(&url_c, NRD_MAX_RESPONSE_BYTES, &worker_token)
            });
            std::thread::sleep(Duration::from_millis(iter % 15));
            let started = Instant::now();
            token.cancel();
            let err = handle
                .join()
                .expect("fetch thread must not panic")
                .expect_err("cancelled fetch must fail");
            let elapsed = started.elapsed();
            assert!(
                err.to_ascii_lowercase().contains("cancel"),
                "iter {iter}: expected cancellation error, got {err}"
            );
            assert!(
                elapsed < Duration::from_secs(1),
                "iter {iter}: cancel took too long ({elapsed:?})"
            );
        }

        stop.store(true, Ordering::Release);
        srv.join().expect("join stress server");
    }
}
