//! Layer 2 early pruning, Sigma subset rule engine, Authenticode verification,
//! and newly-registered domain (NRD) / homograph detection crate.

pub mod allowlist;
pub mod domain;
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

        // All-zero root thumbprint permits match without thumbprint pinning.
        let zero_root_rule = AllowlistRuleRecord {
            root_thumbprint: Some("0000000000000000000000000000000000000000".to_string()),
            allowed_target: None,
            ..rule_exact_dn.clone()
        };
        assert!(is_allowed_by_rules(
            &signed_identity,
            None,
            RuleScope::FileCanaryAllow,
            &[zero_root_rule]
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
}
