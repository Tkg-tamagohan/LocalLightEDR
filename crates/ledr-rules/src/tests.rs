use super::*;
use ledr_auth_helper::{inspect_authenticode, LOCAL_CERT_CHAIN_FLAGS};
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

    // Verify both `assess_domain_risk_with_cache` (flat arena) and legacy `assess_domain_risk`
    // (`&HashSet<String>`) integrate subdomain NRD + homograph detection identically.
    let sub_risk = assess_domain_risk_with_cache("login.phish-bank.top", Some(&loaded));
    assert!(sub_risk.is_nrd);
    assert!(!sub_risk.is_homograph);
    assert_eq!(
        sub_risk,
        assess_domain_risk("login.phish-bank.top", Some(&set))
    );

    let typo_risk = assess_domain_risk_with_cache("micros0ft.com", Some(&loaded));
    assert!(!typo_risk.is_nrd);
    assert!(typo_risk.is_homograph);
    assert_eq!(typo_risk.matched_brand.as_deref(), Some("microsoft"));
    assert_eq!(
        typo_risk,
        assess_domain_risk("micros0ft.com", Some(&set))
    );
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
    let (body, trunc) = crate::nrd::read_bounded_chunks_cancellable(
        19,
        &NrdCancelToken::new(),
        |_| Ok(exact_eof.pop_front()),
    )
    .expect("exact EOF");
    assert!(!trunc);
    assert_eq!(String::from_utf8_lossy(&body), "alpha.xyz\nbeta.xyz\n");

    // 2. Chunk 1 fills exact cap (22 bytes) ending mid-domain, chunk 2 has remaining bytes ->
    //    MUST trim the partial second line even when hitting the `remaining_budget == 0` path!
    let mut exact_then_more = VecDeque::from(vec![
        b"first-ok.xyz\nsecond-ha".to_vec(),
        b"lf.xyz\n".to_vec(),
    ]);
    let (body, trunc) = crate::nrd::read_bounded_chunks_cancellable(
        22,
        &NrdCancelToken::new(),
        |_| Ok(exact_then_more.pop_front()),
    )
    .expect("exact cap then more");
    assert!(trunc);
    assert_eq!(
        String::from_utf8_lossy(&body),
        "first-ok.xyz\n",
        "exact-cap boundary with trailing data must trim partial trailing domain"
    );

    // 3. Overflow mid-chunk with no newline anywhere -> buffer cleared cleanly.
    let mut no_nl = VecDeque::from(vec![b"very-long-single-line-domain.example".to_vec()]);
    let (body, trunc) = crate::nrd::read_bounded_chunks_cancellable(
        18,
        &NrdCancelToken::new(),
        |_| Ok(no_nl.pop_front()),
    )
    .expect("no newline");
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
                    if read_http_get_prefix(&mut s, &stop_bg) {
                        reqs_bg.fetch_add(1, Ordering::AcqRel);
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

fn read_http_get_prefix(
    s: &mut std::net::TcpStream,
    stop: &std::sync::atomic::AtomicBool,
) -> bool {
    use std::io::Read;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(Duration::from_millis(50)));
    let mut buf = [0u8; 512];
    let mut total = 0usize;
    let read_deadline = Instant::now() + Duration::from_millis(250);
    while total < 4 && Instant::now() < read_deadline && !stop.load(Ordering::Acquire) {
        match s.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(_) => break,
        }
    }
    total >= 4 && &buf[..4] == b"GET "
}

// Note: `RULES-P3-13` was intentionally retired in PR #14 (`8268dfe`) during test pruning;
// `RULES-P3-14` and `RULES-P3-15` retain their original IDs to match existing `rules_p3_01`..`rules_p3_12`
// function names and preserve historical traceability.
/// `RULES-P3-14`（`決定記録 L-14` / `AUTO-10` / 指摘 R-11）:
/// ファイル形式 NRD フィードの 64 KiB チャンク単位読み取り（`read_bounded_reader_cancellable` /
/// `read_bounded_file`）について、1 チャンク読み込み後のキャンセルで 2 チャンク目の `read()` を
/// 呼ばず `"NRD feed download cancelled"` で即終了すること、事前キャンセル済みトークンで
/// 0 回読み取り即終了すること、`ErrorKind::Interrupted` 再試行時のキャンセル検知、通常の
/// マルチチャンクファイル読み込み、および `max_bytes` 上限切り詰めと末尾不完全行トリムを
/// 決定的に検証する。
#[test]
fn rules_p3_14_file_nrd_feed_chunked_reader_cancellation_and_truncation() {
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    struct ScriptedChunkReader {
        steps: VecDeque<io::Result<Vec<u8>>>,
        read_calls: Arc<AtomicUsize>,
        observed_buf_lens: Arc<Mutex<Vec<usize>>>,
        cancel_on_call: Option<(usize, NrdCancelToken)>,
    }

    impl Read for ScriptedChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let call_idx = self.read_calls.fetch_add(1, Ordering::AcqRel) + 1;
            self.observed_buf_lens
                .lock()
                .expect("lock observed_buf_lens")
                .push(buf.len());
            let res = match self.steps.pop_front() {
                Some(Ok(chunk)) => {
                    let n = chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    Ok(n)
                }
                Some(Err(err)) => Err(err),
                None => Ok(0),
            };
            if let Some((target_call, ref token)) = self.cancel_on_call {
                if call_idx == target_call {
                    token.cancel();
                }
            }
            res
        }
    }

    let chunk_size = crate::nrd::NRD_FILE_READ_CHUNK_BYTES;
    assert_eq!(chunk_size, 64 * 1024);

    // 1. 1 チャンク（64 KiB）読み込み後に cancel() が実行されると、2 チャンク目の read() を
    //    呼ばず即座に "NRD feed download cancelled" で終了する（read 呼び出し回数 == 1）。
    let mid_token = NrdCancelToken::new();
    let mid_calls = Arc::new(AtomicUsize::new(0));
    let mid_buf_lens = Arc::new(Mutex::new(Vec::new()));
    let mid_reader = ScriptedChunkReader {
        steps: VecDeque::from([
            Ok(vec![b'a'; chunk_size]),
            Ok(vec![b'b'; chunk_size]),
        ]),
        read_calls: Arc::clone(&mid_calls),
        observed_buf_lens: Arc::clone(&mid_buf_lens),
        cancel_on_call: Some((1, mid_token.clone())),
    };
    let err = crate::nrd::read_bounded_reader_cancellable(
        mid_reader,
        NRD_MAX_RESPONSE_BYTES,
        &mid_token,
    )
    .expect_err("cancel after first chunk must abort immediately");
    assert_eq!(err, "NRD feed download cancelled");
    assert_eq!(
        mid_calls.load(Ordering::Acquire),
        1,
        "second chunk read() must not be invoked after cancellation"
    );
    assert_eq!(
        *mid_buf_lens.lock().expect("lock mid_buf_lens"),
        vec![chunk_size],
        "file chunk reader must request 64 KiB chunks"
    );

    // 2. 事前キャンセル済みトークンでは read() を 0 回で即終了する。
    let pre_token = NrdCancelToken::new();
    pre_token.cancel();
    let pre_calls = Arc::new(AtomicUsize::new(0));
    let pre_reader = ScriptedChunkReader {
        steps: VecDeque::from([Ok(b"alpha.xyz\n".to_vec())]),
        read_calls: Arc::clone(&pre_calls),
        observed_buf_lens: Arc::new(Mutex::new(Vec::new())),
        cancel_on_call: None,
    };
    let err = crate::nrd::read_bounded_reader_cancellable(
        pre_reader,
        NRD_MAX_RESPONSE_BYTES,
        &pre_token,
    )
    .expect_err("pre-cancelled reader must abort before first read");
    assert_eq!(err, "NRD feed download cancelled");
    assert_eq!(
        pre_calls.load(Ordering::Acquire),
        0,
        "pre-cancelled reader must perform zero read() calls"
    );

    // 3. ErrorKind::Interrupted 再試行時のキャンセル検知と、非キャンセル時の正常リトライ。
    let eintr_cancel_token = NrdCancelToken::new();
    let eintr_cancel_calls = Arc::new(AtomicUsize::new(0));
    let eintr_cancel_reader = ScriptedChunkReader {
        steps: VecDeque::from([
            Err(io::Error::new(io::ErrorKind::Interrupted, "simulated eintr")),
            Ok(b"never-read.xyz\n".to_vec()),
        ]),
        read_calls: Arc::clone(&eintr_cancel_calls),
        observed_buf_lens: Arc::new(Mutex::new(Vec::new())),
        cancel_on_call: Some((1, eintr_cancel_token.clone())),
    };
    let err = crate::nrd::read_bounded_reader_cancellable(
        eintr_cancel_reader,
        1024,
        &eintr_cancel_token,
    )
    .expect_err("cancel during Interrupted must abort without retrying");
    assert_eq!(err, "NRD feed download cancelled");
    assert_eq!(eintr_cancel_calls.load(Ordering::Acquire), 1);

    let eintr_retry_calls = Arc::new(AtomicUsize::new(0));
    let eintr_retry_reader = ScriptedChunkReader {
        steps: VecDeque::from([
            Err(io::Error::new(io::ErrorKind::Interrupted, "transient eintr")),
            Ok(b"after-eintr.xyz\n".to_vec()),
        ]),
        read_calls: Arc::clone(&eintr_retry_calls),
        observed_buf_lens: Arc::new(Mutex::new(Vec::new())),
        cancel_on_call: None,
    };
    let (retried_bytes, retried_trunc) = crate::nrd::read_bounded_reader_cancellable(
        eintr_retry_reader,
        1024,
        &NrdCancelToken::new(),
    )
    .expect("uncancelled Interrupted should retry and succeed");
    assert!(!retried_trunc);
    assert_eq!(retried_bytes, b"after-eintr.xyz\n");
    assert_eq!(eintr_retry_calls.load(Ordering::Acquire), 3);

    // 4. 通常のファイル読み込み（64 KiB 超マルチチャンク）および事前キャンセル時の read_bounded_file。
    let tmp = TestTempDir::new("ledr-rules-p3-14");
    let large_file = tmp.path().join("large-nrd.txt");
    let mut expected_large = String::new();
    for idx in 0..8_000usize {
        // 19 bytes per line ("d00000.example.xyz\n") -> 152,000 bytes (> 2 * 64 KiB).
        expected_large.push_str(&format!("d{idx:05}.example.xyz\n"));
    }
    assert!(expected_large.len() > chunk_size * 2);
    std::fs::write(&large_file, expected_large.as_bytes()).expect("write large NRD feed");

    let uncancelled = NrdCancelToken::new();
    let (read_all, trunc_all) =
        crate::nrd::read_bounded_file(&large_file, NRD_MAX_RESPONSE_BYTES, &uncancelled)
            .expect("read_bounded_file must read multi-chunk file cleanly");
    assert!(!trunc_all);
    assert_eq!(read_all, expected_large.as_bytes());

    let file_url = format!("file:///{}", large_file.to_string_lossy().replace('\\', "/"));
    let (fetched_all, fetched_trunc) =
        fetch_nrd_feed_url_cancellable(&file_url, NRD_MAX_RESPONSE_BYTES, &uncancelled)
            .expect("fetch_nrd_feed_url_cancellable file:// must succeed");
    assert!(!fetched_trunc);
    assert_eq!(fetched_all, expected_large.as_bytes());

    let missing_path = tmp.path().join("missing-not-opened.txt");
    let pre_file_err = crate::nrd::read_bounded_file(&missing_path, 1024, &pre_token)
        .expect_err("pre-cancelled read_bounded_file must abort before opening file");
    assert_eq!(pre_file_err, "NRD feed download cancelled");

    // 5. max_bytes 境界条件（ちょうど上限での EOF / 上限超過時の末尾不完全行トリム / 改行なし全破棄）。
    // 5a. 小サイズでちょうど max_bytes 一致かつ末尾改行なし -> truncated == false で全量保持。
    let exact_small_file = tmp.path().join("exact-small.txt");
    let exact_small = b"exact-one.xyz\nexact-two.top";
    std::fs::write(&exact_small_file, exact_small).expect("write exact small");
    let (bytes, trunc) =
        crate::nrd::read_bounded_file(&exact_small_file, exact_small.len(), &uncancelled)
            .expect("exact max_bytes EOF");
    assert!(!trunc);
    assert_eq!(bytes, exact_small);

    // 5b. ちょうど 64 KiB チャンク境界で EOF -> truncated == false で全量保持。
    let exact_chunk_buf = vec![b'x'; chunk_size];
    let (bytes, trunc) = crate::nrd::read_bounded_reader_cancellable(
        Cursor::new(exact_chunk_buf.clone()),
        chunk_size,
        &uncancelled,
    )
    .expect("exact 64 KiB EOF");
    assert!(!trunc);
    assert_eq!(bytes, exact_chunk_buf);

    // 5c. ちょうど 64 KiB 上限で後続データが存在し 65536 バイト目がドメイン途中 ->
    //     remaining_budget == 0 経路でも truncated == true かつ末尾不完全行を改行までトリム。
    assert_ne!(chunk_size % 19, 0, "64 KiB boundary must land mid-line");
    let (capped_64k, trunc_64k) =
        crate::nrd::read_bounded_file(&large_file, chunk_size, &uncancelled)
            .expect("64 KiB capped read");
    assert!(trunc_64k);
    let expected_64k_len = (chunk_size / 19) * 19;
    assert_eq!(capped_64k.len(), expected_64k_len);
    assert_eq!(capped_64k, &expected_large.as_bytes()[..expected_64k_len]);
    assert!(capped_64k.ends_with(b"\n"));

    // 5d. 小サイズ上限超過時の末尾不完全行トリム。
    let small_trunc_file = tmp.path().join("small-trunc.txt");
    std::fs::write(
        &small_trunc_file,
        b"first-domain.xyz\nsecond-domain.top\nthird-domain.org\n",
    )
    .expect("write small trunc");
    let (bytes, trunc) = crate::nrd::read_bounded_file(&small_trunc_file, 25, &uncancelled)
        .expect("small mid-line truncation");
    assert!(trunc);
    assert_eq!(bytes, b"first-domain.xyz\n");

    // 5e. 最初の改行より前に max_bytes 超過 -> 不完全な単一行は空バッファとして破棄。
    let single_line_file = tmp.path().join("single-line.txt");
    std::fs::write(
        &single_line_file,
        b"single-very-long-domain-without-early-newline.example\n",
    )
    .expect("write single line");
    let (bytes, trunc) = crate::nrd::read_bounded_file(&single_line_file, 20, &uncancelled)
        .expect("single-line truncation");
    assert!(trunc);
    assert!(bytes.is_empty());
}

/// `RULES-P3-15`（`決定記録 L-14` / PR #5 指摘 #10）:
/// `NrdCancelToken` のブロッキング読み取り観測 API（`is_blocking_read_active()` /
/// `blocking_read_entries()`）と `BlockingReadGuard` の RAII 動作を決定的に検証する。
/// チャネル同期のブロッキング `Read` モックを用い（`thread::sleep` 不使用）、
/// 1 回目 `read()` 通過後の 2 回目 `read()` ブロック中に `blocking_read_entries() == 2`
/// かつ `is_blocking_read_active() == true` をテストスレッドから観測できること、および
/// (a) 通常 EOF 完了、(b) ブロック中 `read()` からの I/O エラー終了、
/// (c) ブロック中 `cancel()` 後のアンブロック終了のいずれでも `is_blocking_read_active()`
/// が自動で `false` へ戻ることを確認する。
#[test]
fn rules_p3_15_nrd_cancel_token_blocking_read_observation_and_guard_reset() {
    use std::io::{self, Read};
    use std::sync::mpsc;
    use std::time::Duration;

    struct ChannelBlockingReader {
        token: NrdCancelToken,
        first_chunk: Vec<u8>,
        first_obs_tx: Option<mpsc::SyncSender<(u64, bool)>>,
        second_entered_tx: Option<mpsc::SyncSender<()>>,
        second_release_rx: mpsc::Receiver<io::Result<Vec<u8>>>,
        call_count: usize,
    }

    impl Read for ChannelBlockingReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.call_count += 1;
            match self.call_count {
                1 => {
                    if let Some(tx) = self.first_obs_tx.take() {
                        let _ = tx.send((
                            self.token.blocking_read_entries(),
                            self.token.is_blocking_read_active(),
                        ));
                    }
                    let n = self.first_chunk.len().min(buf.len());
                    buf[..n].copy_from_slice(&self.first_chunk[..n]);
                    Ok(n)
                }
                2 => {
                    if let Some(tx) = self.second_entered_tx.take() {
                        let _ = tx.send(());
                    }
                    match self.second_release_rx.recv_timeout(Duration::from_secs(5)) {
                        Ok(Ok(bytes)) => {
                            let n = bytes.len().min(buf.len());
                            buf[..n].copy_from_slice(&bytes[..n]);
                            Ok(n)
                        }
                        Ok(Err(err)) => Err(err),
                        Err(err) => Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("test channel did not release 2nd read: {err}"),
                        )),
                    }
                }
                _ => Ok(0),
            }
        }
    }

    type ReaderJoinHandle = std::thread::JoinHandle<Result<(Vec<u8>, bool), String>>;

    let spawn_blocked_on_second_read =
        || -> (NrdCancelToken, mpsc::SyncSender<io::Result<Vec<u8>>>, ReaderJoinHandle) {
            let token = NrdCancelToken::new();
            assert!(!token.is_blocking_read_active());
            assert_eq!(token.blocking_read_entries(), 0);

            let (first_obs_tx, first_obs_rx) = mpsc::sync_channel(1);
            let (second_entered_tx, second_entered_rx) = mpsc::sync_channel(1);
            let (second_release_tx, second_release_rx) = mpsc::sync_channel(1);

            let reader = ChannelBlockingReader {
                token: token.clone(),
                first_chunk: b"alpha-one.xyz\n".to_vec(),
                first_obs_tx: Some(first_obs_tx),
                second_entered_tx: Some(second_entered_tx),
                second_release_rx,
                call_count: 0,
            };
            let worker_token = token.clone();
            let handle = std::thread::spawn(move || {
                crate::nrd::read_bounded_reader_cancellable(
                    reader,
                    NRD_MAX_RESPONSE_BYTES,
                    &worker_token,
                )
            });

            let first_obs = first_obs_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("1st read() must report entry");
            assert_eq!(
                first_obs,
                (1, true),
                "1st read() must observe blocking_read_entries() == 1 and active == true"
            );

            second_entered_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("2nd read() must enter blocking state");
            assert_eq!(
                token.blocking_read_entries(),
                2,
                "test thread must observe blocking_read_entries() == 2 while blocked in 2nd read()"
            );
            assert!(
                token.is_blocking_read_active(),
                "test thread must observe is_blocking_read_active() == true while blocked in 2nd read()"
            );

            (token, second_release_tx, handle)
        };

    // (a) 通常 EOF 完了: 2 回目 read() が Ok(0) で抜けた後に active が false へ戻る。
    {
        let (token, release_tx, handle) = spawn_blocked_on_second_read();
        release_tx
            .send(Ok(Vec::new()))
            .expect("release 2nd read with EOF");
        let (bytes, truncated) = handle
            .join()
            .expect("EOF reader thread must not panic")
            .expect("EOF completion must succeed");
        assert!(!truncated);
        assert_eq!(bytes, b"alpha-one.xyz\n");
        assert!(
            !token.is_blocking_read_active(),
            "is_blocking_read_active() must reset to false after normal EOF completion"
        );
        assert_eq!(token.blocking_read_entries(), 2);
    }

    // (b) I/O エラー終了: ブロック中 2 回目 read() が Err で抜けた後に active が false へ戻る。
    {
        let (token, release_tx, handle) = spawn_blocked_on_second_read();
        release_tx
            .send(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "simulated broken pipe",
            )))
            .expect("release 2nd read with I/O error");
        let err = handle
            .join()
            .expect("error reader thread must not panic")
            .expect_err("I/O error must propagate");
        assert!(
            err.contains("simulated broken pipe"),
            "unexpected I/O error message: {err}"
        );
        assert!(
            !token.is_blocking_read_active(),
            "is_blocking_read_active() must reset to false after I/O error exit"
        );
        assert_eq!(token.blocking_read_entries(), 2);
    }

    // (c) ブロック中 cancel() 後のアンブロック終了:
    //     ブロック中は active == true を維持し、アンブロック後に cancelled エラーで終了して
    //     active == false へ戻り、3 回目の read() へは進まない。
    {
        let (token, release_tx, handle) = spawn_blocked_on_second_read();
        token.cancel();
        assert!(token.is_cancelled());
        assert!(
            token.is_blocking_read_active(),
            "guard must remain active until the blocked 2nd read() actually returns"
        );
        assert_eq!(token.blocking_read_entries(), 2);

        release_tx
            .send(Ok(b"late-chunk.xyz\n".to_vec()))
            .expect("unblock cancelled 2nd read");
        let err = handle
            .join()
            .expect("cancelled reader thread must not panic")
            .expect_err("cancelled reader must fail with cancellation error");
        assert_eq!(err, "NRD feed download cancelled");
        assert!(
            !token.is_blocking_read_active(),
            "is_blocking_read_active() must reset to false after cancelled read unblocks"
        );
        assert_eq!(
            token.blocking_read_entries(),
            2,
            "cancelled reader must not enter a 3rd read()"
        );
    }
}

#[test]
fn rules_p3_16_load_rules_dir_separates_shipped_defaults_from_managed_rules() {
    let tmp = TestTempDir::new("ledr-rules-dir-split");
    let default_json = serde_json::json!({
        "allowlist_rules": [
            {
                "rule_id": "ALLOW-SHIPPED-1",
                "scope": "NetworkAllow",
                "exe_path_pattern": r"C:\Apps\browser.exe",
                "sha256": null,
                "signer_subject": "CN=Example",
                "root_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "allowed_target": null,
                "created_at_ms": 0,
                "created_by": "default_allowlist"
            },
            {
                "rule_id": "OPS-IN-DEFAULT-FILE-BLOCK",
                "scope": "NetworkBlock",
                "exe_path_pattern": r"C:\Apps\blocked.exe",
                "sha256": null,
                "signer_subject": null,
                "root_thumbprint": null,
                "allowed_target": null,
                "created_at_ms": 0,
                "created_by": "default_allowlist"
            },
            {
                "rule_id": "OPS-IN-DEFAULT-FILE-ALLOW",
                "scope": "NetworkAllow",
                "exe_path_pattern": r"C:\Apps\custom.exe",
                "sha256": null,
                "signer_subject": null,
                "root_thumbprint": null,
                "allowed_target": "api.example.com",
                "created_at_ms": 0,
                "created_by": "operator"
            }
        ],
        "early_pruner": {
            "prune_loopback_network": false,
            "ignored_dns_names": ["custom-ignored.local"]
        }
    });
    let ops_json = serde_json::json!({
        "allowlist_rules": [
            {
                "rule_id": "OPS-POLICY-BLOCK",
                "scope": "NetworkBlock",
                "exe_path_pattern": r"C:\Apps\tool.exe",
                "sha256": null,
                "signer_subject": null,
                "root_thumbprint": null,
                "allowed_target": "203.0.113.10",
                "created_at_ms": 0,
                "created_by": "default_allowlist"
            },
            {
                "rule_id": "OPS-POLICY-ALLOW",
                "scope": "NetworkAllow",
                "exe_path_pattern": r"C:\Apps\helper.exe",
                "sha256": null,
                "signer_subject": null,
                "root_thumbprint": null,
                "allowed_target": null,
                "created_at_ms": 0,
                "created_by": "default_allowlist"
            }
        ]
    });

    std::fs::write(
        tmp.path().join("default_allowlist.json"),
        default_json.to_string(),
    )
    .expect("write default_allowlist.json");
    std::fs::write(tmp.path().join("z_ops_policy.json"), ops_json.to_string())
        .expect("write z_ops_policy.json");
    // Also verify uppercase .JSON extension and UTF-8 BOM (common on Windows editors/PowerShell).
    let bom_upper_json = serde_json::json!({
        "allowlist_rules": [
            {
                "rule_id": "OPS-POLICY-BOM-UPPER",
                "scope": "NetworkBlock",
                "exe_path_pattern": r"C:\Apps\upper.exe",
                "sha256": null,
                "signer_subject": null,
                "root_thumbprint": null,
                "allowed_target": "198.51.100.7",
                "created_at_ms": 0,
                "created_by": "operator"
            }
        ]
    });
    std::fs::write(
        tmp.path().join("ZZ_OPS_UPPER.JSON"),
        format!("\u{feff}{}", bom_upper_json),
    )
    .expect("write ZZ_OPS_UPPER.JSON");

    let loaded = load_rules_dir(tmp.path()).expect("load_rules_dir");
    let default_ids: Vec<&str> = loaded
        .default_allowlists
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();
    let managed_ids: Vec<&str> = loaded
        .managed_rules
        .iter()
        .map(|r| r.rule_id.as_str())
        .collect();

    assert_eq!(default_ids, vec!["ALLOW-SHIPPED-1"]);
    assert_eq!(
        managed_ids,
        vec![
            "OPS-POLICY-BOM-UPPER",
            "OPS-IN-DEFAULT-FILE-BLOCK",
            "OPS-IN-DEFAULT-FILE-ALLOW",
            "OPS-POLICY-BLOCK",
            "OPS-POLICY-ALLOW",
        ]
    );

    // Secondary policy file omitting `early_pruner` must NOT clobber `default_allowlist.json`'s pruner.
    let loopback_ev = SensorEvent::NetworkConnect {
        pid: 1234,
        protocol: 6,
        dst_ip: "127.0.0.1".parse().unwrap(),
        dst_port: 8080,
        domain_hint: None,
        timestamp_ms: 1_732_000_000_000,
    };
    assert!(
        !loaded.pruner.should_prune(&EventContext::new(&loopback_ev)),
        "early_pruner.prune_loopback_network=false from default_allowlist.json must be preserved"
    );
}

#[test]
fn rules_p4_cancellable_sha256_respects_max_bytes_and_midstream_cancel() {
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::AtomicBool;

    let tmp_dir = TestTempDir::new("ledr-rules-p4-cancel");
    let file_path = tmp_dir.path().join("chunked.bin");
    let payload = vec![0x5Au8; 150_000];
    std::fs::write(&file_path, &payload).expect("write chunked payload");

    let cancel = AtomicBool::new(false);
    let hashed = compute_file_sha256_hex_cancellable(&file_path, 200_000, &cancel)
        .expect("hash within limit")
        .expect("some digest");
    assert_eq!(hashed, sha256_hex(&payload));

    let oversized = compute_file_sha256_hex_cancellable(&file_path, 149_999, &cancel)
        .expect("oversized returns Ok(None)");
    assert_eq!(oversized, None);

    // Mid-stream cancellation after reading first 64 KiB chunk.
    struct CancellingReader<'a> {
        inner: Cursor<Vec<u8>>,
        cancel: &'a AtomicBool,
        reads: usize,
    }
    impl Read for CancellingReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let n = self.inner.read(buf)?;
            if self.reads == 1 {
                self.cancel.store(true, Ordering::Release);
            }
            Ok(n)
        }
    }

    let mid_cancel = AtomicBool::new(false);
    let mut reader = CancellingReader {
        inner: Cursor::new(payload),
        cancel: &mid_cancel,
        reads: 0,
    };
    let err = compute_reader_sha256_hex_cancellable(&mut reader, 200_000, &mid_cancel)
        .expect_err("midstream cancel must abort");
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
}

/// `RULES-NRD-MEM-01`: Flat sorted arena `NrdCache` (`Box<[u8]>` + `Box<[u32]>`) holds
/// `NRD_MAX_ENTRIES` (`50,000`) domains in compact contiguous memory, supports sorted binary
/// search (exact + subdomain, case/trailing-dot normalization, bare TLD rejection), roundtrips
/// sorted and unsorted files cleanly, preserves duplicate/cap truncation semantics, and agrees
/// with legacy `assess_domain_risk`.
#[test]
fn rules_nrd_mem_01_flat_sorted_arena_50k_compact_lookup_roundtrip_and_edges() {
    let tmp = TestTempDir::new("ledr-rules-nrd-mem-01");

    // 1. Empty and single-entry boundary cases.
    let empty = NrdCache::new();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
    assert_eq!(empty.heap_bytes(), 0);
    assert!(!empty.contains("example.com"));
    assert!(!assess_domain_risk_with_cache("example.com", Some(&empty)).is_nrd);
    let empty_path = tmp.path().join("empty-nrd.txt");
    empty.save_to_file(&empty_path).expect("save empty cache");
    let loaded_empty = NrdCache::load_from_file(&empty_path, NRD_MAX_ENTRIES).expect("load empty");
    assert!(loaded_empty.is_empty());
    assert_eq!(loaded_empty.heap_bytes(), 0);

    let single = NrdCache::from_domains(["ONLY-ONE.XYZ."], Some(1_760_000_000_000), 10);
    assert_eq!(single.len(), 1);
    assert!(!single.is_empty());
    assert!(single.contains("only-one.xyz"));
    assert!(single.contains("sub.only-one.xyz"));
    assert!(!single.contains("aaa.xyz"));
    assert!(!single.contains("zzz.xyz"));
    assert!(!single.contains("xyz"));

    // 2. Duplicate handling before and at cap (both sorted and unsorted input orders).
    let dedup_sorted = NrdCache::from_domains(
        ["a.example", "b.example", "b.example", "c.example"],
        None,
        2,
    );
    assert_eq!(dedup_sorted.len(), 2);
    assert!(dedup_sorted.is_truncated());
    assert!(dedup_sorted.contains("a.example"));
    assert!(dedup_sorted.contains("b.example"));
    assert!(!dedup_sorted.contains("c.example"));

    let dedup_unsorted_no_trunc = NrdCache::from_domains(
        ["zeta.example", "alpha.example", "zeta.example", "alpha.example"],
        None,
        2,
    );
    assert_eq!(dedup_unsorted_no_trunc.len(), 2);
    assert!(!dedup_unsorted_no_trunc.is_truncated());
    let collected: Vec<&str> = dedup_unsorted_no_trunc.iter().collect();
    assert_eq!(collected, vec!["alpha.example", "zeta.example"]);

    // Unsorted cache file load must also produce a sorted binary-searchable arena.
    let unsorted_path = tmp.path().join("unsorted-nrd.txt");
    std::fs::write(
        &unsorted_path,
        "# LocalEDR NRD Cache\n# updated_at_ms=1760000000001\nzeta.top\nalpha.top\nmid.top\nalpha.top\n",
    )
    .expect("write unsorted file");
    let loaded_unsorted =
        NrdCache::load_from_file(&unsorted_path, NRD_MAX_ENTRIES).expect("load unsorted");
    assert_eq!(
        loaded_unsorted.iter().collect::<Vec<_>>(),
        vec!["alpha.top", "mid.top", "zeta.top"]
    );
    assert!(loaded_unsorted.contains("sub.mid.top"));
    assert_eq!(loaded_unsorted.updated_at_ms(), Some(1_760_000_000_001));

    // 3. Full 50,000-entry (`NRD_MAX_ENTRIES`) capacity, compact flat arena footprint,
    // binary-search correctness across reversed insertion order, and disk roundtrip.
    let domains_50k: Vec<String> = (0..NRD_MAX_ENTRIES)
        .rev()
        .map(|i| format!("nrd-{i:05}.fresh-drop.xyz"))
        .collect();
    let cache = NrdCache::from_domains(
        domains_50k.iter(),
        Some(1_760_000_123_456),
        NRD_MAX_ENTRIES,
    );
    assert_eq!(cache.len(), NRD_MAX_ENTRIES);
    assert!(!cache.is_truncated());
    let expected_data_bytes: usize = domains_50k.iter().map(String::len).sum();
    let expected_heap_bytes =
        expected_data_bytes + (NRD_MAX_ENTRIES + 1) * std::mem::size_of::<u32>();
    assert_eq!(cache.heap_bytes(), expected_heap_bytes);
    assert!(
        cache.heap_bytes() < 2 * 1024 * 1024,
        "50,000-entry flat NRD arena must remain under 2 MiB (got {} bytes)",
        cache.heap_bytes()
    );

    // Verify sorted invariant across all 50,000 entries.
    let mut prev: Option<&str> = None;
    for entry in cache.iter() {
        if let Some(p) = prev {
            assert!(p < entry, "NrdCache arena must be strictly sorted: {p} >= {entry}");
        }
        prev = Some(entry);
    }

    // Spot-check first, middle, last, subdomain, and non-matches.
    assert!(cache.contains("nrd-00000.fresh-drop.xyz"));
    assert!(cache.contains("SUB.NRD-25000.FRESH-DROP.XYZ."));
    assert!(cache.contains("nrd-49999.fresh-drop.xyz"));
    assert!(!cache.contains("nrd-50000.fresh-drop.xyz"));
    assert!(!cache.contains("fresh-drop.xyz"));
    assert!(!cache.contains("xyz"));

    // Disk save + sorted load roundtrip preserves count, timestamp, and exact arena size.
    let cache_path = tmp.path().join("nrd-50k.txt");
    cache.save_to_file(&cache_path).expect("save 50k NRD cache");
    let reloaded =
        NrdCache::load_from_file(&cache_path, NRD_MAX_ENTRIES).expect("reload 50k NRD cache");
    assert_eq!(reloaded.len(), NRD_MAX_ENTRIES);
    assert_eq!(reloaded.updated_at_ms(), Some(1_760_000_123_456));
    assert_eq!(reloaded.heap_bytes(), expected_heap_bytes);
    assert!(reloaded.contains("deep.sub.nrd-12345.fresh-drop.xyz"));
    assert!(!reloaded.contains("google.com"));

    // Direct cache risk assessment matches legacy HashSet path.
    let mut sample_set = std::collections::HashSet::new();
    sample_set.insert("nrd-12345.fresh-drop.xyz".to_string());
    assert_eq!(
        assess_domain_risk_with_cache("login.nrd-12345.fresh-drop.xyz", Some(&reloaded)),
        assess_domain_risk("login.nrd-12345.fresh-drop.xyz", Some(&sample_set))
    );
    let homo = assess_domain_risk_with_cache("paypa1.com", Some(&reloaded));
    assert!(!homo.is_nrd);
    assert!(homo.is_homograph);
    assert_eq!(homo.matched_brand.as_deref(), Some("paypal"));

    // 4. Sorted prefix hitting `max_entries` followed by out-of-order entries and duplicates
    // (mirrors two-feed `nrd7.txt` + `nrd14-8.txt` refresh) plus power-of-2 bucket transition,
    // `max_entries = 0` clamping, and invalid UTF-8 bytes in feed.
    let cap_zero = NrdCache::from_domains(["first.example", "second.example"], None, 0);
    assert_eq!(cap_zero.len(), 1);
    assert!(cap_zero.is_truncated());
    assert!(cap_zero.contains("first.example"));

    // Power-of-2 sorted prefix (`8` entries) transitioning to unsorted on the 9th entry.
    let mut pow2_inputs: Vec<String> = (1..=8).map(|i| format!("d-{i:02}.example")).collect();
    pow2_inputs.push("d-00.example".to_string());
    pow2_inputs.push("d-04.example".to_string()); // duplicate after unsorted transition
    let pow2_cache = NrdCache::from_domains(pow2_inputs.iter(), None, 16);
    assert_eq!(pow2_cache.len(), 9);
    assert!(!pow2_cache.is_truncated());
    assert!(pow2_cache.contains("d-00.example"));
    assert!(pow2_cache.contains("d-08.example"));

    // Two sorted feeds where feed1 fills cap and feed2 has duplicates + smaller domains + bad UTF-8.
    let feed1_path = tmp.path().join("sorted-feed1.txt");
    let feed2_path = tmp.path().join("sorted-feed2.txt");
    std::fs::write(&feed1_path, "b-one.xyz\nc-two.xyz\nd-three.xyz\n").expect("write feed1");
    std::fs::write(
        &feed2_path,
        b"b-one.xyz\n\xff\xfe-bad-utf8.xyz\na-zero.xyz\n",
    )
    .expect("write feed2");
    let to_url = |p: &Path| format!("file:///{}", p.to_string_lossy().replace('\\', "/"));
    let (multi_cache, multi_stats) = refresh_nrd_cache(
        &[to_url(&feed1_path), to_url(&feed2_path)],
        3,
        NRD_MAX_RESPONSE_BYTES,
        1_760_000_200_000,
    )
    .expect("multi-feed capped refresh");
    assert_eq!(multi_stats.feeds_succeeded, 2);
    assert_eq!(multi_cache.len(), 3);
    assert!(multi_stats.truncated);
    assert_eq!(
        multi_cache.iter().collect::<Vec<_>>(),
        vec!["b-one.xyz", "c-two.xyz", "d-three.xyz"]
    );
}

#[test]
fn rules_p4_01_local_cert_chain_flags_offline_and_verifies_cmd_exe() {
    // Verify Windows SDK (`wincrypt.h`) bitmask values for offline-only chain building.
    const EXPECTED_CACHE_END_CERT: u32 = 0x0000_0001;
    const EXPECTED_CACHE_ONLY_URL_RETRIEVAL: u32 = 0x0000_0004;
    const EXPECTED_DISABLE_AUTH_ROOT_AUTO_UPDATE: u32 = 0x0000_0100;

    let flags = LOCAL_CERT_CHAIN_FLAGS;
    assert_ne!(flags & EXPECTED_CACHE_END_CERT, 0);
    assert_ne!(flags & EXPECTED_CACHE_ONLY_URL_RETRIEVAL, 0);
    assert_ne!(flags & EXPECTED_DISABLE_AUTH_ROOT_AUTO_UPDATE, 0);
    assert_eq!(
        flags,
        EXPECTED_CACHE_END_CERT
            | EXPECTED_CACHE_ONLY_URL_RETRIEVAL
            | EXPECTED_DISABLE_AUTH_ROOT_AUTO_UPDATE
    );

    let cmd_exe = Path::new(r"C:\Windows\System32\cmd.exe");
    assert!(
        cmd_exe.is_file(),
        "expected Windows system binary {} to exist",
        cmd_exe.display()
    );
    let auth = inspect_authenticode(cmd_exe)
        .expect("cmd.exe should verify locally with offline cert chain flags");
    assert!(
        signer_subject_matches(&auth.signer_subject, "CN=Microsoft Windows"),
        "unexpected signer_subject for cmd.exe: {}",
        auth.signer_subject
    );
    assert_eq!(
        auth.root_thumbprint,
        "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
        "expected Microsoft Root Certificate Authority 2010 thumbprint for cmd.exe, got {:?}",
        auth.root_thumbprint
    );

    let allowlist_json = include_str!("../../../rules/default_allowlist.json");
    let cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse default allowlist");
    let sys32_rules: Vec<_> = cfg
        .allowlist_rules
        .iter()
        .filter(|rule| rule.rule_id == "ALLOW-OS-WIN-SYS32")
        .cloned()
        .collect();
    assert_eq!(
        sys32_rules.len(),
        1,
        "expected ALLOW-OS-WIN-SYS32 in default_allowlist.json"
    );
    let identity = BinaryIdentity::from_path(cmd_exe);
    assert!(
        is_allowed_by_rules(
            &identity,
            None,
            ledr_proto::RuleScope::ProcessAllow,
            &sys32_rules
        ),
        "cmd.exe should match ALLOW-OS-WIN-SYS32 from default_allowlist.json"
    );
}
