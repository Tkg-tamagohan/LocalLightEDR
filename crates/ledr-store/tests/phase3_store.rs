//! Phase 3 store tests: firewall rule (`NetworkAllow` / `NetworkBlock`) CRUD, startup load
//! ordering (deny-before-allow), composite index `EXPLAIN QUERY PLAN`, and local DNS history
//! first-seen / NRD persistence (`STORE-P3-01`..`STORE-P3-04`).

use std::net::{IpAddr, Ipv4Addr};

use ledr_proto::{AllowlistRuleRecord, ProcessIdentity, RuleScope, SensorEvent};
use ledr_store::LedrStore;
use tempfile::TempDir;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

#[test]
fn store_p3_01_firewall_rules_crud_and_persistence_across_reopen() {
    let dir = TempDir::new().expect("temp dir");
    let db_path = dir.path().join("p3_01_fw_rules.db");

    let block_rule = AllowlistRuleRecord {
        rule_id: "FW-BLOCK-001".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: r"C:\Users\alice\Downloads\dropper.exe".to_string(),
        sha256: Some("1111111111111111111111111111111111111111111111111111111111111111".to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: 10_000,
        created_by: "user_quarantine".to_string(),
    };
    let allow_signed = AllowlistRuleRecord {
        rule_id: "FW-ALLOW-001".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: r"C:\Program Files\DevTool\tool.exe".to_string(),
        sha256: None,
        signer_subject: Some("CN=DevTool Corp".to_string()),
        root_thumbprint: Some("AABBCCDDEEFF00112233445566778899AABBCCDD".to_string()),
        allowed_target: Some("93.184.216.34".to_string()),
        created_at_ms: 20_000,
        created_by: "user_triage".to_string(),
    };
    let allow_unsigned = AllowlistRuleRecord {
        rule_id: "FW-ALLOW-002".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: r"C:\Tools\cli.exe".to_string(),
        sha256: Some("2222222222222222222222222222222222222222222222222222222222222222".to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("api.example.com".to_string()),
        created_at_ms: 30_000,
        created_by: "user_policy".to_string(),
    };

    {
        let store = LedrStore::open(&db_path).expect("open store");
        for rule in [&block_rule, &allow_signed, &allow_unsigned] {
            store.upsert_rule(rule).expect("upsert firewall rule");
        }
        store.checkpoint_truncate().expect("checkpoint");
    }

    // Reopen fresh handle to verify startup durability.
    let reopened = LedrStore::open(&db_path).expect("reopen store");
    assert_eq!(
        reopened.get_rule("FW-BLOCK-001").expect("get block"),
        Some(block_rule.clone())
    );
    assert_eq!(
        reopened.get_rule("FW-ALLOW-001").expect("get allow signed"),
        Some(allow_signed.clone())
    );

    // Update target on existing rule via upsert.
    let updated_allow = AllowlistRuleRecord {
        allowed_target: Some("203.0.113.99".to_string()),
        created_at_ms: 40_000,
        ..allow_signed
    };
    reopened
        .upsert_rule(&updated_allow)
        .expect("update firewall rule");
    assert_eq!(
        reopened.get_rule("FW-ALLOW-001").expect("get updated"),
        Some(updated_allow.clone())
    );

    // Delete removes only the specified rule.
    assert!(reopened.delete_rule("FW-ALLOW-002").expect("delete allow2"));
    assert!(!reopened.delete_rule("FW-ALLOW-002").expect("second delete false"));
    assert_eq!(
        reopened.list_network_rules().expect("remaining network rules"),
        vec![block_rule, updated_allow]
    );
}

#[test]
fn store_p3_02_list_network_rules_prioritizes_block_and_excludes_non_network_scopes() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let mk = |id: &str, scope: RuleScope, ts: i64| AllowlistRuleRecord {
        rule_id: id.to_string(),
        scope,
        exe_path_pattern: format!(r"C:\Apps\{id}.exe"),
        sha256: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: ts,
        created_by: "test".to_string(),
    };

    for rule in [
        mk("canary-1", RuleScope::FileCanaryAllow, 90_000),
        mk("proc-1", RuleScope::ProcessAllow, 80_000),
        mk("allow-new", RuleScope::NetworkAllow, 70_000),
        mk("allow-old", RuleScope::NetworkAllow, 50_000),
        mk("block-old", RuleScope::NetworkBlock, 10_000),
        mk("block-new", RuleScope::NetworkBlock, 60_000),
        mk("block-tie-b", RuleScope::NetworkBlock, 60_000),
        mk("block-tie-a", RuleScope::NetworkBlock, 60_000),
    ] {
        store.upsert_rule(&rule).expect("seed rule");
    }

    let net_rules = store.list_network_rules().expect("list_network_rules");
    let ids: Vec<&str> = net_rules.iter().map(|r| r.rule_id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "block-new",
            "block-tie-a",
            "block-tie-b",
            "block-old",
            "allow-new",
            "allow-old",
        ],
        "NetworkBlock must precede NetworkAllow, ordered by created_at_ms DESC, rule_id ASC"
    );

    // Duplicate scopes in list_rules_by_scopes are deduplicated cleanly.
    let dedup = store
        .list_rules_by_scopes(&[RuleScope::NetworkAllow, RuleScope::NetworkAllow])
        .expect("list_rules_by_scopes");
    assert_eq!(dedup.len(), 2);
    assert!(store
        .list_rules_by_scopes(&[])
        .expect("empty scopes")
        .is_empty());
}

#[test]
fn store_p3_03_rules_scope_query_uses_composite_index_without_temp_btree() {
    let dir = TempDir::new().expect("temp dir");
    let db_path = dir.path().join("p3_03_plan.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let plan = store
        .explain_rules_scope_plan()
        .expect("explain_rules_scope_plan");
    let joined = plan.join(" | ");
    assert!(
        joined.contains("idx_rules_scope_created"),
        "expected scope query to use idx_rules_scope_created, got: {joined}"
    );
    assert!(
        !joined.to_ascii_uppercase().contains("TEMP B-TREE"),
        "expected no TEMP B-TREE sort for scope-ordered rules query, got: {joined}"
    );
}

#[test]
fn store_p3_04_has_seen_dns_domain_and_nrd_flag_roundtrip() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let t0 = 1_760_000_000_000i64;
    let ident = ProcessIdentity::new(6001, unix_ms_to_filetime(t0));

    assert!(!store
        .has_seen_dns_domain("fresh-nrd.example")
        .expect("unseen domain"));
    assert!(!store.has_seen_dns_domain("   ").expect("blank domain"));

    store
        .ingest_event(
            &SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: r"C:\Tools\probe.exe".to_string(),
                command_line: "probe.exe".to_string(),
                user_sid: None,
            },
            None,
            false,
            "",
        )
        .expect("ingest start");
    store
        .ingest_event(
            &SensorEvent::DnsQuery {
                pid: ident.pid,
                query_name: "Fresh-NRD.Example".to_string(),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 45))],
                timestamp_ms: t0 + 100,
            },
            Some(&ident.instance_id()),
            true,
            "OBSERVED",
        )
        .expect("ingest dns");
    store.flush_batch().expect("flush batch");

    assert!(store
        .has_seen_dns_domain("fresh-nrd.example.")
        .expect("seen domain case-insensitive + trailing dot"));
    assert!(!store
        .has_seen_dns_domain("other.example")
        .expect("unseen sibling"));

    // Stored trailing-dot FQDN (as sometimes emitted by Windows DNS-Client ETW) must also match.
    store
        .ingest_event(
            &SensorEvent::DnsQuery {
                pid: ident.pid,
                query_name: "Trailing-Dot.Example.".to_string(),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))],
                timestamp_ms: t0 + 150,
            },
            Some(&ident.instance_id()),
            false,
            "OBSERVED",
        )
        .expect("ingest trailing-dot dns");
    store.flush_batch().expect("flush trailing-dot batch");
    assert!(store
        .has_seen_dns_domain("trailing-dot.example")
        .expect("stored trailing-dot domain matches normalized lookup"));

    let dns_plan = store
        .explain_dns_name_nocase_plan()
        .expect("explain_dns_name_nocase_plan");
    let dns_plan_joined = dns_plan.join(" | ");
    assert!(
        dns_plan_joined.contains("idx_dns_name_nocase"),
        "expected has_seen_dns_domain to use idx_dns_name_nocase, got: {dns_plan_joined}"
    );

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query fr");
    assert_eq!(snap.dns_queries.len(), 2);
    assert!(snap
        .dns_queries
        .iter()
        .any(|d| d.query_name == "Fresh-NRD.Example" && d.is_nrd));
}
