use std::net::{IpAddr, Ipv4Addr};

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, CanaryCategory,
    FileCanaryEventRecord, ProcessIdentity, ProcessRecord, RuleScope, SensorEvent,
};
use ledr_store::LedrStore;
use tempfile::TempDir;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DAY_MS: i64 = 86_400_000;

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

fn make_process_record(
    pid: u32,
    created_ms: i64,
    parent_instance_id: Option<&str>,
    ppid: u32,
    exe_path: &str,
    exited_at_ms: Option<i64>,
) -> ProcessRecord {
    let identity = ProcessIdentity::new(pid, unix_ms_to_filetime(created_ms));
    ProcessRecord {
        process_instance_id: identity.instance_id(),
        pid,
        parent_instance_id: parent_instance_id.map(str::to_owned),
        ppid,
        exe_path: exe_path.to_string(),
        command_line: Some(exe_path.to_string()),
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: Some("S-1-5-21-1000".to_string()),
        origin_url: None,
        created_at_ms: created_ms,
        exited_at_ms,
    }
}

fn make_alert(
    alert_id: &str,
    timestamp_ms: i64,
    process_instance_id: Option<&str>,
    status: AlertStatus,
    resolved_at_ms: Option<i64>,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms,
        severity: AlertSeverity::Critical,
        source_layer: "layer1".to_string(),
        rule_id: "canary_file_access".to_string(),
        title: format!("Alert {alert_id}"),
        process_instance_id: process_instance_id.map(str::to_owned),
        process_suspended: status.is_unresolved(),
        status,
        context_json: r#"{"category":"honeypot"}"#.to_string(),
        resolved_at_ms,
    }
}

#[test]
fn store_p2_01_all_canary_categories_immediate_flush_and_filter() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("p2_01_canary.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let base_ms = 1_760_000_000_000i64;
    let proc_a = make_process_record(
        1001,
        base_ms,
        Some("4:1"),
        4,
        r"C:\Temp\stealer_a.exe",
        None,
    );
    let proc_b = make_process_record(
        1002,
        base_ms + 10,
        Some("4:1"),
        4,
        r"C:\Temp\stealer_b.exe",
        None,
    );
    store.upsert_process_record(&proc_a).expect("upsert proc_a");
    store.upsert_process_record(&proc_b).expect("upsert proc_b");

    let categories = [
        (
            CanaryCategory::CookieDb,
            r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
            0x0012_0089u32,
            "SUSPEND",
        ),
        (
            CanaryCategory::LoginData,
            r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            0x0012_0089u32,
            "SUSPEND",
        ),
        (
            CanaryCategory::SshKey,
            r"C:\Users\dev\.ssh\id_ed25519",
            0x0000_0001u32,
            "SUSPEND",
        ),
        (
            CanaryCategory::CloudCredential,
            r"C:\Users\dev\.aws\credentials",
            0x0000_0001u32,
            "SUSPEND",
        ),
        (
            CanaryCategory::EnvFile,
            r"E:\src\app\.env.production",
            0x0000_0001u32,
            "SUSPEND",
        ),
        (
            CanaryCategory::Honeypot,
            r"C:\Users\dev\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
            0x0000_0002u32,
            "SUSPEND_TREE",
        ),
        (
            CanaryCategory::AutorunRegistry,
            r"\REGISTRY\USER\S-1-5-21-1000\Software\Microsoft\Windows\CurrentVersion\Run\Evil",
            0x0002_0006u32,
            "ALERT",
        ),
    ];

    // Part A: Persist all 7 categories immediately via record_file_canary_event (proc_a).
    // Include an explicit timestamp tie on the last two rows to verify id DESC tie-breaking.
    let mut prev_rowid = 0i64;
    let mut direct_ids = Vec::new();
    for (idx, (category, path, access_mask, action)) in categories.iter().enumerate() {
        let ts = if idx >= categories.len() - 2 {
            base_ms + 1_000
        } else {
            base_ms + 100 + i64::try_from(idx).unwrap()
        };
        let rec = FileCanaryEventRecord {
            id: None,
            timestamp_ms: ts,
            process_instance_id: proc_a.process_instance_id.clone(),
            target_path: (*path).to_string(),
            category: *category,
            access_mask: *access_mask,
            action_taken: (*action).to_string(),
        };
        let rowid = store
            .record_file_canary_event(&rec)
            .expect("record_file_canary_event");
        assert!(rowid > prev_rowid, "rowid must increase monotonically");
        prev_rowid = rowid;
        direct_ids.push(rowid);
    }

    // Part B: Persist all 7 categories via ingest_event (proc_b), confirming immediate flush of
    // both a prior buffered telemetry event and the CanaryFileAccess event.
    for (idx, (category, path, access_mask, action)) in categories.iter().enumerate() {
        let pre_dns = SensorEvent::DnsQuery {
            pid: proc_b.pid,
            query_name: format!("pre-canary-{idx}.example.test"),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: base_ms + 2_000 + i64::try_from(idx).unwrap(),
        };
        assert!(
            !store
                .ingest_event(&pre_dns, Some(&proc_b.process_instance_id), false, "")
                .expect("buffer pre-canary dns"),
            "DnsQuery below batch threshold must stay buffered"
        );
        assert_eq!(store.buffered_len(), 1);

        let canary_ev = SensorEvent::CanaryFileAccess {
            pid: proc_b.pid,
            target_path: format!("{path}.copy"),
            category: *category,
            access_mask: *access_mask,
            is_write_or_delete: *category == CanaryCategory::Honeypot,
            timestamp_ms: base_ms + 2_100 + i64::try_from(idx).unwrap(),
        };
        let flushed = store
            .ingest_event(&canary_ev, Some(&proc_b.process_instance_id), false, action)
            .expect("ingest CanaryFileAccess");
        assert!(flushed, "CanaryFileAccess must trigger immediate flush");
        assert_eq!(store.buffered_len(), 0);
    }

    // Part C: Query & filter via list_file_canary_events (limit=0, full list, limit, filters).
    assert!(store
        .list_file_canary_events(None, None, 0)
        .expect("limit 0 returns empty")
        .is_empty());

    let all = store
        .list_file_canary_events(None, None, 100)
        .expect("list all canary events");
    assert_eq!(all.len(), 14);
    for pair in all.windows(2) {
        let newer = &pair[0];
        let older = &pair[1];
        assert!(
            (newer.timestamp_ms, newer.id.unwrap()) > (older.timestamp_ms, older.id.unwrap()),
            "expected ORDER BY timestamp_ms DESC, id DESC: {newer:?} vs {older:?}"
        );
    }

    let limited = store
        .list_file_canary_events(None, None, 4)
        .expect("bounded limit");
    assert_eq!(limited.len(), 4);
    assert_eq!(limited, all[..4]);

    // Filter by each of the 7 CanaryCategory variants.
    for (category, path, access_mask, action) in categories {
        let by_cat = store
            .list_file_canary_events(Some(category), None, 50)
            .expect("filter by category");
        assert_eq!(by_cat.len(), 2, "expected 2 rows for {category:?}");
        assert_eq!(by_cat[0].process_instance_id, proc_b.process_instance_id);
        assert_eq!(by_cat[1].process_instance_id, proc_a.process_instance_id);
        assert_eq!(by_cat[1].target_path, path);
        assert_eq!(by_cat[1].access_mask, access_mask);
        assert_eq!(by_cat[1].action_taken, action);

        let by_cat_proc_a = store
            .list_file_canary_events(Some(category), Some(&proc_a.process_instance_id), 50)
            .expect("filter by category and proc_a");
        assert_eq!(by_cat_proc_a.len(), 1);
        assert_eq!(by_cat_proc_a[0].category, category);
        assert_eq!(
            by_cat_proc_a[0].process_instance_id,
            proc_a.process_instance_id
        );
    }

    // Filter by process_instance_id only, checking tie-break id DESC on the last two proc_a rows.
    let by_proc_a = store
        .list_file_canary_events(None, Some(&proc_a.process_instance_id), 50)
        .expect("filter by proc_a");
    assert_eq!(by_proc_a.len(), 7);
    assert_eq!(by_proc_a[0].id, Some(direct_ids[6]));
    assert_eq!(by_proc_a[0].category, CanaryCategory::AutorunRegistry);
    assert_eq!(by_proc_a[1].id, Some(direct_ids[5]));
    assert_eq!(by_proc_a[1].category, CanaryCategory::Honeypot);

    assert!(store
        .list_file_canary_events(Some(CanaryCategory::CookieDb), Some("9999:0"), 50)
        .expect("nonexistent process filter returns empty")
        .is_empty());
}

#[test]
fn store_p2_02_all_alert_statuses_get_and_list_unresolved() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("p2_02_alerts.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let alerts = vec![
        make_alert(
            "alrt-pending-old",
            1_000,
            Some("100:1"),
            AlertStatus::Pending,
            None,
        ),
        make_alert(
            "alrt-approved-once",
            2_000,
            Some("101:1"),
            AlertStatus::ApprovedOnce,
            Some(2_500),
        ),
        make_alert(
            "alrt-expired-susp",
            3_000,
            Some("102:1"),
            AlertStatus::ExpiredSuspended,
            None,
        ),
        make_alert(
            "alrt-approved-rule",
            4_000,
            Some("103:1"),
            AlertStatus::ApprovedRule,
            Some(4_500),
        ),
        make_alert(
            "alrt-terminated",
            5_000,
            Some("104:1"),
            AlertStatus::TerminatedBlocked,
            Some(5_500),
        ),
        make_alert(
            "alrt-dismissed",
            6_000,
            Some("105:1"),
            AlertStatus::Dismissed,
            Some(6_500),
        ),
        make_alert(
            "alrt-pending-new",
            7_000,
            Some("106:1"),
            AlertStatus::Pending,
            None,
        ),
    ];

    for alert in &alerts {
        store.record_alert(alert).expect("record alert");
    }

    // Verify get_alert for all 6 AlertStatus variants and missing ID.
    assert_eq!(
        store.get_alert("missing-alert").expect("query missing"),
        None
    );
    for expected in &alerts {
        let fetched = store
            .get_alert(&expected.alert_id)
            .expect("get_alert")
            .expect("alert exists");
        assert_eq!(&fetched, expected);
    }

    // Verify list_unresolved_alerts returns only Pending & ExpiredSuspended ordered DESC.
    assert!(store
        .list_unresolved_alerts(0)
        .expect("limit 0 returns empty")
        .is_empty());

    let unresolved = store
        .list_unresolved_alerts(20)
        .expect("list unresolved alerts");
    let unresolved_ids: Vec<&str> = unresolved.iter().map(|a| a.alert_id.as_str()).collect();
    assert_eq!(
        unresolved_ids,
        vec!["alrt-pending-new", "alrt-expired-susp", "alrt-pending-old"]
    );

    let bounded = store
        .list_unresolved_alerts(2)
        .expect("list unresolved alerts bounded by limit");
    let bounded_ids: Vec<&str> = bounded.iter().map(|a| a.alert_id.as_str()).collect();
    assert_eq!(bounded_ids, vec!["alrt-pending-new", "alrt-expired-susp"]);

    // Resolving an unresolved alert removes it from list_unresolved_alerts and updates get_alert.
    assert!(store
        .update_alert_status("alrt-expired-susp", AlertStatus::ApprovedRule, Some(8_000))
        .expect("resolve expired suspended alert"));
    let updated = store
        .get_alert("alrt-expired-susp")
        .expect("get updated alert")
        .expect("updated alert exists");
    assert_eq!(updated.status, AlertStatus::ApprovedRule);
    assert_eq!(updated.resolved_at_ms, Some(8_000));

    let remaining_ids: Vec<String> = store
        .list_unresolved_alerts(20)
        .expect("list remaining unresolved")
        .into_iter()
        .map(|a| a.alert_id)
        .collect();
    assert_eq!(remaining_ids, vec!["alrt-pending-new", "alrt-pending-old"]);
}

#[test]
fn store_p2_03_expire_pending_alerts_atomic_cutoff() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("p2_03_expire.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let cutoff_ms = 20_000i64;
    let seed = [
        make_alert(
            "pending-overdue",
            10_000,
            Some("200:1"),
            AlertStatus::Pending,
            None,
        ),
        make_alert(
            "pending-exact-cutoff",
            cutoff_ms,
            Some("201:1"),
            AlertStatus::Pending,
            None,
        ),
        make_alert(
            "pending-not-overdue",
            cutoff_ms + 1,
            Some("202:1"),
            AlertStatus::Pending,
            None,
        ),
        make_alert(
            "already-expired-suspended",
            5_000,
            Some("203:1"),
            AlertStatus::ExpiredSuspended,
            None,
        ),
        make_alert(
            "resolved-approved-once",
            5_000,
            Some("204:1"),
            AlertStatus::ApprovedOnce,
            Some(6_000),
        ),
        make_alert(
            "resolved-approved-rule",
            6_000,
            Some("205:1"),
            AlertStatus::ApprovedRule,
            Some(7_000),
        ),
        make_alert(
            "resolved-terminated",
            7_000,
            Some("206:1"),
            AlertStatus::TerminatedBlocked,
            Some(8_000),
        ),
        make_alert(
            "resolved-dismissed",
            8_000,
            Some("207:1"),
            AlertStatus::Dismissed,
            Some(9_000),
        ),
    ];
    for alert in &seed {
        store.record_alert(alert).expect("seed alert");
    }

    let updated = store
        .expire_pending_alerts(cutoff_ms)
        .expect("expire pending alerts");
    assert_eq!(updated, 2);

    // Overdue and exact-cutoff PENDING alerts transition to EXPIRED_SUSPENDED with resolved_at_ms=None.
    for id in ["pending-overdue", "pending-exact-cutoff"] {
        let row = store
            .get_alert(id)
            .expect("get expired alert")
            .expect("alert exists");
        assert_eq!(row.status, AlertStatus::ExpiredSuspended);
        assert_eq!(row.resolved_at_ms, None);
    }

    // Non-overdue PENDING alert remains PENDING.
    let fresh = store
        .get_alert("pending-not-overdue")
        .expect("get fresh alert")
        .expect("fresh exists");
    assert_eq!(fresh.status, AlertStatus::Pending);
    assert_eq!(fresh.resolved_at_ms, None);

    // Already EXPIRED_SUSPENDED and all resolved alerts remain completely unchanged.
    for original in &seed[3..] {
        let current = store
            .get_alert(&original.alert_id)
            .expect("get unchanged alert")
            .expect("unchanged exists");
        assert_eq!(&current, original);
    }

    // Re-running with the same cutoff is idempotent (0 additional updates).
    assert_eq!(
        store
            .expire_pending_alerts(cutoff_ms)
            .expect("idempotent second expire"),
        0
    );

    let unresolved_ids: Vec<String> = store
        .list_unresolved_alerts(20)
        .expect("list unresolved after expire")
        .into_iter()
        .map(|a| a.alert_id)
        .collect();
    assert_eq!(
        unresolved_ids,
        vec![
            "pending-not-overdue",
            "pending-exact-cutoff",
            "pending-overdue",
            "already-expired-suspended",
        ]
    );
}

#[test]
fn store_p2_04_allowlist_rules_two_tier_crud() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("p2_04_rules.db");
    let store = LedrStore::open(&db_path).expect("open store");

    assert_eq!(store.get_rule("rule-signed").expect("missing rule"), None);

    // Tier 1 (L-04): Signed binary rule (exe_path_pattern + signer_subject + root_thumbprint).
    let signed_rule = AllowlistRuleRecord {
        rule_id: "rule-signed".to_string(),
        scope: RuleScope::FileCanaryAllow,
        exe_path_pattern: r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string(),
        sha256: None,
        signer_subject: Some("Google LLC".to_string()),
        root_thumbprint: Some("AABBCCDDEEFF00112233445566778899AABBCCDD".to_string()),
        allowed_target: Some(r"*\Google\Chrome\User Data\*\Cookies".to_string()),
        created_at_ms: 1_000,
        created_by: "user".to_string(),
    };

    // Tier 2 (L-04): Unsigned binary rule (exe_path_pattern + sha256 required, no signer).
    let unsigned_rule = AllowlistRuleRecord {
        rule_id: "rule-unsigned".to_string(),
        scope: RuleScope::FileCanaryAllow,
        exe_path_pattern: r"C:\Tools\local_backup.exe".to_string(),
        sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: 2_000,
        created_by: "user".to_string(),
    };

    let net_block_rule = AllowlistRuleRecord {
        rule_id: "rule-net-block".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: r"C:\Users\*\Downloads\*.exe".to_string(),
        sha256: Some("deadbeef".to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("203.0.113.10".to_string()),
        created_at_ms: 3_000,
        created_by: "auto_quarantine".to_string(),
    };

    for rule in [&signed_rule, &unsigned_rule, &net_block_rule] {
        store.upsert_rule(rule).expect("upsert rule");
    }

    assert_eq!(
        store.get_rule("rule-signed").expect("get signed rule"),
        Some(signed_rule.clone())
    );
    assert_eq!(
        store.get_rule("rule-unsigned").expect("get unsigned rule"),
        Some(unsigned_rule.clone())
    );
    assert_eq!(
        store
            .get_rule("rule-net-block")
            .expect("get net block rule"),
        Some(net_block_rule.clone())
    );

    // Upsert update on existing rule_id replaces fields cleanly.
    let updated_unsigned = AllowlistRuleRecord {
        sha256: Some(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        ),
        allowed_target: Some(r"E:\src\*\.env*".to_string()),
        created_at_ms: 4_000,
        created_by: "admin".to_string(),
        ..unsigned_rule
    };
    store
        .upsert_rule(&updated_unsigned)
        .expect("update unsigned rule");
    assert_eq!(
        store.get_rule("rule-unsigned").expect("get updated rule"),
        Some(updated_unsigned.clone())
    );

    // Verify list_rules ordering (created_at_ms DESC, rule_id ASC) and scope filtering.
    let all_rules = store.list_rules(None).expect("list all rules");
    assert_eq!(
        all_rules,
        vec![
            updated_unsigned.clone(),
            net_block_rule.clone(),
            signed_rule.clone()
        ]
    );

    let canary_rules = store
        .list_rules(Some(RuleScope::FileCanaryAllow))
        .expect("list canary rules");
    assert_eq!(canary_rules, vec![updated_unsigned.clone(), signed_rule]);

    let block_rules = store
        .list_rules(Some(RuleScope::NetworkBlock))
        .expect("list network block rules");
    assert_eq!(block_rules, vec![net_block_rule]);

    assert!(store
        .list_rules(Some(RuleScope::ProcessAllow))
        .expect("list empty scope")
        .is_empty());

    // Delete & verify removal.
    assert!(store
        .delete_rule("rule-signed")
        .expect("delete signed rule"));
    assert!(!store
        .delete_rule("rule-signed")
        .expect("second delete returns false"));
    assert_eq!(
        store.get_rule("rule-signed").expect("deleted rule is None"),
        None
    );
    assert_eq!(
        store
            .list_rules(Some(RuleScope::FileCanaryAllow))
            .expect("remaining canary rules"),
        vec![updated_unsigned]
    );
}

#[test]
fn store_p2_05_ttl_purge_preserves_expired_suspended_lineage() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("p2_05_ttl_expired_suspended.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let now_ms = 1_760_000_000_000i64;
    let created_20d = now_ms - 20 * DAY_MS;
    let exited_18d = now_ms - 18 * DAY_MS;
    let exited_17d = now_ms - 17 * DAY_MS;
    let exited_16d = now_ms - 16 * DAY_MS;

    // 3-generation expired branch protected by an EXPIRED_SUSPENDED alert on the leaf.
    let gp = make_process_record(
        500,
        created_20d,
        None,
        4,
        r"C:\Windows\explorer.exe",
        Some(exited_18d),
    );
    let parent = make_process_record(
        501,
        created_20d + 100,
        Some(&gp.process_instance_id),
        500,
        r"C:\Windows\System32\cmd.exe",
        Some(exited_17d),
    );
    let leaf_suspended = make_process_record(
        502,
        created_20d + 200,
        Some(&parent.process_instance_id),
        501,
        r"C:\Users\dev\Downloads\stealer.exe",
        Some(exited_16d),
    );

    // Expired exited sibling with no children and no unresolved alerts -> MUST be purged.
    let dead_sibling = make_process_record(
        503,
        created_20d + 300,
        Some(&gp.process_instance_id),
        500,
        r"C:\Temp\harmless_old.exe",
        Some(exited_16d),
    );

    // Expired branch with a resolved alert -> MUST be purged.
    let dead_resolved = make_process_record(
        504,
        created_20d + 400,
        None,
        4,
        r"C:\Temp\old_dismissed.exe",
        Some(exited_16d),
    );

    for proc_rec in [&gp, &parent, &leaf_suspended, &dead_sibling, &dead_resolved] {
        store
            .upsert_process_record(proc_rec)
            .expect("upsert process");
    }

    // Seed an initially PENDING alert and transition it via expire_pending_alerts -> EXPIRED_SUSPENDED.
    store
        .record_alert(&make_alert(
            "alrt-p2-exp-susp",
            exited_16d,
            Some(&leaf_suspended.process_instance_id),
            AlertStatus::Pending,
            None,
        ))
        .expect("record pending alert");
    assert_eq!(
        store
            .expire_pending_alerts(exited_16d + 60_000)
            .expect("transition to EXPIRED_SUSPENDED"),
        1
    );

    // Seed an old resolved alert that MUST be deleted by purge_expired.
    store
        .record_alert(&make_alert(
            "alrt-p2-old-dismissed",
            exited_16d,
            Some(&dead_resolved.process_instance_id),
            AlertStatus::Dismissed,
            Some(exited_16d + 1_000),
        ))
        .expect("record dismissed alert");

    // Purge with 14-day TTL: dead_sibling, dead_resolved, and dismissed alert are deleted;
    // leaf_suspended, parent, gp, and the EXPIRED_SUSPENDED alert must all survive (L-07, L-11).
    let stats1 = store.purge_expired(now_ms, 14).expect("first purge");
    assert_eq!(stats1.alerts_deleted, 1);
    assert_eq!(stats1.processes_deleted, 2);

    assert_eq!(
        store
            .get_alert("alrt-p2-exp-susp")
            .expect("get EXPIRED_SUSPENDED alert")
            .map(|a| a.status),
        Some(AlertStatus::ExpiredSuspended)
    );
    assert_eq!(
        store
            .get_alert("alrt-p2-old-dismissed")
            .expect("dismissed alert deleted"),
        None
    );

    let lineage = store
        .get_process_lineage(&leaf_suspended.process_instance_id)
        .expect("preserved lineage");
    let lineage_ids: Vec<&str> = lineage
        .iter()
        .map(|p| p.process_instance_id.as_str())
        .collect();
    assert_eq!(
        lineage_ids,
        vec![
            gp.process_instance_id.as_str(),
            parent.process_instance_id.as_str(),
            leaf_suspended.process_instance_id.as_str(),
        ]
    );
    assert!(store
        .get_process_lineage(&dead_sibling.process_instance_id)
        .expect("dead sibling purged")
        .is_empty());

    // Once the EXPIRED_SUSPENDED alert is resolved, the next purge removes the alert and
    // bottom-up deletes leaf_suspended -> parent -> gp.
    assert!(store
        .update_alert_status(
            "alrt-p2-exp-susp",
            AlertStatus::TerminatedBlocked,
            Some(now_ms)
        )
        .expect("resolve EXPIRED_SUSPENDED alert"));

    let stats2 = store.purge_expired(now_ms, 14).expect("second purge");
    assert_eq!(stats2.alerts_deleted, 1);
    assert_eq!(stats2.processes_deleted, 3);

    assert_eq!(
        store
            .get_alert("alrt-p2-exp-susp")
            .expect("resolved alert deleted"),
        None
    );
    assert!(store
        .get_process_lineage(&leaf_suspended.process_instance_id)
        .expect("resolved branch purged")
        .is_empty());
}

/// `STORE-P2-06` (`BUG_0005`): `list_alerts_for_process` must scope by
/// `process_instance_id` in SQL so sibling lookups still see older alerts when the
/// global `list_alerts` top-N window is filled by unrelated processes.
#[test]
fn store_p2_06_list_alerts_for_process_scopes_by_process() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    // Fill the newest slots with unrelated alerts so the global top-1000 list cannot
    // see the target process's older alerts.
    for i in 0..1_100i64 {
        store
            .record_alert(&make_alert(
                &format!("noise-{i}"),
                10_000 + i,
                Some("900:1"),
                AlertStatus::Pending,
                None,
            ))
            .expect("record noise alert");
    }
    store
        .record_alert(&make_alert(
            "target-resolved",
            9_999,
            Some("4242:9"),
            AlertStatus::ApprovedOnce,
            Some(11_000),
        ))
        .expect("record target resolved");
    store
        .record_alert(&make_alert(
            "target-pending",
            9_998,
            Some("4242:9"),
            AlertStatus::Pending,
            None,
        ))
        .expect("record target pending");

    // The regression: a global newest-first listing misses the target alerts entirely.
    assert!(store
        .list_alerts(None, 1_000)
        .expect("global list")
        .iter()
        .all(|a| a.process_instance_id.as_deref() != Some("4242:9")));

    let scoped = store
        .list_alerts_for_process("4242:9", false, 1_000)
        .expect("scoped list");
    assert_eq!(scoped.len(), 2);

    let unresolved = store
        .list_alerts_for_process("4242:9", true, 1_000)
        .expect("scoped unresolved list");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].alert_id, "target-pending");
}
