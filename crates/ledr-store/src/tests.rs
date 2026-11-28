use super::*;
use crate::batch::resolve_process_instance_id;
use ledr_proto::{
    AlertRecord, AlertSeverity, AllowlistRuleRecord, ProcessIdentity, ProcessRecord, RuleScope,
    ScriptSource,
};
use std::net::{IpAddr, Ipv4Addr};
use tempfile::TempDir;

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn unit_schema_tables_indexes_and_all_seven_pragmas() {
    assert_send_sync::<LedrStore>();

    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("schema_check.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let expected_tables = [
        "alerts",
        "allowlist_rules",
        "default_rule_seeds",
        "dns_queries",
        "download_origins",
        "file_canary_events",
        "honeypot_files",
        "network_events",
        "processes",
    ];
    let expected_indexes = [
        "idx_alerts_proc_status",
        "idx_alerts_status_ts",
        "idx_canary_ts",
        "idx_dl_path",
        "idx_dl_path_nocase",
        "idx_dl_sha256",
        "idx_dl_sha256_nocase",
        "idx_dns_name",
        "idx_dns_name_nocase",
        "idx_dns_ts_proc",
        "idx_net_ts_proc",
        "idx_processes_created",
        "idx_processes_parent",
        "idx_processes_pid_created",
        "idx_processes_sha256",
        "idx_rules_scope_created",
    ];

    let writer = store.lock_writer().expect("lock writer");
    {
        let mut tbl_stmt = writer
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare tables query");
        let tables: Vec<String> = tbl_stmt
            .query_map([], |row| row.get(0))
            .expect("query tables")
            .map(|r| r.expect("table row"))
            .collect();
        assert_eq!(tables, expected_tables);

        let mut idx_stmt = writer
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'index' AND name LIKE 'idx_%'
                 ORDER BY name",
            )
            .expect("prepare indexes query");
        let indexes: Vec<String> = idx_stmt
            .query_map([], |row| row.get(0))
            .expect("query indexes")
            .map(|r| r.expect("index row"))
            .collect();
        assert_eq!(indexes, expected_indexes);
    }

    // Verify all 7 AUTO-09 PRAGMAs on both writer (-2048) and reader (-512) connections.
    for (label, expected_cache_size, conn_guard) in [
        ("writer", -2048i64, writer),
        ("reader", -512i64, store.lock_reader().expect("lock reader")),
    ] {
        let jm: String = conn_guard
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .expect("journal_mode");
        let sync: i64 = conn_guard
            .query_row("PRAGMA synchronous;", [], |r| r.get(0))
            .expect("synchronous");
        let cache: i64 = conn_guard
            .query_row("PRAGMA cache_size;", [], |r| r.get(0))
            .expect("cache_size");
        let temp: i64 = conn_guard
            .query_row("PRAGMA temp_store;", [], |r| r.get(0))
            .expect("temp_store");
        let mmap: i64 = conn_guard
            .query_row("PRAGMA mmap_size;", [], |r| r.get(0))
            .expect("mmap_size");
        let auto_ckpt: i64 = conn_guard
            .query_row("PRAGMA wal_autocheckpoint;", [], |r| r.get(0))
            .expect("wal_autocheckpoint");
        let fk: i64 = conn_guard
            .query_row("PRAGMA foreign_keys;", [], |r| r.get(0))
            .expect("foreign_keys");

        assert_eq!(jm.to_ascii_lowercase(), "wal", "{label} journal_mode");
        assert_eq!(sync, 1, "{label} synchronous"); // NORMAL
        assert_eq!(cache, expected_cache_size, "{label} cache_size");
        assert_eq!(temp, 2, "{label} temp_store"); // MEMORY
        assert_eq!(mmap, 0, "{label} mmap_size");
        assert_eq!(auto_ckpt, 1000, "{label} wal_autocheckpoint");
        assert_eq!(fk, 1, "{label} foreign_keys");
    }
}

#[test]
fn unit_alerts_downloads_and_script_event_handling() {
    let store = LedrStore::open_in_memory().expect("open in memory");
    let (_, cache_size, mmap_size) = store.verify_pragmas().expect("verify in-memory pragmas");
    assert_eq!(cache_size, -2048);
    assert_eq!(mmap_size, 0);

    // ScriptEvaluated is not directly buffered into raw telemetry tables.
    let script = SensorEvent::ScriptEvaluated {
        pid: 55,
        source: ScriptSource::PowerShell4104,
        script_content: "Write-Output 'ok'".to_string(),
        timestamp_ms: 1_750_000_000_000,
    };
    assert!(!store
        .ingest_event(&script, None, false, "")
        .expect("script event ok"));
    assert_eq!(store.buffered_len(), 0);

    // ProcessStart buffered, then record_alert atomically flushes pending batch + alert.
    let proc_start = SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(55, 133_765_432_101_234_567),
        parent_pid: 4,
        exe_path: r"C:\Users\dev\Downloads\dropper.exe".to_string(),
        command_line: "dropper.exe --run".to_string(),
        user_sid: None,
    };
    assert!(!store
        .ingest_event(&proc_start, Some("4:1"), false, "")
        .expect("buffer process start"));
    assert_eq!(store.buffered_len(), 1);

    let alert = AlertRecord {
        alert_id: "alrt-unit-1".to_string(),
        timestamp_ms: 1_750_000_000_500,
        severity: AlertSeverity::Critical,
        source_layer: "layer2".to_string(),
        rule_id: "lotl_ps".to_string(),
        title: "Suspicious process".to_string(),
        process_instance_id: Some("55:133765432101234567".to_string()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: "{}".to_string(),
        resolved_at_ms: None,
    };
    store.record_alert(&alert).expect("record alert");
    assert_eq!(store.buffered_len(), 0);

    let pending = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list pending alerts");
    assert_eq!(pending, vec![alert]);

    assert!(store
        .update_alert_status(
            "alrt-unit-1",
            AlertStatus::ApprovedRule,
            Some(1_750_000_001_000)
        )
        .expect("update status"));
    assert!(!store
        .update_alert_status("nonexistent", AlertStatus::Dismissed, None)
        .expect("missing alert returns false"));
    assert!(store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("no pending left")
        .is_empty());

    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\dev\Downloads\dropper.exe".to_string(),
            sha256: Some("cafebabe".to_string()),
            tab_url: "https://downloads.example.test/file".to_string(),
            frame_url: None,
            referrer_url: Some("https://downloads.example.test/".to_string()),
            downloaded_at_ms: 1_750_000_000_100,
        })
        .expect("record download origin");

    let snap = store
        .query_flight_recorder(20, Some("55:133765432101234567"))
        .expect("query scoped snapshot");
    assert_eq!(snap.processes.len(), 1);
    assert_eq!(snap.download_origins.len(), 1);
    assert_eq!(
        snap.download_origins[0].tab_url,
        "https://downloads.example.test/file"
    );
}

#[test]
fn unit_concurrent_writer_and_reader_threads() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("concurrent.db");
    let store = LedrStore::open(&db_path).expect("open store");

    let writer_store = store.clone();
    let writer_handle = std::thread::spawn(move || {
        for i in 0..200 {
            let dns = SensorEvent::DnsQuery {
                pid: 777,
                query_name: format!("concurrent-{i}.example.test"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                timestamp_ms: 1_750_000_000_000 + i,
            };
            writer_store
                .ingest_event(&dns, Some("777:999"), false, "")
                .expect("ingest dns");
            if i % 50 == 49 {
                writer_store.flush_batch().expect("flush batch");
            }
        }
    });

    let reader_store = store.clone();
    let reader_handle = std::thread::spawn(move || {
        for _ in 0..40 {
            let _snap = reader_store
                .query_flight_recorder(50, None)
                .expect("concurrent flight recorder query");
        }
    });

    writer_handle.join().expect("writer thread");
    reader_handle.join().expect("reader thread");

    let final_snap = store
        .query_flight_recorder(500, None)
        .expect("final snapshot");
    assert_eq!(final_snap.dns_queries.len(), 200);
}

#[test]
fn unit_resolve_process_instance_id_fast_hint_and_fallbacks() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let proc_old = ProcessRecord {
        process_instance_id: "42:1000".to_string(),
        pid: 42,
        parent_instance_id: Some("4:1".to_string()),
        ppid: 4,
        exe_path: r"C:\Temp\old.exe".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: None,
        origin_url: None,
        created_at_ms: 1000,
        exited_at_ms: Some(2000),
    };
    let proc_new = ProcessRecord {
        process_instance_id: "42:1500".to_string(),
        pid: 42,
        parent_instance_id: Some("4:1".to_string()),
        ppid: 4,
        exe_path: r"C:\Temp\new.exe".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: None,
        origin_url: None,
        created_at_ms: 1500,
        exited_at_ms: None,
    };
    store
        .upsert_process_record(&proc_old)
        .expect("upsert proc_old");
    store
        .upsert_process_record(&proc_new)
        .expect("upsert proc_new");

    let mut writer = store.lock_writer().expect("lock writer");
    let tx = writer.transaction().expect("begin tx");

    // Index-first priority: even when a stale hint ("42:1000") is valid at ts=1700/2000,
    // PID_TIME_WINDOW_LOOKUP_SQL selects the newest overlapping incarnation ("42:1500").
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 1700, Some("42:1000"))
            .expect("index-first selects newest overlapping mid"),
        "42:1500"
    );
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 2000, Some("42:1000"))
            .expect("index-first selects newest overlapping end"),
        "42:1500"
    );
    // Before proc_new starts at 1500, index selects proc_old ("42:1000") regardless of hint.
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 1000, Some("42:1000")).expect("index start"),
        "42:1000"
    );
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 1200, Some("42:1500"))
            .expect("index ignores future hint"),
        "42:1000"
    );

    // Post-exit of proc_old selects proc_new; pre-start falls back to "{pid}:0".
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 2500, Some("42:1000"))
            .expect("stale hint selects newer"),
        "42:1500"
    );
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 500, Some("42:1000"))
            .expect("early out-of-window hint"),
        "42:0"
    );

    // Unpersisted or PID-mismatched hint resolves persisted row via index first.
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 1700, Some("42:9999"))
            .expect("unpersisted hint resolves persisted row"),
        "42:1500"
    );
    assert_eq!(
        resolve_process_instance_id(&tx, 42, 1700, Some("999:1000"))
            .expect("mismatched pid hint resolves persisted row"),
        "42:1500"
    );
    // Hint fallback applies only when index query finds no row and hint PID/window matches.
    assert_eq!(
        resolve_process_instance_id(&tx, 88, 1700, Some("88:9999"))
            .expect("unpersisted hint fallback"),
        "88:9999"
    );
    assert_eq!(
        resolve_process_instance_id(&tx, 88, 1700, Some("999:1000"))
            .expect("mismatched pid hint fallback"),
        "88:0"
    );
}

#[test]
fn unit_purge_in_batches_stops_between_batches_on_shutdown() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    for i in 0..1_200u32 {
        let pid = 30_000 + i;
        store
            .upsert_process_record(&ProcessRecord {
                process_instance_id: format!("{pid}:{}", 1000 + i),
                pid,
                parent_instance_id: None,
                ppid: 4,
                exe_path: r"C:\Temp\batch_test.exe".to_string(),
                command_line: None,
                sha256: None,
                signer_subject: None,
                is_trusted_os: false,
                user_sid: None,
                origin_url: None,
                created_at_ms: 1000,
                exited_at_ms: Some(2000),
            })
            .expect("seed expired process");
    }

    let mut batches_run = 0usize;
    let deleted = store
        .purge_in_batches(|tx| {
            batches_run += 1;
            let count = tx.execute(
                "DELETE FROM processes
                 WHERE process_instance_id IN (
                     SELECT process_instance_id FROM processes
                     WHERE exited_at_ms < 5000
                     LIMIT 500
                 )",
                [],
            )?;
            if batches_run == 1 {
                store.request_shutdown();
            }
            Ok(count)
        })
        .expect("purge_in_batches stops after batch 1");

    assert_eq!(batches_run, 1);
    assert_eq!(deleted, 500);
    assert!(store.is_shutdown_requested());
    assert!(store.inner.writer.try_lock().is_ok());

    let remaining: i64 = store
        .lock_reader()
        .expect("lock reader")
        .query_row("SELECT COUNT(*) FROM processes", [], |row| row.get(0))
        .expect("count remaining rows");
    assert_eq!(remaining, 700);
}

#[test]
fn store_p2_bug_0002_update_alert_suspension_state_updates_flag_and_context() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    store
        .record_alert(&AlertRecord {
            alert_id: "susp-1".to_string(),
            timestamp_ms: 1_732_000_000_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "Suspended".to_string(),
            process_instance_id: Some("100:1000".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: r#"{"suspended_children":["101:1001"]}"#.to_string(),
            resolved_at_ms: None,
        })
        .expect("record alert");

    assert!(store
        .update_alert_suspension_state(
            "susp-1",
            false,
            r#"{"suspended_children":[],"shutdown_resumed_identities":["100:1000","101:1001"]}"#
        )
        .expect("update existing"));
    assert!(!store
        .update_alert_suspension_state("does-not-exist", false, "{}")
        .expect("update missing"));

    let updated = store
        .get_alert("susp-1")
        .expect("get")
        .expect("row exists");
    assert!(!updated.process_suspended);
    assert!(updated.context_json.contains("shutdown_resumed_identities"));
    assert_eq!(updated.status, AlertStatus::Pending);
    assert!(
        store
            .list_unresolved_suspended_alerts()
            .expect("list after clearing suspension")
            .is_empty(),
        "alert with process_suspended=false and empty suspended_children must not be re-listed"
    );
}

#[test]
fn store_p2_bug_0003_list_unresolved_suspended_alerts_paginates_past_500_and_1000() {
    let store = LedrStore::open_in_memory().expect("in-memory store");

    // Insert 550 unresolved suspended alerts (exceeding the 500-row keyset page size)
    // plus 1,050 newer non-suspended alerts and 1 resolved suspended alert.
    for i in 0..550 {
        let is_child_only = i % 10 == 0;
        let status = if i % 2 == 0 {
            AlertStatus::Pending
        } else {
            AlertStatus::ExpiredSuspended
        };
        store
            .record_alert(&AlertRecord {
                alert_id: format!("susp-{i:04}"),
                timestamp_ms: 1_732_000_000_000 + (i / 5) as i64,
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
                title: "Suspended".to_string(),
                process_instance_id: Some(format!("{}:{}", 1000 + i, 2000 + i)),
                process_suspended: !is_child_only,
                status,
                context_json: if is_child_only {
                    format!(r#"{{"suspended_children":["{}:{}"]}}"#, 5000 + i, 6000 + i)
                } else {
                    "{}".to_string()
                },
                resolved_at_ms: None,
            })
            .expect("record suspended alert");
    }

    for i in 0..1050 {
        store
            .record_alert(&AlertRecord {
                alert_id: format!("noise-{i:04}"),
                timestamp_ms: 1_732_000_100_000 + i as i64,
                severity: AlertSeverity::Low,
                source_layer: "LAYER_2_SIGMA".to_string(),
                rule_id: "LEDR-NOISE".to_string(),
                title: "Not suspended".to_string(),
                process_instance_id: Some(format!("{}:{}", 8000 + i, 9000 + i)),
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("record noise alert");
    }

    store
        .record_alert(&AlertRecord {
            alert_id: "resolved-susp".to_string(),
            timestamp_ms: 1_732_000_200_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
            title: "Resolved".to_string(),
            process_instance_id: Some("9999:9999".to_string()),
            process_suspended: true,
            status: AlertStatus::ApprovedOnce,
            context_json: "{}".to_string(),
            resolved_at_ms: Some(1_732_000_201_000),
        })
        .expect("record resolved alert");

    let found = store
        .list_unresolved_suspended_alerts()
        .expect("list unresolved suspended alerts");
    assert_eq!(found.len(), 550);
    assert!(found.iter().all(|a| a.alert_id.starts_with("susp-")));
}

#[test]
fn store_p2_bug_0004_seed_default_rules_once_does_not_resurrect_deleted_or_overwrite_edited() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let mk_rule = |id: &str, target: Option<&str>| AllowlistRuleRecord {
        rule_id: id.to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: format!(r"*\app_{id}.exe"),
        sha256: None,
        signer_subject: Some("Test Signer".to_string()),
        root_thumbprint: None,
        allowed_target: target.map(str::to_string),
        created_at_ms: 1_732_000_000_000,
        created_by: "system-default".to_string(),
    };

    let initial = vec![mk_rule("DEF-1", None), mk_rule("DEF-2", None)];
    assert_eq!(
        store.seed_default_rules_once(&initial).expect("first seed"),
        2
    );

    // Operator deletes DEF-1 and customizes DEF-2.
    assert!(store.delete_rule("DEF-1").expect("delete DEF-1"));
    let mut edited = mk_rule("DEF-2", Some("example.com"));
    edited.created_by = "operator".to_string();
    store.upsert_rule(&edited).expect("edit DEF-2");

    // Re-seeding on next daemon startup must NOT resurrect DEF-1 or overwrite DEF-2,
    // while still seeding a brand-new default rule DEF-3.
    let next_boot = vec![
        mk_rule("DEF-1", None),
        mk_rule("DEF-2", None),
        mk_rule("DEF-3", None),
    ];
    assert_eq!(
        store
            .seed_default_rules_once(&next_boot)
            .expect("second seed"),
        1
    );

    assert!(
        store.get_rule("DEF-1").expect("get DEF-1").is_none(),
        "BUG_0004: deleted default rule must not be resurrected on restart"
    );
    let r2 = store
        .get_rule("DEF-2")
        .expect("get DEF-2")
        .expect("DEF-2 exists");
    assert_eq!(r2.allowed_target.as_deref(), Some("example.com"));
    assert_eq!(r2.created_by, "operator");
    assert!(store.get_rule("DEF-3").expect("get DEF-3").is_some());
}

#[test]
fn store_p2_analysis_list_unresolved_suspended_alerts_uses_top_level_json_array() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let mk_alert = |id: &str, ts: i64, suspended: bool, ctx: &str| AlertRecord {
        alert_id: id.to_string(),
        timestamp_ms: ts,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        title: format!("Alert {id}"),
        process_instance_id: Some(format!("4000:{ts}")),
        process_suspended: suspended,
        status: AlertStatus::Pending,
        context_json: ctx.to_string(),
        resolved_at_ms: None,
    };

    // Must be INCLUDED:
    // 1. Top-level non-empty array even when a nested object carries an empty same-named array.
    store
        .record_alert(&mk_alert(
            "inc-nested-empty",
            1,
            false,
            r#"{"suspended_children":["101:1001"],"meta":{"suspended_children":[]}}"#,
        ))
        .expect("record inc-nested-empty");
    // 2. Pretty-printed / whitespace-formatted top-level non-empty array.
    store
        .record_alert(&mk_alert(
            "inc-whitespace",
            2,
            false,
            "{ \"suspended_children\" : [ \"102:1002\" ] }",
        ))
        .expect("record inc-whitespace");
    // 3. Parent suspended with malformed JSON must still be included without error.
    store
        .record_alert(&mk_alert("inc-malformed-parent", 3, true, "{bad json"))
        .expect("record inc-malformed-parent");
    // 3b. EXPIRED_SUSPENDED alert with process_suspended=false and non-empty top-level array.
    let mut expired_child_only = mk_alert(
        "inc-expired-child",
        35,
        false,
        r#"{"suspended_children":["106:1006"]}"#,
    );
    expired_child_only.status = AlertStatus::ExpiredSuspended;
    store
        .record_alert(&expired_child_only)
        .expect("record inc-expired-child");

    // Must be EXCLUDED:
    // 4. Pretty-printed empty array with spaces (would fool LIKE/NOT LIKE).
    store
        .record_alert(&mk_alert(
            "exc-whitespace-empty",
            4,
            false,
            "{ \"suspended_children\" : [ ] }",
        ))
        .expect("record exc-whitespace-empty");
    // 5. Nested non-empty array when top-level has no suspended_children.
    store
        .record_alert(&mk_alert(
            "exc-nested-only",
            5,
            false,
            r#"{"meta":{"suspended_children":["103:1003"]}}"#,
        ))
        .expect("record exc-nested-only");
    // 6. Top-level non-array value (string / null / object).
    store
        .record_alert(&mk_alert(
            "exc-string",
            6,
            false,
            r#"{"suspended_children":"104:1004"}"#,
        ))
        .expect("record exc-string");
    store
        .record_alert(&mk_alert(
            "exc-null",
            7,
            false,
            r#"{"suspended_children":null}"#,
        ))
        .expect("record exc-null");
    // 7. Malformed JSON / empty string with process_suspended=false must be excluded without SQLite error.
    store
        .record_alert(&mk_alert("exc-malformed", 8, false, "{not valid json"))
        .expect("record exc-malformed");
    store
        .record_alert(&mk_alert("exc-empty-str", 81, false, ""))
        .expect("record exc-empty-str");
    // 8. Top-level JSON array / scalar instead of object.
    store
        .record_alert(&mk_alert("exc-top-array", 9, false, r#"["105:1005"]"#))
        .expect("record exc-top-array");
    store
        .record_alert(&mk_alert("exc-top-scalar", 91, false, "null"))
        .expect("record exc-top-scalar");

    let found = store
        .list_unresolved_suspended_alerts()
        .expect("list unresolved suspended alerts with SQLite JSON functions");
    let found_ids: Vec<&str> = found.iter().map(|a| a.alert_id.as_str()).collect();
    assert_eq!(
        found_ids,
        vec![
            "inc-nested-empty",
            "inc-whitespace",
            "inc-malformed-parent",
            "inc-expired-child",
        ]
    );
}

#[test]
fn store_p2_upsert_process_preserves_existing_ppid_and_exe_path() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let ident = ProcessIdentity::new(4200, 133_800_000_000_000_000);
    let inst_id = ident.instance_id();

    // Initial ProcessStart with known ppid and empty exe_path.
    let initial = SensorEvent::ProcessStart {
        identity: ident,
        parent_pid: 1234,
        exe_path: String::new(),
        command_line: "tool.exe --run".to_string(),
        user_sid: None,
    };
    store
        .ingest_event_with_exit(&initial, None, None, false, "OBSERVED")
        .expect("ingest initial");
    store.flush_batch().expect("flush initial");

    // Partial backfill carrying exe_path but parent_pid == 0 must preserve ppid=1234.
    let backfill_exe = SensorEvent::ProcessStart {
        identity: ident,
        parent_pid: 0,
        exe_path: r"C:\Temp\tool.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_exit(&backfill_exe, None, None, false, "OBSERVED")
        .expect("ingest backfill");
    store.flush_batch().expect("flush backfill");

    // Subsequent partial upsert with empty exe_path and parent_pid == 0 must preserve both.
    let empty_partial = SensorEvent::ProcessStart {
        identity: ident,
        parent_pid: 0,
        exe_path: String::new(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_exit(&empty_partial, None, None, false, "OBSERVED")
        .expect("ingest empty partial");
    store.flush_batch().expect("flush empty partial");

    let snap = store
        .query_flight_recorder(10, Some(&inst_id))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == inst_id)
        .expect("process row exists");
    assert_eq!(row.ppid, 1234, "partial upsert with ppid=0 must not clobber existing ppid");
    assert_eq!(
        row.exe_path, r"C:\Temp\tool.exe",
        "partial upsert with empty exe_path must not clobber existing exe_path"
    );
}

#[test]
fn store_p2_upsert_process_record_allows_explicit_zero_ppid_and_empty_exe_path() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let inst_id = "4201:133800000000000000".to_string();
    store
        .upsert_process_record(&ProcessRecord {
            process_instance_id: inst_id.clone(),
            pid: 4201,
            parent_instance_id: None,
            ppid: 1234,
            exe_path: r"C:\Temp\tool.exe".to_string(),
            command_line: Some("tool.exe --run".to_string()),
            sha256: None,
            signer_subject: None,
            is_trusted_os: false,
            user_sid: None,
            origin_url: None,
            created_at_ms: 1_700_000_000_000,
            exited_at_ms: Some(1_700_000_005_000),
        })
        .expect("seed full process record");

    // Full-record upsert must allow explicitly clearing ppid and exe_path while keeping
    // existing exited_at_ms and Option fields untouched when None.
    store
        .upsert_process_record(&ProcessRecord {
            process_instance_id: inst_id.clone(),
            pid: 4201,
            parent_instance_id: None,
            ppid: 0,
            exe_path: String::new(),
            command_line: None,
            sha256: None,
            signer_subject: None,
            is_trusted_os: false,
            user_sid: None,
            origin_url: None,
            created_at_ms: 1_700_000_000_000,
            exited_at_ms: None,
        })
        .expect("overwrite full process record");

    let snap = store
        .query_flight_recorder(10, Some(&inst_id))
        .expect("query flight recorder");
    let row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == inst_id)
        .expect("process row exists");
    assert_eq!(row.ppid, 0, "full-record upsert must allow explicit ppid=0");
    assert_eq!(row.exe_path, "", "full-record upsert must allow explicit empty exe_path");
    assert_eq!(
        row.command_line.as_deref(),
        Some("tool.exe --run"),
        "None Option fields remain preserved via COALESCE"
    );
    assert_eq!(
        row.exited_at_ms,
        Some(1_700_000_005_000),
        "already-set exited_at_ms must remain preserved"
    );
}

#[test]
fn store_p2_ingest_process_start_closes_superseded_placeholder_atomically_without_time_inversion() {
    let store = LedrStore::open_in_memory().expect("in-memory store");
    let placeholder_id = ProcessIdentity::new(4202, 0);
    let placeholder_key = placeholder_id.instance_id();

    // Seed placeholder row (create_time_100ns = 0 -> created_at_ms = received_at_ms).
    store
        .ingest_event_with_lifecycle(
            &SensorEvent::ProcessStart {
                identity: placeholder_id,
                parent_pid: 4,
                exe_path: r"C:\Temp\svc.exe".to_string(),
                command_line: String::new(),
                user_sid: None,
            },
            None,
            None,
            None,
            false,
            "OBSERVED",
        )
        .expect("ingest placeholder");
    store.flush_batch().expect("flush placeholder");

    let placeholder_created = store
        .query_flight_recorder(10, Some(&placeholder_key))
        .expect("query placeholder")
        .processes
        .into_iter()
        .find(|p| p.process_instance_id == placeholder_key)
        .expect("placeholder exists")
        .created_at_ms;

    // Superseding real ProcessStart carries an earlier real start timestamp (< placeholder_created).
    let real_created_ms = placeholder_created - 2_000;
    let real_ticks =
        (u64::try_from(real_created_ms).expect("positive ms") * 10_000) + 116_444_736_000_000_000;
    let real_id = ProcessIdentity::new(4202, real_ticks);
    let real_key = real_id.instance_id();

    store
        .ingest_event_with_lifecycle(
            &SensorEvent::ProcessStart {
                identity: real_id,
                parent_pid: 4,
                exe_path: r"C:\Temp\svc.exe".to_string(),
                command_line: "svc.exe --run".to_string(),
                user_sid: None,
            },
            None,
            None,
            Some((placeholder_key.as_str(), real_created_ms)),
            false,
            "OBSERVED",
        )
        .expect("ingest superseding start");
    store.flush_batch().expect("flush superseding start");

    let snap = store
        .query_flight_recorder(20, None)
        .expect("query flight recorder");
    let placeholder_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == placeholder_key)
        .expect("placeholder row remains for lineage/alert references");
    let real_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == real_key)
        .expect("real row exists");

    assert_eq!(
        placeholder_row.exited_at_ms,
        Some(placeholder_created),
        "superseded placeholder must be closed with exited_at_ms clamped to >= created_at_ms"
    );
    assert_eq!(real_row.exited_at_ms, None, "real process row remains active");
}

/// `STORE-MEM-01`: File-backed `writer` uses `cache_size = -2048` and `reader` uses
/// `cache_size = -512`; `shrink_reader_memory_if_idle(Duration::from_secs(30))` skips when
/// idle < 30s, shrinks once when idle > 30s, skips on repeat / lock contention / shutdown,
/// resumes after `clear_shutdown_flag()`, and preserves read/write consistency (including on
/// `open_in_memory()`).
#[test]
fn store_mem_01_reader_cache_size_and_idle_shrink() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("store_mem_01.db");
    let store = LedrStore::open(&db_path).expect("open file-backed store");

    let (_, w_cache, _) = store.verify_pragmas().expect("verify writer pragmas");
    let (_, r_cache, _) = store
        .verify_reader_pragmas()
        .expect("verify reader pragmas");
    assert_eq!(w_cache, -2048);
    assert_eq!(r_cache, -512);

    let id1 = ProcessIdentity::new(5101, 133_765_432_101_000_000);
    let ev1 = SensorEvent::ProcessStart {
        identity: id1,
        parent_pid: 4,
        exe_path: r"C:\Tools\mem_probe_1.exe".to_string(),
        command_line: "mem_probe_1.exe --alpha".to_string(),
        user_sid: None,
    };
    store
        .ingest_event(&ev1, Some("4:1"), false, "OBSERVED")
        .expect("ingest ev1");
    store.flush_batch().expect("flush ev1");

    let snap1 = store
        .query_flight_recorder(10, Some(&id1.instance_id()))
        .expect("query ev1");
    assert_eq!(snap1.processes.len(), 1);

    // Idle < 30s must not execute shrink_memory.
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("shrink check < 30s"),
        "must not shrink before 30s idle"
    );

    // Contention on reader lock must return Ok(false) without blocking even when idle > 30s.
    {
        let _reader_guard = store.lock_reader().expect("hold reader lock");
        store.advance_reader_idle_for_test(Duration::from_secs(31));
        assert!(
            !store
                .shrink_reader_memory_if_idle(Duration::from_secs(30))
                .expect("contended shrink must not block or error"),
            "must return Ok(false) on WouldBlock"
        );
    }

    // Idle > 30s and uncontended must shrink once, then skip immediate repeat.
    assert!(
        store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("shrink after 31s idle"),
        "must shrink once after > 30s idle"
    );
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("repeat shrink immediately after"),
        "must not re-shrink until reader is accessed again"
    );

    // Accessing reader resets idle timer and clears shrunk flag.
    let snap1_after = store
        .query_flight_recorder(10, Some(&id1.instance_id()))
        .expect("query ev1 after shrink");
    assert_eq!(snap1_after.processes.len(), 1);
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("shrink check right after query"),
        "reader access must reset 30s idle timer"
    );

    // Shutdown requested suppresses shrink without falsely marking shrunk.
    store.advance_reader_idle_for_test(Duration::from_secs(31));
    store.request_shutdown();
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("shrink check during shutdown"),
        "must not acquire reader lock or shrink when shutdown is requested"
    );

    // Clearing shutdown flag (restart path) allows pending idle shrink to proceed.
    store.clear_shutdown_flag();
    assert!(
        store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("shrink after clear_shutdown_flag"),
        "must shrink once shutdown flag is cleared"
    );

    // Read/write consistency and reader cache_size pragma remain intact after shrink.
    let id2 = ProcessIdentity::new(5102, 133_765_432_102_000_000);
    let ev2 = SensorEvent::ProcessStart {
        identity: id2,
        parent_pid: 4,
        exe_path: r"C:\Tools\mem_probe_2.exe".to_string(),
        command_line: "mem_probe_2.exe --beta".to_string(),
        user_sid: None,
    };
    store
        .ingest_event(&ev2, Some("4:1"), false, "OBSERVED")
        .expect("ingest ev2");
    store.flush_batch().expect("flush ev2");

    let snap_all = store.query_flight_recorder(10, None).expect("query all");
    assert_eq!(snap_all.processes.len(), 2);
    let (_, r_cache_after, _) = store
        .verify_reader_pragmas()
        .expect("verify reader pragmas after shrink");
    assert_eq!(r_cache_after, -512);

    // Verify open_in_memory() keeps cache_size = -2048 and safely preserves rows on shrink.
    let mem_store = LedrStore::open_in_memory().expect("open in-memory store");
    let (_, mem_w_cache, _) = mem_store.verify_pragmas().expect("in-memory writer pragma");
    let (_, mem_r_cache, _) = mem_store
        .verify_reader_pragmas()
        .expect("in-memory reader pragma");
    assert_eq!(mem_w_cache, -2048);
    assert_eq!(mem_r_cache, -2048);

    mem_store
        .ingest_event(&ev1, Some("4:1"), false, "OBSERVED")
        .expect("in-memory ingest");
    mem_store.flush_batch().expect("in-memory flush");
    mem_store.advance_reader_idle_for_test(Duration::from_secs(31));
    assert!(
        mem_store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("in-memory shrink succeeds safely"),
        "in-memory shrink_memory should succeed safely"
    );
    let mem_snap = mem_store
        .query_flight_recorder(10, Some(&id1.instance_id()))
        .expect("in-memory query after shrink");
    assert_eq!(mem_snap.processes.len(), 1);
    let (_, mem_cache_after, _) = mem_store
        .verify_reader_pragmas()
        .expect("in-memory pragma after shrink");
    assert_eq!(mem_cache_after, -2048);
}

#[test]
fn store_fu_p4_03_idempotent_package_column_migration_and_non_clobbering_roundtrip() {
    let dir = TempDir::new().expect("tempdir");
    let db_path = dir.path().join("legacy_processes.db");

    // 1. Seed a legacy SQLite DB lacking `package_family_name` / `package_sid` on `processes`.
    {
        let legacy = rusqlite::Connection::open(&db_path).expect("open legacy sqlite");
        legacy
            .execute_batch(
                "CREATE TABLE processes (
                    process_instance_id TEXT PRIMARY KEY,
                    pid                 INTEGER NOT NULL,
                    parent_instance_id  TEXT,
                    ppid                INTEGER NOT NULL,
                    exe_path            TEXT NOT NULL,
                    command_line        TEXT,
                    sha256              TEXT,
                    signer_subject      TEXT,
                    is_trusted_os       INTEGER NOT NULL DEFAULT 0,
                    user_sid            TEXT,
                    origin_url          TEXT,
                    created_at_ms       INTEGER NOT NULL,
                    exited_at_ms        INTEGER
                ) WITHOUT ROWID;
                INSERT INTO processes (
                    process_instance_id, pid, ppid, exe_path, created_at_ms
                ) VALUES ('100:1000', 100, 4, 'C:\\Legacy\\app.exe', 1700000000000);",
            )
            .expect("seed legacy schema");
    }

    // 2. First and second LedrStore::open calls must migrate idempotently without losing rows.
    let store = LedrStore::open(&db_path).expect("migrate legacy db");
    drop(store);
    let store = LedrStore::open(&db_path).expect("reopen migrated db idempotently");

    let legacy_snap = store
        .query_flight_recorder(10, Some("100:1000"))
        .expect("query migrated legacy process");
    assert_eq!(legacy_snap.processes.len(), 1);
    assert_eq!(legacy_snap.processes[0].exe_path, r"C:\Legacy\app.exe");
    assert_eq!(
        store
            .get_process_package_info("100:1000")
            .expect("query legacy package cols"),
        Some(ProcessPackageRecord {
            package_family_name: None,
            package_sid: None,
        })
    );
    assert_eq!(
        store
            .get_process_package_info("999:999")
            .expect("missing process returns None"),
        None
    );

    // 3. Persist all 4 independent combinations (PFN+SID, PFN-only, SID-only, None).
    let cases = [
        (
            ProcessIdentity::new(201, 133_800_000_000_000_100),
            r"C:\Windows\System32\backgroundTaskHost.exe",
            Some("Contoso.App_12345"),
            Some("S-1-15-2-10-20-30"),
        ),
        (
            ProcessIdentity::new(202, 133_800_000_000_000_200),
            r"C:\Windows\System32\RuntimeBroker.exe",
            Some("Microsoft.Windows.Shell_cw5n1h2txyewy"),
            None,
        ),
        (
            ProcessIdentity::new(203, 133_800_000_000_000_300),
            r"C:\Windows\System32\fontdrvhost.exe",
            None,
            Some("S-1-15-2-99-88-77"),
        ),
        (
            ProcessIdentity::new(204, 133_800_000_000_000_400),
            r"C:\Windows\System32\cmd.exe",
            None,
            None,
        ),
    ];

    for (ident, exe, pfn, sid) in cases {
        let ev = SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: exe.to_string(),
            command_line: format!("{exe} --run"),
            user_sid: None,
        };
        store
            .ingest_event_with_extra_metadata(
                &ev,
                None,
                None,
                None,
                ProcessExtraMetadata {
                    origin_url: None,
                    sha256: None,
                    package_family_name: pfn,
                    package_sid: sid,
                },
                false,
                "OBSERVED",
            )
            .expect("ingest extra metadata");
    }
    store.flush_batch().expect("flush extra metadata");

    for (ident, _, pfn, sid) in cases {
        assert_eq!(
            store
                .get_process_package_info(&ident.instance_id())
                .expect("read back package attrs"),
            Some(ProcessPackageRecord {
                package_family_name: pfn.map(str::to_string),
                package_sid: sid.map(str::to_string),
            })
        );
    }

    // 4. Subsequent upsert_process_record and None ProcessStart must NOT clobber existing attrs.
    let id_both = cases[0].0;
    store
        .upsert_process_record(&ProcessRecord {
            process_instance_id: id_both.instance_id(),
            pid: id_both.pid,
            parent_instance_id: None,
            ppid: 4,
            exe_path: cases[0].1.to_string(),
            command_line: Some("updated".to_string()),
            sha256: Some("a".repeat(64)),
            signer_subject: None,
            is_trusted_os: true,
            user_sid: None,
            origin_url: None,
            created_at_ms: 1_700_000_000_000,
            exited_at_ms: None,
        })
        .expect("upsert_process_record preserves package cols");
    let dup_none = SensorEvent::ProcessStart {
        identity: id_both,
        parent_pid: 4,
        exe_path: cases[0].1.to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_extra_metadata(
            &dup_none,
            None,
            None,
            None,
            ProcessExtraMetadata::default(),
            false,
            "OBSERVED",
        )
        .expect("ingest duplicate none");
    store.flush_batch().expect("flush duplicate none");
    assert_eq!(
        store
            .get_process_package_info(&id_both.instance_id())
            .expect("verify non-clobber"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Contoso.App_12345".to_string()),
            package_sid: Some("S-1-15-2-10-20-30".to_string()),
        })
    );

    // Conflicting non-NULL values in a subsequent upsert must preserve first-non-NULL values.
    store
        .ingest_event_with_extra_metadata(
            &dup_none,
            None,
            None,
            None,
            ProcessExtraMetadata {
                package_family_name: Some("Conflicting.App_99999"),
                package_sid: Some("S-1-15-2-99-99-99"),
                ..Default::default()
            },
            false,
            "OBSERVED",
        )
        .expect("ingest conflicting metadata on id_both");
    // Missing column (package_sid == None on id_pfn_only) still backfills while preserving existing PFN.
    let id_pfn_only = cases[1].0;
    let pfn_only_ev = SensorEvent::ProcessStart {
        identity: id_pfn_only,
        parent_pid: 4,
        exe_path: cases[1].1.to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_extra_metadata(
            &pfn_only_ev,
            None,
            None,
            None,
            ProcessExtraMetadata {
                package_family_name: Some("ShouldNotReplace.Broker"),
                package_sid: Some("S-1-15-2-filled-sid"),
                ..Default::default()
            },
            false,
            "OBSERVED",
        )
        .expect("backfill missing sid via ingest");
    // Whitespace-only values normalize to None and update_process_package_metadata rejects empty updates.
    assert!(
        !store
            .update_process_package_metadata(&id_pfn_only.instance_id(), Some("   "), Some("\t\n"))
            .expect("whitespace-only metadata is a no-op")
    );
    store.flush_batch().expect("flush conflicting and backfill checks");
    assert_eq!(
        store
            .get_process_package_info(&id_both.instance_id())
            .expect("verify first-non-null preserved"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Contoso.App_12345".to_string()),
            package_sid: Some("S-1-15-2-10-20-30".to_string()),
        })
    );
    assert_eq!(
        store
            .get_process_package_info(&id_pfn_only.instance_id())
            .expect("verify null-only backfill on ingest"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Microsoft.Windows.Shell_cw5n1h2txyewy".to_string()),
            package_sid: Some("S-1-15-2-filled-sid".to_string()),
        })
    );

    // 5. update_process_package_metadata updates both pending batch entries and committed rows via COALESCE.
    let id_pending = ProcessIdentity::new(205, 133_800_000_000_000_500);
    let ev_pending = SensorEvent::ProcessStart {
        identity: id_pending,
        parent_pid: 4,
        exe_path: r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_extra_metadata(
            &ev_pending,
            None,
            None,
            None,
            ProcessExtraMetadata {
                package_family_name: Some("Initial.Pkg_1"),
                ..Default::default()
            },
            false,
            "OBSERVED",
        )
        .expect("buffer pending row");
    assert!(
        store
            .update_process_package_metadata(
                &id_pending.instance_id(),
                Some("ShouldNotOverwrite.Pkg_1"),
                Some("S-1-15-2-555"),
            )
            .expect("backfill pending batch entry")
    );
    store.flush_batch().expect("flush backfilled pending row");
    assert_eq!(
        store
            .get_process_package_info(&id_pending.instance_id())
            .expect("query flushed backfilled row"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Initial.Pkg_1".to_string()),
            package_sid: Some("S-1-15-2-555".to_string()),
        })
    );

    // Also verify committed row backfill on id_none (204).
    assert!(
        store
            .update_process_package_metadata(
                &cases[3].0.instance_id(),
                Some("Committed.Pkg_2"),
                None,
            )
            .expect("backfill committed row")
    );
    assert_eq!(
        store
            .get_process_package_info(&cases[3].0.instance_id())
            .expect("query committed backfilled row"),
        Some(ProcessPackageRecord {
            package_family_name: Some("Committed.Pkg_2".to_string()),
            package_sid: None,
        })
    );
}
