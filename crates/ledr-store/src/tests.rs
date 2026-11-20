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
        "network_events",
        "processes",
    ];
    let expected_indexes = [
        "idx_alerts_proc_status",
        "idx_alerts_status_ts",
        "idx_canary_ts",
        "idx_dl_path",
        "idx_dl_sha256",
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

    // Verify all 7 AUTO-09 PRAGMAs on both writer and reader connections.
    for conn_guard in [writer, store.lock_reader().expect("lock reader")] {
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

        assert_eq!(jm.to_ascii_lowercase(), "wal");
        assert_eq!(sync, 1); // NORMAL
        assert_eq!(cache, -2048);
        assert_eq!(temp, 2); // MEMORY
        assert_eq!(mmap, 0);
        assert_eq!(auto_ckpt, 1000);
        assert_eq!(fk, 1);
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
