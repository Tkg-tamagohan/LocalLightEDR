use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, CanaryCategory,
    DownloadOriginRecord, ProcessIdentity, ProcessRecord, RuleScope, SensorEvent,
    STORE_BATCH_MAX_EVENTS,
};
use ledr_store::{
    default_alert_status, default_retention_days, sqlite_version, store_version, LedrStore,
};
use tempfile::TempDir;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DAY_MS: i64 = 86_400_000;

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

fn make_process_start(
    pid: u32,
    created_ms: i64,
    parent_pid: u32,
    exe_path: &str,
    cmd: &str,
) -> (ProcessIdentity, SensorEvent) {
    let identity = ProcessIdentity::new(pid, unix_ms_to_filetime(created_ms));
    let event = SensorEvent::ProcessStart {
        identity,
        parent_pid,
        exe_path: exe_path.to_string(),
        command_line: cmd.to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };
    (identity, event)
}

fn make_process_stop(pid: u32, exited_ms: i64) -> SensorEvent {
    SensorEvent::ProcessStop {
        pid,
        exit_time_100ns: unix_ms_to_filetime(exited_ms),
        exit_code: 0,
    }
}

fn make_alert(
    alert_id: &str,
    ts_ms: i64,
    proc_id: Option<&str>,
    status: AlertStatus,
    resolved_at_ms: Option<i64>,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms: ts_ms,
        severity: AlertSeverity::High,
        source_layer: "layer2".to_string(),
        rule_id: "sigma_lotl_test".to_string(),
        title: format!("Alert {alert_id}"),
        process_instance_id: proc_id.map(str::to_owned),
        process_suspended: status.is_unresolved(),
        status,
        context_json: r#"{"test":true}"#.to_string(),
        resolved_at_ms,
    }
}

#[test]
fn store_01_wal_pragmas_and_separated_readonly_connection() {
    assert!(!store_version().is_empty());
    assert!(!sqlite_version().is_empty());
    assert_eq!(default_retention_days(), 14);
    assert_eq!(default_alert_status(), AlertStatus::Pending);

    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("nested").join("ledr.db");
    let store = LedrStore::open(&db_path).expect("open file-backed LedrStore");

    let (journal_mode, cache_size, mmap_size) =
        store.verify_pragmas().expect("verify writer pragmas");
    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    assert_eq!(cache_size, -2048);
    assert_eq!(mmap_size, 0);

    let (r_mode, r_cache, r_mmap) = store
        .verify_reader_pragmas()
        .expect("verify reader pragmas");
    assert_eq!(r_mode.to_ascii_lowercase(), "wal");
    assert_eq!(r_cache, -2048);
    assert_eq!(r_mmap, 0);

    // Confirm separated read-only query connection actively rejects SQL writes.
    assert!(store
        .verify_reader_rejects_writes()
        .expect("verify reader rejects writes"));

    // Confirm writer commits and read-only query_flight_recorder serves the data.
    let (ident, proc_start) = make_process_start(
        4242,
        1_750_000_000_000,
        4,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
    );
    store
        .ingest_event(&proc_start, Some("4:1"), false, "")
        .expect("ingest process start");
    store.flush_batch().expect("flush process start");

    let snapshot = store
        .query_flight_recorder(50, Some(&ident.instance_id()))
        .expect("query flight recorder via read-only connection");
    assert_eq!(snapshot.processes.len(), 1);
    assert_eq!(
        snapshot.processes[0].process_instance_id,
        ident.instance_id()
    );
    assert_eq!(
        snapshot.processes[0].command_line.as_deref(),
        Some("cmd.exe /c whoami")
    );
}

#[test]
fn store_02_batch_buffering_canary_immediate_flush_and_checkpoint_truncate() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path: PathBuf = dir.path().join("batch_test.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let (ident, proc_start) = make_process_start(
        1000,
        1_750_000_000_000,
        4,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -NoProfile",
    );
    assert!(!store
        .ingest_event(&proc_start, Some("4:1"), false, "")
        .expect("buffer process start"));

    // Ingest 498 DNS queries -> total 499 buffered events, must remain buffered (< 500).
    for i in 0..498 {
        let dns = SensorEvent::DnsQuery {
            pid: 1000,
            query_name: format!("host-{i}.example.test"),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 1_750_000_000_100 + i64::from(i),
        };
        let flushed = store
            .ingest_event(&dns, Some(&ident.instance_id()), false, "")
            .expect("buffer dns query");
        assert!(
            !flushed,
            "must stay buffered below {STORE_BATCH_MAX_EVENTS}"
        );
    }
    assert_eq!(store.buffered_len(), STORE_BATCH_MAX_EVENTS - 1);
    let pre_flush_snap = store
        .query_flight_recorder(1000, None)
        .expect("query before batch flush");
    assert!(pre_flush_snap.processes.is_empty());
    assert!(pre_flush_snap.dns_queries.is_empty());

    // 500th event triggers automatic batch flush.
    let dns_500 = SensorEvent::DnsQuery {
        pid: 1000,
        query_name: "trigger-flush.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
        timestamp_ms: 1_750_000_001_000,
    };
    let auto_flushed = store
        .ingest_event(&dns_500, Some(&ident.instance_id()), true, "")
        .expect("ingest 500th event");
    assert!(auto_flushed, "500th buffered event must flush immediately");
    assert_eq!(store.buffered_len(), 0);

    let after_500_snap = store
        .query_flight_recorder(1000, None)
        .expect("query after 500-event flush");
    assert_eq!(after_500_snap.processes.len(), 1);
    assert_eq!(after_500_snap.dns_queries.len(), 499);

    // Explicit flush_batch test.
    for i in 0..10 {
        let net = SensorEvent::NetworkConnect {
            pid: 1000,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i + 1) as u8)),
            dst_port: 443,
            domain_hint: Some("c2.example.test".to_string()),
            timestamp_ms: 1_750_000_002_000 + i64::from(i),
        };
        assert!(!store
            .ingest_event(&net, None, false, "ALLOW")
            .expect("buffer network event"));
    }
    assert_eq!(store.buffered_len(), 10);
    assert_eq!(store.flush_batch().expect("explicit flush_batch"), 10);
    assert_eq!(store.buffered_len(), 0);

    // CanaryFileAccess must flush immediately even with prior buffered events.
    let buffered_dns = SensorEvent::DnsQuery {
        pid: 1000,
        query_name: "before-canary.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![],
        timestamp_ms: 1_750_000_003_000,
    };
    assert!(!store
        .ingest_event(&buffered_dns, None, false, "")
        .expect("buffer pre-canary dns"));
    assert_eq!(store.buffered_len(), 1);

    let canary = SensorEvent::CanaryFileAccess {
        pid: 1000,
        target_path: r"C:\Users\dev\.ssh\id_ed25519".to_string(),
        category: CanaryCategory::SshKey,
        access_mask: 0x0012_0089,
        is_write_or_delete: false,
        timestamp_ms: 1_750_000_003_100,
    };
    let canary_flushed = store
        .ingest_event(&canary, None, false, "SUSPEND")
        .expect("canary event");
    assert!(canary_flushed, "CanaryFileAccess must flush immediately");
    assert_eq!(store.buffered_len(), 0);

    // Buffer more events, then checkpoint_truncate must flush remaining buffer and truncate WAL.
    for i in 0..25 {
        let net = SensorEvent::NetworkConnect {
            pid: 1000,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i + 1) as u8)),
            dst_port: 8443,
            domain_hint: None,
            timestamp_ms: 1_750_000_004_000 + i64::from(i),
        };
        assert!(!store
            .ingest_event(&net, None, false, "ALLOW")
            .expect("buffer trailing network event"));
    }
    assert_eq!(store.buffered_len(), 25);

    store
        .checkpoint_truncate()
        .expect("checkpoint_truncate flushes batch and truncates WAL");
    assert_eq!(store.buffered_len(), 0);

    let final_snap = store
        .query_flight_recorder(1000, Some(&ident.instance_id()))
        .expect("query final snapshot");
    assert_eq!(final_snap.dns_queries.len(), 500);
    assert_eq!(final_snap.network_events.len(), 35);
    assert_eq!(final_snap.file_canary_events.len(), 1);
    assert_eq!(final_snap.file_canary_events[0].action_taken, "SUSPEND");

    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    if wal_path.exists() {
        let wal_len = std::fs::metadata(&wal_path).expect("stat wal").len();
        assert_eq!(wal_len, 0, "WAL file must be truncated to 0 bytes");
    }
}

#[test]
fn store_03_ttl_purge_prevents_parent_orphans_and_batches_over_500() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("ttl_purge.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let now_ms = 1_750_000_000_000i64;
    let expired_20d = now_ms - 20 * DAY_MS;
    let expired_18d = now_ms - 18 * DAY_MS;
    let expired_16d = now_ms - 16 * DAY_MS;
    let expired_15d = now_ms - 15 * DAY_MS;
    let recent_5d = now_ms - 5 * DAY_MS;
    let recent_1d = now_ms - DAY_MS;

    // Branch A: expired grandparent -> expired parent -> STILL RUNNING child.
    let (gp_a, gp_a_start) =
        make_process_start(100, expired_20d, 4, r"C:\Windows\System32\services.exe", "");
    let (p_a, p_a_start) = make_process_start(
        101,
        expired_18d,
        100,
        r"C:\Windows\System32\svchost.exe",
        "",
    );
    let (c_a, c_a_start) = make_process_start(102, expired_15d, 101, r"C:\Tools\worker.exe", "");

    // Branch B: expired parent -> recently exited (non-expired) child.
    let (p_b, p_b_start) = make_process_start(200, expired_20d, 4, r"C:\Windows\explorer.exe", "");
    let (c_b, c_b_start) = make_process_start(201, expired_16d, 200, r"C:\Tools\editor.exe", "");

    // Branch C & D: expired exited processes protected by PENDING and EXPIRED_SUSPENDED alerts.
    let (p_pending, p_pending_start) =
        make_process_start(300, expired_20d, 4, r"C:\Temp\suspect1.exe", "");
    let (p_suspended, p_suspended_start) =
        make_process_start(301, expired_20d, 4, r"C:\Temp\suspect2.exe", "");

    // Branch E: 3-generation completely expired dead branch (must purge bottom-up).
    let (dead_gp, dead_gp_start) =
        make_process_start(400, expired_20d, 4, r"C:\Temp\dead_gp.exe", "");
    let (dead_p, dead_p_start) =
        make_process_start(401, expired_18d, 400, r"C:\Temp\dead_p.exe", "");
    let (dead_c, dead_c_start) =
        make_process_start(402, expired_16d, 401, r"C:\Temp\dead_c.exe", "");

    for (ev, parent) in [
        (&gp_a_start, None),
        (&p_a_start, Some(gp_a.instance_id())),
        (&c_a_start, Some(p_a.instance_id())),
        (&p_b_start, None),
        (&c_b_start, Some(p_b.instance_id())),
        (&p_pending_start, None),
        (&p_suspended_start, None),
        (&dead_gp_start, None),
        (&dead_p_start, Some(dead_gp.instance_id())),
        (&dead_c_start, Some(dead_p.instance_id())),
    ] {
        store
            .ingest_event(ev, parent.as_deref(), false, "")
            .expect("ingest proc start");
    }

    for ev in [
        make_process_stop(100, expired_18d),
        make_process_stop(101, expired_16d),
        make_process_stop(200, expired_18d),
        make_process_stop(201, recent_5d),
        make_process_stop(300, expired_16d),
        make_process_stop(301, expired_16d),
        make_process_stop(400, expired_18d),
        make_process_stop(401, expired_16d),
        make_process_stop(402, expired_15d),
    ] {
        store
            .ingest_event(&ev, None, false, "")
            .expect("ingest proc stop");
    }
    store.flush_batch().expect("flush initial processes");

    // Unresolved alerts protecting p_pending and p_suspended.
    store
        .record_alert(&make_alert(
            "alrt-pending",
            expired_16d,
            Some(&p_pending.instance_id()),
            AlertStatus::Pending,
            None,
        ))
        .expect("record pending alert");
    store
        .record_alert(&make_alert(
            "alrt-suspended",
            expired_16d,
            Some(&p_suspended.instance_id()),
            AlertStatus::ExpiredSuspended,
            None,
        ))
        .expect("record expired_suspended alert");

    // > 500 expired rows across all purgeable tables + non-expired rows that must survive.
    for i in 0..1200 {
        let dns = SensorEvent::DnsQuery {
            pid: 402,
            query_name: format!("old-{i}.example.test"),
            query_type: 1,
            resolved_ips: vec![],
            timestamp_ms: expired_16d + i64::from(i),
        };
        store
            .ingest_event(&dns, Some(&dead_c.instance_id()), false, "")
            .expect("ingest old dns");
    }
    for i in 0..5 {
        let dns = SensorEvent::DnsQuery {
            pid: 102,
            query_name: format!("recent-{i}.example.test"),
            query_type: 1,
            resolved_ips: vec![],
            timestamp_ms: recent_1d + i64::from(i),
        };
        store
            .ingest_event(&dns, Some(&c_a.instance_id()), false, "")
            .expect("ingest recent dns");
    }

    for i in 0..650 {
        let net = SensorEvent::NetworkConnect {
            pid: 402,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 250 + 1) as u8)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: expired_16d + i64::from(i),
        };
        store
            .ingest_event(&net, Some(&dead_c.instance_id()), false, "ALLOW")
            .expect("ingest old net");
    }

    for i in 0..600 {
        let canary = SensorEvent::CanaryFileAccess {
            pid: 402,
            target_path: format!(r"C:\Users\dev\.env.{i}"),
            category: CanaryCategory::EnvFile,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: expired_16d + i64::from(i),
        };
        store
            .ingest_event(&canary, Some(&dead_c.instance_id()), false, "SUSPEND")
            .expect("ingest old canary");
    }

    for i in 0..600 {
        let leaf_pid = 10_000 + i;
        let (leaf_id, leaf_start) = make_process_start(
            leaf_pid,
            expired_20d + i64::from(i),
            4,
            r"C:\Temp\ephemeral.exe",
            "",
        );
        store
            .ingest_event(&leaf_start, None, false, "")
            .expect("ingest leaf start");
        store
            .ingest_event(
                &make_process_stop(leaf_pid, expired_16d + i64::from(i)),
                Some(&leaf_id.instance_id()),
                false,
                "",
            )
            .expect("ingest leaf stop");
    }
    store.flush_batch().expect("flush leaf procs");

    for i in 0..600 {
        store
            .record_alert(&make_alert(
                &format!("alrt-old-resolved-{i}"),
                expired_16d + i64::from(i),
                None,
                AlertStatus::Dismissed,
                Some(expired_15d),
            ))
            .expect("record old resolved alert");
        store
            .record_download_origin(&DownloadOriginRecord {
                id: None,
                file_path: format!(r"C:\Users\dev\Downloads\file-{i}.exe"),
                sha256: None,
                tab_url: "https://example.test/".to_string(),
                frame_url: None,
                referrer_url: None,
                downloaded_at_ms: expired_16d + i64::from(i),
            })
            .expect("record old download");
    }
    // Recent download that must survive.
    store
        .record_download_origin(&DownloadOriginRecord {
            id: None,
            file_path: r"C:\Users\dev\Downloads\fresh.exe".to_string(),
            sha256: Some("abc123".to_string()),
            tab_url: "https://example.test/fresh".to_string(),
            frame_url: None,
            referrer_url: None,
            downloaded_at_ms: recent_1d,
        })
        .expect("record fresh download");

    let stats1 = store
        .purge_expired(now_ms, 14)
        .expect("first purge_expired run");
    assert_eq!(stats1.dns_deleted, 1200);
    assert_eq!(stats1.network_deleted, 650);
    assert_eq!(stats1.canary_deleted, 600);
    assert_eq!(stats1.alerts_deleted, 600);
    assert_eq!(stats1.downloads_deleted, 600);
    // 600 leaf procs + dead_c + dead_p + dead_gp = 603.
    assert_eq!(stats1.processes_deleted, 603);

    // Verify protected ancestors and alert-referenced processes remain intact.
    let lineage_a = store
        .get_process_lineage(&c_a.instance_id())
        .expect("lineage A must remain intact");
    assert_eq!(lineage_a.len(), 3);
    assert_eq!(lineage_a[0].process_instance_id, gp_a.instance_id());
    assert_eq!(lineage_a[1].process_instance_id, p_a.instance_id());
    assert_eq!(lineage_a[2].process_instance_id, c_a.instance_id());

    let lineage_b = store
        .get_process_lineage(&c_b.instance_id())
        .expect("lineage B must remain intact");
    assert_eq!(lineage_b.len(), 2);

    assert_eq!(
        store
            .get_process_lineage(&p_pending.instance_id())
            .expect("pending proc kept")
            .len(),
        1
    );
    assert_eq!(
        store
            .get_process_lineage(&p_suspended.instance_id())
            .expect("suspended proc kept")
            .len(),
        1
    );
    assert!(store
        .get_process_lineage(&dead_gp.instance_id())
        .expect("dead branch purged")
        .is_empty());

    let remaining_alerts = store.list_alerts(None, 100).expect("list remaining alerts");
    assert_eq!(remaining_alerts.len(), 2);

    let snap_after_1 = store
        .query_flight_recorder(100, None)
        .expect("query after first purge");
    assert_eq!(snap_after_1.dns_queries.len(), 5);
    assert_eq!(snap_after_1.download_origins.len(), 1);
    assert_eq!(snap_after_1.processes.len(), 7);

    // Now exit active_child_a in the past and resolve both alerts.
    store
        .ingest_event(
            &make_process_stop(102, expired_15d),
            Some(&c_a.instance_id()),
            false,
            "",
        )
        .expect("stop c_a");
    store.flush_batch().expect("flush c_a stop");

    assert!(store
        .update_alert_status("alrt-pending", AlertStatus::ApprovedOnce, Some(now_ms))
        .expect("resolve pending alert"));
    assert!(store
        .update_alert_status(
            "alrt-suspended",
            AlertStatus::TerminatedBlocked,
            Some(now_ms)
        )
        .expect("resolve suspended alert"));

    // Advance 10 days so recent_child_b (exited 5d before now_ms -> 15d before now_ms + 10d) expires.
    let now_later = now_ms + 10 * DAY_MS;
    let stats2 = store
        .purge_expired(now_later, 14)
        .expect("second purge_expired after resolution");
    assert_eq!(stats2.processes_deleted, 7);
    assert_eq!(stats2.alerts_deleted, 2);

    let final_snap = store
        .query_flight_recorder(100, None)
        .expect("query after second purge");
    assert!(final_snap.processes.is_empty());
    assert!(store
        .list_alerts(None, 100)
        .expect("no alerts left")
        .is_empty());
}

#[test]
fn store_04_process_lineage_order_and_cycle_safety() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let t0 = 1_750_000_000_000i64;
    let root = ProcessRecord {
        process_instance_id: "4:1".to_string(),
        pid: 4,
        parent_instance_id: None,
        ppid: 0,
        exe_path: r"System".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: Some("Microsoft Windows".to_string()),
        is_trusted_os: true,
        user_sid: Some("S-1-5-18".to_string()),
        origin_url: None,
        created_at_ms: t0,
        exited_at_ms: None,
    };
    let explorer = ProcessRecord {
        process_instance_id: "100:2".to_string(),
        pid: 100,
        parent_instance_id: Some("4:1".to_string()),
        ppid: 4,
        exe_path: r"C:\Windows\explorer.exe".to_string(),
        command_line: Some(r"C:\Windows\explorer.exe".to_string()),
        sha256: None,
        signer_subject: Some("Microsoft Windows".to_string()),
        is_trusted_os: true,
        user_sid: Some("S-1-5-21-1000".to_string()),
        origin_url: None,
        created_at_ms: t0 + 100,
        exited_at_ms: None,
    };
    let cmd = ProcessRecord {
        process_instance_id: "200:3".to_string(),
        pid: 200,
        parent_instance_id: Some("100:2".to_string()),
        ppid: 100,
        exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
        command_line: Some("cmd.exe /c powershell -enc AAAA".to_string()),
        sha256: None,
        signer_subject: Some("Microsoft Windows".to_string()),
        is_trusted_os: true,
        user_sid: Some("S-1-5-21-1000".to_string()),
        origin_url: None,
        created_at_ms: t0 + 200,
        exited_at_ms: None,
    };
    let ps = ProcessRecord {
        process_instance_id: "300:4".to_string(),
        pid: 300,
        parent_instance_id: Some("200:3".to_string()),
        ppid: 200,
        exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        command_line: Some("powershell -enc AAAA".to_string()),
        sha256: None,
        signer_subject: Some("Microsoft Windows".to_string()),
        is_trusted_os: true,
        user_sid: Some("S-1-5-21-1000".to_string()),
        origin_url: None,
        created_at_ms: t0 + 300,
        exited_at_ms: None,
    };

    for proc_rec in [&root, &explorer, &cmd, &ps] {
        store
            .upsert_process_record(proc_rec)
            .expect("upsert lineage proc");
    }

    let lineage = store
        .get_process_lineage("300:4")
        .expect("get root-to-leaf lineage");
    let ids: Vec<&str> = lineage
        .iter()
        .map(|p| p.process_instance_id.as_str())
        .collect();
    assert_eq!(ids, vec!["4:1", "100:2", "200:3", "300:4"]);

    assert!(store
        .get_process_lineage("99999:0")
        .expect("missing process lineage")
        .is_empty());

    // Self-referential cycle guard.
    let self_cycle = ProcessRecord {
        process_instance_id: "500:5".to_string(),
        pid: 500,
        parent_instance_id: Some("500:5".to_string()),
        ppid: 500,
        exe_path: r"C:\Temp\loop.exe".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: None,
        origin_url: None,
        created_at_ms: t0 + 400,
        exited_at_ms: None,
    };
    store
        .upsert_process_record(&self_cycle)
        .expect("insert self-cycle");
    let self_lineage = store
        .get_process_lineage("500:5")
        .expect("self-cycle lineage terminates");
    assert_eq!(self_lineage.len(), 1);
    assert_eq!(self_lineage[0].process_instance_id, "500:5");

    // 2-node mutual cycle guard (600:6 <-> 601:7).
    let cyc_a = ProcessRecord {
        process_instance_id: "600:6".to_string(),
        pid: 600,
        parent_instance_id: Some("601:7".to_string()),
        ppid: 601,
        exe_path: r"C:\Temp\a.exe".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: None,
        origin_url: None,
        created_at_ms: t0 + 500,
        exited_at_ms: None,
    };
    let cyc_b = ProcessRecord {
        process_instance_id: "601:7".to_string(),
        pid: 601,
        parent_instance_id: Some("600:6".to_string()),
        ppid: 600,
        exe_path: r"C:\Temp\b.exe".to_string(),
        command_line: None,
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: None,
        origin_url: None,
        created_at_ms: t0 + 501,
        exited_at_ms: None,
    };
    store.upsert_process_record(&cyc_a).expect("insert cyc_a");
    store.upsert_process_record(&cyc_b).expect("insert cyc_b");

    let cyc_lineage = store
        .get_process_lineage("600:6")
        .expect("mutual cycle lineage terminates");
    let cyc_ids: Vec<&str> = cyc_lineage
        .iter()
        .map(|p| p.process_instance_id.as_str())
        .collect();
    assert_eq!(cyc_ids, vec!["601:7", "600:6"]);

    // Verify allowlist rules CRUD & in-memory checkpoint_truncate.
    let rule = AllowlistRuleRecord {
        rule_id: "rule-allow-1".to_string(),
        scope: RuleScope::ProcessAllow,
        exe_path_pattern: r"C:\Program Files\Dev\tool.exe".to_string(),
        sha256: Some("deadbeef".to_string()),
        signer_subject: Some("Dev Corp".to_string()),
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: t0,
        created_by: "user".to_string(),
    };
    store.upsert_rule(&rule).expect("upsert rule");
    let rules = store
        .list_rules(Some(RuleScope::ProcessAllow))
        .expect("list process allow rules");
    assert_eq!(rules, vec![rule.clone()]);
    assert!(store.delete_rule("rule-allow-1").expect("delete rule"));
    assert!(!store
        .delete_rule("rule-allow-1")
        .expect("delete missing rule"));
    assert!(store.list_rules(None).expect("list empty rules").is_empty());

    store
        .checkpoint_truncate()
        .expect("in-memory checkpoint_truncate succeeds");
}
