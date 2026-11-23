use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, CanaryCategory,
    DownloadOriginRecord, ProcessIdentity, ProcessRecord, RuleScope, SensorEvent,
    STORE_BATCH_MAX_EVENTS,
};
use ledr_store::{
    default_alert_status, default_retention_days, sqlite_version, store_version, LedrStore,
};
use rusqlite::{Connection, OpenFlags};
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
    assert_eq!(r_cache, -512);
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

#[test]
fn store_05_alert_failure_preserves_buffered_batch() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("alert_fail_preserves_batch.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let (proc_id, proc_start) = make_process_start(
        700,
        1_750_000_000_000,
        4,
        r"C:\Temp\beacon.exe",
        "beacon.exe --poll",
    );
    let dns = SensorEvent::DnsQuery {
        pid: 700,
        query_name: "c2-fail.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
        timestamp_ms: 1_750_000_000_100,
    };
    let net = SensorEvent::NetworkConnect {
        pid: 700,
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        dst_port: 443,
        domain_hint: Some("c2-fail.example.test".to_string()),
        timestamp_ms: 1_750_000_000_200,
    };

    assert!(!store
        .ingest_event(&proc_start, Some("4:1"), false, "")
        .expect("buffer proc start"));
    assert!(!store
        .ingest_event(&dns, Some(&proc_id.instance_id()), true, "")
        .expect("buffer dns"));
    assert!(!store
        .ingest_event(&net, Some(&proc_id.instance_id()), false, "OBSERVED")
        .expect("buffer net"));
    assert_eq!(store.buffered_len(), 3);

    // Inject an INSERT failure on alerts (simulating disk full / SQLite abort).
    let fault_conn = Connection::open(&db_path).expect("open secondary sqlite connection");
    fault_conn
        .execute_batch(
            "CREATE TRIGGER fail_alert_insert
             BEFORE INSERT ON alerts
             BEGIN
                 SELECT RAISE(ABORT, 'simulated disk full');
             END;",
        )
        .expect("create fail_alert_insert trigger");

    let alert = make_alert(
        "alrt-fail-05",
        1_750_000_000_300,
        Some(&proc_id.instance_id()),
        AlertStatus::Pending,
        None,
    );
    let err = store
        .record_alert(&alert)
        .expect_err("record_alert must fail when trigger aborts");
    assert!(err.to_string().contains("simulated disk full"));

    // Buffered events must remain intact and uncommitted in the batch buffer.
    assert_eq!(store.buffered_len(), 3);
    let pre_snap = store
        .query_flight_recorder(50, None)
        .expect("query after failed alert tx");
    assert!(pre_snap.processes.is_empty());
    assert!(pre_snap.dns_queries.is_empty());
    assert!(pre_snap.network_events.is_empty());
    assert!(store
        .list_alerts(None, 10)
        .expect("no alert persisted")
        .is_empty());

    // Drop the failure trigger and verify flush_batch persists all preserved events.
    fault_conn
        .execute_batch("DROP TRIGGER fail_alert_insert;")
        .expect("drop fail_alert_insert trigger");

    let flushed = store
        .flush_batch()
        .expect("flush_batch persists preserved events");
    assert_eq!(flushed, 3);
    assert_eq!(store.buffered_len(), 0);

    let post_snap = store
        .query_flight_recorder(50, Some(&proc_id.instance_id()))
        .expect("query after flush");
    assert_eq!(post_snap.processes.len(), 1);
    assert_eq!(post_snap.dns_queries.len(), 1);
    assert_eq!(post_snap.network_events.len(), 1);
    assert_eq!(post_snap.dns_queries[0].query_name, "c2-fail.example.test");

    // Also verify flush_batch failure preserves newly buffered events.
    let extra_dns = SensorEvent::DnsQuery {
        pid: 700,
        query_name: "after-recovery.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![],
        timestamp_ms: 1_750_000_000_400,
    };
    assert!(!store
        .ingest_event(&extra_dns, Some(&proc_id.instance_id()), false, "")
        .expect("buffer extra dns"));
    assert_eq!(store.buffered_len(), 1);

    fault_conn
        .execute_batch(
            "CREATE TRIGGER fail_dns_insert
             BEFORE INSERT ON dns_queries
             BEGIN
                 SELECT RAISE(ABORT, 'simulated dns write error');
             END;",
        )
        .expect("create fail_dns_insert trigger");
    assert!(store.flush_batch().is_err());
    assert_eq!(store.buffered_len(), 1);

    fault_conn
        .execute_batch("DROP TRIGGER fail_dns_insert;")
        .expect("drop fail_dns_insert trigger");
    assert_eq!(store.flush_batch().expect("flush recovered extra dns"), 1);
    assert_eq!(store.buffered_len(), 0);
}

#[test]
fn store_06_pid_reuse_time_window_attribution() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let (proc_a, proc_a_start) =
        make_process_start(42, 1000, 4, r"C:\Temp\proc_a.exe", "proc_a.exe --first");
    let proc_a_stop = make_process_stop(42, 2000);
    let (proc_b, proc_b_start) =
        make_process_start(42, 3000, 4, r"C:\Temp\proc_b.exe", "proc_b.exe --reused");

    store
        .ingest_event(&proc_a_start, Some("4:1"), false, "")
        .expect("ingest proc A start");
    store
        .ingest_event(&proc_a_stop, Some(&proc_a.instance_id()), false, "")
        .expect("ingest proc A stop");
    store
        .ingest_event(&proc_b_start, Some("4:1"), false, "")
        .expect("ingest proc B start");
    store.flush_batch().expect("flush processes");

    // BUG_0006: Upserting a snapshot of Process A with exited_at_ms=None must preserve exited=2000.
    store
        .upsert_process_record(&ProcessRecord {
            process_instance_id: proc_a.instance_id(),
            pid: 42,
            parent_instance_id: Some("4:1".to_string()),
            ppid: 4,
            exe_path: r"C:\Temp\proc_a.exe".to_string(),
            command_line: Some("proc_a.exe --first".to_string()),
            sha256: Some("aaaa".to_string()),
            signer_subject: None,
            is_trusted_os: false,
            user_sid: Some("S-1-5-21-1000".to_string()),
            origin_url: None,
            created_at_ms: 1000,
            exited_at_ms: None,
        })
        .expect("upsert snapshot over exited proc A");
    let snap_a_check = store
        .query_flight_recorder(10, Some(&proc_a.instance_id()))
        .expect("query proc A");
    assert_eq!(snap_a_check.processes[0].exited_at_ms, Some(2000));
    assert_eq!(snap_a_check.processes[0].sha256.as_deref(), Some("aaaa"));

    // BUG_0006: An older ProcessStop (exit=2000) must never mark newer Process B (created=3000) exited.
    store
        .ingest_event(&make_process_stop(42, 2000), None, false, "")
        .expect("ingest stale stop without hint");
    store
        .ingest_event(
            &make_process_stop(42, 2000),
            Some(&proc_b.instance_id()),
            false,
            "",
        )
        .expect("ingest stale stop with wrong hint");
    store.flush_batch().expect("flush stale stops");

    let snap_b_check = store
        .query_flight_recorder(10, Some(&proc_b.instance_id()))
        .expect("query proc B");
    assert_eq!(snap_b_check.processes[0].exited_at_ms, None);

    // BUG_0002: DnsQuery at ts=1500 must resolve to Process A even when hinted with Process B or None.
    let dns_wrong_hint = SensorEvent::DnsQuery {
        pid: 42,
        query_name: "a-wrong-hint.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        timestamp_ms: 1500,
    };
    let dns_no_hint = SensorEvent::DnsQuery {
        pid: 42,
        query_name: "a-no-hint.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
        timestamp_ms: 1500,
    };
    let dns_during_b = SensorEvent::DnsQuery {
        pid: 42,
        query_name: "b-stale-hint.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 36))],
        timestamp_ms: 3500,
    };
    let dns_gap = SensorEvent::DnsQuery {
        pid: 42,
        query_name: "gap-window.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![],
        timestamp_ms: 2500,
    };

    store
        .ingest_event(&dns_wrong_hint, Some(&proc_b.instance_id()), false, "")
        .expect("ingest dns with out-of-window hint B");
    store
        .ingest_event(&dns_no_hint, None, false, "")
        .expect("ingest dns with no hint");
    store
        .ingest_event(&dns_during_b, Some(&proc_a.instance_id()), false, "")
        .expect("ingest dns during B with stale hint A");
    store
        .ingest_event(&dns_gap, Some(&proc_b.instance_id()), false, "")
        .expect("ingest dns in gap with out-of-window hint B");
    store.flush_batch().expect("flush dns queries");

    let snap_a = store
        .query_flight_recorder(20, Some(&proc_a.instance_id()))
        .expect("query flight recorder for proc A");
    let a_domains: Vec<&str> = snap_a
        .dns_queries
        .iter()
        .map(|d| d.query_name.as_str())
        .collect();
    assert_eq!(snap_a.dns_queries.len(), 2);
    assert!(a_domains.contains(&"a-wrong-hint.example.test"));
    assert!(a_domains.contains(&"a-no-hint.example.test"));

    let snap_b = store
        .query_flight_recorder(20, Some(&proc_b.instance_id()))
        .expect("query flight recorder for proc B");
    assert_eq!(snap_b.dns_queries.len(), 1);
    assert_eq!(
        snap_b.dns_queries[0].query_name,
        "b-stale-hint.example.test"
    );

    let snap_unknown = store
        .query_flight_recorder(20, Some("42:0"))
        .expect("query flight recorder for gap fallback");
    assert_eq!(snap_unknown.dns_queries.len(), 1);
    assert_eq!(
        snap_unknown.dns_queries[0].query_name,
        "gap-window.example.test"
    );

    // Overlapping active rows for PID 42 with a stale hint for the older incarnation must
    // still resolve to the newer incarnation via index-first lookup.
    let overlap_store = LedrStore::open_in_memory().expect("open overlap store");
    let (overlap_old, overlap_old_start) =
        make_process_start(42, 1000, 4, r"C:\Temp\overlap_old.exe", "overlap_old.exe");
    let (overlap_new, overlap_new_start) =
        make_process_start(42, 2000, 4, r"C:\Temp\overlap_new.exe", "overlap_new.exe");
    overlap_store
        .ingest_event(&overlap_new_start, Some("4:1"), false, "")
        .expect("ingest overlap new");
    overlap_store
        .ingest_event(&overlap_old_start, Some("4:1"), false, "")
        .expect("ingest overlap old");
    overlap_store.flush_batch().expect("flush overlapping procs");

    let overlap_dns = SensorEvent::DnsQuery {
        pid: 42,
        query_name: "overlap-stale-hint.example.test".to_string(),
        query_type: 1,
        resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 37))],
        timestamp_ms: 2500,
    };
    overlap_store
        .ingest_event(&overlap_dns, Some(&overlap_old.instance_id()), false, "")
        .expect("ingest dns with stale older hint");
    overlap_store.flush_batch().expect("flush overlap dns");

    let overlap_new_snap = overlap_store
        .query_flight_recorder(10, Some(&overlap_new.instance_id()))
        .expect("query overlap new");
    assert_eq!(overlap_new_snap.dns_queries.len(), 1);
    assert_eq!(
        overlap_new_snap.dns_queries[0].query_name,
        "overlap-stale-hint.example.test"
    );
    let overlap_old_snap = overlap_store
        .query_flight_recorder(10, Some(&overlap_old.instance_id()))
        .expect("query overlap old");
    assert!(overlap_old_snap.dns_queries.is_empty());
}

#[test]
fn store_07_reconcile_stale_running_processes_on_restart() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("reconcile_restart.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let now_ms = 1_750_000_000_000i64;
    let old_created_ms = now_ms - 20 * DAY_MS;
    let reconciled_at_ms = now_ms - 15 * DAY_MS;

    let (stale_proc, stale_start) = make_process_start(
        501,
        old_created_ms,
        4,
        r"C:\Temp\stale_worker.exe",
        "stale_worker.exe",
    );
    let (live_proc, live_start) = make_process_start(
        502,
        old_created_ms,
        4,
        r"C:\Windows\System32\svchost.exe",
        "svchost.exe -k netsvcs",
    );
    let (newer_proc, newer_start) = make_process_start(
        503,
        reconciled_at_ms + 5000,
        4,
        r"C:\Temp\newer_worker.exe",
        "newer_worker.exe",
    );

    // Flush stale_proc and newer_proc, leave live_proc buffered to verify flush_batch runs first.
    store
        .ingest_event(&stale_start, Some("4:1"), false, "")
        .expect("ingest stale_proc");
    store
        .ingest_event(&newer_start, Some("4:1"), false, "")
        .expect("ingest newer_proc");
    store.flush_batch().expect("flush initial processes");

    store
        .ingest_event(&live_start, Some("4:1"), false, "")
        .expect("buffer live_proc");
    assert_eq!(store.buffered_len(), 1);

    let updated = store
        .reconcile_stale_running_processes(&[live_proc.instance_id()], reconciled_at_ms)
        .expect("reconcile stale running processes");
    assert_eq!(updated, 1);
    assert_eq!(store.buffered_len(), 0);

    let stale_snap = store
        .query_flight_recorder(10, Some(&stale_proc.instance_id()))
        .expect("query stale_proc");
    assert_eq!(stale_snap.processes.len(), 1);
    assert_eq!(stale_snap.processes[0].exited_at_ms, Some(reconciled_at_ms));

    let live_snap = store
        .query_flight_recorder(10, Some(&live_proc.instance_id()))
        .expect("query live_proc");
    assert_eq!(live_snap.processes.len(), 1);
    assert_eq!(live_snap.processes[0].exited_at_ms, None);

    let newer_snap = store
        .query_flight_recorder(10, Some(&newer_proc.instance_id()))
        .expect("query newer_proc");
    assert_eq!(newer_snap.processes.len(), 1);
    assert_eq!(newer_snap.processes[0].exited_at_ms, None);

    // Stale reconciled process is past 14-day retention TTL and must be purged.
    let purge_stats = store
        .purge_expired(now_ms, 14)
        .expect("purge expired reconciled process");
    assert_eq!(purge_stats.processes_deleted, 1);

    assert!(store
        .query_flight_recorder(10, Some(&stale_proc.instance_id()))
        .expect("stale_proc purged")
        .processes
        .is_empty());
    assert_eq!(
        store
            .query_flight_recorder(10, Some(&live_proc.instance_id()))
            .expect("live_proc retained")
            .processes
            .len(),
        1
    );
}

#[test]
fn store_08_pid_created_index_query_plan_and_shutdown_interrupts_purge() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("store_08_index_and_shutdown.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    // 1. Verify SQLite uses idx_processes_pid_created for (pid, event_ts_ms) time-window lookups
    //    and idx_alerts_proc_status for purge's unresolved-alert existence check.
    let plan = store
        .explain_pid_lookup_plan()
        .expect("explain pid lookup plan");
    assert!(
        plan.iter().any(|detail| {
            detail.contains("SEARCH processes USING")
                && detail.contains("idx_processes_pid_created")
        }),
        "expected SEARCH processes USING ... idx_processes_pid_created, got: {plan:?}"
    );

    let inspect_conn = Connection::open(&db_path).expect("open inspection sqlite connection");
    let mut alert_plan_stmt = inspect_conn
        .prepare(
            "EXPLAIN QUERY PLAN
             SELECT 1 FROM alerts
             WHERE process_instance_id = ?1
               AND status IN ('PENDING', 'EXPIRED_SUSPENDED')",
        )
        .expect("prepare alert query plan");
    let alert_plan: Vec<String> = alert_plan_stmt
        .query_map(["4:1"], |row| row.get(3))
        .expect("query alert plan")
        .map(|r| r.expect("alert plan detail"))
        .collect();
    assert!(
        alert_plan.iter().any(|detail| {
            detail.contains("SEARCH alerts USING") && detail.contains("idx_alerts_proc_status")
        }),
        "expected SEARCH alerts USING ... idx_alerts_proc_status, got: {alert_plan:?}"
    );

    // 2. Verify pre-session candidate reconciliation (BUG_0001 & BUG_0002).
    let now_ms = 1_750_000_000_000i64;
    let old_created_ms = now_ms - 20 * DAY_MS;
    let reconciled_at_ms = now_ms - 15 * DAY_MS;

    let (stale_candidate, stale_start) = make_process_start(
        601,
        old_created_ms,
        4,
        r"C:\Temp\stale_candidate.exe",
        "stale_candidate.exe",
    );
    let (live_candidate, live_start) = make_process_start(
        602,
        old_created_ms,
        4,
        r"C:\Windows\System32\svchost.exe",
        "svchost.exe",
    );

    store
        .ingest_event(&stale_start, Some("4:1"), false, "")
        .expect("ingest stale_candidate");
    store
        .ingest_event(&live_start, Some("4:1"), false, "")
        .expect("buffer live_candidate");
    assert_eq!(store.buffered_len(), 2);

    let candidates = store
        .list_running_process_instance_ids()
        .expect("list running candidates");
    assert_eq!(store.buffered_len(), 0);
    assert_eq!(candidates.len(), 2);
    assert!(candidates.contains(&stale_candidate.instance_id()));
    assert!(candidates.contains(&live_candidate.instance_id()));

    // A new ETW process observed after capturing candidates is NOT in candidates and NOT in
    // active_instance_ids; reconciliation must leave it running (BUG_0001).
    let (new_etw_proc, new_etw_start) = make_process_start(
        603,
        old_created_ms + 5000,
        4,
        r"C:\Temp\new_etw_proc.exe",
        "new_etw_proc.exe",
    );
    store
        .ingest_event(&new_etw_start, Some("4:1"), false, "")
        .expect("ingest new_etw_proc");
    store.flush_batch().expect("flush new_etw_proc");

    // Empty active_instance_ids or empty candidate_instance_ids safety guards (BUG_0002).
    assert_eq!(
        store
            .reconcile_stale_running_candidates(&candidates, &[], reconciled_at_ms)
            .expect("empty active_ids guard"),
        0
    );
    assert_eq!(
        store
            .reconcile_stale_running_candidates(
                &[],
                &[live_candidate.instance_id()],
                reconciled_at_ms
            )
            .expect("empty candidates guard"),
        0
    );
    assert_eq!(
        store
            .reconcile_stale_running_processes(&[], reconciled_at_ms)
            .expect("legacy reconcile empty active_ids guard"),
        0
    );

    let reconciled = store
        .reconcile_stale_running_candidates(
            &candidates,
            &[live_candidate.instance_id()],
            reconciled_at_ms,
        )
        .expect("reconcile stale candidates");
    assert_eq!(reconciled, 1);

    assert_eq!(
        store
            .query_flight_recorder(10, Some(&stale_candidate.instance_id()))
            .expect("query stale_candidate")
            .processes[0]
            .exited_at_ms,
        Some(reconciled_at_ms)
    );
    assert_eq!(
        store
            .query_flight_recorder(10, Some(&live_candidate.instance_id()))
            .expect("query live_candidate")
            .processes[0]
            .exited_at_ms,
        None
    );
    assert_eq!(
        store
            .query_flight_recorder(10, Some(&new_etw_proc.instance_id()))
            .expect("query new_etw_proc")
            .processes[0]
            .exited_at_ms,
        None
    );

    // 3. Mid-lifecycle checkpoint_truncate must NOT flip shutdown_requested, so purge_expired works.
    store
        .checkpoint_truncate()
        .expect("mid-lifecycle checkpoint_truncate");
    assert!(!store.is_shutdown_requested());
    let pre_shutdown_purge = store
        .purge_expired(now_ms, 14)
        .expect("purge expired reconciled candidate before shutdown");
    assert_eq!(pre_shutdown_purge.processes_deleted, 1);

    // 4. Seed >1,500 expired processes, request_shutdown(), and verify purge_expired stops
    //    immediately (0 deleted) and checkpoint_truncate completes quickly (BUG_0004).
    let expired_start_ms = now_ms - 20 * DAY_MS;
    let expired_exit_ms = now_ms - 16 * DAY_MS;
    for i in 0..1_600u32 {
        let pid = 20_000 + i;
        let (proc_id, proc_start) = make_process_start(
            pid,
            expired_start_ms + i64::from(i),
            4,
            r"C:\Temp\bulk_expired.exe",
            "",
        );
        store
            .ingest_event(&proc_start, None, false, "")
            .expect("ingest bulk expired start");
        store
            .ingest_event(
                &make_process_stop(pid, expired_exit_ms + i64::from(i)),
                Some(&proc_id.instance_id()),
                false,
                "",
            )
            .expect("ingest bulk expired stop");
    }
    store.flush_batch().expect("flush 1600 expired processes");

    store.request_shutdown();
    assert!(store.is_shutdown_requested());

    let shutdown_purge = store
        .purge_expired(now_ms, 14)
        .expect("purge_expired after request_shutdown");
    assert_eq!(shutdown_purge.processes_deleted, 0);

    let ckpt_start = Instant::now();
    store
        .checkpoint_truncate()
        .expect("checkpoint_truncate after request_shutdown");
    assert!(
        ckpt_start.elapsed() < Duration::from_secs(5),
        "checkpoint_truncate took too long after shutdown: {:?}",
        ckpt_start.elapsed()
    );

    let remaining_expired: i64 = inspect_conn
        .query_row(
            "SELECT COUNT(*) FROM processes WHERE exited_at_ms IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("count remaining expired processes");
    assert_eq!(remaining_expired, 1_600);
}

#[test]
fn store_09_same_ms_pid_reuse_prefers_newer_create_time_100ns() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    // Two incarnations of PID 42 whose create times differ by 5 ticks (< 1 ms), so both rows
    // share the same created_at_ms while instance ids differ in the 100 ns component.
    let base_ms: i64 = 1_750_000_000_000;
    let older_ident = ProcessIdentity::new(42, unix_ms_to_filetime(base_ms));
    let newer_ident = ProcessIdentity::new(42, unix_ms_to_filetime(base_ms) + 5);
    let older_start = SensorEvent::ProcessStart {
        identity: older_ident,
        parent_pid: 4,
        exe_path: r"C:\Temp\older.exe".to_string(),
        command_line: "older.exe".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };
    let newer_start = SensorEvent::ProcessStart {
        identity: newer_ident,
        parent_pid: 4,
        exe_path: r"C:\Temp\newer.exe".to_string(),
        command_line: "newer.exe".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };

    store
        .ingest_event(&older_start, Some("4:1"), false, "")
        .expect("ingest older same-ms start");
    store
        .ingest_event(&newer_start, Some("4:1"), false, "")
        .expect("ingest newer same-ms start");
    store.flush_batch().expect("flush same-ms processes");

    let net = SensorEvent::NetworkConnect {
        pid: 42,
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        dst_port: 443,
        domain_hint: None,
        timestamp_ms: base_ms + 500,
    };
    store
        .ingest_event(&net, None, false, "ALLOW")
        .expect("ingest network event without hint");
    store.flush_batch().expect("flush network event");

    let snap = store
        .query_flight_recorder(20, Some(&newer_ident.instance_id()))
        .expect("query flight recorder for newer row");
    let net_row = snap
        .network_events
        .iter()
        .find(|n| n.dst_port == 443)
        .expect("network event recorded");
    assert_eq!(
        net_row.process_instance_id,
        newer_ident.instance_id(),
        "same-created_at_ms tie must resolve to the row with the newer 100ns create time"
    );
}

/// `PR23-U2-01`: Superseded placeholder exit must apply even when SQLite persistence order
/// reverses relative to in-memory `ActiveProcessTable` order (both within a single batch and
/// across separate `flush_batch` transactions).
#[test]
fn store_10_pr23_u2_out_of_order_superseded_exit_closes_late_placeholder() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let base_ms: i64 = 1_760_000_000_000;

    // Case A: Reversed order within the same batch (`4610:<real>` with superseded `4610:0` first,
    // then `4610:0` placeholder second).
    let real_a = ProcessIdentity::new(4610, unix_ms_to_filetime(base_ms));
    let placeholder_a = ProcessIdentity::new(4610, 0);
    let real_a_start = SensorEvent::ProcessStart {
        identity: real_a,
        parent_pid: 4,
        exe_path: r"C:\Temp\reordered_same_batch.exe".to_string(),
        command_line: "reordered_same_batch.exe".to_string(),
        user_sid: None,
    };
    let placeholder_a_start = SensorEvent::ProcessStart {
        identity: placeholder_a,
        parent_pid: 4,
        exe_path: r"C:\Temp\reordered_same_batch.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_lifecycle(
            &real_a_start,
            Some("4:1"),
            None,
            Some((&placeholder_a.instance_id(), base_ms + 50)),
            false,
            "OBSERVED",
        )
        .expect("ingest superseding start A first");
    store
        .ingest_event_with_lifecycle(&placeholder_a_start, Some("4:1"), None, None, false, "OBSERVED")
        .expect("ingest late placeholder A second");
    store.flush_batch().expect("flush same-batch reversed pair");

    let snap_a = store
        .query_flight_recorder(20, None)
        .expect("query flight recorder A");
    let ph_a = snap_a
        .processes
        .iter()
        .find(|p| p.process_instance_id == placeholder_a.instance_id())
        .expect("placeholder A row exists");
    let rl_a = snap_a
        .processes
        .iter()
        .find(|p| p.process_instance_id == real_a.instance_id())
        .expect("real A row exists");
    assert!(
        ph_a.exited_at_ms.is_some_and(|ex| ex >= ph_a.created_at_ms),
        "same-batch late placeholder 4610:0 must be closed (created={}, exited={:?})",
        ph_a.created_at_ms,
        ph_a.exited_at_ms
    );
    assert_eq!(rl_a.exited_at_ms, None, "real A row must remain running");

    // Case B: Reversed order across two separate transactions (`flush #1` commits `4611:<real>`
    // with superseded `4611:0`; `flush #2` later inserts `4611:0`).
    let real_b = ProcessIdentity::new(4611, unix_ms_to_filetime(base_ms + 1_000));
    let placeholder_b = ProcessIdentity::new(4611, 0);
    let real_b_start = SensorEvent::ProcessStart {
        identity: real_b,
        parent_pid: 4,
        exe_path: r"C:\Temp\reordered_cross_tx.exe".to_string(),
        command_line: "reordered_cross_tx.exe".to_string(),
        user_sid: None,
    };
    let placeholder_b_start = SensorEvent::ProcessStart {
        identity: placeholder_b,
        parent_pid: 4,
        exe_path: r"C:\Temp\reordered_cross_tx.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    store
        .ingest_event_with_lifecycle(
            &real_b_start,
            Some("4:1"),
            None,
            Some((&placeholder_b.instance_id(), base_ms + 1_050)),
            false,
            "OBSERVED",
        )
        .expect("ingest superseding start B");
    store.flush_batch().expect("flush tx #1 with real B only");

    // Verify no synthetic empty row was prematurely fabricated for 4611:0 before it arrives.
    let mid_b = store
        .query_flight_recorder(20, Some(&placeholder_b.instance_id()))
        .expect("query before late placeholder B");
    assert!(
        mid_b.processes.is_empty(),
        "store must not fabricate placeholder row before late ProcessStart arrives"
    );

    store
        .ingest_event_with_lifecycle(&placeholder_b_start, Some("4:1"), None, None, false, "OBSERVED")
        .expect("ingest late placeholder B in tx #2");
    store.flush_batch().expect("flush tx #2 with late placeholder B");

    let snap_b = store
        .query_flight_recorder(20, None)
        .expect("query flight recorder B");
    let ph_b = snap_b
        .processes
        .iter()
        .find(|p| p.process_instance_id == placeholder_b.instance_id())
        .expect("placeholder B row exists after tx #2");
    let rl_b = snap_b
        .processes
        .iter()
        .find(|p| p.process_instance_id == real_b.instance_id())
        .expect("real B row exists");
    assert!(
        ph_b.exited_at_ms.is_some_and(|ex| ex >= ph_b.created_at_ms),
        "cross-tx late placeholder 4611:0 must be closed (created={}, exited={:?})",
        ph_b.created_at_ms,
        ph_b.exited_at_ms
    );
    assert_eq!(rl_b.exited_at_ms, None, "real B row must remain running");
}

/// `STORE-11` (`PRRT_kwDOVyjVyM66riuS`, `FU-E2E-05`): `checkpoint_truncate_with_deadline` caps
/// SQLite's `busy_timeout` so an active reader holding the WAL lock causes an immediate bounded
/// `Ok(false)` instead of stalling 5,000 ms, and completes (`Ok(true)`, 0-byte WAL) once the
/// reader releases its snapshot.
#[test]
fn store_11_checkpoint_truncate_with_deadline_respects_budget_under_reader_lock() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("bounded_checkpoint_reader.db");
    let wal_path = PathBuf::from(format!("{}-wal", db_path.display()));
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let (_, ev1) = make_process_start(
        101,
        1_750_000_000_000,
        4,
        r"C:\Tools\wal_reader_block_1.exe",
        "wal_reader_block_1.exe",
    );
    store
        .ingest_event(&ev1, Some("4:1"), false, "OBSERVED")
        .expect("ingest ev1");
    store.flush_batch().expect("flush ev1");

    // Hold a WAL read snapshot on a separate read-only connection, then append a second WAL write
    // AFTER the snapshot begins so `TRUNCATE` cannot truncate past the reader's WAL mark.
    let reader = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open secondary readonly connection");
    reader
        .execute_batch("BEGIN DEFERRED; SELECT COUNT(*) FROM processes;")
        .expect("acquire active WAL reader snapshot");

    let (_, ev2) = make_process_start(
        102,
        1_750_000_001_000,
        4,
        r"C:\Tools\wal_reader_block_2.exe",
        "wal_reader_block_2.exe",
    );
    store
        .ingest_event(&ev2, Some("4:1"), false, "OBSERVED")
        .expect("ingest ev2 while reader holds older snapshot");
    store.flush_batch().expect("flush ev2");
    assert!(
        std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0) > 0,
        "WAL must be non-empty before checkpoint attempt"
    );

    let started = Instant::now();
    let completed = store
        .checkpoint_truncate_with_deadline(Instant::now() + Duration::from_millis(120))
        .expect("bounded checkpoint must not error when WAL reader is busy");
    let elapsed = started.elapsed();
    assert!(
        !completed,
        "checkpoint_truncate_with_deadline must return Ok(false) while WAL reader holds older snapshot"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "checkpoint_truncate_with_deadline must respect ~120ms deadline instead of stalling 5000ms (took {elapsed:?})"
    );

    reader.execute_batch("COMMIT;").expect("release WAL reader snapshot");
    drop(reader);

    let completed_after = store
        .checkpoint_truncate_with_deadline(Instant::now() + Duration::from_millis(500))
        .expect("checkpoint after reader release");
    assert!(
        completed_after,
        "checkpoint_truncate_with_deadline must return Ok(true) once WAL reader releases lock"
    );
    if wal_path.exists() {
        assert_eq!(
            std::fs::metadata(&wal_path).expect("stat wal").len(),
            0,
            "WAL must be truncated to 0 bytes after reader releases"
        );
    }
}

/// `STORE-MEM-01` integration boundary check: verifies public `shrink_reader_memory_if_idle`
/// behavior against idle threshold, repeat suppression, shutdown suppression, restart recovery,
/// and read/write consistency across the separated read-only connection.
#[test]
fn store_12_shrink_reader_memory_if_idle_public_boundary() {
    let dir = TempDir::new().expect("create temp dir");
    let db_path = dir.path().join("shrink_boundary.db");
    let store = LedrStore::open(&db_path).expect("open LedrStore");

    let (_, w_cache, _) = store.verify_pragmas().expect("verify writer pragmas");
    let (_, r_cache, _) = store
        .verify_reader_pragmas()
        .expect("verify reader pragmas");
    assert_eq!(w_cache, -2048);
    assert_eq!(r_cache, -512);

    let (ident, proc_start) = make_process_start(
        6101,
        1_750_000_000_000,
        4,
        r"C:\Tools\shrink_boundary.exe",
        "shrink_boundary.exe --check",
    );
    store
        .ingest_event(&proc_start, Some("4:1"), false, "OBSERVED")
        .expect("ingest process start");
    store.flush_batch().expect("flush process start");

    let snap = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query process");
    assert_eq!(snap.processes.len(), 1);

    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::from_secs(30))
            .expect("idle < 30s must not shrink"),
        "30s threshold must not shrink immediately after reader access"
    );

    assert!(
        store
            .shrink_reader_memory_if_idle(Duration::ZERO)
            .expect("zero-threshold shrink"),
        "idle >= 0 threshold must shrink once"
    );
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::ZERO)
            .expect("repeat zero-threshold shrink"),
        "already shrunk since last access must return Ok(false)"
    );

    // Reader query resets shrunk state; shutdown still blocks execution.
    let snap2 = store
        .query_flight_recorder(10, Some(&ident.instance_id()))
        .expect("query process after shrink");
    assert_eq!(snap2.processes.len(), 1);

    store.request_shutdown();
    assert!(
        !store
            .shrink_reader_memory_if_idle(Duration::ZERO)
            .expect("shrink during shutdown"),
        "shutdown requested must suppress shrink_memory"
    );
    store.clear_shutdown_flag();
    assert!(
        store
            .shrink_reader_memory_if_idle(Duration::ZERO)
            .expect("shrink after clear_shutdown_flag"),
        "clear_shutdown_flag must allow shrink_memory again"
    );
}
