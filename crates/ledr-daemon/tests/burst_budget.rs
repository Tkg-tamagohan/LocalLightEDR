//! Integration tests for `ledr-daemon` two-lane burst budget, LOTL rule detection,
//! Named Pipe IPC server round-trip, startup reconciliation, and shutdown purge interruption
//! (`BURST-01`..`BURST-11`).

use std::fs::OpenOptions;
use std::future::Future;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    is_authorized_bridge_caller, start_ipc_server, ActiveProcessTable, DaemonConfig, DaemonEngine,
    HighPrioritySendError, TwoLaneChannel,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, AlertSeverity, AlertStatus, BrowserSecurityEventType,
    CanaryCategory, IpcRequest, IpcResponse, ProcessIdentity, ScriptSource, SensorEvent,
    ACTIVE_PROCESS_TABLE_CAPACITY, AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH,
    HIGH_PRIORITY_CHANNEL_CAPACITY, SHUTDOWN_FLUSH_TIMEOUT_MS, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{EarlyPruner, SigmaEngine};
use ledr_store::LedrStore;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DAY_MS: i64 = 86_400_000;

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create test temp dir");
        Self { path }
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

static PIPE_SEQ: AtomicU32 = AtomicU32::new(1);

fn unique_test_pipe_name() -> String {
    let pid = std::process::id();
    let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\localedr-ipc-test-{pid}-{seq}")
}

fn open_pipe_with_retry(pipe_name: &str) -> std::fs::File {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match OpenOptions::new().read(true).write(true).open(pipe_name) {
            Ok(file) => return file,
            Err(err) if Instant::now() < deadline && matches!(err.raw_os_error(), Some(231) | Some(2)) => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("open Named Pipe client handle `{pipe_name}` failed: {err}"),
        }
    }
}

fn send_pipe_request(pipe_name: &str, req: &IpcRequest) -> IpcResponse {
    let mut pipe = open_pipe_with_retry(pipe_name);
    write_ipc_frame(&mut pipe, req).expect("write IPC request frame");
    read_ipc_frame::<_, IpcResponse>(&mut pipe).expect("read IPC response frame")
}

#[tokio::test]
async fn burst_01_two_lane_budget_and_10k_event_flush() {
    // Part A: Direct channel overflow verification (>8,192 telemetry drop-oldest, 0 high-priority drop).
    let (tx, mut rx) = TwoLaneChannel::new().split();
    assert_eq!(tx.high_priority_capacity(), HIGH_PRIORITY_CHANNEL_CAPACITY);
    assert_eq!(tx.telemetry_capacity(), TELEMETRY_CHANNEL_CAPACITY);

    let total_direct_tel = TELEMETRY_CHANNEL_CAPACITY + 808; // 9,000 telemetry events
    for i in 0..total_direct_tel {
        tx.send_telemetry(SensorEvent::DnsQuery {
            pid: 1000,
            query_name: format!("q{i}.example.com"),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 1_700_000_000_000 + i64::try_from(i).unwrap_or(0),
        })
        .expect("telemetry ring buffer never fails while open");
    }
    assert_eq!(tx.telemetry_depth(), TELEMETRY_CHANNEL_CAPACITY);
    assert_eq!(tx.telemetry_dropped(), 808);
    assert_eq!(tx.high_priority_dropped(), 0);

    for i in 0..HIGH_PRIORITY_CHANNEL_CAPACITY {
        tx.try_send_high_priority(SensorEvent::CanaryFileAccess {
            pid: 2000,
            target_path: format!(r"C:\Users\alice\.ssh\id_rsa_{i}"),
            category: CanaryCategory::SshKey,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: 1_700_000_000_000 + i64::try_from(i).unwrap_or(0),
        })
        .expect("within high-priority capacity");
    }
    assert_eq!(tx.high_priority_depth(), HIGH_PRIORITY_CHANNEL_CAPACITY);

    let overflow_hp = tx.try_send_high_priority(SensorEvent::ScriptEvaluated {
        pid: 2000,
        source: ScriptSource::Amsi,
        script_content: "Write-Host 'preserved'".to_string(),
        timestamp_ms: 1_700_000_009_999,
    });
    assert!(matches!(overflow_hp, Err(HighPrioritySendError::Full(_))));
    assert_eq!(tx.high_priority_dropped(), 0);

    // Drain verifies high-priority comes out strictly first, and telemetry preserved newest 8,192.
    let drained = rx.drain_ready();
    assert_eq!(
        drained.len(),
        HIGH_PRIORITY_CHANNEL_CAPACITY + TELEMETRY_CHANNEL_CAPACITY
    );
    assert!(matches!(drained[0], SensorEvent::CanaryFileAccess { .. }));
    match &drained[HIGH_PRIORITY_CHANNEL_CAPACITY] {
        SensorEvent::DnsQuery { query_name, .. } => {
            assert_eq!(query_name, "q808.example.com");
        }
        other => panic!("expected oldest surviving DnsQuery q808, got {other:?}"),
    }
    match drained.last().expect("non-empty") {
        SensorEvent::DnsQuery { query_name, .. } => {
            assert_eq!(query_name, "q8999.example.com");
        }
        other => panic!("expected newest DnsQuery q8999, got {other:?}"),
    }

    // Part B: End-to-end DaemonEngine 10,000-event burst + batch flush + <= 20 MB budget check.
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let sigma = SigmaEngine::from_rules(Vec::new()).expect("empty rules");
    let pruner = EarlyPruner::default();
    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    // Seed parent/active processes for the burst.
    let base_time = 133_765_432_100_000_000u64;
    let total_burst = 10_000usize;
    let high_priority_count = 1_200usize; // > 1,024 high-priority events to exercise async backpressure
    let telemetry_count = total_burst - high_priority_count; // 8,800 telemetry events (> 8,192)

    let start = Instant::now();
    for i in 0..high_priority_count {
        let ev = match i % 3 {
            0 => SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(10_000 + u32::try_from(i).unwrap_or(0), base_time + u64::try_from(i).unwrap_or(0)),
                parent_pid: 4,
                exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
                command_line: format!("svchost.exe -k netsvcs -n {i}"),
                user_sid: None,
            },
            1 => SensorEvent::ScriptEvaluated {
                pid: 10_000,
                source: ScriptSource::PowerShell4104,
                script_content: format!("Write-Output {i}"),
                timestamp_ms: 1_700_000_100_000 + i64::try_from(i).unwrap_or(0),
            },
            _ => SensorEvent::CanaryFileAccess {
                pid: 10_000,
                target_path: format!(r"C:\Users\test\.env.local.{i}"),
                category: CanaryCategory::EnvFile,
                access_mask: 1,
                is_write_or_delete: false,
                timestamp_ms: 1_700_000_100_000 + i64::try_from(i).unwrap_or(0),
            },
        };
        sender.send(ev).await.expect("send high-priority event");
    }

    for i in 0..telemetry_count {
        let ev = if i % 2 == 0 {
            SensorEvent::DnsQuery {
                pid: 10_000,
                query_name: format!("host-{i}.example.org"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))],
                timestamp_ms: 1_700_000_200_000 + i64::try_from(i).unwrap_or(0),
            }
        } else {
            SensorEvent::NetworkConnect {
                pid: 10_000,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                dst_port: 443,
                domain_hint: Some(format!("host-{i}.example.org")),
                timestamp_ms: 1_700_000_200_000 + i64::try_from(i).unwrap_or(0),
            }
        };
        sender.send(ev).await.expect("send telemetry event");
    }

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");
    let elapsed = start.elapsed();

    let metrics = engine.metrics();
    assert_eq!(engine.high_priority_dropped(), 0);
    assert_eq!(metrics.high_priority_processed, u64::try_from(high_priority_count).unwrap());
    assert_eq!(
        metrics.telemetry_processed + metrics.telemetry_dropped,
        u64::try_from(telemetry_count).unwrap()
    );
    assert_eq!(store.buffered_len(), 0, "all buffered SQLite events flushed");
    assert!(
        elapsed < Duration::from_millis(SHUTDOWN_FLUSH_TIMEOUT_MS * 3),
        "10k burst + flush completed promptly ({elapsed:?})"
    );

    // Verify bounded in-memory structure budget stays strictly well below 20 MB (L-10 ~2-3 MB target).
    let channel_struct_bytes = (HIGH_PRIORITY_CHANNEL_CAPACITY + TELEMETRY_CHANNEL_CAPACITY)
        * std::mem::size_of::<SensorEvent>();
    let proc_table_bytes =
        ACTIVE_PROCESS_TABLE_CAPACITY * std::mem::size_of::<ledr_daemon::ActiveProcessEntry>();
    let total_bounded_bytes = channel_struct_bytes + proc_table_bytes;
    assert!(
        total_bounded_bytes <= 20 * 1024 * 1024,
        "bounded buffer baseline {total_bounded_bytes} bytes exceeds 20 MB budget"
    );

    // Also verify ActiveProcessTable enforces 4,096 capacity bound when churned.
    let mut table = ActiveProcessTable::default();
    for i in 1..=5_000u32 {
        table.on_process_start(
            ProcessIdentity::new(i, u64::from(i) * 100),
            0,
            r"C:\Windows\System32\notepad.exe".to_string(),
            String::new(),
            None,
            i64::from(i),
        );
        if i <= 4_500 {
            table.on_process_stop(i, i64::from(i) + 1);
        }
    }
    assert_eq!(table.total_len(), ACTIVE_PROCESS_TABLE_CAPACITY);
}

#[tokio::test]
async fn burst_02_lotl_cmd_powershell_end_to_end() {
    let lotl_json = include_str!("../../../rules/lotl_core.json");
    let allowlist_json = include_str!("../../../rules/default_allowlist.json");

    let sigma = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");
    let pruner = EarlyPruner::from_json_str(allowlist_json).expect("build pruner");
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    let cmd_ident = ProcessIdentity::new(4100, 133_765_432_100_000_001);
    let ps_ident = ProcessIdentity::new(4200, 133_765_432_100_000_002);

    sender
        .send(SensorEvent::ProcessStart {
            identity: cmd_ident,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
            command_line: r"cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAA==".to_string(),
            user_sid: Some("S-1-5-21-1000".to_string()),
        })
        .await
        .expect("send cmd ProcessStart");

    sender
        .send(SensorEvent::ProcessStart {
            identity: ps_ident,
            parent_pid: cmd_ident.pid,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEwAbwBjAGEAbABFAEQAUgAtAFMAaQBtAC0ATABPAFQATAAiAA==".to_string(),
            user_sid: Some("S-1-5-21-1000".to_string()),
        })
        .await
        .expect("send powershell ProcessStart");

    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_ident.pid,
            query_name: "c2.example.com".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 1_732_069_610_500,
        })
        .await
        .expect("send DnsQuery");

    sender
        .send(SensorEvent::NetworkConnect {
            pid: ps_ident.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("c2.example.com".to_string()),
            timestamp_ms: 1_732_069_610_600,
        })
        .await
        .expect("send NetworkConnect");

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].rule_id, "LEDR-LOTL-001");
    assert_eq!(alerts[0].severity, AlertSeverity::High);
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(ps_ident.instance_id().as_str())
    );

    let snapshot = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder");
    assert_eq!(snapshot.processes.len(), 2);
    assert_eq!(snapshot.dns_queries.len(), 1);
    assert_eq!(
        snapshot.dns_queries[0].process_instance_id,
        ps_ident.instance_id()
    );
    assert_eq!(snapshot.network_events.len(), 1);
    assert_eq!(
        snapshot.network_events[0].process_instance_id,
        ps_ident.instance_id()
    );

    let lineage = store
        .get_process_lineage(&ps_ident.instance_id())
        .expect("get_process_lineage");
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].process_instance_id, cmd_ident.instance_id());
    assert_eq!(lineage[1].process_instance_id, ps_ident.instance_id());
    assert_eq!(
        lineage[1].parent_instance_id.as_deref(),
        Some(cmd_ident.instance_id().as_str())
    );
}

#[tokio::test]
async fn burst_03_named_pipe_ipc_roundtrip_and_auth() {
    let pipe_name = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let sigma = SigmaEngine::from_rules(Vec::new()).expect("empty rules");
    let pruner = EarlyPruner::default();

    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: false, // Verify caller verification rejects non-ProgramFiles test binary
            ..DaemonConfig::default()
        },
    );

    let proc_ident = ProcessIdentity::new(5555, 133_765_432_100_000_555);
    engine
        .seed_processes(vec![SensorEvent::ProcessStart {
            identity: proc_ident,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: "powershell.exe -NoLogo".to_string(),
            user_sid: None,
        }])
        .expect("seed process");

    let ipc_handle = start_ipc_server(std::sync::Arc::clone(&engine)).expect("bind Named Pipe");
    let pipe_for_client = pipe_name.clone();

    let (pong, snapshot_resp, metrics_resp, risk_resp, unauth_resp) =
        tokio::task::spawn_blocking(move || {
            let pong = send_pipe_request(&pipe_for_client, &IpcRequest::Ping);
            let snapshot_resp = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::GetFlightRecorder {
                    limit: 20,
                    process_instance_id: None,
                },
            );
            let metrics_resp = send_pipe_request(&pipe_for_client, &IpcRequest::GetPipelineMetrics);
            let risk_resp = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::CheckDomainRisk {
                    domain: "micros0ft.com".to_string(),
                },
            );
            let unauth_resp = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::DeleteRule {
                    rule_id: "ALLOW-OS-WIN-SYS32".to_string(),
                },
            );
            (pong, snapshot_resp, metrics_resp, risk_resp, unauth_resp)
        })
        .await
        .expect("join IPC client task");

    match pong {
        IpcResponse::Pong {
            protocol_version, ..
        } => assert_eq!(protocol_version, ledr_proto::IPC_PROTOCOL_VERSION),
        other => panic!("expected Pong, got {other:?}"),
    }
    match snapshot_resp {
        IpcResponse::FlightRecorder(snap) => {
            assert_eq!(snap.processes.len(), 1);
            assert_eq!(snap.processes[0].process_instance_id, proc_ident.instance_id());
        }
        other => panic!("expected FlightRecorder, got {other:?}"),
    }
    match metrics_resp {
        IpcResponse::Metrics(m) => {
            assert_eq!(m.high_priority_capacity, HIGH_PRIORITY_CHANNEL_CAPACITY);
            assert_eq!(m.telemetry_capacity, TELEMETRY_CHANNEL_CAPACITY);
            assert_eq!(m.active_processes, 1);
        }
        other => panic!("expected Metrics, got {other:?}"),
    }
    match risk_resp {
        IpcResponse::DomainRisk {
            is_homograph,
            matched_brand,
            ..
        } => {
            assert!(is_homograph);
            assert_eq!(matched_brand.as_deref(), Some("microsoft"));
        }
        other => panic!("expected DomainRisk, got {other:?}"),
    }
    match unauth_resp {
        IpcResponse::Error { code, .. } => assert_eq!(code, "UNAUTHORIZED"),
        other => panic!("expected UNAUTHORIZED error, got {other:?}"),
    }

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown_and_flush");
}

#[tokio::test]
async fn burst_04_pid_reuse_telemetry_attribution_and_channel_close_drain() {
    // Part A: PID reuse time-window attribution (`A start -> A stop -> B start -> A dns`).
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let sigma = SigmaEngine::from_rules(Vec::new()).expect("empty rules");
    let pruner = EarlyPruner::default();
    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    let t0 = 1_750_000_000_000i64;
    let pid = 4242u32;
    let proc_a = ProcessIdentity::new(pid, unix_ms_to_filetime(t0));
    let proc_b = ProcessIdentity::new(pid, unix_ms_to_filetime(t0 + 1000));

    sender
        .send(SensorEvent::ProcessStart {
            identity: proc_a,
            parent_pid: 4,
            exe_path: r"C:\Tools\proc_a.exe".to_string(),
            command_line: "proc_a.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send proc A start");
    sender
        .send(SensorEvent::ProcessStop {
            pid,
            exit_time_100ns: unix_ms_to_filetime(t0 + 500),
            exit_code: 0,
        })
        .await
        .expect("send proc A stop");
    sender
        .send(SensorEvent::ProcessStart {
            identity: proc_b,
            parent_pid: 4,
            exe_path: r"C:\Tools\proc_b.exe".to_string(),
            command_line: "proc_b.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send proc B start");

    // Ensure high-priority lifecycle events are processed first so active PID mapping points to B.
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 3 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for high-priority lifecycle processing"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    sender
        .send(SensorEvent::DnsQuery {
            pid,
            query_name: "proc-a-query.example.test".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: t0 + 200,
        })
        .await
        .expect("send proc A dns");
    sender
        .send(SensorEvent::DnsQuery {
            pid,
            query_name: "proc-b-query.example.test".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))],
            timestamp_ms: t0 + 1200,
        })
        .await
        .expect("send proc B dns");

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let snap_a = store
        .query_flight_recorder(20, Some(&proc_a.instance_id()))
        .expect("query proc A");
    assert_eq!(snap_a.dns_queries.len(), 1);
    assert_eq!(snap_a.dns_queries[0].query_name, "proc-a-query.example.test");

    let snap_b = store
        .query_flight_recorder(20, Some(&proc_b.instance_id()))
        .expect("query proc B");
    assert_eq!(snap_b.dns_queries.len(), 1);
    assert_eq!(snap_b.dns_queries[0].query_name, "proc-b-query.example.test");

    // Part B: TwoLaneChannel close while high-priority sender is waiting on capacity 1.
    let (tx, mut rx) = TwoLaneChannel::with_capacities(1, 4).split();
    let ev_a = SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(101, unix_ms_to_filetime(t0)),
        parent_pid: 4,
        exe_path: "a.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    let ev_b = SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(102, unix_ms_to_filetime(t0 + 1)),
        parent_pid: 4,
        exe_path: "b.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };
    let ev_c = SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(103, unix_ms_to_filetime(t0 + 2)),
        parent_pid: 4,
        exe_path: "c.exe".to_string(),
        command_line: String::new(),
        user_sid: None,
    };

    tx.send_high_priority(ev_a).await.expect("send A");

    let send_b = tx.send_high_priority(ev_b);
    tokio::pin!(send_b);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(send_b.as_mut().poll(&mut cx), Poll::Pending),
        "sender B must block in Poll::Pending on capacity 1"
    );

    tx.close();
    assert!(matches!(
        tx.try_send_high_priority(ev_c),
        Err(HighPrioritySendError::Closed(_))
    ));

    let (send_b_res, drained) = tokio::join!(send_b, async {
        let mut out = Vec::new();
        while let Some(ev) = rx.recv().await {
            out.push(ev);
        }
        out
    });
    send_b_res.expect("sender B accepted before close must succeed");
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].pid(), 101);
    assert_eq!(drained[1].pid(), 102);
}

#[tokio::test]
async fn burst_05_periodic_ttl_purge_and_startup_stale_reconciliation() {
    let dir = TestTempDir::new("ledr-burst-05");
    let db_path = dir.path.join("daemon_ttl_reconcile.db");

    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .unwrap_or(i64::MAX);

    let expired_ident = ProcessIdentity::new(7001, unix_ms_to_filetime(now_ms - 20 * DAY_MS));
    let stale_ident = ProcessIdentity::new(7002, unix_ms_to_filetime(now_ms - 60_000));
    let live_ident = ProcessIdentity::new(7003, unix_ms_to_filetime(now_ms - 30_000));

    let live_snapshot = SensorEvent::ProcessStart {
        identity: live_ident,
        parent_pid: 4,
        exe_path: r"C:\Tools\live.exe".to_string(),
        command_line: "live.exe".to_string(),
        user_sid: None,
    };

    // Prior daemon DB session: 1 expired exited proc+DNS, 1 stale running proc, 1 still-running proc.
    {
        let store1 = LedrStore::open(&db_path).expect("open prior store");
        store1
            .ingest_event(
                &SensorEvent::ProcessStart {
                    identity: expired_ident,
                    parent_pid: 4,
                    exe_path: r"C:\Tools\old.exe".to_string(),
                    command_line: String::new(),
                    user_sid: None,
                },
                None,
                false,
                "",
            )
            .expect("ingest expired start");
        store1
            .ingest_event(
                &SensorEvent::DnsQuery {
                    pid: expired_ident.pid,
                    query_name: "expired.example.test".to_string(),
                    query_type: 1,
                    resolved_ips: vec![],
                    timestamp_ms: now_ms - 18 * DAY_MS,
                },
                Some(&expired_ident.instance_id()),
                false,
                "",
            )
            .expect("ingest expired dns");
        store1
            .ingest_event(
                &SensorEvent::ProcessStop {
                    pid: expired_ident.pid,
                    exit_time_100ns: unix_ms_to_filetime(now_ms - 19 * DAY_MS),
                    exit_code: 0,
                },
                Some(&expired_ident.instance_id()),
                false,
                "",
            )
            .expect("ingest expired stop");

        store1
            .ingest_event(
                &SensorEvent::ProcessStart {
                    identity: stale_ident,
                    parent_pid: 4,
                    exe_path: r"C:\Tools\stale.exe".to_string(),
                    command_line: String::new(),
                    user_sid: None,
                },
                None,
                false,
                "",
            )
            .expect("ingest stale start");
        store1
            .ingest_event(&live_snapshot, None, false, "")
            .expect("ingest live start");
        store1.checkpoint_truncate().expect("checkpoint prior store");
    }

    // New DaemonEngine session with fast periodic TTL purge ticker (50 ms) and startup seeding.
    let store2 = LedrStore::open(&db_path).expect("reopen store");
    let engine = DaemonEngine::start(
        store2.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty rules"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ttl_purge_interval_ms: 50,
            ttl_retention_days: 14,
            ..DaemonConfig::default()
        },
    );

    engine
        .seed_processes(vec![live_snapshot])
        .expect("seed active processes and reconcile stale ones");

    // Stale running process from prior run is immediately marked exited; live process remains active.
    let stale_snap = store2
        .query_flight_recorder(10, Some(&stale_ident.instance_id()))
        .expect("query stale proc");
    assert_eq!(stale_snap.processes.len(), 1);
    assert!(
        stale_snap.processes[0].exited_at_ms.is_some(),
        "stale prior-session process must be reconciled on startup"
    );

    let live_snap = store2
        .query_flight_recorder(10, Some(&live_ident.instance_id()))
        .expect("query live proc");
    assert_eq!(live_snap.processes.len(), 1);
    assert_eq!(live_snap.processes[0].exited_at_ms, None);

    // Wait for periodic background TTL purge ticker to delete the expired process & DNS row.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let exp_snap = store2
            .query_flight_recorder(10, Some(&expired_ident.instance_id()))
            .expect("query expired proc");
        if exp_snap.processes.is_empty() && exp_snap.dns_queries.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "periodic TTL purge ticker did not purge expired records in time"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // Recent reconciled/live processes remain preserved.
    assert_eq!(
        store2
            .query_flight_recorder(10, Some(&stale_ident.instance_id()))
            .expect("query stale retained")
            .processes
            .len(),
        1
    );
    assert_eq!(
        store2
            .query_flight_recorder(10, Some(&live_ident.instance_id()))
            .expect("query live retained")
            .processes
            .len(),
        1
    );

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");
}

#[tokio::test]
async fn burst_06_ipc_bridge_caller_auth_and_stalled_frame_timeout() {
    assert!(is_authorized_bridge_caller(
        Some(AUTHORIZED_BRIDGE_EXE_PATH),
        false
    ));
    assert!(is_authorized_bridge_caller(
        Some(&AUTHORIZED_BRIDGE_EXE_PATH.to_ascii_uppercase()),
        false
    ));
    assert!(!is_authorized_bridge_caller(
        Some(AUTHORIZED_UI_EXE_PATH),
        false
    ));
    assert!(!is_authorized_bridge_caller(None, false));
    assert!(is_authorized_bridge_caller(None, true));

    let pipe_name = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let engine = DaemonEngine::start(
        store,
        SigmaEngine::from_rules(Vec::new()).expect("empty rules"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: false,
            max_concurrent_ipc_clients: 2,
            ipc_frame_timeout_ms: 100,
            ..DaemonConfig::default()
        },
    );

    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind Named Pipe");
    let pipe_for_client = pipe_name.clone();

    let (browser_resp, download_resp, stalled_closed, pong_resp) =
        tokio::task::spawn_blocking(move || {
            let browser_resp = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ReportBrowserEvent {
                    event_type: BrowserSecurityEventType::ClickFixPastejacking,
                    url: "https://example.invalid/".to_string(),
                    details: Some("test".to_string()),
                    timestamp_ms: 1_750_000_000_000,
                },
            );
            let download_resp = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ReportDownloadOrigin {
                    file_path: r"C:\Users\test\Downloads\drop.exe".to_string(),
                    tab_url: "https://example.invalid/dl".to_string(),
                    frame_url: None,
                    referrer_url: None,
                    downloaded_at_ms: 1_750_000_000_001,
                },
            );

            // Stalled partial header (2 bytes) + stalled 1 MiB payload header must time out promptly.
            let mut stalled_hdr_pipe = open_pipe_with_retry(&pipe_for_client);
            stalled_hdr_pipe
                .write_all(&[0x20, 0x00])
                .expect("write partial 2-byte header");
            stalled_hdr_pipe.flush().expect("flush partial header");

            let mut stalled_body_pipe = open_pipe_with_retry(&pipe_for_client);
            stalled_body_pipe
                .write_all(&(1_048_576u32).to_le_bytes())
                .expect("write 1 MiB header");
            stalled_body_pipe.flush().expect("flush 1 MiB header");

            std::thread::sleep(Duration::from_millis(250));

            let mut probe_buf = [0u8; 8];
            let hdr_closed = matches!(stalled_hdr_pipe.read(&mut probe_buf), Ok(0) | Err(_));
            let body_closed = matches!(stalled_body_pipe.read(&mut probe_buf), Ok(0) | Err(_));

            let pong_resp = send_pipe_request(&pipe_for_client, &IpcRequest::Ping);
            (
                browser_resp,
                download_resp,
                hdr_closed && body_closed,
                pong_resp,
            )
        })
        .await
        .expect("join IPC client task");

    match browser_resp {
        IpcResponse::Error { code, .. } => assert_eq!(code, "UNAUTHORIZED_CALLER"),
        other => panic!("expected UNAUTHORIZED_CALLER for browser event, got {other:?}"),
    }
    match download_resp {
        IpcResponse::Error { code, .. } => assert_eq!(code, "UNAUTHORIZED_CALLER"),
        other => panic!("expected UNAUTHORIZED_CALLER for download origin, got {other:?}"),
    }
    assert!(
        stalled_closed,
        "stalled IPC connections must be closed after ipc_frame_timeout_ms"
    );
    match pong_resp {
        IpcResponse::Pong {
            protocol_version, ..
        } => assert_eq!(protocol_version, ledr_proto::IPC_PROTOCOL_VERSION),
        other => panic!("expected Pong after stalled clients timed out, got {other:?}"),
    }

    // Part B (SEC_0001): Non-reading clients requesting >64 KiB responses time out in
    // `write_response` and release their `Semaphore` permits while still open.
    let bulk_snapshots: Vec<SensorEvent> = (0..600u32)
        .map(|i| SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(30_000 + i, 133_765_432_200_000_000 + u64::from(i)),
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\svchost.exe".to_string(),
            command_line: format!(
                "svchost.exe -k netsvcs -p -s Schedule --pad-{i:04}-0000000000000000000000000000000000000000000000000000000000000000"
            ),
            user_sid: None,
        })
        .collect();
    engine
        .seed_processes(bulk_snapshots)
        .expect("seed 600 processes for oversized IPC response");

    let pipe_for_non_reader = pipe_name.clone();
    let (post_timeout_pong, non_reader_disconnected) = tokio::task::spawn_blocking(move || {
        let mut non_reader_1 = open_pipe_with_retry(&pipe_for_non_reader);
        write_ipc_frame(
            &mut non_reader_1,
            &IpcRequest::GetFlightRecorder {
                limit: 600,
                process_instance_id: None,
            },
        )
        .expect("write GetFlightRecorder frame 1");
        non_reader_1.flush().expect("flush request 1");

        let mut non_reader_2 = open_pipe_with_retry(&pipe_for_non_reader);
        write_ipc_frame(
            &mut non_reader_2,
            &IpcRequest::GetFlightRecorder {
                limit: 600,
                process_instance_id: None,
            },
        )
        .expect("write GetFlightRecorder frame 2");
        non_reader_2.flush().expect("flush request 2");

        // Wait past `ipc_frame_timeout_ms` (100 ms) while keeping both pipes open & unread.
        std::thread::sleep(Duration::from_millis(250));

        let deadline = Instant::now() + Duration::from_secs(2);
        let post_timeout_pong = loop {
            let mut pipe = open_pipe_with_retry(&pipe_for_non_reader);
            if write_ipc_frame(&mut pipe, &IpcRequest::Ping).is_ok() {
                if let Ok(resp) = read_ipc_frame::<_, IpcResponse>(&mut pipe) {
                    break resp;
                }
            }
            assert!(
                Instant::now() < deadline,
                "Semaphore permit was not released after non-reading client write timeout"
            );
            std::thread::sleep(Duration::from_millis(20));
        };

        let drain_start = Instant::now();
        let mut discard = Vec::new();
        let _ = non_reader_1.read_to_end(&mut discard);
        let _ = non_reader_2.read_to_end(&mut discard);
        let disconnected_promptly = drain_start.elapsed() < Duration::from_secs(1);

        (post_timeout_pong, disconnected_promptly)
    })
    .await
    .expect("join non-reading IPC client task");

    match post_timeout_pong {
        IpcResponse::Pong {
            protocol_version, ..
        } => assert_eq!(protocol_version, ledr_proto::IPC_PROTOCOL_VERSION),
        other => panic!("expected Pong after write_response timeout, got {other:?}"),
    }
    assert!(
        non_reader_disconnected,
        "non-reading client pipes must be closed promptly after write_response timeout"
    );

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown_and_flush");
}

#[tokio::test]
async fn burst_07_startup_reconcile_preserves_new_etw_process_and_deduplicates_alerts() {
    let dir = TestTempDir::new("ledr-burst-07");
    let db_path = dir.path.join("daemon_startup_reconcile.db");

    let lotl_json = include_str!("../../../rules/lotl_core.json");
    let allowlist_json = include_str!("../../../rules/default_allowlist.json");
    let sigma = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");
    let pruner = EarlyPruner::from_json_str(allowlist_json).expect("build pruner");

    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .unwrap_or(i64::MAX);

    let prior_stale_ident = ProcessIdentity::new(8101, unix_ms_to_filetime(now_ms - 60_000));
    let prior_live_ident = ProcessIdentity::new(8102, unix_ms_to_filetime(now_ms - 30_000));
    let prior_live_snapshot = SensorEvent::ProcessStart {
        identity: prior_live_ident,
        parent_pid: 4,
        exe_path: r"C:\Tools\prior_live.exe".to_string(),
        command_line: "prior_live.exe".to_string(),
        user_sid: None,
    };

    // Prior daemon DB session: 1 stale running process + 1 still-running process.
    {
        let store1 = LedrStore::open(&db_path).expect("open prior store");
        store1
            .ingest_event(
                &SensorEvent::ProcessStart {
                    identity: prior_stale_ident,
                    parent_pid: 4,
                    exe_path: r"C:\Tools\prior_stale.exe".to_string(),
                    command_line: "prior_stale.exe".to_string(),
                    user_sid: None,
                },
                None,
                false,
                "",
            )
            .expect("ingest prior stale");
        store1
            .ingest_event(&prior_live_snapshot, None, false, "")
            .expect("ingest prior live");
        store1.checkpoint_truncate().expect("checkpoint prior store");
    }

    let store2 = LedrStore::open(&db_path).expect("reopen store");
    let engine = DaemonEngine::start(
        store2.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );

    // BUG_0002: empty snapshot must not reconcile prior running processes.
    assert_eq!(
        engine.seed_processes(Vec::new()).expect("empty seed"),
        0
    );
    let stale_before = store2
        .query_flight_recorder(10, Some(&prior_stale_ident.instance_id()))
        .expect("query prior stale before non-empty seed");
    assert_eq!(stale_before.processes[0].exited_at_ms, None);

    // BUG_0001 + BUG_0005: simulate ETW delivering new processes after DaemonEngine::start
    // and before seed_processes runs.
    let new_etw_cmd_ident = ProcessIdentity::new(8201, unix_ms_to_filetime(now_ms - 500));
    let lotl_both_ident = ProcessIdentity::new(8202, unix_ms_to_filetime(now_ms - 200));
    let new_etw_cmd_ev = SensorEvent::ProcessStart {
        identity: new_etw_cmd_ident,
        parent_pid: 4,
        exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
        command_line: "cmd.exe /c".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };
    let lotl_both_ev = SensorEvent::ProcessStart {
        identity: lotl_both_ident,
        parent_pid: new_etw_cmd_ident.pid,
        exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        command_line: "powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAA==".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };

    let sender = engine.sender();
    sender.send(new_etw_cmd_ev).await.expect("send ETW cmd");
    sender.send(lotl_both_ev.clone()).await.expect("send ETW lotl");

    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 2 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for ETW events to process before seed_processes"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    store2.flush_batch().expect("flush ETW events before seed");

    // Seed with prior_live + duplicate lotl_both, intentionally omitting new_etw_cmd_ident and prior_stale.
    let seeded = engine
        .seed_processes(vec![prior_live_snapshot, lotl_both_ev])
        .expect("seed processes");
    assert_eq!(seeded, 2);

    // Prior stale process is marked exited, prior live and new ETW process remain active (BUG_0001).
    let stale_after = store2
        .query_flight_recorder(10, Some(&prior_stale_ident.instance_id()))
        .expect("query prior stale after seed");
    assert!(stale_after.processes[0].exited_at_ms.is_some());

    let live_after = store2
        .query_flight_recorder(10, Some(&prior_live_ident.instance_id()))
        .expect("query prior live after seed");
    assert_eq!(live_after.processes[0].exited_at_ms, None);

    let etw_cmd_after = store2
        .query_flight_recorder(10, Some(&new_etw_cmd_ident.instance_id()))
        .expect("query new ETW cmd after seed");
    assert_eq!(etw_cmd_after.processes.len(), 1);
    assert_eq!(
        etw_cmd_after.processes[0].exited_at_ms, None,
        "new ETW process started after DaemonEngine::start must not be marked exited by seed_processes"
    );

    // BUG_0005: ETW + seed_processes duplicate observation emitted only 1 alert.
    let alerts_after_dup = store2
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list alerts after duplicate");
    assert_eq!(alerts_after_dup.len(), 1);
    assert_eq!(alerts_after_dup[0].rule_id, "LEDR-LOTL-001");

    // BUG_0005 enrichment: initial empty command line emits 0 alerts, enriched non-empty emits 1,
    // and repeat observation emits 0 more.
    let enriched_ident = ProcessIdentity::new(8203, unix_ms_to_filetime(now_ms - 100));
    sender
        .send(SensorEvent::ProcessStart {
            identity: enriched_ident,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        })
        .await
        .expect("send empty cmdline start");
    let enriched_ev = SensorEvent::ProcessStart {
        identity: enriched_ident,
        parent_pid: 4,
        exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        command_line: "powershell.exe -Command iex 'payload'".to_string(),
        user_sid: None,
    };
    sender
        .send(enriched_ev.clone())
        .await
        .expect("send enriched cmdline start");
    sender
        .send(enriched_ev)
        .await
        .expect("send repeat enriched cmdline start");

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let final_alerts = store2
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list final alerts");
    assert_eq!(final_alerts.len(), 2);
    let lotl_001_count = final_alerts
        .iter()
        .filter(|a| a.rule_id == "LEDR-LOTL-001")
        .count();
    let lotl_002_count = final_alerts
        .iter()
        .filter(|a| a.rule_id == "LEDR-LOTL-002")
        .count();
    assert_eq!(lotl_001_count, 1);
    assert_eq!(lotl_002_count, 1);
}

#[tokio::test]
async fn burst_08_shutdown_interrupts_large_purge_within_budget() {
    let dir = TestTempDir::new("ledr-burst-08");
    let db_path = dir.path.join("daemon_large_purge.db");

    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_millis(),
    )
    .unwrap_or(i64::MAX);

    {
        let store1 = LedrStore::open(&db_path).expect("open seed store");
        for i in 0..3_000u32 {
            let ident = ProcessIdentity::new(
                20_000 + i,
                unix_ms_to_filetime(now_ms - 20 * DAY_MS - i64::from(i)),
            );
            store1
                .ingest_event(
                    &SensorEvent::ProcessStart {
                        identity: ident,
                        parent_pid: 4,
                        exe_path: r"C:\Tools\expired.exe".to_string(),
                        command_line: format!("expired.exe --idx {i}"),
                        user_sid: None,
                    },
                    None,
                    false,
                    "",
                )
                .expect("ingest expired start");
            store1
                .ingest_event(
                    &SensorEvent::ProcessStop {
                        pid: ident.pid,
                        exit_time_100ns: unix_ms_to_filetime(now_ms - 19 * DAY_MS - i64::from(i)),
                        exit_code: 0,
                    },
                    Some(&ident.instance_id()),
                    false,
                    "",
                )
                .expect("ingest expired stop");
        }
        store1.checkpoint_truncate().expect("checkpoint 3k rows");
    }

    let store2 = LedrStore::open(&db_path).expect("reopen large purge store");
    store2.set_purge_batch_delay_ms(40);
    let engine = DaemonEngine::start(
        store2.clone(),
        SigmaEngine::from_rules(Vec::new()).expect("empty rules"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ttl_purge_interval_ms: 50,
            ttl_retention_days: 14,
            ..DaemonConfig::default()
        },
    );

    // Wait until periodic purge commits at least one 500-row batch.
    let wait_deadline = Instant::now() + Duration::from_secs(3);
    while store2.purge_batches_completed() < 1 {
        assert!(
            Instant::now() < wait_deadline,
            "timed out waiting for periodic purge to begin"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let post_purge_ident = ProcessIdentity::new(29_999, unix_ms_to_filetime(now_ms));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: post_purge_ident,
            parent_pid: 4,
            exe_path: r"C:\Tools\survivor.exe".to_string(),
            command_line: "survivor.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send survivor process start");

    let shutdown_start = Instant::now();
    engine
        .shutdown_and_flush()
        .await
        .expect("shutdown_and_flush during large purge");
    let shutdown_elapsed = shutdown_start.elapsed();

    assert!(
        shutdown_elapsed < Duration::from_millis(SHUTDOWN_FLUSH_TIMEOUT_MS),
        "shutdown_and_flush took {shutdown_elapsed:?}, exceeding {SHUTDOWN_FLUSH_TIMEOUT_MS} ms budget"
    );
    assert_eq!(store2.buffered_len(), 0);
    let remaining_snap = store2
        .query_flight_recorder(3_000, None)
        .expect("query remaining processes after interrupted purge");
    let remaining_expired = remaining_snap
        .processes
        .iter()
        .filter(|p| p.exited_at_ms.is_some())
        .count();
    assert!(
        !remaining_snap.processes.is_empty() && remaining_snap.processes.len() < 3_000,
        "expected partially purged process count in (0, 3000), got {}",
        remaining_snap.processes.len()
    );
    assert!(
        remaining_expired > 0 && remaining_expired < 3_000,
        "expected remaining expired processes in (0, 3000), got {remaining_expired}"
    );
    let survivor = store2
        .query_flight_recorder(10, Some(&post_purge_ident.instance_id()))
        .expect("query survivor process");
    assert_eq!(survivor.processes.len(), 1);
}

#[tokio::test]
async fn burst_09_parent_enrichment_triggers_lotl_alert_and_older_snapshot_preserves_newer_pid() {
    let lotl_json = include_str!("../../../rules/lotl_core.json");
    let allowlist_json = include_str!("../../../rules/default_allowlist.json");
    let sigma = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");
    let pruner = EarlyPruner::from_json_str(allowlist_json).expect("build pruner");
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    let t_base = 1_750_000_000_000i64;
    let cmd_ident = ProcessIdentity::new(6100, unix_ms_to_filetime(t_base + 1_000));
    let ps_ident = ProcessIdentity::new(6200, unix_ms_to_filetime(t_base + 1_100));

    let cmd_ev = SensorEvent::ProcessStart {
        identity: cmd_ident,
        parent_pid: 4,
        exe_path: r"C:\Windows\System32\cmd.exe".to_string(),
        command_line: "cmd.exe /c powershell.exe".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };
    let ps_ev = SensorEvent::ProcessStart {
        identity: ps_ident,
        parent_pid: cmd_ident.pid,
        exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
        command_line: "powershell.exe -NoP -EncodedCommand VwByAGkAdABlAA==".to_string(),
        user_sid: Some("S-1-5-21-1000".to_string()),
    };

    // 1. Child seen by ETW before parent exists: 0 alerts initially.
    sender
        .send(ps_ev.clone())
        .await
        .expect("send child powershell before parent");
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 1 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for initial child ProcessStart"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    store.flush_batch().expect("flush initial child");
    assert!(
        store
            .list_alerts(Some(AlertStatus::Pending), 20)
            .expect("list initial alerts")
            .is_empty(),
        "child without parent context must not match LEDR-LOTL-001 initially"
    );

    // Seed parent + child snapshots -> parent_instance_id is enriched and LEDR-LOTL-001 triggers once.
    engine
        .seed_processes(vec![cmd_ev, ps_ev.clone()])
        .expect("seed cmd and powershell snapshots");
    let ps_snap = store
        .query_flight_recorder(10, Some(&ps_ident.instance_id()))
        .expect("query enriched child");
    assert_eq!(ps_snap.processes.len(), 1);
    assert_eq!(
        ps_snap.processes[0].parent_instance_id.as_deref(),
        Some(cmd_ident.instance_id().as_str())
    );
    let alerts_after_seed = store
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list alerts after parent enrichment");
    assert_eq!(alerts_after_seed.len(), 1);
    assert_eq!(alerts_after_seed[0].rule_id, "LEDR-LOTL-001");
    assert_eq!(
        alerts_after_seed[0].process_instance_id.as_deref(),
        Some(ps_ident.instance_id().as_str())
    );

    // Re-sending the same ProcessStart must NOT duplicate the alert.
    sender
        .send(ps_ev)
        .await
        .expect("resend duplicate powershell ProcessStart");
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 2 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for duplicate child ProcessStart"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert_eq!(
        store
            .list_alerts(Some(AlertStatus::Pending), 20)
            .expect("list alerts after duplicate ProcessStart")
            .len(),
        1
    );

    // 2. Newer ETW ProcessStart(PID 42, t=2000) followed by older snapshot ProcessStart(PID 42, t=1000):
    //    DnsQuery(PID 42, t=2500) must attribute to 42:<t=2000>, not 42:<t=1000>.
    let newer_42 = ProcessIdentity::new(42, unix_ms_to_filetime(t_base + 2_000));
    let older_42 = ProcessIdentity::new(42, unix_ms_to_filetime(t_base + 1_000));

    sender
        .send(SensorEvent::ProcessStart {
            identity: newer_42,
            parent_pid: 4,
            exe_path: r"C:\Tools\newer42.exe".to_string(),
            command_line: "newer42.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send newer PID 42 ETW start");
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 3 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for newer PID 42 ETW start"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    engine
        .seed_processes(vec![SensorEvent::ProcessStart {
            identity: older_42,
            parent_pid: 4,
            exe_path: r"C:\Tools\older42.exe".to_string(),
            command_line: "older42.exe".to_string(),
            user_sid: None,
        }])
        .expect("process older PID 42 snapshot");

    sender
        .send(SensorEvent::DnsQuery {
            pid: 42,
            query_name: "newer-pid42.example.test".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: t_base + 2_500,
        })
        .await
        .expect("send DnsQuery for PID 42 at t=2500");

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let snap = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder");
    let dns = snap
        .dns_queries
        .iter()
        .find(|d| d.query_name == "newer-pid42.example.test")
        .expect("DnsQuery recorded");
    assert_eq!(dns.process_instance_id, newer_42.instance_id());
    assert_ne!(dns.process_instance_id, older_42.instance_id());

    let newer_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == newer_42.instance_id())
        .expect("newer PID 42 row recorded");
    assert_eq!(newer_row.exited_at_ms, None);

    assert_eq!(
        store
            .list_alerts(Some(AlertStatus::Pending), 20)
            .expect("final alerts")
            .len(),
        1
    );
}

#[tokio::test]
async fn burst_10_older_snapshot_process_gets_inferred_exit_in_store() {
    let sigma = SigmaEngine::from_rules(Vec::new()).expect("empty rules");
    let pruner = EarlyPruner::default();
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    // Newer incarnation of PID 42 observed via ETW first, then an older snapshot arrives.
    // The older row must be persisted with an inferred exited_at_ms instead of staying "running".
    let t_base = 1_750_000_000_000i64;
    let newer_42 = ProcessIdentity::new(42, unix_ms_to_filetime(t_base + 2_000));
    let older_42 = ProcessIdentity::new(42, unix_ms_to_filetime(t_base + 1_000));

    sender
        .send(SensorEvent::ProcessStart {
            identity: newer_42,
            parent_pid: 4,
            exe_path: r"C:\Tools\newer42.exe".to_string(),
            command_line: "newer42.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send newer PID 42 ETW start");
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 1 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for newer PID 42 ETW start"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    engine
        .seed_processes(vec![SensorEvent::ProcessStart {
            identity: older_42,
            parent_pid: 4,
            exe_path: r"C:\Tools\older42.exe".to_string(),
            command_line: "older42.exe".to_string(),
            user_sid: None,
        }])
        .expect("seed older PID 42 snapshot");

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let snap = store
        .query_flight_recorder(50, None)
        .expect("query flight recorder");
    let older_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == older_42.instance_id())
        .expect("older PID 42 row recorded");
    assert_eq!(
        older_row.exited_at_ms,
        Some(t_base + 2_000),
        "older incarnation must carry the inferred exit time (newer row's created_at_ms)"
    );
    let newer_row = snap
        .processes
        .iter()
        .find(|p| p.process_instance_id == newer_42.instance_id())
        .expect("newer PID 42 row recorded");
    assert_eq!(newer_row.exited_at_ms, None);
}

#[tokio::test]
async fn burst_11_distinct_script_bodies_each_emit_alert_per_rule() {
    let lotl_json = include_str!("../../../rules/lotl_core.json");
    let allowlist_json = include_str!("../../../rules/default_allowlist.json");
    let sigma = SigmaEngine::from_json_str(lotl_json).expect("compile lotl_core.json");
    let pruner = EarlyPruner::from_json_str(allowlist_json).expect("build pruner");
    let store = LedrStore::open_in_memory().expect("open in-memory store");

    let engine = DaemonEngine::start(
        store.clone(),
        sigma,
        pruner,
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );
    let sender = engine.sender();

    let t_base = 1_750_000_000_000i64;
    let ps_ident = ProcessIdentity::new(7100, unix_ms_to_filetime(t_base + 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps_ident,
            parent_pid: 4,
            exe_path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            command_line: "powershell.exe".to_string(),
            user_sid: Some("S-1-5-21-1000".to_string()),
        })
        .await
        .expect("send powershell ProcessStart");
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 1 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for powershell ProcessStart"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Two different script bodies matching the same rule must each emit an alert; replaying the
    // identical body must still be deduplicated.
    let script_a = "Invoke-AmsiUtils bypass".to_string();
    let script_b = "New-Object VirtualAlloc; FromBase64String payload".to_string();
    for (content, ts) in [
        (script_a.as_str(), t_base + 2_000),
        (script_b.as_str(), t_base + 3_000),
        (script_a.as_str(), t_base + 4_000),
    ] {
        sender
            .send(SensorEvent::ScriptEvaluated {
                pid: 7100,
                source: ScriptSource::PowerShell4104,
                script_content: content.to_string(),
                timestamp_ms: ts,
            })
            .await
            .expect("send ScriptEvaluated");
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while engine.metrics().high_priority_processed < 4 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for ScriptEvaluated processing"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    engine.shutdown_and_flush().await.expect("shutdown_and_flush");

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list alerts");
    assert_eq!(
        alerts.len(),
        2,
        "distinct script bodies must each fire LEDR-SCRIPT-001, identical replay deduplicated"
    );
    assert!(alerts.iter().all(|a| a.rule_id == "LEDR-SCRIPT-001"));
    assert!(
        alerts
            .iter()
            .all(|a| a.process_instance_id.as_deref() == Some(ps_ident.instance_id().as_str()))
    );
}
