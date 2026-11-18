//! Integration tests for `ledr-daemon` two-lane burst budget, LOTL rule detection,
//! and Named Pipe IPC server round-trip (`BURST-01`..`BURST-03`).

use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ledr_daemon::{
    start_ipc_server, ActiveProcessTable, DaemonConfig, DaemonEngine, HighPrioritySendError,
    TwoLaneChannel,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, AlertSeverity, AlertStatus, CanaryCategory, IpcRequest,
    IpcResponse, ProcessIdentity, ScriptSource, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY,
    HIGH_PRIORITY_CHANNEL_CAPACITY, SHUTDOWN_FLUSH_TIMEOUT_MS, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{EarlyPruner, SigmaEngine};
use ledr_store::LedrStore;

static PIPE_SEQ: AtomicU32 = AtomicU32::new(1);

fn unique_test_pipe_name() -> String {
    let pid = std::process::id();
    let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\localedr-ipc-test-{pid}-{seq}")
}

fn send_pipe_request(pipe_name: &str, req: &IpcRequest) -> IpcResponse {
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(pipe_name)
        .expect("open Named Pipe client handle");
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
            timestamp_ms: 1_700_000_500_000,
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
            timestamp_ms: 1_700_000_500_100,
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
