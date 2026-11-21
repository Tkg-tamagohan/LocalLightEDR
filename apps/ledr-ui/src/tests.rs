use super::*;
use cli::parse_launch_mode;
#[cfg(windows)]
use defense_status::probe_native_host_reg_string;
use defense_status::{
    BrowserRegistryProbe, BrowserShieldProbe, EXPECTED_CHROME_EXTENSION_ID, HONEYPOT_FILENAME,
    MANIFEST_STATUS_INVALID, MANIFEST_STATUS_NOT_REGISTERED, MANIFEST_STATUS_UNVERIFIED,
    MANIFEST_STATUS_VALID, MAX_MANIFEST_BYTES, ManifestValidationOutcome, NATIVE_HOST_NAME,
    RegistryStringProbe, classify_manifest_file_in_allowed_dirs, collect_local_defense_status_with,
    collect_local_defense_status_with_probe,
    collect_local_defense_status_with_probe_in_allowed_dirs, default_allowed_manifest_dirs_from,
    select_preferred_wow64_probe, validate_manifest_file, validate_manifest_file_in_allowed_dirs,
};
use ipc::{
    parse_ack_response, parse_alerts_response, parse_flight_recorder_response,
    parse_metrics_response, parse_ping_response, parse_rules_response,
};
use ledr_proto::{
    AlertDecision, AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, CanaryCategory,
    DnsQueryRecord, FileCanaryEventRecord, FlightRecorderSnapshot, IpcRequest, IpcResponse,
    NetworkEventRecord, PipelineMetrics, ProcessRecord, RuleScope, decode_ipc_frame,
    encode_ipc_frame,
};
use notify::{
    ToastAlertSummary, base64_encode, build_notify_oneshot_event, build_winrt_toast_xml,
    is_os_toast_disabled_value, is_os_toast_suppressed_by_setting, summarize_alert_for_toast,
};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tree::build_process_tree;
#[cfg(windows)]
use uri_reg::{
    LEDR_AUMID_DISPLAY_NAME, LEDR_URI_DESCRIPTION, RegDefaultSzProbe, RegNativeHostSzProbe,
    RegWow64View, win_uri_reg,
};
use uri_reg::{
    LEDR_URI_REG_SUBKEY, UriRegistrationOutcome, build_register_uri_event, format_ledr_uri_command,
};

fn sample_process(
    pid: u32,
    create_ms: i64,
    parent_instance_id: Option<&str>,
    ppid: u32,
    exe_path: &str,
) -> ProcessRecord {
    ProcessRecord {
        process_instance_id: format!("{pid}:{}", create_ms * 10_000),
        pid,
        parent_instance_id: parent_instance_id.map(str::to_string),
        ppid,
        exe_path: exe_path.to_string(),
        command_line: Some(format!("{exe_path} --test")),
        sha256: None,
        signer_subject: None,
        is_trusted_os: false,
        user_sid: Some("S-1-5-21-1000".to_string()),
        origin_url: None,
        created_at_ms: create_ms,
        exited_at_ms: None,
    }
}

struct MockIpcStream<F> {
    tx_buf: Vec<u8>,
    rx_buf: Vec<u8>,
    rx_pos: usize,
    handler: F,
}

impl<F> MockIpcStream<F> {
    fn new(handler: F) -> Self {
        Self {
            tx_buf: Vec::new(),
            rx_buf: Vec::new(),
            rx_pos: 0,
            handler,
        }
    }
}

impl<F> Write for MockIpcStream<F>
where
    F: FnMut(IpcRequest) -> IpcResponse,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tx_buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.tx_buf.len() >= 4 {
            let req: IpcRequest = decode_ipc_frame(&self.tx_buf)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            self.tx_buf.clear();
            let resp = (self.handler)(req);
            let frame = encode_ipc_frame(&resp)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
            self.rx_buf.extend_from_slice(&frame);
        }
        Ok(())
    }
}

impl<F> Read for MockIpcStream<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.rx_buf.len().saturating_sub(self.rx_pos);
        let n = remaining.min(buf.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.rx_buf[self.rx_pos..self.rx_pos + n]);
            self.rx_pos += n;
        }
        Ok(n)
    }
}

#[test]
fn parses_normal_mode() {
    assert_eq!(parse_launch_mode(["ledr-ui"]), Ok(LaunchMode::Normal));
}

#[test]
fn parses_notify_flag() {
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--notify", "alert-123"]),
        Ok(LaunchMode::Notify("alert-123".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--notify=alert-456"]),
        Ok(LaunchMode::Notify("alert-456".to_string()))
    );
}

#[test]
fn parses_alert_id_flag() {
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--alert-id", "alert-789"]),
        Ok(LaunchMode::AlertFocus("alert-789".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--alert-id=alert-000"]),
        Ok(LaunchMode::AlertFocus("alert-000".to_string()))
    );
}

#[test]
fn rejects_missing_flag_value() {
    assert!(parse_launch_mode(["ledr-ui", "--notify"]).is_err());
    assert!(parse_launch_mode(["ledr-ui", "--alert-id="]).is_err());
}

#[test]
fn ui_05_build_process_tree_hierarchy_and_orphans() {
    let explorer = sample_process(100, 1_000, None, 0, r"C:\Windows\explorer.exe");
    let cmd = sample_process(
        200,
        2_000,
        Some(&explorer.process_instance_id),
        100,
        r"C:\Windows\System32\cmd.exe",
    );
    let ps_late = sample_process(
        302,
        3_500,
        Some(&cmd.process_instance_id),
        200,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    );
    let ps_early = sample_process(
        301,
        3_000,
        Some(&cmd.process_instance_id),
        200,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    );
    let orphan_missing_parent_id = sample_process(
        400,
        1_500,
        Some("9999:999"),
        9999,
        r"C:\Users\dev\AppData\Local\Temp\dropper.exe",
    );
    let orphan_missing_ppid = sample_process(
        500,
        4_000,
        None,
        8888,
        r"C:\Windows\System32\svchost.exe",
    );

    let snapshot = FlightRecorderSnapshot {
        processes: vec![
            ps_late.clone(),
            orphan_missing_ppid.clone(),
            cmd.clone(),
            orphan_missing_parent_id.clone(),
            explorer.clone(),
            ps_early.clone(),
        ],
        dns_queries: vec![DnsQueryRecord {
            id: Some(1),
            timestamp_ms: 3_100,
            process_instance_id: ps_early.process_instance_id.clone(),
            query_name: "cdn-update.example".to_string(),
            query_type: 1,
            resolved_ips: vec!["203.0.113.10".to_string()],
            is_nrd: true,
        }],
        network_events: vec![
            NetworkEventRecord {
                id: Some(1),
                timestamp_ms: 3_120,
                process_instance_id: ps_early.process_instance_id.clone(),
                protocol: 6,
                dst_ip: "203.0.113.10".to_string(),
                dst_port: 443,
                domain_hint: Some("cdn-update.example".to_string()),
                action: "LOG".to_string(),
            },
            NetworkEventRecord {
                id: Some(2),
                timestamp_ms: 3_600,
                process_instance_id: ps_late.process_instance_id.clone(),
                protocol: 6,
                dst_ip: "198.51.100.7".to_string(),
                dst_port: 8443,
                domain_hint: None,
                action: "LOG".to_string(),
            },
        ],
        file_canary_events: vec![FileCanaryEventRecord {
            id: Some(1),
            timestamp_ms: 1_600,
            process_instance_id: orphan_missing_parent_id.process_instance_id.clone(),
            target_path: r"C:\Users\dev\.ssh\id_ed25519".to_string(),
            category: CanaryCategory::SshKey,
            access_mask: 0x0012_0089,
            action_taken: "SUSPENDED".to_string(),
        }],
        download_origins: Vec::new(),
    };

    let roots = build_process_tree(&snapshot);
    assert_eq!(roots.len(), 3);

    // Roots sorted by created_at_ms: explorer (1000), orphan_missing_parent_id (1500), orphan_missing_ppid (4000)
    assert_eq!(roots[0].process.pid, 100);
    assert!(!roots[0].is_orphan_root);
    assert_eq!(roots[0].children.len(), 1);

    let cmd_node = &roots[0].children[0];
    assert_eq!(cmd_node.process.pid, 200);
    assert!(!cmd_node.is_orphan_root);
    assert_eq!(cmd_node.children.len(), 2);
    assert_eq!(cmd_node.children[0].process.pid, 301);
    assert_eq!(cmd_node.children[0].dns_count, 1);
    assert_eq!(cmd_node.children[0].network_count, 1);
    assert_eq!(cmd_node.children[1].process.pid, 302);
    assert_eq!(cmd_node.children[1].network_count, 1);

    assert_eq!(roots[1].process.pid, 400);
    assert!(roots[1].is_orphan_root);
    assert_eq!(roots[1].canary_count, 1);

    assert_eq!(roots[2].process.pid, 500);
    assert!(roots[2].is_orphan_root);

    // Verify cycle protection never drops nodes or recurses infinitely.
    let mut cyc_a = sample_process(701, 5_000, Some("702:50000000"), 702, "a.exe");
    cyc_a.process_instance_id = "701:50000000".to_string();
    let mut cyc_b = sample_process(702, 5_000, Some("701:50000000"), 701, "b.exe");
    cyc_b.process_instance_id = "702:50000000".to_string();
    let cyclic_roots = build_process_tree(&FlightRecorderSnapshot {
        processes: vec![cyc_a, cyc_b],
        ..Default::default()
    });
    assert_eq!(cyclic_roots.len(), 1);
    assert!(cyclic_roots[0].is_orphan_root);
    assert_eq!(cyclic_roots[0].children.len(), 1);
}

#[test]
fn ui_06_ipc_client_frame_roundtrip() {
    let expected_snapshot = FlightRecorderSnapshot {
        processes: vec![sample_process(
            420,
            10_000,
            None,
            0,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )],
        ..Default::default()
    };
    let expected_metrics = PipelineMetrics {
        high_priority_depth: 1,
        high_priority_capacity: ledr_proto::HIGH_PRIORITY_CHANNEL_CAPACITY,
        high_priority_processed: 42,
        telemetry_depth: 5,
        telemetry_capacity: ledr_proto::TELEMETRY_CHANNEL_CAPACITY,
        telemetry_processed: 128,
        telemetry_dropped: 0,
        active_processes: 1,
        pending_alerts: 0,
        uptime_secs: 99,
    };

    let snapshot_clone = expected_snapshot.clone();
    let metrics_clone = expected_metrics.clone();

    let mut stream = MockIpcStream::new(move |req| match req {
        IpcRequest::Ping => IpcResponse::Pong {
            daemon_version: "0.1.0".to_string(),
            protocol_version: ledr_proto::IPC_PROTOCOL_VERSION,
        },
        IpcRequest::GetFlightRecorder {
            limit,
            process_instance_id,
        } => {
            assert_eq!(limit, 50);
            assert_eq!(process_instance_id.as_deref(), Some("420:100000000"));
            IpcResponse::FlightRecorder(snapshot_clone.clone())
        }
        IpcRequest::GetPipelineMetrics => IpcResponse::Metrics(metrics_clone.clone()),
        IpcRequest::CheckDomainRisk { .. } => IpcResponse::Error {
            code: "NOT_IMPLEMENTED".to_string(),
            message: "stub error".to_string(),
        },
        other => panic!("unexpected request: {other:?}"),
    });

    let ping_resp = IpcClient::send_request_over_stream(&mut stream, &IpcRequest::Ping)
        .expect("ping roundtrip");
    assert_eq!(
        parse_ping_response(ping_resp).expect("parse pong"),
        "ledr-daemon v0.1.0 (proto v1)"
    );

    let fr_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::GetFlightRecorder {
            limit: 50,
            process_instance_id: Some("420:100000000".to_string()),
        },
    )
    .expect("flight recorder roundtrip");
    assert_eq!(
        parse_flight_recorder_response(fr_resp).expect("parse snapshot"),
        expected_snapshot
    );

    let metrics_resp =
        IpcClient::send_request_over_stream(&mut stream, &IpcRequest::GetPipelineMetrics)
            .expect("metrics roundtrip");
    assert_eq!(
        parse_metrics_response(metrics_resp).expect("parse metrics"),
        expected_metrics
    );

    let err_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::CheckDomainRisk {
            domain: "example.com".to_string(),
        },
    )
    .expect("error response roundtrip");
    let err_msg = parse_ping_response(err_resp).expect_err("error variant returns Err");
    assert!(err_msg.contains("NOT_IMPLEMENTED"));

    // Non-existent pipe endpoint returns a clean offline error without panicking.
    let offline_client = IpcClient::new(r"\\.\pipe\localedr-ui-nonexistent-test-pipe");
    let offline_err = offline_client
        .ping()
        .expect_err("missing pipe should fail gracefully");
    assert!(offline_err.contains("offline") || offline_err.contains("failed"));
}

#[test]
fn ui_p2_01_parse_launch_mode_ledr_alert_uri() {
    assert_eq!(
        parse_launch_mode(["ledr-ui", "ledr://alert/alert-123"]),
        Ok(LaunchMode::AlertFocus("alert-123".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "LEDR://alert/alert-456/"]),
        Ok(LaunchMode::AlertFocus("alert-456".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "LeDr://Alert/Alert-Case-789/?source=toast#focus"]),
        Ok(LaunchMode::AlertFocus("Alert-Case-789".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--uri", "ledr://alert/uri-001"]),
        Ok(LaunchMode::AlertFocus("uri-001".to_string()))
    );
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--uri=LEDR://alert/uri-002/#action"]),
        Ok(LaunchMode::AlertFocus("uri-002".to_string()))
    );

    for invalid in [
        vec!["ledr-ui", "ledr://alert/"],
        vec!["ledr-ui", "ledr://alert/?q=1"],
        vec!["ledr-ui", "ledr://unknown/123"],
        vec!["ledr-ui", "ledr://alert/a/b"],
        vec!["ledr-ui", "--uri"],
        vec!["ledr-ui", "--uri="],
        vec!["ledr-ui", "--uri", "https://example.invalid/alert/1"],
    ] {
        assert!(
            parse_launch_mode(invalid.iter().copied()).is_err(),
            "expected invalid URI rejection for {invalid:?}"
        );
    }
}

#[test]
fn ui_p2_02_winrt_toast_xml_escaping_and_launch_uri() {
    let summary = ToastAlertSummary {
        alert_id: "alert-&\"'<1>".to_string(),
        title: "Canary <Access> & 'Exfil' \"Attempt\"".to_string(),
        target_path: Some(r"C:\Users\A&B\<dev>\Cookies".to_string()),
        exe_path: Some(r"C:\Temp\steal&run.exe".to_string()),
        rule_id: Some("CANARY-COOKIE-01".to_string()),
        severity: Some("CRITICAL".to_string()),
        process_suspended: true,
        is_expired_suspended: false,
        has_suspended_children: false,
        shutdown_resumed: false,
        shutdown_cleared: false,
    };

    let xml = build_winrt_toast_xml(&summary);
    let expected_escaped_uri = "ledr://alert/alert-&amp;&quot;&apos;&lt;1&gt;";
    assert!(xml.contains(&format!("launch=\"{expected_escaped_uri}\"")));
    assert!(xml.contains("activationType=\"protocol\""));
    assert!(xml.contains(&format!("arguments=\"{expected_escaped_uri}\"")));
    assert!(xml.contains("[SUSPENDED]"));
    assert!(xml.contains("CRITICAL Canary &lt;Access&gt; &amp; &apos;Exfil&apos; &quot;Attempt&quot;"));
    assert!(xml.contains(r"Target: C:\Users\A&amp;B\&lt;dev&gt;\Cookies"));
    assert!(xml.contains(r"Process: C:\Temp\steal&amp;run.exe | Rule: CANARY-COOKIE-01"));
    assert!(xml.contains("<action content=\"Triage Alert\""));

    // Verify EXPIRED_SUSPENDED badge wording and absence of unescaped raw special chars inside text nodes.
    let expired_summary = ToastAlertSummary {
        alert_id: "alert-exp-1".to_string(),
        title: "Honeypot Modified".to_string(),
        target_path: Some(r"C:\Users\user\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string()),
        exe_path: None,
        rule_id: Some("CANARY-HONEYPOT".to_string()),
        severity: Some("CRITICAL".to_string()),
        process_suspended: true,
        is_expired_suspended: true,
        has_suspended_children: false,
        shutdown_resumed: false,
        shutdown_cleared: false,
    };
    let expired_xml = build_winrt_toast_xml(&expired_summary);
    assert!(expired_xml.contains("[EXPIRED_SUSPENDED · FROZEN]"));
    assert!(expired_xml.contains("launch=\"ledr://alert/alert-exp-1\""));

    // Verify EXPIRED_SUSPENDED resumed on daemon shutdown distinguishes resumed vs still-frozen.
    let shutdown_resumed_record = AlertRecord {
        alert_id: "alert-exp-resumed".to_string(),
        timestamp_ms: 1_700_000_000_000,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Cookies Access".to_string(),
        process_instance_id: Some("4200:133800000000000000".to_string()),
        process_suspended: false,
        status: AlertStatus::ExpiredSuspended,
        context_json: r#"{"suspended_children":[],"shutdown_resumed_at_ms":1700000099000}"#
            .to_string(),
        resolved_at_ms: None,
    };
    let resumed_summary =
        summarize_alert_for_toast(&shutdown_resumed_record.alert_id, Some(&shutdown_resumed_record));
    assert!(!resumed_summary.process_suspended);
    assert!(!resumed_summary.has_suspended_children);
    assert!(resumed_summary.shutdown_resumed);
    let resumed_xml = build_winrt_toast_xml(&resumed_summary);
    assert!(
        resumed_xml.contains("[EXPIRED · RESUMED]"),
        "shutdown-resumed expired alert must not claim FROZEN: {resumed_xml}"
    );
    assert!(!resumed_xml.contains("FROZEN"));

    // Partial resume where parent resumed but a child remains suspended must still show FROZEN.
    let partial_child_record = AlertRecord {
        alert_id: "alert-exp-child-frozen".to_string(),
        context_json: r#"{"suspended_children":["4204:133800000000000000"],"shutdown_resumed_at_ms":1700000099000}"#
            .to_string(),
        ..shutdown_resumed_record
    };
    let partial_summary =
        summarize_alert_for_toast(&partial_child_record.alert_id, Some(&partial_child_record));
    assert!(partial_summary.has_suspended_children);
    let partial_xml = build_winrt_toast_xml(&partial_summary);
    assert!(partial_xml.contains("[EXPIRED_SUSPENDED · FROZEN]"));

    // PR23-U3-02: Shutdown clear of an already-exited / PID-reused process must NOT claim RESUMED.
    let shutdown_gone_record = AlertRecord {
        alert_id: "alert-exp-gone".to_string(),
        context_json: r#"{"suspended_children":[],"shutdown_gone_identities":["4200:133800000000000000"],"shutdown_cleared_at_ms":1700000099500}"#
            .to_string(),
        ..partial_child_record.clone()
    };
    let gone_summary =
        summarize_alert_for_toast(&shutdown_gone_record.alert_id, Some(&shutdown_gone_record));
    assert!(!gone_summary.shutdown_resumed);
    assert!(gone_summary.shutdown_cleared);
    let gone_xml = build_winrt_toast_xml(&gone_summary);
    assert!(
        gone_xml.contains("[EXPIRED · CLEARED]"),
        "shutdown-cleared gone process must show CLEARED badge: {gone_xml}"
    );
    assert!(!gone_xml.contains("RESUMED"));
    assert!(!gone_xml.contains("FROZEN"));

    // PR23-U3-02 (mixed): When both a resumed target and a gone/reused target were cleared on
    // shutdown, badge must use CLEARED instead of claiming all targets resumed.
    let shutdown_mixed_record = AlertRecord {
        alert_id: "alert-exp-mixed".to_string(),
        context_json: r#"{"suspended_children":[],"shutdown_resumed_identities":["4200:133800000000000000"],"shutdown_resumed_at_ms":1700000099000,"shutdown_gone_identities":["4204:133800000000000000"],"shutdown_cleared_at_ms":1700000099000}"#
            .to_string(),
        ..shutdown_gone_record
    };
    let mixed_summary =
        summarize_alert_for_toast(&shutdown_mixed_record.alert_id, Some(&shutdown_mixed_record));
    assert!(mixed_summary.shutdown_resumed);
    assert!(mixed_summary.shutdown_cleared);
    let mixed_xml = build_winrt_toast_xml(&mixed_summary);
    assert!(
        mixed_xml.contains("[EXPIRED · CLEARED]"),
        "mixed shutdown resume/gone clear must show CLEARED badge: {mixed_xml}"
    );
    assert!(!mixed_xml.contains("RESUMED"));

    // RFC 4648 base64 sanity check for PowerShell -EncodedCommand encoding.
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg==");
    assert_eq!(base64_encode(b"fo"), "Zm8=");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn ui_p2_03_ipc_get_alerts_and_list_rules_roundtrip() {
    let sample_alerts = vec![
        AlertRecord {
            alert_id: "alert-pending-1".to_string(),
            timestamp_ms: 1_700_000_010_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "CANARY-COOKIE-DB".to_string(),
            title: "Chrome Cookies Read".to_string(),
            process_instance_id: Some("1001:133765432100000000".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: r#"{"target_path":"C:\\Users\\dev\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies","category":"cookie_db"}"#.to_string(),
            resolved_at_ms: None,
        },
        AlertRecord {
            alert_id: "alert-expired-2".to_string(),
            timestamp_ms: 1_700_000_000_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "CANARY-HONEYPOT".to_string(),
            title: "Honeypot Write Detected".to_string(),
            process_instance_id: Some("2002:133765432100000000".to_string()),
            process_suspended: true,
            status: AlertStatus::ExpiredSuspended,
            context_json: r#"{"target_path":"C:\\Users\\dev\\Documents\\!00_LocalEDR_Canary_DoNotEdit.docx","category":"honeypot","is_write_or_delete":true}"#.to_string(),
            resolved_at_ms: None,
        },
    ];

    let sample_rules = vec![AllowlistRuleRecord {
        rule_id: "rule-allow-1".to_string(),
        scope: RuleScope::FileCanaryAllow,
        exe_path_pattern: r"C:\Program Files\DevTool\tool.exe".to_string(),
        sha256: Some("deadbeef".repeat(8)),
        signer_subject: Some("CN=DevTool Corp".to_string()),
        root_thumbprint: Some("00112233445566778899AABBCCDDEEFF00112233".to_string()),
        allowed_target: Some(r"C:\Users\*\Cookies".to_string()),
        created_at_ms: 1_700_000_020_000,
        created_by: "user".to_string(),
    }];

    let alerts_clone = sample_alerts.clone();
    let rules_clone = sample_rules.clone();

    let mut stream = MockIpcStream::new(move |req| match req {
        IpcRequest::GetAlerts { status, limit } => {
            assert_eq!(limit, 50);
            let filtered = match status {
                Some(st) => alerts_clone
                    .iter()
                    .filter(|a| a.status == st)
                    .cloned()
                    .collect(),
                None => alerts_clone.clone(),
            };
            IpcResponse::Alerts(filtered)
        }
        IpcRequest::ListRules { scope } => {
            let filtered = match scope {
                Some(sc) => rules_clone
                    .iter()
                    .filter(|r| r.scope == sc)
                    .cloned()
                    .collect(),
                None => rules_clone.clone(),
            };
            IpcResponse::Rules(filtered)
        }
        other => panic!("unexpected request: {other:?}"),
    });

    let all_alerts_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::GetAlerts {
            status: None,
            limit: 50,
        },
    )
    .expect("get_alerts roundtrip");
    assert_eq!(
        parse_alerts_response(all_alerts_resp).expect("parse alerts"),
        sample_alerts
    );

    let expired_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::GetAlerts {
            status: Some(AlertStatus::ExpiredSuspended),
            limit: 50,
        },
    )
    .expect("filtered get_alerts roundtrip");
    let expired_alerts = parse_alerts_response(expired_resp).expect("parse filtered alerts");
    assert_eq!(expired_alerts.len(), 1);
    assert_eq!(expired_alerts[0].alert_id, "alert-expired-2");

    let rules_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::ListRules {
            scope: Some(RuleScope::FileCanaryAllow),
        },
    )
    .expect("list_rules roundtrip");
    assert_eq!(
        parse_rules_response(rules_resp).expect("parse rules"),
        sample_rules
    );

    let err = parse_rules_response(IpcResponse::Error {
        code: "STORE_ERROR".to_string(),
        message: "db locked".to_string(),
    })
    .expect_err("error variant should return Err");
    assert!(err.contains("STORE_ERROR"));
}

#[test]
fn ui_p2_04_ipc_resolve_alert_all_decisions_roundtrip() {
    let decisions = vec![
        (
            "alert-1",
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
            "resolved TERMINATED_BLOCKED",
        ),
        ("alert-2", AlertDecision::AllowOnce, "resolved APPROVED_ONCE"),
        (
            "alert-3",
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: Some(r"C:\Users\*\Cookies".to_string()),
            },
            "resolved APPROVED_RULE",
        ),
    ];

    let mut stream = MockIpcStream::new(|req| match req {
        IpcRequest::ResolveAlert { alert_id, decision } => {
            if alert_id == "missing-alert" {
                IpcResponse::Error {
                    code: "NOT_FOUND".to_string(),
                    message: "alert not found".to_string(),
                }
            } else {
                IpcResponse::Ack {
                    message: format!(
                        "resolved {} for {alert_id}",
                        decision.resulting_status().as_db_str()
                    ),
                }
            }
        }
        other => panic!("unexpected request: {other:?}"),
    });

    for (alert_id, decision, expected_fragment) in decisions {
        let resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::ResolveAlert {
                alert_id: alert_id.to_string(),
                decision,
            },
        )
        .expect("resolve_alert roundtrip");
        let msg = parse_ack_response(resp).expect("parse ack");
        assert!(msg.contains(expected_fragment), "got ack: {msg}");
        assert!(msg.contains(alert_id));
    }

    let err_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::ResolveAlert {
            alert_id: "missing-alert".to_string(),
            decision: AlertDecision::AllowOnce,
        },
    )
    .expect("missing alert roundtrip");
    let err = parse_ack_response(err_resp).expect_err("not found returns Err");
    assert!(err.contains("NOT_FOUND"));
}

#[test]
fn ui_p2_05_notify_oneshot_json_output() {
    assert!(is_os_toast_disabled_value(Some("1")));
    assert!(is_os_toast_disabled_value(Some("true")));
    assert!(is_os_toast_disabled_value(Some("YES")));
    assert!(!is_os_toast_disabled_value(None));
    assert!(!is_os_toast_disabled_value(Some("")));
    assert!(!is_os_toast_disabled_value(Some("0")));
    assert!(!is_os_toast_disabled_value(Some("false")));

    let live_alert = AlertRecord {
        alert_id: "alert-cookie-42".to_string(),
        timestamp_ms: 1_700_000_050_000,
        severity: AlertSeverity::Critical,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "CANARY-COOKIE-DB".to_string(),
        title: "Chrome Cookies Accessed".to_string(),
        process_instance_id: Some("4242:133765432100000000".to_string()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "target_path": r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            "exe_path": r"C:\Users\dev\Downloads\stealer.exe",
            "category": "cookie_db",
            "is_write_or_delete": false,
            "access_mask": 0x00120089
        })
        .to_string(),
        resolved_at_ms: None,
    };

    let online_event = build_notify_oneshot_event(
        "alert-cookie-42",
        r"\\.\pipe\localedr-ipc",
        Ok(vec![live_alert]),
        true,
    );
    let online_json = serde_json::to_string(&online_event).expect("serialize online event");
    let parsed: serde_json::Value =
        serde_json::from_str(&online_json).expect("valid JSON output");

    assert_eq!(parsed["mode"], "notify_oneshot");
    assert_eq!(parsed["alert_id"], "alert-cookie-42");
    assert_eq!(parsed["launch_uri"], "ledr://alert/alert-cookie-42");
    assert_eq!(parsed["daemon_reachable"], true);
    assert_eq!(parsed["alert_found"], true);
    assert_eq!(parsed["process_suspended"], true);
    assert_eq!(parsed["os_toast_status"], "disabled_by_env");
    assert_eq!(parsed["status"], "disabled_by_env");
    assert_eq!(
        parsed["target_path"],
        r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Cookies"
    );
    let toast_xml = parsed["toast_xml"].as_str().expect("toast_xml string");
    assert!(toast_xml.contains("launch=\"ledr://alert/alert-cookie-42\""));
    assert!(toast_xml.contains("[SUSPENDED]"));
    assert!(toast_xml.contains("Chrome Cookies Accessed"));

    // Graceful fallback when daemon is offline.
    let offline_client = IpcClient::new(r"\\.\pipe\localedr-ui-nonexistent-test-pipe");
    let offline_event = build_notify_oneshot_event(
        "alert-offline-99",
        offline_client.pipe_name(),
        offline_client.get_alerts(None, 50),
        true,
    );
    assert!(!offline_event.daemon_reachable);
    assert!(!offline_event.alert_found);
    assert_eq!(offline_event.launch_uri, "ledr://alert/alert-offline-99");
    assert!(offline_event
        .toast_xml
        .contains("launch=\"ledr://alert/alert-offline-99\""));
    assert!(serde_json::to_string(&offline_event).is_ok());
}

#[test]
fn ui_p2_06_register_uri_args_and_hkcu_idempotent() {
    assert_eq!(
        parse_launch_mode(["ledr-ui", "--register-uri"]),
        Ok(LaunchMode::RegisterUri)
    );
    assert!(parse_launch_mode(["ledr-ui", "--register-uri=true"]).is_err());

    assert_eq!(
        format_ledr_uri_command(std::path::Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe")),
        r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
    );
    assert_eq!(
        format_ledr_uri_command(std::path::Path::new(r"\\?\C:\Program Files\LocalEDR\ledr-ui.exe")),
        r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
    );

    let sample_outcome = UriRegistrationOutcome {
        registry_key: format!(r"HKCU\{LEDR_URI_REG_SUBKEY}"),
        command: r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#.to_string(),
        updated: true,
    };
    let event = build_register_uri_event(&sample_outcome);
    let json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&event).expect("serialize register_uri"))
            .expect("valid JSON");
    assert_eq!(json["mode"], "register_uri");
    assert_eq!(json["scheme"], "ledr");
    assert_eq!(json["registry_key"], r"HKCU\Software\Classes\ledr");
    assert_eq!(json["updated"], true);
    assert_eq!(json["status"], "registered");

    #[cfg(windows)]
    {
        struct TestKeyCleanup(String);
        impl Drop for TestKeyCleanup {
            fn drop(&mut self) {
                win_uri_reg::reg_delete_hkcu_tree(&self.0);
            }
        }

        let root_cleanup = format!(r"Software\LocalEDRTest\ui-p2-06-{}", std::process::id());
        let subkey = format!(r"{root_cleanup}\ledr");
        let _guard = TestKeyCleanup(root_cleanup);

        let first_exe = std::path::Path::new(r"C:\Temp\LocalEDR\v1\ledr-ui.exe");
        let first = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, first_exe)
            .expect("initial test HKCU registration");
        assert!(first.updated);
        assert_eq!(first.command, r#""C:\Temp\LocalEDR\v1\ledr-ui.exe" "%1""#);

        let base_key = win_uri_reg::reg_open_hkcu(&subkey, 0x0001)
            .expect("open base key")
            .expect("base key exists");
        assert_eq!(
            win_uri_reg::reg_query_sz(&base_key, None).expect("query default"),
            Some(LEDR_URI_DESCRIPTION.to_string())
        );
        assert_eq!(
            win_uri_reg::reg_query_sz(&base_key, Some("URL Protocol"))
                .expect("query URL Protocol"),
            Some(String::new())
        );

        // Second call with identical path must be idempotent (`updated == false`).
        let second = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, first_exe)
            .expect("idempotent check");
        assert!(!second.updated);
        assert_eq!(build_register_uri_event(&second).status, "already_registered");

        // Changing executable path updates `shell\open\command` (`updated == true`).
        let next_exe = std::path::Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe");
        let third = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, next_exe)
            .expect("update path");
        assert!(third.updated);
        assert_eq!(
            third.command,
            r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
        );
    }
}

#[test]
fn ui_p3_01_ipc_upsert_delete_rule_and_domain_risk_roundtrip() {
    let rule = AllowlistRuleRecord {
        rule_id: "RULE-UI-P3-01".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: r"C:\Tools\bad.exe".to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("198.51.100.5".to_string()),
        created_at_ms: 1_732_070_000_000,
        created_by: "user_policy".to_string(),
    };

    let mut stream = MockIpcStream::new(|req| match req {
        IpcRequest::UpsertRule { rule: r } => IpcResponse::Ack {
            message: format!("rule {} saved", r.rule_id),
        },
        IpcRequest::DeleteRule { rule_id } => IpcResponse::Ack {
            message: format!("rule {rule_id} deleted"),
        },
        IpcRequest::CheckDomainRisk { domain } => IpcResponse::DomainRisk {
            domain: domain.clone(),
            is_nrd: domain.ends_with(".fresh-c2.example"),
            is_homograph: domain.contains("xn--"),
            matched_brand: if domain.contains("xn--") {
                Some("paypal.com".to_string())
            } else {
                None
            },
        },
        other => IpcResponse::Error {
            code: "UNEXPECTED".to_string(),
            message: format!("{other:?}"),
        },
    });

    let upsert_resp =
        IpcClient::send_request_over_stream(&mut stream, &IpcRequest::UpsertRule { rule })
            .expect("upsert roundtrip");
    let upsert_msg = parse_ack_response(upsert_resp).expect("parse upsert ack");
    assert!(upsert_msg.contains("RULE-UI-P3-01"));

    let del_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::DeleteRule {
            rule_id: "RULE-UI-P3-01".to_string(),
        },
    )
    .expect("delete roundtrip");
    let del_msg = parse_ack_response(del_resp).expect("parse delete ack");
    assert!(del_msg.contains("RULE-UI-P3-01"));

    let risk_resp = IpcClient::send_request_over_stream(
        &mut stream,
        &IpcRequest::CheckDomainRisk {
            domain: "api.fresh-c2.example".to_string(),
        },
    )
    .expect("domain risk roundtrip");
    let risk = ipc::parse_domain_risk_response(risk_resp).expect("parse domain risk");
    assert_eq!(risk.domain, "api.fresh-c2.example");
    assert!(risk.is_nrd);
    assert!(!risk.is_homograph);
    assert!(risk.matched_brand.is_none());
}

#[test]
fn ui_p3_02_local_defense_status_honeypot_detection_and_static_templates() {
    let tmp_root = std::env::temp_dir().join(format!(
        "ledr-ui-p3-status-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_root);
    let docs = tmp_root.join("Documents");
    let desk = tmp_root.join("Desktop");
    std::fs::create_dir_all(&docs).expect("create Documents");
    std::fs::create_dir_all(&desk).expect("create Desktop");
    std::fs::write(docs.join(HONEYPOT_FILENAME), b"decoy-docx-bytes-1")
        .expect("write Documents honeypot");
    std::fs::write(desk.join(HONEYPOT_FILENAME), b"decoy-docx-2")
        .expect("write Desktop honeypot");
    let fake_bridge = tmp_root.join("ledr-bridge-nm.exe");
    std::fs::write(&fake_bridge, b"stub-bridge").expect("write bridge stub");

    let status = collect_local_defense_status_with(
        Some(&tmp_root),
        &fake_bridge,
        true,
        false,
    );
    assert_eq!(status.honeypots.len(), 3);
    let doc_item = status
        .honeypots
        .iter()
        .find(|h| h.folder == "Documents")
        .expect("Documents item");
    assert!(doc_item.deployed);
    assert_eq!(doc_item.size_bytes, Some(18));

    let desk_item = status
        .honeypots
        .iter()
        .find(|h| h.folder == "Desktop")
        .expect("Desktop item");
    assert!(desk_item.deployed);
    assert_eq!(desk_item.size_bytes, Some(12));

    let pic_item = status
        .honeypots
        .iter()
        .find(|h| h.folder == "Pictures")
        .expect("Pictures item");
    assert!(!pic_item.deployed);
    assert_eq!(pic_item.size_bytes, None);

    assert_eq!(status.protected_paths.len(), 6);
    assert!(status.protected_paths.iter().any(|p| p.category == "CookieDb"));
    assert!(status.protected_paths.iter().any(|p| p.category == "SshKey"));
    assert!(status.protected_paths.iter().any(|p| p.category == "CloudCreds"));
    assert!(status.protected_paths.iter().any(|p| p.category == "EnvFile"));
    assert!(status.protected_paths.iter().any(|p| p.category == "Honeypot"));
    assert!(status.protected_paths.iter().any(|p| p.category == "AutorunRegistry"));

    assert!(status.browser_shield.bridge_binary_present);
    assert!(status.browser_shield.native_host_registered);
    assert!(!status.browser_shield.uri_scheme_registered);

    let _ = std::fs::remove_dir_all(&tmp_root);
}

#[test]
fn ui_p3_03_network_alert_toast_extracts_dst_and_domain() {
    let net_alert = AlertRecord {
        alert_id: "net-alert-p3".to_string(),
        timestamp_ms: 1_732_070_000_000,
        severity: AlertSeverity::High,
        source_layer: "LAYER_3_NETWORK".to_string(),
        rule_id: "LEDR-NET-UNKNOWN-OUTBOUND".to_string(),
        title: "Unknown Process Outbound Connection".to_string(),
        process_instance_id: Some("6000:133765432100000000".to_string()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "dst_ip": "198.51.100.42",
            "dst_port": 443,
            "domain_hint": "c2.fresh-nrd.example",
            "exe_path": r"C:\Tools\probe.exe",
        })
        .to_string(),
        resolved_at_ms: None,
    };
    let summary = summarize_alert_for_toast(&net_alert.alert_id, Some(&net_alert));
    assert_eq!(
        summary.target_path.as_deref(),
        Some("c2.fresh-nrd.example (198.51.100.42:443)")
    );
    assert_eq!(summary.exe_path.as_deref(), Some(r"C:\Tools\probe.exe"));
    let xml = build_winrt_toast_xml(&summary);
    assert!(xml.contains("c2.fresh-nrd.example (198.51.100.42:443)"));
}

#[test]
fn ui_p3_04_toast_os_setting_suppression_and_aumid_registration() {
    assert!(is_os_toast_suppressed_by_setting(Some(0)));
    assert!(!is_os_toast_suppressed_by_setting(Some(1)));
    assert!(!is_os_toast_suppressed_by_setting(None));

    // Ensure notify.rs no longer spawns PowerShell with -EncodedCommand / FromBase64String
    // (which self-triggered LEDR-SCRIPT-001 and LEDR-LOTL-001).
    let notify_src = include_str!("notify.rs");
    assert!(
        !notify_src.contains("powershell.exe"),
        "notify.rs must use native WinRT instead of spawning powershell.exe"
    );
    assert!(
        !notify_src.contains("FromBase64String"),
        "notify.rs must not emit FromBase64String scripts"
    );
    assert!(
        !notify_src.contains("-EncodedCommand"),
        "notify.rs must not emit -EncodedCommand arguments"
    );

    #[cfg(windows)]
    {
        struct TestKeyCleanup(String);
        impl Drop for TestKeyCleanup {
            fn drop(&mut self) {
                win_uri_reg::reg_delete_hkcu_tree(&self.0);
            }
        }

        let root_cleanup = format!(r"Software\LocalEDRTest\ui-p3-04-{}", std::process::id());
        let aumid_subkey = format!(r"{root_cleanup}\AppUserModelId\LocalEDR.AlertUI");
        let _guard = TestKeyCleanup(root_cleanup);

        let first =
            win_uri_reg::ensure_hkcu_aumid_registered_at(&aumid_subkey, LEDR_AUMID_DISPLAY_NAME)
                .expect("initial AUMID registration");
        assert!(first, "initial AUMID registration must report updated=true");

        let key = win_uri_reg::reg_open_hkcu(&aumid_subkey, 0x0001)
            .expect("open AUMID key")
            .expect("AUMID key exists");
        assert_eq!(
            win_uri_reg::reg_query_sz(&key, Some("DisplayName")).expect("query DisplayName"),
            Some(LEDR_AUMID_DISPLAY_NAME.to_string())
        );

        let second =
            win_uri_reg::ensure_hkcu_aumid_registered_at(&aumid_subkey, LEDR_AUMID_DISPLAY_NAME)
                .expect("idempotent AUMID check");
        assert!(!second, "second AUMID registration must be idempotent");
    }
}

struct TempTestDir(std::path::PathBuf);

impl TempTestDir {
    fn new(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_test_manifest(
    manifest_path: &std::path::Path,
    name: &str,
    host_type: &str,
    bridge_path: &str,
    allowed_origins: &[&str],
) {
    let doc = serde_json::json!({
        "name": name,
        "description": "LocalEDR Browser Shield Native Messaging Bridge",
        "path": bridge_path,
        "type": host_type,
        "allowed_origins": allowed_origins,
    });
    std::fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&doc).expect("serialize test manifest"),
    )
    .expect("write test manifest");
}

#[test]
fn ui_p4_01_hkcu_hklm_dual_probe_and_browser_aggregation() {
    let tmp = TempTestDir::new("ledr-ui-p4-01");
    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge stub");
    let bridge_str = bridge_exe.to_string_lossy().into_owned();
    let expected_origin = format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/");

    let chrome_hkcu = tmp.0.join("chrome_hkcu.json");
    let chrome_hklm = tmp.0.join("chrome_hklm.json");
    let edge_hklm = tmp.0.join("edge_hklm.json");
    let brave_hklm = tmp.0.join("brave_hklm.json");
    for p in [&chrome_hkcu, &chrome_hklm, &edge_hklm, &brave_hklm] {
        write_test_manifest(p, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin]);
    }

    let allowed = vec![tmp.0.clone()];

    // 1. HKCU only (Chrome + Edge), URI HKCU only
    let hkcu_only = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Present(edge_hklm.to_string_lossy().into_owned()),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(chrome_hkcu.to_string_lossy().into_owned()),
                    hklm: RegistryStringProbe::Absent,
                },
            ],
            uri_hkcu: true,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(hkcu_only.browser_shield.native_host_registered);
    assert_eq!(hkcu_only.browser_shield.native_host_scope.as_deref(), Some("HKCU"));
    assert_eq!(hkcu_only.browser_shield.registered_browsers, vec!["Chrome", "Edge"]);
    assert!(hkcu_only.browser_shield.manifest_valid);
    assert_eq!(hkcu_only.browser_shield.uri_scheme_scope.as_deref(), Some("HKCU"));
    assert_eq!(hkcu_only.browser_shield.expected_extension_id, EXPECTED_CHROME_EXTENSION_ID);

    // 2. HKLM only (Brave), URI HKLM only
    let hklm_only = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![BrowserRegistryProbe {
                browser: "Brave".to_string(),
                hkcu: RegistryStringProbe::Absent,
                hklm: RegistryStringProbe::Present(brave_hklm.to_string_lossy().into_owned()),
            }],
            uri_hkcu: false,
            uri_hklm: true,
        },
        &allowed,
    );
    assert_eq!(hklm_only.browser_shield.native_host_scope.as_deref(), Some("HKLM"));
    assert_eq!(hklm_only.browser_shield.registered_browsers, vec!["Brave"]);
    assert!(hklm_only.browser_shield.manifest_valid);
    assert_eq!(hklm_only.browser_shield.uri_scheme_scope.as_deref(), Some("HKLM"));

    // 3. HKCU + HKLM combined: Chrome HKCU shadows broken HKLM; Edge HKLM only; Brave absent
    let broken_hklm = tmp.0.join("missing_shadowed.json");
    let both = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Brave".to_string(),
                    hkcu: RegistryStringProbe::Absent,
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(chrome_hkcu.to_string_lossy().into_owned()),
                    hklm: RegistryStringProbe::Present(broken_hklm.to_string_lossy().into_owned()),
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Absent,
                    hklm: RegistryStringProbe::Present(edge_hklm.to_string_lossy().into_owned()),
                },
            ],
            uri_hkcu: true,
            uri_hklm: true,
        },
        &allowed,
    );
    assert_eq!(both.browser_shield.native_host_scope.as_deref(), Some("HKCU+HKLM"));
    assert_eq!(both.browser_shield.uri_scheme_scope.as_deref(), Some("HKCU+HKLM"));
    assert_eq!(both.browser_shield.registered_browsers, vec!["Chrome", "Edge"]);
    assert!(both.browser_shield.manifest_valid);
    assert_eq!(both.browser_shield.browsers[0].browser, "Chrome");
    assert_eq!(both.browser_shield.browsers[0].effective_scope.as_deref(), Some("HKCU"));
    assert!(both.browser_shield.browsers[0].hkcu_registered);
    assert!(both.browser_shield.browsers[0].hklm_registered);
    assert_eq!(both.browser_shield.browsers[1].browser, "Edge");
    assert_eq!(both.browser_shield.browsers[1].effective_scope.as_deref(), Some("HKLM"));
    assert_eq!(both.browser_shield.browsers[2].browser, "Brave");
    assert_eq!(both.browser_shield.browsers[2].effective_scope, None);

    #[cfg(windows)]
    {
        struct TestKeyCleanup(String);
        impl Drop for TestKeyCleanup {
            fn drop(&mut self) {
                win_uri_reg::reg_delete_hkcu_tree(&self.0);
            }
        }

        let root = format!(r"Software\LocalEDRTest\ui-p4-01-{}", std::process::id());
        let _guard = TestKeyCleanup(root.clone());

        // Absent subkey in HKCU & HKLM
        let absent_subkey = format!(r"{root}\MissingKey");
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive(false, &absent_subkey).expect("probe absent HKCU"),
            RegDefaultSzProbe::Absent
        );
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive(true, &absent_subkey).expect("probe absent HKLM"),
            RegDefaultSzProbe::Absent
        );

        // Present non-empty default value via ensure_hkcu_uri_registered_at
        let uri_base = format!(r"{root}\ledr");
        win_uri_reg::ensure_hkcu_uri_registered_at(&uri_base, &bridge_exe).expect("write test uri key");
        let cmd_subkey = format!(r"{uri_base}\shell\open\command");
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive(false, &cmd_subkey).expect("probe present HKCU"),
            RegDefaultSzProbe::Present(format_ledr_uri_command(&bridge_exe))
        );

        // Existing key with empty default value (`EmptyOrInvalidType`)
        let empty_aumid = format!(r"{root}\EmptyDefault");
        win_uri_reg::ensure_hkcu_aumid_registered_at(&empty_aumid, "LocalEDR").expect("create test key");
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive(false, &empty_aumid).expect("probe empty default"),
            RegDefaultSzProbe::EmptyOrInvalidType
        );
    }
}

#[test]
fn ui_p4_02_manifest_validation_matrix() {
    let tmp = TempTestDir::new("ledr-ui-p4-02");
    let allowed = vec![tmp.0.clone()];
    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge stub");
    let bridge_str = bridge_exe.to_string_lossy().into_owned();
    let expected_origin_upper =
        format!("CHROME-EXTENSION://{}/", EXPECTED_CHROME_EXTENSION_ID.to_ascii_uppercase());

    // 1. Valid manifest (case-insensitive allowed_origins)
    let valid_path = tmp.0.join("valid.json");
    write_test_manifest(&valid_path, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin_upper]);
    assert_eq!(
        validate_manifest_file_in_allowed_dirs(&valid_path, EXPECTED_CHROME_EXTENSION_ID, &allowed),
        Ok(())
    );

    // 2. Missing manifest file
    let missing_path = tmp.0.join("nonexistent.json");
    let err =
        validate_manifest_file_in_allowed_dirs(&missing_path, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("does not exist"), "unexpected error: {err}");

    // 3. Path points to directory instead of regular file
    let dir_path = tmp.0.join("subdir");
    std::fs::create_dir_all(&dir_path).expect("create subdir");
    let err =
        validate_manifest_file_in_allowed_dirs(&dir_path, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("not a regular file"), "unexpected error: {err}");

    // 4. Malformed JSON
    let bad_json = tmp.0.join("bad.json");
    std::fs::write(&bad_json, b"{not valid json").expect("write bad json");
    let err =
        validate_manifest_file_in_allowed_dirs(&bad_json, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("invalid manifest JSON"), "unexpected error: {err}");

    // 5. Missing bridge exe, wrong type, wrong name, wrong allowed_origins
    let missing_exe = tmp.0.join("missing_exe.json");
    let absent_exe = tmp.0.join("absent-bridge.exe").to_string_lossy().into_owned();
    write_test_manifest(
        &missing_exe,
        "com.wrong.host",
        "pipe",
        &absent_exe,
        &["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"],
    );
    let err =
        validate_manifest_file_in_allowed_dirs(&missing_exe, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("manifest 'name'"), "unexpected error: {err}");
    assert!(err.contains("manifest 'type'"), "unexpected error: {err}");
    assert!(err.contains("not found"), "unexpected error: {err}");
    assert!(err.contains("allowed_origins"), "unexpected error: {err}");

    // 6. Relative path & directory path for bridge executable
    let rel_exe = tmp.0.join("rel_exe.json");
    write_test_manifest(
        &rel_exe,
        NATIVE_HOST_NAME,
        "stdio",
        "ledr-bridge-nm.exe",
        &[&format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/")],
    );
    let err =
        validate_manifest_file_in_allowed_dirs(&rel_exe, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("must be absolute"), "unexpected error: {err}");

    // 7. Missing trailing slash in allowed_origins
    let no_slash = tmp.0.join("no_slash.json");
    write_test_manifest(
        &no_slash,
        NATIVE_HOST_NAME,
        "stdio",
        &bridge_str,
        &[&format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}")],
    );
    let err =
        validate_manifest_file_in_allowed_dirs(&no_slash, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("allowed_origins"), "unexpected error: {err}");

    // 8. Size limit boundary: exact 64 KiB passes, 64 KiB + 1 byte fails
    let base_json = serde_json::to_string(&serde_json::json!({
        "name": NATIVE_HOST_NAME,
        "description": "",
        "path": bridge_str,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/")],
    }))
    .expect("serialize base");
    let exact_limit = MAX_MANIFEST_BYTES as usize;
    assert!(base_json.len() < exact_limit);
    let padded_exact = format!("{base_json}{}", " ".repeat(exact_limit - base_json.len()));
    assert_eq!(padded_exact.len(), exact_limit);
    let exact_path = tmp.0.join("exact64k.json");
    std::fs::write(&exact_path, padded_exact.as_bytes()).expect("write 64KiB manifest");
    assert_eq!(
        validate_manifest_file_in_allowed_dirs(&exact_path, EXPECTED_CHROME_EXTENSION_ID, &allowed),
        Ok(())
    );

    let over_limit = format!("{padded_exact} ");
    assert_eq!(over_limit.len(), exact_limit + 1);
    let over_path = tmp.0.join("over64k.json");
    std::fs::write(&over_path, over_limit.as_bytes()).expect("write 64KiB+1 manifest");
    let err =
        validate_manifest_file_in_allowed_dirs(&over_path, EXPECTED_CHROME_EXTENSION_ID, &allowed)
            .unwrap_err();
    assert!(err.contains("64 KiB limit"), "unexpected error: {err}");
}

#[test]
fn ui_p4_03_multi_browser_partial_failure_and_empty_registry_value() {
    let tmp = TempTestDir::new("ledr-ui-p4-03");
    let allowed = vec![tmp.0.clone()];
    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge stub");
    let bridge_str = bridge_exe.to_string_lossy().into_owned();
    let expected_origin = format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/");

    let chrome_valid = tmp.0.join("chrome_valid.json");
    write_test_manifest(&chrome_valid, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin]);
    let edge_bad = tmp.0.join("edge_bad.json");
    std::fs::write(&edge_bad, b"{corrupt").expect("write corrupt manifest");

    // Partial failure: Chrome valid, Edge corrupt -> overall manifest_valid must be false
    let partial = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(chrome_valid.to_string_lossy().into_owned()),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Present(edge_bad.to_string_lossy().into_owned()),
                    hklm: RegistryStringProbe::Absent,
                },
            ],
            uri_hkcu: true,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(partial.browser_shield.native_host_registered);
    assert!(!partial.browser_shield.manifest_valid);
    assert_eq!(
        partial.browser_shield.manifest_path.as_deref(),
        Some(edge_bad.to_string_lossy().as_ref())
    );
    let err = partial.browser_shield.manifest_error.as_deref().expect("manifest_error");
    assert!(err.contains("Edge:"), "expected Edge error, got: {err}");
    assert!(partial.browser_shield.browsers[0].manifest_valid);
    assert!(!partial.browser_shield.browsers[1].manifest_valid);

    // Empty REG_SZ / AccessError must surface as registered + invalid, never hidden as unregistered
    let empty_reg = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::EmptyOrInvalidType,
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Absent,
                    hklm: RegistryStringProbe::AccessError("OS status 5".to_string()),
                },
            ],
            uri_hkcu: false,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(empty_reg.browser_shield.native_host_registered);
    assert_eq!(empty_reg.browser_shield.registered_browsers, vec!["Chrome", "Edge"]);
    assert!(!empty_reg.browser_shield.manifest_valid);
    let err = empty_reg.browser_shield.manifest_error.as_deref().expect("error");
    assert!(err.contains("Chrome: registry default value is empty"), "got: {err}");
    assert!(err.contains("Edge: OS status 5"), "got: {err}");
}

#[test]
fn ui_p4_04_sensitive_user_files_never_opened() {
    let tmp = TempTestDir::new("ledr-ui-p4-04");
    let allowed = vec![tmp.0.clone()];
    let cookies_dir = tmp
        .0
        .join("AppData")
        .join("Local")
        .join("Google")
        .join("Chrome")
        .join("User Data")
        .join("Default");
    let ssh_dir = tmp.0.join(".ssh");
    std::fs::create_dir_all(&cookies_dir).expect("create Chrome dir");
    std::fs::create_dir_all(&ssh_dir).expect("create .ssh dir");

    let cookies_path = cookies_dir.join("Cookies");
    let ssh_key_path = ssh_dir.join("id_rsa");
    std::fs::write(&cookies_path, b"secret-cookie-db").expect("write Cookies");
    std::fs::write(&ssh_key_path, b"secret-ssh-key").expect("write id_rsa");

    // Hold exclusive locks (share_mode = 0 on Windows) so any file open attempt would fail.
    #[cfg(windows)]
    let (_cookies_lock, _ssh_lock) = {
        use std::os::windows::fs::OpenOptionsExt;
        let c = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&cookies_path)
            .expect("lock Cookies");
        let s = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&ssh_key_path)
            .expect("lock id_rsa");
        (c, s)
    };

    let docs = tmp.0.join("Documents");
    std::fs::create_dir_all(&docs).expect("create Documents");
    std::fs::write(docs.join(HONEYPOT_FILENAME), b"decoy").expect("write honeypot");

    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge");
    let manifest_path = tmp.0.join("manifest.json");
    write_test_manifest(
        &manifest_path,
        NATIVE_HOST_NAME,
        "stdio",
        bridge_exe.to_string_lossy().as_ref(),
        &[&format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/")],
    );

    let status = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![BrowserRegistryProbe {
                browser: "Chrome".to_string(),
                hkcu: RegistryStringProbe::Present(manifest_path.to_string_lossy().into_owned()),
                hklm: RegistryStringProbe::Absent,
            }],
            uri_hkcu: true,
            uri_hklm: false,
        },
        &allowed,
    );

    assert!(status.honeypots.iter().any(|h| h.folder == "Documents" && h.deployed));
    assert!(status.browser_shield.bridge_binary_present);
    assert!(status.browser_shield.manifest_valid);
    assert_eq!(std::fs::read(&cookies_path).ok().as_deref(), None.or(cfg!(not(windows)).then_some(b"secret-cookie-db".as_slice())));
}

#[test]
fn ui_p4_11_wow64_32_64_registry_view_probing_and_precedence() {
    // Pure precedence matrix: 32-bit view takes priority over 64-bit view (Chromium order).
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::Present(r"C:\m32.json".to_string()),
            RegistryStringProbe::Absent,
        ),
        RegistryStringProbe::Present(r"C:\m32.json".to_string())
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::Absent,
            RegistryStringProbe::Present(r"C:\m64.json".to_string()),
        ),
        RegistryStringProbe::Present(r"C:\m64.json".to_string())
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::Present(r"C:\m32.json".to_string()),
            RegistryStringProbe::Present(r"C:\m64.json".to_string()),
        ),
        RegistryStringProbe::Present(r"C:\m32.json".to_string())
    );
    assert_eq!(
        select_preferred_wow64_probe(RegistryStringProbe::Absent, RegistryStringProbe::Absent),
        RegistryStringProbe::Absent
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::EmptyString,
            RegistryStringProbe::Present(r"C:\m64.json".to_string()),
        ),
        RegistryStringProbe::EmptyString
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::Absent,
            RegistryStringProbe::EmptyString,
        ),
        RegistryStringProbe::EmptyString
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::EmptyOrInvalidType,
            RegistryStringProbe::EmptyString,
        ),
        RegistryStringProbe::EmptyString
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::EmptyOrInvalidType,
            RegistryStringProbe::Present(r"C:\m64.json".to_string()),
        ),
        RegistryStringProbe::Present(r"C:\m64.json".to_string())
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::EmptyOrInvalidType,
            RegistryStringProbe::Absent,
        ),
        RegistryStringProbe::EmptyOrInvalidType
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::AccessError("denied".to_string()),
            RegistryStringProbe::Present(r"C:\m64.json".to_string()),
        ),
        RegistryStringProbe::Present(r"C:\m64.json".to_string())
    );
    assert_eq!(
        select_preferred_wow64_probe(
            RegistryStringProbe::AccessError("denied".to_string()),
            RegistryStringProbe::Absent,
        ),
        RegistryStringProbe::AccessError("denied".to_string())
    );

    #[cfg(windows)]
    {
        assert_eq!(win_uri_reg::KEY_WOW64_64KEY, 0x0100);
        assert_eq!(win_uri_reg::KEY_WOW64_32KEY, 0x0200);

        // `HKCU\Software\Classes\CLSID` is WOW64-redirected on x64 Windows (32-bit view maps to
        // `WOW6432Node\CLSID` while 64-bit view stays under `CLSID`) without needing elevation.
        let parent = r"Software\Classes\CLSID";
        let child = format!("{{LocalEDR-Test-UI-P4-11-{}}}", std::process::id());
        let subkey = format!(r"{parent}\{child}");

        struct Wow64Cleanup {
            parent: &'static str,
            child: String,
        }
        impl Drop for Wow64Cleanup {
            fn drop(&mut self) {
                win_uri_reg::reg_delete_hkcu_tree_in_view(
                    self.parent,
                    &self.child,
                    RegWow64View::View32,
                );
                win_uri_reg::reg_delete_hkcu_tree_in_view(
                    self.parent,
                    &self.child,
                    RegWow64View::View64,
                );
            }
        }
        let _cleanup = Wow64Cleanup {
            parent,
            child: child.clone(),
        };
        // Clean slate before assertions.
        win_uri_reg::reg_delete_hkcu_tree_in_view(parent, &child, RegWow64View::View32);
        win_uri_reg::reg_delete_hkcu_tree_in_view(parent, &child, RegWow64View::View64);

        let val_32 = r"C:\ProgramData\LocalEDR\native-messaging\from-32bit.json";
        let val_64 = r"C:\ProgramData\LocalEDR\native-messaging\from-64bit.json";

        // 1. 32-bit view only: Native Messaging probe finds it; default/64-bit view stays Absent.
        win_uri_reg::reg_set_hkcu_default_sz_with_view(&subkey, val_32, RegWow64View::View32)
            .expect("write 32-bit view key");
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive_with_view(false, &subkey, RegWow64View::View32)
                .expect("query 32-bit view"),
            RegDefaultSzProbe::Present(val_32.to_string())
        );
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive_with_view(false, &subkey, RegWow64View::View64)
                .expect("query 64-bit view"),
            RegDefaultSzProbe::Absent
        );
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive(false, &subkey)
                .expect("default URI-style probe remains separate"),
            RegDefaultSzProbe::Absent
        );
        assert_eq!(
            probe_native_host_reg_string(false, &subkey),
            RegistryStringProbe::Present(val_32.to_string())
        );

        // 2. Both 32-bit and 64-bit registered: 32-bit view takes priority over 64-bit view.
        win_uri_reg::reg_set_hkcu_default_sz_with_view(&subkey, val_64, RegWow64View::View64)
            .expect("write 64-bit view key");
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive_with_view(false, &subkey, RegWow64View::View64)
                .expect("query 64-bit view"),
            RegDefaultSzProbe::Present(val_64.to_string())
        );
        assert_eq!(
            probe_native_host_reg_string(false, &subkey),
            RegistryStringProbe::Present(val_32.to_string())
        );

        // 3. 64-bit view only (after removing 32-bit view): falls back to 64-bit view.
        win_uri_reg::reg_delete_hkcu_tree_in_view(parent, &child, RegWow64View::View32);
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive_with_view(false, &subkey, RegWow64View::View32)
                .expect("query deleted 32-bit view"),
            RegDefaultSzProbe::Absent
        );
        assert_eq!(
            probe_native_host_reg_string(false, &subkey),
            RegistryStringProbe::Present(val_64.to_string())
        );

        // 4. Empty REG_SZ in 32-bit view with valid 64-bit view: Chromium stops at 32-bit view
        //    and fails host launch, so Native Messaging probe MUST return EmptyString (not val_64).
        win_uri_reg::reg_set_hkcu_default_sz_with_view(&subkey, "", RegWow64View::View32)
            .expect("write empty REG_SZ in 32-bit view");
        assert_eq!(
            win_uri_reg::reg_query_native_host_sz_in_hive_with_view(
                false,
                &subkey,
                RegWow64View::View32
            )
            .expect("query empty REG_SZ in 32-bit view"),
            RegNativeHostSzProbe::EmptyString
        );
        // URI protocol probe remains separate and continues collapsing empty REG_SZ to EmptyOrInvalidType.
        assert_eq!(
            win_uri_reg::reg_query_default_sz_in_hive_with_view(false, &subkey, RegWow64View::View32)
                .expect("URI-style probe on empty REG_SZ"),
            RegDefaultSzProbe::EmptyOrInvalidType
        );
        assert_eq!(
            probe_native_host_reg_string(false, &subkey),
            RegistryStringProbe::EmptyString
        );
        let empty32_status = collect_local_defense_status_with_probe(
            None,
            Path::new(r"C:\Program Files\LocalEDR\ledr-bridge-nm.exe"),
            &BrowserShieldProbe {
                browsers: vec![BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Absent,
                    hklm: probe_native_host_reg_string(false, &subkey),
                }],
                uri_hkcu: false,
                uri_hklm: false,
            },
        );
        assert!(empty32_status.browser_shield.native_host_registered);
        assert!(!empty32_status.browser_shield.manifest_valid);
        assert_eq!(
            empty32_status.browser_shield.manifest_status,
            MANIFEST_STATUS_INVALID
        );
        assert!(
            empty32_status
                .browser_shield
                .manifest_error
                .as_deref()
                .is_some_and(|msg| msg.contains("empty REG_SZ")),
            "expected empty REG_SZ error, got: {:?}",
            empty32_status.browser_shield.manifest_error
        );

        // 5. Non-REG_SZ (REG_DWORD) default value in 32-bit view: Chromium's ReadValue fails and
        //    falls back to the valid 64-bit view.
        win_uri_reg::reg_set_hkcu_default_dword_with_view(&subkey, 1, RegWow64View::View32)
            .expect("write REG_DWORD in 32-bit view");
        assert_eq!(
            win_uri_reg::reg_query_native_host_sz_in_hive_with_view(
                false,
                &subkey,
                RegWow64View::View32
            )
            .expect("query REG_DWORD in 32-bit view"),
            RegNativeHostSzProbe::MissingOrInvalidType
        );
        assert_eq!(
            probe_native_host_reg_string(false, &subkey),
            RegistryStringProbe::Present(val_64.to_string())
        );
    }
}

#[test]
fn ui_p4_12_manifest_description_missing_and_invalid_type() {
    let tmp = TempTestDir::new("ledr-ui-p4-12");
    let allowed = vec![tmp.0.clone()];
    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge stub");
    let bridge_str = bridge_exe.to_string_lossy().into_owned();
    let expected_origin = format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/");

    // 1. Missing required `description` field must fail validation
    let missing_desc = tmp.0.join("missing_desc.json");
    std::fs::write(
        &missing_desc,
        serde_json::to_vec(&serde_json::json!({
            "name": NATIVE_HOST_NAME,
            "path": bridge_str,
            "type": "stdio",
            "allowed_origins": [expected_origin],
        }))
        .expect("serialize missing description"),
    )
    .expect("write missing_desc.json");
    let err = validate_manifest_file_in_allowed_dirs(
        &missing_desc,
        EXPECTED_CHROME_EXTENSION_ID,
        &allowed,
    )
    .unwrap_err();
    assert!(
        err.contains("invalid manifest JSON") && err.contains("description"),
        "expected missing description error, got: {err}"
    );

    // 2. Non-string `description` types (null, number, array, object) must all fail
    for (label, bad_value) in [
        ("null", serde_json::Value::Null),
        ("number", serde_json::json!(42)),
        ("array", serde_json::json!(["LocalEDR"])),
        ("object", serde_json::json!({"text": "LocalEDR"})),
    ] {
        let bad_path = tmp.0.join(format!("bad_desc_{label}.json"));
        std::fs::write(
            &bad_path,
            serde_json::to_vec(&serde_json::json!({
                "name": NATIVE_HOST_NAME,
                "description": bad_value,
                "path": bridge_str,
                "type": "stdio",
                "allowed_origins": [format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/")],
            }))
            .expect("serialize bad description"),
        )
        .expect("write bad_desc manifest");
        let err = validate_manifest_file_in_allowed_dirs(
            &bad_path,
            EXPECTED_CHROME_EXTENSION_ID,
            &allowed,
        )
        .unwrap_err();
        assert!(
            err.contains("invalid manifest JSON"),
            "expected invalid JSON error for description={label}, got: {err}"
        );
    }

    // 3. End-to-end View 3 probe surfaces missing description as invalid
    let status = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![BrowserRegistryProbe {
                browser: "Chrome".to_string(),
                hkcu: RegistryStringProbe::Present(missing_desc.to_string_lossy().into_owned()),
                hklm: RegistryStringProbe::Absent,
            }],
            uri_hkcu: true,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(status.browser_shield.native_host_registered);
    assert!(!status.browser_shield.manifest_valid);
    let err = status
        .browser_shield
        .manifest_error
        .as_deref()
        .expect("manifest_error");
    assert!(
        err.contains("Chrome:") && err.contains("description"),
        "unexpected manifest_error: {err}"
    );
}

#[test]
fn ui_p4_13_manifest_allowlist_reparse_hardlink_and_sensitive_file_non_touch() {
    let tmp = TempTestDir::new("ledr-ui-p4-13");

    // 1. Default production allowlist consists strictly of the 2 LocalEDR manifest directories.
    let fake_local = Path::new(r"C:\Users\Alice\AppData\Local");
    let fake_progdata = Path::new(r"C:\ProgramData\LocalEDR");
    assert_eq!(
        default_allowed_manifest_dirs_from(Some(fake_local), fake_progdata),
        vec![
            PathBuf::from(r"C:\Users\Alice\AppData\Local\LocalEDR\native-messaging"),
            PathBuf::from(r"C:\ProgramData\LocalEDR\native-messaging"),
        ]
    );
    assert_eq!(
        default_allowed_manifest_dirs_from(None, fake_progdata),
        vec![PathBuf::from(r"C:\ProgramData\LocalEDR\native-messaging")]
    );

    let allowed_dir = tmp.0.join("allowed-native-messaging");
    let outside_dir = tmp.0.join("sensitive-user-data");
    std::fs::create_dir_all(&allowed_dir).expect("create allowed_dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside_dir");
    let allowed = vec![allowed_dir.clone()];

    let bridge_exe = tmp.0.join("ledr-bridge-nm.exe");
    std::fs::write(&bridge_exe, b"stub-bridge").expect("write bridge");
    let bridge_str = bridge_exe.to_string_lossy().into_owned();
    let expected_origin = format!("chrome-extension://{EXPECTED_CHROME_EXTENSION_ID}/");

    // Write valid manifest JSON into sensitive files so any accidental read would pass JSON checks.
    let cookies_path = outside_dir.join("Cookies");
    let ssh_key_path = outside_dir.join("id_rsa");
    write_test_manifest(&cookies_path, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin]);
    write_test_manifest(&ssh_key_path, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin]);

    // Create hard link inside allowed_dir pointing to sensitive Cookies before locking Cookies.
    let hardlink_manifest = allowed_dir.join("com.localedr.bridge.hardlink.json");
    std::fs::hard_link(&cookies_path, &hardlink_manifest).expect("create hard link to Cookies");

    // Hold exclusive share_mode(0) locks on Windows so any data-read open would fail with sharing violation.
    #[cfg(windows)]
    let (cookies_lock, _ssh_lock) = {
        use std::os::windows::fs::OpenOptionsExt;
        let c = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&cookies_path)
            .expect("lock Cookies");
        let s = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&ssh_key_path)
            .expect("lock id_rsa");
        (c, s)
    };

    // 2. Production default allowlist rejects registry values pointing directly to Cookies / id_rsa.
    let default_status = collect_local_defense_status_with_probe(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        cookies_path.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        ssh_key_path.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
            ],
            uri_hkcu: false,
            uri_hklm: false,
        },
    );
    assert!(!default_status.browser_shield.manifest_valid);
    for detail in &default_status.browser_shield.browsers {
        assert!(!detail.manifest_valid);
        let err = detail.manifest_error.as_deref().expect("expected rejection error");
        assert!(
            err.contains("outside allowed LocalEDR manifest directories"),
            "expected allowlist rejection without file I/O, got: {err}"
        );
    }

    // 3. Direct validate_manifest_file also rejects out-of-scope / traversal / UNC / device / ADS paths.
    let bad_candidates = vec![
        cookies_path.to_string_lossy().into_owned(),
        format!(r"{}\..\sensitive-user-data\Cookies", allowed_dir.display()),
        format!(r"{}\.\valid.json", allowed_dir.display()),
        format!(r"{}\valid.json:secret", allowed_dir.display()),
        format!(r"{}\valid.json ", allowed_dir.display()),
        format!(r"{}\valid.json.", allowed_dir.display()),
        r"\\attacker.invalid\share\com.localedr.bridge.json".to_string(),
        r"\\.\pipe\localedr".to_string(),
        "relative-manifest.json".to_string(),
    ];
    for candidate in &bad_candidates {
        let err = validate_manifest_file_in_allowed_dirs(
            Path::new(candidate),
            EXPECTED_CHROME_EXTENSION_ID,
            &allowed,
        )
        .unwrap_err();
        assert!(
            err.contains("outside allowed LocalEDR manifest directories"),
            "candidate '{candidate}' must fail allowlist check before I/O, got: {err}"
        );
    }
    assert!(
        validate_manifest_file(&cookies_path, EXPECTED_CHROME_EXTENSION_ID)
            .unwrap_err()
            .contains("outside allowed LocalEDR manifest directories")
    );

    // 4. Hard link inside allowed_dir pointing to locked Cookies is rejected by `nNumberOfLinks != 1`
    //    via attribute-only pre-check (never triggers data-read sharing violation).
    let hl_err_locked = validate_manifest_file_in_allowed_dirs(
        &hardlink_manifest,
        EXPECTED_CHROME_EXTENSION_ID,
        &allowed,
    )
    .unwrap_err();
    assert!(
        hl_err_locked.contains("hard links"),
        "expected hard-link rejection before data open, got: {hl_err_locked}"
    );

    #[cfg(windows)]
    drop(cookies_lock);

    // Even when Cookies is unlocked and holds valid JSON, hard link must still be rejected.
    let hl_err_unlocked = validate_manifest_file_in_allowed_dirs(
        &hardlink_manifest,
        EXPECTED_CHROME_EXTENSION_ID,
        &allowed,
    )
    .unwrap_err();
    assert!(
        hl_err_unlocked.contains("hard links"),
        "expected hard-link rejection for unlocked target too, got: {hl_err_unlocked}"
    );

    // 5. Windows NTFS junction (reparse point) on allowed_dir itself AND on an ancestor directory
    //    must be rejected before opening any file under the junction target.
    #[cfg(windows)]
    {
        struct JunctionGuard(PathBuf);
        impl Drop for JunctionGuard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir(&self.0);
            }
        }

        // 5a. Allowed dir itself is a junction -> outside_dir (contains locked id_rsa).
        let junction_allowed = tmp.0.join("junction-allowed");
        let mk1 = std::process::Command::new("cmd.exe")
            .args([
                "/c",
                "mklink",
                "/J",
                &junction_allowed.to_string_lossy(),
                &outside_dir.to_string_lossy(),
            ])
            .output()
            .expect("invoke mklink /J for allowed dir");
        assert!(
            mk1.status.success(),
            "mklink /J failed: {}",
            String::from_utf8_lossy(&mk1.stderr)
        );
        let _j1 = JunctionGuard(junction_allowed.clone());

        let err_j1 = validate_manifest_file_in_allowed_dirs(
            &junction_allowed.join("id_rsa"),
            EXPECTED_CHROME_EXTENSION_ID,
            std::slice::from_ref(&junction_allowed),
        )
        .unwrap_err();
        assert!(
            err_j1.contains("reparse point"),
            "expected reparse point rejection on junction allowed dir, got: {err_j1}"
        );

        // 5b. Ancestor component above allowed dir is a junction -> real parent containing a valid manifest.
        let real_parent = tmp.0.join("real-parent");
        let real_nested_allowed = real_parent.join("native-messaging");
        std::fs::create_dir_all(&real_nested_allowed).expect("create real_nested_allowed");
        let real_nested_manifest = real_nested_allowed.join("com.localedr.bridge.user.chrome.json");
        write_test_manifest(
            &real_nested_manifest,
            NATIVE_HOST_NAME,
            "stdio",
            &bridge_str,
            &[&expected_origin],
        );

        let ancestor_junction = tmp.0.join("ancestor-junction");
        let mk2 = std::process::Command::new("cmd.exe")
            .args([
                "/c",
                "mklink",
                "/J",
                &ancestor_junction.to_string_lossy(),
                &real_parent.to_string_lossy(),
            ])
            .output()
            .expect("invoke mklink /J for ancestor dir");
        assert!(
            mk2.status.success(),
            "mklink /J ancestor failed: {}",
            String::from_utf8_lossy(&mk2.stderr)
        );
        let _j2 = JunctionGuard(ancestor_junction.clone());

        let allowed_via_ancestor = ancestor_junction.join("native-messaging");
        let err_j2 = validate_manifest_file_in_allowed_dirs(
            &allowed_via_ancestor.join("com.localedr.bridge.user.chrome.json"),
            EXPECTED_CHROME_EXTENSION_ID,
            &[allowed_via_ancestor],
        )
        .unwrap_err();
        assert!(
            err_j2.contains("reparse point"),
            "expected reparse point rejection on ancestor junction, got: {err_j2}"
        );
    }

    // 6. Valid manifest inside allowed_dir whose `path` field targets a sensitive file or UNC share
    //    must be rejected syntactically without stat'ing the sensitive/remote target.
    let bad_target_manifest = allowed_dir.join("bad_bridge_target.json");
    write_test_manifest(
        &bad_target_manifest,
        NATIVE_HOST_NAME,
        "stdio",
        ssh_key_path.to_string_lossy().as_ref(),
        &[&expected_origin],
    );
    let err_bad_target = validate_manifest_file_in_allowed_dirs(
        &bad_target_manifest,
        EXPECTED_CHROME_EXTENSION_ID,
        &allowed,
    )
    .unwrap_err();
    assert!(
        err_bad_target.contains("local .exe"),
        "expected local .exe guard for manifest path targeting id_rsa, got: {err_bad_target}"
    );
    write_test_manifest(
        &bad_target_manifest,
        NATIVE_HOST_NAME,
        "stdio",
        r"\\attacker.invalid\share\ledr-bridge-nm.exe",
        &[&expected_origin],
    );
    let err_unc_target = validate_manifest_file_in_allowed_dirs(
        &bad_target_manifest,
        EXPECTED_CHROME_EXTENSION_ID,
        &allowed,
    )
    .unwrap_err();
    assert!(
        err_unc_target.contains("local .exe"),
        "expected local .exe guard for UNC bridge path, got: {err_unc_target}"
    );

    // 7. Positive sanity: single-link regular manifest inside allowed_dir succeeds.
    let clean_manifest = allowed_dir.join("com.localedr.bridge.user.chrome.json");
    write_test_manifest(&clean_manifest, NATIVE_HOST_NAME, "stdio", &bridge_str, &[&expected_origin]);
    assert_eq!(
        validate_manifest_file_in_allowed_dirs(
            &clean_manifest,
            EXPECTED_CHROME_EXTENSION_ID,
            &allowed,
        ),
        Ok(())
    );
    assert_eq!(
        classify_manifest_file_in_allowed_dirs(
            &clean_manifest,
            EXPECTED_CHROME_EXTENSION_ID,
            &allowed,
        ),
        ManifestValidationOutcome::Valid
    );

    // 8. Custom `--manifest-dir` path outside allowed_dirs with LocalEDR manifest filename:
    //    must still perform ZERO file I/O (even when exclusively locked), keep `manifest_valid == false`,
    //    and classify as `Unverified` (distinct from red `Invalid` for Cookies/id_rsa/corrupt).
    let custom_manifest = outside_dir.join("com.localedr.bridge.user.chrome.json");
    write_test_manifest(
        &custom_manifest,
        NATIVE_HOST_NAME,
        "stdio",
        &bridge_str,
        &[&expected_origin],
    );
    #[cfg(windows)]
    let _custom_lock = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&custom_manifest)
            .expect("exclusively lock custom manifest")
    };
    assert!(matches!(
        classify_manifest_file_in_allowed_dirs(
            &custom_manifest,
            EXPECTED_CHROME_EXTENSION_ID,
            &allowed,
        ),
        ManifestValidationOutcome::UnverifiedCustomPath(_)
    ));
    let custom_status = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        clean_manifest.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        custom_manifest.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Brave".to_string(),
                    hkcu: RegistryStringProbe::Absent,
                    hklm: RegistryStringProbe::Absent,
                },
            ],
            uri_hkcu: true,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(!custom_status.browser_shield.manifest_valid);
    assert_eq!(
        custom_status.browser_shield.manifest_status,
        MANIFEST_STATUS_UNVERIFIED
    );
    assert_eq!(
        custom_status.browser_shield.browsers[0].manifest_status,
        MANIFEST_STATUS_VALID
    );
    assert_eq!(
        custom_status.browser_shield.browsers[1].manifest_status,
        MANIFEST_STATUS_UNVERIFIED
    );
    assert_eq!(
        custom_status.browser_shield.browsers[2].manifest_status,
        MANIFEST_STATUS_NOT_REGISTERED
    );
    assert!(
        custom_status
            .browser_shield
            .manifest_error
            .as_deref()
            .is_some_and(|m| {
                m.contains("Edge:")
                    && m.contains("ledr-bridge-nm status")
                    && m.contains("WOW64 32-bit")
            }),
        "unexpected unverified note: {:?}",
        custom_status.browser_shield.manifest_error
    );

    // Mixed Unverified + Invalid (Cookies) must escalate overall status to Invalid (fail-closed).
    let mixed_invalid_status = collect_local_defense_status_with_probe_in_allowed_dirs(
        Some(&tmp.0),
        &bridge_exe,
        &BrowserShieldProbe {
            browsers: vec![
                BrowserRegistryProbe {
                    browser: "Chrome".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        custom_manifest.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
                BrowserRegistryProbe {
                    browser: "Edge".to_string(),
                    hkcu: RegistryStringProbe::Present(
                        cookies_path.to_string_lossy().into_owned(),
                    ),
                    hklm: RegistryStringProbe::Absent,
                },
            ],
            uri_hkcu: false,
            uri_hklm: false,
        },
        &allowed,
    );
    assert!(!mixed_invalid_status.browser_shield.manifest_valid);
    assert_eq!(
        mixed_invalid_status.browser_shield.manifest_status,
        MANIFEST_STATUS_INVALID
    );
    assert_eq!(
        mixed_invalid_status.browser_shield.browsers[0].manifest_status,
        MANIFEST_STATUS_UNVERIFIED
    );
    assert_eq!(
        mixed_invalid_status.browser_shield.browsers[1].manifest_status,
        MANIFEST_STATUS_INVALID
    );

    // 9. Missing leaf directory under an existing allowed parent must report missing file
    //    (not outside allowlist), exercising ancestor prefix long-path expansion.
    let nonexistent_allowed = tmp.0.join("not-yet-created").join("native-messaging");
    let missing_in_nonexistent = nonexistent_allowed.join("com.localedr.bridge.user.chrome.json");
    assert_eq!(
        classify_manifest_file_in_allowed_dirs(
            &missing_in_nonexistent,
            EXPECTED_CHROME_EXTENSION_ID,
            std::slice::from_ref(&nonexistent_allowed),
        ),
        ManifestValidationOutcome::Invalid("manifest file does not exist".to_string())
    );
}
