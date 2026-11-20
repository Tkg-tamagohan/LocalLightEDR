use super::*;
use cli::parse_launch_mode;
use defense_status::{HONEYPOT_FILENAME, collect_local_defense_status_with};
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
use tree::build_process_tree;
#[cfg(windows)]
use uri_reg::{LEDR_AUMID_DISPLAY_NAME, LEDR_URI_DESCRIPTION, win_uri_reg};
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
    };
    let expired_xml = build_winrt_toast_xml(&expired_summary);
    assert!(expired_xml.contains("[EXPIRED_SUSPENDED · FROZEN]"));
    assert!(expired_xml.contains("launch=\"ledr://alert/alert-exp-1\""));

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
