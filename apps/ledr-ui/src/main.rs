#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;
mod tree;

use ipc::IpcClient;
use ledr_proto::{FlightRecorderSnapshot, PipelineMetrics};
use serde::{Deserialize, Serialize};
use tauri::Manager;

/// Launch mode for the on-demand LocalEDR UI binary (`決定記録 L-08`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "alert_id", rename_all = "snake_case")]
pub enum LaunchMode {
    Normal,
    Notify(String),
    AlertFocus(String),
}

#[derive(Debug, Serialize)]
struct NotifyStubEvent<'a> {
    mode: &'static str,
    alert_id: &'a str,
    launch_uri: String,
    ipc_pipe: &'a str,
    status: &'static str,
}

fn parse_flag_value<I, S>(flag: &str, arg: &str, iter: &mut I) -> Result<Option<String>, String>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    if arg == flag {
        let value = iter
            .next()
            .map(|v| v.as_ref().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("missing value for {flag}"))?;
        return Ok(Some(value));
    }
    let prefix = format!("{flag}=");
    if let Some(value) = arg.strip_prefix(&prefix) {
        if value.is_empty() {
            return Err(format!("missing value for {prefix}"));
        }
        return Ok(Some(value.to_string()));
    }
    Ok(None)
}

/// Parses CLI arguments into a [`LaunchMode`].
///
/// Supports `--notify <alert_id>` (one-shot WinRT toast mode) and
/// `--alert-id <id>` (direct alert triage focus mode).
fn parse_launch_mode<I, S>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        let s = arg.as_ref();
        if let Some(alert_id) = parse_flag_value("--notify", s, &mut iter)? {
            return Ok(LaunchMode::Notify(alert_id));
        }
        if let Some(alert_id) = parse_flag_value("--alert-id", s, &mut iter)? {
            return Ok(LaunchMode::AlertFocus(alert_id));
        }
    }
    Ok(LaunchMode::Normal)
}

#[tauri::command]
async fn fetch_flight_recorder(
    client: tauri::State<'_, IpcClient>,
    limit: usize,
    process_instance_id: Option<String>,
) -> Result<FlightRecorderSnapshot, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        client.get_flight_recorder(limit, process_instance_id)
    })
    .await
    .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn fetch_pipeline_metrics(
    client: tauri::State<'_, IpcClient>,
) -> Result<PipelineMetrics, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.get_pipeline_metrics())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn ping_daemon(client: tauri::State<'_, IpcClient>) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.ping())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
fn get_launch_mode(mode: tauri::State<'_, LaunchMode>) -> LaunchMode {
    mode.inner().clone()
}

#[tauri::command]
fn build_process_tree_view(snapshot: FlightRecorderSnapshot) -> Vec<tree::ProcessTreeNode> {
    tree::build_process_tree(&snapshot)
}

fn dispatch_notify_oneshot(alert_id: &str, ipc_pipe: &str) -> Result<(), String> {
    let event = NotifyStubEvent {
        mode: "notify_oneshot",
        alert_id,
        launch_uri: format!("ledr://alert/{alert_id}"),
        ipc_pipe,
        status: "dispatched_stub",
    };
    let json = serde_json::to_string(&event)
        .map_err(|err| format!("failed to serialize notify stub event: {err}"))?;
    println!("{json}");
    Ok(())
}

fn run_gui(launch_mode: LaunchMode, ipc_client: IpcClient) -> Result<(), String> {
    let app = tauri::Builder::default()
        .manage(launch_mode)
        .manage(ipc_client)
        .invoke_handler(tauri::generate_handler![
            fetch_flight_recorder,
            fetch_pipeline_metrics,
            ping_daemon,
            get_launch_mode,
            build_process_tree_view,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                window.app_handle().exit(0);
            }
        })
        .build(tauri::generate_context!())
        .map_err(|err| format!("failed to build Tauri application: {err}"))?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            // Do not call `api.prevent_exit()`: closing the window must terminate
            // the UI process and WebView2 completely with 0 MB resident (`決定記録 L-08`).
        }
    });

    Ok(())
}

fn main() {
    let mode = match parse_launch_mode(std::env::args()) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("ledr-ui argument error: {err}");
            std::process::exit(2);
        }
    };
    let ipc_client = IpcClient::default_endpoint();

    if let LaunchMode::Notify(ref alert_id) = mode {
        if let Err(err) = dispatch_notify_oneshot(alert_id, ipc_client.pipe_name()) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(err) = run_gui(mode, ipc_client) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::{
        parse_flight_recorder_response, parse_metrics_response, parse_ping_response,
    };
    use ledr_proto::{
        CanaryCategory, DnsQueryRecord, FileCanaryEventRecord, IpcRequest, IpcResponse,
        NetworkEventRecord, ProcessRecord, decode_ipc_frame, encode_ipc_frame,
    };
    use std::io::{self, Read, Write};
    use tree::build_process_tree;

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
}
