//! Named Pipe IPC server (`\\.\pipe\localedr-ipc`, `決定記録 L-09`, `AUTO-11`).

use std::io::ErrorKind;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use ledr_proto::{
    decode_ipc_frame, encode_ipc_frame, AlertRecord, AlertSeverity, AlertStatus,
    DownloadOriginRecord, IpcRequest, IpcResponse, AUTHORIZED_UI_EXE_PATH, IPC_MAX_FRAME_BYTES,
};
use ledr_rules::assess_domain_risk;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::engine::{current_unix_ms, DaemonEngine};

/// Handle owning the Named Pipe IPC accept loop task.
pub struct IpcServerHandle {
    pipe_name: String,
    shutdown_tx: watch::Sender<bool>,
    join_handle: Option<JoinHandle<()>>,
}

impl IpcServerHandle {
    /// Returns the Named Pipe endpoint path served by this instance.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Signals the IPC server accept loop to stop and waits for it to finish.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

/// Binds the initial Named Pipe instance synchronously (preventing client connection races)
/// and spawns an asynchronous accept loop serving 4-byte LE JSON frames.
///
/// Note on Phase 1 security posture (`決定記録 L-09`):
/// In Phase 1 `--foreground` dev mode, the pipe uses the process default security descriptor
/// (accessible to the interactive user, administrators, and SYSTEM). Phase 2+ service mode
/// restricts the creation DACL to `SYSTEM`, `Administrators`, and `Interactive` and enforces
/// `AUTHORIZED_UI_EXE_PATH` / Authenticode / SHA-256 caller verification on mutating requests.
pub fn start_ipc_server(engine: Arc<DaemonEngine>) -> std::io::Result<IpcServerHandle> {
    let pipe_name = engine.config().pipe_name.clone();
    let initial_server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&pipe_name)?;

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let loop_pipe_name = pipe_name.clone();

    let join_handle = tokio::spawn(async move {
        let mut server = initial_server;
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                connect_res = server.connect() => {
                    match connect_res {
                        Ok(()) => {
                            let client_pipe = server;
                            let client_engine = Arc::clone(&engine);
                            tokio::spawn(async move {
                                if let Err(err) = handle_pipe_client(client_pipe, client_engine).await {
                                    tracing::debug!(error = %err, "IPC client session ended");
                                }
                            });

                            match ServerOptions::new().create(&loop_pipe_name) {
                                Ok(next_server) => server = next_server,
                                Err(err) => {
                                    tracing::error!(
                                        pipe = %loop_pipe_name,
                                        error = %err,
                                        "failed to create next Named Pipe instance"
                                    );
                                    break;
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(pipe = %loop_pipe_name, error = %err, "Named Pipe connect error");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(IpcServerHandle {
        pipe_name,
        shutdown_tx,
        join_handle: Some(join_handle),
    })
}

/// Checks whether a caller executable path is authorized to execute mutating UI commands (`L-09`).
pub fn is_authorized_ui_caller(caller_exe_path: Option<&str>, dev_mode_bypass: bool) -> bool {
    if dev_mode_bypass {
        return true;
    }
    caller_exe_path.is_some_and(|path| path.eq_ignore_ascii_case(AUTHORIZED_UI_EXE_PATH))
}

/// Resolves the connected client process PID and executable image path via `GetNamedPipeClientProcessId`.
pub fn inspect_pipe_client_exe(pipe: &NamedPipeServer) -> Result<(u32, String), String> {
    let raw = HANDLE(pipe.as_raw_handle());
    let mut client_pid: u32 = 0;

    // Safety: `raw` is a live Named Pipe server handle owned by `pipe` for this call duration.
    unsafe {
        GetNamedPipeClientProcessId(raw, &mut client_pid)
            .map_err(|err| format!("GetNamedPipeClientProcessId failed: {err}"))?;
    }
    if client_pid == 0 {
        return Err("GetNamedPipeClientProcessId returned PID 0".to_string());
    }

    let proc_handle = OwnedWinHandle(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|err| format!("OpenProcess({client_pid}) failed: {err}"))?
    });

    let mut buf = vec![0u16; 1024];
    let mut len = u32::try_from(buf.len()).unwrap_or(1024);

    // Safety: `buf` is valid writable UTF-16 memory of length `len`.
    unsafe {
        QueryFullProcessImageNameW(
            proc_handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .map_err(|err| format!("QueryFullProcessImageNameW({client_pid}) failed: {err}"))?;
    }

    let exe_len = usize::try_from(len).unwrap_or(0).min(buf.len());
    let exe_path = String::from_utf16_lossy(&buf[..exe_len]);
    Ok((client_pid, exe_path))
}

struct OwnedWinHandle(HANDLE);

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // Safety: handle was opened by `OpenProcess` and is closed exactly once on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

async fn handle_pipe_client(
    mut pipe: NamedPipeServer,
    engine: Arc<DaemonEngine>,
) -> std::io::Result<()> {
    let caller_info = inspect_pipe_client_exe(&pipe);
    let caller_exe = match &caller_info {
        Ok((pid, exe)) => {
            tracing::debug!(client_pid = pid, client_exe = %exe, "IPC client connected");
            Some(exe.clone())
        }
        Err(err) => {
            tracing::debug!(reason = %err, "could not inspect IPC client process path");
            None
        }
    };

    loop {
        let mut len_buf = [0u8; 4];
        match pipe.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
                ) =>
            {
                break;
            }
            Err(err) => return Err(err),
        }

        let payload_len = u32::from_le_bytes(len_buf) as usize;
        if payload_len == 0 {
            let err_resp = IpcResponse::Error {
                code: "EMPTY_FRAME".to_string(),
                message: "empty IPC frame".to_string(),
            };
            write_response(&mut pipe, &err_resp).await?;
            break;
        }
        if payload_len > IPC_MAX_FRAME_BYTES {
            let err_resp = IpcResponse::Error {
                code: "FRAME_TOO_LARGE".to_string(),
                message: format!("IPC frame {payload_len} exceeds {IPC_MAX_FRAME_BYTES} bytes"),
            };
            write_response(&mut pipe, &err_resp).await?;
            break;
        }

        let mut frame = vec![0u8; 4 + payload_len];
        frame[..4].copy_from_slice(&len_buf);
        pipe.read_exact(&mut frame[4..]).await?;

        let response = match decode_ipc_frame::<IpcRequest>(&frame) {
            Ok(req) => dispatch_request(&engine, caller_exe.as_deref(), req),
            Err(err) => IpcResponse::Error {
                code: "INVALID_REQUEST".to_string(),
                message: err.to_string(),
            },
        };

        write_response(&mut pipe, &response).await?;
    }

    Ok(())
}

async fn write_response(pipe: &mut NamedPipeServer, resp: &IpcResponse) -> std::io::Result<()> {
    let encoded = encode_ipc_frame(resp).unwrap_or_else(|err| {
        let fallback = IpcResponse::Error {
            code: "ENCODE_ERROR".to_string(),
            message: err.to_string(),
        };
        encode_ipc_frame(&fallback).unwrap_or_default()
    });
    pipe.write_all(&encoded).await?;
    pipe.flush().await?;
    Ok(())
}

fn dispatch_request(
    engine: &DaemonEngine,
    caller_exe: Option<&str>,
    req: IpcRequest,
) -> IpcResponse {
    if req.requires_ui_authorization()
        && !is_authorized_ui_caller(caller_exe, engine.config().dev_mode_bypass_ui_auth)
    {
        return IpcResponse::Error {
            code: "UNAUTHORIZED".to_string(),
            message: format!(
                "caller {:?} is not authorized for mutating IPC command (expected {})",
                caller_exe, AUTHORIZED_UI_EXE_PATH
            ),
        };
    }

    let store = engine.store();
    match req {
        IpcRequest::Ping => IpcResponse::Pong {
            daemon_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: ledr_proto::IPC_PROTOCOL_VERSION,
        },
        IpcRequest::GetFlightRecorder {
            limit,
            process_instance_id,
        } => match store.query_flight_recorder(limit, process_instance_id.as_deref()) {
            Ok(snapshot) => IpcResponse::FlightRecorder(snapshot),
            Err(err) => store_error_response(err),
        },
        IpcRequest::GetAlerts { status, limit } => match store.list_alerts(status, limit) {
            Ok(alerts) => IpcResponse::Alerts(alerts),
            Err(err) => store_error_response(err),
        },
        IpcRequest::ListRules { scope } => match store.list_rules(scope) {
            Ok(rules) => IpcResponse::Rules(rules),
            Err(err) => store_error_response(err),
        },
        IpcRequest::GetPipelineMetrics => IpcResponse::Metrics(engine.metrics()),
        IpcRequest::CheckDomainRisk { domain } => {
            let assessment = assess_domain_risk(&domain, None);
            IpcResponse::DomainRisk {
                domain: assessment.domain,
                is_nrd: assessment.is_nrd,
                is_homograph: assessment.is_homograph,
                matched_brand: assessment.matched_brand,
            }
        }
        IpcRequest::ResolveAlert { alert_id, decision } => {
            let new_status = decision.resulting_status();
            match store.update_alert_status(&alert_id, new_status, Some(current_unix_ms())) {
                Ok(true) => IpcResponse::Ack {
                    message: format!("alert {alert_id} resolved to {}", new_status.as_db_str()),
                },
                Ok(false) => IpcResponse::Error {
                    code: "NOT_FOUND".to_string(),
                    message: format!("alert {alert_id} not found"),
                },
                Err(err) => store_error_response(err),
            }
        }
        IpcRequest::UpsertRule { rule } => match store.upsert_rule(&rule) {
            Ok(()) => IpcResponse::Ack {
                message: format!("upserted rule {}", rule.rule_id),
            },
            Err(err) => store_error_response(err),
        },
        IpcRequest::DeleteRule { rule_id } => match store.delete_rule(&rule_id) {
            Ok(true) => IpcResponse::Ack {
                message: format!("deleted rule {rule_id}"),
            },
            Ok(false) => IpcResponse::Error {
                code: "NOT_FOUND".to_string(),
                message: format!("rule {rule_id} not found"),
            },
            Err(err) => store_error_response(err),
        },
        IpcRequest::ReportDownloadOrigin {
            file_path,
            tab_url,
            frame_url,
            referrer_url,
            downloaded_at_ms,
        } => {
            let record = DownloadOriginRecord {
                id: None,
                file_path,
                sha256: None,
                tab_url,
                frame_url,
                referrer_url,
                downloaded_at_ms,
            };
            match store.record_download_origin(&record) {
                Ok(()) => IpcResponse::Ack {
                    message: "recorded download origin".to_string(),
                },
                Err(err) => store_error_response(err),
            }
        }
        IpcRequest::ReportBrowserEvent {
            event_type,
            url,
            details,
            timestamp_ms,
        } => {
            let context_json = serde_json::json!({
                "event_type": event_type,
                "url": url,
                "details": details,
            })
            .to_string();
            let alert = AlertRecord {
                alert_id: Uuid::new_v4().to_string(),
                timestamp_ms,
                severity: AlertSeverity::Medium,
                source_layer: "LAYER_4_BROWSER".to_string(),
                rule_id: format!("BROWSER-{event_type:?}"),
                title: format!("Browser Shield Event: {event_type:?}"),
                process_instance_id: None,
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json,
                resolved_at_ms: None,
            };
            match store.record_alert(&alert) {
                Ok(()) => IpcResponse::Ack {
                    message: format!("recorded browser event {}", alert.alert_id),
                },
                Err(err) => store_error_response(err),
            }
        }
    }
}

fn store_error_response(err: ledr_store::StoreError) -> IpcResponse {
    IpcResponse::Error {
        code: "STORE_ERROR".to_string(),
        message: err.to_string(),
    }
}
