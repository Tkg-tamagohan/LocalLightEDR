//! Named Pipe IPC server (`\\.\pipe\localedr-ipc`, `決定記録 L-09`, `AUTO-11`).

use std::ffi::c_void;
use std::io::ErrorKind;
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;

use ledr_proto::{
    decode_ipc_frame, encode_ipc_frame, AlertRecord, AlertSeverity, AlertStatus,
    DownloadOriginRecord, IpcRequest, IpcResponse, AUTHORIZED_BRIDGE_EXE_PATH,
    AUTHORIZED_UI_EXE_PATH, IPC_MAX_FRAME_BYTES,
};
use ledr_rules::{assess_domain_risk, signer_subject_matches, BinaryIdentity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::engine::DaemonEngine;

const IPC_READ_CHUNK_BYTES: usize = 8_192;
const SDDL_REVISION_1: u32 = 1;

/// Strict Named Pipe SDDL permitting full access to `SYSTEM` and `Administrators`,
/// and read/write access to `Interactive` users (`決定記録 L-09`).
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// Owned self-relative Windows security descriptor converted from SDDL (`L-09`).
pub struct PipeSecurityDescriptor {
    sd: PSECURITY_DESCRIPTOR,
    sd_len: u32,
}

// SAFETY: A converted Windows self-relative security descriptor is immutable raw buffer
// memory freed exactly once via `LocalFree` on `Drop` with no thread affinity.
unsafe impl Send for PipeSecurityDescriptor {}
// SAFETY: Shared references only expose read-only pointer metadata.
unsafe impl Sync for PipeSecurityDescriptor {}

impl PipeSecurityDescriptor {
    /// Parses an SDDL string into an owned Windows `SECURITY_DESCRIPTOR` via
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw_sd: *mut c_void = std::ptr::null_mut();
        let mut sd_len: u32 = 0;

        // SAFETY: `sddl_w` is NUL-terminated UTF-16; `raw_sd` is owned and freed by `LocalFree`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut raw_sd,
                &mut sd_len,
            )
        };
        if ok == 0 || raw_sd.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            sd: PSECURITY_DESCRIPTOR(raw_sd),
            sd_len,
        })
    }

    /// Returns a `SECURITY_ATTRIBUTES` struct referencing this security descriptor.
    /// The returned value must not outlive `self`.
    pub fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: false.into(),
        }
    }

    /// Returns the size in bytes of the converted self-relative security descriptor.
    pub fn byte_len(&self) -> u32 {
        self.sd_len
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: `self.sd.0` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
            self.sd.0 = std::ptr::null_mut();
        }
    }
}

/// Builds the Phase 2+ strict Named Pipe security descriptor (`SERVICE_PIPE_SDDL`, `L-09`).
pub fn build_service_pipe_security_descriptor() -> std::io::Result<PipeSecurityDescriptor> {
    PipeSecurityDescriptor::from_sddl(SERVICE_PIPE_SDDL)
}

#[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
}

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

fn create_pipe_server(
    pipe_name: &str,
    first_instance: bool,
    strict_dacl: bool,
) -> std::io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    if first_instance {
        opts.first_pipe_instance(true);
    }
    if strict_dacl {
        let sd = build_service_pipe_security_descriptor()?;
        let mut sa = sd.security_attributes();
        // SAFETY: `sa` points to `sd` which lives until after `create_with_security_attributes_raw` returns.
        unsafe {
            opts.create_with_security_attributes_raw(
                pipe_name,
                &mut sa as *mut SECURITY_ATTRIBUTES as *mut c_void,
            )
        }
    } else {
        opts.create(pipe_name)
    }
}

/// Binds the initial Named Pipe instance synchronously (preventing client connection races)
/// and spawns an asynchronous accept loop serving 4-byte LE JSON frames.
///
/// In `--foreground` dev mode (`strict_pipe_dacl: false`), uses the process default security
/// descriptor. In `--service-strict` mode (`strict_pipe_dacl: true`), applies
/// [`SERVICE_PIPE_SDDL`] restricting access to `SYSTEM`, `Administrators`, and `Interactive`
/// users (`決定記録 L-09`).
pub fn start_ipc_server(engine: Arc<DaemonEngine>) -> std::io::Result<IpcServerHandle> {
    let pipe_name = engine.config().pipe_name.clone();
    let strict_dacl = engine.config().strict_pipe_dacl;
    let initial_server = create_pipe_server(&pipe_name, true, strict_dacl)?;

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let loop_pipe_name = pipe_name.clone();
    let max_clients = engine.config().max_concurrent_ipc_clients.max(1);
    let client_semaphore = Arc::new(Semaphore::new(max_clients));

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
                            match Arc::clone(&client_semaphore).try_acquire_owned() {
                                Ok(permit) => {
                                    let client_pipe = server;
                                    let client_engine = Arc::clone(&engine);
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Err(err) = handle_pipe_client(client_pipe, client_engine).await {
                                            tracing::debug!(error = %err, "IPC client session ended");
                                        }
                                    });
                                }
                                Err(_) => {
                                    tracing::warn!(
                                        pipe = %loop_pipe_name,
                                        max_concurrent_ipc_clients = max_clients,
                                        "rejecting IPC client connection: concurrent client limit reached"
                                    );
                                    drop(server);
                                }
                            }

                            match create_pipe_server(&loop_pipe_name, false, strict_dacl) {
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
    verify_authorized_caller_binary(
        caller_exe_path,
        AUTHORIZED_UI_EXE_PATH,
        None,
        None,
        None,
        dev_mode_bypass,
    )
}

/// Checks whether a caller executable path is authorized to submit browser bridge events (`L-09`).
pub fn is_authorized_bridge_caller(caller_exe_path: Option<&str>, dev_mode_bypass: bool) -> bool {
    verify_authorized_caller_binary(
        caller_exe_path,
        AUTHORIZED_BRIDGE_EXE_PATH,
        None,
        None,
        None,
        dev_mode_bypass,
    )
}

/// Verifies an IPC caller executable against an expected protected path AND optional
/// expected SHA-256 digest and Authenticode signer (`L-09`), preserving `dev_mode_bypass`.
pub fn verify_authorized_caller_binary(
    caller_exe_path: Option<&str>,
    expected_exe_path: &str,
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
    dev_mode_bypass: bool,
) -> bool {
    if dev_mode_bypass {
        return true;
    }
    let Some(caller_path) = caller_exe_path.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if !normalized_path_eq_ascii_ci(caller_path, expected_exe_path) {
        return false;
    }

    let has_sha_pin = expected_sha256
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let has_signer_pin = expected_signer
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());

    if !has_sha_pin && !has_signer_pin {
        return true;
    }

    let identity = BinaryIdentity::from_path(caller_path);
    verify_caller_identity(
        Some(&identity),
        expected_exe_path,
        expected_sha256,
        expected_signer,
        expected_root_thumbprint,
        false,
    )
}

/// Pure identity verification helper matching path, optional SHA-256, and optional
/// Authenticode signer + root thumbprint (`L-09`).
pub fn verify_caller_identity(
    caller_identity: Option<&BinaryIdentity>,
    expected_exe_path: &str,
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
    dev_mode_bypass: bool,
) -> bool {
    if dev_mode_bypass {
        return true;
    }
    let Some(identity) = caller_identity else {
        return false;
    };
    if !normalized_path_eq_ascii_ci(identity.exe_path.trim(), expected_exe_path) {
        return false;
    }

    if let Some(expected_sha) = expected_sha256
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let matches = identity
            .sha256
            .as_deref()
            .map(str::trim)
            .is_some_and(|actual| actual.eq_ignore_ascii_case(expected_sha));
        if !matches {
            return false;
        }
    }

    if let Some(expected_subj) = expected_signer
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let Some(auth) = identity.authenticode.as_ref() else {
            return false;
        };
        if !signer_subject_matches(&auth.signer_subject, expected_subj) {
            return false;
        }
        if let Some(expected_tp) = expected_root_thumbprint
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let all_zeros = expected_tp.chars().all(|c| c == '0');
            if !all_zeros
                && (auth.root_thumbprint.trim().is_empty()
                    || !auth.root_thumbprint.trim().eq_ignore_ascii_case(expected_tp))
            {
                return false;
            }
        }
    }

    true
}

fn normalized_path_eq_ascii_ci(a: &str, b: &str) -> bool {
    let na = a.trim().replace('/', "\\");
    let nb = b.trim().replace('/', "\\");
    !na.is_empty() && na.eq_ignore_ascii_case(&nb)
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

    let frame_timeout = Duration::from_millis(engine.config().ipc_frame_timeout_ms.max(50));

    loop {
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(frame_timeout, pipe.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if is_disconnect_error(&err) => break,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                tracing::debug!(
                    timeout_ms = frame_timeout.as_millis(),
                    "IPC client timed out reading frame header; closing session"
                );
                break;
            }
        }

        let payload_len = u32::from_le_bytes(len_buf) as usize;
        if payload_len == 0 {
            let err_resp = IpcResponse::Error {
                code: "EMPTY_FRAME".to_string(),
                message: "empty IPC frame".to_string(),
            };
            write_response(&mut pipe, &err_resp, frame_timeout).await?;
            break;
        }
        if payload_len > IPC_MAX_FRAME_BYTES {
            let err_resp = IpcResponse::Error {
                code: "FRAME_TOO_LARGE".to_string(),
                message: format!("IPC frame {payload_len} exceeds {IPC_MAX_FRAME_BYTES} bytes"),
            };
            write_response(&mut pipe, &err_resp, frame_timeout).await?;
            break;
        }

        let mut frame = Vec::with_capacity(4 + payload_len.min(IPC_READ_CHUNK_BYTES));
        frame.extend_from_slice(&len_buf);
        let payload_read = tokio::time::timeout(frame_timeout, async {
            let mut remaining = payload_len;
            let mut chunk = [0u8; IPC_READ_CHUNK_BYTES];
            while remaining > 0 {
                let to_read = remaining.min(chunk.len());
                pipe.read_exact(&mut chunk[..to_read]).await?;
                frame.extend_from_slice(&chunk[..to_read]);
                remaining -= to_read;
            }
            Ok::<(), std::io::Error>(())
        })
        .await;

        match payload_read {
            Ok(Ok(())) => {}
            Ok(Err(err)) if is_disconnect_error(&err) => break,
            Ok(Err(err)) => return Err(err),
            Err(_) => {
                tracing::debug!(
                    timeout_ms = frame_timeout.as_millis(),
                    payload_len,
                    "IPC client timed out reading frame payload; closing session"
                );
                break;
            }
        }

        let response = match decode_ipc_frame::<IpcRequest>(&frame) {
            Ok(req) => dispatch_request(&engine, caller_exe.as_deref(), req),
            Err(err) => IpcResponse::Error {
                code: "INVALID_REQUEST".to_string(),
                message: err.to_string(),
            },
        };

        write_response(&mut pipe, &response, frame_timeout).await?;
    }

    Ok(())
}

fn is_disconnect_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::UnexpectedEof | ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
    )
}

async fn write_response(
    pipe: &mut NamedPipeServer,
    resp: &IpcResponse,
    frame_timeout: Duration,
) -> std::io::Result<()> {
    let encoded = encode_ipc_frame(resp).unwrap_or_else(|err| {
        let fallback = IpcResponse::Error {
            code: "ENCODE_ERROR".to_string(),
            message: err.to_string(),
        };
        encode_ipc_frame(&fallback).unwrap_or_default()
    });
    match tokio::time::timeout(frame_timeout, async {
        pipe.write_all(&encoded).await?;
        pipe.flush().await
    })
    .await
    {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "IPC response write timed out",
        )),
    }
}

fn dispatch_request(
    engine: &DaemonEngine,
    caller_exe: Option<&str>,
    req: IpcRequest,
) -> IpcResponse {
    let cfg = engine.config();
    if req.requires_ui_authorization()
        && !verify_authorized_caller_binary(
            caller_exe,
            AUTHORIZED_UI_EXE_PATH,
            cfg.authorized_ui_sha256.as_deref(),
            cfg.authorized_ui_signer.as_deref(),
            cfg.authorized_ui_root_thumbprint.as_deref(),
            cfg.dev_mode_bypass_ui_auth,
        )
    {
        return IpcResponse::Error {
            code: "UNAUTHORIZED".to_string(),
            message: format!(
                "caller {:?} is not authorized for mutating IPC command (expected {})",
                caller_exe, AUTHORIZED_UI_EXE_PATH
            ),
        };
    }

    if matches!(
        req,
        IpcRequest::ReportDownloadOrigin { .. } | IpcRequest::ReportBrowserEvent { .. }
    ) && !verify_authorized_caller_binary(
        caller_exe,
        AUTHORIZED_BRIDGE_EXE_PATH,
        cfg.authorized_bridge_sha256.as_deref(),
        cfg.authorized_bridge_signer.as_deref(),
        cfg.authorized_bridge_root_thumbprint.as_deref(),
        cfg.dev_mode_bypass_ui_auth,
    ) {
        return IpcResponse::Error {
            code: "UNAUTHORIZED_CALLER".to_string(),
            message: format!(
                "caller {:?} is not authorized for browser bridge IPC command (expected {})",
                caller_exe, AUTHORIZED_BRIDGE_EXE_PATH
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
            match engine.resolve_alert(&alert_id, decision) {
                Ok(resolved) => IpcResponse::Ack {
                    message: format!(
                        "alert {} resolved to {}",
                        resolved.alert_id,
                        resolved.status.as_db_str()
                    ),
                },
                Err(msg) => {
                    let code = if msg.contains("not found") {
                        "NOT_FOUND"
                    } else if msg.contains("already resolved") {
                        "ALREADY_RESOLVED"
                    } else {
                        "RESOLVE_ERROR"
                    };
                    IpcResponse::Error {
                        code: code.to_string(),
                        message: msg,
                    }
                }
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
