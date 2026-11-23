//! Named Pipe IPC server lifecycle, strict DACL recreation retry, and framed I/O.

use std::ffi::c_void;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ledr_proto::{
    decode_ipc_frame, encode_ipc_frame, IpcRequest, IpcResponse, IPC_MAX_FRAME_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use windows::Win32::Security::SECURITY_ATTRIBUTES;

use crate::engine::{BrowserReportError, DaemonEngine};

use super::auth::inspect_pipe_client_exe;
use super::dispatch::{
    authorize_caller_policy, browser_report_error_response, dispatch_request, CallerAuthPolicy,
};
use super::security::{build_strict_pipe_security_descriptor, PipeSecurityDescriptor};
#[cfg(doc)]
use super::security::{DEV_BYPASS_SYSTEM_PIPE_SDDL, SERVICE_PIPE_SDDL};

const IPC_READ_CHUNK_BYTES: usize = 8_192;

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
    pipe_sd: Option<&PipeSecurityDescriptor>,
) -> std::io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true);
    if first_instance {
        opts.first_pipe_instance(true);
    }
    if let Some(sd) = pipe_sd {
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
/// In same-privilege test harnesses (`strict_pipe_dacl: false`), uses the process default
/// security descriptor. The `ledr-daemon` CLI always sets `strict_pipe_dacl: true`:
/// - Production (`dev_mode_bypass_ui_auth == false`): applies [`SERVICE_PIPE_SDDL`]
///   (`SYSTEM`, `Administrators`, and `Interactive` users with `0x12019B`) together with
///   `L-09` binary verification.
/// - Dev bypass (`dev_mode_bypass_ui_auth == true`): omits `IU` and grants `0x12019B` only
///   to the launching user's SID (or fails closed to [`DEV_BYPASS_SYSTEM_PIPE_SDDL`] under
///   `S-1-5-18` `LocalSystem`).
pub fn start_ipc_server(engine: Arc<DaemonEngine>) -> std::io::Result<IpcServerHandle> {
    let pipe_name = engine.config().pipe_name.clone();
    let pipe_sd = if engine.config().strict_pipe_dacl {
        Some(build_strict_pipe_security_descriptor(
            engine.config().dev_mode_bypass_ui_auth,
        )?)
    } else {
        None
    };
    let strict_dacl = pipe_sd.is_some();
    let initial_server = create_pipe_server(&pipe_name, true, pipe_sd.as_ref())?;

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
                            match create_pipe_server(&loop_pipe_name, false, pipe_sd.as_ref()) {
                                Ok(next_server) => {
                                    let client_pipe = std::mem::replace(&mut server, next_server);
                                    match Arc::clone(&client_semaphore).try_acquire_owned() {
                                        Ok(permit) => {
                                            let client_engine = Arc::clone(&engine);
                                            tokio::spawn(async move {
                                                let _permit = permit;
                                                if let Err(err) =
                                                    handle_pipe_client(client_pipe, client_engine)
                                                        .await
                                                {
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
                                            drop(client_pipe);
                                        }
                                    }
                                }
                                Err(err)
                                    if strict_dacl && err.kind() == ErrorKind::PermissionDenied =>
                                {
                                    // Under strict pipe DACL (SERVICE_PIPE_SDDL or dev-bypass
                                    // current-user DACL), non-elevated callers lack
                                    // FILE_CREATE_PIPE_INSTANCE (0x0004), so a non-elevated
                                    // daemon cannot open a second pipe instance. Finish and drop
                                    // `client_pipe` completely so mio/kernel state resets cleanly,
                                    // then recreate a brand-new NamedPipeServer instance with the
                                    // same security descriptor.
                                    tracing::debug!(
                                        pipe = %loop_pipe_name,
                                        "strict pipe ACL denies secondary instance creation in non-elevated context; cycling single pipe instance"
                                    );
                                    let client_pipe = server;
                                    let mut stop_after_client = false;
                                    tokio::select! {
                                        biased;
                                        _ = shutdown_rx.changed() => {
                                            if *shutdown_rx.borrow() {
                                                stop_after_client = true;
                                            }
                                        }
                                        res = handle_pipe_client(client_pipe, Arc::clone(&engine)) => {
                                            if let Err(io_err) = res {
                                                tracing::debug!(error = %io_err, "IPC client session ended");
                                            }
                                        }
                                    }
                                    if stop_after_client {
                                        break;
                                    }
                                    let Some(fresh_server) = recreate_strict_pipe_with_retry(
                                        &loop_pipe_name,
                                        pipe_sd.as_ref(),
                                        &mut shutdown_rx,
                                    )
                                    .await
                                    else {
                                        break;
                                    };
                                    server = fresh_server;
                                }
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

async fn recreate_strict_pipe_with_retry(
    pipe_name: &str,
    pipe_sd: Option<&PipeSecurityDescriptor>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<NamedPipeServer> {
    const MAX_RECREATE_ATTEMPTS: usize = 50;
    const RECREATE_RETRY_DELAY: Duration = Duration::from_millis(4);

    for attempt in 0..MAX_RECREATE_ATTEMPTS {
        match create_pipe_server(pipe_name, true, pipe_sd) {
            Ok(next_server) => return Some(next_server),
            Err(err)
                if attempt + 1 < MAX_RECREATE_ATTEMPTS
                    && (err.kind() == ErrorKind::PermissionDenied
                        || matches!(err.raw_os_error(), Some(231))) =>
            {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            return None;
                        }
                    }
                    _ = tokio::time::sleep(RECREATE_RETRY_DELAY) => {}
                }
            }
            Err(err) => {
                tracing::error!(
                    pipe = %pipe_name,
                    error = %err,
                    "failed to recreate strict Named Pipe instance after client close"
                );
                return None;
            }
        }
    }

    tracing::error!(
        pipe = %pipe_name,
        "timed out waiting for previous strict Named Pipe handle teardown"
    );
    None
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
    // SEC_0001: cap the total session lifetime so one client cannot pin the single
    // strict-mode pipe instance forever with periodic lightweight requests.
    let session_timeout =
        Duration::from_millis(engine.config().ipc_session_timeout_ms.max(1_000));
    let session_deadline = tokio::time::Instant::now() + session_timeout;

    loop {
        let session_remaining =
            session_deadline.saturating_duration_since(tokio::time::Instant::now());
        if session_remaining.is_zero() {
            tracing::info!(
                timeout_ms = session_timeout.as_millis(),
                "IPC client session lifetime cap reached; closing session (SEC_0001)"
            );
            break;
        }
        let mut len_buf = [0u8; 4];
        match tokio::time::timeout(session_remaining.min(frame_timeout), pipe.read_exact(&mut len_buf))
            .await
        {
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

        let session_remaining =
            session_deadline.saturating_duration_since(tokio::time::Instant::now());
        if session_remaining.is_zero() {
            tracing::info!(
                timeout_ms = session_timeout.as_millis(),
                "IPC client session lifetime cap reached; closing session (SEC_0001)"
            );
            break;
        }

        let mut frame = Vec::with_capacity(4 + payload_len.min(IPC_READ_CHUNK_BYTES));
        frame.extend_from_slice(&len_buf);
        let payload_read = tokio::time::timeout(session_remaining.min(frame_timeout), async {
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
            Ok(IpcRequest::ReportDownloadOrigin {
                file_path,
                tab_url,
                frame_url,
                referrer_url,
                downloaded_at_ms,
            }) => {
                let session_remaining =
                    session_deadline.saturating_duration_since(tokio::time::Instant::now());
                if session_remaining.is_zero() {
                    tracing::info!(
                        timeout_ms = session_timeout.as_millis(),
                        "IPC client session lifetime cap reached before dispatch; closing session (SEC_0001)"
                    );
                    break;
                }
                let auth_engine = Arc::clone(&engine);
                let auth_caller = caller_exe.clone();
                let auth_task = tokio::task::spawn_blocking(move || {
                    authorize_caller_policy(
                        &auth_engine,
                        auth_caller.as_deref(),
                        CallerAuthPolicy::BridgeOnly,
                    )
                });
                let denied_opt = match tokio::time::timeout(session_remaining, auth_task).await {
                    Ok(Ok(opt)) => opt,
                    Ok(Err(join_err)) => {
                        tracing::error!(error = %join_err, "IPC authorization task panicked");
                        Some(IpcResponse::Error {
                            code: "INTERNAL_ERROR".to_string(),
                            message: format!("IPC authorization task failed: {join_err}"),
                        })
                    }
                    Err(_) => {
                        tracing::info!(
                            timeout_ms = session_timeout.as_millis(),
                            "IPC client session lifetime cap reached during auth; closing session (SEC_0001)"
                        );
                        break;
                    }
                };
                if let Some(denied) = denied_opt {
                    denied
                } else {
                    let session_remaining =
                        session_deadline.saturating_duration_since(tokio::time::Instant::now());
                    if session_remaining.is_zero() {
                        tracing::info!(
                            timeout_ms = session_timeout.as_millis(),
                            "IPC client session lifetime cap reached before download inspect; closing session (SEC_0001)"
                        );
                        break;
                    }
                    let cancel = Arc::new(AtomicBool::new(false));
                    match tokio::time::timeout(
                        session_remaining,
                        engine.record_browser_download_origin_async(
                            &file_path,
                            &tab_url,
                            frame_url.as_deref(),
                            referrer_url.as_deref(),
                            downloaded_at_ms,
                            Arc::clone(&cancel),
                        ),
                    )
                    .await
                    {
                        Ok(Ok(_)) => IpcResponse::Ack {
                            message: "recorded download origin".to_string(),
                        },
                        Ok(Err(BrowserReportError::Cancelled)) => {
                            tracing::info!(
                                "download origin report cancelled before completion; closing IPC session"
                            );
                            break;
                        }
                        Ok(Err(err)) => browser_report_error_response(err),
                        Err(_) => {
                            cancel.store(true, Ordering::Release);
                            tracing::info!(
                                timeout_ms = session_timeout.as_millis(),
                                "IPC client session lifetime cap reached during ReportDownloadOrigin; cancelling and closing session (SEC_0001)"
                            );
                            break;
                        }
                    }
                }
            }
            Ok(req) => {
                let session_remaining =
                    session_deadline.saturating_duration_since(tokio::time::Instant::now());
                if session_remaining.is_zero() {
                    tracing::info!(
                        timeout_ms = session_timeout.as_millis(),
                        "IPC client session lifetime cap reached before dispatch; closing session (SEC_0001)"
                    );
                    break;
                }
                let dispatch_engine = Arc::clone(&engine);
                let dispatch_caller = caller_exe.clone();
                let blocking = tokio::task::spawn_blocking(move || {
                    dispatch_request(&dispatch_engine, dispatch_caller.as_deref(), req)
                });
                match tokio::time::timeout(session_remaining, blocking).await {
                    Ok(Ok(resp)) => resp,
                    Ok(Err(join_err)) => {
                        tracing::error!(error = %join_err, "IPC dispatch blocking task panicked");
                        IpcResponse::Error {
                            code: "INTERNAL_ERROR".to_string(),
                            message: format!("IPC dispatch task failed: {join_err}"),
                        }
                    }
                    Err(_) => {
                        tracing::info!(
                            timeout_ms = session_timeout.as_millis(),
                            "IPC client session lifetime cap reached during dispatch; closing session (SEC_0001)"
                        );
                        break;
                    }
                }
            }
            Err(err) => IpcResponse::Error {
                code: "INVALID_REQUEST".to_string(),
                message: err.to_string(),
            },
        };

        let session_remaining =
            session_deadline.saturating_duration_since(tokio::time::Instant::now());
        if session_remaining.is_zero() {
            tracing::info!(
                timeout_ms = session_timeout.as_millis(),
                "IPC client session lifetime cap reached; closing session (SEC_0001)"
            );
            break;
        }
        write_response(&mut pipe, &response, session_remaining.min(frame_timeout)).await?;
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
