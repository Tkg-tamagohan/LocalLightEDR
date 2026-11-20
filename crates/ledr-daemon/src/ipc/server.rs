//! Named Pipe IPC server lifecycle, strict DACL recreation retry, and framed I/O.

use std::ffi::c_void;
use std::io::ErrorKind;
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

use crate::engine::DaemonEngine;

use super::auth::inspect_pipe_client_exe;
use super::dispatch::dispatch_request;
use super::security::build_service_pipe_security_descriptor;
#[cfg(doc)]
use super::security::SERVICE_PIPE_SDDL;

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
    strict_dacl: bool,
) -> std::io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.reject_remote_clients(true);
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
                            match create_pipe_server(&loop_pipe_name, false, strict_dacl) {
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
                                    // Under SERVICE_PIPE_SDDL, Interactive Users lack
                                    // FILE_CREATE_PIPE_INSTANCE (0x0004), so a non-elevated
                                    // daemon cannot open a second pipe instance. Finish and drop
                                    // `client_pipe` completely so mio/kernel state resets cleanly,
                                    // then recreate a brand-new NamedPipeServer instance.
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
                                    let Some(fresh_server) =
                                        recreate_strict_pipe_with_retry(&loop_pipe_name, &mut shutdown_rx)
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
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<NamedPipeServer> {
    const MAX_RECREATE_ATTEMPTS: usize = 50;
    const RECREATE_RETRY_DELAY: Duration = Duration::from_millis(4);

    for attempt in 0..MAX_RECREATE_ATTEMPTS {
        match create_pipe_server(pipe_name, true, true) {
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
            Ok(req) => dispatch_request(&engine, caller_exe.as_deref(), req),
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
