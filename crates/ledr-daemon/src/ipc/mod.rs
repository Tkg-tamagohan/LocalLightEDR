//! Named Pipe IPC server (`\\.\pipe\localedr-ipc`, `決定記録 L-09`, `AUTO-11`).

mod auth;
mod dispatch;
mod security;
mod server;

pub use auth::{
    inspect_pipe_client_exe, is_authorized_bridge_caller, is_authorized_ui_caller,
    verify_authorized_caller_binary, verify_caller_identity,
};
pub use security::{
    build_service_pipe_security_descriptor, PipeSecurityDescriptor, SERVICE_PIPE_SDDL,
};
pub use server::{start_ipc_server, IpcServerHandle};
