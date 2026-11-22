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
    build_dev_bypass_pipe_security_descriptor, build_dev_bypass_pipe_security_descriptor_for_sid,
    build_service_pipe_security_descriptor, current_process_user_sid, format_dev_bypass_pipe_sddl,
    read_kernel_object_dacl_sddl, PipeSecurityDescriptor, DEV_BYPASS_SYSTEM_PIPE_SDDL,
    SERVICE_PIPE_SDDL,
};
pub use server::{start_ipc_server, IpcServerHandle};
