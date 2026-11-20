//! Layer 2 LocalEDR resident core daemon library.
//!
//! Exposes [`TwoLaneChannel`], [`ActiveProcessTable`], [`DaemonEngine`],
//! [`Session0ToastLauncher`], and the Windows Named Pipe IPC server (`ipc::start_ipc_server`).

pub mod channel;
pub mod engine;
pub mod firewall;
pub mod ipc;
pub mod notify;
pub mod process_table;

pub use channel::{
    ChannelClosedError, ClassifiedEventSender, HighPrioritySendError, OutboundLaneClassifier,
    TwoLaneChannel, TwoLaneReceiver, TwoLaneSender,
};
pub use engine::{
    BinaryInspector, DaemonConfig, DaemonEngine, LiveProcessInspector, OutboundEnforcementMode,
    PolicyRuleError, WindowsBinaryInspector, WindowsLiveProcessInspector,
};
pub use firewall::{
    InstalledWfpFilter, WfpFailedOp, WfpFilterOrigin, WfpReconcileReport, WfpRuleManager,
};
pub use ipc::{
    build_service_pipe_security_descriptor, inspect_pipe_client_exe, is_authorized_bridge_caller,
    is_authorized_ui_caller, start_ipc_server, verify_authorized_caller_binary,
    verify_caller_identity, IpcServerHandle, PipeSecurityDescriptor, SERVICE_PIPE_SDDL,
};
pub use notify::{
    current_process_session_id, NoopNotificationDispatcher, NotificationDispatcher,
    Session0ToastLauncher,
};
pub use process_table::{ActiveProcessEntry, ActiveProcessTable, ProcessStartResolution};
