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
pub mod service_win;

pub use channel::{
    ChannelClosedError, ClassifiedEventSender, HighPrioritySendError, OutboundLaneClassifier,
    TwoLaneChannel, TwoLaneReceiver, TwoLaneSender,
};
pub use engine::{
    BinaryInspector, BrowserEventOutcome, BrowserReportError, DaemonConfig, DaemonEngine,
    InspectOutcome, LiveProcessInspector, MotwAttribution, MotwInspector, MotwMatchStage,
    OutboundEnforcementMode, PolicyRuleError, WindowsBinaryInspector, WindowsLiveProcessInspector,
    WindowsMotwInspector, DEFAULT_MAX_CONCURRENT_IPC_CLIENTS, MAX_BROWSER_EVENT_DETAILS_BYTES,
    MAX_DOWNLOAD_HASH_BYTES,
};
pub use firewall::{
    InstalledWfpFilter, WfpFailedOp, WfpFilterOrigin, WfpReconcileReport, WfpRuleManager,
};
pub use ipc::{
    build_dev_bypass_pipe_security_descriptor, build_dev_bypass_pipe_security_descriptor_for_sid,
    build_service_pipe_security_descriptor, canonical_sddl_trustee_for_sid,
    current_process_user_sid, format_dev_bypass_pipe_sddl, inspect_pipe_client_exe,
    is_authorized_bridge_caller, is_authorized_ui_caller, read_kernel_object_dacl_sddl,
    start_ipc_server, verify_authorized_caller_binary, verify_caller_identity, IpcServerHandle,
    PipeSecurityDescriptor, DEV_BYPASS_SYSTEM_PIPE_SDDL, SERVICE_PIPE_SDDL,
};
pub use notify::{
    current_process_session_id, NoopNotificationDispatcher, NotificationDispatcher,
    Session0ToastLauncher,
};
pub use process_table::{ActiveProcessEntry, ActiveProcessTable, ProcessStartResolution};
