//! Layer 2 LocalEDR resident core daemon library.
//!
//! Exposes [`TwoLaneChannel`], [`ActiveProcessTable`], [`DaemonEngine`], and the
//! Windows Named Pipe IPC server (`ipc::start_ipc_server`).

pub mod channel;
pub mod engine;
pub mod ipc;
pub mod process_table;

pub use channel::{
    ChannelClosedError, HighPrioritySendError, TwoLaneChannel, TwoLaneReceiver, TwoLaneSender,
};
pub use engine::{DaemonConfig, DaemonEngine};
pub use ipc::{
    inspect_pipe_client_exe, is_authorized_bridge_caller, is_authorized_ui_caller,
    start_ipc_server, IpcServerHandle,
};
pub use process_table::{ActiveProcessEntry, ActiveProcessTable, ProcessStartResolution};
