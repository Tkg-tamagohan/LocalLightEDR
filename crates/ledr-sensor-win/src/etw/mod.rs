//! ETW real-time trace sessions (`Kernel-Process`, `Kernel-File`, `Kernel-Registry`,
//! `DNS-Client`, `Kernel-Network`, `AMSI`, and PowerShell 4104) and Toolhelp32 initial process
//! snapshots (`AUTO-03`, `AUTO-06`, `AUTO-08`).

pub mod file_canary;
pub(crate) mod tdh;

mod context;
mod handlers;
mod registry;
mod session;
mod snapshot;

pub use self::file_canary::{
    CanaryMatcher, is_autorun_registry_key, is_autorun_registry_key_u16,
    is_autorun_registry_value_target, is_autorun_registry_value_target_u16,
    prefilter_and_classify_canary, prefilter_and_classify_canary_u16,
};
pub use self::session::{
    DEFAULT_ETW_SESSION_NAME, EventSinkFn, NoopSensorBackend, WindowsEtwSensor,
};
pub use self::snapshot::{capture_running_processes, try_capture_running_processes};

/// Live process attributes retrieved on demand via Win32 `OpenProcess` / `GetProcessTimes` /
/// `QueryFullProcessImageNameW` / `NtQueryInformationProcess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProcessInfo {
    pub create_time_100ns: u64,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
}

/// On-demand process inspection fallback for ETW cross-provider ordering races (e.g., when
/// `Kernel-File` reports a canary access milliseconds before `Kernel-Process` delivers
/// `ProcessStart`).
pub fn inspect_live_process(pid: u32) -> Option<LiveProcessInfo> {
    let info: self::tdh::ProcessInspectInfo = self::tdh::inspect_process_by_pid(pid, None)?;
    Some(LiveProcessInfo {
        create_time_100ns: info.create_time_100ns,
        exe_path: info.exe_path,
        command_line: info.command_line,
    })
}

#[cfg(test)]
mod tests;
