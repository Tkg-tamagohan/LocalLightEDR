//! ETW real-time trace sessions (`Kernel-Process`, `Kernel-File`, `Kernel-Registry`,
//! `DNS-Client`, `Kernel-Network`, `AMSI`, and PowerShell 4104) and Toolhelp32 initial process
//! snapshots (`AUTO-03`, `AUTO-06`, `AUTO-08`).

pub mod file_canary;
pub(crate) mod tdh;

mod cmdline_correlator;
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
    DEFAULT_ETW_SESSION_NAME, EventSinkFn, NoopSensorBackend, PackageAwareEventSinkFn,
    WindowsEtwSensor,
};
pub use self::snapshot::{
    CapturedProcessSnapshot, LiveSiblingCheck, capture_running_processes,
    find_other_live_processes_for_exe_key, try_capture_running_processes,
    try_capture_running_processes_with_package,
};

/// Package and AppContainer attributes gathered from a live process handle/token (`FU-P4-03`).
///
/// Both fields are collected independently without synthesizing a `package_sid` from
/// `package_family_name` when `TokenAppContainerSid` is absent (`PFN_ONLY_NON_APPCONTAINER`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessPackageInfo {
    pub package_family_name: Option<String>,
    pub package_sid: Option<String>,
}

impl ProcessPackageInfo {
    /// Returns `true` when neither `package_family_name` nor `package_sid` is populated.
    pub fn is_empty(&self) -> bool {
        self.package_family_name.is_none() && self.package_sid.is_none()
    }

    /// Trims whitespace and converts empty strings to `None` on both fields.
    pub fn normalized(self) -> Self {
        Self {
            package_family_name: normalize_optional_attr(self.package_family_name),
            package_sid: normalize_optional_attr(self.package_sid),
        }
    }
}

fn normalize_optional_attr(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| {
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

/// Live process attributes retrieved on demand via Win32 `OpenProcess` / `GetProcessTimes` /
/// `QueryFullProcessImageNameW` / `NtQueryInformationProcess`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProcessInfo {
    pub create_time_100ns: u64,
    pub exe_path: Option<String>,
    pub command_line: Option<String>,
    pub package_family_name: Option<String>,
    pub package_sid: Option<String>,
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
        package_family_name: info.package_family_name,
        package_sid: info.package_sid,
    })
}

#[cfg(test)]
mod tests;
