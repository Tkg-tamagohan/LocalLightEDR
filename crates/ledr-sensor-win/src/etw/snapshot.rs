//! Toolhelp32 initial running-process baseline snapshot (`AUTO-03`, `BUG_0002`).

use ledr_proto::{ProcessIdentity, SensorEvent};
use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use crate::path_norm::DosVolumeMap;
use crate::{OwnedHandle, SensorError};

use super::tdh::inspect_process_by_pid;

/// Captures a baseline snapshot of currently running processes using Toolhelp32 (`AUTO-03`,
/// `BUG_0002`).
///
/// Queries each accessible process's `CreationTime` (`create_time_100ns`), full Win32 image path,
/// and command line. Protected system processes that deny `PROCESS_QUERY_LIMITED_INFORMATION`
/// in non-elevated sessions still emit an entry using the Toolhelp32 executable name fallback.
///
/// Returns `Err(SensorError::Snapshot)` if snapshot creation, initial enumeration, mid-stream
/// iteration (any `Process32NextW` error other than `ERROR_NO_MORE_FILES`), or zero-process
/// enumeration occurs so callers never mistake a truncated snapshot for all processes having
/// exited.
pub fn try_capture_running_processes() -> Result<Vec<SensorEvent>, SensorError> {
    // SAFETY: `TH32CS_SNAPPROCESS` with PID 0 snapshots all processes on the host.
    let raw_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|err| {
        SensorError::Snapshot(format!(
            "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed: {err}"
        ))
    })?;
    let snapshot = OwnedHandle::new(raw_snap).ok_or_else(|| {
        SensorError::Snapshot(
            "CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) returned an invalid handle".to_string(),
        )
    })?;

    let volume_map = DosVolumeMap::from_system();
    let mut events = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: `snapshot` is a valid process snapshot handle and `entry.dwSize` is initialized.
    if let Err(err) = unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) } {
        return Err(SensorError::Snapshot(format!(
            "Process32FirstW failed: {err}"
        )));
    }

    let no_more_files = ERROR_NO_MORE_FILES.to_hresult();
    loop {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            let fallback_name = utf16_z_to_string(&entry.szExeFile);
            let inspected = inspect_process_by_pid(pid, Some(&volume_map));
            let (create_time_100ns, exe_path, command_line) = match inspected {
                Some(info) => (
                    info.create_time_100ns,
                    info.exe_path.unwrap_or(fallback_name),
                    info.command_line.unwrap_or_default(),
                ),
                None => (0, fallback_name, String::new()),
            };

            events.push(SensorEvent::ProcessStart {
                identity: ProcessIdentity::new(pid, create_time_100ns),
                parent_pid: entry.th32ParentProcessID,
                exe_path,
                command_line,
                user_sid: None,
            });
        }

        // SAFETY: `snapshot` and `entry` remain valid across iteration.
        if let Err(err) = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) } {
            if err.code() == no_more_files {
                break;
            }
            return Err(SensorError::Snapshot(format!(
                "Process32NextW failed: {err}"
            )));
        }
    }

    if events.is_empty() {
        return Err(SensorError::Snapshot(
            "enumerated 0 running processes".to_string(),
        ));
    }

    Ok(events)
}

/// Captures a baseline snapshot of currently running processes using Toolhelp32 (`AUTO-03`).
///
/// Backwards-compatible infallible wrapper around [`try_capture_running_processes`]; returns an
/// empty vector on snapshot errors. Callers performing stale-process reconciliation should prefer
/// [`try_capture_running_processes`] to distinguish empty snapshots from enumeration failures.
pub fn capture_running_processes() -> Vec<SensorEvent> {
    try_capture_running_processes().unwrap_or_default()
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
