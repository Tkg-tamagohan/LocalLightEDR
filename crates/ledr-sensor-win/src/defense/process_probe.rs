//! Low-level Win32 process handle inspection, Toolhelp32 snapshot, and liveness probe (`BUG_0002`, `BUG_0004`).

use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    QueryFullProcessImageNameW,
};

use crate::OwnedHandle;

#[derive(Debug, Clone)]
pub(super) struct SnapshotEntry {
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) exe_name: String,
}

pub(super) fn snapshot_process_entries() -> Result<Vec<SnapshotEntry>, String> {
    // SAFETY: `TH32CS_SNAPPROCESS` with PID 0 enumerates all processes on the host.
    let raw_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|err| format!("CreateToolhelp32Snapshot failed: {err}"))?;
    let snapshot = OwnedHandle::new(raw_snap)
        .ok_or_else(|| "CreateToolhelp32Snapshot returned an invalid handle".to_string())?;

    let mut out = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: `snapshot` is valid and `entry.dwSize` is initialized.
    if let Err(err) = unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) } {
        return Err(format!("Process32FirstW failed: {err}"));
    }

    let no_more_files = ERROR_NO_MORE_FILES.to_hresult();
    loop {
        out.push(SnapshotEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            exe_name: utf16_z_to_string(&entry.szExeFile),
        });

        // SAFETY: `snapshot` and `entry` remain valid across iteration.
        if let Err(err) = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) } {
            if err.code() == no_more_files {
                break;
            }
            return Err(format!("Process32NextW failed: {err}"));
        }
    }

    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OpenProcessError {
    PidZero,
    PidMismatch { requested: u32, actual: u32 },
    Failed(String),
}

impl OpenProcessError {
    pub(super) fn into_message(self) -> String {
        match self {
            Self::PidZero => "OpenProcess(PID 0) refused".to_string(),
            Self::PidMismatch { requested, actual } => {
                format!("OpenProcess(PID {requested}) resolved to mismatched PID {actual}")
            }
            Self::Failed(msg) => msg,
        }
    }
}

pub(super) fn open_process_checked_detailed(
    pid: u32,
    access: PROCESS_ACCESS_RIGHTS,
) -> Result<OwnedHandle, OpenProcessError> {
    if pid == 0 {
        return Err(OpenProcessError::PidZero);
    }
    // SAFETY: `OpenProcess` takes plain integer flags and PID; result handle is RAII-wrapped.
    let raw = unsafe { OpenProcess(access, false, pid) }
        .map_err(|err| OpenProcessError::Failed(format!("OpenProcess(PID {pid}) failed: {err}")))?;
    let handle = OwnedHandle::new(raw).ok_or_else(|| {
        OpenProcessError::Failed(format!("OpenProcess(PID {pid}) returned invalid handle"))
    })?;
    // Windows `OpenProcess` ignores the low 2 bits of `pid` (`pid & !3`), so `pid + 1..=3` can
    // silently open `pid & !3` (including PID 4 via 5..=7 or self via `self_pid + 1..=3`).
    // Callers pass `PROCESS_QUERY_LIMITED_INFORMATION`; fail closed on `0` or any PID mismatch.
    // SAFETY: `handle` is an open process handle owned by `handle`.
    let actual_pid = unsafe { GetProcessId(handle.as_raw()) };
    if actual_pid == 0 {
        return Err(OpenProcessError::Failed(format!(
            "GetProcessId(PID {pid}) failed (handle lacks query access or is invalid)"
        )));
    }
    if actual_pid != pid {
        return Err(OpenProcessError::PidMismatch {
            requested: pid,
            actual: actual_pid,
        });
    }
    Ok(handle)
}

pub(super) fn open_process_checked(
    pid: u32,
    access: PROCESS_ACCESS_RIGHTS,
) -> Result<OwnedHandle, String> {
    open_process_checked_detailed(pid, access).map_err(OpenProcessError::into_message)
}

pub(super) fn query_full_image_name(handle: HANDLE) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `handle` is an open process handle and `buf` is valid writable storage.
    unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }
        .ok()?;
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(
        &buf[..(len as usize).min(buf.len())],
    ))
}

pub(super) fn query_process_creation_time(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` structs are valid.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.ok()?;
    Some(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
}

pub(super) fn find_process_exe_toolhelp32(pid: u32) -> Option<String> {
    let entries = snapshot_process_entries().ok()?;
    entries
        .into_iter()
        .find(|e| e.pid == pid)
        .map(|e| e.exe_name)
}

/// Tri-state liveness of a PID from the Toolhelp32 snapshot. [`ProcessLiveness::Gone`]
/// means the snapshot enumerated successfully and the PID is absent; `Unknown` means
/// snapshot creation or enumeration failed, so absence is unconfirmed. Containment
/// decisions must not treat `Unknown` as "gone" (`BUG_0002`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLiveness {
    Running,
    Gone,
    Unknown,
}

/// Probes whether `pid` is present in the current Toolhelp32 snapshot, distinguishing
/// confirmed absence from snapshot/enumeration failures (`BUG_0004`, `BUG_0002` — lets
/// callers tell "target already exited" from a genuine suspend/resume/terminate failure
/// on a still-running process, and both from an unverifiable state).
pub fn process_liveness(pid: u32) -> ProcessLiveness {
    match snapshot_process_entries() {
        Ok(entries) if entries.iter().any(|e| e.pid == pid) => ProcessLiveness::Running,
        Ok(_) => ProcessLiveness::Gone,
        Err(_) => ProcessLiveness::Unknown,
    }
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
