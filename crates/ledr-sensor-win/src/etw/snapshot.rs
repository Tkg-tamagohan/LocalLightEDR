//! Toolhelp32 initial running-process baseline snapshot (`AUTO-03`, `BUG_0002`).

use ledr_proto::{ProcessIdentity, SensorEvent};
use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

use crate::path_norm::DosVolumeMap;
use crate::{OwnedHandle, SensorError};

use super::ProcessPackageInfo;
use super::tdh::{
    PidBasicInspect, filetime_100ns_to_unix_ms, inspect_process_basic_by_pid, inspect_process_by_pid,
};

/// Running-process snapshot entry paired with independently collected package/AppContainer
/// attributes (`FU-P4-03`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProcessSnapshot {
    pub event: SensorEvent,
    pub package: ProcessPackageInfo,
}

/// Result of querying live OS processes for another active instance of the same executable (`FU-E2E-05`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveSiblingCheck {
    NoneFound,
    SiblingFound(Vec<ProcessIdentity>),
    CandidateGone,
    Indeterminate,
}

fn normalize_exe_key(raw: &str) -> String {
    let trimmed = raw.trim().replace('/', "\\");
    let stripped = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &trimmed[8..])
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed
    };
    stripped.to_ascii_lowercase()
}

/// Scans running OS processes via Toolhelp32, pre-filtering by `szExeFile` basename before
/// opening process handles, to detect concurrent live sibling instances of `exe_key` (`FU-E2E-05`).
pub fn find_other_live_processes_for_exe_key(
    exe_key: &str,
    candidate: ProcessIdentity,
    max_created_at_ms: i64,
) -> LiveSiblingCheck {
    let target_key = normalize_exe_key(exe_key);
    let target_leaf = target_key
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim();
    if target_key.is_empty() || target_leaf.is_empty() {
        return LiveSiblingCheck::Indeterminate;
    }

    // SAFETY: `TH32CS_SNAPPROCESS` with PID 0 snapshots all processes on the host.
    let Ok(raw_snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return LiveSiblingCheck::Indeterminate;
    };
    let Some(snapshot) = OwnedHandle::new(raw_snap) else {
        return LiveSiblingCheck::Indeterminate;
    };

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: `snapshot` is a valid process snapshot handle and `entry.dwSize` is initialized.
    if unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) }.is_err() {
        return LiveSiblingCheck::Indeterminate;
    }

    let no_more_files = ERROR_NO_MORE_FILES.to_hresult();
    let mut volume_map: Option<DosVolumeMap> = None;
    let mut saw_candidate_live = false;
    let mut siblings: Vec<ProcessIdentity> = Vec::new();
    let mut unverified_same_name_other_pid = false;

    loop {
        let pid = entry.th32ProcessID;
        if pid != 0 {
            let exe_name = utf16_z_to_string(&entry.szExeFile);
            if exe_name.eq_ignore_ascii_case(target_leaf) {
                let vmap = volume_map.get_or_insert_with(DosVolumeMap::from_system);
                match inspect_process_basic_by_pid(pid, Some(vmap)) {
                    PidBasicInspect::Accessible {
                        create_time_100ns,
                        exe_path,
                    } => {
                        if pid == candidate.pid
                            && (candidate.create_time_100ns == 0
                                || create_time_100ns == candidate.create_time_100ns)
                        {
                            saw_candidate_live = true;
                        } else if let Some(path) = exe_path {
                            if normalize_exe_key(&path) == target_key {
                                if create_time_100ns != 0 {
                                    let created_ms = filetime_100ns_to_unix_ms(create_time_100ns);
                                    if created_ms <= max_created_at_ms {
                                        siblings.push(ProcessIdentity::new(pid, create_time_100ns));
                                    }
                                } else {
                                    unverified_same_name_other_pid = true;
                                }
                            }
                        } else if pid != candidate.pid {
                            unverified_same_name_other_pid = true;
                        }
                    }
                    PidBasicInspect::AccessDenied => {
                        if pid == candidate.pid {
                            saw_candidate_live = true;
                        } else {
                            unverified_same_name_other_pid = true;
                        }
                    }
                    PidBasicInspect::GoneOrInvalid => {}
                }
            }
        }

        // SAFETY: `snapshot` and `entry` remain valid across iteration.
        if let Err(err) = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) } {
            if err.code() == no_more_files {
                break;
            }
            return LiveSiblingCheck::Indeterminate;
        }
    }

    if !siblings.is_empty() {
        LiveSiblingCheck::SiblingFound(siblings)
    } else if unverified_same_name_other_pid {
        LiveSiblingCheck::SiblingFound(Vec::new())
    } else if candidate.create_time_100ns != 0 && !saw_candidate_live {
        LiveSiblingCheck::CandidateGone
    } else {
        LiveSiblingCheck::NoneFound
    }
}

/// Captures a baseline snapshot of currently running processes using Toolhelp32 (`AUTO-03`,
/// `BUG_0002`), preserving each process's independently collected [`ProcessPackageInfo`].
pub fn try_capture_running_processes_with_package()
-> Result<Vec<CapturedProcessSnapshot>, SensorError> {
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
    let mut snapshots = Vec::new();
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
            let (create_time_100ns, exe_path, command_line, package) = match inspected {
                Some(info) => (
                    info.create_time_100ns,
                    info.exe_path.unwrap_or(fallback_name),
                    info.command_line.unwrap_or_default(),
                    ProcessPackageInfo {
                        package_family_name: info.package_family_name,
                        package_sid: info.package_sid,
                    }
                    .normalized(),
                ),
                None => (0, fallback_name, String::new(), ProcessPackageInfo::default()),
            };

            snapshots.push(CapturedProcessSnapshot {
                event: SensorEvent::ProcessStart {
                    identity: ProcessIdentity::new(pid, create_time_100ns),
                    parent_pid: entry.th32ParentProcessID,
                    exe_path,
                    command_line,
                    user_sid: None,
                },
                package,
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

    if snapshots.is_empty() {
        return Err(SensorError::Snapshot(
            "enumerated 0 running processes".to_string(),
        ));
    }

    Ok(snapshots)
}

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
    Ok(try_capture_running_processes_with_package()?
        .into_iter()
        .map(|snap| snap.event)
        .collect())
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
