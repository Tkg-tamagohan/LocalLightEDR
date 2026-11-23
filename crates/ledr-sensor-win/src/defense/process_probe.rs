//! Low-level Win32 process handle inspection, Toolhelp32 snapshot, and liveness probe (`BUG_0002`, `BUG_0004`).

use std::ffi::c_void;
use std::mem::{align_of, size_of};

use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME, HANDLE, STILL_ACTIVE, WAIT_OBJECT_0};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessId, GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    QueryFullProcessImageNameW, WaitForSingleObject,
};

use crate::OwnedHandle;

const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
const INITIAL_SYS_PROC_BUF_BYTES: usize = 256 * 1024;
const MAX_SYS_PROC_QUERY_ATTEMPTS: usize = 8;
const MAX_SYS_PROC_BUF_BYTES: usize = 64 * 1024 * 1024;

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// Binary layout matching Windows `SYSTEM_PROCESS_INFORMATION` through `InheritedFromUniqueProcessId`.
#[repr(C)]
struct SystemProcessInformationHeader {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name_length: u16,
    image_name_maximum_length: u16,
    #[cfg(target_pointer_width = "64")]
    _image_name_pad: u32,
    image_name_buffer: *const u16,
    base_priority: i32,
    #[cfg(target_pointer_width = "64")]
    _base_priority_pad: u32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[derive(Debug, Clone)]
pub(super) struct SnapshotEntry {
    pub(super) pid: u32,
    pub(super) ppid: u32,
    pub(super) exe_name: String,
    pub(super) create_time_100ns: Option<u64>,
}

pub(super) fn snapshot_process_entries() -> Result<Vec<SnapshotEntry>, String> {
    match snapshot_process_entries_nt_system_info() {
        Ok(entries) => Ok(entries),
        Err(nt_err) => {
            tracing::warn!(
                error = %nt_err,
                "NtQuerySystemInformation(SystemProcessInformation) failed; falling back to Toolhelp32 without creation timestamps"
            );
            snapshot_process_entries_toolhelp32()
        }
    }
}

fn snapshot_process_entries_nt_system_info() -> Result<Vec<SnapshotEntry>, String> {
    let mut buf_bytes = INITIAL_SYS_PROC_BUF_BYTES;
    let mut buffer: Vec<u64> = Vec::new();
    let mut valid_len: usize = 0;

    for _ in 0..MAX_SYS_PROC_QUERY_ATTEMPTS {
        let words = buf_bytes.div_ceil(size_of::<u64>());
        buffer.resize(words, 0);
        let byte_cap = buffer.len() * size_of::<u64>();
        let Ok(byte_cap_u32) = u32::try_from(byte_cap) else {
            return Err("SystemProcessInformation buffer exceeds u32 capacity".to_string());
        };
        let mut return_len: u32 = 0;

        // SAFETY: `buffer` is 8-byte aligned writable storage of `byte_cap_u32` bytes and
        // `return_len` is a valid writable `u32`.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                buffer.as_mut_ptr().cast::<c_void>(),
                byte_cap_u32,
                &mut return_len,
            )
        };
        if status >= 0 {
            let returned = usize::try_from(return_len).unwrap_or(byte_cap);
            valid_len = if returned == 0 {
                byte_cap
            } else {
                returned.min(byte_cap)
            };
            break;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL {
            let hinted = usize::try_from(return_len).unwrap_or(0);
            let next_bytes = hinted
                .saturating_add(64 * 1024)
                .max(buf_bytes.saturating_mul(2))
                .min(MAX_SYS_PROC_BUF_BYTES);
            if next_bytes <= buf_bytes {
                return Err(format!(
                    "SystemProcessInformation exceeded max buffer ({MAX_SYS_PROC_BUF_BYTES} bytes)"
                ));
            }
            buf_bytes = next_bytes;
            continue;
        }
        return Err(format!(
            "NtQuerySystemInformation(SystemProcessInformation) failed with NTSTATUS 0x{:08X}",
            status as u32
        ));
    }

    if valid_len == 0 {
        return Err("NtQuerySystemInformation(SystemProcessInformation) exhausted resize retries".to_string());
    }

    let base_ptr = buffer.as_ptr().cast::<u8>();
    let buf_start = base_ptr as usize;
    let buf_end = buf_start
        .checked_add(valid_len)
        .ok_or_else(|| "SystemProcessInformation buffer address overflow".to_string())?;
    let header_size = size_of::<SystemProcessInformationHeader>();
    let header_align = align_of::<SystemProcessInformationHeader>();

    let mut out = Vec::new();
    let mut cursor: usize = 0;
    loop {
        if !cursor.is_multiple_of(header_align) || cursor.saturating_add(header_size) > valid_len {
            return Err(format!(
                "SystemProcessInformation entry misaligned or truncated at offset {cursor}/{valid_len}"
            ));
        }

        // SAFETY: `cursor` is within `valid_len` and properly aligned for `SystemProcessInformationHeader`.
        let header = unsafe { &*base_ptr.add(cursor).cast::<SystemProcessInformationHeader>() };
        if let (Ok(pid), Ok(ppid)) = (
            u32::try_from(header.unique_process_id),
            u32::try_from(header.inherited_from_unique_process_id),
        ) {
            let exe_name = extract_unicode_image_name(
                header.image_name_length,
                header.image_name_buffer,
                buf_start,
                buf_end,
            );
            let create_time_100ns = u64::try_from(header.create_time).ok().filter(|&ct| ct > 0);
            out.push(SnapshotEntry {
                pid,
                ppid,
                exe_name,
                create_time_100ns,
            });
        }

        if header.next_entry_offset == 0 {
            break;
        }
        let step = header.next_entry_offset as usize;
        if step < header_size {
            return Err(format!(
                "SystemProcessInformation invalid NextEntryOffset {step} < {header_size}"
            ));
        }
        let next_cursor = cursor
            .checked_add(step)
            .ok_or_else(|| "SystemProcessInformation NextEntryOffset overflow".to_string())?;
        if next_cursor >= valid_len {
            return Err(format!(
                "SystemProcessInformation NextEntryOffset {next_cursor} >= {valid_len}"
            ));
        }
        cursor = next_cursor;
    }

    Ok(out)
}

fn extract_unicode_image_name(
    byte_len: u16,
    ptr: *const u16,
    buf_start: usize,
    buf_end: usize,
) -> String {
    let len_bytes = usize::from(byte_len);
    if len_bytes < size_of::<u16>() || ptr.is_null() {
        return String::new();
    }
    let addr = ptr as usize;
    if addr < buf_start || addr > buf_end || (buf_end - addr) < len_bytes {
        return String::new();
    }
    let u16_len = len_bytes / size_of::<u16>();
    let mut wide = vec![0u16; u16_len];
    // SAFETY: We verified `[addr .. addr + u16_len * 2]` lies inside `[buf_start .. buf_end]`;
    // `copy_nonoverlapping` handles any byte alignment safely.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), wide.as_mut_ptr().cast::<u8>(), u16_len * 2);
    }
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

fn snapshot_process_entries_toolhelp32() -> Result<Vec<SnapshotEntry>, String> {
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
            create_time_100ns: None,
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

/// Bounded wait (in milliseconds) for Windows asynchronous kernel process rundown.
pub(super) const PROCESS_EXIT_WAIT_MS: u32 = 25;

pub(super) fn query_process_creation_time(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` structs are valid.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.ok()?;
    Some(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
}

pub(super) fn query_process_exit_code(handle: HANDLE) -> Option<u32> {
    let mut exit_code = 0u32;
    // SAFETY: `handle` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`
    // (or `PROCESS_QUERY_INFORMATION`) and `exit_code` is valid writable storage.
    unsafe { GetExitCodeProcess(handle, &mut exit_code) }.ok()?;
    Some(exit_code)
}

/// Returns `true` only when `handle` positively confirms the process has exited in the kernel:
/// - When `has_synchronize` is `true`, uses `WaitForSingleObject(handle, wait_ms) == WAIT_OBJECT_0`
///   (authoritative process-object signal; never relies on `GetProcessTimes` `lpExitTime`, which
///   Win32 leaves undefined while a process is still running).
/// - When `has_synchronize` is `false` (`PROCESS_QUERY_LIMITED_INFORMATION` fallback), checks
///   `GetExitCodeProcess(handle) != STILL_ACTIVE` (`259`), failing closed (`false`) if the query
///   fails or reports `STILL_ACTIVE`.
pub(super) fn is_process_handle_exited(
    handle: HANDLE,
    has_synchronize: bool,
    wait_ms: u32,
) -> bool {
    if has_synchronize {
        // SAFETY: `handle` is an open process handle granted `PROCESS_SYNCHRONIZE`.
        return unsafe { WaitForSingleObject(handle, wait_ms) } == WAIT_OBJECT_0;
    }
    query_process_exit_code(handle).is_some_and(|code| code != STILL_ACTIVE.0 as u32)
}

pub(super) fn find_process_exe_toolhelp32(pid: u32) -> Option<String> {
    let entries = snapshot_process_entries().ok()?;
    entries
        .into_iter()
        .find(|e| e.pid == pid)
        .map(|e| e.exe_name)
}

/// Tri-state liveness of a PID from the Toolhelp32 snapshot and kernel exit probe.
/// [`ProcessLiveness::Gone`] means the snapshot positively confirmed absence or the
/// kernel confirmed process exit (signaled `SYNCHRONIZE` handle or `GetExitCodeProcess !=
/// STILL_ACTIVE` for a zombie/rundown process); `Unknown` means snapshot creation or enumeration
/// failed, so absence is unconfirmed. Containment decisions must not treat `Unknown`
/// as "gone" (`BUG_0002`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLiveness {
    Running,
    Gone,
    Unknown,
}

/// Probes whether `pid` is live, distinguishing confirmed absence/exit (including terminated
/// zombie processes whose handles are still held open during Windows asynchronous rundown)
/// from genuinely running processes and snapshot/enumeration failures (`BUG_0004`, `BUG_0002`).
pub fn process_liveness(pid: u32) -> ProcessLiveness {
    match snapshot_process_entries() {
        Ok(entries) if entries.iter().any(|e| e.pid == pid) => {
            probe_snapshot_present_pid_liveness(pid)
        }
        Ok(_) => ProcessLiveness::Gone,
        Err(_) => ProcessLiveness::Unknown,
    }
}

pub(super) fn probe_snapshot_present_pid_liveness(pid: u32) -> ProcessLiveness {
    if pid == 0 {
        return ProcessLiveness::Running;
    }

    match open_process_checked_detailed(
        pid,
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Ok(handle) => {
            if is_process_handle_exited(handle.as_raw(), true, PROCESS_EXIT_WAIT_MS) {
                ProcessLiveness::Gone
            } else {
                ProcessLiveness::Running
            }
        }
        Err(OpenProcessError::PidZero | OpenProcessError::PidMismatch { .. }) => {
            ProcessLiveness::Running
        }
        Err(OpenProcessError::Failed(_)) => {
            match open_process_checked_detailed(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
                Ok(handle) => {
                    if is_process_handle_exited(handle.as_raw(), false, 0) {
                        ProcessLiveness::Gone
                    } else {
                        ProcessLiveness::Running
                    }
                }
                Err(OpenProcessError::PidZero | OpenProcessError::PidMismatch { .. }) => {
                    ProcessLiveness::Running
                }
                Err(OpenProcessError::Failed(_)) => {
                    // Re-check snapshot once in case the PID finished exiting between the first
                    // snapshot and `OpenProcess`, while staying fail-closed (`Running`) on live
                    // protected processes that deny `OpenProcess` (`ERROR_ACCESS_DENIED`).
                    match snapshot_process_entries() {
                        Ok(entries) if entries.iter().any(|e| e.pid == pid) => {
                            ProcessLiveness::Running
                        }
                        Ok(_) => ProcessLiveness::Gone,
                        Err(_) => ProcessLiveness::Unknown,
                    }
                }
            }
        }
    }
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
