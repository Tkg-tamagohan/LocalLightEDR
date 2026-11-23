//! Process attribute inspection (`NtQueryInformationProcess`) and FILETIME helpers.

use std::ffi::c_void;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, FILETIME};
use windows::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::OwnedHandle;
use crate::path_norm::DosVolumeMap;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023_u32 as i32;

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtQueryInformationProcess(
        process_handle: windows::Win32::Foundation::HANDLE,
        process_information_class: u32,
        process_information: *mut c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: *mut c_void,
    affinity_mask: usize,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
}

#[repr(C)]
struct NtUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

/// Process attributes inspected via Win32 / `ntdll` process handle queries.
pub(crate) struct ProcessInspectInfo {
    pub(crate) parent_pid: Option<u32>,
    pub(crate) create_time_100ns: u64,
    pub(crate) exe_path: Option<String>,
    pub(crate) command_line: Option<String>,
}

/// Lightweight live process check result distinguishing `ERROR_ACCESS_DENIED` from exited/missing PIDs.
pub(crate) enum PidBasicInspect {
    Accessible {
        create_time_100ns: u64,
        exe_path: Option<String>,
    },
    AccessDenied,
    GoneOrInvalid,
}

/// Returns current Unix epoch time in milliseconds.
pub(crate) fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Converts a Windows 100ns `FILETIME` value to Unix epoch milliseconds.
pub(crate) fn filetime_100ns_to_unix_ms(ft_100ns: u64) -> i64 {
    if ft_100ns >= WINDOWS_TO_UNIX_EPOCH_100NS {
        ((ft_100ns - WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000) as i64
    } else {
        now_unix_ms()
    }
}

/// Combines `FILETIME` low/high parts into a `u64` 100ns timestamp.
#[inline]
pub(crate) fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

/// Inspects creation time, full Win32 image path, and command line for `pid` when accessible.
pub(crate) fn inspect_process_by_pid(
    pid: u32,
    volume_map: Option<&DosVolumeMap>,
) -> Option<ProcessInspectInfo> {
    if pid == 0 {
        return None;
    }

    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only metadata access.
    let raw_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let handle = OwnedHandle::new(raw_handle)?;

    // Windows `OpenProcess` -> `PsLookupProcessByProcessId` ignores the low 2 bits of `pid`
    // (`pid & !3`), so non-multiple-of-4 PIDs such as `pid + 1..=3` silently open `pid & !3`.
    // Reject handles whose actual kernel PID does not match the requested `pid` (also fails
    // closed if `GetProcessId` returns `0`).
    // SAFETY: `handle` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`.
    let actual_pid = unsafe { GetProcessId(handle.as_raw()) };
    if actual_pid != pid {
        return None;
    }

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` pointers are stack-allocated.
    let create_time_100ns = if unsafe {
        GetProcessTimes(
            handle.as_raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .is_ok()
    {
        filetime_to_u64(creation)
    } else {
        0
    };

    let mut path_buf = vec![0u16; 1024];
    let mut path_len = path_buf.len() as u32;
    // SAFETY: `handle` is valid and `path_buf` has `path_len` `u16` elements.
    let exe_path = if unsafe {
        QueryFullProcessImageNameW(
            handle.as_raw(),
            PROCESS_NAME_WIN32,
            PWSTR(path_buf.as_mut_ptr()),
            &mut path_len,
        )
    }
    .is_ok()
        && path_len > 0
    {
        let raw_slice = &path_buf[..(path_len as usize).min(path_buf.len())];
        Some(match volume_map {
            Some(map) => map.normalize_u16(raw_slice),
            None => String::from_utf16_lossy(raw_slice),
        })
    } else {
        None
    };

    let parent_pid = query_handle_parent_pid(handle.as_raw(), pid);
    let command_line = query_handle_command_line(handle.as_raw());

    Some(ProcessInspectInfo {
        parent_pid,
        create_time_100ns,
        exe_path,
        command_line,
    })
}

/// Lightweight live process probe querying only creation time and image path (skipping PEB reads)
/// while distinguishing `ERROR_ACCESS_DENIED` from exited or invalid PIDs.
pub(crate) fn inspect_process_basic_by_pid(
    pid: u32,
    volume_map: Option<&DosVolumeMap>,
) -> PidBasicInspect {
    if pid == 0 {
        return PidBasicInspect::GoneOrInvalid;
    }

    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only metadata access.
    let raw_handle = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(h) => h,
        Err(err) => {
            if err.code() == ERROR_ACCESS_DENIED.to_hresult() {
                return PidBasicInspect::AccessDenied;
            }
            return PidBasicInspect::GoneOrInvalid;
        }
    };
    let Some(handle) = OwnedHandle::new(raw_handle) else {
        return PidBasicInspect::GoneOrInvalid;
    };

    // SAFETY: `handle` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`.
    let actual_pid = unsafe { GetProcessId(handle.as_raw()) };
    if actual_pid != pid {
        return PidBasicInspect::GoneOrInvalid;
    }

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is open and all four `FILETIME` pointers are stack-allocated.
    let create_time_100ns = if unsafe {
        GetProcessTimes(
            handle.as_raw(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    }
    .is_ok()
    {
        filetime_to_u64(creation)
    } else {
        0
    };

    let mut path_buf = vec![0u16; 1024];
    let mut path_len = path_buf.len() as u32;
    // SAFETY: `handle` is valid and `path_buf` has `path_len` `u16` elements.
    let exe_path = if unsafe {
        QueryFullProcessImageNameW(
            handle.as_raw(),
            PROCESS_NAME_WIN32,
            PWSTR(path_buf.as_mut_ptr()),
            &mut path_len,
        )
    }
    .is_ok()
        && path_len > 0
    {
        let raw_slice = &path_buf[..(path_len as usize).min(path_buf.len())];
        Some(match volume_map {
            Some(map) => map.normalize_u16(raw_slice),
            None => String::from_utf16_lossy(raw_slice),
        })
    } else {
        None
    };

    PidBasicInspect::Accessible {
        create_time_100ns,
        exe_path,
    }
}

fn query_handle_parent_pid(
    handle: windows::Win32::Foundation::HANDLE,
    expected_pid: u32,
) -> Option<u32> {
    let mut info = ProcessBasicInformation {
        exit_status: 0,
        peb_base_address: std::ptr::null_mut(),
        affinity_mask: 0,
        base_priority: 0,
        unique_process_id: 0,
        inherited_from_unique_process_id: 0,
    };
    let mut ret_len: u32 = 0;

    // SAFETY: `handle` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`
    // and `info` is a writable stack-allocated `ProcessBasicInformation` buffer.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_BASIC_INFORMATION_CLASS,
            (&mut info as *mut ProcessBasicInformation).cast::<c_void>(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status != 0
        || (ret_len != 0 && (ret_len as usize) < std::mem::size_of::<ProcessBasicInformation>())
        || info.unique_process_id != expected_pid as usize
    {
        return None;
    }

    u32::try_from(info.inherited_from_unique_process_id)
        .ok()
        .filter(|&ppid| ppid != 0 && ppid != expected_pid)
}

fn query_handle_command_line(handle: windows::Win32::Foundation::HANDLE) -> Option<String> {
    let mut buf = vec![0u64; 512]; // 4 KiB, 8-byte aligned
    let mut ret_len: u32 = 0;

    // SAFETY: `handle` is an open process handle; `buf` is 8-byte aligned writable storage.
    let mut status = unsafe {
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            buf.as_mut_ptr().cast::<c_void>(),
            (buf.len() * 8) as u32,
            &mut ret_len,
        )
    };

    if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL)
        && ret_len > (buf.len() * 8) as u32
        && ret_len <= 65_536
    {
        buf.resize((ret_len as usize).div_ceil(8), 0);
        // SAFETY: same preconditions as above with resized buffer.
        status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr().cast::<c_void>(),
                (buf.len() * 8) as u32,
                &mut ret_len,
            )
        };
    }

    if status != 0 {
        return None;
    }

    let total_bytes = buf.len() * 8;
    if total_bytes < std::mem::size_of::<NtUnicodeString>() {
        return None;
    }

    // SAFETY: `buf` is 8-byte aligned and at least `size_of::<NtUnicodeString>()` bytes.
    let us = unsafe { &*(buf.as_ptr().cast::<NtUnicodeString>()) };
    if us.length == 0 || us.buffer.is_null() || (us.length & 1) != 0 {
        return Some(String::new());
    }

    let buf_start = buf.as_ptr() as usize;
    let buf_end = buf_start + total_bytes;
    let str_start = us.buffer as usize;
    let str_len_bytes = us.length as usize;
    if str_start < buf_start || str_start.saturating_add(str_len_bytes) > buf_end {
        return None;
    }

    // SAFETY: verified `str_start..str_start + str_len_bytes` lies completely inside `buf`.
    let slice = unsafe { std::slice::from_raw_parts(us.buffer, str_len_bytes / 2) };
    Some(String::from_utf16_lossy(slice))
}
