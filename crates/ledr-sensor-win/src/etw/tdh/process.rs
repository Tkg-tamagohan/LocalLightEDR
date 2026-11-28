//! Process attribute inspection (`NtQueryInformationProcess`) and FILETIME helpers.

use std::ffi::c_void;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use windows::core::PWSTR;
use windows::Win32::Foundation::{
    APPMODEL_ERROR_NO_PACKAGE, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS,
    FILETIME, HANDLE,
};
use windows::Win32::Security::{
    GetTokenInformation, TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY, TokenAppContainerSid,
};
use windows::Win32::Storage::Packaging::Appx::GetPackageFamilyName;
use windows::Win32::System::Threading::{
    GetProcessId, GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

use crate::OwnedHandle;
use crate::etw::ProcessPackageInfo;
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

#[link(name = "advapi32")]
extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(hmem: *mut c_void) -> *mut c_void;
}

struct OwnedLocalPtr(*mut c_void);

impl Drop for OwnedLocalPtr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `ConvertSidToStringSidW` and must be freed via `LocalFree`.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

/// Distinguishes access-denied/OS errors from confirmed absence (`Ok(None)`) when querying
/// process package/AppContainer metadata (`FU-P4-03`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PackageAttrQueryError {
    AccessDenied,
    OsError(u32),
    InvalidData,
}

/// Independent probe result for `GetPackageFamilyName` and `TokenAppContainerSid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessPackageProbe {
    pub(crate) package_family_name: Result<Option<String>, PackageAttrQueryError>,
    pub(crate) package_sid: Result<Option<String>, PackageAttrQueryError>,
}

impl ProcessPackageProbe {
    pub(crate) fn into_info(self) -> ProcessPackageInfo {
        ProcessPackageInfo {
            package_family_name: self.package_family_name.ok().flatten(),
            package_sid: self.package_sid.ok().flatten(),
        }
        .normalized()
    }
}

#[inline]
fn win32_code_from_error(err: &windows::core::Error) -> Option<u32> {
    let hr = err.code().0 as u32;
    ((hr & 0xFFFF_0000) == 0x8007_0000).then_some(hr & 0xFFFF)
}

fn map_windows_error_to_pkg_err(err: &windows::core::Error) -> PackageAttrQueryError {
    match win32_code_from_error(err) {
        Some(code) if code == ERROR_ACCESS_DENIED.0 => PackageAttrQueryError::AccessDenied,
        Some(code) => PackageAttrQueryError::OsError(code),
        None => PackageAttrQueryError::OsError(err.code().0 as u32),
    }
}

/// Converts a Win32 `SID` pointer to its canonical `S-1-...` string representation.
pub(crate) fn sid_ptr_to_string(sid: *const c_void) -> Result<String, u32> {
    if sid.is_null() {
        return Err(87); // ERROR_INVALID_PARAMETER
    }
    let mut ptr_wide: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid non-null Win32 SID pointer for the duration of this call.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut ptr_wide) };
    if ok == 0 || ptr_wide.is_null() {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .and_then(|c| u32::try_from(c).ok())
            .filter(|&c| c != 0)
            .unwrap_or(1);
        return Err(code);
    }
    let _guard = OwnedLocalPtr(ptr_wide.cast::<c_void>());
    let mut len = 0usize;
    // SAFETY: `ConvertSidToStringSidW` guarantees a NUL-terminated UTF-16 string.
    while unsafe { *ptr_wide.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `ptr_wide` points to `len` valid `u16` code units.
    let slice = unsafe { std::slice::from_raw_parts(ptr_wide, len) };
    Ok(String::from_utf16_lossy(slice))
}

/// Queries `GetPackageFamilyName` on an open process handle without deriving or fabricating a SID.
pub(crate) fn query_process_package_family_name(
    proc_handle: HANDLE,
) -> Result<Option<String>, PackageAttrQueryError> {
    if proc_handle.0.is_null() {
        return Err(PackageAttrQueryError::InvalidData);
    }
    let mut len: u32 = 0;
    // SAFETY: `proc_handle` is a valid process handle; `None` probes required UTF-16 length.
    let first = unsafe { GetPackageFamilyName(proc_handle, &mut len, None) };
    if first == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if first == ERROR_ACCESS_DENIED {
        return Err(PackageAttrQueryError::AccessDenied);
    }
    if first != ERROR_INSUFFICIENT_BUFFER {
        return Err(PackageAttrQueryError::OsError(first.0));
    }
    if len == 0 || len > 4096 {
        return Err(PackageAttrQueryError::InvalidData);
    }

    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` has length `len` as requested by `GetPackageFamilyName`.
    let second = unsafe { GetPackageFamilyName(proc_handle, &mut len, Some(PWSTR(buf.as_mut_ptr()))) };
    if second == APPMODEL_ERROR_NO_PACKAGE {
        return Ok(None);
    }
    if second == ERROR_ACCESS_DENIED {
        return Err(PackageAttrQueryError::AccessDenied);
    }
    if second != ERROR_SUCCESS {
        return Err(PackageAttrQueryError::OsError(second.0));
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let name = String::from_utf16_lossy(&buf[..end]);
    let trimmed = name.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

/// Queries `TokenAppContainerSid` on an open process handle without falling back to
/// `DeriveAppContainerSidFromAppContainerName`.
pub(crate) fn query_token_app_container_sid(
    proc_handle: HANDLE,
) -> Result<Option<String>, PackageAttrQueryError> {
    if proc_handle.0.is_null() {
        return Err(PackageAttrQueryError::InvalidData);
    }
    let mut raw_token = HANDLE::default();
    // SAFETY: `proc_handle` is valid; `raw_token` receives the opened token handle.
    unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut raw_token) }
        .map_err(|err| map_windows_error_to_pkg_err(&err))?;
    let Some(token) = OwnedHandle::new(raw_token) else {
        return Err(PackageAttrQueryError::InvalidData);
    };

    let mut needed: u32 = 0;
    // SAFETY: probing required buffer size for `TokenAppContainerSid`.
    let first = unsafe {
        GetTokenInformation(token.as_raw(), TokenAppContainerSid, None, 0, &mut needed)
    };
    if first.is_ok() {
        return Ok(None);
    }
    if let Err(err) = first {
        if win32_code_from_error(&err) != Some(ERROR_INSUFFICIENT_BUFFER.0) {
            return Err(map_windows_error_to_pkg_err(&err));
        }
    }
    if needed < std::mem::size_of::<TOKEN_APPCONTAINER_INFORMATION>() as u32 || needed > 65_536 {
        return Err(PackageAttrQueryError::InvalidData);
    }

    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` has `needed` bytes and `TOKEN_APPCONTAINER_INFORMATION` starts at offset 0.
    unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenAppContainerSid,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            needed,
            &mut needed,
        )
    }
    .map_err(|err| map_windows_error_to_pkg_err(&err))?;

    if (needed as usize) < std::mem::size_of::<TOKEN_APPCONTAINER_INFORMATION>()
        || (needed as usize) > buf.len()
    {
        return Err(PackageAttrQueryError::InvalidData);
    }
    // SAFETY: `buf` is at least `size_of::<TOKEN_APPCONTAINER_INFORMATION>()` bytes; `read_unaligned` avoids alignment UB.
    let info = unsafe { ptr::read_unaligned(buf.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()) };
    if info.TokenAppContainer.is_invalid() || info.TokenAppContainer.0.is_null() {
        return Ok(None);
    }
    let sid_str = sid_ptr_to_string(info.TokenAppContainer.0).map_err(|code| {
        if code == ERROR_ACCESS_DENIED.0 {
            PackageAttrQueryError::AccessDenied
        } else {
            PackageAttrQueryError::OsError(code)
        }
    })?;
    let trimmed = sid_str.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

/// Probes `package_family_name` and `package_sid` independently on an open process handle.
pub(crate) fn inspect_process_package_by_handle(proc_handle: HANDLE) -> ProcessPackageProbe {
    ProcessPackageProbe {
        package_family_name: query_process_package_family_name(proc_handle),
        package_sid: query_token_app_container_sid(proc_handle),
    }
}

/// Inspects `package_family_name` and `package_sid` for `pid` after verifying the live handle
/// belongs to the expected process incarnation (`expected_create_time_100ns` or `max_event_ts_100ns`).
pub(crate) fn inspect_process_package_by_pid(
    pid: u32,
    expected_create_time_100ns: u64,
    max_event_ts_100ns: Option<u64>,
) -> Option<ProcessPackageInfo> {
    if pid == 0 {
        return None;
    }
    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only metadata access.
    let raw_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let handle = OwnedHandle::new(raw_handle)?;
    // SAFETY: `handle` is open with `PROCESS_QUERY_LIMITED_INFORMATION`.
    let actual_pid = unsafe { GetProcessId(handle.as_raw()) };
    if actual_pid != pid {
        return None;
    }

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is open and all four `FILETIME` pointers are stack-allocated.
    let actual_create = if unsafe {
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

    let same_incarnation = if expected_create_time_100ns != 0 {
        actual_create == expected_create_time_100ns
    } else if let Some(max_ts) = max_event_ts_100ns.filter(|&ts| ts > 0) {
        actual_create > 0 && actual_create <= max_ts
    } else {
        false
    };
    if !same_incarnation {
        return None;
    }

    let info = inspect_process_package_by_handle(handle.as_raw()).into_info();
    (!info.is_empty()).then_some(info)
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
    pub(crate) package_family_name: Option<String>,
    pub(crate) package_sid: Option<String>,
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
    let package = inspect_process_package_by_handle(handle.as_raw()).into_info();

    Some(ProcessInspectInfo {
        parent_pid,
        create_time_100ns,
        exe_path,
        command_line,
        package_family_name: package.package_family_name,
        package_sid: package.package_sid,
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

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
    }

    #[test]
    fn sens_fu_p4_03_self_process_package_queries_return_ok_none_and_invalid_handle_errors() {
        // SAFETY: pseudo-handle returned by `GetCurrentProcess` is valid for current process.
        let current = unsafe { GetCurrentProcess() };
        assert_eq!(query_process_package_family_name(current), Ok(None));
        assert_eq!(query_token_app_container_sid(current), Ok(None));

        let invalid = HANDLE::default();
        assert_eq!(
            query_process_package_family_name(invalid),
            Err(PackageAttrQueryError::InvalidData)
        );
        assert_eq!(
            query_token_app_container_sid(invalid),
            Err(PackageAttrQueryError::InvalidData)
        );

        let bogus = HANDLE(0xDEAD_BEEFusize as *mut c_void);
        assert!(query_process_package_family_name(bogus).is_err());
        assert!(query_token_app_container_sid(bogus).is_err());
    }

    #[test]
    fn sens_fu_p4_03_sid_ptr_to_string_roundtrip_and_null_rejected() {
        assert!(sid_ptr_to_string(ptr::null()).is_err());

        let expected = "S-1-15-2-1-2-3-4-5-6-7";
        let wide: Vec<u16> = expected.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw_sid: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated UTF-16; `raw_sid` is freed by `OwnedLocalPtr`.
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) };
        assert_ne!(ok, 0);
        let _guard = OwnedLocalPtr(raw_sid);
        assert_eq!(sid_ptr_to_string(raw_sid), Ok(expected.to_string()));
    }
}
