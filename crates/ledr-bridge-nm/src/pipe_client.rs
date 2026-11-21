//! 1-request-1-connection Named Pipe IPC client with `SEC_0003` server validation and bounded timeouts.

use std::fmt;
#[cfg(not(windows))]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::bail;
use ledr_proto::{
    decode_ipc_frame, encode_ipc_frame, IpcRequest, IpcResponse, IPC_MAX_FRAME_BYTES, IPC_PIPE_NAME,
};

use crate::cli::RelayArgs;
use crate::extension_id::is_valid_extension_id;

/// Environment variable overriding the Named Pipe path for testing.
pub const IPC_PIPE_OVERRIDE_ENV: &str = "LEDR_IPC_PIPE";

/// Authorized install path for `ledr-daemon.exe` verified before sending IPC requests (`SEC_0003`, `L-09`).
pub const AUTHORIZED_DAEMON_EXE_PATH: &str = r"C:\Program Files\LocalEDR\ledr-daemon.exe";

/// Named Pipe client access mask (`FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES`),
/// intentionally omitting `FILE_CREATE_PIPE_INSTANCE` (`0x0004`) to match `SERVICE_PIPE_SDDL` (`SEC_0003`).
#[cfg(windows)]
pub const PIPE_CLIENT_ACCESS_MODE: u32 = 0x0012_019B;

/// Default per-request pipe write timeout.
pub const DEFAULT_PIPE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default per-request pipe read timeout.
pub const DEFAULT_PIPE_READ_TIMEOUT: Duration = Duration::from_secs(10);

const RELAY_CHUNK_BYTES: usize = 8 * 1024;
const ERROR_PIPE_BUSY_CODE: i32 = 231;
const PIPE_BUSY_MAX_RETRIES: usize = 16;
const PIPE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(15);

/// Errors emitted while connecting to, authenticating, or exchanging frames with `ledr-daemon`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeTransportError {
    DaemonOffline(String),
    ServerVerificationFailed(String),
    Timeout(String),
    Protocol(String),
    Io(String),
}

impl BridgeTransportError {
    /// Maps transport errors to `ledr_proto::IpcResponse::Error` codes returned to Chrome.
    pub fn ipc_error_code(&self) -> &'static str {
        match self {
            Self::DaemonOffline(_) => "DAEMON_OFFLINE",
            Self::ServerVerificationFailed(_)
            | Self::Timeout(_)
            | Self::Protocol(_)
            | Self::Io(_) => "BRIDGE_TRANSPORT_ERROR",
        }
    }
}

impl fmt::Display for BridgeTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DaemonOffline(msg) => write!(f, "ledr-daemon is offline: {msg}"),
            Self::ServerVerificationFailed(msg) => {
                write!(f, "pipe server verification failed: {msg}")
            }
            Self::Timeout(msg) => write!(f, "IPC pipe timeout: {msg}"),
            Self::Protocol(msg) => write!(f, "IPC protocol error: {msg}"),
            Self::Io(msg) => write!(f, "IPC I/O error: {msg}"),
        }
    }
}

impl std::error::Error for BridgeTransportError {}

/// Returns `true` if `pipe_name` points to LocalEDR's default production pipe.
pub fn is_default_ipc_pipe(pipe_name: &str) -> bool {
    let normalized = pipe_name
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    normalized == IPC_PIPE_NAME.to_ascii_lowercase()
        || normalized.ends_with(r"\pipe\localedr-ipc")
}

pub(crate) fn normalize_windows_exe_path(raw: &str) -> String {
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

pub(crate) fn is_authorized_pipe_server_exe_with(
    server_exe: &str,
    current_exe: Option<&Path>,
    installed_daemon_exists: bool,
    allow_sibling_in_debug: bool,
) -> bool {
    let norm_server = normalize_windows_exe_path(server_exe);
    if norm_server.is_empty() {
        return false;
    }

    if norm_server == normalize_windows_exe_path(AUTHORIZED_DAEMON_EXE_PATH) {
        return true;
    }

    if allow_sibling_in_debug || !installed_daemon_exists {
        if let Some(sibling_daemon) = current_exe
            .and_then(Path::parent)
            .map(|dir| dir.join("ledr-daemon.exe"))
        {
            if norm_server == normalize_windows_exe_path(&sibling_daemon.to_string_lossy()) {
                return true;
            }
        }
    }

    false
}

pub(crate) fn is_authorized_pipe_server_exe(
    server_exe: &str,
    current_exe: Option<&Path>,
) -> bool {
    is_authorized_pipe_server_exe_with(
        server_exe,
        current_exe,
        Path::new(AUTHORIZED_DAEMON_EXE_PATH).exists(),
        cfg!(debug_assertions),
    )
}

const AUTHORIZED_BROWSER_SUBPATHS: &[&str] = &[
    r"Google\Chrome\Application\chrome.exe",
    r"Google\Chrome Beta\Application\chrome.exe",
    r"Google\Chrome Dev\Application\chrome.exe",
    r"Google\Chrome SxS\Application\chrome.exe",
    r"Microsoft\Edge\Application\msedge.exe",
    r"Microsoft\Edge Beta\Application\msedge.exe",
    r"Microsoft\Edge Dev\Application\msedge.exe",
    r"Microsoft\Edge SxS\Application\msedge.exe",
    r"BraveSoftware\Brave-Browser\Application\brave.exe",
    r"BraveSoftware\Brave-Browser-Beta\Application\brave.exe",
    r"BraveSoftware\Brave-Browser-Nightly\Application\brave.exe",
];

fn clean_windows_path_no_traversal(raw: &Path) -> Option<String> {
    let raw_str = raw.to_string_lossy();
    let trimmed = raw_str.trim().replace('/', "\\");
    let stripped = if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
    {
        &trimmed[4..]
    } else {
        trimmed.as_str()
    };
    if stripped.len() < 3 {
        return None;
    }
    let bytes = stripped.as_bytes();
    if !(bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\') {
        return None;
    }
    let without_trailing = stripped.trim_end_matches('\\');
    if without_trailing.split('\\').any(|seg| seg.is_empty() || seg == "." || seg == "..") {
        return None;
    }
    Some(without_trailing.to_ascii_lowercase())
}

fn standard_browser_install_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(val) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            let pb = PathBuf::from(val);
            if !roots.iter().any(|existing| existing == &pb) {
                roots.push(pb);
            }
        }
    }
    roots
}

/// Validates a Chromium Native Messaging caller origin argument (`chrome-extension://<id>/`).
pub fn is_valid_caller_origin(origin: &str) -> bool {
    let Some(id_part) = origin
        .trim()
        .strip_prefix("chrome-extension://")
        .and_then(|rest| rest.strip_suffix('/'))
    else {
        return false;
    };
    is_valid_extension_id(id_part)
}

/// Checks whether `parent_exe` matches a canonical Chrome/Edge/Brave install path under `roots`,
/// rejecting path-traversal segments (`..`, `.`) and stripping extended `\\?\` prefixes (`SEC_0001`).
pub fn is_authorized_browser_parent_exe_with(parent_exe: &Path, roots: &[&Path]) -> bool {
    let Some(norm_parent) = clean_windows_path_no_traversal(parent_exe) else {
        return false;
    };
    for root in roots {
        let Some(norm_root) = clean_windows_path_no_traversal(root) else {
            continue;
        };
        for subpath in AUTHORIZED_BROWSER_SUBPATHS {
            let expected = format!("{norm_root}\\{}", subpath.to_ascii_lowercase());
            if norm_parent == expected {
                return true;
            }
        }
    }
    false
}

/// Checks whether `parent_exe` matches a canonical Chrome/Edge/Brave binary under standard
/// Windows install roots (`ProgramFiles`, `ProgramW6432`, `ProgramFiles(x86)`, `LOCALAPPDATA`).
pub fn is_authorized_browser_parent_exe(parent_exe: &Path) -> bool {
    let roots = standard_browser_install_roots();
    let root_refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    is_authorized_browser_parent_exe_with(parent_exe, &root_refs)
}

/// Verifies relay caller origin and browser parent process using an injected parent verifier
/// (production default pipe `\\.\pipe\localedr-ipc` only; custom `--pipe` overrides bypass parent check).
pub fn verify_browser_relay_caller_with<F>(
    args: &RelayArgs,
    check_parent: F,
) -> anyhow::Result<()>
where
    F: FnOnce() -> anyhow::Result<()>,
{
    if !is_default_ipc_pipe(&args.pipe_name) {
        return Ok(());
    }
    let origin = args.caller_origin.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "refusing direct relay launch on production IPC pipe '{}': missing chrome-extension://<id>/ caller origin",
            args.pipe_name
        )
    })?;
    if !is_valid_caller_origin(origin) {
        bail!("refusing relay launch: invalid caller origin '{origin}'");
    }
    check_parent()
}

/// Enforces `SEC_0001` caller origin + browser parent process authentication when relaying to the
/// default production pipe `\\.\pipe\localedr-ipc`.
pub fn verify_browser_relay_caller(args: &RelayArgs) -> anyhow::Result<()> {
    verify_browser_relay_caller_with(args, win_pipe_auth::verify_browser_parent_process)
}

#[cfg(windows)]
pub(crate) mod win_pipe_auth {
    use super::{
        is_authorized_browser_parent_exe, is_authorized_pipe_server_exe, AUTHORIZED_DAEMON_EXE_PATH,
    };
    use anyhow::bail;
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_NAME_WIN32: u32 = 0;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    const SYSTEM_PROCESS_ID_INFORMATION_CLASS: u32 = 88;
    const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    fn filetime_to_u64(ft: FileTime) -> u64 {
        (u64::from(ft.dw_high_date_time) << 32) | u64::from(ft.dw_low_date_time)
    }

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: usize,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: usize,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct SystemProcessIdInformation {
        process_id: *mut c_void,
        image_name: UnicodeString,
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetNamedPipeServerProcessId(pipe: *mut c_void, server_process_id: *mut u32) -> i32;
        fn OpenProcess(
            desired_access: u32,
            inherit_handle: i32,
            process_id: u32,
        ) -> *mut c_void;
        fn GetProcessTimes(
            process: *mut c_void,
            creation_time: *mut FileTime,
            exit_time: *mut FileTime,
            kernel_time: *mut FileTime,
            user_time: *mut FileTime,
        ) -> i32;
        fn QueryFullProcessImageNameW(
            process: *mut c_void,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn QueryDosDeviceW(
            device_name: *const u16,
            target_path: *mut u16,
            max_chars: u32,
        ) -> u32;
        fn CloseHandle(object: *mut c_void) -> i32;
    }

    #[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn NtQuerySystemInformation(
            system_information_class: u32,
            system_information: *mut c_void,
            system_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn NtQueryInformationProcess(
            process_handle: *mut c_void,
            process_information_class: u32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    struct OwnedWinHandle(*mut c_void);

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was returned by `OpenProcess` and is closed once on drop.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub(crate) fn nt_device_path_to_dos_with_map(
        nt_path: &str,
        drive_devices: &[(char, String)],
    ) -> Option<String> {
        let mut best: Option<(char, usize)> = None;
        for (drive, device) in drive_devices {
            if device.is_empty() {
                continue;
            }
            if let Some(prefix) = nt_path.get(..device.len()) {
                if prefix.eq_ignore_ascii_case(device) {
                    let remainder = &nt_path[device.len()..];
                    if (remainder.is_empty() || remainder.starts_with('\\'))
                        && best.is_none_or(|(_, best_len)| device.len() > best_len)
                    {
                        best = Some((*drive, device.len()));
                    }
                }
            }
        }
        best.map(|(drive, dev_len)| format!("{drive}:{}", &nt_path[dev_len..]))
    }

    fn query_drive_device_map() -> Vec<(char, String)> {
        let mut mappings = Vec::new();
        let mut buf = [0u16; 512];
        for letter in 'A'..='Z' {
            let dos_drive = [letter as u16, b':' as u16, 0];
            // SAFETY: `dos_drive` is NUL-terminated UTF-16 and `buf` holds 512 `u16` units.
            let copied =
                unsafe { QueryDosDeviceW(dos_drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
            if copied == 0 {
                continue;
            }
            let slice = &buf[..(copied as usize).min(buf.len())];
            let first_len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            if first_len > 0 {
                mappings.push((letter, String::from_utf16_lossy(&slice[..first_len])));
            }
        }
        mappings
    }

    pub(crate) fn query_process_image_path_nt_fallback(server_pid: u32) -> Result<String, String> {
        let mut cap_u16: usize = 1024;
        for _ in 0..2 {
            let mut buf = vec![0u16; cap_u16];
            let max_bytes = u16::try_from(buf.len() * std::mem::size_of::<u16>())
                .unwrap_or(0xFFFE_u16);
            let mut info = SystemProcessIdInformation {
                process_id: server_pid as usize as *mut c_void,
                image_name: UnicodeString {
                    length: 0,
                    maximum_length: max_bytes,
                    buffer: buf.as_mut_ptr(),
                },
            };
            let mut ret_len: u32 = 0;
            // SAFETY: `info` matches `SYSTEM_PROCESS_ID_INFORMATION` and `buf` outlives the syscall.
            let status = unsafe {
                NtQuerySystemInformation(
                    SYSTEM_PROCESS_ID_INFORMATION_CLASS,
                    &mut info as *mut SystemProcessIdInformation as *mut c_void,
                    std::mem::size_of::<SystemProcessIdInformation>() as u32,
                    &mut ret_len,
                )
            };
            if status == STATUS_INFO_LENGTH_MISMATCH {
                let needed_u16 = (usize::from(info.image_name.maximum_length) / 2).saturating_add(1);
                if needed_u16 > cap_u16 {
                    cap_u16 = needed_u16;
                    continue;
                }
            }
            if status != STATUS_SUCCESS {
                return Err(format!(
                    "NtQuerySystemInformation(SystemProcessIdInformation, {server_pid}) failed: NTSTATUS 0x{:08X}",
                    status as u32
                ));
            }
            let used_u16 = (usize::from(info.image_name.length) / 2).min(buf.len());
            let nt_path = String::from_utf16_lossy(&buf[..used_u16]);
            if nt_path.is_empty() {
                return Err(format!(
                    "NtQuerySystemInformation returned empty image path for PID {server_pid}"
                ));
            }
            if !nt_path.starts_with('\\') || nt_path.starts_with(r"\\") {
                return Ok(nt_path);
            }
            let drive_map = query_drive_device_map();
            return nt_device_path_to_dos_with_map(&nt_path, &drive_map).ok_or_else(|| {
                format!(
                    "failed to map NT image path '{nt_path}' for PID {server_pid} to a DOS drive"
                )
            });
        }
        Err(format!(
            "NtQuerySystemInformation buffer resize exhausted for PID {server_pid}"
        ))
    }

    fn query_process_image_path_from_handle(handle: *mut c_void, pid: u32) -> Result<String, String> {
        let mut cap = 1024usize;
        loop {
            let mut buf = vec![0u16; cap];
            let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `handle` is valid and `buf` holds `cap` writable UTF-16 code units.
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    handle,
                    PROCESS_NAME_WIN32,
                    buf.as_mut_ptr(),
                    &mut len,
                )
            };
            if ok != 0 {
                let exe_len = usize::try_from(len).unwrap_or(0).min(buf.len());
                return Ok(String::from_utf16_lossy(&buf[..exe_len]));
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER) && cap < 32_768 {
                cap *= 2;
                continue;
            }
            return Err(format!("QueryFullProcessImageNameW({pid}) failed: {err}"));
        }
    }

    fn query_process_image_path(server_pid: u32) -> Result<String, String> {
        // SAFETY: Win32 FFI call with plain PID scalar.
        let raw_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
        if raw_proc.is_null() {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                return query_process_image_path_nt_fallback(server_pid);
            }
            return Err(format!("OpenProcess({server_pid}) failed: {err}"));
        }
        let proc_handle = OwnedWinHandle(raw_proc);
        query_process_image_path_from_handle(proc_handle.0, server_pid)
    }

    pub(crate) fn verify_browser_parent_process() -> anyhow::Result<()> {
        // SAFETY: `GetCurrentProcess` always returns the current process pseudo-handle.
        let self_handle = unsafe { GetCurrentProcess() };
        let mut self_create = FileTime::default();
        let mut exit_ft = FileTime::default();
        let mut kernel_ft = FileTime::default();
        let mut user_ft = FileTime::default();
        // SAFETY: All `FILETIME` pointers point to writable stack locals.
        let ok_self_times = unsafe {
            GetProcessTimes(
                self_handle,
                &mut self_create,
                &mut exit_ft,
                &mut kernel_ft,
                &mut user_ft,
            )
        };
        if ok_self_times == 0 {
            bail!(
                "GetProcessTimes(current process) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut pbi: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let mut return_len: u32 = 0;
        // SAFETY: `pbi` is properly sized and aligned for `ProcessBasicInformation` (class 0).
        let status = unsafe {
            NtQueryInformationProcess(
                self_handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                (&mut pbi as *mut ProcessBasicInformation).cast::<c_void>(),
                u32::try_from(std::mem::size_of::<ProcessBasicInformation>()).unwrap_or(u32::MAX),
                &mut return_len,
            )
        };
        if status < 0 {
            bail!(
                "NtQueryInformationProcess(ProcessBasicInformation) failed: NTSTATUS 0x{status:08X}"
            );
        }

        let parent_pid = u32::try_from(pbi.inherited_from_unique_process_id)
            .ok()
            .filter(|&pid| pid != 0)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "refusing default IPC relay: invalid inherited parent PID {}",
                    pbi.inherited_from_unique_process_id
                )
            })?;

        // SAFETY: Plain Win32 PID lookup with minimal read access.
        let raw_parent = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid) };
        if raw_parent.is_null() {
            bail!(
                "refusing default IPC relay: cannot inspect parent process PID {parent_pid}: {}",
                std::io::Error::last_os_error()
            );
        }
        let parent_handle = OwnedWinHandle(raw_parent);

        let mut parent_create = FileTime::default();
        // SAFETY: `parent_handle.0` is valid and `FileTime` pointers are stack locals.
        let ok_parent_times = unsafe {
            GetProcessTimes(
                parent_handle.0,
                &mut parent_create,
                &mut exit_ft,
                &mut kernel_ft,
                &mut user_ft,
            )
        };
        if ok_parent_times == 0 {
            bail!(
                "refusing default IPC relay: GetProcessTimes(parent PID {parent_pid}) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        if filetime_to_u64(parent_create) > filetime_to_u64(self_create) {
            bail!(
                "refusing default IPC relay: parent PID {parent_pid} was created after bridge process (PID reuse)"
            );
        }

        let parent_exe =
            query_process_image_path_from_handle(parent_handle.0, parent_pid).map_err(|e| {
                anyhow::anyhow!("refusing default IPC relay: {e}")
            })?;
        if !is_authorized_browser_parent_exe(Path::new(&parent_exe)) {
            bail!(
                "refusing default IPC relay from untrusted parent process PID {parent_pid} ('{parent_exe}')"
            );
        }
        Ok(())
    }

    pub(crate) fn verify_named_pipe_server_process(
        pipe: &File,
        current_exe: Option<&Path>,
    ) -> Result<(), String> {
        let mut server_pid: u32 = 0;
        // SAFETY: `pipe.as_raw_handle()` is an open Named Pipe handle for this call.
        let ok = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut server_pid) };
        if ok == 0 {
            return Err(format!(
                "GetNamedPipeServerProcessId failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if server_pid == 0 {
            return Err("GetNamedPipeServerProcessId returned PID 0".to_string());
        }

        let server_exe = query_process_image_path(server_pid)?;
        if is_authorized_pipe_server_exe(&server_exe, current_exe) {
            return Ok(());
        }

        Err(format!(
            "refusing IPC connection to untrusted pipe server PID {server_pid} ('{server_exe}'): expected '{AUTHORIZED_DAEMON_EXE_PATH}' or sibling ledr-daemon.exe"
        ))
    }
}

#[cfg(not(windows))]
pub(crate) mod win_pipe_auth {
    pub(crate) fn verify_browser_parent_process() -> anyhow::Result<()> {
        anyhow::bail!("Browser parent process verification is only supported on Windows")
    }
}

#[cfg(windows)]
mod win_pipe_io {
    use super::BridgeTransportError;
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use std::time::Instant;

    const ERROR_HANDLE_EOF: i32 = 38;
    const ERROR_BROKEN_PIPE: i32 = 109;
    const ERROR_NO_DATA: i32 = 232;
    const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
    const ERROR_IO_PENDING: i32 = 997;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        h_event: *mut c_void,
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn CreateEventW(
            event_attributes: *const c_void,
            manual_reset: i32,
            initial_state: i32,
            name: *const u16,
        ) -> *mut c_void;
        fn ResetEvent(h_event: *mut c_void) -> i32;
        fn ReadFile(
            h_file: *mut c_void,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn WriteFile(
            h_file: *mut c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: u32) -> u32;
        fn GetOverlappedResult(
            h_file: *mut c_void,
            lp_overlapped: *mut Overlapped,
            lp_number_of_bytes_transferred: *mut u32,
            b_wait: i32,
        ) -> i32;
        fn CancelIoEx(h_file: *mut c_void, lp_overlapped: *const Overlapped) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
    }

    struct OwnedEvent(*mut c_void);

    impl Drop for OwnedEvent {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was created by `CreateEventW` and is closed once on drop.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub(crate) struct TimedPipeHandle {
        pipe: File,
        event: OwnedEvent,
    }

    impl TimedPipeHandle {
        pub(crate) fn new(pipe: File) -> Result<Self, BridgeTransportError> {
            // SAFETY: Creates an unnamed manual-reset Win32 event initially nonsignaled.
            let raw_event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
            if raw_event.is_null() {
                return Err(BridgeTransportError::Io(format!(
                    "CreateEventW failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self {
                pipe,
                event: OwnedEvent(raw_event),
            })
        }

        pub(crate) fn write_all_deadline(
            &self,
            mut data: &[u8],
            deadline: Instant,
        ) -> Result<(), BridgeTransportError> {
            let handle = self.pipe.as_raw_handle();
            while !data.is_empty() {
                let remaining = remaining_timeout_ms(deadline, "writing IPC request")?;
                // SAFETY: `self.event.0` is an open manual-reset event handle.
                unsafe {
                    let _ = ResetEvent(self.event.0);
                }
                let chunk_len = u32::try_from(data.len()).unwrap_or(u32::MAX);
                let mut ov = Overlapped {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    offset_high: 0,
                    h_event: self.event.0,
                };
                // SAFETY: `handle` is open with `FILE_FLAG_OVERLAPPED`, `data` and `ov` remain pinned
                // until `GetOverlappedResult` completes (or after `CancelIoEx` + draining wait).
                let ok = unsafe {
                    WriteFile(
                        handle,
                        data.as_ptr(),
                        chunk_len,
                        ptr::null_mut(),
                        &mut ov as *mut Overlapped as *mut c_void,
                    )
                };
                let transferred = wait_or_cancel(
                    handle,
                    &mut ov,
                    self.event.0,
                    ok,
                    remaining,
                    "writing IPC request",
                )?;
                if transferred == 0 {
                    return Err(BridgeTransportError::Io(
                        "WriteFile transferred 0 bytes on Named Pipe".to_string(),
                    ));
                }
                data = &data[transferred..];
            }
            Ok(())
        }

        pub(crate) fn read_exact_deadline(
            &self,
            mut buf: &mut [u8],
            deadline: Instant,
        ) -> Result<(), BridgeTransportError> {
            let handle = self.pipe.as_raw_handle();
            while !buf.is_empty() {
                let remaining = remaining_timeout_ms(deadline, "reading IPC response")?;
                // SAFETY: `self.event.0` is an open manual-reset event handle.
                unsafe {
                    let _ = ResetEvent(self.event.0);
                }
                let chunk_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
                let mut ov = Overlapped {
                    internal: 0,
                    internal_high: 0,
                    offset: 0,
                    offset_high: 0,
                    h_event: self.event.0,
                };
                // SAFETY: `handle` is open with `FILE_FLAG_OVERLAPPED`, `buf` and `ov` remain pinned
                // until `GetOverlappedResult` completes (or after `CancelIoEx` + draining wait).
                let ok = unsafe {
                    ReadFile(
                        handle,
                        buf.as_mut_ptr(),
                        chunk_len,
                        ptr::null_mut(),
                        &mut ov as *mut Overlapped as *mut c_void,
                    )
                };
                let transferred = wait_or_cancel(
                    handle,
                    &mut ov,
                    self.event.0,
                    ok,
                    remaining,
                    "reading IPC response",
                )?;
                if transferred == 0 {
                    return Err(BridgeTransportError::Io(
                        "unexpected EOF while reading from Named Pipe".to_string(),
                    ));
                }
                buf = &mut buf[transferred..];
            }
            Ok(())
        }
    }

    fn remaining_timeout_ms(deadline: Instant, phase: &str) -> Result<u32, BridgeTransportError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(BridgeTransportError::Timeout(format!(
                "timed out while {phase}"
            )));
        }
        let dur = deadline.saturating_duration_since(now);
        let ms = dur.as_millis().clamp(1, u128::from(u32::MAX - 1));
        Ok(ms as u32)
    }

    fn is_pipe_eof_os_code(code: Option<i32>) -> bool {
        matches!(
            code,
            Some(ERROR_HANDLE_EOF | ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
        )
    }

    fn wait_or_cancel(
        handle: *mut c_void,
        ov: &mut Overlapped,
        event: *mut c_void,
        immediate_ok: i32,
        timeout_ms: u32,
        phase: &str,
    ) -> Result<usize, BridgeTransportError> {
        if immediate_ok == 0 {
            let err = std::io::Error::last_os_error();
            let raw = err.raw_os_error();
            if raw != Some(ERROR_IO_PENDING) {
                if is_pipe_eof_os_code(raw) {
                    return Err(BridgeTransportError::Io(format!(
                        "pipe disconnected while {phase}: {err}"
                    )));
                }
                return Err(BridgeTransportError::Io(format!(
                    "pipe operation failed while {phase}: {err}"
                )));
            }

            // SAFETY: `event` is a valid manual-reset event bound to `ov`.
            let wait_res = unsafe { WaitForSingleObject(event, timeout_ms) };
            match wait_res {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => {
                    // Cancel pending I/O and block in `GetOverlappedResult(..., TRUE)` so the kernel
                    // stops touching `ov` and the caller's slice before stack unwind.
                    // SAFETY: `handle` and `ov` remain valid until `GetOverlappedResult` returns.
                    unsafe {
                        let _ = CancelIoEx(handle, ov);
                        let mut dummy: u32 = 0;
                        let _ = GetOverlappedResult(handle, ov, &mut dummy, 1);
                    }
                    return Err(BridgeTransportError::Timeout(format!(
                        "timed out after waiting while {phase}"
                    )));
                }
                other => {
                    let wait_err = std::io::Error::last_os_error();
                    // SAFETY: Same cancellation + drain safety invariant as `WAIT_TIMEOUT`.
                    unsafe {
                        let _ = CancelIoEx(handle, ov);
                        let mut dummy: u32 = 0;
                        let _ = GetOverlappedResult(handle, ov, &mut dummy, 1);
                    }
                    return Err(BridgeTransportError::Io(format!(
                        "WaitForSingleObject returned {other} while {phase}: {wait_err}"
                    )));
                }
            }
        }

        let mut transferred: u32 = 0;
        // SAFETY: `handle` and `ov` are valid; `bWait = 1` finishes any inline completion.
        let res_ok = unsafe { GetOverlappedResult(handle, ov, &mut transferred, 1) };
        if res_ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(BridgeTransportError::Io(format!(
                "GetOverlappedResult failed while {phase}: {err}"
            )));
        }
        Ok(transferred as usize)
    }
}

/// 1-request-1-connection Named Pipe IPC client used by `ledr-bridge-nm`.
#[derive(Debug, Clone)]
pub struct PipeClient {
    pipe_name: String,
    verify_server: bool,
    write_timeout: Duration,
    read_timeout: Duration,
}

impl PipeClient {
    /// Creates a `PipeClient` targeting `pipe_name`, automatically enabling `SEC_0003` server
    /// process verification when `pipe_name` refers to `\\.\pipe\localedr-ipc`.
    pub fn new(pipe_name: impl Into<String>) -> Self {
        let pipe_name = pipe_name.into();
        let verify_server = is_default_ipc_pipe(&pipe_name);
        Self {
            pipe_name,
            verify_server,
            write_timeout: DEFAULT_PIPE_WRITE_TIMEOUT,
            read_timeout: DEFAULT_PIPE_READ_TIMEOUT,
        }
    }

    /// Overrides the per-request write and read timeouts.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_timeouts(mut self, write_timeout: Duration, read_timeout: Duration) -> Self {
        self.write_timeout = write_timeout;
        self.read_timeout = read_timeout;
        self
    }

    /// Overrides whether `SEC_0003` `GetNamedPipeServerProcessId` verification is enforced.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_verify_server(mut self, verify_server: bool) -> Self {
        self.verify_server = verify_server;
        self
    }

    /// Connects to the Named Pipe for a single raw frame exchange and immediately drops the handle.
    #[cfg(windows)]
    pub fn exchange_raw_frame(&self, raw_payload: &[u8]) -> Result<Vec<u8>, BridgeTransportError> {
        use std::os::windows::fs::OpenOptionsExt;

        const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;

        if raw_payload.is_empty() {
            return Err(BridgeTransportError::Protocol(
                "cannot transmit empty IPC request frame".to_string(),
            ));
        }
        if raw_payload.len() > IPC_MAX_FRAME_BYTES {
            return Err(BridgeTransportError::Protocol(format!(
                "request payload {} bytes exceeds IPC limit {} bytes",
                raw_payload.len(),
                IPC_MAX_FRAME_BYTES
            )));
        }

        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .access_mode(PIPE_CLIENT_ACCESS_MODE)
            .custom_flags(FILE_FLAG_OVERLAPPED);

        let mut attempt = 0usize;
        let mut saw_pipe_busy = false;
        let pipe = loop {
            match opts.open(&self.pipe_name) {
                Ok(file) => break file,
                Err(err)
                    if err.raw_os_error() == Some(ERROR_PIPE_BUSY_CODE)
                        && attempt < PIPE_BUSY_MAX_RETRIES =>
                {
                    saw_pipe_busy = true;
                    attempt += 1;
                    thread::sleep(PIPE_BUSY_RETRY_DELAY);
                }
                Err(err) if err.raw_os_error() == Some(ERROR_PIPE_BUSY_CODE) => {
                    return Err(BridgeTransportError::Timeout(format!(
                        "pipe '{}' stayed busy after {} retries",
                        self.pipe_name, PIPE_BUSY_MAX_RETRIES
                    )));
                }
                Err(err)
                    if err.kind() == ErrorKind::NotFound
                        && saw_pipe_busy
                        && attempt < PIPE_BUSY_MAX_RETRIES =>
                {
                    attempt += 1;
                    thread::sleep(PIPE_BUSY_RETRY_DELAY);
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    return Err(BridgeTransportError::DaemonOffline(format!(
                        "pipe '{}' not found ({err})",
                        self.pipe_name
                    )));
                }
                Err(err) => {
                    return Err(BridgeTransportError::Io(format!(
                        "failed to open pipe '{}': {err}",
                        self.pipe_name
                    )));
                }
            }
        };

        if self.verify_server {
            let current_exe = std::env::current_exe().ok();
            win_pipe_auth::verify_named_pipe_server_process(&pipe, current_exe.as_deref())
                .map_err(BridgeTransportError::ServerVerificationFailed)?;
        }

        let timed = win_pipe_io::TimedPipeHandle::new(pipe)?;

        let write_deadline = Instant::now() + self.write_timeout;
        let req_len = u32::try_from(raw_payload.len()).map_err(|_| {
            BridgeTransportError::Protocol("request payload length overflow".to_string())
        })?;
        timed.write_all_deadline(&req_len.to_le_bytes(), write_deadline)?;
        for chunk in raw_payload.chunks(RELAY_CHUNK_BYTES) {
            timed.write_all_deadline(chunk, write_deadline)?;
        }

        let read_deadline = Instant::now() + self.read_timeout;
        let mut resp_len_buf = [0u8; 4];
        timed.read_exact_deadline(&mut resp_len_buf, read_deadline)?;
        let resp_len = u32::from_le_bytes(resp_len_buf) as usize;
        if resp_len == 0 {
            return Err(BridgeTransportError::Protocol(
                "daemon returned empty 0-byte IPC frame".to_string(),
            ));
        }
        if resp_len > IPC_MAX_FRAME_BYTES {
            return Err(BridgeTransportError::Protocol(format!(
                "daemon response length {resp_len} exceeds IPC max {IPC_MAX_FRAME_BYTES} bytes"
            )));
        }

        let mut resp = Vec::with_capacity(resp_len.min(RELAY_CHUNK_BYTES));
        let mut chunk = [0u8; RELAY_CHUNK_BYTES];
        while resp.len() < resp_len {
            let to_read = (resp_len - resp.len()).min(chunk.len());
            timed.read_exact_deadline(&mut chunk[..to_read], read_deadline)?;
            resp.extend_from_slice(&chunk[..to_read]);
        }

        // `timed` (and underlying `File`) drops on return, closing the Named Pipe instance immediately.
        Ok(resp)
    }

    #[cfg(not(windows))]
    pub fn exchange_raw_frame(&self, _raw_payload: &[u8]) -> Result<Vec<u8>, BridgeTransportError> {
        let _ = (&self.verify_server, self.write_timeout, self.read_timeout);
        let _ = (RELAY_CHUNK_BYTES, ERROR_PIPE_BUSY_CODE, PIPE_BUSY_MAX_RETRIES, PIPE_BUSY_RETRY_DELAY);
        let _ = (OpenOptions::new, File::open, ErrorKind::NotFound, thread::sleep);
        Err(BridgeTransportError::DaemonOffline(
            "Windows Named Pipe IPC is only supported on Windows".to_string(),
        ))
    }

    /// Sends `IpcRequest::Ping` and returns `(daemon_version, protocol_version)`.
    pub fn ping(&self) -> Result<(String, u32), BridgeTransportError> {
        let encoded = encode_ipc_frame(&IpcRequest::Ping)
            .map_err(|err| BridgeTransportError::Protocol(err.to_string()))?;
        let resp_payload = self.exchange_raw_frame(&encoded[4..])?;

        let mut framed = Vec::with_capacity(4 + resp_payload.len());
        framed.extend_from_slice(&(resp_payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&resp_payload);

        let resp: IpcResponse = decode_ipc_frame(&framed)
            .map_err(|err| BridgeTransportError::Protocol(err.to_string()))?;
        match resp {
            IpcResponse::Pong {
                daemon_version,
                protocol_version,
            } => Ok((daemon_version, protocol_version)),
            IpcResponse::Error { code, message } => Err(BridgeTransportError::Protocol(format!(
                "daemon returned error [{code}]: {message}"
            ))),
            other => Err(BridgeTransportError::Protocol(format!(
                "unexpected IPC response to Ping: {other:?}"
            ))),
        }
    }
}
