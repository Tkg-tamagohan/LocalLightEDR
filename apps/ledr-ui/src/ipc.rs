//! Named Pipe IPC client communicating with `ledr-daemon` over `\\.\pipe\localedr-ipc`.

use ledr_proto::{
    AlertDecision, AlertRecord, AlertStatus, AllowPermanentPathMode, AllowlistRuleRecord,
    FlightRecorderSnapshot, IPC_PIPE_NAME, IpcRequest, IpcResponse, PipelineMetrics, RuleScope,
    read_ipc_frame, write_ipc_frame,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
use std::thread;
use std::time::Duration;

/// Optional environment variable overriding the Named Pipe path for testing.
pub const IPC_PIPE_OVERRIDE_ENV: &str = "LEDR_IPC_PIPE";

/// Authorized install path for `ledr-daemon.exe` verified before sending IPC requests (`SEC_0003`, `L-09`).
pub const AUTHORIZED_DAEMON_EXE_PATH: &str = r"C:\Program Files\LocalEDR\ledr-daemon.exe";

/// Named Pipe client access mask (`FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES`),
/// intentionally omitting `FILE_CREATE_PIPE_INSTANCE` (`0x0004`) to match `SERVICE_PIPE_SDDL` (`SEC_0003`).
#[cfg(windows)]
const PIPE_CLIENT_ACCESS_MODE: u32 = 0x0012_019B;

const ERROR_PIPE_BUSY_CODE: i32 = 231;
const PIPE_BUSY_MAX_RETRIES: usize = 12;
const PIPE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(15);

/// Resolves the Named Pipe endpoint from `LEDR_IPC_PIPE` or [`IPC_PIPE_NAME`].
pub fn resolve_ipc_pipe_name() -> String {
    std::env::var(IPC_PIPE_OVERRIDE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| IPC_PIPE_NAME.to_string())
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_default_ipc_pipe(pipe_name: &str) -> bool {
    let normalized = pipe_name
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    normalized == IPC_PIPE_NAME.to_ascii_lowercase()
        || normalized.ends_with(r"\pipe\localedr-ipc")
}

#[cfg_attr(not(windows), allow(dead_code))]
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

#[cfg_attr(not(windows), allow(dead_code))]
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

#[cfg_attr(not(windows), allow(dead_code))]
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

#[cfg(windows)]
mod win_pipe_auth {
    use super::{AUTHORIZED_DAEMON_EXE_PATH, is_authorized_pipe_server_exe};
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_NAME_WIN32: u32 = 0;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    const SYSTEM_PROCESS_ID_INFORMATION_CLASS: u32 = 88;
    const STATUS_SUCCESS: i32 = 0;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

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
        fn GetNamedPipeServerProcessId(pipe: *mut c_void, server_process_id: *mut u32) -> i32;
        fn OpenProcess(
            desired_access: u32,
            inherit_handle: i32,
            process_id: u32,
        ) -> *mut c_void;
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
            let copied = unsafe { QueryDosDeviceW(dos_drive.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
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
            // SAFETY: `info` is `#[repr(C)]` matching `SYSTEM_PROCESS_ID_INFORMATION` and `buf` stays valid across the syscall.
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
                format!("failed to map NT image path '{nt_path}' for PID {server_pid} to a DOS drive")
            });
        }
        Err(format!(
            "NtQuerySystemInformation buffer resize exhausted for PID {server_pid}"
        ))
    }

    fn query_process_image_path(server_pid: u32) -> Result<String, String> {
        // SAFETY: Win32 FFI call with plain PID scalar.
        let raw_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
        if raw_proc.is_null() {
            let err = std::io::Error::last_os_error();
            // Medium-integrity `ledr-ui.exe` cannot open `LocalSystem` `ledr-daemon.exe` with
            // `PROCESS_QUERY_LIMITED_INFORMATION`; fall back to kernel image-path query and still
            // enforce the exact path allowlist below.
            if err.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
                return query_process_image_path_nt_fallback(server_pid);
            }
            return Err(format!("OpenProcess({server_pid}) failed: {err}"));
        }
        let proc_handle = OwnedWinHandle(raw_proc);

        let mut cap = 1024usize;
        loop {
            let mut buf = vec![0u16; cap];
            let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
            // SAFETY: `proc_handle.0` is an open process handle and `buf` is writable UTF-16 storage.
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    proc_handle.0,
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
            return Err(format!("QueryFullProcessImageNameW({server_pid}) failed: {err}"));
        }
    }

    pub(crate) fn verify_named_pipe_server_process_with_options(
        pipe: &File,
        allow_same_pid: bool,
        current_exe: Option<&Path>,
    ) -> Result<(), String> {
        let mut server_pid: u32 = 0;
        // SAFETY: `pipe.as_raw_handle()` is an open Named Pipe client handle for this call duration.
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

        if allow_same_pid && server_pid == std::process::id() {
            return Ok(());
        }

        let server_exe = query_process_image_path(server_pid)?;
        if is_authorized_pipe_server_exe(&server_exe, current_exe) {
            return Ok(());
        }

        Err(format!(
            "refusing IPC connection to untrusted pipe server process PID {server_pid} ('{server_exe}'): expected '{AUTHORIZED_DAEMON_EXE_PATH}' or sibling ledr-daemon.exe"
        ))
    }
}

/// Verifies on Windows that the connected Named Pipe server process is an authorized
/// `ledr-daemon.exe` binary (`C:\Program Files\LocalEDR\ledr-daemon.exe`, sibling
/// `ledr-daemon.exe` next to `current_exe()`, or same-PID self-test harness under `#[cfg(test)]`) (`SEC_0003`).
#[cfg(windows)]
pub(crate) fn verify_named_pipe_server_process(pipe: &File) -> Result<(), String> {
    let current_exe = std::env::current_exe().ok();
    win_pipe_auth::verify_named_pipe_server_process_with_options(
        pipe,
        cfg!(test),
        current_exe.as_deref(),
    )
}

/// Structured daemon handshake version metadata returned by `IpcRequest::Ping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct DaemonPingInfo {
    pub daemon_version: String,
    pub protocol_version: u32,
}

/// Domain risk lookup result returned by `IpcRequest::CheckDomainRisk` (`L-13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRiskView {
    pub domain: String,
    pub is_nrd: bool,
    pub is_homograph: bool,
    pub matched_brand: Option<String>,
}

/// Client for exchanging 4-byte little-endian length-prefixed JSON frames with `ledr-daemon`.
#[derive(Debug, Clone)]
pub struct IpcClient {
    pipe_name: String,
}

impl IpcClient {
    /// Creates an IPC client targeting `pipe_name`.
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    /// Creates an IPC client targeting `LEDR_IPC_PIPE` if set, otherwise [`IPC_PIPE_NAME`].
    pub fn default_endpoint() -> Self {
        Self::new(resolve_ipc_pipe_name())
    }

    /// Returns the configured Named Pipe endpoint path.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Sends one [`IpcRequest`] over any bidirectional byte stream and reads one [`IpcResponse`].
    pub fn send_request_over_stream<S: Read + Write>(
        stream: &mut S,
        request: &IpcRequest,
    ) -> Result<IpcResponse, String> {
        write_ipc_frame(stream, request).map_err(|err| format!("IPC frame write error: {err}"))?;
        read_ipc_frame::<S, IpcResponse>(stream)
            .map_err(|err| format!("IPC frame read error: {err}"))
    }

    /// Opens the configured Named Pipe and performs a single request/response round-trip.
    pub fn send_request(&self, request: &IpcRequest) -> Result<IpcResponse, String> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.access_mode(PIPE_CLIENT_ACCESS_MODE);
        }

        let mut attempt = 0;
        let mut saw_pipe_busy = false;
        let mut pipe = loop {
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
                Err(err)
                    if err.kind() == ErrorKind::NotFound
                        && saw_pipe_busy
                        && attempt < PIPE_BUSY_MAX_RETRIES =>
                {
                    attempt += 1;
                    thread::sleep(PIPE_BUSY_RETRY_DELAY);
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    return Err(format!(
                        "ledr-daemon is offline (IPC pipe '{}' not found: {err})",
                        self.pipe_name
                    ));
                }
                Err(err) => {
                    return Err(format!(
                        "failed to connect to IPC pipe '{}': {err}",
                        self.pipe_name
                    ));
                }
            }
        };

        #[cfg(windows)]
        if is_default_ipc_pipe(&self.pipe_name) {
            verify_named_pipe_server_process(&pipe)?;
        }

        Self::send_request_over_stream(&mut pipe, request)
    }

    /// Sends `IpcRequest::Ping` and returns a formatted daemon handshake summary.
    pub fn ping(&self) -> Result<String, String> {
        parse_ping_response(self.send_request(&IpcRequest::Ping)?)
    }

    /// Sends `IpcRequest::Ping` and returns structured daemon version metadata.
    #[allow(dead_code)]
    pub fn ping_info(&self) -> Result<DaemonPingInfo, String> {
        parse_ping_info_response(self.send_request(&IpcRequest::Ping)?)
    }

    /// Fetches a [`FlightRecorderSnapshot`] from `ledr-daemon`.
    pub fn get_flight_recorder(
        &self,
        limit: usize,
        process_instance_id: Option<String>,
    ) -> Result<FlightRecorderSnapshot, String> {
        let req = IpcRequest::GetFlightRecorder {
            limit,
            process_instance_id,
        };
        parse_flight_recorder_response(self.send_request(&req)?)
    }

    /// Fetches [`PipelineMetrics`] from `ledr-daemon`.
    pub fn get_pipeline_metrics(&self) -> Result<PipelineMetrics, String> {
        parse_metrics_response(self.send_request(&IpcRequest::GetPipelineMetrics)?)
    }

    /// Fetches persisted alerts from `ledr-daemon`, optionally filtered by [`AlertStatus`].
    pub fn get_alerts(
        &self,
        status: Option<AlertStatus>,
        limit: usize,
    ) -> Result<Vec<AlertRecord>, String> {
        let req = IpcRequest::GetAlerts { status, limit };
        parse_alerts_response(self.send_request(&req)?)
    }

    /// Resolves an alert with the given [`AlertDecision`] (`L-07`).
    pub fn resolve_alert(
        &self,
        alert_id: String,
        decision: AlertDecision,
    ) -> Result<String, String> {
        let req = IpcRequest::ResolveAlert { alert_id, decision };
        parse_ack_response(self.send_request(&req)?)
    }

    pub(crate) fn build_resolve_alert_request(
        alert_id: String,
        decision: AlertDecision,
        path_mode: AllowPermanentPathMode,
    ) -> IpcRequest {
        match path_mode {
            AllowPermanentPathMode::Exact => IpcRequest::ResolveAlert { alert_id, decision },
            AllowPermanentPathMode::WindowsAppsVersionWildcard => {
                IpcRequest::ResolveAlertWithOptions {
                    alert_id,
                    decision,
                    path_mode,
                }
            }
        }
    }

    /// Resolves an alert with the given [`AlertDecision`] and [`AllowPermanentPathMode`] (`L-07`).
    ///
    /// Uses legacy [`IpcRequest::ResolveAlert`] via [`Self::resolve_alert`] when
    /// `path_mode == AllowPermanentPathMode::Exact` and [`IpcRequest::ResolveAlertWithOptions`]
    /// only for [`AllowPermanentPathMode::WindowsAppsVersionWildcard`].
    pub fn resolve_alert_with_options(
        &self,
        alert_id: String,
        decision: AlertDecision,
        path_mode: AllowPermanentPathMode,
    ) -> Result<String, String> {
        match path_mode {
            AllowPermanentPathMode::Exact => self.resolve_alert(alert_id, decision),
            AllowPermanentPathMode::WindowsAppsVersionWildcard => {
                let req = Self::build_resolve_alert_request(alert_id, decision, path_mode);
                parse_ack_response(self.send_request(&req)?)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn resolve_alert_with_options_over_stream<S: Read + Write>(
        stream: &mut S,
        alert_id: String,
        decision: AlertDecision,
        path_mode: AllowPermanentPathMode,
    ) -> Result<String, String> {
        let req = Self::build_resolve_alert_request(alert_id, decision, path_mode);
        parse_ack_response(Self::send_request_over_stream(stream, &req)?)
    }

    /// Lists allowlist/blocklist policy rules from `ledr-daemon`, optionally filtered by [`RuleScope`].
    pub fn list_rules(
        &self,
        scope: Option<RuleScope>,
    ) -> Result<Vec<AllowlistRuleRecord>, String> {
        let req = IpcRequest::ListRules { scope };
        parse_rules_response(self.send_request(&req)?)
    }

    /// Creates or updates a policy rule via `ledr-daemon` and reconciles live WFP filters.
    pub fn upsert_rule(&self, rule: AllowlistRuleRecord) -> Result<String, String> {
        let req = IpcRequest::UpsertRule { rule };
        parse_ack_response(self.send_request(&req)?)
    }

    /// Deletes a persisted policy rule by `rule_id` and reconciles live WFP filters.
    pub fn delete_rule(&self, rule_id: String) -> Result<String, String> {
        let req = IpcRequest::DeleteRule { rule_id };
        parse_ack_response(self.send_request(&req)?)
    }

    /// Queries the live NRD + homograph domain risk engine in `ledr-daemon` (`L-13`).
    pub fn check_domain_risk(&self, domain: String) -> Result<DomainRiskView, String> {
        let req = IpcRequest::CheckDomainRisk { domain };
        parse_domain_risk_response(self.send_request(&req)?)
    }
}

pub(crate) fn parse_ping_response(response: IpcResponse) -> Result<String, String> {
    match response {
        IpcResponse::Pong {
            daemon_version,
            protocol_version,
        } => Ok(format!(
            "ledr-daemon v{daemon_version} (proto v{protocol_version})"
        )),
        other => Err(unexpected_or_daemon_error(other, "Pong")),
    }
}

#[allow(dead_code)]
pub(crate) fn parse_ping_info_response(response: IpcResponse) -> Result<DaemonPingInfo, String> {
    match response {
        IpcResponse::Pong {
            daemon_version,
            protocol_version,
        } => Ok(DaemonPingInfo {
            daemon_version,
            protocol_version,
        }),
        other => Err(unexpected_or_daemon_error(other, "Pong")),
    }
}

pub(crate) fn parse_flight_recorder_response(
    response: IpcResponse,
) -> Result<FlightRecorderSnapshot, String> {
    match response {
        IpcResponse::FlightRecorder(snapshot) => Ok(snapshot),
        other => Err(unexpected_or_daemon_error(other, "FlightRecorder")),
    }
}

pub(crate) fn parse_metrics_response(response: IpcResponse) -> Result<PipelineMetrics, String> {
    match response {
        IpcResponse::Metrics(metrics) => Ok(metrics),
        other => Err(unexpected_or_daemon_error(other, "Metrics")),
    }
}

pub(crate) fn parse_alerts_response(response: IpcResponse) -> Result<Vec<AlertRecord>, String> {
    match response {
        IpcResponse::Alerts(alerts) => Ok(alerts),
        other => Err(unexpected_or_daemon_error(other, "Alerts")),
    }
}

pub(crate) fn parse_ack_response(response: IpcResponse) -> Result<String, String> {
    match response {
        IpcResponse::Ack { message } => Ok(message),
        other => Err(unexpected_or_daemon_error(other, "Ack")),
    }
}

pub(crate) fn parse_rules_response(
    response: IpcResponse,
) -> Result<Vec<AllowlistRuleRecord>, String> {
    match response {
        IpcResponse::Rules(rules) => Ok(rules),
        other => Err(unexpected_or_daemon_error(other, "Rules")),
    }
}

pub(crate) fn parse_domain_risk_response(response: IpcResponse) -> Result<DomainRiskView, String> {
    match response {
        IpcResponse::DomainRisk {
            domain,
            is_nrd,
            is_homograph,
            matched_brand,
        } => Ok(DomainRiskView {
            domain,
            is_nrd,
            is_homograph,
            matched_brand,
        }),
        other => Err(unexpected_or_daemon_error(other, "DomainRisk")),
    }
}

fn unexpected_or_daemon_error(response: IpcResponse, expected: &str) -> String {
    match response {
        IpcResponse::Error { code, message } => format!("daemon error [{code}]: {message}"),
        other => format!("unexpected IPC response (expected {expected}): {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_0003_default_pipe_detection_and_authorized_server_paths() {
        assert!(is_default_ipc_pipe(IPC_PIPE_NAME));
        assert!(is_default_ipc_pipe(r"\\.\PIPE\LocalEDR-IPC"));
        assert!(is_default_ipc_pipe(r"\\?\pipe\localedr-ipc"));
        assert!(is_default_ipc_pipe("//./pipe/localedr-ipc"));
        assert!(is_default_ipc_pipe(r"\\localhost\pipe\localedr-ipc"));
        assert!(!is_default_ipc_pipe(r"\\.\pipe\localedr-ui-test-123"));
        assert!(!is_default_ipc_pipe(r"\\.\pipe\localedr-ipc-custom"));

        let prod_ui = Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe");
        assert!(is_authorized_pipe_server_exe(
            r"C:\Program Files\LocalEDR\ledr-daemon.exe",
            Some(prod_ui)
        ));
        assert!(is_authorized_pipe_server_exe(
            r"c:/program files/localedr/ledr-daemon.exe",
            Some(prod_ui)
        ));
        assert!(is_authorized_pipe_server_exe(
            r"\\?\C:\Program Files\LocalEDR\ledr-daemon.exe",
            Some(prod_ui)
        ));

        let dev_ui = Path::new(r"D:\LocalEDR\target\debug\ledr-ui.exe");
        assert!(is_authorized_pipe_server_exe_with(
            r"D:\LocalEDR\target\debug\ledr-daemon.exe",
            Some(dev_ui),
            false,
            false
        ));
        assert!(is_authorized_pipe_server_exe_with(
            r"D:\LocalEDR\target\debug\ledr-daemon.exe",
            Some(dev_ui),
            true,
            true
        ));
        // Once installed at `AUTHORIZED_DAEMON_EXE_PATH` in release mode, reject non-installed siblings.
        assert!(!is_authorized_pipe_server_exe_with(
            r"D:\LocalEDR\target\release\ledr-daemon.exe",
            Some(Path::new(r"D:\LocalEDR\target\release\ledr-ui.exe")),
            true,
            false
        ));
        assert!(is_authorized_pipe_server_exe_with(
            r"C:\Program Files\LocalEDR\ledr-daemon.exe",
            Some(Path::new(r"D:\LocalEDR\target\release\ledr-ui.exe")),
            true,
            false
        ));

        // Rogue executables (even with the same filename in another directory) must be rejected.
        assert!(!is_authorized_pipe_server_exe(
            r"C:\Users\dev\AppData\Local\Temp\evil.exe",
            Some(prod_ui)
        ));
        assert!(!is_authorized_pipe_server_exe(
            r"C:\Users\dev\Downloads\ledr-daemon.exe",
            Some(prod_ui)
        ));
        assert!(!is_authorized_pipe_server_exe("", Some(prod_ui)));
    }

    #[cfg(windows)]
    #[test]
    fn sec_0003_client_connects_under_service_pipe_sddl_and_verifies_server() {
        use std::ffi::c_void;
        use std::os::windows::fs::OpenOptionsExt;

        const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
        const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
        const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
        const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
        const PIPE_WAIT: u32 = 0x0000_0000;
        const SDDL_REVISION_1: u32 = 1;
        const ERROR_PIPE_CONNECTED: i32 = 535;
        const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)";

        #[repr(C)]
        struct SecurityAttributes {
            n_length: u32,
            lp_security_descriptor: *mut c_void,
            b_inherit_handle: i32,
        }

        #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
        extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                string_security_descriptor: *const u16,
                string_sd_revision: u32,
                security_descriptor: *mut *mut c_void,
                security_descriptor_size: *mut u32,
            ) -> i32;
        }

        #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
        extern "system" {
            fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
            fn CreateNamedPipeW(
                name: *const u16,
                open_mode: u32,
                pipe_mode: u32,
                max_instances: u32,
                out_buffer_size: u32,
                in_buffer_size: u32,
                default_time_out: u32,
                security_attributes: *const SecurityAttributes,
            ) -> *mut c_void;
            fn ConnectNamedPipe(pipe: *mut c_void, overlapped: *mut c_void) -> i32;
            fn DisconnectNamedPipe(pipe: *mut c_void) -> i32;
            fn CloseHandle(object: *mut c_void) -> i32;
        }

        struct PipeHandle(*mut c_void);
        unsafe impl Send for PipeHandle {}
        impl PipeHandle {
            fn raw(&self) -> *mut c_void {
                self.0
            }

            fn into_raw(self) -> *mut c_void {
                let raw = self.0;
                std::mem::forget(self);
                raw
            }
        }
        impl Drop for PipeHandle {
            fn drop(&mut self) {
                if !self.0.is_null() && self.0 as isize != -1 {
                    unsafe {
                        let _ = DisconnectNamedPipe(self.0);
                        let _ = CloseHandle(self.0);
                    }
                }
            }
        }

        fn create_strict_pipe(pipe_name: &str) -> PipeHandle {
            let sddl_w: Vec<u16> = SERVICE_PIPE_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut sd: *mut c_void = std::ptr::null_mut();
            let mut sd_len: u32 = 0;
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    &mut sd_len,
                )
            };
            assert_ne!(ok, 0, "ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: sd,
                b_inherit_handle: 0,
            };
            let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
            let raw = unsafe {
                CreateNamedPipeW(
                    name_w.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    1,
                    4096,
                    4096,
                    0,
                    &sa,
                )
            };
            unsafe {
                let _ = LocalFree(sd);
            }
            assert_ne!(raw as isize, -1, "CreateNamedPipeW failed: {}", std::io::Error::last_os_error());
            PipeHandle(raw)
        }

        // 1. Verify `IpcClient::send_request` succeeds under `SERVICE_PIPE_SDDL` (omitting `FILE_CREATE_PIPE_INSTANCE`).
        let pipe_name = format!(r"\\.\pipe\localedr-ui-sec0003-roundtrip-{}", std::process::id());
        let server_pipe = create_strict_pipe(&pipe_name);
        let server_thread = thread::spawn(move || {
            use std::os::windows::io::FromRawHandle;
            let pipe = server_pipe;
            let ok = unsafe { ConnectNamedPipe(pipe.raw(), std::ptr::null_mut()) };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                assert_eq!(err.raw_os_error(), Some(ERROR_PIPE_CONNECTED));
            }
            let raw = pipe.into_raw();
            let mut stream = unsafe { File::from_raw_handle(raw) };
            let req: IpcRequest = read_ipc_frame(&mut stream).expect("read ping");
            assert_eq!(req, IpcRequest::Ping);
            write_ipc_frame(
                &mut stream,
                &IpcResponse::Pong {
                    daemon_version: "0.1.0".to_string(),
                    protocol_version: ledr_proto::IPC_PROTOCOL_VERSION,
                },
            )
            .expect("write pong");
            let _ = stream.flush();
            // Wait until client finishes reading the response and closes its handle.
            let mut eof_buf = [0u8; 1];
            let _ = stream.read(&mut eof_buf);
        });

        let client = IpcClient::new(&pipe_name);
        let pong = client.ping().expect("client ping under SERVICE_PIPE_SDDL");
        assert!(pong.contains("ledr-daemon v0.1.0"));
        server_thread.join().expect("server thread finished");

        // 2. Verify live `GetNamedPipeServerProcessId` + `OpenProcess` + `QueryFullProcessImageNameW`:
        //    - allows same-PID self-test harness (`verify_named_pipe_server_process`)
        //    - rejects untrusted server exe when strict path checking is enforced (`allow_same_pid = false`).
        let verify_pipe_name = format!(r"\\.\pipe\localedr-ui-sec0003-auth-{}", std::process::id());
        let auth_server_pipe = create_strict_pipe(&verify_pipe_name);
        // Connect the client before spawning the server thread so `ConnectNamedPipe`
        // deterministically observes the already-connected client (`ERROR_PIPE_CONNECTED`).
        // The client handle stays open until the thread is joined; an earlier drop lets
        // `ConnectNamedPipe` see `ERROR_NO_DATA` when it loses the thread start-up race.
        let client_file = OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(PIPE_CLIENT_ACCESS_MODE)
            .open(&verify_pipe_name)
            .expect("open strict pipe with PIPE_CLIENT_ACCESS_MODE");
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let auth_thread = thread::spawn(move || {
            let pipe = auth_server_pipe;
            let ok = unsafe { ConnectNamedPipe(pipe.raw(), std::ptr::null_mut()) };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                assert_eq!(err.raw_os_error(), Some(ERROR_PIPE_CONNECTED));
            }
            let _ = done_rx.recv();
        });

        verify_named_pipe_server_process(&client_file)
            .expect("same-PID test harness should pass self-test verification");

        let rogue_err = win_pipe_auth::verify_named_pipe_server_process_with_options(
            &client_file,
            false,
            Some(Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe")),
        )
        .expect_err("test runner binary must be rejected when strict daemon binary check runs");
        assert!(
            rogue_err.contains("untrusted pipe server process"),
            "unexpected error message: {rogue_err}"
        );
        // Keep the client handle alive until the server thread finishes `ConnectNamedPipe`;
        // dropping it earlier lets `ConnectNamedPipe` observe `ERROR_NO_DATA` instead of
        // `ERROR_PIPE_CONNECTED` when the spawned thread loses the start-up race.
        let _ = done_tx.send(());
        auth_thread.join().expect("auth server thread finished");
        drop(client_file);

        // 3. Verify `NtQuerySystemInformation(SystemProcessIdInformation)` + `QueryDosDeviceW` fallback
        //    against the current process (`std::env::current_exe()`).
        let nt_resolved = win_pipe_auth::query_process_image_path_nt_fallback(std::process::id())
            .expect("NT fallback resolves current process path");
        let current_exe = std::env::current_exe().expect("current_exe");
        assert_eq!(
            normalize_windows_exe_path(&nt_resolved),
            normalize_windows_exe_path(&current_exe.to_string_lossy())
        );

        assert_eq!(
            win_pipe_auth::nt_device_path_to_dos_with_map(
                r"\Device\HarddiskVolume3\Program Files\LocalEDR\ledr-daemon.exe",
                &[('C', r"\Device\HarddiskVolume3".to_string())],
            ),
            Some(r"C:\Program Files\LocalEDR\ledr-daemon.exe".to_string())
        );
    }
}
