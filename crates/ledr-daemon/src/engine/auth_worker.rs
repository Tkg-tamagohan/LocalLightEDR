//! Out-of-process Authenticode verification worker client (`FU-E2E-03` Track 2, Option 2-A + Option X).
//!
//! Spawns `ledr-auth-helper.exe` on demand over anonymous stdin/stdout pipes (4-byte LE length
//! prefix + JSON payload, max 64 KiB) with strict Win32 handle/binary hardening (`CREATE_NO_WINDOW`,
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `JobObject` `KILL_ON_JOB_CLOSE`, reparse/hardlink/same-dir
//! checks, and TOCTOU-safe 64 KiB streaming SHA-256 verification).

use std::collections::VecDeque;
use std::ffi::{c_void, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ledr_proto::AuthenticodeInfo;
use ledr_rules::compute_reader_sha256_hex_cancellable;
use serde::{Deserialize, Serialize};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, SetHandleInformation, DUPLICATE_HANDLE_OPTIONS,
    DUPLICATE_SAME_ACCESS, HANDLE, HANDLE_FLAG_INHERIT, WAIT_TIMEOUT,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, GetFileType, GetFinalPathNameByHandleW, ReOpenFile,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_TYPE_DISK, OPEN_EXISTING, SYNCHRONIZE, VOLUME_NAME_DOS,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROCESS_TERMINATE,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

pub const MAX_AUTH_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_HELPER_IDLE_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 5_000;
pub const DEFAULT_RETRY_TOTAL_BUDGET_MS: u64 = 6_000;
pub const DEFAULT_CIRCUIT_BREAKER_THRESHOLD: usize = 3;
pub const DEFAULT_CIRCUIT_BREAKER_WINDOW_MS: u64 = 30_000;
pub const DEFAULT_CIRCUIT_BREAKER_OPEN_MS: u64 = 30_000;
const SHUTDOWN_POLL_SLICE_MS: u64 = 10;
const MAX_HELPER_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const AUTH_HELPER_EXE_NAME: &str = "ledr-auth-helper.exe";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyRequest {
    pub id: u64,
    pub exe_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthVerifyResponse {
    pub id: u64,
    pub authenticode: Option<AuthenticodeInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthWorkerError {
    Cancelled,
    CircuitOpen,
    Timeout,
    BrokenPipe,
    SpawnFailed(String),
    Protocol(String),
    WorkerIo(String),
}

impl std::fmt::Display for AuthWorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "auth worker cancelled"),
            Self::CircuitOpen => write!(f, "auth worker circuit breaker open"),
            Self::Timeout => write!(f, "auth worker request timed out"),
            Self::BrokenPipe => write!(f, "auth worker pipe closed"),
            Self::SpawnFailed(msg) => write!(f, "auth worker spawn failed: {msg}"),
            Self::Protocol(msg) => write!(f, "auth worker protocol error: {msg}"),
            Self::WorkerIo(msg) => write!(f, "auth worker I/O error: {msg}"),
        }
    }
}

impl std::error::Error for AuthWorkerError {}

#[derive(Debug, Clone)]
pub struct AuthWorkerConfig {
    pub helper_exe_override: Option<PathBuf>,
    pub expected_dir_override: Option<PathBuf>,
    pub auth_helper_sha256: Option<String>,
    pub idle_timeout_ms: u64,
    pub request_timeout: Duration,
    pub retry_total_budget: Duration,
    pub circuit_breaker_threshold: usize,
    pub circuit_breaker_window: Duration,
    pub circuit_breaker_open_duration: Duration,
    #[cfg(test)]
    pub extra_args: Vec<String>,
}

impl Default for AuthWorkerConfig {
    fn default() -> Self {
        Self {
            helper_exe_override: None,
            expected_dir_override: None,
            auth_helper_sha256: None,
            idle_timeout_ms: DEFAULT_HELPER_IDLE_TIMEOUT_MS,
            request_timeout: Duration::from_millis(DEFAULT_REQUEST_TIMEOUT_MS),
            retry_total_budget: Duration::from_millis(DEFAULT_RETRY_TOTAL_BUDGET_MS),
            circuit_breaker_threshold: DEFAULT_CIRCUIT_BREAKER_THRESHOLD,
            circuit_breaker_window: Duration::from_millis(DEFAULT_CIRCUIT_BREAKER_WINDOW_MS),
            circuit_breaker_open_duration: Duration::from_millis(DEFAULT_CIRCUIT_BREAKER_OPEN_MS),
            #[cfg(test)]
            extra_args: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum RecvError {
    Timeout,
    Disconnected,
    Protocol(String),
}

type KillFn = Box<dyn FnOnce() + Send>;

pub trait WorkerProcessHandle: Send {
    fn pid(&self) -> u32;
    fn try_has_exited(&mut self) -> bool;
    fn kill_handle(&self) -> Option<KillFn>;
    fn send_request(&mut self, req: &AuthVerifyRequest) -> io::Result<()>;
    fn recv_response_timeout(&mut self, timeout: Duration) -> Result<AuthVerifyResponse, RecvError>;
    fn force_kill(self: Box<Self>);
}

pub trait WorkerSpawner: Send + Sync {
    fn spawn(&self, cancel: &AtomicBool) -> Result<Box<dyn WorkerProcessHandle>, AuthWorkerError>;
}

#[derive(Debug)]
pub(crate) struct OwnedWinHandle(HANDLE);

// SAFETY: Win32 kernel handles (`HANDLE`) are process-global tokens safe to send between threads.
unsafe impl Send for OwnedWinHandle {}
// SAFETY: Shared references only read the handle value for Win32 FFI calls.
unsafe impl Sync for OwnedWinHandle {}

impl OwnedWinHandle {
    fn into_raw(self) -> HANDLE {
        let h = self.0;
        std::mem::forget(self);
        h
    }
}

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: Handle is owned exclusively by this wrapper and closed once on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct ProcThreadAttrListGuard {
    _backing: Vec<usize>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl Drop for ProcThreadAttrListGuard {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was initialized by `InitializeProcThreadAttributeList`.
        unsafe {
            DeleteProcThreadAttributeList(self.ptr);
        }
    }
}

fn dup_read_handle_as_file(handle: HANDLE) -> Result<File, String> {
    let mut dup = HANDLE::default();
    // SAFETY: Duplicates `handle` with identical access so `File` owns only the duplicate.
    unsafe {
        let current = GetCurrentProcess();
        DuplicateHandle(
            current,
            handle,
            current,
            &mut dup,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|e| format!("DuplicateHandle on helper binary failed: {e}"))?;
    // SAFETY: `dup` is a freshly duplicated exclusively owned Win32 file handle.
    Ok(unsafe { File::from_raw_handle(dup.0 as RawHandle) })
}

fn encode_wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn query_final_path(handle: HANDLE) -> Result<PathBuf, String> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `handle` is an open Win32 file/directory handle and `buf` is valid writable UTF-16 memory.
        let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buf, VOLUME_NAME_DOS) };
        if len == 0 {
            return Err(format!(
                "GetFinalPathNameByHandleW failed: {}",
                io::Error::last_os_error()
            ));
        }
        let len_usize = len as usize;
        if len_usize < buf.len() {
            let os = OsString::from_wide(&buf[..len_usize]);
            return Ok(PathBuf::from(os));
        }
        buf.resize(len_usize + 1, 0);
    }
}

fn normalize_dos_final_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let trimmed = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
    let trimmed = if let Some(unc) = trimmed.strip_prefix(r"UNC\") {
        format!(r"\\{unc}")
    } else {
        trimmed.to_string()
    };
    trimmed.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
}

/// Verifies `helper_path` using attribute-only open (`FILE_FLAG_OPEN_REPARSE_POINT`),
/// `FILE_TYPE_DISK`, non-reparse, `nNumberOfLinks == 1`, `GetFinalPathNameByHandleW` same-directory
/// confinement, `ReOpenFile` upgrade with `FILE_SHARE_READ`-only sharing, and 64 KiB streaming
/// SHA-256 verification.
///
/// Returns `(held_read_handle, normalized_spawn_path)` so callers hold `FILE_SHARE_READ` across
/// `CreateProcessW` to prevent TOCTOU replacement.
pub(crate) fn open_and_verify_helper_binary(
    helper_path: &Path,
    expected_dir: &Path,
    expected_sha256_pin: Option<&str>,
    cancel: &AtomicBool,
) -> Result<(OwnedWinHandle, PathBuf), String> {
    if cancel.load(Ordering::Acquire) {
        return Err("cancelled before helper binary verification".to_string());
    }

    let helper_w = encode_wide_nul(helper_path.as_os_str());
    let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // Step 1: Attribute-only open with `FILE_FLAG_OPEN_REPARSE_POINT` (never follows symlinks).
    // SAFETY: `helper_w` is NUL-terminated UTF-16.
    let attr_raw = unsafe {
        CreateFileW(
            PCWSTR(helper_w.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share_all,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| format!("helper binary open failed ({}): {e}", helper_path.display()))?;
    if attr_raw.is_invalid() {
        return Err(format!("helper binary invalid handle ({})", helper_path.display()));
    }
    let attr_handle = OwnedWinHandle(attr_raw);

    // SAFETY: `attr_handle.0` is an open Win32 handle.
    if unsafe { GetFileType(attr_handle.0) } != FILE_TYPE_DISK {
        return Err("helper binary is not a disk file".to_string());
    }

    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `attr_handle.0` is an open file handle and `info` is valid out storage.
    unsafe { GetFileInformationByHandle(attr_handle.0, &mut info) }
        .map_err(|e| format!("GetFileInformationByHandle on helper failed: {e}"))?;
    if (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
        return Err("helper binary is a reparse point (rejected)".to_string());
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0 {
        return Err("helper binary path is a directory (rejected)".to_string());
    }
    if info.nNumberOfLinks != 1 {
        return Err(format!(
            "helper binary has {} hard links (expected 1; rejected)",
            info.nNumberOfLinks
        ));
    }

    // Step 2: Same-directory confinement via `GetFinalPathNameByHandleW`.
    let dir_w = encode_wide_nul(expected_dir.as_os_str());
    // SAFETY: `dir_w` is NUL-terminated UTF-16; attribute-only directory inspection.
    let dir_raw = unsafe {
        CreateFileW(
            PCWSTR(dir_w.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            share_all,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|e| format!("expected helper dir open failed ({}): {e}", expected_dir.display()))?;
    let dir_handle = OwnedWinHandle(dir_raw);
    let mut dir_info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `dir_handle.0` is an open directory handle.
    unsafe { GetFileInformationByHandle(dir_handle.0, &mut dir_info) }
        .map_err(|e| format!("GetFileInformationByHandle on expected dir failed: {e}"))?;
    if (dir_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
        return Err("expected helper directory is a reparse point (rejected)".to_string());
    }
    if (dir_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) == 0 {
        return Err("expected helper directory is not a directory".to_string());
    }

    let final_dir = query_final_path(dir_handle.0)?;
    let final_helper = query_final_path(attr_handle.0)?;
    let Some(final_helper_parent) = final_helper.parent() else {
        return Err("helper final path has no parent directory".to_string());
    };
    if normalize_dos_final_path(final_helper_parent) != normalize_dos_final_path(&final_dir) {
        return Err(format!(
            "helper binary escaped expected directory: {} not in {}",
            final_helper.display(),
            final_dir.display()
        ));
    }
    let expected_name = helper_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "helper path missing file name".to_string())?;
    let final_name = final_helper
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "helper final path missing file name".to_string())?;
    if !final_name.eq_ignore_ascii_case(expected_name) {
        return Err(format!(
            "helper final filename mismatch: got {final_name}, expected {expected_name}"
        ));
    }

    // Step 3: Upgrade exact kernel file object via `ReOpenFile` with `FILE_SHARE_READ`-only sharing.
    // Holding this handle open across `CreateProcessW` prevents any writer/deleter TOCTOU swap.
    // SAFETY: `attr_handle.0` is an open verified disk file handle.
    let read_raw = unsafe {
        ReOpenFile(
            attr_handle.0,
            FILE_READ_DATA.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ,
            FILE_FLAGS_AND_ATTRIBUTES(0),
        )
    }
    .map_err(|e| format!("ReOpenFile(FILE_SHARE_READ) on helper failed: {e}"))?;
    if read_raw.is_invalid() {
        return Err("ReOpenFile returned invalid handle".to_string());
    }
    let read_handle = OwnedWinHandle(read_raw);

    let mut info2 = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `read_handle.0` is an open file handle.
    unsafe { GetFileInformationByHandle(read_handle.0, &mut info2) }
        .map_err(|e| format!("GetFileInformationByHandle after ReOpenFile failed: {e}"))?;
    if (info2.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0
        || (info2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0) != 0
        || info2.nNumberOfLinks != 1
    {
        return Err("helper binary attributes violated after ReOpenFile".to_string());
    }

    // Step 4: 64 KiB streaming SHA-256 verification directly from the locked open handle.
    let mut reader = dup_read_handle_as_file(read_handle.0)?;
    let sha256 = compute_reader_sha256_hex_cancellable(&mut reader, MAX_HELPER_BINARY_BYTES, cancel)
        .map_err(|e| format!("helper binary SHA-256 read failed: {e}"))?
        .ok_or_else(|| "helper binary exceeds maximum allowed size".to_string())?;
    drop(reader);

    if let Some(pin) = expected_sha256_pin.map(str::trim).filter(|s| !s.is_empty()) {
        if !sha256.eq_ignore_ascii_case(pin) {
            return Err(format!(
                "helper binary SHA-256 mismatch: computed {sha256}, expected {pin}"
            ));
        }
    }

    let final_str = final_helper.to_string_lossy();
    let spawn_path = if let Some(stripped) = final_str.strip_prefix(r"\\?\") {
        if let Some(unc) = stripped.strip_prefix(r"UNC\") {
            PathBuf::from(format!(r"\\{unc}"))
        } else {
            PathBuf::from(stripped)
        }
    } else {
        final_helper
    };

    Ok((read_handle, spawn_path))
}

fn read_framed_json_from_file<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_AUTH_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("auth worker frame length {len} out of bounds (1..={MAX_AUTH_FRAME_BYTES})"),
        ));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid auth worker response JSON: {err}"),
        )
    })
}

fn write_framed_json_to_file<W: Write, T: Serialize>(writer: &mut W, value: &T) -> io::Result<()> {
    let payload = serde_json::to_vec(value).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed serializing auth worker request JSON: {err}"),
        )
    })?;
    if payload.is_empty() || payload.len() > MAX_AUTH_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "auth worker frame length {} out of bounds (1..={MAX_AUTH_FRAME_BYTES})",
                payload.len()
            ),
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflows u32"))?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

pub struct OsWorkerSpawner {
    config: AuthWorkerConfig,
}

impl OsWorkerSpawner {
    pub fn new(config: AuthWorkerConfig) -> Self {
        Self { config }
    }

    fn resolve_paths(&self) -> Result<(PathBuf, PathBuf), AuthWorkerError> {
        if let Some(ref override_path) = self.config.helper_exe_override {
            let expected_dir = match self.config.expected_dir_override {
                Some(ref dir) => dir.clone(),
                None => override_path
                    .parent()
                    .map(Path::to_path_buf)
                    .ok_or_else(|| {
                        AuthWorkerError::SpawnFailed("override helper path has no parent".into())
                    })?,
            };
            return Ok((override_path.clone(), expected_dir));
        }
        let current = std::env::current_exe().map_err(|e| {
            AuthWorkerError::SpawnFailed(format!("failed resolving current_exe: {e}"))
        })?;
        let parent = current.parent().ok_or_else(|| {
            AuthWorkerError::SpawnFailed("current_exe has no parent directory".into())
        })?;
        let helper = parent.join(AUTH_HELPER_EXE_NAME);
        let expected_dir = self
            .config
            .expected_dir_override
            .clone()
            .unwrap_or_else(|| parent.to_path_buf());
        Ok((helper, expected_dir))
    }
}

struct OsWorkerProcess {
    pid: u32,
    job_handle: Option<OwnedWinHandle>,
    process_handle: OwnedWinHandle,
    stdin_write: Option<File>,
    resp_rx: mpsc::Receiver<io::Result<AuthVerifyResponse>>,
    reader_thread: Option<JoinHandle<()>>,
}

impl OsWorkerProcess {
    fn kill_process_now(handle: HANDLE) {
        if !handle.is_invalid() && !handle.0.is_null() {
            // SAFETY: `handle` has `PROCESS_TERMINATE` rights.
            unsafe {
                let _ = TerminateProcess(handle, 1);
            }
        }
    }
}

impl WorkerProcessHandle for OsWorkerProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn try_has_exited(&mut self) -> bool {
        // SAFETY: `self.process_handle.0` is an open Win32 process handle.
        let wait = unsafe { WaitForSingleObject(self.process_handle.0, 0) };
        wait != WAIT_TIMEOUT
    }

    fn kill_handle(&self) -> Option<KillFn> {
        let mut dup = HANDLE::default();
        // SAFETY: Duplicates `process_handle` with `PROCESS_TERMINATE` access for lock-free shutdown kill.
        let ok = unsafe {
            let current = GetCurrentProcess();
            DuplicateHandle(
                current,
                self.process_handle.0,
                current,
                &mut dup,
                PROCESS_TERMINATE.0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        };
        if ok.is_err() || dup.is_invalid() {
            return None;
        }
        let owned = OwnedWinHandle(dup);
        Some(Box::new(move || {
            let owned = owned;
            Self::kill_process_now(owned.0);
        }))
    }

    fn send_request(&mut self, req: &AuthVerifyRequest) -> io::Result<()> {
        let Some(ref mut stdin) = self.stdin_write else {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "auth worker stdin closed",
            ));
        };
        write_framed_json_to_file(stdin, req)
    }

    fn recv_response_timeout(&mut self, timeout: Duration) -> Result<AuthVerifyResponse, RecvError> {
        match self.resp_rx.recv_timeout(timeout) {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(err)) => {
                if err.kind() == io::ErrorKind::UnexpectedEof
                    || err.kind() == io::ErrorKind::BrokenPipe
                {
                    Err(RecvError::Disconnected)
                } else {
                    Err(RecvError::Protocol(err.to_string()))
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(RecvError::Timeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(RecvError::Disconnected),
        }
    }

    fn force_kill(mut self: Box<Self>) {
        drop(self.stdin_write.take());
        Self::kill_process_now(self.process_handle.0);
        drop(self.job_handle.take());
        // SAFETY: Bounded short wait for kernel teardown after `TerminateProcess`.
        unsafe {
            let _ = WaitForSingleObject(self.process_handle.0, 50);
        }
        if let Some(jh) = self.reader_thread.take() {
            let _ = jh.join();
        }
    }
}

impl Drop for OsWorkerProcess {
    fn drop(&mut self) {
        drop(self.stdin_write.take());
        Self::kill_process_now(self.process_handle.0);
        drop(self.job_handle.take());
        // Do not join indefinitely in arbitrary Drop; pipes are closed and process terminated.
        let _ = self.reader_thread.take();
    }
}

impl WorkerSpawner for OsWorkerSpawner {
    fn spawn(&self, cancel: &AtomicBool) -> Result<Box<dyn WorkerProcessHandle>, AuthWorkerError> {
        let (helper_path, expected_dir) = self.resolve_paths()?;
        let (held_binary_guard, spawn_path) = open_and_verify_helper_binary(
            &helper_path,
            &expected_dir,
            self.config.auth_helper_sha256.as_deref(),
            cancel,
        )
        .map_err(|msg| {
            if cancel.load(Ordering::Acquire) {
                AuthWorkerError::Cancelled
            } else {
                AuthWorkerError::SpawnFailed(msg)
            }
        })?;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: false.into(),
        };

        let (mut stdin_read_raw, mut stdin_write_raw) = (HANDLE::default(), HANDLE::default());
        // SAFETY: Valid out pointers for anonymous stdin pipe.
        unsafe { CreatePipe(&mut stdin_read_raw, &mut stdin_write_raw, Some(&sa), 0) }
            .map_err(|e| AuthWorkerError::SpawnFailed(format!("CreatePipe(stdin) failed: {e}")))?;
        let stdin_read = OwnedWinHandle(stdin_read_raw);
        let stdin_write = OwnedWinHandle(stdin_write_raw);

        let (mut stdout_read_raw, mut stdout_write_raw) = (HANDLE::default(), HANDLE::default());
        // SAFETY: Valid out pointers for anonymous stdout pipe.
        unsafe { CreatePipe(&mut stdout_read_raw, &mut stdout_write_raw, Some(&sa), 0) }
            .map_err(|e| AuthWorkerError::SpawnFailed(format!("CreatePipe(stdout) failed: {e}")))?;
        let stdout_read = OwnedWinHandle(stdout_read_raw);
        let stdout_write = OwnedWinHandle(stdout_write_raw);

        // Allow inheritance ONLY on the child pipe endpoints.
        // SAFETY: `stdin_read.0` and `stdout_write.0` are open pipe handles.
        unsafe {
            SetHandleInformation(stdin_read.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                .map_err(|e| AuthWorkerError::SpawnFailed(format!("SetHandleInformation(stdin) failed: {e}")))?;
            SetHandleInformation(stdout_write.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                .map_err(|e| AuthWorkerError::SpawnFailed(format!("SetHandleInformation(stdout) failed: {e}")))?;
        }

        // Prepare `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` containing ONLY `[stdin_read, stdout_write]`.
        let mut attr_size: usize = 0;
        // SAFETY: Query required buffer size for 1 proc-thread attribute.
        let _ = unsafe {
            InitializeProcThreadAttributeList(None, 1, Some(0), &mut attr_size)
        };
        if attr_size == 0 {
            return Err(AuthWorkerError::SpawnFailed(
                "InitializeProcThreadAttributeList returned 0 size".into(),
            ));
        }
        let word_count = attr_size.div_ceil(std::mem::size_of::<usize>());
        let mut backing = vec![0usize; word_count];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(backing.as_mut_ptr().cast::<c_void>());
        // SAFETY: `backing` is aligned and at least `attr_size` bytes.
        unsafe {
            InitializeProcThreadAttributeList(Some(attr_list), 1, Some(0), &mut attr_size)
                .map_err(|e| {
                    AuthWorkerError::SpawnFailed(format!(
                        "InitializeProcThreadAttributeList failed: {e}"
                    ))
                })?;
        }
        let attr_guard = ProcThreadAttrListGuard {
            _backing: backing,
            ptr: attr_list,
        };

        let mut inherit_handles = [stdin_read.0, stdout_write.0];
        // SAFETY: `attr_guard.ptr` is initialized and `inherit_handles` outlives `CreateProcessW`.
        unsafe {
            UpdateProcThreadAttribute(
                attr_guard.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(inherit_handles.as_mut_ptr().cast::<c_void>()),
                std::mem::size_of_val(&inherit_handles),
                None,
                None,
            )
            .map_err(|e| {
                AuthWorkerError::SpawnFailed(format!("UpdateProcThreadAttribute failed: {e}"))
            })?;
        }

        // Create `JobObject` with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
        // SAFETY: Standard anonymous JobObject creation.
        let job_raw = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| AuthWorkerError::SpawnFailed(format!("CreateJobObjectW failed: {e}")))?;
        let job = OwnedWinHandle(job_raw);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job.0` is an open JobObject handle and `limits` is properly sized.
        unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                ptr::addr_of!(limits).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .map_err(|e| {
                AuthWorkerError::SpawnFailed(format!("SetInformationJobObject failed: {e}"))
            })?;
        }

        let mut cmd_str = format!("\"{}\"", spawn_path.display());
        #[cfg(test)]
        {
            if !self.config.extra_args.is_empty() {
                for arg in &self.config.extra_args {
                    cmd_str.push(' ');
                    cmd_str.push_str(arg);
                }
            } else if self.config.idle_timeout_ms != DEFAULT_HELPER_IDLE_TIMEOUT_MS {
                cmd_str.push_str(&format!(" --idle-timeout-ms {}", self.config.idle_timeout_ms));
            }
        }
        #[cfg(not(test))]
        if self.config.idle_timeout_ms != DEFAULT_HELPER_IDLE_TIMEOUT_MS {
            cmd_str.push_str(&format!(" --idle-timeout-ms {}", self.config.idle_timeout_ms));
        }

        let app_w = encode_wide_nul(spawn_path.as_os_str());
        let mut cmd_w: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();

        let mut startup_ex = STARTUPINFOEXW::default();
        startup_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup_ex.StartupInfo.hStdInput = stdin_read.0;
        startup_ex.StartupInfo.hStdOutput = stdout_write.0;
        startup_ex.StartupInfo.hStdError = HANDLE(ptr::null_mut());
        startup_ex.lpAttributeList = attr_guard.ptr;

        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `app_w`, `cmd_w`, and `startup_ex` remain valid across `CreateProcessW`.
        // `held_binary_guard` keeps `FILE_SHARE_READ` open across `CreateProcessW` (TOCTOU guard).
        unsafe {
            CreateProcessW(
                PCWSTR(app_w.as_ptr()),
                Some(PWSTR(cmd_w.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED,
                None,
                PCWSTR::null(),
                &startup_ex.StartupInfo,
                &mut pi,
            )
            .map_err(|e| AuthWorkerError::SpawnFailed(format!("CreateProcessW failed: {e}")))?;
        }
        let process_handle = OwnedWinHandle(pi.hProcess);
        let thread_handle = OwnedWinHandle(pi.hThread);

        // Close parent copies of child pipe ends immediately.
        drop(stdin_read);
        drop(stdout_write);
        drop(attr_guard);

        // Assign suspended child to JobObject before resuming a single instruction.
        // SAFETY: `job.0` and `process_handle.0` are valid open handles.
        if let Err(e) = unsafe { AssignProcessToJobObject(job.0, process_handle.0) } {
            OsWorkerProcess::kill_process_now(process_handle.0);
            return Err(AuthWorkerError::SpawnFailed(format!(
                "AssignProcessToJobObject failed: {e}"
            )));
        }

        // SAFETY: `thread_handle.0` is the suspended primary thread of `process_handle.0`.
        let resume_res = unsafe { ResumeThread(thread_handle.0) };
        drop(thread_handle);
        drop(held_binary_guard);
        if resume_res == u32::MAX {
            OsWorkerProcess::kill_process_now(process_handle.0);
            return Err(AuthWorkerError::SpawnFailed("ResumeThread failed".into()));
        }

        // SAFETY: `stdin_write` and `stdout_read` are exclusively owned open pipe handles.
        let stdin_file = unsafe { File::from_raw_handle(stdin_write.into_raw().0 as RawHandle) };
        // SAFETY: `stdout_read` is an exclusively owned open pipe handle.
        let mut stdout_file = unsafe { File::from_raw_handle(stdout_read.into_raw().0 as RawHandle) };

        let (resp_tx, resp_rx) = mpsc::sync_channel::<io::Result<AuthVerifyResponse>>(1);
        let reader_thread = std::thread::Builder::new()
            .name("auth-worker-stdout".to_string())
            .spawn(move || loop {
                let res = read_framed_json_from_file::<_, AuthVerifyResponse>(&mut stdout_file);
                let is_err = res.is_err();
                if resp_tx.send(res).is_err() || is_err {
                    break;
                }
            })
            .map_err(|e| {
                OsWorkerProcess::kill_process_now(process_handle.0);
                AuthWorkerError::SpawnFailed(format!("spawn stdout reader thread failed: {e}"))
            })?;

        Ok(Box::new(OsWorkerProcess {
            pid: pi.dwProcessId,
            job_handle: Some(job),
            process_handle,
            stdin_write: Some(stdin_file),
            resp_rx,
            reader_thread: Some(reader_thread),
        }))
    }
}

struct AuthWorkerState {
    active_worker: Option<Box<dyn WorkerProcessHandle>>,
    next_request_id: u64,
    recent_failures: VecDeque<Instant>,
    circuit_open_until: Option<Instant>,
}

/// Thread-safe client managing the on-demand `ledr-auth-helper.exe` child process,
/// 1-retry `BrokenPipe` recovery, 5s request timeout + force-kill, `<= 50 ms` shutdown cancel,
/// 3-in-30s circuit breaker, and self-PID recursion tracking.
pub struct AuthWorkerClient {
    config: AuthWorkerConfig,
    spawner: Arc<dyn WorkerSpawner>,
    active_helper_pid: Arc<AtomicU32>,
    shutdown_requested: Arc<AtomicBool>,
    active_kill_fn: Arc<Mutex<Option<KillFn>>>,
    inner: Mutex<AuthWorkerState>,
}

impl std::fmt::Debug for AuthWorkerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthWorkerClient")
            .field("active_helper_pid", &self.active_helper_pid.load(Ordering::Relaxed))
            .field("shutdown_requested", &self.shutdown_requested.load(Ordering::Relaxed))
            .finish()
    }
}

impl AuthWorkerClient {
    pub fn new(config: AuthWorkerConfig) -> Self {
        let spawner = Arc::new(OsWorkerSpawner::new(config.clone()));
        Self::with_spawner(config, spawner)
    }

    pub fn with_spawner(config: AuthWorkerConfig, spawner: Arc<dyn WorkerSpawner>) -> Self {
        Self {
            config,
            spawner,
            active_helper_pid: Arc::new(AtomicU32::new(0)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            active_kill_fn: Arc::new(Mutex::new(None)),
            inner: Mutex::new(AuthWorkerState {
                active_worker: None,
                next_request_id: 1,
                recent_failures: VecDeque::new(),
                circuit_open_until: None,
            }),
        }
    }

    pub fn active_helper_pid(&self) -> Option<u32> {
        let pid = self.active_helper_pid.load(Ordering::Acquire);
        (pid != 0).then_some(pid)
    }

    pub fn is_helper_pid(&self, pid: u32) -> bool {
        pid != 0 && self.active_helper_pid.load(Ordering::Acquire) == pid
    }

    /// Signals shutdown and force-terminates any live `ledr-auth-helper` process immediately so
    /// in-flight pipe waits abort well within 50 ms.
    pub fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        self.active_helper_pid.store(0, Ordering::Release);
        if let Ok(mut kill_guard) = self.active_kill_fn.lock() {
            if let Some(kill) = kill_guard.take() {
                kill();
            }
        }
        if let Ok(mut state) = self.inner.try_lock() {
            if let Some(worker) = state.active_worker.take() {
                worker.force_kill();
            }
        }
    }

    fn discard_active_worker(&self, state: &mut AuthWorkerState) {
        self.active_helper_pid.store(0, Ordering::Release);
        if let Ok(mut kill_guard) = self.active_kill_fn.lock() {
            *kill_guard = None;
        }
        if let Some(worker) = state.active_worker.take() {
            worker.force_kill();
        }
    }

    fn record_failure(&self, state: &mut AuthWorkerState, now: Instant) {
        let window = self.config.circuit_breaker_window;
        while let Some(&front) = state.recent_failures.front() {
            if now.saturating_duration_since(front) > window {
                state.recent_failures.pop_front();
            } else {
                break;
            }
        }
        state.recent_failures.push_back(now);
        if state.recent_failures.len() >= self.config.circuit_breaker_threshold.max(1) {
            state.circuit_open_until = Some(now + self.config.circuit_breaker_open_duration);
            state.recent_failures.clear();
            tracing::warn!(
                open_secs = self.config.circuit_breaker_open_duration.as_secs(),
                "auth worker circuit breaker tripped after consecutive failures; failing closed (Option X)"
            );
        }
    }

    fn is_cancelled(&self, cancel: &AtomicBool) -> bool {
        cancel.load(Ordering::Acquire) || self.shutdown_requested.load(Ordering::Acquire)
    }

    pub fn verify_cancellable(
        &self,
        exe_path: &str,
        cancel: &AtomicBool,
    ) -> Result<Option<AuthenticodeInfo>, AuthWorkerError> {
        if self.is_cancelled(cancel) {
            return Err(AuthWorkerError::Cancelled);
        }

        let mut state = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if self.is_cancelled(cancel) {
            self.discard_active_worker(&mut state);
            return Err(AuthWorkerError::Cancelled);
        }

        let now = Instant::now();
        if let Some(until) = state.circuit_open_until {
            if now < until {
                return Err(AuthWorkerError::CircuitOpen);
            }
            state.circuit_open_until = None;
        }

        let overall_start = Instant::now();
        let poll_slice = Duration::from_millis(SHUTDOWN_POLL_SLICE_MS);

        for attempt in 0..=1 {
            if self.is_cancelled(cancel) {
                self.discard_active_worker(&mut state);
                return Err(AuthWorkerError::Cancelled);
            }

            if let Some(ref mut w) = state.active_worker {
                if w.try_has_exited() {
                    self.discard_active_worker(&mut state);
                }
            }

            if state.active_worker.is_none() {
                let worker = match self.spawner.spawn(cancel) {
                    Ok(w) => w,
                    Err(AuthWorkerError::Cancelled) => return Err(AuthWorkerError::Cancelled),
                    Err(err) => {
                        if self.is_cancelled(cancel) {
                            return Err(AuthWorkerError::Cancelled);
                        }
                        self.record_failure(&mut state, Instant::now());
                        return Err(err);
                    }
                };
                self.active_helper_pid.store(worker.pid(), Ordering::Release);
                if let Ok(mut kill_guard) = self.active_kill_fn.lock() {
                    *kill_guard = worker.kill_handle();
                }
                state.active_worker = Some(worker);
                if self.is_cancelled(cancel) {
                    self.discard_active_worker(&mut state);
                    return Err(AuthWorkerError::Cancelled);
                }
            }

            let req_id = state.next_request_id;
            state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
            let req = AuthVerifyRequest {
                id: req_id,
                exe_path: exe_path.to_string(),
            };

            let send_res = state
                .active_worker
                .as_mut()
                .expect("active worker spawned")
                .send_request(&req);
            if let Err(err) = send_res {
                let is_pipe_race = matches!(
                    err.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                );
                self.discard_active_worker(&mut state);
                if is_pipe_race
                    && attempt == 0
                    && overall_start.elapsed() < self.config.retry_total_budget
                {
                    continue;
                }
                self.record_failure(&mut state, Instant::now());
                return Err(if is_pipe_race {
                    AuthWorkerError::BrokenPipe
                } else {
                    AuthWorkerError::WorkerIo(err.to_string())
                });
            }

            let remaining_budget = self
                .config
                .retry_total_budget
                .saturating_sub(overall_start.elapsed());
            if remaining_budget.is_zero() {
                self.discard_active_worker(&mut state);
                self.record_failure(&mut state, Instant::now());
                return Err(AuthWorkerError::Timeout);
            }
            let attempt_timeout = self.config.request_timeout.min(remaining_budget);
            let attempt_deadline = Instant::now() + attempt_timeout;

            loop {
                if self.is_cancelled(cancel) {
                    self.discard_active_worker(&mut state);
                    return Err(AuthWorkerError::Cancelled);
                }
                let now_loop = Instant::now();
                if now_loop >= attempt_deadline {
                    self.discard_active_worker(&mut state);
                    self.record_failure(&mut state, now_loop);
                    return Err(AuthWorkerError::Timeout);
                }
                let wait_for = poll_slice.min(attempt_deadline.saturating_duration_since(now_loop));
                let recv_res = state
                    .active_worker
                    .as_mut()
                    .expect("active worker present")
                    .recv_response_timeout(wait_for);

                match recv_res {
                    Ok(resp) => {
                        if resp.id != req_id {
                            self.discard_active_worker(&mut state);
                            self.record_failure(&mut state, Instant::now());
                            return Err(AuthWorkerError::Protocol(format!(
                                "mismatched auth response id: expected {req_id}, got {}",
                                resp.id
                            )));
                        }
                        state.recent_failures.clear();
                        return Ok(resp.authenticode);
                    }
                    Err(RecvError::Timeout) => {
                        // Poll slice elapsed; re-check cancel and attempt deadline on next iteration.
                    }
                    Err(RecvError::Disconnected) => {
                        if self.is_cancelled(cancel) {
                            self.discard_active_worker(&mut state);
                            return Err(AuthWorkerError::Cancelled);
                        }
                        self.discard_active_worker(&mut state);
                        if attempt == 0 && overall_start.elapsed() < self.config.retry_total_budget {
                            break;
                        }
                        self.record_failure(&mut state, Instant::now());
                        return Err(AuthWorkerError::BrokenPipe);
                    }
                    Err(RecvError::Protocol(msg)) => {
                        self.discard_active_worker(&mut state);
                        self.record_failure(&mut state, Instant::now());
                        return Err(AuthWorkerError::Protocol(msg));
                    }
                }
            }
        }

        self.discard_active_worker(&mut state);
        self.record_failure(&mut state, Instant::now());
        Err(AuthWorkerError::BrokenPipe)
    }
}

impl Drop for AuthWorkerClient {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::AtomicUsize;

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static SEQ: AtomicU32 = AtomicU32::new(1);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Clone)]
    enum MockStep {
        AuthenticodeViaHelperLib,
        BrokenPipeOnSend,
        ImmediateEofOnRecv,
        DelayMsThenId { delay_ms: u64, force_id: Option<u64> },
        HangUntilKilled { started_tx: mpsc::Sender<u32> },
    }

    struct MockWorkerProcess {
        pid: u32,
        step: MockStep,
        last_req: Option<AuthVerifyRequest>,
        exited: Arc<AtomicBool>,
        killed: Arc<AtomicBool>,
        delayed_replies: Arc<Mutex<Vec<u64>>>,
    }

    impl WorkerProcessHandle for MockWorkerProcess {
        fn pid(&self) -> u32 {
            self.pid
        }

        fn try_has_exited(&mut self) -> bool {
            self.exited.load(Ordering::Acquire)
        }

        fn kill_handle(&self) -> Option<KillFn> {
            let killed = Arc::clone(&self.killed);
            let exited = Arc::clone(&self.exited);
            Some(Box::new(move || {
                killed.store(true, Ordering::Release);
                exited.store(true, Ordering::Release);
            }))
        }

        fn send_request(&mut self, req: &AuthVerifyRequest) -> io::Result<()> {
            if matches!(self.step, MockStep::BrokenPipeOnSend) {
                self.exited.store(true, Ordering::Release);
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "mock broken pipe"));
            }
            self.last_req = Some(req.clone());
            if let MockStep::HangUntilKilled { ref started_tx } = self.step {
                let _ = started_tx.send(self.pid);
            }
            Ok(())
        }

        fn recv_response_timeout(&mut self, timeout: Duration) -> Result<AuthVerifyResponse, RecvError> {
            let req = self.last_req.take().unwrap_or(AuthVerifyRequest {
                id: 0,
                exe_path: String::new(),
            });
            match &self.step {
                MockStep::BrokenPipeOnSend | MockStep::ImmediateEofOnRecv => {
                    self.exited.store(true, Ordering::Release);
                    Err(RecvError::Disconnected)
                }
                MockStep::AuthenticodeViaHelperLib => {
                    let auth = ledr_auth_helper::inspect_authenticode(Path::new(&req.exe_path));
                    Ok(AuthVerifyResponse {
                        id: req.id,
                        authenticode: auth,
                    })
                }
                MockStep::DelayMsThenId { delay_ms, force_id } => {
                    let delay = Duration::from_millis(*delay_ms);
                    if delay > timeout {
                        std::thread::sleep(timeout);
                        self.last_req = Some(AuthVerifyRequest {
                            id: req.id,
                            exe_path: req.exe_path,
                        });
                        // Simulate a delayed response written to the discarded pipe later.
                        if !self.killed.load(Ordering::Acquire) {
                            if let Ok(mut g) = self.delayed_replies.lock() {
                                g.push(force_id.unwrap_or(req.id));
                            }
                        }
                        return Err(RecvError::Timeout);
                    }
                    std::thread::sleep(delay);
                    if self.killed.load(Ordering::Acquire) {
                        return Err(RecvError::Disconnected);
                    }
                    Ok(AuthVerifyResponse {
                        id: force_id.unwrap_or(req.id),
                        authenticode: None,
                    })
                }
                MockStep::HangUntilKilled { .. } => {
                    if self.killed.load(Ordering::Acquire) {
                        return Err(RecvError::Disconnected);
                    }
                    std::thread::sleep(timeout.min(Duration::from_millis(10)));
                    self.last_req = Some(req);
                    if self.killed.load(Ordering::Acquire) {
                        Err(RecvError::Disconnected)
                    } else {
                        Err(RecvError::Timeout)
                    }
                }
            }
        }

        fn force_kill(self: Box<Self>) {
            self.killed.store(true, Ordering::Release);
            self.exited.store(true, Ordering::Release);
        }
    }

    struct ScriptedSpawner {
        steps: Mutex<VecDeque<MockStep>>,
        spawn_count: Arc<AtomicUsize>,
        next_pid: AtomicU32,
        delayed_replies: Arc<Mutex<Vec<u64>>>,
        last_killed: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
    }

    impl ScriptedSpawner {
        fn new(steps: Vec<MockStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
                spawn_count: Arc::new(AtomicUsize::new(0)),
                next_pid: AtomicU32::new(50_000),
                delayed_replies: Arc::new(Mutex::new(Vec::new())),
                last_killed: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl WorkerSpawner for ScriptedSpawner {
        fn spawn(&self, cancel: &AtomicBool) -> Result<Box<dyn WorkerProcessHandle>, AuthWorkerError> {
            if cancel.load(Ordering::Acquire) {
                return Err(AuthWorkerError::Cancelled);
            }
            self.spawn_count.fetch_add(1, Ordering::AcqRel);
            let step = self
                .steps
                .lock()
                .expect("steps lock")
                .pop_front()
                .unwrap_or(MockStep::AuthenticodeViaHelperLib);
            let pid = self.next_pid.fetch_add(1, Ordering::AcqRel);
            let killed = Arc::new(AtomicBool::new(false));
            self.last_killed.lock().expect("killed lock").push(Arc::clone(&killed));
            Ok(Box::new(MockWorkerProcess {
                pid,
                step,
                last_req: None,
                exited: Arc::new(AtomicBool::new(false)),
                killed,
                delayed_replies: Arc::clone(&self.delayed_replies),
            }))
        }
    }

    #[test]
    fn auth_worker_01_subcases_1_to_7_lifecycle_retry_timeout_cancel_breaker_and_self_pid() {
        let cancel = AtomicBool::new(false);

        // Sub-case (1): Normal verification (signed & unsigned, matching `AuthenticodeInfo`).
        let tmp = TestTempDir::new("auth-worker-01");
        let unsigned = tmp.path.join("unsigned.exe");
        std::fs::write(&unsigned, b"MZ-unsigned-test").expect("write unsigned");
        let cmd_exe = r"C:\Windows\System32\cmd.exe";
        let expected_cmd = ledr_auth_helper::inspect_authenticode(Path::new(cmd_exe));
        assert!(expected_cmd.is_some());

        let spawner1 = Arc::new(ScriptedSpawner::new(vec![MockStep::AuthenticodeViaHelperLib]));
        let client1 = AuthWorkerClient::with_spawner(AuthWorkerConfig::default(), spawner1);
        let got_signed = client1
            .verify_cancellable(cmd_exe, &cancel)
            .expect("signed verification");
        assert_eq!(got_signed, expected_cmd);
        let got_unsigned = client1
            .verify_cancellable(&unsigned.to_string_lossy(), &cancel)
            .expect("unsigned verification");
        assert_eq!(got_unsigned, None);

        // Sub-case (3): BrokenPipe / immediate EOF race performs 1 automatic retry within 6,000 ms budget.
        let spawner3 = Arc::new(ScriptedSpawner::new(vec![
            MockStep::BrokenPipeOnSend,
            MockStep::AuthenticodeViaHelperLib,
        ]));
        let client3 = AuthWorkerClient::with_spawner(AuthWorkerConfig::default(), Arc::clone(&spawner3) as Arc<dyn WorkerSpawner>);
        let retried = client3
            .verify_cancellable(cmd_exe, &cancel)
            .expect("BrokenPipe should auto-retry once and succeed");
        assert_eq!(retried, expected_cmd);
        assert_eq!(spawner3.spawn_count.load(Ordering::Acquire), 2);

        // Immediate EOF on recv also auto-retries once.
        let spawner3b = Arc::new(ScriptedSpawner::new(vec![
            MockStep::ImmediateEofOnRecv,
            MockStep::AuthenticodeViaHelperLib,
        ]));
        let client3b = AuthWorkerClient::with_spawner(AuthWorkerConfig::default(), Arc::clone(&spawner3b) as Arc<dyn WorkerSpawner>);
        let retried_eof = client3b
            .verify_cancellable(cmd_exe, &cancel)
            .expect("Immediate EOF should auto-retry once and succeed");
        assert_eq!(retried_eof, expected_cmd);
        assert_eq!(spawner3b.spawn_count.load(Ordering::Acquire), 2);

        // Sub-case (4): Timeout force-kills helper, discards pipe, and never misroutes delayed response.
        let cfg_timeout = AuthWorkerConfig {
            request_timeout: Duration::from_millis(80),
            retry_total_budget: Duration::from_millis(500),
            ..AuthWorkerConfig::default()
        };
        let spawner4 = Arc::new(ScriptedSpawner::new(vec![
            MockStep::DelayMsThenId {
                delay_ms: 400,
                force_id: Some(1),
            },
            MockStep::AuthenticodeViaHelperLib,
        ]));
        let client4 = AuthWorkerClient::with_spawner(cfg_timeout, Arc::clone(&spawner4) as Arc<dyn WorkerSpawner>);
        let err4 = client4
            .verify_cancellable(cmd_exe, &cancel)
            .expect_err("slow worker should time out");
        assert_eq!(err4, AuthWorkerError::Timeout);
        assert!(
            spawner4.last_killed.lock().expect("lock")[0].load(Ordering::Acquire),
            "timed-out worker must be force-killed"
        );
        // Immediate subsequent request gets fresh worker and exact response, never delayed response #1.
        let next4 = client4
            .verify_cancellable(cmd_exe, &cancel)
            .expect("subsequent call after timeout must succeed on fresh pipe");
        assert_eq!(next4, expected_cmd);
        assert_eq!(spawner4.spawn_count.load(Ordering::Acquire), 2);

        // Sub-case (5): Shutdown cancel aborts in-flight wait within <= 50 ms without tripping breaker.
        let (started_tx, started_rx) = mpsc::channel();
        let spawner5 = Arc::new(ScriptedSpawner::new(vec![MockStep::HangUntilKilled {
            started_tx,
        }]));
        let client5 = Arc::new(AuthWorkerClient::with_spawner(
            AuthWorkerConfig::default(),
            Arc::clone(&spawner5) as Arc<dyn WorkerSpawner>,
        ));
        let cancel5 = Arc::new(AtomicBool::new(false));
        let client5_bg = Arc::clone(&client5);
        let cancel5_bg = Arc::clone(&cancel5);
        let cmd_str = cmd_exe.to_string();
        let jh = std::thread::spawn(move || client5_bg.verify_cancellable(&cmd_str, &cancel5_bg));
        let active_pid = started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker should enter in-flight wait");

        // Sub-case (7): Self-PID recursion guard sees active worker PID while in-flight.
        assert!(client5.is_helper_pid(active_pid));
        assert!(!client5.is_helper_pid(active_pid + 1));
        assert!(!client5.is_helper_pid(0));

        let cancel_t0 = Instant::now();
        cancel5.store(true, Ordering::Release);
        let cancel_res = jh.join().expect("join");
        let cancel_elapsed = cancel_t0.elapsed();
        assert_eq!(cancel_res, Err(AuthWorkerError::Cancelled));
        assert!(
            cancel_elapsed <= Duration::from_millis(50),
            "cancel abort took {:?} (expected <= 50 ms)",
            cancel_elapsed
        );
        assert!(!client5.is_helper_pid(active_pid));

        // Sub-case (6): 3 consecutive failures within 30s -> 30s circuit breaker open.
        let spawner6 = Arc::new(ScriptedSpawner::new(vec![
            MockStep::BrokenPipeOnSend,
            MockStep::BrokenPipeOnSend,
            MockStep::BrokenPipeOnSend,
            MockStep::BrokenPipeOnSend,
            MockStep::BrokenPipeOnSend,
            MockStep::BrokenPipeOnSend,
            MockStep::AuthenticodeViaHelperLib,
        ]));
        let cfg6 = AuthWorkerConfig {
            circuit_breaker_threshold: 3,
            circuit_breaker_window: Duration::from_secs(30),
            circuit_breaker_open_duration: Duration::from_millis(200),
            ..AuthWorkerConfig::default()
        };
        let client6 = AuthWorkerClient::with_spawner(cfg6, Arc::clone(&spawner6) as Arc<dyn WorkerSpawner>);
        for i in 0..3 {
            let res = client6.verify_cancellable(cmd_exe, &cancel);
            assert!(
                matches!(res, Err(AuthWorkerError::BrokenPipe)),
                "failure {i} should fail after retry: {res:?}"
            );
        }
        let spawns_at_trip = spawner6.spawn_count.load(Ordering::Acquire);
        assert_eq!(spawns_at_trip, 6);
        let open_res = client6.verify_cancellable(cmd_exe, &cancel);
        assert_eq!(open_res, Err(AuthWorkerError::CircuitOpen));
        assert_eq!(
            spawner6.spawn_count.load(Ordering::Acquire),
            spawns_at_trip,
            "open circuit breaker must NOT spawn worker"
        );
        std::thread::sleep(Duration::from_millis(230));
        let recovered = client6
            .verify_cancellable(cmd_exe, &cancel)
            .expect("circuit breaker should recover after open duration");
        assert_eq!(recovered, expected_cmd);
    }

    #[test]
    fn auth_worker_01_os_process_hardening_timeout_cancel_and_self_pid() {
        assert_eq!(DEFAULT_HELPER_IDLE_TIMEOUT_MS, 15_000);
        assert_eq!(DEFAULT_REQUEST_TIMEOUT_MS, 5_000);
        assert_eq!(DEFAULT_RETRY_TOTAL_BUDGET_MS, 6_000);

        let tmp = TestTempDir::new("auth-worker-os-hardening");
        let allowed_dir = tmp.path.join("allowed");
        let escaped_dir = tmp.path.join("escaped");
        std::fs::create_dir_all(&allowed_dir).expect("create allowed");
        std::fs::create_dir_all(&escaped_dir).expect("create escaped");

        let helper_bin = allowed_dir.join("ledr-auth-helper.exe");
        std::fs::write(&helper_bin, b"MZ-helper-payload").expect("write helper");
        let helper_sha =
            ledr_rules::compute_file_sha256_hex(&helper_bin).expect("hash helper");
        let cancel = AtomicBool::new(false);

        // 1. Valid regular file in expected dir passes + SHA-256 pin check works.
        let (guard, spawn_path) =
            open_and_verify_helper_binary(&helper_bin, &allowed_dir, Some(&helper_sha), &cancel)
                .expect("valid helper binary should pass");
        assert!(spawn_path.ends_with("ledr-auth-helper.exe"));
        drop(guard);

        let wrong_pin = "0".repeat(64);
        assert!(
            open_and_verify_helper_binary(&helper_bin, &allowed_dir, Some(&wrong_pin), &cancel)
                .is_err(),
            "SHA-256 pin mismatch must fail closed"
        );

        // 2. Directory escape rejected.
        let outside_bin = escaped_dir.join("ledr-auth-helper.exe");
        std::fs::write(&outside_bin, b"MZ-outside").expect("write outside");
        assert!(
            open_and_verify_helper_binary(&outside_bin, &allowed_dir, None, &cancel).is_err(),
            "directory escape must be rejected"
        );

        // 3. Hardlink (`nNumberOfLinks > 1`) rejected.
        let hardlink_bin = allowed_dir.join("hardlink-helper.exe");
        std::fs::hard_link(&helper_bin, &hardlink_bin).expect("create hard link");
        let hardlink_err =
            open_and_verify_helper_binary(&hardlink_bin, &allowed_dir, None, &cancel)
                .expect_err("hardlinked helper must be rejected");
        assert!(hardlink_err.contains("hard links"), "got: {hardlink_err}");
        let _ = std::fs::remove_file(&hardlink_bin);

        // 4. Reparse point / junction rejected.
        let junction_dir = tmp.path.join("junction_dir");
        let mklink_status = Command::new("cmd.exe")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction_dir.to_string_lossy(),
                &allowed_dir.to_string_lossy(),
            ])
            .output()
            .expect("run mklink /J");
        if mklink_status.status.success() {
            let via_junction = junction_dir.join("ledr-auth-helper.exe");
            assert!(
                open_and_verify_helper_binary(&via_junction, &junction_dir, None, &cancel).is_err(),
                "reparse-point directory must be rejected"
            );
        }

        // 5. Real OS child spawn via `OsWorkerSpawner`: copied `cmd.exe` hang killed on timeout AND on <= 50ms cancel.
        let sys_cmd = Path::new(r"C:\Windows\System32\cmd.exe");
        if sys_cmd.is_file() {
            let hang_exe = allowed_dir.join("test-hang-helper.exe");
            std::fs::copy(sys_cmd, &hang_exe).expect("copy cmd.exe for hang test");
            let hang_sha = ledr_rules::compute_file_sha256_hex(&hang_exe).expect("hash hang_exe");
            let cfg = AuthWorkerConfig {
                helper_exe_override: Some(hang_exe.clone()),
                expected_dir_override: Some(allowed_dir.clone()),
                auth_helper_sha256: Some(hang_sha.clone()),
                request_timeout: Duration::from_millis(120),
                retry_total_budget: Duration::from_millis(500),
                extra_args: vec![
                    "/c".to_string(),
                    "ping".to_string(),
                    "-n".to_string(),
                    "10".to_string(),
                    "127.0.0.1".to_string(),
                    ">nul".to_string(),
                ],
                ..AuthWorkerConfig::default()
            };
            let os_client = AuthWorkerClient::new(cfg);
            let t0 = Instant::now();
            let res = os_client.verify_cancellable(r"C:\Windows\System32\cmd.exe", &cancel);
            assert_eq!(res, Err(AuthWorkerError::Timeout));
            assert!(t0.elapsed() < Duration::from_secs(2));
            assert_eq!(os_client.active_helper_pid(), None);

            // Real OS child instant shutdown cancel (<= 50 ms) via `shutdown()`.
            let cfg_cancel = AuthWorkerConfig {
                helper_exe_override: Some(hang_exe),
                expected_dir_override: Some(allowed_dir.clone()),
                auth_helper_sha256: Some(hang_sha),
                request_timeout: Duration::from_millis(5_000),
                retry_total_budget: Duration::from_millis(6_000),
                extra_args: vec![
                    "/c".to_string(),
                    "ping".to_string(),
                    "-n".to_string(),
                    "10".to_string(),
                    "127.0.0.1".to_string(),
                    ">nul".to_string(),
                ],
                ..AuthWorkerConfig::default()
            };
            let os_client2 = Arc::new(AuthWorkerClient::new(cfg_cancel));
            let os_bg = Arc::clone(&os_client2);
            let cancel2 = Arc::new(AtomicBool::new(false));
            let cancel2_bg = Arc::clone(&cancel2);
            let jh = std::thread::spawn(move || {
                os_bg.verify_cancellable(r"C:\Windows\System32\cmd.exe", &cancel2_bg)
            });

            // Wait until real OS helper PID becomes active.
            let wait_start = Instant::now();
            while os_client2.active_helper_pid().is_none() {
                assert!(
                    wait_start.elapsed() < Duration::from_secs(3),
                    "timed out waiting for OS child spawn"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            let real_pid = os_client2.active_helper_pid().expect("active pid");
            assert!(os_client2.is_helper_pid(real_pid));

            let t_cancel = Instant::now();
            os_client2.shutdown();
            let res2 = jh.join().expect("join");
            let cancel_dt = t_cancel.elapsed();
            assert_eq!(res2, Err(AuthWorkerError::Cancelled));
            assert!(
                cancel_dt <= Duration::from_millis(50),
                "real OS child shutdown took {:?} (expected <= 50 ms)",
                cancel_dt
            );
            assert!(!os_client2.is_helper_pid(real_pid));
        }

        // 6. Real `ledr-auth-helper.exe` end-to-end test via `OsWorkerSpawner` if built in target dir.
        let manifest_target = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("target");
        let current_exe = std::env::current_exe().expect("current_exe");
        let target_profile_dir = current_exe.parent().and_then(Path::parent);
        let candidates = [
            target_profile_dir.map(|d| d.join("ledr-auth-helper.exe")),
            Some(manifest_target.join("debug").join("ledr-auth-helper.exe")),
            Some(manifest_target.join("release").join("ledr-auth-helper.exe")),
        ];
        if let Some(real_helper) = candidates.into_iter().flatten().find(|p| p.is_file()) {
                let copied_helper = allowed_dir.join("ledr-auth-helper.exe");
                std::fs::copy(&real_helper, &copied_helper).expect("copy real helper");
                let real_sha =
                    ledr_rules::compute_file_sha256_hex(&copied_helper).expect("hash real helper");
                let cfg_real = AuthWorkerConfig {
                    helper_exe_override: Some(copied_helper),
                    expected_dir_override: Some(allowed_dir.clone()),
                    auth_helper_sha256: Some(real_sha),
                    idle_timeout_ms: 150,
                    ..AuthWorkerConfig::default()
                };
                let real_client = AuthWorkerClient::new(cfg_real);
                let expected = ledr_auth_helper::inspect_authenticode(Path::new(r"C:\Windows\System32\cmd.exe"));
                let got = real_client
                    .verify_cancellable(r"C:\Windows\System32\cmd.exe", &cancel)
                    .expect("real helper verify");
                assert_eq!(got, expected);

                // Wait for 150ms idle self-exit, then verify next call respawns cleanly without failing.
                std::thread::sleep(Duration::from_millis(300));
                let got_after_idle = real_client
                    .verify_cancellable(r"C:\Windows\System32\cmd.exe", &cancel)
                    .expect("real helper respawn after idle self-exit");
                assert_eq!(got_after_idle, expected);
                real_client.shutdown();
        }
    }
}
