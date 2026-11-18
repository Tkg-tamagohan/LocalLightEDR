//! ETW real-time trace sessions (`Kernel-Process`, `Kernel-File`, `Kernel-Registry`,
//! `DNS-Client`, `Kernel-Network`, `AMSI`, and PowerShell 4104) and Toolhelp32 initial process
//! snapshots (`AUTO-03`, `AUTO-06`, `AUTO-08`).

pub mod file_canary;
mod tdh;

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};

use ledr_proto::{CanaryCategory, ProcessIdentity, ScriptSource, SensorBackend, SensorEvent};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NOT_FOUND, ERROR_NO_MORE_FILES, ERROR_SUCCESS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
    TRACE_LEVEL_INFORMATION, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};

pub use self::file_canary::{
    CanaryMatcher, is_autorun_registry_key, is_autorun_registry_key_u16,
    is_autorun_registry_value_target, is_autorun_registry_value_target_u16,
    prefilter_and_classify_canary, prefilter_and_classify_canary_u16,
};
use self::tdh::{
    TdhEventInfo, filetime_100ns_to_unix_ms, inspect_process_by_pid, parse_dns_query_results,
};
use crate::dns_cache::DnsResolutionCache;
use crate::path_norm::DosVolumeMap;
use crate::{OwnedHandle, SensorError};

/// Default Windows ETW trace session name for LocalEDR real-time telemetry.
pub const DEFAULT_ETW_SESSION_NAME: &str = "LocalEDR-ETW-Session";

/// Direct callback sink receiving normalized [`SensorEvent`] values from the ETW consumer
/// without an unbounded intermediate queue (`BUG_0001`).
///
/// Returning `true` indicates the event was accepted (or intentionally shed by a bounded
/// telemetry ring) and ETW consumption should continue. Returning `false` indicates the
/// downstream receiver has closed and the ETW consumer should terminate promptly.
pub type EventSinkFn = Arc<dyn Fn(SensorEvent) -> bool + Send + Sync>;
const MAX_SESSION_NAME_CHARS: usize = 128;
const MAX_LOGFILE_NAME_CHARS: usize = 128;
const MAX_TRACKED_HONEYPOT_HANDLES: usize = 512;
const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
const KERNEL_FILE_KEYWORDS: u64 = 0x0010 | 0x0020 | 0x0080 | 0x0200 | 0x0400 | 0x0800 | 0x1000;
const KERNEL_REGISTRY_KEYWORDS: u64 = 0x0100 | 0x0200 | 0x1000 | 0x2000 | 0x4000;
const ERROR_WMI_INSTANCE_NOT_FOUND_CODE: u32 = 4201;

/// `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`).
const KERNEL_PROCESS_GUID: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// `Microsoft-Windows-Kernel-File` (`{EDD08927-9CC4-4E65-B970-C2560FB5C289}`).
const KERNEL_FILE_GUID: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// `Microsoft-Windows-Kernel-Registry` (`{70EB4F03-C1DE-4F73-A051-33D13D5413BD}`).
const KERNEL_REGISTRY_GUID: GUID = GUID::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
/// `Microsoft-Windows-DNS-Client` (`{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`).
const DNS_CLIENT_GUID: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
/// `Microsoft-Windows-Kernel-Network` (`{7DD42A49-5329-4832-8DFD-43D979153A88}`).
const KERNEL_NETWORK_GUID: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// `Microsoft-Windows-AMSI` (`{2A576B87-09A7-520E-C21A-4942F0271D67}`).
const AMSI_GUID: GUID = GUID::from_u128(0x2a576b87_09a7_520e_c21a_4942f0271d67);
/// `Microsoft-Windows-PowerShell` (`{A0C1853B-5C40-4B15-8766-3CF1C58F985A}`).
const POWERSHELL_GUID: GUID = GUID::from_u128(0xa0c1853b_5c40_4b15_8766_3cf1c58f985a);

/// Non-privileged no-op [`SensorBackend`] stub for Phase 0 scaffolding and unit tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSensorBackend;

impl SensorBackend for NoopSensorBackend {
    fn start(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        Ok(())
    }
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

#[repr(C)]
struct TracePropertiesBuffer {
    props: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; MAX_SESSION_NAME_CHARS],
    log_file_name: [u16; MAX_LOGFILE_NAME_CHARS],
}

impl TracePropertiesBuffer {
    fn new_realtime(session_name_nul: &[u16]) -> Self {
        let mut buf = Self {
            props: EVENT_TRACE_PROPERTIES::default(),
            logger_name: [0u16; MAX_SESSION_NAME_CHARS],
            log_file_name: [0u16; MAX_LOGFILE_NAME_CHARS],
        };
        buf.props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
        buf.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // ClientContext = 2 selects system time (FILETIME 100ns) for EventHeader.TimeStamp.
        buf.props.Wnode.ClientContext = 2;
        buf.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        buf.props.FlushTimer = 1;
        buf.props.BufferSize = 64;
        buf.props.MinimumBuffers = 4;
        buf.props.MaximumBuffers = 16;
        buf.props.LoggerNameOffset = std::mem::offset_of!(Self, logger_name) as u32;
        buf.props.LogFileNameOffset = 0;

        let copy_len = session_name_nul.len().min(MAX_SESSION_NAME_CHARS);
        buf.logger_name[..copy_len].copy_from_slice(&session_name_nul[..copy_len]);
        buf
    }

    fn new_control() -> Self {
        let mut buf = Self {
            props: EVENT_TRACE_PROPERTIES::default(),
            logger_name: [0u16; MAX_SESSION_NAME_CHARS],
            log_file_name: [0u16; MAX_LOGFILE_NAME_CHARS],
        };
        buf.props.Wnode.BufferSize = std::mem::size_of::<Self>() as u32;
        buf.props.LoggerNameOffset = std::mem::offset_of!(Self, logger_name) as u32;
        buf.props.LogFileNameOffset = std::mem::offset_of!(Self, log_file_name) as u32;
        buf
    }
}

struct ActiveEtwSession {
    session_handle: CONTROLTRACE_HANDLE,
    session_name_nul: Vec<u16>,
    stop_requested: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

struct TrackedHoneypotHandle {
    target_path: String,
    triggered: bool,
}

#[derive(Default)]
struct HoneypotHandleTracker {
    by_file_object: HashMap<u64, TrackedHoneypotHandle>,
    fifo_order: VecDeque<u64>,
}

impl HoneypotHandleTracker {
    fn track_open(&mut self, file_object: u64, target_path: String) -> bool {
        if file_object == 0 {
            return !self.by_file_object.is_empty();
        }
        if let Some(existing) = self.by_file_object.get_mut(&file_object) {
            existing.target_path = target_path;
            existing.triggered = false;
            return true;
        }
        while self.by_file_object.len() >= MAX_TRACKED_HONEYPOT_HANDLES {
            let Some(oldest) = self.fifo_order.pop_front() else {
                break;
            };
            self.by_file_object.remove(&oldest);
        }
        self.fifo_order.push_back(file_object);
        self.by_file_object.insert(
            file_object,
            TrackedHoneypotHandle {
                target_path,
                triggered: false,
            },
        );
        true
    }

    fn trigger_write_or_delete(&mut self, file_object: u64) -> Option<String> {
        let entry = self.by_file_object.get_mut(&file_object)?;
        if entry.triggered {
            return None;
        }
        entry.triggered = true;
        Some(entry.target_path.clone())
    }

    fn close_handle(&mut self, file_object: u64) -> bool {
        self.by_file_object.remove(&file_object);
        !self.by_file_object.is_empty()
    }
}

struct EtwCallbackContext {
    sink: EventSinkFn,
    dns_cache: Mutex<DnsResolutionCache>,
    volume_map: DosVolumeMap,
    canary_matcher: Arc<RwLock<CanaryMatcher>>,
    honeypot_handles: Mutex<HoneypotHandleTracker>,
    has_honeypot_handles: AtomicBool,
    registry_kcb_names: Mutex<HashMap<u64, String>>,
    stop_requested: Arc<AtomicBool>,
    session_name_nul: Vec<u16>,
}

/// Bound on the cached `KeyObject` -> key-path map for autorun registry keys.
/// Only autorun paths are cached, so this stays small; on overflow the cache is
/// cleared rather than grown to keep worst-case memory bounded.
const REGISTRY_KCB_CACHE_CAPACITY: usize = 4096;

impl EtwCallbackContext {
    /// Emits a decoded event directly to the bounded downstream sink.
    ///
    /// Marks `stop_requested` only once the sink returns `false` (downstream receiver closed)
    /// or if cancellation was already requested.
    fn dispatch_event(&self, event: SensorEvent) -> bool {
        if self.stop_requested.load(Ordering::Acquire) {
            return false;
        }
        if !(self.sink)(event) {
            self.stop_requested.store(true, Ordering::Release);
            return false;
        }
        true
    }

    fn track_honeypot_handle(&self, file_object: u64, target_path: String) {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let non_empty = tracker.track_open(file_object, target_path);
        self.has_honeypot_handles.store(non_empty, Ordering::Release);
    }

    fn trigger_honeypot_handle(&self, file_object: u64) -> Option<String> {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tracker.trigger_write_or_delete(file_object)
    }

    fn close_honeypot_handle(&self, file_object: u64) {
        let mut tracker = self
            .honeypot_handles
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let non_empty = tracker.close_handle(file_object);
        self.has_honeypot_handles.store(non_empty, Ordering::Release);
    }

    /// Caches an autorun registry key's KCB pointer -> path so write events whose
    /// `KeyName` arrives empty (uncached KCB name) can still be attributed.
    fn remember_registry_key(&self, key_object: u64, key_name: &str) {
        let mut cache = self
            .registry_kcb_names
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if cache.len() >= REGISTRY_KCB_CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(key_object, key_name.to_owned());
    }

    fn lookup_registry_key(&self, key_object: u64) -> Option<String> {
        self.registry_kcb_names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key_object)
            .cloned()
    }

    /// Removes and returns the cached path (used on DeleteKey, after which the
    /// KCB no longer accepts writes).
    fn take_registry_key(&self, key_object: u64) -> Option<String> {
        self.registry_kcb_names
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key_object)
    }
}

/// Real-time Windows ETW sensor backend subscribing to Process, File, Registry, DNS, Network,
/// AMSI, and PowerShell 4104 providers (`AUTO-03`, `AUTO-05`, `AUTO-06`, `AUTO-08`).
pub struct WindowsEtwSensor {
    sink: EventSinkFn,
    session_name: String,
    dev_roots: Vec<PathBuf>,
    honeypot_paths: Vec<PathBuf>,
    user_profiles: Vec<PathBuf>,
    canary_matcher: Arc<RwLock<CanaryMatcher>>,
    state: Mutex<Option<ActiveEtwSession>>,
}

impl WindowsEtwSensor {
    /// Creates a new [`WindowsEtwSensor`] emitting normalized events to `tx`.
    pub fn new(tx: mpsc::Sender<SensorEvent>) -> Self {
        Self::with_session_name(tx, DEFAULT_ETW_SESSION_NAME)
    }

    /// Creates a new [`WindowsEtwSensor`] using a custom ETW trace session name.
    pub fn with_session_name(
        tx: mpsc::Sender<SensorEvent>,
        session_name: impl Into<String>,
    ) -> Self {
        let tx = Mutex::new(tx);
        let sink: EventSinkFn = Arc::new(move |ev| {
            tx.lock()
                .unwrap_or_else(|e| e.into_inner())
                .send(ev)
                .is_ok()
        });
        Self::with_sink(sink, session_name)
    }

    /// Creates a new [`WindowsEtwSensor`] delivering events directly to `sink` (`BUG_0001`).
    pub fn with_sink(sink: EventSinkFn, session_name: impl Into<String>) -> Self {
        let user_profiles: Vec<PathBuf> = std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .into_iter()
            .collect();
        let matcher = CanaryMatcher::new(Vec::<PathBuf>::new(), Vec::<PathBuf>::new())
            .with_user_profiles(user_profiles.iter());
        Self {
            sink,
            session_name: session_name.into(),
            dev_roots: Vec::new(),
            honeypot_paths: Vec::new(),
            user_profiles,
            canary_matcher: Arc::new(RwLock::new(matcher)),
            state: Mutex::new(None),
        }
    }

    /// Configures development root directories whose `.env*` files are protected (`L-05`).
    pub fn with_dev_roots(mut self, dev_roots: Vec<PathBuf>) -> Self {
        self.set_dev_roots(dev_roots);
        self
    }

    /// Configures explicit honeypot decoy file paths in addition to the default filename (`L-06`).
    pub fn with_honeypot_paths(mut self, honeypot_paths: Vec<PathBuf>) -> Self {
        self.set_honeypot_paths(honeypot_paths);
        self
    }

    /// Configures both development roots and honeypot paths on the sensor.
    pub fn with_canary_paths(
        mut self,
        dev_roots: Vec<PathBuf>,
        honeypot_paths: Vec<PathBuf>,
    ) -> Self {
        self.dev_roots = dev_roots;
        self.honeypot_paths = honeypot_paths;
        self.rebuild_canary_matcher();
        self
    }

    /// Updates protected development root directories (safe before or after `start()`).
    pub fn set_dev_roots(&mut self, dev_roots: Vec<PathBuf>) {
        self.dev_roots = dev_roots;
        self.rebuild_canary_matcher();
    }

    /// Updates explicit honeypot decoy paths (safe before or after `start()`).
    pub fn set_honeypot_paths(&mut self, honeypot_paths: Vec<PathBuf>) {
        self.honeypot_paths = honeypot_paths;
        self.rebuild_canary_matcher();
    }

    /// Returns a snapshot of the configured [`CanaryMatcher`].
    pub fn canary_matcher(&self) -> CanaryMatcher {
        self.canary_matcher
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn rebuild_canary_matcher(&self) {
        let updated = CanaryMatcher::new(&self.dev_roots, &self.honeypot_paths)
            .with_user_profiles(&self.user_profiles);
        let mut guard = self
            .canary_matcher
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *guard = updated;
    }

    /// Returns the configured ETW session name.
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Immediately aborts ETW buffer/record processing without waiting to drain flushed buffers.
    pub fn force_abort(&mut self) {
        self.stop_with_mode(true);
    }

    fn stop_with_mode(&mut self, abort_immediately: bool) {
        let active = {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };

        if let Some(mut session) = active {
            if abort_immediately {
                // Only abort in-flight callbacks on explicit force-abort; graceful stop()
                // lets ControlTraceW flush buffered events to ProcessTrace before exiting.
                session.stop_requested.store(true, Ordering::Release);
            }
            stop_trace_session(session.session_handle, &session.session_name_nul);
            if let Some(handle) = session.worker.take() {
                let _ = handle.join();
            }
            tracing::info!(
                session = %self.session_name,
                abort_immediately,
                "ETW real-time sensor stopped"
            );
        }
    }
}

impl Drop for WindowsEtwSensor {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

impl SensorBackend for WindowsEtwSensor {
    fn start(&mut self) -> Result<(), String> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Err(SensorError::AlreadyRunning.to_string());
        }

        let session_name_nul: Vec<u16> = self
            .session_name
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .collect();
        if session_name_nul.len() > MAX_SESSION_NAME_CHARS {
            return Err(SensorError::Etw {
                session: self.session_name.clone(),
                message: format!(
                    "session name exceeds {MAX_SESSION_NAME_CHARS} UTF-16 code units"
                ),
            }
            .to_string());
        }

        let session_handle = start_or_restart_session(&self.session_name, &session_name_nul)
            .map_err(|e| e.to_string())?;

        if let Err(err) = enable_all_providers(&self.session_name, session_handle) {
            stop_trace_session(session_handle, &session_name_nul);
            return Err(err.to_string());
        }

        let sink_clone = Arc::clone(&self.sink);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let mut ctx_box = Box::new(EtwCallbackContext {
            sink: sink_clone,
            dns_cache: Mutex::new(DnsResolutionCache::default()),
            volume_map: DosVolumeMap::from_system(),
            canary_matcher: Arc::clone(&self.canary_matcher),
            honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
            has_honeypot_handles: AtomicBool::new(false),
            registry_kcb_names: Mutex::new(HashMap::new()),
            stop_requested: Arc::clone(&stop_requested),
            session_name_nul: session_name_nul.clone(),
        });

        let logger_name_ptr = ctx_box.session_name_nul.as_mut_ptr();
        let ctx_raw = Box::into_raw(ctx_box);

        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: PWSTR(logger_name_ptr),
            BufferCallback: Some(buffer_callback),
            Context: ctx_raw.cast::<c_void>(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        // SAFETY: `logfile` points to live `session_name_nul` and `ctx_raw` for the call duration.
        let trace_handle = unsafe { OpenTraceW(&mut logfile) };
        if trace_handle.Value == u64::MAX || trace_handle.Value == 0 {
            // SAFETY: `OpenTraceW` failed, so no worker thread exists; reclaim `ctx_raw`.
            unsafe { drop(Box::from_raw(ctx_raw)) };
            stop_trace_session(session_handle, &session_name_nul);
            return Err(SensorError::Etw {
                session: self.session_name.clone(),
                message: "OpenTraceW returned invalid trace handle".to_string(),
            }
            .to_string());
        }

        let ctx_addr = ctx_raw as usize;
        let trace_val = trace_handle.Value;
        let session_label = self.session_name.clone();
        let worker = thread::Builder::new()
            .name(format!("ledr-etw-{}", self.session_name))
            .spawn(move || {
                let handles = [PROCESSTRACE_HANDLE { Value: trace_val }];
                // SAFETY: `handles` holds a valid `PROCESSTRACE_HANDLE` from `OpenTraceW` and
                // `ctx_addr` remains valid until after `ProcessTrace` and `CloseTrace` complete.
                let status = unsafe { ProcessTrace(&handles, None, None) };
                if status != ERROR_SUCCESS {
                    tracing::debug!(
                        session = %session_label,
                        status = status.0,
                        "ProcessTrace exited"
                    );
                }
                // SAFETY: `trace_val` was opened via `OpenTraceW` and is closed once here.
                let _ = unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: trace_val }) };
                // SAFETY: `ProcessTrace` has returned and callbacks can no longer run.
                unsafe { drop(Box::from_raw(ctx_addr as *mut EtwCallbackContext)) };
            })
            .map_err(|err| {
                // SAFETY: thread spawn failed before consumer started.
                unsafe {
                    let _ = CloseTrace(trace_handle);
                    drop(Box::from_raw(ctx_raw));
                }
                stop_trace_session(session_handle, &session_name_nul);
                SensorError::Etw {
                    session: self.session_name.clone(),
                    message: format!("failed to spawn ETW consumer thread: {err}"),
                }
                .to_string()
            })?;

        *guard = Some(ActiveEtwSession {
            session_handle,
            session_name_nul,
            stop_requested,
            worker: Some(worker),
        });

        tracing::info!(session = %self.session_name, "ETW real-time sensor started");
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        // Leave `stop_requested` false so ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)
        // flushes remaining ETW buffers to `event_record_callback` before `ProcessTrace`
        // exits naturally (`BUG_0003`).
        self.stop_with_mode(false);
        Ok(())
    }
}

fn start_or_restart_session(
    session_name: &str,
    session_name_nul: &[u16],
) -> Result<CONTROLTRACE_HANDLE, SensorError> {
    let mut props = Box::new(TracePropertiesBuffer::new_realtime(session_name_nul));
    let mut handle = CONTROLTRACE_HANDLE::default();

    // SAFETY: `handle`, `session_name_nul`, and `props` are properly aligned and sized.
    let mut status = unsafe {
        StartTraceW(
            &mut handle,
            PCWSTR(session_name_nul.as_ptr()),
            &mut props.props,
        )
    };

    if status == ERROR_ALREADY_EXISTS {
        tracing::warn!(
            session = session_name,
            "stopping stale ETW session before restarting"
        );
        stop_trace_session(CONTROLTRACE_HANDLE::default(), session_name_nul);
        *props = TracePropertiesBuffer::new_realtime(session_name_nul);
        handle = CONTROLTRACE_HANDLE::default();
        // SAFETY: same preconditions as initial `StartTraceW`.
        status = unsafe {
            StartTraceW(
                &mut handle,
                PCWSTR(session_name_nul.as_ptr()),
                &mut props.props,
            )
        };
    }

    if status != ERROR_SUCCESS {
        return Err(SensorError::Win32 {
            api: "StartTraceW",
            message: format!("Win32 error {} for session `{session_name}`", status.0),
        });
    }

    Ok(handle)
}

fn enable_all_providers(
    session_name: &str,
    session_handle: CONTROLTRACE_HANDLE,
) -> Result<(), SensorError> {
    let providers: [(&str, &GUID, u8, u64, bool); 7] = [
        (
            "Microsoft-Windows-Kernel-Process",
            &KERNEL_PROCESS_GUID,
            TRACE_LEVEL_INFORMATION as u8,
            WINEVENT_KEYWORD_PROCESS,
            true,
        ),
        (
            "Microsoft-Windows-Kernel-File",
            &KERNEL_FILE_GUID,
            TRACE_LEVEL_INFORMATION as u8,
            KERNEL_FILE_KEYWORDS,
            true,
        ),
        (
            "Microsoft-Windows-Kernel-Registry",
            &KERNEL_REGISTRY_GUID,
            TRACE_LEVEL_INFORMATION as u8,
            KERNEL_REGISTRY_KEYWORDS,
            false,
        ),
        (
            "Microsoft-Windows-DNS-Client",
            &DNS_CLIENT_GUID,
            TRACE_LEVEL_INFORMATION as u8,
            u64::MAX,
            true,
        ),
        (
            "Microsoft-Windows-Kernel-Network",
            &KERNEL_NETWORK_GUID,
            TRACE_LEVEL_INFORMATION as u8,
            u64::MAX,
            true,
        ),
        (
            "Microsoft-Windows-AMSI",
            &AMSI_GUID,
            TRACE_LEVEL_VERBOSE as u8,
            u64::MAX,
            false,
        ),
        (
            "Microsoft-Windows-PowerShell",
            &POWERSHELL_GUID,
            TRACE_LEVEL_VERBOSE as u8,
            u64::MAX,
            true,
        ),
    ];

    for (name, guid, level, keyword, required) in providers {
        // SAFETY: `session_handle` is a valid trace session and `guid` points to a static `GUID`.
        let status = unsafe {
            EnableTraceEx2(
                session_handle,
                guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                level,
                keyword,
                0,
                0,
                None,
            )
        };
        if status != ERROR_SUCCESS {
            if !required && (status == ERROR_NOT_FOUND || status == ERROR_ACCESS_DENIED) {
                tracing::warn!(
                    provider = name,
                    status = status.0,
                    "optional ETW provider unavailable; skipping"
                );
                continue;
            }
            let detail = if status == ERROR_ACCESS_DENIED {
                "ERROR_ACCESS_DENIED (administrator/SYSTEM privileges required)"
            } else {
                "EnableTraceEx2 failed"
            };
            return Err(SensorError::Etw {
                session: session_name.to_string(),
                message: format!("{name}: {detail} (error {})", status.0),
            });
        }
    }

    Ok(())
}

fn stop_trace_session(session_handle: CONTROLTRACE_HANDLE, session_name_nul: &[u16]) {
    let mut stop_props = Box::new(TracePropertiesBuffer::new_control());
    // SAFETY: `stop_props` is properly sized with `LoggerNameOffset` / `LogFileNameOffset`.
    let status = unsafe {
        ControlTraceW(
            session_handle,
            PCWSTR(session_name_nul.as_ptr()),
            &mut stop_props.props,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
    if status != ERROR_SUCCESS && status.0 != ERROR_WMI_INSTANCE_NOT_FOUND_CODE {
        tracing::debug!(status = status.0, "ControlTraceW stop returned non-zero");
    }
}

unsafe extern "system" fn buffer_callback(logfile: *mut EVENT_TRACE_LOGFILEW) -> u32 {
    if logfile.is_null() {
        return 0;
    }
    // SAFETY: `logfile` is non-null and provided by ETW runtime.
    let ctx_ptr = unsafe { (*logfile).Context.cast::<EtwCallbackContext>() };
    if ctx_ptr.is_null() {
        return 1;
    }
    // SAFETY: `ctx_ptr` remains valid for the lifetime of `ProcessTrace`.
    let ctx = unsafe { &*ctx_ptr };
    // Return 0 only when cancellation was requested (downstream sink closed or force_abort),
    // allowing graceful stop() to drain all flushed buffers before ProcessTrace exits.
    if ctx.stop_requested.load(Ordering::Acquire) {
        0
    } else {
        1
    }
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    // SAFETY: `event_record` is non-null and valid for the callback duration.
    let record = unsafe { &*event_record };
    let ctx_ptr = record.UserContext.cast::<EtwCallbackContext>();
    if ctx_ptr.is_null() {
        return;
    }
    // SAFETY: `ctx_ptr` remains valid until after `ProcessTrace` exits.
    let ctx = unsafe { &*ctx_ptr };
    if ctx.stop_requested.load(Ordering::Acquire) {
        return;
    }

    let provider = record.EventHeader.ProviderId;
    let event_id = record.EventHeader.EventDescriptor.Id;

    let emitted = if provider == KERNEL_PROCESS_GUID {
        match event_id {
            1 => handle_process_start(record, ctx),
            2 => handle_process_stop(record),
            _ => None,
        }
    } else if provider == KERNEL_FILE_GUID {
        handle_kernel_file(record, event_id, ctx)
    } else if provider == KERNEL_REGISTRY_GUID {
        handle_kernel_registry(record, event_id, ctx)
    } else if provider == DNS_CLIENT_GUID {
        match event_id {
            3008 | 3018 | 3020 | 3006 => handle_dns_client(record, event_id, ctx),
            _ => None,
        }
    } else if provider == KERNEL_NETWORK_GUID {
        match event_id {
            12 | 28 | 42 | 58 => handle_kernel_network(record, event_id, ctx),
            _ => None,
        }
    } else if provider == AMSI_GUID && event_id == 1101 {
        handle_script_event(record, ScriptSource::Amsi, "content")
    } else if provider == POWERSHELL_GUID && event_id == 4104 {
        handle_script_event(record, ScriptSource::PowerShell4104, "ScriptBlockText")
    } else {
        None
    };

    let Some(event) = emitted else {
        return;
    };
    let _ = ctx.dispatch_event(event);
}

fn handle_process_start(record: &EVENT_RECORD, ctx: &EtwCallbackContext) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let pid = info.get_u32("ProcessID")?;
    let parent_pid = info
        .get_u32("ParentProcessID")
        .unwrap_or(record.EventHeader.ProcessId);

    let mut create_time_100ns = info.get_u64("CreateTime").unwrap_or(0);
    let mut exe_path = info
        .get_string("ImageName")
        .map(|raw| ctx.volume_map.normalize_path(&raw))
        .unwrap_or_default();
    let mut command_line = info.get_string("CommandLine").unwrap_or_default();
    let user_sid = info.get_sid_string("UserSID");

    let needs_inspect = create_time_100ns == 0 || exe_path.is_empty() || command_line.is_empty();
    let inspected = if needs_inspect {
        inspect_process_by_pid(pid, Some(&ctx.volume_map))
    } else {
        None
    };
    if let Some(inspected) = inspected {
        if create_time_100ns == 0 && inspected.create_time_100ns > 0 {
            create_time_100ns = inspected.create_time_100ns;
        }
        if exe_path.is_empty() {
            exe_path = inspected.exe_path.unwrap_or_default();
        }
        if command_line.is_empty() {
            command_line = inspected.command_line.unwrap_or_default();
        }
    }

    if create_time_100ns == 0 && record.EventHeader.TimeStamp > 0 {
        create_time_100ns = record.EventHeader.TimeStamp as u64;
    }

    Some(SensorEvent::ProcessStart {
        identity: ProcessIdentity::new(pid, create_time_100ns),
        parent_pid,
        exe_path,
        command_line,
        user_sid,
    })
}

fn handle_process_stop(record: &EVENT_RECORD) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let pid = info
        .get_u32("ProcessID")
        .unwrap_or(record.EventHeader.ProcessId);
    let exit_time_100ns = info
        .get_u64("ExitTime")
        .filter(|&t| t > 0)
        .unwrap_or_else(|| record.EventHeader.TimeStamp.max(0) as u64);
    let exit_code = info.get_u32("ExitCode").unwrap_or(0);

    Some(SensorEvent::ProcessStop {
        pid,
        exit_time_100ns,
        exit_code,
    })
}

fn handle_dns_client(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let query_name = info
        .get_string("QueryName")
        .map(|s| s.trim().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())?;

    let results_raw = info.get_string("QueryResults").unwrap_or_default();
    let resolved_ips = parse_dns_query_results(&results_raw);
    if event_id == 3006 && resolved_ips.is_empty() {
        return None;
    }

    let query_type = info
        .get_u16("QueryType")
        .or_else(|| info.get_u32("QueryType").map(|v| v as u16))
        .unwrap_or(0);
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    if !resolved_ips.is_empty() {
        let mut cache = ctx.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert_resolution(&query_name, &resolved_ips, timestamp_ms);
    }

    Some(SensorEvent::DnsQuery {
        pid: record.EventHeader.ProcessId,
        query_name,
        query_type,
        resolved_ips,
        timestamp_ms,
    })
}

fn handle_kernel_network(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let pid = info
        .get_u32("PID")
        .filter(|&p| p != 0)
        .unwrap_or(record.EventHeader.ProcessId);
    let dst_ip = info.get_ip_addr("daddr")?;
    let dst_port = info.get_port_be("dport")?;
    let protocol = if event_id == 12 || event_id == 28 { 6 } else { 17 };
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    let domain_hint = {
        let mut cache = ctx.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.lookup_domain(&dst_ip)
    };

    Some(SensorEvent::NetworkConnect {
        pid,
        protocol,
        dst_ip,
        dst_port,
        domain_hint,
        timestamp_ms,
    })
}

fn handle_script_event(
    record: &EVENT_RECORD,
    source: ScriptSource,
    field_name: &str,
) -> Option<SensorEvent> {
    let info = TdhEventInfo::from_record(record)?;
    let script_content = info.get_string(field_name).filter(|s| !s.is_empty())?;
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    Some(SensorEvent::ScriptEvaluated {
        pid: record.EventHeader.ProcessId,
        source,
        script_content,
        timestamp_ms,
    })
}

fn handle_kernel_file(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
    const WRITE_OR_DELETE_ACCESS_BITS: u32 = 0x4001_0006; // GENERIC_WRITE | DELETE | WRITE_DATA | APPEND_DATA

    match event_id {
        12 | 30 | 26 | 27 | 28 => {
            let pid = record.EventHeader.ProcessId;
            if pid == 0 || pid == u32::MAX {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            let (is_write_or_delete, access_mask) = match event_id {
                12 => {
                    let create_options = info.get_u32("CreateOptions").unwrap_or(0);
                    let desired_access = info.get_u32("DesiredAccess");
                    let disposition = (create_options >> 24) & 0xFF;
                    let write_disp = matches!(disposition, 0 | 2 | 4 | 5);
                    let delete_on_close = (create_options & FILE_DELETE_ON_CLOSE) != 0;
                    let write_access =
                        desired_access.is_some_and(|a| (a & WRITE_OR_DELETE_ACCESS_BITS) != 0);
                    (
                        write_disp || delete_on_close || write_access,
                        desired_access.unwrap_or(create_options),
                    )
                }
                30 => (true, info.get_u32("CreateOptions").unwrap_or(0)),
                _ => (true, info.get_u32("InfoClass").unwrap_or(0)),
            };

            let prop_names: &[&str] = match event_id {
                26..=28 => &["FilePath", "FileName", "OpenPath"],
                _ => &["FileName", "OpenPath", "FilePath"],
            };

            let matched = {
                let matcher = ctx.canary_matcher.read().unwrap_or_else(|e| e.into_inner());
                info.inspect_first_utf16_property(prop_names, |u16_slice| {
                    if let Some(cat) =
                        matcher.classify_u16(u16_slice, &ctx.volume_map, is_write_or_delete)
                    {
                        return Some((cat, ctx.volume_map.normalize_u16(u16_slice), false));
                    }
                    // Track read/existing opens of honeypot files without alerting so a
                    // subsequent Write/SetDelete/Rename on the same FileObject is caught (L-06).
                    if event_id == 12
                        && !is_write_or_delete
                        && matcher.is_honeypot_u16(u16_slice, &ctx.volume_map)
                    {
                        return Some((
                            CanaryCategory::Honeypot,
                            ctx.volume_map.normalize_u16(u16_slice),
                            true,
                        ));
                    }
                    None
                })?
            };

            let (category, target_path, track_only) = matched;
            if track_only {
                if let Some(file_object) = info.get_u64("FileObject") {
                    ctx.track_honeypot_handle(file_object, target_path);
                }
                return None;
            }

            let timestamp_ms =
                filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);
            Some(SensorEvent::CanaryFileAccess {
                pid,
                target_path,
                category,
                access_mask,
                is_write_or_delete,
                timestamp_ms,
            })
        }
        16 | 18 | 19 | 29 => {
            if !ctx.has_honeypot_handles.load(Ordering::Acquire) {
                return None;
            }
            let pid = record.EventHeader.ProcessId;
            if pid == 0 || pid == u32::MAX {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            let file_object = info.get_u64("FileObject")?;
            let target_path = ctx.trigger_honeypot_handle(file_object)?;
            let access_mask = info
                .get_u32("IOFlags")
                .or_else(|| info.get_u32("InfoClass"))
                .unwrap_or(event_id as u32);
            let timestamp_ms =
                filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);
            Some(SensorEvent::CanaryFileAccess {
                pid,
                target_path,
                category: CanaryCategory::Honeypot,
                access_mask,
                is_write_or_delete: true,
                timestamp_ms,
            })
        }
        14 => {
            if !ctx.has_honeypot_handles.load(Ordering::Acquire) {
                return None;
            }
            let info = TdhEventInfo::from_record(record)?;
            if let Some(file_object) = info.get_u64("FileObject") {
                ctx.close_honeypot_handle(file_object);
            }
            None
        }
        _ => None,
    }
}

fn handle_kernel_registry(
    record: &EVENT_RECORD,
    event_id: u16,
    ctx: &EtwCallbackContext,
) -> Option<SensorEvent> {
    if !matches!(event_id, 1 | 2 | 3 | 5 | 6) {
        return None;
    }
    let pid = record.EventHeader.ProcessId;
    if pid == 0 || pid == u32::MAX {
        return None;
    }
    let info = TdhEventInfo::from_record(record)?;
    let key_object = info.get_u64("KeyObject");

    // Event 1 (CreateKey) also fires when `RegCreateKeyEx`/`NtCreateKey` merely opens an
    // existing key (`Disposition` = `REG_OPENED_EXISTING_KEY`), and event 2 (OpenKey)
    // covers plain `RegOpenKeyEx`/`NtOpenKey`. Only a genuinely new key under an autorun
    // location is a persistence write, so opens never alert; instead their resolved
    // autorun path is cached under `KeyObject` (which is stable for the opened handle)
    // so that later SetValue/DeleteValue/DeleteKey events on the same handle — whose
    // `KeyName` arrives empty when the KCB name is not yet populated — can still be
    // attributed.
    const REG_CREATED_NEW_KEY: u32 = 0x0000_0001;
    let key_name = if matches!(event_id, 1 | 2) {
        let key_name = info
            .inspect_first_utf16_property(&["KeyName"], |u16_slice| {
                if is_autorun_registry_key_u16(u16_slice) {
                    Some(String::from_utf16_lossy(u16_slice))
                } else {
                    None
                }
            })
            .or_else(|| {
                info.inspect_joined_utf16_properties("BaseName", "RelativeName", |u16_slice| {
                    if is_autorun_registry_key_u16(u16_slice) {
                        Some(String::from_utf16_lossy(u16_slice))
                    } else {
                        None
                    }
                })
            });
        if let (Some(key_object), Some(key_name)) = (key_object, key_name.as_deref()) {
            // Cache only value-write-relevant autorun keys so the map stays small and is
            // not churned by constant `Services\*` traffic.
            if is_autorun_registry_value_target(key_name) {
                ctx.remember_registry_key(key_object, key_name);
            }
        }
        if event_id == 2
            || info
                .get_u32("Disposition")
                .is_some_and(|disposition| disposition != REG_CREATED_NEW_KEY)
        {
            return None;
        }
        key_name?
    } else {
        let via_key_name = info.inspect_first_utf16_property(&["KeyName"], |u16_slice| {
            if is_autorun_registry_key_u16(u16_slice) {
                Some(String::from_utf16_lossy(u16_slice))
            } else {
                None
            }
        });
        match (via_key_name, key_object) {
            (Some(key_name), Some(key_object)) => {
                if event_id == 3 {
                    ctx.take_registry_key(key_object);
                } else if is_autorun_registry_value_target(&key_name) {
                    ctx.remember_registry_key(key_object, &key_name);
                }
                key_name
            }
            (Some(key_name), None) => key_name,
            (None, Some(key_object)) => {
                if event_id == 3 {
                    ctx.take_registry_key(key_object)?
                } else {
                    ctx.lookup_registry_key(key_object)?
                }
            }
            (None, None) => return None,
        }
    };

    // Value writes only matter under the persistence locations where the written value is
    // itself the payload (Run/RunOnce entries, Winlogon shell/userinit). Existing
    // `Services\*` keys see constant benign churn (e.g. `Tcpip\Parameters`), so writes
    // there are not alerted on; service persistence stays covered by new-key creation.
    if matches!(event_id, 5 | 6) && !is_autorun_registry_value_target(&key_name) {
        return None;
    }

    let target_path = if matches!(event_id, 5 | 6) {
        match info.get_string("ValueName").filter(|v| !v.is_empty()) {
            Some(value_name) => format!("{key_name}\\{value_name}"),
            None => key_name,
        }
    } else {
        key_name
    };

    let access_mask = info
        .get_u32("Disposition")
        .or_else(|| info.get_u32("Type"))
        .unwrap_or(event_id as u32);
    let timestamp_ms = filetime_100ns_to_unix_ms(record.EventHeader.TimeStamp.max(0) as u64);

    Some(SensorEvent::CanaryFileAccess {
        pid,
        target_path,
        category: CanaryCategory::AutorunRegistry,
        access_mask,
        is_write_or_delete: true,
        timestamp_ms,
    })
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn assert_snapshot_contains_current_process(events: &[SensorEvent], source: &str) {
        let current_pid = std::process::id();
        assert!(
            !events.is_empty(),
            "{source}: expected Toolhelp32 snapshot to list running processes"
        );

        let current_entry = events.iter().find_map(|event| match event {
            SensorEvent::ProcessStart {
                identity, exe_path, ..
            } if identity.pid == current_pid => Some((identity, exe_path)),
            _ => None,
        });

        let (identity, exe_path) =
            current_entry.unwrap_or_else(|| panic!("current PID must appear in {source}"));
        assert!(
            identity.create_time_100ns > 0,
            "current process create_time_100ns must be > 0"
        );
        assert!(
            !exe_path.is_empty(),
            "current process exe_path must be non-empty"
        );
    }

    #[test]
    fn sens_03_capture_running_processes_current_pid() {
        let events = capture_running_processes();
        assert_snapshot_contains_current_process(&events, "capture_running_processes()");
    }

    #[test]
    fn sens_07_try_capture_running_processes_non_empty() {
        let events = try_capture_running_processes()
            .expect("try_capture_running_processes() must succeed on a live host");
        assert_snapshot_contains_current_process(&events, "try_capture_running_processes()");

        let err = SensorError::Snapshot("enumerated 0 running processes".to_string());
        assert_eq!(
            err.to_string(),
            "process snapshot failed: enumerated 0 running processes"
        );
        assert_eq!(
            windows::core::Error::from(ERROR_NO_MORE_FILES).code(),
            ERROR_NO_MORE_FILES.to_hresult()
        );
    }

    #[test]
    fn sens_etw_dns_results_parser_and_noop_backend() {
        let mut noop = NoopSensorBackend;
        assert_eq!(noop.start(), Ok(()));
        assert_eq!(noop.stop(), Ok(()));

        let parsed = parse_dns_query_results(
            "type:  1 93.184.216.34;type: 28 2606:2800:220:1:248:1893:25c8:1946;",
        );
        assert_eq!(
            parsed,
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V6(Ipv6Addr::new(
                    0x2606, 0x2800, 0x0220, 0x0001, 0x0248, 0x1893, 0x25c8, 0x1946
                )),
            ]
        );
    }

    #[test]
    fn sens_06_custom_sink_and_graceful_stop_drain() {
        let captured = Arc::new(Mutex::new(Vec::<SensorEvent>::new()));
        let sink_open = Arc::new(AtomicBool::new(true));
        let captured_clone = Arc::clone(&captured);
        let sink_open_clone = Arc::clone(&sink_open);

        let sink: EventSinkFn = Arc::new(move |event| {
            if !sink_open_clone.load(Ordering::Acquire) {
                return false;
            }
            captured_clone
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(event);
            true
        });

        let mut sensor = WindowsEtwSensor::with_sink(sink, "LocalEDR-Custom-Sink-Test");
        assert_eq!(sensor.session_name(), "LocalEDR-Custom-Sink-Test");
        assert_eq!(sensor.stop(), Ok(()));

        // Backwards-compatible mpsc::Sender constructors delegate to the EventSinkFn path.
        let (tx, rx) = mpsc::channel();
        let legacy_sensor = WindowsEtwSensor::new(tx);
        assert_eq!(legacy_sensor.session_name(), DEFAULT_ETW_SESSION_NAME);
        let sample_start = SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(4242, 123_456),
            parent_pid: 4,
            exe_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
            command_line: "cmd.exe /c echo ok".to_string(),
            user_sid: None,
        };
        assert!((legacy_sensor.sink)(sample_start.clone()));
        assert!(rx.try_recv().is_ok());
        drop(rx);
        assert!(!(legacy_sensor.sink)(sample_start.clone()));

        let (tx2, _rx2) = mpsc::channel();
        let named_legacy = WindowsEtwSensor::with_session_name(tx2, "LocalEDR-Legacy-Named");
        assert_eq!(named_legacy.session_name(), "LocalEDR-Legacy-Named");

        // Verify graceful stop() does NOT set stop_requested before draining flushed buffers.
        let stop_requested = Arc::new(AtomicBool::new(false));
        let session_name_nul: Vec<u16> =
            format!("LocalEDR-UnitTest-Drain-{}", std::process::id())
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .collect();

        let worker_ctx = EtwCallbackContext {
            sink: Arc::clone(&sensor.sink),
            dns_cache: Mutex::new(DnsResolutionCache::default()),
            volume_map: DosVolumeMap::with_mappings(Vec::new()),
            canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
            honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
            has_honeypot_handles: AtomicBool::new(false),
            registry_kcb_names: Mutex::new(HashMap::new()),
            stop_requested: Arc::clone(&stop_requested),
            session_name_nul: session_name_nul.clone(),
        };
        let flushed_start = sample_start.clone();
        let flushed_dns = SensorEvent::DnsQuery {
            pid: 4242,
            query_name: "example.com".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 1_700_000_000_000,
        };
        let worker = thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(20));
            let mut ctx_box = Box::new(worker_ctx);
            let mut logfile = EVENT_TRACE_LOGFILEW {
                Context: (&mut *ctx_box as *mut EtwCallbackContext).cast::<c_void>(),
                ..Default::default()
            };
            // SAFETY: `logfile.Context` points to live `ctx_box`.
            assert_eq!(unsafe { buffer_callback(&mut logfile) }, 1);
            assert!(ctx_box.dispatch_event(flushed_start));
            assert!(ctx_box.dispatch_event(flushed_dns));
            assert_eq!(unsafe { buffer_callback(&mut logfile) }, 1);
        });

        {
            let mut guard = sensor.state.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(ActiveEtwSession {
                session_handle: CONTROLTRACE_HANDLE::default(),
                session_name_nul: session_name_nul.clone(),
                stop_requested: Arc::clone(&stop_requested),
                worker: Some(worker),
            });
        }

        assert_eq!(sensor.stop(), Ok(()));
        assert!(
            !stop_requested.load(Ordering::Acquire),
            "graceful stop() must leave stop_requested false while draining flushed buffers"
        );
        assert_eq!(
            captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            2,
            "all flushed events must be delivered during graceful stop()"
        );

        // Verify stop_requested flips to true ONLY once the downstream sink returns false.
        let mut post_ctx = Box::new(EtwCallbackContext {
            sink: Arc::clone(&sensor.sink),
            dns_cache: Mutex::new(DnsResolutionCache::default()),
            volume_map: DosVolumeMap::with_mappings(Vec::new()),
            canary_matcher: Arc::new(RwLock::new(CanaryMatcher::default())),
            honeypot_handles: Mutex::new(HoneypotHandleTracker::default()),
            has_honeypot_handles: AtomicBool::new(false),
            registry_kcb_names: Mutex::new(HashMap::new()),
            stop_requested: Arc::clone(&stop_requested),
            session_name_nul: session_name_nul.clone(),
        });
        let mut post_logfile = EVENT_TRACE_LOGFILEW {
            Context: (&mut *post_ctx as *mut EtwCallbackContext).cast::<c_void>(),
            ..Default::default()
        };
        // SAFETY: `post_logfile.Context` points to live `post_ctx`.
        assert_eq!(unsafe { buffer_callback(&mut post_logfile) }, 1);

        sink_open.store(false, Ordering::Release);
        assert!(!post_ctx.dispatch_event(sample_start.clone()));
        assert!(
            stop_requested.load(Ordering::Acquire),
            "stop_requested must flip true once downstream sink returns false"
        );
        // SAFETY: `post_logfile.Context` points to live `post_ctx`.
        assert_eq!(
            unsafe { buffer_callback(&mut post_logfile) },
            0,
            "buffer_callback must return 0 once downstream sink closed"
        );

        // Even if the sink flag flips back, dispatch_event stays latched closed.
        sink_open.store(true, Ordering::Release);
        assert!(!post_ctx.dispatch_event(sample_start));
        assert_eq!(
            captured
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len(),
            2
        );

        // Verify explicit force_abort() sets stop_requested before joining worker.
        let abort_flag = Arc::new(AtomicBool::new(false));
        {
            let mut guard = sensor.state.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(ActiveEtwSession {
                session_handle: CONTROLTRACE_HANDLE::default(),
                session_name_nul,
                stop_requested: Arc::clone(&abort_flag),
                worker: Some(thread::spawn(|| {})),
            });
        }
        sensor.force_abort();
        assert!(abort_flag.load(Ordering::Acquire));
    }

    #[test]
    fn sens_etw_canary_config_tdh_bytes_and_honeypot_tracker() {
        use windows::Win32::System::Diagnostics::Etw::TDH_INTYPE_UNICODESTRING;

        let (tx, _rx) = mpsc::channel();
        let sensor = WindowsEtwSensor::new(tx)
            .with_dev_roots(vec![PathBuf::from(r"D:\Code\secret")])
            .with_honeypot_paths(vec![PathBuf::from(r"D:\Decoy\trap.docx")]);
        let matcher = sensor.canary_matcher();
        assert_eq!(matcher.dev_root_count(), 1);
        assert_eq!(matcher.honeypot_path_count(), 1);

        let vmap = DosVolumeMap::with_mappings(vec![(
            r"\Device\HarddiskVolume4".encode_utf16().collect(),
            "D:".to_string(),
        )]);

        let to_utf16_bytes = |s: &str| -> Vec<u8> {
            let mut out = Vec::new();
            for unit in s.encode_utf16().chain(std::iter::once(0u16)) {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out
        };

        let benign_bytes = to_utf16_bytes(r"\Device\HarddiskVolume4\Windows\System32\ntdll.dll");
        assert_eq!(
            tdh::inspect_and_classify_canary_bytes(
                &benign_bytes,
                TDH_INTYPE_UNICODESTRING.0 as u16,
                &matcher,
                &vmap,
                false,
            ),
            None
        );

        let env_bytes = to_utf16_bytes(r"\Device\HarddiskVolume4\Code\secret\.env.prod");
        assert_eq!(
            tdh::inspect_and_classify_canary_bytes(
                &env_bytes,
                TDH_INTYPE_UNICODESTRING.0 as u16,
                &matcher,
                &vmap,
                false,
            ),
            Some((CanaryCategory::EnvFile, r"D:\Code\secret\.env.prod".to_string()))
        );

        // Verify FileObject tracking only triggers once on write/delete and clears on close.
        let mut tracker = HoneypotHandleTracker::default();
        assert!(tracker.track_open(0xABCD, r"C:\Users\alice\Documents\!00.docx".to_string()));
        assert_eq!(
            tracker.trigger_write_or_delete(0xABCD),
            Some(r"C:\Users\alice\Documents\!00.docx".to_string())
        );
        assert_eq!(tracker.trigger_write_or_delete(0xABCD), None);
        assert!(!tracker.close_handle(0xABCD));
    }
}
