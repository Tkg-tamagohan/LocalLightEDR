//! ETW trace session lifecycle, Win32 session control, and `WindowsEtwSensor`.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};

use ledr_proto::{SensorBackend, SensorEvent};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_NOT_FOUND, ERROR_SUCCESS,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
    TRACE_LEVEL_INFORMATION, TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};

use crate::dns_cache::DnsResolutionCache;
use crate::path_norm::DosVolumeMap;
use crate::SensorError;

use super::context::{EtwCallbackContext, HoneypotHandleTracker};
use super::file_canary::CanaryMatcher;
use super::handlers::{
    AMSI_GUID, DNS_CLIENT_GUID, KERNEL_FILE_GUID, KERNEL_FILE_KEYWORDS, KERNEL_NETWORK_GUID,
    KERNEL_PROCESS_GUID, KERNEL_REGISTRY_GUID, KERNEL_REGISTRY_KEYWORDS, POWERSHELL_GUID,
    WINEVENT_KEYWORD_PROCESS, buffer_callback, event_record_callback,
};

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
const ERROR_WMI_INSTANCE_NOT_FOUND_CODE: u32 = 4201;

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

pub(super) struct ActiveEtwSession {
    pub(super) session_handle: CONTROLTRACE_HANDLE,
    pub(super) session_name_nul: Vec<u16>,
    pub(super) stop_requested: Arc<AtomicBool>,
    pub(super) worker: Option<JoinHandle<()>>,
}

/// Real-time Windows ETW sensor backend subscribing to Process, File, Registry, DNS, Network,
/// AMSI, and PowerShell 4104 providers (`AUTO-03`, `AUTO-05`, `AUTO-06`, `AUTO-08`).
pub struct WindowsEtwSensor {
    pub(super) sink: EventSinkFn,
    session_name: String,
    dev_roots: Vec<PathBuf>,
    honeypot_paths: Vec<PathBuf>,
    user_profiles: Vec<PathBuf>,
    canary_matcher: Arc<RwLock<CanaryMatcher>>,
    pub(super) state: Mutex<Option<ActiveEtwSession>>,
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
