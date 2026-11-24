//! Windows Service Control Manager (SCM) integration for `ledr-daemon`.
//!
//! Implements the Win32 `LocalEDR` service dispatcher (`StartServiceCtrlDispatcherW`),
//! control handler (`RegisterServiceCtrlHandlerExW` / `ServiceCtrlHandlerExW`),
//! status reporting (`SetServiceStatus`), and a pure-Rust state machine for
//! deterministic unit testing without SCM elevation.

use std::ffi::c_void;
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use tokio::sync::watch;
use windows::core::{Error as WinError, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_GEN_FAILURE,
    ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    ENUM_SERVICE_TYPE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

/// Registered Windows Service name for `ledr-daemon`.
pub const SERVICE_NAME: &str = "LocalEDR";

/// Initial `dwWaitHint` (ms) reported while transitioning through `SERVICE_START_PENDING`.
pub const START_PENDING_WAIT_HINT_MS: u32 = 10_000;

/// `dwWaitHint` (ms) reported while draining shutdown in `SERVICE_STOP_PENDING`.
pub const STOP_PENDING_WAIT_HINT_MS: u32 = 5_000;

/// Process exit code returned when `--service` is launched outside Windows SCM (`1063`).
pub const NON_SCM_EXIT_CODE: u8 = 2;

type BoxedServiceEntrypoint =
    Box<dyn FnOnce(ServiceControlHandle) -> anyhow::Result<()> + Send + 'static>;

struct PendingLaunch {
    entrypoint: BoxedServiceEntrypoint,
    result_slot: Arc<Mutex<Option<Result<(), ServiceRunError>>>>,
}

static PENDING_ENTRYPOINT: Mutex<Option<PendingLaunch>> = Mutex::new(None);
static ACTIVE_BRIDGE: Mutex<Option<Arc<ServiceRuntimeBridge>>> = Mutex::new(None);

/// Lifecycle phase of the Windows Service status state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePhase {
    Uninitialized,
    StartPending,
    Running,
    StopPending,
    Stopped,
}

/// Final service exit status reported in `SERVICE_STOPPED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceExitStatus {
    Clean,
    Failure(u32),
}

/// Pure-Rust representation of Win32 `SERVICE_STATUS` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatusSnapshot {
    pub phase: ServicePhase,
    pub service_type: u32,
    pub current_state: u32,
    pub controls_accepted: u32,
    pub win32_exit_code: u32,
    pub service_specific_exit_code: u32,
    pub check_point: u32,
    pub wait_hint: u32,
}

impl ServiceStatusSnapshot {
    fn to_win32_status(self) -> SERVICE_STATUS {
        SERVICE_STATUS {
            dwServiceType: ENUM_SERVICE_TYPE(self.service_type),
            dwCurrentState: SERVICE_STATUS_CURRENT_STATE(self.current_state),
            dwControlsAccepted: self.controls_accepted,
            dwWin32ExitCode: self.win32_exit_code,
            dwServiceSpecificExitCode: self.service_specific_exit_code,
            dwCheckPoint: self.check_point,
            dwWaitHint: self.wait_hint,
        }
    }
}

/// Result of applying a Win32 control code to [`ServiceStatusMachine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlDecision {
    pub return_code: u32,
    pub trigger_shutdown: bool,
    pub status_to_report: Option<ServiceStatusSnapshot>,
}

/// Deterministic state machine enforcing valid SCM status transitions and checkpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatusMachine {
    snapshot: ServiceStatusSnapshot,
}

impl Default for ServiceStatusMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceStatusMachine {
    /// Creates a new uninitialized service status state machine.
    pub fn new() -> Self {
        Self {
            snapshot: ServiceStatusSnapshot {
                phase: ServicePhase::Uninitialized,
                service_type: SERVICE_WIN32_OWN_PROCESS.0,
                current_state: SERVICE_STOPPED.0,
                controls_accepted: 0,
                win32_exit_code: NO_ERROR.0,
                service_specific_exit_code: 0,
                check_point: 0,
                wait_hint: 0,
            },
        }
    }

    /// Returns the current [`ServiceStatusSnapshot`].
    pub fn snapshot(&self) -> ServiceStatusSnapshot {
        self.snapshot
    }

    /// Transitions `Uninitialized -> StartPending` with `dwControlsAccepted = 0`.
    pub fn begin_start_pending(&mut self) -> Option<ServiceStatusSnapshot> {
        if self.snapshot.phase != ServicePhase::Uninitialized {
            return None;
        }
        self.snapshot.phase = ServicePhase::StartPending;
        self.snapshot.current_state = SERVICE_START_PENDING.0;
        self.snapshot.controls_accepted = 0;
        self.snapshot.win32_exit_code = NO_ERROR.0;
        self.snapshot.service_specific_exit_code = 0;
        self.snapshot.check_point = 1;
        self.snapshot.wait_hint = START_PENDING_WAIT_HINT_MS;
        Some(self.snapshot)
    }

    /// Advances the `dwCheckPoint` while remaining in `StartPending`.
    pub fn advance_start_pending(&mut self) -> Option<ServiceStatusSnapshot> {
        if self.snapshot.phase != ServicePhase::StartPending {
            return None;
        }
        self.snapshot.check_point = self.snapshot.check_point.saturating_add(1).max(1);
        Some(self.snapshot)
    }

    /// Transitions `StartPending -> Running` and enables `STOP | SHUTDOWN` controls.
    ///
    /// Guards against regressing if the service is already `Running`, `StopPending`,
    /// or `Stopped`.
    pub fn mark_running(&mut self) -> Option<ServiceStatusSnapshot> {
        if self.snapshot.phase != ServicePhase::StartPending {
            return None;
        }
        self.snapshot.phase = ServicePhase::Running;
        self.snapshot.current_state = SERVICE_RUNNING.0;
        self.snapshot.controls_accepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        self.snapshot.win32_exit_code = NO_ERROR.0;
        self.snapshot.service_specific_exit_code = 0;
        self.snapshot.check_point = 0;
        self.snapshot.wait_hint = 0;
        Some(self.snapshot)
    }

    /// Processes a Win32 `HandlerEx` control code.
    pub fn handle_control_code(&mut self, control: u32) -> ControlDecision {
        match control {
            SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => match self.snapshot.phase {
                ServicePhase::StartPending | ServicePhase::Running => {
                    let next_checkpoint = if self.snapshot.phase == ServicePhase::StartPending {
                        self.snapshot.check_point.saturating_add(1).max(1)
                    } else {
                        1
                    };
                    self.snapshot.phase = ServicePhase::StopPending;
                    self.snapshot.current_state = SERVICE_STOP_PENDING.0;
                    self.snapshot.controls_accepted = 0;
                    self.snapshot.win32_exit_code = NO_ERROR.0;
                    self.snapshot.service_specific_exit_code = 0;
                    self.snapshot.check_point = next_checkpoint;
                    self.snapshot.wait_hint = STOP_PENDING_WAIT_HINT_MS;
                    ControlDecision {
                        return_code: NO_ERROR.0,
                        trigger_shutdown: true,
                        status_to_report: Some(self.snapshot),
                    }
                }
                ServicePhase::StopPending => {
                    self.snapshot.check_point = self.snapshot.check_point.saturating_add(1).max(1);
                    self.snapshot.controls_accepted = 0;
                    self.snapshot.wait_hint = STOP_PENDING_WAIT_HINT_MS;
                    ControlDecision {
                        return_code: NO_ERROR.0,
                        trigger_shutdown: false,
                        status_to_report: Some(self.snapshot),
                    }
                }
                ServicePhase::Uninitialized | ServicePhase::Stopped => ControlDecision {
                    return_code: NO_ERROR.0,
                    trigger_shutdown: false,
                    status_to_report: None,
                },
            },
            SERVICE_CONTROL_INTERROGATE => {
                let status_to_report = if self.snapshot.phase == ServicePhase::Uninitialized {
                    None
                } else {
                    Some(self.snapshot)
                };
                ControlDecision {
                    return_code: NO_ERROR.0,
                    trigger_shutdown: false,
                    status_to_report,
                }
            }
            _ => ControlDecision {
                return_code: ERROR_CALL_NOT_IMPLEMENTED.0,
                trigger_shutdown: false,
                status_to_report: None,
            },
        }
    }

    /// Transitions any active phase to `Stopped` (idempotent once `Stopped`).
    pub fn mark_stopped(&mut self, exit: ServiceExitStatus) -> Option<ServiceStatusSnapshot> {
        if self.snapshot.phase == ServicePhase::Stopped {
            return None;
        }
        self.snapshot.phase = ServicePhase::Stopped;
        self.snapshot.current_state = SERVICE_STOPPED.0;
        self.snapshot.controls_accepted = 0;
        self.snapshot.check_point = 0;
        self.snapshot.wait_hint = 0;
        match exit {
            ServiceExitStatus::Clean => {
                self.snapshot.win32_exit_code = NO_ERROR.0;
                self.snapshot.service_specific_exit_code = 0;
            }
            ServiceExitStatus::Failure(code) => {
                self.snapshot.win32_exit_code = ERROR_SERVICE_SPECIFIC_ERROR.0;
                self.snapshot.service_specific_exit_code = code.max(1);
            }
        }
        Some(self.snapshot)
    }
}

/// Errors produced when starting or running `ledr-daemon` as a Windows Service.
#[derive(Debug)]
pub enum ServiceRunError {
    /// `StartServiceCtrlDispatcherW` failed with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (`1063`).
    NotStartedByScm,
    /// `StartServiceCtrlDispatcherW` failed with another Win32 error.
    DispatcherFailed(WinError),
    /// Another service lifecycle is already active in this process.
    ServiceAlreadyRunning,
    /// Service registration or daemon entrypoint returned an error.
    EntrypointFailed(anyhow::Error),
    /// A panic occurred inside the service entrypoint FFI boundary.
    ServicePanicked,
}

impl fmt::Display for ServiceRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStartedByScm => write!(
                f,
                "process was not started by the Windows Service Control Manager (error 1063)"
            ),
            Self::DispatcherFailed(err) => {
                write!(f, "StartServiceCtrlDispatcherW failed: {err}")
            }
            Self::ServiceAlreadyRunning => {
                write!(f, "Windows service dispatcher is already active in this process")
            }
            Self::EntrypointFailed(err) => write!(f, "{err:#}"),
            Self::ServicePanicked => write!(f, "service entrypoint panicked"),
        }
    }
}

impl std::error::Error for ServiceRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DispatcherFailed(err) => Some(err),
            Self::EntrypointFailed(err) => Some(err.as_ref()),
            Self::NotStartedByScm | Self::ServiceAlreadyRunning | Self::ServicePanicked => None,
        }
    }
}

/// Returns `true` when `err` represents `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (`1063`).
pub fn is_non_scm_connect_error(err: &WinError) -> bool {
    err.code() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult()
}

/// `SERVICE_STATUS_HANDLE` wraps `*mut c_void`; SCM handles are process-wide opaque tokens
/// without thread affinity and are never closed with `CloseHandle`.
#[derive(Clone, Copy)]
struct SendSyncServiceStatusHandle(SERVICE_STATUS_HANDLE);

unsafe impl Send for SendSyncServiceStatusHandle {}
unsafe impl Sync for SendSyncServiceStatusHandle {}

trait StatusSink: Send {
    fn report(&mut self, snapshot: &ServiceStatusSnapshot) -> Result<(), WinError>;
}

struct Win32StatusSink(SendSyncServiceStatusHandle);

impl StatusSink for Win32StatusSink {
    fn report(&mut self, snapshot: &ServiceStatusSnapshot) -> Result<(), WinError> {
        let status = snapshot.to_win32_status();
        unsafe { SetServiceStatus(self.0 .0, &status) }
    }
}

struct BridgeInner {
    machine: ServiceStatusMachine,
    sink: Box<dyn StatusSink>,
}

struct ServiceRuntimeBridge {
    inner: Mutex<BridgeInner>,
    shutdown_tx: watch::Sender<bool>,
}

impl ServiceRuntimeBridge {
    fn new(sink: Box<dyn StatusSink>) -> Arc<Self> {
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        Arc::new(Self {
            inner: Mutex::new(BridgeInner {
                machine: ServiceStatusMachine::new(),
                sink,
            }),
            shutdown_tx,
        })
    }

    fn begin_start_pending(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(snap) = guard.machine.begin_start_pending() {
            if let Err(err) = guard.sink.report(&snap) {
                tracing::warn!(error = %err, "SetServiceStatus(SERVICE_START_PENDING) failed");
            }
        }
    }

    fn mark_running(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(snap) = guard.machine.mark_running() {
            if let Err(err) = guard.sink.report(&snap) {
                tracing::warn!(error = %err, "SetServiceStatus(SERVICE_RUNNING) failed");
            }
        }
    }

    fn handle_control(&self, control: u32) -> u32 {
        let decision = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let decision = guard.machine.handle_control_code(control);
            if let Some(ref snap) = decision.status_to_report {
                if let Err(err) = guard.sink.report(snap) {
                    tracing::warn!(
                        error = %err,
                        control,
                        state = snap.current_state,
                        "SetServiceStatus failed during control handling"
                    );
                }
            }
            decision
        };
        if decision.trigger_shutdown {
            let _ = self.shutdown_tx.send(true);
        }
        decision.return_code
    }

    fn report_stopped(&self, exit: ServiceExitStatus) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(snap) = guard.machine.mark_stopped(exit) {
            if let Err(err) = guard.sink.report(&snap) {
                tracing::warn!(error = %err, "SetServiceStatus(SERVICE_STOPPED) failed");
            }
        }
    }

    fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }
}

/// Handle passed to the daemon entrypoint for reporting readiness and receiving SCM stop signals.
#[derive(Clone)]
pub struct ServiceControlHandle {
    bridge: Arc<ServiceRuntimeBridge>,
}

impl ServiceControlHandle {
    /// Transitions SCM status from `SERVICE_START_PENDING` to `SERVICE_RUNNING`.
    pub fn mark_running(&self) {
        self.bridge.mark_running();
    }

    /// Returns a `watch::Receiver<bool>` that becomes `true` when SCM sends `STOP` or `SHUTDOWN`.
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.bridge.shutdown_receiver()
    }
}

fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct PendingCleanupGuard;

impl Drop for PendingCleanupGuard {
    fn drop(&mut self) {
        {
            let mut pending = PENDING_ENTRYPOINT.lock().unwrap_or_else(|e| e.into_inner());
            *pending = None;
        }
        {
            let mut active = ACTIVE_BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
            *active = None;
        }
    }
}

struct ActiveBridgeGuard;

impl Drop for ActiveBridgeGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE_BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
        *active = None;
    }
}

/// Connects to the Windows Service Control Manager (`StartServiceCtrlDispatcherW`) for
/// [`SERVICE_NAME`] (`"LocalEDR"`) and runs `entrypoint` inside `service_main`.
///
/// The caller's `entrypoint` must drop its Tokio runtime (if any) before returning so that
/// `SERVICE_STOPPED` is only reported after all runtime worker threads have unwound.
pub fn run_windows_service<F>(entrypoint: F) -> Result<(), ServiceRunError>
where
    F: FnOnce(ServiceControlHandle) -> anyhow::Result<()> + Send + 'static,
{
    let result_slot = Arc::new(Mutex::new(None));
    {
        let mut pending = PENDING_ENTRYPOINT.lock().unwrap_or_else(|e| e.into_inner());
        let active = ACTIVE_BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
        if pending.is_some() || active.is_some() {
            return Err(ServiceRunError::ServiceAlreadyRunning);
        }
        *pending = Some(PendingLaunch {
            entrypoint: Box::new(entrypoint),
            result_slot: Arc::clone(&result_slot),
        });
    }
    let _cleanup_guard = PendingCleanupGuard;

    let service_name_w = encode_wide_nul(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name_w.as_ptr() as *mut u16),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    if let Err(err) = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        if is_non_scm_connect_error(&err) {
            return Err(ServiceRunError::NotStartedByScm);
        }
        return Err(ServiceRunError::DispatcherFailed(err));
    }

    let outcome = result_slot.lock().unwrap_or_else(|e| e.into_inner()).take();
    outcome.unwrap_or_else(|| {
        Err(ServiceRunError::EntrypointFailed(anyhow::anyhow!(
            "Windows service entrypoint exited without reporting a result"
        )))
    })
}

fn run_bridge_with_panic_barrier<F>(
    bridge: &Arc<ServiceRuntimeBridge>,
    entrypoint: F,
) -> (ServiceExitStatus, Result<(), ServiceRunError>)
where
    F: FnOnce(ServiceControlHandle) -> anyhow::Result<()>,
{
    let control = ServiceControlHandle {
        bridge: Arc::clone(bridge),
    };
    let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        entrypoint(control)
    }));
    let (exit_status, run_result) = match panic_res {
        Ok(Ok(())) => (ServiceExitStatus::Clean, Ok(())),
        Ok(Err(err)) => (
            ServiceExitStatus::Failure(1),
            Err(ServiceRunError::EntrypointFailed(err)),
        ),
        Err(_) => {
            tracing::error!("panic caught at Windows service_main FFI boundary");
            (
                ServiceExitStatus::Failure(2),
                Err(ServiceRunError::ServicePanicked),
            )
        }
    };
    bridge.report_stopped(exit_status);
    (exit_status, run_result)
}

fn dispatch_control_with_panic_barrier<F>(control: u32, handler: F) -> u32
where
    F: FnOnce() -> u32,
{
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(handler));
    match res {
        Ok(code) => code,
        Err(_) => {
            tracing::error!(
                control,
                "panic caught at Windows service_ctrl_handler FFI boundary"
            );
            ERROR_GEN_FAILURE.0
        }
    }
}

fn register_win32_bridge() -> anyhow::Result<Arc<ServiceRuntimeBridge>> {
    let service_name_w = encode_wide_nul(SERVICE_NAME);
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR(service_name_w.as_ptr()),
            Some(service_ctrl_handler),
            None,
        )
    }
    .context("RegisterServiceCtrlHandlerExW failed")?;

    let bridge = ServiceRuntimeBridge::new(Box::new(Win32StatusSink(
        SendSyncServiceStatusHandle(handle),
    )));
    {
        let mut active = ACTIVE_BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
        *active = Some(Arc::clone(&bridge));
    }
    bridge.begin_start_pending();
    Ok(bridge)
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let pending = {
            let mut guard = PENDING_ENTRYPOINT.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        let Some(PendingLaunch {
            entrypoint,
            result_slot,
        }) = pending
        else {
            tracing::error!("service_main invoked without a pending service entrypoint");
            return;
        };

        let _active_guard = ActiveBridgeGuard;
        let run_result = match register_win32_bridge() {
            Ok(bridge) => {
                let (_exit_status, res) = run_bridge_with_panic_barrier(&bridge, entrypoint);
                res
            }
            Err(err) => Err(ServiceRunError::EntrypointFailed(err)),
        };

        let mut res_guard = result_slot.lock().unwrap_or_else(|e| e.into_inner());
        *res_guard = Some(run_result);
    }));
}

unsafe extern "system" fn service_ctrl_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    dispatch_control_with_panic_barrier(control, || {
        let bridge = {
            let guard = ACTIVE_BRIDGE.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().map(Arc::clone)
        };
        match bridge {
            Some(bridge) => bridge.handle_control(control),
            None => ERROR_CALL_NOT_IMPLEMENTED.0,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Services::{
        SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_PAUSE,
    };

    #[derive(Clone, Default)]
    struct RecordingStatusSink {
        log: Arc<Mutex<Vec<String>>>,
        snapshots: Arc<Mutex<Vec<ServiceStatusSnapshot>>>,
    }

    impl RecordingStatusSink {
        fn snapshots(&self) -> Vec<ServiceStatusSnapshot> {
            self.snapshots
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }
    }

    impl StatusSink for RecordingStatusSink {
        fn report(&mut self, snapshot: &ServiceStatusSnapshot) -> Result<(), WinError> {
            self.snapshots
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(*snapshot);
            self.log
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(format!("status:{:?}", snapshot.phase));
            Ok(())
        }
    }

    #[test]
    fn scm_01_nominal_lifecycle_transitions_and_wait_hints() {
        assert_eq!(SERVICE_NAME, "LocalEDR");
        assert_eq!(START_PENDING_WAIT_HINT_MS, 10_000);
        assert_eq!(STOP_PENDING_WAIT_HINT_MS, 5_000);

        let mut machine = ServiceStatusMachine::new();
        assert_eq!(machine.snapshot().phase, ServicePhase::Uninitialized);

        let start = machine
            .begin_start_pending()
            .expect("begin_start_pending succeeds");
        assert_eq!(start.phase, ServicePhase::StartPending);
        assert_eq!(start.current_state, SERVICE_START_PENDING.0);
        assert_eq!(start.controls_accepted, 0);
        assert_eq!(start.check_point, 1);
        assert_eq!(start.wait_hint, 10_000);
        assert_eq!(start.win32_exit_code, NO_ERROR.0);

        let running = machine.mark_running().expect("mark_running succeeds");
        assert_eq!(running.phase, ServicePhase::Running);
        assert_eq!(running.current_state, SERVICE_RUNNING.0);
        assert_eq!(
            running.controls_accepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        assert_eq!(running.check_point, 0);
        assert_eq!(running.wait_hint, 0);

        let stop_decision = machine.handle_control_code(SERVICE_CONTROL_STOP);
        assert_eq!(stop_decision.return_code, NO_ERROR.0);
        assert!(stop_decision.trigger_shutdown);
        let stop_pending = stop_decision.status_to_report.expect("STOP_PENDING status");
        assert_eq!(stop_pending.phase, ServicePhase::StopPending);
        assert_eq!(stop_pending.current_state, SERVICE_STOP_PENDING.0);
        assert_eq!(stop_pending.controls_accepted, 0);
        assert_eq!(stop_pending.check_point, 1);
        assert_eq!(stop_pending.wait_hint, 5_000);

        let stopped = machine
            .mark_stopped(ServiceExitStatus::Clean)
            .expect("mark_stopped succeeds");
        assert_eq!(stopped.phase, ServicePhase::Stopped);
        assert_eq!(stopped.current_state, SERVICE_STOPPED.0);
        assert_eq!(stopped.controls_accepted, 0);
        assert_eq!(stopped.check_point, 0);
        assert_eq!(stopped.wait_hint, 0);
        assert_eq!(stopped.win32_exit_code, NO_ERROR.0);
        assert_eq!(stopped.service_specific_exit_code, 0);
    }

    #[test]
    fn scm_02_checkpoint_monotonicity_and_duplicate_stop_shutdown() {
        let mut machine = ServiceStatusMachine::new();
        let s1 = machine.begin_start_pending().unwrap();
        let s2 = machine.advance_start_pending().unwrap();
        let s3 = machine.advance_start_pending().unwrap();
        assert_eq!((s1.check_point, s2.check_point, s3.check_point), (1, 2, 3));

        // Transitioning directly from StartPending(3) -> StopPending must keep checkpoint monotonic.
        let first_stop = machine.handle_control_code(SERVICE_CONTROL_SHUTDOWN);
        assert_eq!(first_stop.return_code, NO_ERROR.0);
        assert!(first_stop.trigger_shutdown);
        let p1 = first_stop.status_to_report.unwrap();
        assert_eq!(p1.phase, ServicePhase::StopPending);
        assert_eq!(p1.check_point, 4);
        assert_eq!(p1.wait_hint, 5_000);

        // Duplicate STOP / SHUTDOWN increments checkpoint and does NOT re-trigger shutdown.
        let dup_stop = machine.handle_control_code(SERVICE_CONTROL_STOP);
        assert_eq!(dup_stop.return_code, NO_ERROR.0);
        assert!(!dup_stop.trigger_shutdown);
        let p2 = dup_stop.status_to_report.unwrap();
        assert_eq!(p2.check_point, 5);
        assert_eq!(p2.controls_accepted, 0);

        let dup_shutdown = machine.handle_control_code(SERVICE_CONTROL_SHUTDOWN);
        assert_eq!(dup_shutdown.return_code, NO_ERROR.0);
        assert!(!dup_shutdown.trigger_shutdown);
        let p3 = dup_shutdown.status_to_report.unwrap();
        assert_eq!(p3.check_point, 6);
    }

    #[test]
    fn scm_03_regression_guards_and_idempotency() {
        let mut machine = ServiceStatusMachine::new();
        assert!(machine.mark_running().is_none());
        assert!(machine.begin_start_pending().is_some());
        assert!(machine.begin_start_pending().is_none());

        let stop = machine.handle_control_code(SERVICE_CONTROL_STOP);
        assert!(stop.trigger_shutdown);

        // Late mark_running() after StopPending must be ignored.
        assert!(machine.mark_running().is_none());
        assert_eq!(machine.snapshot().phase, ServicePhase::StopPending);

        assert!(machine.mark_stopped(ServiceExitStatus::Clean).is_some());
        assert!(machine.mark_stopped(ServiceExitStatus::Clean).is_none());
        assert!(machine.mark_running().is_none());

        let post_stop = machine.handle_control_code(SERVICE_CONTROL_STOP);
        assert_eq!(post_stop.return_code, NO_ERROR.0);
        assert!(!post_stop.trigger_shutdown);
        assert!(post_stop.status_to_report.is_none());
    }

    #[test]
    fn scm_04_interrogate_and_unsupported_controls() {
        let mut machine = ServiceStatusMachine::new();
        let uninit_interrogate = machine.handle_control_code(SERVICE_CONTROL_INTERROGATE);
        assert_eq!(uninit_interrogate.return_code, NO_ERROR.0);
        assert!(!uninit_interrogate.trigger_shutdown);
        assert!(uninit_interrogate.status_to_report.is_none());

        machine.begin_start_pending().unwrap();
        machine.mark_running().unwrap();

        let interrogate = machine.handle_control_code(SERVICE_CONTROL_INTERROGATE);
        assert_eq!(interrogate.return_code, NO_ERROR.0);
        assert!(!interrogate.trigger_shutdown);
        assert_eq!(
            interrogate.status_to_report.unwrap().phase,
            ServicePhase::Running
        );

        for unsupported in [SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_CONTINUE, 999] {
            let decision = machine.handle_control_code(unsupported);
            assert_eq!(decision.return_code, ERROR_CALL_NOT_IMPLEMENTED.0);
            assert!(!decision.trigger_shutdown);
            assert!(decision.status_to_report.is_none());
        }
        assert_eq!(machine.snapshot().phase, ServicePhase::Running);
    }

    #[test]
    fn scm_05_failure_exit_codes_and_1063_mapping() {
        let mut machine = ServiceStatusMachine::new();
        machine.begin_start_pending().unwrap();
        let failed = machine
            .mark_stopped(ServiceExitStatus::Failure(7))
            .expect("stopped with failure");
        assert_eq!(failed.win32_exit_code, ERROR_SERVICE_SPECIFIC_ERROR.0);
        assert_eq!(failed.service_specific_exit_code, 7);

        // Failure(0) must normalize to non-zero service-specific exit code.
        let mut machine_zero = ServiceStatusMachine::new();
        machine_zero.begin_start_pending().unwrap();
        let failed_zero = machine_zero
            .mark_stopped(ServiceExitStatus::Failure(0))
            .expect("stopped with failure 0");
        assert_eq!(failed_zero.win32_exit_code, ERROR_SERVICE_SPECIFIC_ERROR.0);
        assert_eq!(failed_zero.service_specific_exit_code, 1);

        let err_1063 = WinError::from(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT);
        assert!(is_non_scm_connect_error(&err_1063));
        let err_other = WinError::from(ERROR_CALL_NOT_IMPLEMENTED);
        assert!(!is_non_scm_connect_error(&err_other));
    }

    #[test]
    fn scm_06_tokio_bridge_no_lost_wakeup_and_runtime_drop_before_stopped() {
        let sink = RecordingStatusSink::default();
        let log_ref = Arc::clone(&sink.log);
        let bridge = ServiceRuntimeBridge::new(Box::new(sink.clone()));
        bridge.begin_start_pending();

        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let bridge_for_ctrl = Arc::clone(&bridge);
        let ctrl_thread = std::thread::spawn(move || {
            ready_rx.recv().expect("wait for running");
            assert_eq!(
                bridge_for_ctrl.handle_control(SERVICE_CONTROL_INTERROGATE),
                NO_ERROR.0
            );
            assert_eq!(
                bridge_for_ctrl.handle_control(SERVICE_CONTROL_STOP),
                NO_ERROR.0
            );
            // Duplicate shutdown control must also return NO_ERROR.
            assert_eq!(
                bridge_for_ctrl.handle_control(SERVICE_CONTROL_SHUTDOWN),
                NO_ERROR.0
            );
        });

        let (exit_status, res) = run_bridge_with_panic_barrier(&bridge, move |control| {
            let mut shutdown_rx = control.shutdown_receiver();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            rt.block_on(async move {
                control.mark_running();
                ready_tx.send(()).expect("notify ctrl thread");
                let _ = shutdown_rx.wait_for(|&stopped| stopped).await;
            });
            drop(rt);
            log_ref
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push("runtime_dropped".to_string());
            Ok(())
        });

        ctrl_thread.join().expect("ctrl thread join");
        assert_eq!(exit_status, ServiceExitStatus::Clean);
        assert!(res.is_ok());

        let phases: Vec<ServicePhase> = sink.snapshots().into_iter().map(|s| s.phase).collect();
        assert_eq!(
            phases,
            vec![
                ServicePhase::StartPending,
                ServicePhase::Running,
                ServicePhase::Running, // INTERROGATE
                ServicePhase::StopPending,
                ServicePhase::StopPending, // duplicate SHUTDOWN
                ServicePhase::Stopped,
            ]
        );

        let log = sink.log();
        let rt_drop_idx = log
            .iter()
            .position(|entry| entry == "runtime_dropped")
            .expect("runtime_dropped recorded");
        let stopped_idx = log
            .iter()
            .position(|entry| entry == "status:Stopped")
            .expect("status:Stopped recorded");
        assert!(
            rt_drop_idx < stopped_idx,
            "Tokio runtime MUST be dropped before SERVICE_STOPPED is reported: {log:?}"
        );

        // Verify pre-sent STOP before wait_for() is never a lost wakeup.
        let sink2 = RecordingStatusSink::default();
        let bridge2 = ServiceRuntimeBridge::new(Box::new(sink2));
        bridge2.begin_start_pending();
        let (exit2, res2) = run_bridge_with_panic_barrier(&bridge2, |control| {
            let mut shutdown_rx = control.shutdown_receiver();
            control.mark_running();
            // Deliver STOP *before* entering the async wait.
            assert_eq!(bridge2.handle_control(SERVICE_CONTROL_STOP), NO_ERROR.0);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    shutdown_rx.wait_for(|&stopped| stopped),
                )
                .await
                .expect("must not hang on pre-delivered STOP")
                .expect("watch channel open");
            });
            drop(rt);
            Ok(())
        });
        assert_eq!(exit2, ServiceExitStatus::Clean);
        assert!(res2.is_ok());
    }

    #[test]
    fn scm_07_panic_barriers_prevent_ffi_unwind() {
        let sink = RecordingStatusSink::default();
        let bridge = ServiceRuntimeBridge::new(Box::new(sink.clone()));
        bridge.begin_start_pending();

        let (exit_status, res) = run_bridge_with_panic_barrier(&bridge, |_control| {
            panic!("simulated daemon panic inside service_main");
        });
        assert_eq!(exit_status, ServiceExitStatus::Failure(2));
        assert!(matches!(res, Err(ServiceRunError::ServicePanicked)));

        let last = sink.snapshots().last().copied().expect("stopped snapshot");
        assert_eq!(last.phase, ServicePhase::Stopped);
        assert_eq!(last.win32_exit_code, ERROR_SERVICE_SPECIFIC_ERROR.0);
        assert_eq!(last.service_specific_exit_code, 2);

        let ctrl_code = dispatch_control_with_panic_barrier(SERVICE_CONTROL_STOP, || {
            panic!("simulated panic inside service_ctrl_handler");
        });
        assert_eq!(ctrl_code, ERROR_GEN_FAILURE.0);
    }
}
