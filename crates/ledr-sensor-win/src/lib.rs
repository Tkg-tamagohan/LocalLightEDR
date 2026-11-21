//! Layer 1 Windows kernel/ETW telemetry sensor and active-defense controller crate.

pub mod defense;
pub mod dns_cache;
pub mod etw;
pub mod motw;
pub mod path_norm;
pub mod privileges;
pub mod wfp;

pub use defense::{
    HoneypotManager, WindowsDefenseController, collect_live_descendants, validate_target_process,
};
pub use etw::file_canary::{
    CanaryMatcher, is_autorun_registry_key, is_autorun_registry_key_u16,
    prefilter_and_classify_canary, prefilter_and_classify_canary_u16,
};
pub use motw::{
    MAX_ZONE_IDENTIFIER_BYTES, MotwZoneInfo, ZONE_ID_INTERNET, parse_zone_identifier,
    read_zone_identifier, write_zone_identifier,
};
pub use wfp::{
    LEDR_WFP_PROVIDER_GUID, LEDR_WFP_SUBLAYER_GUID, WFP_WEIGHT_BLOCK_APP,
    WFP_WEIGHT_BLOCK_SPECIFIC, WFP_WEIGHT_LOOPBACK_PERMIT, WFP_WEIGHT_PERMIT_APP,
    WFP_WEIGHT_PERMIT_SPECIFIC, WfpBackend, WfpDropEvent, WfpDropSinkFn, WfpDynamicEngine,
    WfpFilterAction, WfpFilterMeta, WfpFilterSpec, WfpLayer, WfpLoopbackCondition,
    WfpLoopbackFilterSpec, WfpRemoteAddress, build_loopback_permit_filter_specs,
    build_wfp_filter_specs, parse_wfp_classify_drop_fields, validate_wfp_rule_request,
};

use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{ActiveDefenseController, ProcessIdentity};
use thiserror::Error;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

/// Errors produced by Layer 1 Windows sensor and privilege operations.
#[derive(Debug, Error)]
pub enum SensorError {
    #[error("Win32 API call `{api}` failed: {message}")]
    Win32 { api: &'static str, message: String },
    #[error("ETW trace session `{session}` error: {message}")]
    Etw { session: String, message: String },
    #[error("sensor backend is already running")]
    AlreadyRunning,
    #[error("process snapshot failed: {0}")]
    Snapshot(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// RAII guard for Win32 `HANDLE` values that must be closed via `CloseHandle`.
pub(crate) struct OwnedHandle(pub(crate) HANDLE);

impl OwnedHandle {
    /// Wraps a non-null, non-invalid Win32 `HANDLE`.
    pub(crate) fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_invalid() || handle.0.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }

    /// Returns the raw Win32 handle.
    pub(crate) fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` is an owned Win32 handle obtained by this process.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Returns the crate identifier for diagnostics and Phase 0 smoke checks.
pub fn crate_name() -> &'static str {
    "ledr-sensor-win"
}

/// Returns the Win32 handle type descriptors wired for Phase 1 sensor/actuator modules.
pub fn win32_handle_types() -> (&'static str, &'static str) {
    (
        std::any::type_name::<windows::Win32::Foundation::HANDLE>(),
        std::any::type_name::<windows_sys::Win32::Foundation::HANDLE>(),
    )
}

/// Non-privileged no-op implementation of [`ActiveDefenseController`] for unit tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopDefenseController;

impl ActiveDefenseController for NoopDefenseController {
    fn suspend_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        tracing::trace!(pid = target.pid, include_children, "noop suspend_process");
        Ok(())
    }

    fn resume_process(&self, _target: &ProcessIdentity) -> Result<(), String> {
        Ok(())
    }

    fn terminate_process(
        &self,
        _target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        _exe_path: &Path,
        _remote_ip: Option<IpAddr>,
        _allow: bool,
    ) -> Result<u64, String> {
        Ok(0)
    }

    fn remove_wfp_rule(&self, _filter_id: u64) -> Result<(), String> {
        Ok(())
    }
}
