//! Layer 1 Windows kernel/ETW telemetry sensor and active-defense controller crate.

pub mod defense;
pub mod dns_cache;
pub mod etw;
pub mod path_norm;
pub mod privileges;
pub mod wfp;

use std::net::IpAddr;
use std::path::Path;

use ledr_proto::{ActiveDefenseController, ProcessIdentity};

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
