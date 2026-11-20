//! ETW real-time trace sessions (`Kernel-Process`, `Kernel-File`, `Kernel-Registry`,
//! `DNS-Client`, `Kernel-Network`, `AMSI`, and PowerShell 4104) and Toolhelp32 initial process
//! snapshots (`AUTO-03`, `AUTO-06`, `AUTO-08`).

pub mod file_canary;
pub(crate) mod tdh;

mod context;
mod handlers;
mod registry;
mod session;
mod snapshot;

pub use self::file_canary::{
    CanaryMatcher, is_autorun_registry_key, is_autorun_registry_key_u16,
    is_autorun_registry_value_target, is_autorun_registry_value_target_u16,
    prefilter_and_classify_canary, prefilter_and_classify_canary_u16,
};
pub use self::session::{
    DEFAULT_ETW_SESSION_NAME, EventSinkFn, NoopSensorBackend, WindowsEtwSensor,
};
pub use self::snapshot::{capture_running_processes, try_capture_running_processes};

#[cfg(test)]
mod tests;
