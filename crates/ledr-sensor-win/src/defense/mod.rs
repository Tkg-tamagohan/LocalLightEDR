//! Active defense actuators (`NtSuspendProcess`, `NtResumeProcess`, `TerminateProcess`,
//! Never-Suspend / `CreationTime` safety guards, descendant tree containment, and
//! honeypot decoy file lifecycle management) (`AUTO-02`, `AUTO-03`, `L-06`, `L-07`).

mod controller;
mod guard;
mod honeypot;
mod process_probe;
mod tree;

pub use controller::WindowsDefenseController;
pub use guard::validate_target_process;
pub use honeypot::HoneypotManager;
pub use process_probe::{ProcessLiveness, process_liveness};
pub use tree::collect_live_descendants;

#[cfg(test)]
mod tests;
