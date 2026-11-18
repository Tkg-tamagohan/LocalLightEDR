//! ETW real-time trace sessions (`Kernel-Process`, `Kernel-Network`, `Kernel-File`,
//! `DNS-Client`, `AMSI`, and PowerShell 4104) implemented in Phase 1.

use ledr_proto::SensorBackend;

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
