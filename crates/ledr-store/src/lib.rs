//! Layer 3 embedded SQLite WAL time-series store, batch writer, and TTL purge engine.

use ledr_proto::{AlertStatus, DEFAULT_TTL_RETENTION_DAYS};

/// Returns the store crate version string.
pub fn store_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the bundled SQLite engine version string via `rusqlite`.
pub fn sqlite_version() -> &'static str {
    tracing::trace!("querying bundled SQLite version");
    rusqlite::version()
}

/// Returns the default telemetry retention window in days (`ledr_proto::DEFAULT_TTL_RETENTION_DAYS`).
pub fn default_retention_days() -> u32 {
    DEFAULT_TTL_RETENTION_DAYS
}

/// Returns the initial status assigned to newly recorded alerts.
pub fn default_alert_status() -> AlertStatus {
    AlertStatus::Pending
}
