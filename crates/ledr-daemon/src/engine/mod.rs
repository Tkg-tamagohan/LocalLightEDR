//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

mod alerts;
mod auth_worker;
mod binary_inspector;
mod config;
mod dns_history;
mod domain_policy;
mod events;
mod lifecycle;
mod motw;
mod nrd;
mod outbound;
mod pipeline;
mod policy;
#[cfg(test)]
mod tests;
mod wfp_drops;
mod wfp_premat;

pub use alerts::ResolvedAlertOutcome;
pub use binary_inspector::{
    BinaryInspector, InspectOutcome, LiveProcessInspector, WindowsBinaryInspector,
    WindowsLiveProcessInspector,
};
pub use config::{DaemonConfig, OutboundEnforcementMode, DEFAULT_MAX_CONCURRENT_IPC_CLIENTS};
pub use motw::{
    BrowserEventOutcome, BrowserReportError, MotwAttribution, MotwInspector, MotwMatchStage,
    WindowsMotwInspector, MAX_BROWSER_EVENT_DETAILS_BYTES, MAX_DOWNLOAD_HASH_BYTES,
};
pub use policy::PolicyRuleError;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use ledr_proto::EventLane;
use ledr_proto::{ActiveDefenseController, AlertStatus, PipelineMetrics, SensorEvent};
use ledr_rules::{EarlyPruner, NrdCache, NrdCancelToken, SigmaEngine};
use ledr_store::{LedrStore, StoreError};
use tokio::task::JoinHandle;

#[cfg(doc)]
use crate::channel::TwoLaneChannel;
use crate::channel::{ClassifiedEventSender, OutboundLaneClassifier, TwoLaneSender};
use crate::firewall::WfpRuleManager;
use crate::notify::NotificationDispatcher;
use crate::process_table::ActiveProcessTable;

#[cfg(test)]
use alerts::tolerate_missing_target;
use dns_history::ProcessDnsHistory;
#[cfg(test)]
use dns_history::{DnsHistoryEntry, DomainTimestamp, MAX_DOMAINS_PER_PROCESS_IP};
#[cfg(test)]
use domain_policy::select_outbound_decision_for_domains;
use motw::{BrowserEventDedupCache, MotwIoWorkerPool, MotwStage2Cache};
use nrd::NrdThreadHandle;
use outbound::{VerifiedAppWideAllowCache, VERIFIED_APP_WIDE_ALLOW_CAPACITY};
use pipeline::WorkerExit;
#[cfg(test)]
use wfp_drops::{OverflowPushOutcome, PendingWfpDrop};
use wfp_drops::{AppWfpAlertDedup, QueuedWfpDrop, WfpDropDedupCache, WfpDropOverflowQueue};

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const WFP_DROP_DEDUP_CAPACITY: usize = 1024;
const WFP_DROP_DEDUP_WINDOW_MS: i64 = 250;
const APP_WFP_ALERT_DEDUP_CAPACITY: usize = 512;
const AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS: i64 = 60_000;

#[derive(Debug, Default)]
struct WriteGateState {
    closed: bool,
    sealed: bool,
    in_flight: usize,
    active_sql_writes: usize,
}

/// Coordinates engine-initiated SQLite mutations with graceful shutdown (`FU-E2E-05`).
///
/// Multi-step transactions + compensation rollbacks (e.g., `resolve_alert_with_outcome`,
/// `upsert_policy_rule`, `delete_policy_rule`) hold a [`WriteOpGuard`] across the whole logical
/// operation, while direct single-step SQLite write paths (download origin persistence and
/// per-batch TTL purges) hold an [`OwnedSqlWriteGuard`] from [`StoreWriteGate::enter_sql_write`].
///
/// If an admitted multi-step operation outlives the shutdown drain budget,
/// [`StoreWriteGate::seal_and_wait_sql_idle`] permanently seals `WriteOpGuard::write` and waits
/// for both active [`WriteOpGuard::write`] calls and [`OwnedSqlWriteGuard`]s to unwind before
/// final `wal_checkpoint(TRUNCATE)` so late post-checkpoint writes cannot regenerate `-wal`.
#[derive(Debug, Default)]
pub(super) struct StoreWriteGate {
    state: Mutex<WriteGateState>,
    notify_idle: tokio::sync::Notify,
    notify_sql_idle: tokio::sync::Notify,
}

pub(super) struct WriteOpGuard {
    gate: Arc<StoreWriteGate>,
}

impl Drop for WriteOpGuard {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if state.in_flight == 0 {
            self.gate.notify_idle.notify_waiters();
        }
    }
}

struct SqlWriteGuard<'a>(&'a StoreWriteGate);

impl Drop for SqlWriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active_sql_writes = state.active_sql_writes.saturating_sub(1);
        if state.active_sql_writes == 0 {
            self.0.notify_sql_idle.notify_waiters();
        }
    }
}

pub(super) struct OwnedSqlWriteGuard {
    gate: Arc<StoreWriteGate>,
}

impl Drop for OwnedSqlWriteGuard {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        state.active_sql_writes = state.active_sql_writes.saturating_sub(1);
        if state.in_flight == 0 {
            self.gate.notify_idle.notify_waiters();
        }
        if state.active_sql_writes == 0 {
            self.gate.notify_sql_idle.notify_waiters();
        }
    }
}

impl WriteOpGuard {
    pub(super) fn write<T>(
        &self,
        store: &LedrStore,
        op: impl FnOnce(&LedrStore) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        {
            let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.sealed {
                return Err(StoreError::Io(std::io::Error::other(
                    "store write gate sealed for shutdown checkpoint",
                )));
            }
            state.active_sql_writes = state.active_sql_writes.saturating_add(1);
        }
        let _sql_guard = SqlWriteGuard(&self.gate);
        op(store)
    }
}

impl StoreWriteGate {
    pub(super) fn enter_op(gate: &Arc<Self>) -> Option<WriteOpGuard> {
        let mut state = gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.sealed {
            return None;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        Some(WriteOpGuard {
            gate: Arc::clone(gate),
        })
    }

    pub(super) fn enter_sql_write(gate: &Arc<Self>) -> Option<OwnedSqlWriteGuard> {
        let mut state = gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.closed || state.sealed {
            return None;
        }
        state.in_flight = state.in_flight.saturating_add(1);
        state.active_sql_writes = state.active_sql_writes.saturating_add(1);
        Some(OwnedSqlWriteGuard {
            gate: Arc::clone(gate),
        })
    }

    pub(super) async fn close_and_wait_idle(&self, deadline: tokio::time::Instant) -> bool {
        let mut notified = std::pin::pin!(self.notify_idle.notified());
        loop {
            notified.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.closed = true;
                if state.in_flight == 0 {
                    return true;
                }
            }
            if tokio::time::timeout_at(deadline, notified.as_mut())
                .await
                .is_err()
            {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                return state.in_flight == 0;
            }
            notified.set(self.notify_idle.notified());
        }
    }

    pub(super) async fn seal_and_wait_sql_idle(&self, deadline: tokio::time::Instant) -> bool {
        let mut notified = std::pin::pin!(self.notify_sql_idle.notified());
        loop {
            notified.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                state.closed = true;
                state.sealed = true;
                if state.active_sql_writes == 0 {
                    return true;
                }
            }
            if tokio::time::timeout_at(deadline, notified.as_mut())
                .await
                .is_err()
            {
                let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                return state.active_sql_writes == 0;
            }
            notified.set(self.notify_sql_idle.notified());
        }
    }
}

/// Resident Layer 2 detection and persistence pipeline engine.
pub struct DaemonEngine {
    config: DaemonConfig,
    self_pid: u32,
    self_exe_normalized: Option<String>,
    store: LedrStore,
    sigma: SigmaEngine,
    pruner: EarlyPruner,
    defense: Arc<dyn ActiveDefenseController>,
    notifier: Arc<dyn NotificationDispatcher>,
    inspector: Arc<dyn BinaryInspector>,
    live_process_inspector: Arc<dyn LiveProcessInspector>,
    motw_inspector: Arc<dyn MotwInspector>,
    download_origin_state: Arc<AtomicU64>,
    motw_stage2_cache: Arc<Mutex<MotwStage2Cache>>,
    motw_pool: MotwIoWorkerPool,
    browser_event_dedup: Mutex<BrowserEventDedupCache>,
    process_table: Mutex<ActiveProcessTable>,
    firewall: Mutex<WfpRuleManager>,
    outbound_classifier: Arc<OutboundLaneClassifier>,
    verified_app_wide_allows: Mutex<VerifiedAppWideAllowCache>,
    process_dns_history: Mutex<ProcessDnsHistory>,
    wfp_drop_dedup: Mutex<WfpDropDedupCache>,
    wfp_drop_tx: tokio::sync::mpsc::Sender<QueuedWfpDrop>,
    wfp_drop_overflow: Mutex<WfpDropOverflowQueue>,
    wfp_drop_overflow_notify: tokio::sync::Notify,
    wfp_drop_overflow_pushed: AtomicU64,
    wfp_drop_overflow_coalesced: AtomicU64,
    app_wfp_alert_dedup: Mutex<AppWfpAlertDedup>,
    nrd_cache: Arc<RwLock<NrdCache>>,
    nrd_cancel: NrdCancelToken,
    nrd_in_flight: Arc<AtomicBool>,
    nrd_thread_handle: Mutex<Option<NrdThreadHandle>>,
    /// Serializes `resolve_alert` so concurrent resolves of sibling alerts cannot both
    /// observe "another unresolved suspended alert exists" and leave the process
    /// suspended forever (`BUG_0002`).
    resolve_lock: Mutex<()>,
    /// Serializes SQLite network rule mutations + baseline WFP reconciliation across
    /// `upsert_policy_rule`, `delete_policy_rule`, and `resolve_alert_with_outcome`
    /// (`resolve_lock -> policy_lock -> store/firewall`).
    policy_lock: Mutex<()>,
    prior_running_candidates: Mutex<Vec<String>>,
    sender: TwoLaneSender,
    started_at: Instant,
    high_priority_processed: AtomicU64,
    telemetry_processed: AtomicU64,
    pruned_events: AtomicU64,
    alerts_emitted: AtomicU64,
    fail_record_alert_for_test: AtomicBool,
    #[cfg(test)]
    pub(super) tier2c_periodic_sweeps: AtomicU64,
    #[cfg(test)]
    pub(super) tier2c_periodic_sweep_removals: AtomicU64,
    #[cfg(test)]
    pub(super) select_idle_periodic_sweeps: AtomicU64,
    #[cfg(test)]
    pub(super) select_idle_periodic_sweep_removals: AtomicU64,
    #[cfg(test)]
    pub(super) mem_maintenance_interval_ms: AtomicU64,
    #[cfg(test)]
    pub(super) tier2c_mem_maintenance_runs: AtomicU64,
    #[cfg(test)]
    pub(super) select_idle_mem_maintenance_runs: AtomicU64,
    shutdown_initiated: Arc<AtomicBool>,
    shutdown_drain_cutoff: Arc<AtomicBool>,
    shutdown_cutoff_notify: Arc<tokio::sync::Notify>,
    store_write_gate: Arc<StoreWriteGate>,
    worker_handle: tokio::sync::Mutex<Option<JoinHandle<Result<WorkerExit, StoreError>>>>,
}

impl DaemonEngine {
    /// Returns a cloneable [`TwoLaneSender`] handle for submitting events into the pipeline.
    pub fn sender(&self) -> TwoLaneSender {
        self.sender.clone()
    }

    /// Returns a cloneable [`ClassifiedEventSender`] handle that promotes unverified external
    /// `NetworkConnect` events onto the non-dropping high-priority lane (`L-10`, `#6`).
    pub fn classified_sender(&self) -> ClassifiedEventSender {
        ClassifiedEventSender::new(self.sender.clone(), Arc::clone(&self.outbound_classifier))
    }

    fn invalidate_non_protected_steady_pids(&self) {
        self.outbound_classifier.clear_non_protected();
        self.verified_app_wide_allows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    #[cfg(test)]
    pub(super) fn verified_app_wide_allows_len(&self) -> usize {
        self.verified_app_wide_allows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Returns a reference to the backing [`LedrStore`].
    pub fn store(&self) -> &LedrStore {
        &self.store
    }

    /// Returns the active [`DaemonConfig`].
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Returns the active [`BinaryInspector`] implementation.
    pub fn inspector(&self) -> &Arc<dyn BinaryInspector> {
        &self.inspector
    }

    #[doc(hidden)]
    pub fn set_fail_record_alert_for_test(&self, fail: bool) {
        self.fail_record_alert_for_test
            .store(fail, Ordering::Release);
    }

    pub(super) fn mem_maintenance_interval(&self) -> std::time::Duration {
        #[cfg(test)]
        {
            std::time::Duration::from_millis(
                self.mem_maintenance_interval_ms
                    .load(Ordering::Acquire)
                    .max(1),
            )
        }
        #[cfg(not(test))]
        {
            std::time::Duration::from_secs(60)
        }
    }

    #[cfg(test)]
    pub(super) fn set_mem_maintenance_interval_for_test(&self, interval: std::time::Duration) {
        let ms = u64::try_from(interval.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        self.mem_maintenance_interval_ms
            .store(ms, Ordering::Release);
    }

    /// Returns current [`PipelineMetrics`] (`決定記録 L-10`).
    pub fn metrics(&self) -> PipelineMetrics {
        let active_processes = self
            .process_table
            .lock()
            .map(|t| t.active_count())
            .unwrap_or(0);
        let pending_alerts = self
            .store
            .list_alerts(Some(AlertStatus::Pending), 1000)
            .map(|v| v.len())
            .unwrap_or(0);

        PipelineMetrics {
            high_priority_depth: self.sender.high_priority_depth(),
            high_priority_capacity: self.sender.high_priority_capacity(),
            high_priority_processed: self.high_priority_processed.load(Ordering::Relaxed),
            telemetry_depth: self.sender.telemetry_depth(),
            telemetry_capacity: self.sender.telemetry_capacity(),
            telemetry_processed: self.telemetry_processed.load(Ordering::Relaxed),
            telemetry_dropped: self.sender.telemetry_dropped(),
            active_processes,
            pending_alerts,
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }

    /// Total high-priority events dropped (always `0` per `決定記録 L-10`).
    pub fn high_priority_dropped(&self) -> u64 {
        self.sender.high_priority_dropped()
    }

    /// Total events skipped from Sigma evaluation by [`EarlyPruner`].
    pub fn pruned_events(&self) -> u64 {
        self.pruned_events.load(Ordering::Relaxed)
    }

    /// Total alerts persisted to [`LedrStore`] from Sigma matches.
    pub fn alerts_emitted(&self) -> u64 {
        self.alerts_emitted.load(Ordering::Relaxed)
    }

    /// Number of entries currently retained in [`ActiveProcessTable`].
    pub fn active_process_table_len(&self) -> usize {
        self.process_table
            .lock()
            .map(|t| t.total_len())
            .unwrap_or(0)
    }

    /// Signals early cooperative shutdown before stopping the ETW backend (`FU-E2E-05`).
    ///
    /// Cancels background NRD fetches, halts multi-batch TTL purges, and allows
    /// `shutdown_skip_cold_binary_inspect` to abort/skip cold disk hashing without closing the
    /// event channel prematurely so `ControlTraceW` buffer collection still drains cleanly.
    pub fn signal_early_shutdown(&self) {
        self.shutdown_initiated.store(true, Ordering::Release);
        self.nrd_cancel.cancel();
        self.store.request_shutdown();
    }

    pub(super) fn is_shutdown_drain_cutoff(&self) -> bool {
        self.shutdown_drain_cutoff.load(Ordering::Acquire)
    }

    pub(super) fn store_write_closed_err() -> StoreError {
        StoreError::InvalidValue {
            field: "store.shutdown",
            value: "daemon store writes closed for shutdown".to_string(),
        }
    }

    pub(super) fn try_store_write<T>(
        &self,
        op: impl FnOnce(&LedrStore) -> Result<T, StoreError>,
    ) -> Option<Result<T, StoreError>> {
        let guard = StoreWriteGate::enter_op(&self.store_write_gate)?;
        Some(guard.write(&self.store, op))
    }

    pub(super) fn inspect_binary_for_pipeline(&self, exe_path: &str) -> InspectOutcome {
        if self.is_shutdown_drain_cutoff() {
            return InspectOutcome::Cancelled;
        }
        let fast_skip = self.config.shutdown_skip_cold_binary_inspect
            && self.shutdown_initiated.load(Ordering::Acquire);
        let cancel_flag = if self.config.shutdown_skip_cold_binary_inspect {
            &self.shutdown_initiated
        } else {
            &self.shutdown_drain_cutoff
        };
        self.inspector
            .inspect_cancellable(exe_path, cancel_flag, fast_skip)
    }

    /// Returns `true` if `pid` belongs to the active out-of-process Authenticode helper
    /// (`FU-E2E-03` Track 2 self-PID recursion guard).
    pub fn is_helper_pid(&self, pid: u32) -> bool {
        self.inspector.is_helper_pid(pid)
    }

    /// Returns `true` iff `(pid, exe_path)` matches the running daemon's own PID and normalized
    /// executable path (or its active Authenticode helper PID, fail-closed when
    /// `self_exe_normalized` is `None` or `exe_path` is empty).
    pub(super) fn is_self_process(&self, pid: u32, exe_path: &str) -> bool {
        if self.inspector.is_helper_pid(pid) {
            return true;
        }
        if pid != self.self_pid || exe_path.trim().is_empty() {
            return false;
        }
        let Some(ref self_exe) = self.self_exe_normalized else {
            return false;
        };
        normalize_exe_path_for_self_check(exe_path) == *self_exe
    }
}

pub(super) fn normalize_exe_path_for_self_check(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let slash_norm = trimmed.replace('/', "\\");
    let without_nt = if slash_norm
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\??\UNC\"))
    {
        format!(r"\\{}", &slash_norm[8..])
    } else if slash_norm.get(..4).is_some_and(|p| p == r"\??\") {
        slash_norm[4..].to_string()
    } else {
        slash_norm
    };
    motw::normalize_windows_path(&without_nt).to_lowercase()
}

pub(crate) fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn event_timestamp_ms(event: &SensorEvent, fallback_ms: i64) -> i64 {
    match event {
        SensorEvent::ProcessStart { identity, .. } => {
            filetime_100ns_to_unix_ms(identity.create_time_100ns, fallback_ms)
        }
        SensorEvent::ProcessStop {
            exit_time_100ns, ..
        } => filetime_100ns_to_unix_ms(*exit_time_100ns, fallback_ms),
        SensorEvent::DnsQuery { timestamp_ms, .. }
        | SensorEvent::NetworkConnect { timestamp_ms, .. }
        | SensorEvent::CanaryFileAccess { timestamp_ms, .. }
        | SensorEvent::ScriptEvaluated { timestamp_ms, .. } => *timestamp_ms,
    }
}

fn filetime_100ns_to_unix_ms(ticks: u64, fallback_ms: i64) -> i64 {
    if ticks >= WINDOWS_TO_UNIX_EPOCH_100NS {
        let unix_ms = (ticks - WINDOWS_TO_UNIX_EPOCH_100NS) / TICKS_PER_MS;
        i64::try_from(unix_ms).unwrap_or(fallback_ms)
    } else {
        fallback_ms
    }
}
