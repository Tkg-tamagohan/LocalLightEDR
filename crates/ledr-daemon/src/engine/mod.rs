//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

mod alerts;
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
    BinaryInspector, LiveProcessInspector, WindowsBinaryInspector, WindowsLiveProcessInspector,
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
#[cfg(test)]
use wfp_drops::{OverflowPushOutcome, PendingWfpDrop};
use wfp_drops::{AppWfpAlertDedup, QueuedWfpDrop, WfpDropDedupCache, WfpDropOverflowQueue};

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const WFP_DROP_DEDUP_CAPACITY: usize = 1024;
const WFP_DROP_DEDUP_WINDOW_MS: i64 = 250;
const APP_WFP_ALERT_DEDUP_CAPACITY: usize = 512;
const AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS: i64 = 60_000;

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
    worker_handle: tokio::sync::Mutex<Option<JoinHandle<Result<(), StoreError>>>>,
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

    #[doc(hidden)]
    pub fn set_fail_record_alert_for_test(&self, fail: bool) {
        self.fail_record_alert_for_test
            .store(fail, Ordering::Release);
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

    /// Returns `true` iff `(pid, exe_path)` matches the running daemon's own PID and normalized
    /// executable path (fail-closed when `self_exe_normalized` is `None` or `exe_path` is empty).
    pub(super) fn is_self_process(&self, pid: u32, exe_path: &str) -> bool {
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
