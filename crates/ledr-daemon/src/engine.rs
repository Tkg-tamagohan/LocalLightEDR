//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    AlertRecord, AlertStatus, EventLane, PipelineMetrics, SensorEvent,
    ACTIVE_PROCESS_TABLE_CAPACITY, DEFAULT_TTL_RETENTION_DAYS, HIGH_PRIORITY_CHANNEL_CAPACITY,
    IPC_PIPE_NAME, SHUTDOWN_FLUSH_TIMEOUT_MS, STORE_BATCH_FLUSH_INTERVAL_MS,
    TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{assess_domain_risk, EarlyPruner, EventContext, SigmaEngine};
use ledr_store::{LedrStore, PurgeStats, StoreError};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::channel::{TwoLaneChannel, TwoLaneReceiver, TwoLaneSender};
use crate::process_table::ActiveProcessTable;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DEFAULT_TTL_PURGE_INTERVAL_MS: u64 = 3_600_000;
const DEFAULT_MAX_CONCURRENT_IPC_CLIENTS: usize = 16;
const DEFAULT_IPC_FRAME_TIMEOUT_MS: u64 = 5_000;

/// Configuration options for [`DaemonEngine`] and the Named Pipe IPC server.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub high_priority_capacity: usize,
    pub telemetry_capacity: usize,
    pub active_process_capacity: usize,
    pub batch_flush_interval_ms: u64,
    pub shutdown_flush_timeout_ms: u64,
    pub ttl_purge_interval_ms: u64,
    pub ttl_retention_days: u32,
    pub max_concurrent_ipc_clients: usize,
    pub ipc_frame_timeout_ms: u64,
    pub pipe_name: String,
    /// When `true` (Phase 1 `--foreground` dev mode), mutating IPC commands bypass the
    /// `C:\Program Files\LocalEDR\ledr-ui.exe` install-path check while still inspecting
    /// and logging caller process identity.
    pub dev_mode_bypass_ui_auth: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            high_priority_capacity: HIGH_PRIORITY_CHANNEL_CAPACITY,
            telemetry_capacity: TELEMETRY_CHANNEL_CAPACITY,
            active_process_capacity: ACTIVE_PROCESS_TABLE_CAPACITY,
            batch_flush_interval_ms: STORE_BATCH_FLUSH_INTERVAL_MS,
            shutdown_flush_timeout_ms: SHUTDOWN_FLUSH_TIMEOUT_MS,
            ttl_purge_interval_ms: DEFAULT_TTL_PURGE_INTERVAL_MS,
            ttl_retention_days: DEFAULT_TTL_RETENTION_DAYS,
            max_concurrent_ipc_clients: DEFAULT_MAX_CONCURRENT_IPC_CLIENTS,
            ipc_frame_timeout_ms: DEFAULT_IPC_FRAME_TIMEOUT_MS,
            pipe_name: IPC_PIPE_NAME.to_string(),
            dev_mode_bypass_ui_auth: true,
        }
    }
}

/// Resident Layer 2 detection and persistence pipeline engine.
pub struct DaemonEngine {
    config: DaemonConfig,
    store: LedrStore,
    sigma: SigmaEngine,
    pruner: EarlyPruner,
    process_table: Mutex<ActiveProcessTable>,
    prior_running_candidates: Mutex<Vec<String>>,
    sender: TwoLaneSender,
    started_at: Instant,
    high_priority_processed: AtomicU64,
    telemetry_processed: AtomicU64,
    pruned_events: AtomicU64,
    alerts_emitted: AtomicU64,
    worker_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl DaemonEngine {
    /// Starts a new [`DaemonEngine`] background pipeline task consuming from a bounded [`TwoLaneChannel`].
    pub fn start(
        store: LedrStore,
        sigma: SigmaEngine,
        pruner: EarlyPruner,
        config: DaemonConfig,
    ) -> Arc<Self> {
        let prior_running_candidates = store.list_running_process_instance_ids().unwrap_or_default();
        let (sender, receiver) = TwoLaneChannel::with_capacities(
            config.high_priority_capacity,
            config.telemetry_capacity,
        )
        .split();
        let process_table = Mutex::new(ActiveProcessTable::new(config.active_process_capacity));

        let engine = Arc::new(Self {
            config,
            store,
            sigma,
            pruner,
            process_table,
            prior_running_candidates: Mutex::new(prior_running_candidates),
            sender,
            started_at: Instant::now(),
            high_priority_processed: AtomicU64::new(0),
            telemetry_processed: AtomicU64::new(0),
            pruned_events: AtomicU64::new(0),
            alerts_emitted: AtomicU64::new(0),
            worker_handle: tokio::sync::Mutex::new(None),
        });

        let worker_engine = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            worker_engine.run_pipeline(receiver).await;
        });

        if let Ok(mut slot) = engine.worker_handle.try_lock() {
            *slot = Some(handle);
        }

        engine
    }

    /// Returns a cloneable [`TwoLaneSender`] handle for submitting events into the pipeline.
    pub fn sender(&self) -> TwoLaneSender {
        self.sender.clone()
    }

    /// Returns a reference to the backing [`LedrStore`].
    pub fn store(&self) -> &LedrStore {
        &self.store
    }

    /// Returns the active [`DaemonConfig`].
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Seeds the in-memory [`ActiveProcessTable`] and SQLite store with initial OS process snapshots
    /// (`AUTO-03`), flushes them immediately, and reconciles any stale running processes from prior
    /// daemon sessions (`BUG_0001`, `BUG_0002`).
    pub fn seed_processes(&self, snapshots: Vec<SensorEvent>) -> Result<usize, anyhow::Error> {
        let mut count = 0usize;
        let mut active_id_set = HashSet::with_capacity(snapshots.len());
        for ev in snapshots {
            if let SensorEvent::ProcessStart { identity, .. } = &ev {
                active_id_set.insert(identity.instance_id());
                self.process_event(&ev);
                count += 1;
            }
        }
        if count == 0 {
            tracing::warn!(
                "seed_processes received zero ProcessStart snapshots; skipping stale reconciliation"
            );
            return Ok(0);
        }
        self.store.flush_batch()?;
        {
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for id in table.active_instance_ids() {
                active_id_set.insert(id);
            }
        }
        let candidates = {
            let mut guard = self
                .prior_running_candidates
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *guard)
        };
        let active_ids: Vec<String> = active_id_set.into_iter().collect();
        let reconciled = self.store.reconcile_stale_running_candidates(
            &candidates,
            &active_ids,
            current_unix_ms(),
        )?;
        if reconciled > 0 {
            tracing::info!(
                reconciled_stale_processes = reconciled,
                "reconciled stale running processes from prior session"
            );
        }
        Ok(count)
    }

    /// Executes a single SQLite TTL purge pass using the configured retention window (`L-11`).
    pub fn run_ttl_purge_once(&self) -> Result<PurgeStats, StoreError> {
        self.store
            .purge_expired(current_unix_ms(), self.config.ttl_retention_days)
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

    /// Closes ingestion, drains remaining queued events, flushes SQLite batches, and runs
    /// `PRAGMA wal_checkpoint(TRUNCATE)` within `SHUTDOWN_FLUSH_TIMEOUT_MS` (`3,000 ms`, `AUTO-10`).
    pub async fn shutdown_and_flush(&self) -> Result<(), anyhow::Error> {
        self.store.request_shutdown();
        self.sender.close();

        let handle = {
            let mut guard = self.worker_handle.lock().await;
            guard.take()
        };

        let timeout = Duration::from_millis(self.config.shutdown_flush_timeout_ms.max(1));
        if let Some(h) = handle {
            match tokio::time::timeout(timeout, h).await {
                Ok(join_res) => {
                    if let Err(err) = join_res {
                        tracing::error!(error = %err, "daemon worker task panicked during shutdown");
                    }
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = self.config.shutdown_flush_timeout_ms,
                        "daemon pipeline drain exceeded shutdown flush timeout; forcing checkpoint"
                    );
                }
            }
        }

        self.store.checkpoint_truncate()?;
        Ok(())
    }

    async fn run_pipeline(self: Arc<Self>, mut receiver: TwoLaneReceiver) {
        let interval_ms = self.config.batch_flush_interval_ms.max(50);
        let mut flush_ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let purge_interval = Duration::from_millis(self.config.ttl_purge_interval_ms.max(50));
        let mut purge_ticker = tokio::time::interval(purge_interval);
        purge_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate t=0 tick so TTL purge runs periodically on interval ticks.
        purge_ticker.tick().await;
        let mut purge_in_flight: Option<JoinHandle<()>> = None;

        loop {
            tokio::select! {
                biased;
                maybe_event = receiver.recv() => {
                    match maybe_event {
                        Some(event) => self.process_event(&event),
                        None => break,
                    }
                }
                _ = flush_ticker.tick() => {
                    if let Err(err) = self.store.flush_if_interval_elapsed() {
                        tracing::warn!(error = %err, "periodic SQLite batch flush failed");
                    }
                }
                _ = purge_ticker.tick() => {
                    let busy = purge_in_flight.as_ref().is_some_and(|h| !h.is_finished());
                    if !busy {
                        let store = self.store.clone();
                        let retention_days = self.config.ttl_retention_days;
                        purge_in_flight = Some(tokio::task::spawn_blocking(move || {
                            let now_ms = current_unix_ms();
                            if let Err(err) = store.purge_expired(now_ms, retention_days) {
                                tracing::warn!(error = %err, "periodic SQLite TTL purge failed");
                            }
                        }));
                    }
                }
            }
        }

        if let Some(handle) = purge_in_flight {
            if let Err(err) = handle.await {
                tracing::warn!(error = %err, "TTL purge task panicked during shutdown");
            }
        }

        for remaining in receiver.drain_ready() {
            self.process_event(&remaining);
        }

        if let Err(err) = self.store.checkpoint_truncate() {
            tracing::warn!(error = %err, "worker shutdown checkpoint_truncate failed");
        }
    }

    fn process_event(&self, event: &SensorEvent) {
        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);

        let proc_ctx = self.resolve_process_context(event, event_ts_ms);

        let ctx = EventContext::with_parent(
            event,
            proc_ctx.parent_exe_path.as_deref(),
            proc_ctx.parent_command_line.as_deref(),
        );

        if self
            .pruner
            .should_prune_with_image(&ctx, proc_ctx.proc_exe_path.as_deref())
        {
            self.pruned_events.fetch_add(1, Ordering::Relaxed);
        } else if proc_ctx.should_evaluate_sigma {
            let matches = self
                .sigma
                .evaluate_with_image(&ctx, proc_ctx.proc_exe_path.as_deref());
            for m in matches {
                if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                    // Distinct script bodies evaluated in the same process must each be able to
                    // fire an alert; deduplicate per (instance, rule, content fingerprint).
                    let dedup_key = match event {
                        SensorEvent::ScriptEvaluated { script_content, .. } => {
                            let mut h = DefaultHasher::new();
                            script_content.hash(&mut h);
                            format!("{}:{:x}", m.rule_id, h.finish())
                        }
                        _ => m.rule_id.clone(),
                    };
                    if !self.is_new_rule_alert(inst_id, &dedup_key) {
                        continue;
                    }
                }
                let context_json = serde_json::json!({
                    "event": event,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "matched_fields": m.matched_fields,
                })
                .to_string();

                let alert = AlertRecord {
                    alert_id: Uuid::new_v4().to_string(),
                    timestamp_ms: event_ts_ms,
                    severity: m.severity,
                    source_layer: "LAYER_2_RULES".to_string(),
                    rule_id: m.rule_id,
                    title: m.title,
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended: false,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };
                if let Err(err) = self.store.record_alert(&alert) {
                    tracing::warn!(error = %err, rule_id = %alert.rule_id, "failed to record Sigma alert");
                } else {
                    self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let is_nrd = if let SensorEvent::DnsQuery { query_name, .. } = event {
            assess_domain_risk(query_name, None).is_nrd
        } else {
            false
        };

        if let Err(err) = self.store.ingest_event_with_exit(
            event,
            proc_ctx.store_hint.as_deref(),
            proc_ctx.exited_at_ms,
            is_nrd,
            "OBSERVED",
        ) {
            tracing::warn!(error = %err, "failed to ingest event into SQLite store");
        }

        match event.default_lane() {
            EventLane::HighPriority => {
                self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            }
            EventLane::Telemetry => {
                self.telemetry_processed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn is_new_rule_alert(&self, instance_id: &str, rule_id: &str) -> bool {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.mark_rule_alert_emitted(instance_id, rule_id)
    }

    fn resolve_process_context(
        &self,
        event: &SensorEvent,
        event_ts_ms: i64,
    ) -> ResolvedProcessContext {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        match event {
            SensorEvent::ProcessStart {
                identity,
                parent_pid,
                exe_path,
                command_line,
                user_sid,
            } => {
                let res = table.on_process_start(
                    *identity,
                    *parent_pid,
                    exe_path.clone(),
                    command_line.clone(),
                    user_sid.clone(),
                    event_ts_ms,
                );
                ResolvedProcessContext {
                    proc_instance_id: Some(res.instance_id),
                    proc_exe_path: Some(exe_path.clone()),
                    store_hint: res.parent_instance_id,
                    parent_exe_path: res.parent_exe_path,
                    parent_command_line: res.parent_command_line,
                    should_evaluate_sigma: res.should_evaluate_sigma,
                    exited_at_ms: res.exited_at_ms,
                }
            }
            SensorEvent::ProcessStop { pid, .. } => {
                let id = table.on_process_stop(*pid, event_ts_ms);
                ResolvedProcessContext {
                    proc_instance_id: id.clone(),
                    proc_exe_path: None,
                    store_hint: id,
                    parent_exe_path: None,
                    parent_command_line: None,
                    should_evaluate_sigma: true,
                    exited_at_ms: None,
                }
            }
            SensorEvent::DnsQuery { pid, .. }
            | SensorEvent::NetworkConnect { pid, .. }
            | SensorEvent::CanaryFileAccess { pid, .. }
            | SensorEvent::ScriptEvaluated { pid, .. } => {
                // Clone only the fields the context needs: cloning the whole entry would copy
                // `emitted_rule_ids`, which grows with every distinct fired (rule, script) pair.
                let Some((instance_id, exe_path, parent_instance_id)) = table
                    .lookup_by_pid_at(*pid, event_ts_ms)
                    .map(|e| {
                        (
                            e.instance_id.clone(),
                            e.exe_path.clone(),
                            e.parent_instance_id.clone(),
                        )
                    })
                else {
                    return ResolvedProcessContext::default();
                };
                let (parent_exe, parent_cmd) = parent_instance_id
                    .as_deref()
                    .and_then(|parent_id| table.get_by_instance_id(parent_id))
                    .map(|p| {
                        (
                            Some(p.exe_path.clone()),
                            (!p.command_line.is_empty()).then(|| p.command_line.clone()),
                        )
                    })
                    .unwrap_or((None, None));
                ResolvedProcessContext {
                    proc_instance_id: Some(instance_id.clone()),
                    proc_exe_path: Some(exe_path),
                    store_hint: Some(instance_id),
                    parent_exe_path: parent_exe,
                    parent_command_line: parent_cmd,
                    should_evaluate_sigma: true,
                    exited_at_ms: None,
                }
            }
        }
    }
}

struct ResolvedProcessContext {
    proc_instance_id: Option<String>,
    proc_exe_path: Option<String>,
    store_hint: Option<String>,
    parent_exe_path: Option<String>,
    parent_command_line: Option<String>,
    should_evaluate_sigma: bool,
    /// Inferred exit time carried from [`ProcessStartResolution`] for older snapshot
    /// incarnations so the store row does not stay "running" forever.
    exited_at_ms: Option<i64>,
}

impl Default for ResolvedProcessContext {
    fn default() -> Self {
        Self {
            proc_instance_id: None,
            proc_exe_path: None,
            store_hint: None,
            parent_exe_path: None,
            parent_command_line: None,
            should_evaluate_sigma: true,
            exited_at_ms: None,
        }
    }
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
