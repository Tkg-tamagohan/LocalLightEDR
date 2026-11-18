//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    is_never_suspend_process, ActiveDefenseController, AlertDecision, AlertRecord, AlertSeverity,
    AlertStatus, AllowlistRuleRecord, CanaryCategory, EventLane, PipelineMetrics, ProcessIdentity,
    RuleScope, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY, DEFAULT_ALERT_TIMEOUT_SECS,
    DEFAULT_TTL_RETENTION_DAYS, HIGH_PRIORITY_CHANNEL_CAPACITY, IPC_PIPE_NAME,
    SHUTDOWN_FLUSH_TIMEOUT_MS, STORE_BATCH_FLUSH_INTERVAL_MS, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{
    assess_domain_risk, is_allowed_by_rules, BinaryIdentity, EarlyPruner, EventContext,
    SigmaEngine,
};
use ledr_sensor_win::NoopDefenseController;
use ledr_store::{LedrStore, PurgeStats, StoreError};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::channel::{TwoLaneChannel, TwoLaneReceiver, TwoLaneSender};
use crate::notify::{NoopNotificationDispatcher, NotificationDispatcher};
use crate::process_table::ActiveProcessTable;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DEFAULT_TTL_PURGE_INTERVAL_MS: u64 = 3_600_000;
const DEFAULT_MAX_CONCURRENT_IPC_CLIENTS: usize = 16;
const DEFAULT_IPC_FRAME_TIMEOUT_MS: u64 = 5_000;
const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;

/// Abstraction for inspecting binary SHA-256 and Authenticode metadata (`L-04`).
pub trait BinaryInspector: Send + Sync {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity;
}

#[derive(Debug, Clone)]
struct CachedBinaryIdentity {
    file_len: u64,
    modified_ns: u128,
    identity: BinaryIdentity,
}

/// Default Windows binary inspector computing streaming SHA-256 and Authenticode
/// verification with `(len, mtime)` bounded caching (`L-04`).
#[derive(Debug, Default)]
pub struct WindowsBinaryInspector {
    cache: Mutex<HashMap<String, CachedBinaryIdentity>>,
}

impl WindowsBinaryInspector {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BinaryInspector for WindowsBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        if exe_path.trim().is_empty() {
            return BinaryIdentity {
                exe_path: String::new(),
                sha256: None,
                authenticode: None,
            };
        }

        let path = Path::new(exe_path);
        let Ok(meta) = std::fs::metadata(path) else {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        };
        if !meta.is_file() {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        }

        let file_len = meta.len();
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        let cache_key = exe_path.to_ascii_lowercase();

        if let Ok(guard) = self.cache.lock() {
            if let Some(cached) = guard.get(&cache_key) {
                if cached.file_len == file_len && cached.modified_ns == modified_ns {
                    return BinaryIdentity {
                        exe_path: exe_path.to_string(),
                        sha256: cached.identity.sha256.clone(),
                        authenticode: cached.identity.authenticode.clone(),
                    };
                }
            }
        }

        let computed = BinaryIdentity::from_path(path);
        if let Ok(mut guard) = self.cache.lock() {
            if guard.len() >= BINARY_INSPECTOR_CACHE_CAPACITY {
                guard.clear();
            }
            guard.insert(
                cache_key,
                CachedBinaryIdentity {
                    file_len,
                    modified_ns,
                    identity: computed.clone(),
                },
            );
        }
        computed
    }
}

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
    pub alert_timeout_ms: u64,
    pub max_concurrent_ipc_clients: usize,
    pub ipc_frame_timeout_ms: u64,
    pub pipe_name: String,
    /// When `true` (Phase 1 `--foreground` dev mode), mutating IPC commands bypass the
    /// `C:\Program Files\LocalEDR\ledr-ui.exe` install-path check while still inspecting
    /// and logging caller process identity.
    pub dev_mode_bypass_ui_auth: bool,
    /// When `true` (`--service-strict` mode), applies the restricted `SERVICE_PIPE_SDDL`
    /// DACL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`) when creating the Named Pipe.
    pub strict_pipe_dacl: bool,
    /// Optional expected lowercase SHA-256 hex digest for the authorized UI binary (`L-09`).
    pub authorized_ui_sha256: Option<String>,
    /// Optional expected Authenticode signer subject for the authorized UI binary (`L-09`).
    pub authorized_ui_signer: Option<String>,
    /// Optional expected Authenticode root thumbprint for the authorized UI binary (`L-09`).
    pub authorized_ui_root_thumbprint: Option<String>,
    /// Optional expected lowercase SHA-256 hex digest for the authorized bridge binary (`L-09`).
    pub authorized_bridge_sha256: Option<String>,
    /// Optional expected Authenticode signer subject for the authorized bridge binary (`L-09`).
    pub authorized_bridge_signer: Option<String>,
    /// Optional expected Authenticode root thumbprint for the authorized bridge binary (`L-09`).
    pub authorized_bridge_root_thumbprint: Option<String>,
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
            alert_timeout_ms: DEFAULT_ALERT_TIMEOUT_SECS * 1000,
            max_concurrent_ipc_clients: DEFAULT_MAX_CONCURRENT_IPC_CLIENTS,
            ipc_frame_timeout_ms: DEFAULT_IPC_FRAME_TIMEOUT_MS,
            pipe_name: IPC_PIPE_NAME.to_string(),
            dev_mode_bypass_ui_auth: true,
            strict_pipe_dacl: false,
            authorized_ui_sha256: None,
            authorized_ui_signer: None,
            authorized_ui_root_thumbprint: None,
            authorized_bridge_sha256: None,
            authorized_bridge_signer: None,
            authorized_bridge_root_thumbprint: None,
        }
    }
}

/// Resident Layer 2 detection and persistence pipeline engine.
pub struct DaemonEngine {
    config: DaemonConfig,
    store: LedrStore,
    sigma: SigmaEngine,
    pruner: EarlyPruner,
    defense: Arc<dyn ActiveDefenseController>,
    notifier: Arc<dyn NotificationDispatcher>,
    inspector: Arc<dyn BinaryInspector>,
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
    /// Starts a new [`DaemonEngine`] using [`NoopDefenseController`] and [`NoopNotificationDispatcher`].
    pub fn start(
        store: LedrStore,
        sigma: SigmaEngine,
        pruner: EarlyPruner,
        config: DaemonConfig,
    ) -> Arc<Self> {
        Self::start_with_controllers(
            store,
            sigma,
            pruner,
            config,
            Arc::new(NoopDefenseController),
            Arc::new(NoopNotificationDispatcher),
        )
    }

    /// Starts a new [`DaemonEngine`] with explicit [`ActiveDefenseController`] and
    /// [`NotificationDispatcher`] implementations (`L-01`, `L-07`, `L-08`).
    pub fn start_with_controllers(
        store: LedrStore,
        sigma: SigmaEngine,
        pruner: EarlyPruner,
        config: DaemonConfig,
        defense: Arc<dyn ActiveDefenseController>,
        notifier: Arc<dyn NotificationDispatcher>,
    ) -> Arc<Self> {
        Self::start_with_dependencies(
            store,
            sigma,
            pruner,
            config,
            defense,
            notifier,
            Arc::new(WindowsBinaryInspector::new()),
        )
    }

    /// Starts a new [`DaemonEngine`] with custom [`ActiveDefenseController`],
    /// [`NotificationDispatcher`], and [`BinaryInspector`] implementations.
    pub fn start_with_dependencies(
        store: LedrStore,
        sigma: SigmaEngine,
        pruner: EarlyPruner,
        config: DaemonConfig,
        defense: Arc<dyn ActiveDefenseController>,
        notifier: Arc<dyn NotificationDispatcher>,
        inspector: Arc<dyn BinaryInspector>,
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
            defense,
            notifier,
            inspector,
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

    /// Transitions overdue `PENDING` alerts older than `alert_timeout_ms` to
    /// `EXPIRED_SUSPENDED` WITHOUT resuming the suspended processes (`L-07`).
    pub fn expire_overdue_alerts(&self, now_ms: i64) -> Result<usize, StoreError> {
        let timeout_ms = i64::try_from(self.config.alert_timeout_ms).unwrap_or(i64::MAX);
        let cutoff_ms = now_ms.saturating_sub(timeout_ms);
        self.store.expire_pending_alerts(cutoff_ms)
    }

    /// Applies a user triage decision (`AllowOnce`, `AllowPermanent`, `TerminateAndBlock`)
    /// to an unresolved (`Pending` or `ExpiredSuspended`) alert (`L-04`, `L-07`).
    pub fn resolve_alert(
        &self,
        alert_id: &str,
        decision: AlertDecision,
    ) -> Result<AlertRecord, String> {
        let mut alert = self
            .store
            .get_alert(alert_id)
            .map_err(|err| format!("failed to query alert {alert_id}: {err}"))?
            .ok_or_else(|| format!("alert {alert_id} not found"))?;

        if !alert.status.is_unresolved() {
            return Err(format!(
                "alert {alert_id} is already resolved ({})",
                alert.status.as_db_str()
            ));
        }

        let ctx_val: serde_json::Value =
            serde_json::from_str(&alert.context_json).unwrap_or(serde_json::Value::Null);

        let identity = alert
            .process_instance_id
            .as_deref()
            .and_then(ProcessIdentity::from_instance_id)
            .or_else(|| {
                ctx_val
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .and_then(|p| u32::try_from(p).ok())
                    .map(|pid| ProcessIdentity::new(pid, 0))
            });

        let mut exe_path = json_non_empty_str(&ctx_val, "/exe_path")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/ProcessStart/exe_path"))
            .or_else(|| {
                alert
                    .process_instance_id
                    .as_deref()
                    .and_then(|inst_id| {
                        self.process_table
                            .lock()
                            .ok()
                            .and_then(|t| t.get_by_instance_id(inst_id).map(|e| e.exe_path.clone()))
                    })
                    .filter(|s| !s.trim().is_empty())
            });
        if exe_path.is_none() {
            if let Some(ref inst_id) = alert.process_instance_id {
                if let Ok(snap) = self.store.query_flight_recorder(1, Some(inst_id)) {
                    exe_path = snap
                        .processes
                        .into_iter()
                        .next()
                        .map(|p| p.exe_path)
                        .filter(|s| !s.trim().is_empty());
                }
            }
        }

        let mut sha256 = json_non_empty_str(&ctx_val, "/sha256");
        let mut signer_subject = json_non_empty_str(&ctx_val, "/signer_subject");
        let mut root_thumbprint = json_non_empty_str(&ctx_val, "/root_thumbprint");

        if (sha256.is_none() || (signer_subject.is_some() && root_thumbprint.is_none()))
            && exe_path.is_some()
        {
            if let Some(ref exe) = exe_path {
                let inspected = self.inspector.inspect(exe);
                if sha256.is_none() {
                    sha256 = inspected.sha256;
                }
                if signer_subject.is_none() || root_thumbprint.is_none() {
                    if let Some(auth) = inspected.authenticode {
                        if signer_subject.is_none() {
                            signer_subject = Some(auth.signer_subject);
                        }
                        if root_thumbprint.is_none() {
                            root_thumbprint = Some(auth.root_thumbprint);
                        }
                    }
                }
            }
        }

        let now_ms = current_unix_ms();
        let new_status = decision.resulting_status();

        match decision {
            AlertDecision::AllowOnce => {
                if alert.process_suspended {
                    let ident = identity.ok_or_else(|| {
                        format!("missing process identity to resume suspended alert {alert_id}")
                    })?;
                    self.defense.resume_process(&ident)?;
                }
            }
            AlertDecision::AllowPermanent {
                use_signer_if_available,
                allow_dest,
            } => {
                let exe = exe_path.clone().ok_or_else(|| {
                    format!("missing executable path to create allowlist rule for alert {alert_id}")
                })?;

                let scope = if ctx_val.pointer("/event/NetworkConnect").is_some() {
                    RuleScope::NetworkAllow
                } else {
                    RuleScope::FileCanaryAllow
                };

                let (rule_sha256, rule_signer, rule_thumbprint) =
                    if use_signer_if_available
                        && signer_subject.is_some()
                        && root_thumbprint.is_some()
                    {
                        (None, signer_subject, root_thumbprint)
                    } else {
                        let hash = sha256.ok_or_else(|| {
                            format!(
                                "cannot create unsigned allowlist rule without SHA-256 digest for {exe} (L-04)"
                            )
                        })?;
                        (Some(hash), None, None)
                    };

                let rule = AllowlistRuleRecord {
                    rule_id: format!("RULE-ALLOW-{}", Uuid::new_v4()),
                    scope,
                    exe_path_pattern: exe,
                    sha256: rule_sha256,
                    signer_subject: rule_signer,
                    root_thumbprint: rule_thumbprint,
                    allowed_target: allow_dest
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    created_at_ms: now_ms,
                    created_by: "user_triage".to_string(),
                };

                self.store
                    .upsert_rule(&rule)
                    .map_err(|err| format!("failed to store permanent allowlist rule: {err}"))?;

                if alert.process_suspended {
                    let ident = identity.ok_or_else(|| {
                        format!("missing process identity to resume suspended alert {alert_id}")
                    })?;
                    self.defense.resume_process(&ident)?;
                }
            }
            AlertDecision::TerminateAndBlock { add_block_rule } => {
                if let Some(ident) = identity {
                    if let Err(err) = self.defense.terminate_process(&ident, true) {
                        if alert.process_suspended || is_protected_process_refusal(&err) {
                            return Err(err);
                        }
                        tracing::warn!(
                            alert_id = %alert_id,
                            pid = ident.pid,
                            error = %err,
                            "terminate_process failed for non-suspended alert (process already exited or PID reused); continuing block rule and alert resolution"
                        );
                    }
                } else if alert.process_suspended {
                    return Err(format!(
                        "missing process identity to terminate suspended alert {alert_id}"
                    ));
                }

                if add_block_rule {
                    if let Some(exe) = exe_path {
                        let block_rule = AllowlistRuleRecord {
                            rule_id: format!("RULE-BLOCK-{}", Uuid::new_v4()),
                            scope: RuleScope::NetworkBlock,
                            exe_path_pattern: exe,
                            sha256,
                            signer_subject: None,
                            root_thumbprint: None,
                            allowed_target: None,
                            created_at_ms: now_ms,
                            created_by: "user_quarantine".to_string(),
                        };
                        self.store
                            .upsert_rule(&block_rule)
                            .map_err(|err| format!("failed to store block rule: {err}"))?;
                    }
                }
            }
        }

        let updated = self
            .store
            .update_alert_status(alert_id, new_status, Some(now_ms))
            .map_err(|err| format!("failed to update alert status: {err}"))?;
        if !updated {
            return Err(format!("alert {alert_id} not found"));
        }

        alert.status = new_status;
        alert.resolved_at_ms = Some(now_ms);
        Ok(alert)
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

        let expiry_interval_ms = (self.config.alert_timeout_ms / 4).clamp(50, 5_000);
        let mut expiry_ticker = tokio::time::interval(Duration::from_millis(expiry_interval_ms));
        expiry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        expiry_ticker.tick().await;

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
                _ = expiry_ticker.tick() => {
                    if let Err(err) = self.expire_overdue_alerts(current_unix_ms()) {
                        tracing::warn!(error = %err, "periodic alert expiry transition failed");
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
        if let SensorEvent::CanaryFileAccess {
            category: CanaryCategory::Honeypot,
            is_write_or_delete: false,
            ..
        } = event
        {
            // L-06: Read-only honeypot opens are ignored to avoid SearchIndexer/backup false positives.
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);

        let proc_ctx = self.resolve_process_context(event, event_ts_ms);

        if matches!(event, SensorEvent::CanaryFileAccess { .. }) {
            self.handle_canary_file_access(event, &proc_ctx, event_ts_ms);
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return;
        }

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

    fn handle_canary_file_access(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        event_ts_ms: i64,
    ) {
        let SensorEvent::CanaryFileAccess {
            pid,
            target_path,
            category,
            access_mask,
            is_write_or_delete,
            ..
        } = event
        else {
            return;
        };

        let exe_path = proc_ctx.proc_exe_path.clone().unwrap_or_default();
        let bin_identity = if exe_path.trim().is_empty() {
            BinaryIdentity {
                exe_path: String::new(),
                sha256: None,
                authenticode: None,
            }
        } else {
            self.inspector.inspect(&exe_path)
        };

        let rules = self.store.list_rules(Some(RuleScope::FileCanaryAllow)).unwrap_or_default();
        let allowed = !exe_path.trim().is_empty()
            && is_allowed_by_rules(
                &bin_identity,
                Some(target_path),
                RuleScope::FileCanaryAllow,
                &rules,
            );

        if allowed {
            if let Err(err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                "ALLOWED",
            ) {
                tracing::warn!(error = %err, "failed to ingest allowed canary event");
            }
            return;
        }

        let dedup_key = format!(
            "CANARY:{}:{}",
            category.as_str(),
            target_path.trim().replace('/', "\\").to_ascii_lowercase()
        );
        let is_new_alert = proc_ctx
            .proc_instance_id
            .as_deref()
            .is_none_or(|inst_id| self.is_new_rule_alert(inst_id, &dedup_key));
        if !is_new_alert {
            if let Err(err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                "DEDUP_SUPPRESSED",
            ) {
                tracing::warn!(error = %err, "failed to ingest deduplicated canary event");
            }
            return;
        }

        let include_children = matches!(category, CanaryCategory::Honeypot);
        let target_ident = proc_ctx
            .proc_identity
            .unwrap_or_else(|| ProcessIdentity::new(*pid, 0));

        let mut process_suspended = false;
        if is_never_suspend_process(&exe_path) {
            tracing::info!(
                pid = *pid,
                exe_path = %exe_path,
                target_path = %target_path,
                "never-suspend guard skipped suspension on canary alert"
            );
        } else {
            match self.defense.suspend_process(&target_ident, include_children) {
                Ok(()) => process_suspended = true,
                Err(err) => {
                    tracing::warn!(
                        pid = *pid,
                        exe_path = %exe_path,
                        include_children,
                        error = %err,
                        "suspend_process failed on canary access"
                    );
                }
            }
        }

        let context_json = serde_json::json!({
            "target_path": target_path,
            "category": category.as_str(),
            "access_mask": access_mask,
            "is_write_or_delete": is_write_or_delete,
            "pid": pid,
            "exe_path": exe_path,
            "command_line": proc_ctx.proc_command_line,
            "parent_exe_path": proc_ctx.parent_exe_path,
            "parent_command_line": proc_ctx.parent_command_line,
            "sha256": bin_identity.sha256,
            "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
            "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
            "include_children": include_children,
        })
        .to_string();

        let alert = AlertRecord {
            alert_id: Uuid::new_v4().to_string(),
            timestamp_ms: event_ts_ms,
            severity: canary_severity(*category),
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: format!("LEDR-CANARY-{}", category.as_str().to_ascii_uppercase()),
            title: canary_alert_title(*category, target_path),
            process_instance_id: proc_ctx.proc_instance_id.clone(),
            process_suspended,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        if let Err(err) = self.store.record_alert(&alert) {
            tracing::warn!(error = %err, alert_id = %alert.alert_id, "failed to record canary alert");
        } else {
            self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        }

        let action = if process_suspended {
            "SUSPENDED"
        } else {
            "ALERTED"
        };
        if let Err(err) = self.store.ingest_event_with_exit(
            event,
            proc_ctx.store_hint.as_deref(),
            None,
            false,
            action,
        ) {
            tracing::warn!(error = %err, "failed to ingest canary event");
        }

        if let Err(err) = self.notifier.notify_alert(&alert) {
            tracing::warn!(
                alert_id = %alert.alert_id,
                error = %err,
                "failed to dispatch toast notification for canary alert"
            );
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
                    proc_identity: Some(*identity),
                    proc_instance_id: Some(res.instance_id),
                    proc_exe_path: Some(exe_path.clone()),
                    proc_command_line: (!command_line.is_empty()).then(|| command_line.clone()),
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
                    proc_identity: None,
                    proc_instance_id: id.clone(),
                    proc_exe_path: None,
                    proc_command_line: None,
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
                let Some((identity, instance_id, exe_path, command_line, parent_instance_id)) =
                    table.lookup_by_pid_at(*pid, event_ts_ms).map(|e| {
                        (
                            e.identity,
                            e.instance_id.clone(),
                            e.exe_path.clone(),
                            e.command_line.clone(),
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
                    proc_identity: Some(identity),
                    proc_instance_id: Some(instance_id.clone()),
                    proc_exe_path: Some(exe_path),
                    proc_command_line: (!command_line.is_empty()).then_some(command_line),
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
    proc_identity: Option<ProcessIdentity>,
    proc_instance_id: Option<String>,
    proc_exe_path: Option<String>,
    proc_command_line: Option<String>,
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
            proc_identity: None,
            proc_instance_id: None,
            proc_exe_path: None,
            proc_command_line: None,
            store_hint: None,
            parent_exe_path: None,
            parent_command_line: None,
            should_evaluate_sigma: true,
            exited_at_ms: None,
        }
    }
}

fn is_protected_process_refusal(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("refusing to act on") || lower.contains("never-suspend")
}

fn json_non_empty_str(val: &serde_json::Value, pointer: &str) -> Option<String> {
    val.pointer(pointer)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

const fn canary_severity(category: CanaryCategory) -> AlertSeverity {
    match category {
        CanaryCategory::Honeypot => AlertSeverity::Critical,
        CanaryCategory::CookieDb
        | CanaryCategory::LoginData
        | CanaryCategory::SshKey
        | CanaryCategory::CloudCredential
        | CanaryCategory::EnvFile
        | CanaryCategory::AutorunRegistry => AlertSeverity::High,
    }
}

fn canary_alert_title(category: CanaryCategory, target_path: &str) -> String {
    let label = match category {
        CanaryCategory::CookieDb => "Browser Cookie Store Access",
        CanaryCategory::LoginData => "Browser Credential Store Access",
        CanaryCategory::SshKey => "SSH Private Key Access",
        CanaryCategory::CloudCredential => "Cloud Credential Access",
        CanaryCategory::EnvFile => "Project .env Secret Access",
        CanaryCategory::Honeypot => "Honeypot Decoy Modification",
        CanaryCategory::AutorunRegistry => "Autorun Persistence Modification",
    };
    let name = target_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(target_path);
    format!("{label}: {name}")
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
