use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ledr_proto::{ActiveDefenseController, ProcessIdentity, SensorEvent};
use ledr_rules::{EarlyPruner, NrdCache, NrdCancelToken, SigmaEngine, NRD_MAX_ENTRIES};
use ledr_sensor_win::NoopDefenseController;
use ledr_store::{LedrStore, PurgeStats, StoreError};

use crate::channel::{OutboundLaneClassifier, TwoLaneChannel};
use crate::firewall::WfpRuleManager;
use crate::notify::{NoopNotificationDispatcher, NotificationDispatcher};
use crate::process_table::ActiveProcessTable;

use super::dns_history::ProcessDnsHistory;
use super::wfp_drops::{AppWfpAlertDedup, WfpDropDedupCache, WfpDropOverflowQueue};
use super::{
    current_unix_ms, BinaryInspector, DaemonConfig, DaemonEngine, LiveProcessInspector,
    WindowsBinaryInspector, WindowsLiveProcessInspector, APP_WFP_ALERT_DEDUP_CAPACITY,
    WFP_DROP_DEDUP_CAPACITY, WFP_DROP_DEDUP_WINDOW_MS,
};

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
        Self::start_with_all_dependencies(
            store,
            sigma,
            pruner,
            config,
            defense,
            notifier,
            inspector,
            Arc::new(WindowsLiveProcessInspector::new()),
        )
    }

    /// Starts a new [`DaemonEngine`] with custom [`ActiveDefenseController`],
    /// [`NotificationDispatcher`], [`BinaryInspector`], and [`LiveProcessInspector`]
    /// implementations (enabling deterministic test isolation from host OS PIDs).
    #[allow(clippy::too_many_arguments)]
    pub fn start_with_all_dependencies(
        store: LedrStore,
        sigma: SigmaEngine,
        pruner: EarlyPruner,
        config: DaemonConfig,
        defense: Arc<dyn ActiveDefenseController>,
        notifier: Arc<dyn NotificationDispatcher>,
        inspector: Arc<dyn BinaryInspector>,
        live_process_inspector: Arc<dyn LiveProcessInspector>,
    ) -> Arc<Self> {
        let prior_running_candidates = store.list_running_process_instance_ids().unwrap_or_default();
        let (sender, receiver) = TwoLaneChannel::with_capacities(
            config.high_priority_capacity,
            config.telemetry_capacity,
        )
        .split();
        let process_table = Mutex::new(ActiveProcessTable::new(config.active_process_capacity));
        let initial_nrd = config
            .nrd_cache_path
            .as_deref()
            .filter(|p| p.is_file())
            .and_then(|p| match NrdCache::load_from_file(p, NRD_MAX_ENTRIES) {
                Ok(cache) => {
                    tracing::info!(
                        path = %p.display(),
                        entries = cache.len(),
                        "loaded local NRD cache from disk"
                    );
                    Some(cache)
                }
                Err(err) => {
                    tracing::warn!(
                        path = %p.display(),
                        error = %err,
                        "failed loading local NRD cache; starting with empty NRD cache"
                    );
                    None
                }
            })
            .unwrap_or_default();

        let mut wfp_manager = WfpRuleManager::new();
        if config.outbound_firewall_enabled
            && config.outbound_enforcement_mode != super::OutboundEnforcementMode::Audit
        {
            wfp_manager.set_startup_preemptive_executables(&config.preemptive_startup_executables);
        }
        let outbound_classifier = Arc::new(OutboundLaneClassifier::new(
            config.outbound_firewall_enabled,
        ));
        let process_dns_history =
            Mutex::new(ProcessDnsHistory::new(config.dns_history_capacity));
        let wfp_drop_dedup = Mutex::new(WfpDropDedupCache::new(
            WFP_DROP_DEDUP_CAPACITY,
            WFP_DROP_DEDUP_WINDOW_MS,
        ));
        let (wfp_drop_tx, wfp_drop_rx) =
            tokio::sync::mpsc::channel(config.high_priority_capacity.max(1));
        let wfp_drop_overflow = Mutex::new(WfpDropOverflowQueue::new(
            config.high_priority_capacity.max(1),
        ));

        let engine = Arc::new(Self {
            config,
            store,
            sigma,
            pruner,
            defense,
            notifier,
            inspector,
            live_process_inspector,
            process_table,
            firewall: Mutex::new(wfp_manager),
            outbound_classifier,
            process_dns_history,
            wfp_drop_dedup,
            wfp_drop_tx,
            wfp_drop_overflow,
            wfp_drop_overflow_notify: tokio::sync::Notify::new(),
            wfp_drop_overflow_pushed: AtomicU64::new(0),
            wfp_drop_overflow_coalesced: AtomicU64::new(0),
            app_wfp_alert_dedup: Mutex::new(AppWfpAlertDedup::new(APP_WFP_ALERT_DEDUP_CAPACITY)),
            nrd_cache: Arc::new(RwLock::new(initial_nrd)),
            nrd_cancel: NrdCancelToken::new(),
            nrd_in_flight: Arc::new(AtomicBool::new(false)),
            nrd_thread_handle: Mutex::new(None),
            resolve_lock: Mutex::new(()),
            policy_lock: Mutex::new(()),
            prior_running_candidates: Mutex::new(prior_running_candidates),
            sender,
            started_at: Instant::now(),
            high_priority_processed: AtomicU64::new(0),
            telemetry_processed: AtomicU64::new(0),
            pruned_events: AtomicU64::new(0),
            alerts_emitted: AtomicU64::new(0),
            fail_record_alert_for_test: AtomicBool::new(false),
            worker_handle: tokio::sync::Mutex::new(None),
        });

        if engine.config.outbound_firewall_enabled {
            let report = engine.deploy_persisted_network_rules();
            if report.applied > 0 || report.failed > 0 {
                tracing::info!(
                    applied = report.applied,
                    removed = report.removed,
                    failed = report.failed,
                    "redeployed persisted firewall rules at engine startup"
                );
            }
        }

        let worker_engine = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            worker_engine.run_pipeline(receiver, wfp_drop_rx).await
        });

        if let Ok(mut slot) = engine.worker_handle.try_lock() {
            *slot = Some(handle);
        }

        engine
    }

    /// Seeds the in-memory [`ActiveProcessTable`] and SQLite store with initial OS process snapshots
    /// (`AUTO-03`), flushes them immediately, and reconciles any stale running processes from prior
    /// daemon sessions (`BUG_0001`, `BUG_0002`).
    pub fn seed_processes(&self, snapshots: Vec<SensorEvent>) -> Result<usize, anyhow::Error> {
        let mut count = 0usize;
        let mut active_id_set = HashSet::with_capacity(snapshots.len());
        for ev in snapshots {
            if matches!(&ev, SensorEvent::ProcessStart { .. }) {
                if let Some(resolved_id) = self.process_seed_process_start(&ev) {
                    active_id_set.insert(resolved_id);
                }
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

    /// Collects unexited descendant [`ProcessIdentity`] values for `root_ident` by combining
    /// the in-memory [`ActiveProcessTable`] with live OS Toolhelp32 descendants (`BUG_0005`).
    pub fn collect_descendant_identities_for_pid(
        &self,
        root_ident: &ProcessIdentity,
    ) -> Vec<ProcessIdentity> {
        if root_ident.create_time_100ns == 0 {
            return Vec::new();
        }
        let mut combined = {
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            table.collect_unexited_descendants(root_ident)
        };
        let mut seen: HashSet<ProcessIdentity> = combined.iter().copied().collect();
        seen.insert(*root_ident);
        for live in ledr_sensor_win::defense::collect_live_descendants(root_ident) {
            if live.create_time_100ns != 0 && seen.insert(live) {
                combined.push(live);
            }
        }
        combined
    }

    /// Closes ingestion, drains remaining queued events, joins background worker & NRD refresh
    /// threads, flushes SQLite batches, and runs `PRAGMA wal_checkpoint(TRUNCATE)` within
    /// `SHUTDOWN_FLUSH_TIMEOUT_MS` (`3,000 ms`, `AUTO-10`).
    pub async fn shutdown_and_flush(&self) -> Result<(), anyhow::Error> {
        let total_budget = Duration::from_millis(self.config.shutdown_flush_timeout_ms.max(1));
        let deadline = tokio::time::Instant::now() + total_budget;
        self.nrd_cancel.cancel();
        self.store.request_shutdown();
        self.sender.close();

        let handle = {
            let mut guard = self.worker_handle.lock().await;
            guard.take()
        };

        let mut worker_checkpointed = false;
        let mut drain_err: Option<anyhow::Error> = None;
        if let Some(h) = handle {
            match tokio::time::timeout_at(deadline, h).await {
                Ok(Ok(Ok(()))) => {
                    worker_checkpointed = true;
                }
                Ok(Ok(Err(store_err))) => {
                    drain_err = Some(anyhow::Error::new(store_err));
                }
                Ok(Err(join_err)) => {
                    tracing::error!(error = %join_err, "daemon worker task panicked during shutdown");
                    drain_err = Some(anyhow::anyhow!(
                        "daemon worker task panicked during shutdown: {join_err}"
                    ));
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = self.config.shutdown_flush_timeout_ms,
                        "daemon pipeline drain exceeded shutdown flush timeout; forcing best-effort checkpoint"
                    );
                    drain_err = Some(anyhow::anyhow!(
                        "daemon pipeline drain exceeded {} ms shutdown flush timeout",
                        self.config.shutdown_flush_timeout_ms
                    ));
                }
            }
        }

        let mut needs_checkpoint = !worker_checkpointed;
        if self.config.resume_suspended_on_shutdown
            && self.resume_unresolved_suspended_processes_on_shutdown(deadline)
        {
            needs_checkpoint = true;
        }

        // Prioritize WAL truncation BEFORE waiting on any remaining NRD refresh thread so a slow
        // or wedged NRD thread can never delay or starve SQLite checkpointing (`AUTO-10`, `R-11`, `ANALYSIS_0003`).
        if needs_checkpoint {
            self.store.checkpoint_truncate()?;
        }

        let nrd_handle = {
            let mut guard = self
                .nrd_thread_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        if let Some(mut nrd) = nrd_handle {
            let mut completed = nrd.join_handle.is_finished()
                || !matches!(
                    nrd.done_rx.try_recv(),
                    Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                );
            if !completed {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if !remaining.is_zero() {
                    match tokio::time::timeout(remaining, &mut nrd.done_rx).await {
                        Ok(Ok(())) | Ok(Err(_)) => {
                            completed = true;
                        }
                        Err(_) => {
                            completed = nrd.join_handle.is_finished();
                        }
                    }
                }
            }
            if completed {
                if nrd.join_handle.join().is_err() {
                    tracing::warn!("background NRD refresh thread panicked during shutdown");
                }
            } else {
                // Detach the raw OS thread without touching Tokio's blocking pool so subsequent
                // `Runtime::drop` cannot hang on an unresponsive NRD I/O thread (`R-11`).
                tracing::warn!(
                    timeout_ms = self.config.shutdown_flush_timeout_ms,
                    "shutdown budget exhausted waiting for background NRD refresh thread; detaching thread"
                );
            }
        }

        if let Some(err) = drain_err {
            return Err(err);
        }
        Ok(())
    }

    /// Best-effort resumes all unresolved (`Pending` / `ExpiredSuspended`) parent and child
    /// processes recorded as suspended in SQLite within the shared shutdown `deadline` when
    /// `resume_suspended_on_shutdown` is enabled (`--foreground` or `--resume-suspended-on-shutdown`).
    ///
    /// Confirmed resumed identities are recorded under `context_json.shutdown_resumed_identities` /
    /// `context_json.shutdown_resumed_at_ms`, while already-exited or PID-reused identities are
    /// separated into `context_json.shutdown_gone_identities` / `context_json.shutdown_cleared_at_ms`
    /// so UI and toast surfaces never claim a vanished process was resumed (`BUG_0002`, `BUG_0003`,
    /// `ANALYSIS_0003`, `PR23-U3`).
    /// Returns `true` if any SQLite alert row was updated and requires WAL checkpointing.
    pub(super) fn resume_unresolved_suspended_processes_on_shutdown(
        &self,
        deadline: tokio::time::Instant,
    ) -> bool {
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                "shutdown budget already exhausted before resuming unresolved suspended processes"
            );
            return false;
        }
        let alerts = match self.store.list_unresolved_suspended_alerts() {
            Ok(alerts) => alerts,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to query unresolved suspended alerts during shutdown"
                );
                return false;
            }
        };

        let mut seen: HashSet<ProcessIdentity> = HashSet::new();
        let mut to_resume: Vec<ProcessIdentity> = Vec::new();

        for alert in &alerts {
            let parent_ident = alert
                .process_instance_id
                .as_deref()
                .and_then(ProcessIdentity::from_instance_id)
                .filter(|id| id.create_time_100ns != 0);
            if alert.process_suspended {
                if let Some(id) = parent_ident {
                    if seen.insert(id) {
                        to_resume.push(id);
                    }
                }
            }
            if let Ok(ctx_val) = serde_json::from_str::<serde_json::Value>(&alert.context_json) {
                super::alerts::collect_suspended_children_from_ctx(
                    &ctx_val,
                    if alert.process_suspended {
                        parent_ident
                    } else {
                        None
                    },
                    &mut seen,
                    &mut to_resume,
                );
            }
        }

        if to_resume.is_empty() {
            return false;
        }

        let mut resumed = 0usize;
        let mut gone_or_replaced = 0usize;
        let mut failed = 0usize;
        let mut skipped_budget = 0usize;
        let mut resumed_identities: HashSet<ProcessIdentity> = HashSet::new();
        let mut gone_identities: HashSet<ProcessIdentity> = HashSet::new();

        for (idx, ident) in to_resume.iter().enumerate() {
            if tokio::time::Instant::now() >= deadline {
                skipped_budget = to_resume.len().saturating_sub(idx);
                tracing::warn!(
                    attempted = idx,
                    skipped_budget,
                    total = to_resume.len(),
                    "shutdown budget exhausted while resuming unresolved suspended processes"
                );
                break;
            }
            match self.defense.resume_process(ident) {
                Ok(()) => {
                    resumed += 1;
                    resumed_identities.insert(*ident);
                }
                Err(err) => {
                    if !super::alerts::is_protected_process_refusal(&err)
                        && super::alerts::is_process_gone_or_replaced(&err, ident.pid)
                    {
                        gone_or_replaced += 1;
                        gone_identities.insert(*ident);
                        tracing::info!(
                            pid = ident.pid,
                            create_time_100ns = ident.create_time_100ns,
                            error = %err,
                            "suspended process already exited or PID reused during shutdown resume; clearing suspension state"
                        );
                    } else {
                        failed += 1;
                        tracing::warn!(
                            pid = ident.pid,
                            create_time_100ns = ident.create_time_100ns,
                            error = %err,
                            "best-effort resume_process failed during shutdown; keeping suspension state"
                        );
                    }
                }
            }
        }

        let mut updated_alerts = 0usize;
        if !resumed_identities.is_empty() || !gone_identities.is_empty() {
            let cleared_at_ms = current_unix_ms();
            for alert in &alerts {
                let parent_ident = alert
                    .process_instance_id
                    .as_deref()
                    .and_then(ProcessIdentity::from_instance_id)
                    .filter(|id| id.create_time_100ns != 0);
                let parent_resumed = alert.process_suspended
                    && parent_ident.is_some_and(|id| resumed_identities.contains(&id));
                let parent_gone = alert.process_suspended
                    && parent_ident.is_some_and(|id| gone_identities.contains(&id));
                let parent_cleared = parent_resumed || parent_gone;
                let new_process_suspended = if parent_cleared {
                    false
                } else {
                    alert.process_suspended
                };

                let mut newly_resumed_ids: Vec<String> = Vec::new();
                let mut newly_gone_ids: Vec<String> = Vec::new();
                if let Some(id) = parent_ident {
                    if parent_resumed {
                        newly_resumed_ids.push(id.instance_id());
                    } else if parent_gone {
                        newly_gone_ids.push(id.instance_id());
                    }
                }

                let mut children_changed = false;
                let updated_context_json = match serde_json::from_str::<serde_json::Value>(
                    &alert.context_json,
                ) {
                    Ok(mut ctx_val) => {
                        if let Some(obj) = ctx_val.as_object_mut() {
                            if let Some(arr) =
                                obj.get("suspended_children").and_then(|v| v.as_array())
                            {
                                let mut remaining = Vec::with_capacity(arr.len());
                                for item in arr {
                                    let child_ident = item
                                        .as_str()
                                        .and_then(ProcessIdentity::from_instance_id)
                                        .filter(|id| id.create_time_100ns != 0);
                                    if let Some(child_id) =
                                        child_ident.filter(|id| resumed_identities.contains(id))
                                    {
                                        children_changed = true;
                                        let id_str = child_id.instance_id();
                                        if !newly_resumed_ids.contains(&id_str) {
                                            newly_resumed_ids.push(id_str);
                                        }
                                    } else if let Some(child_id) =
                                        child_ident.filter(|id| gone_identities.contains(id))
                                    {
                                        children_changed = true;
                                        let id_str = child_id.instance_id();
                                        if !newly_gone_ids.contains(&id_str) {
                                            newly_gone_ids.push(id_str);
                                        }
                                    } else {
                                        remaining.push(item.clone());
                                    }
                                }
                                if children_changed {
                                    obj.insert(
                                        "suspended_children".to_string(),
                                        serde_json::Value::Array(remaining),
                                    );
                                }
                            }
                            if parent_cleared || children_changed {
                                if !newly_resumed_ids.is_empty() {
                                    let existing_audit = obj
                                        .entry("shutdown_resumed_identities".to_string())
                                        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                                    if let Some(audit_arr) = existing_audit.as_array_mut() {
                                        for id_str in &newly_resumed_ids {
                                            let exists = audit_arr
                                                .iter()
                                                .any(|v| v.as_str() == Some(id_str.as_str()));
                                            if !exists {
                                                audit_arr.push(serde_json::Value::String(
                                                    id_str.clone(),
                                                ));
                                            }
                                        }
                                    }
                                    obj.insert(
                                        "shutdown_resumed_at_ms".to_string(),
                                        serde_json::Value::from(cleared_at_ms),
                                    );
                                }
                                if !newly_gone_ids.is_empty() {
                                    let existing_gone = obj
                                        .entry("shutdown_gone_identities".to_string())
                                        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
                                    if let Some(gone_arr) = existing_gone.as_array_mut() {
                                        for id_str in &newly_gone_ids {
                                            let exists = gone_arr
                                                .iter()
                                                .any(|v| v.as_str() == Some(id_str.as_str()));
                                            if !exists {
                                                gone_arr.push(serde_json::Value::String(
                                                    id_str.clone(),
                                                ));
                                            }
                                        }
                                    }
                                    obj.insert(
                                        "shutdown_cleared_at_ms".to_string(),
                                        serde_json::Value::from(cleared_at_ms),
                                    );
                                }
                            }
                        }
                        if parent_cleared || children_changed {
                            Some(ctx_val.to_string())
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        if parent_cleared {
                            Some(alert.context_json.clone())
                        } else {
                            None
                        }
                    }
                };

                if let Some(new_ctx_json) = updated_context_json {
                    match self.store.update_alert_suspension_state(
                        &alert.alert_id,
                        new_process_suspended,
                        &new_ctx_json,
                    ) {
                        Ok(true) => updated_alerts += 1,
                        Ok(false) => {}
                        Err(err) => {
                            tracing::warn!(
                                alert_id = %alert.alert_id,
                                error = %err,
                                "failed to update alert suspension state after shutdown resume"
                            );
                        }
                    }
                }
            }
        }

        tracing::info!(
            total = to_resume.len(),
            resumed,
            gone_or_replaced,
            failed,
            skipped_budget,
            updated_alerts,
            "completed best-effort resume of unresolved suspended processes on shutdown"
        );
        updated_alerts > 0
    }
}
