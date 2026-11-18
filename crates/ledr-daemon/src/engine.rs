//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    is_never_suspend_process, ActiveDefenseController, AlertDecision, AlertRecord, AlertSeverity,
    AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, CanaryCategory, EventLane, PipelineMetrics,
    ProcessIdentity, RuleScope, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY,
    DEFAULT_ALERT_TIMEOUT_SECS, DEFAULT_TTL_RETENTION_DAYS, HIGH_PRIORITY_CHANNEL_CAPACITY,
    IPC_PIPE_NAME, SHUTDOWN_FLUSH_TIMEOUT_MS, STORE_BATCH_FLUSH_INTERVAL_MS,
    TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{
    assess_domain_risk, compute_file_sha256_hex, inspect_authenticode, is_allowed_by_rules,
    BinaryIdentity, EarlyPruner, EventContext, SigmaEngine,
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
const DEFAULT_IPC_SESSION_TIMEOUT_MS: u64 = 60_000;
const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;

/// Abstraction for inspecting binary SHA-256 and Authenticode metadata (`L-04`).
pub trait BinaryInspector: Send + Sync {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity;
}

/// Default Windows binary inspector computing fresh streaming SHA-256 on every call
/// and caching only `Option<AuthenticodeInfo>` keyed by `(lowercase_exe_path, fresh_sha256)`
/// (`L-04`, `SEC_0005` — prevents size/mtime `SetFileTime` cache spoofing).
#[derive(Debug, Default)]
pub struct WindowsBinaryInspector {
    authenticode_cache: Mutex<HashMap<(String, String), Option<AuthenticodeInfo>>>,
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

        // Always recompute SHA-256 directly from file contents (SEC_0005).
        let Some(fresh_sha256) = compute_file_sha256_hex(path).ok() else {
            return BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            };
        };

        let cache_key = (exe_path.to_ascii_lowercase(), fresh_sha256.clone());
        if let Ok(guard) = self.authenticode_cache.lock() {
            if let Some(cached_auth) = guard.get(&cache_key) {
                return BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: Some(fresh_sha256),
                    authenticode: cached_auth.clone(),
                };
            }
        }

        let authenticode = inspect_authenticode(path);
        if let Ok(mut guard) = self.authenticode_cache.lock() {
            if guard.len() >= BINARY_INSPECTOR_CACHE_CAPACITY {
                guard.clear();
            }
            guard.insert(cache_key, authenticode.clone());
        }

        BinaryIdentity {
            exe_path: exe_path.to_string(),
            sha256: Some(fresh_sha256),
            authenticode,
        }
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
    /// Maximum wall-clock lifetime of one IPC client session (`SEC_0001`). In strict
    /// non-elevated mode only a single pipe instance exists, so a client must not be
    /// able to pin it forever with periodic lightweight requests.
    pub ipc_session_timeout_ms: u64,
    pub pipe_name: String,
    /// When `true` (Phase 1 `--foreground` dev mode), mutating IPC commands bypass the
    /// `C:\Program Files\LocalEDR\ledr-ui.exe` install-path check while still inspecting
    /// and logging caller process identity.
    pub dev_mode_bypass_ui_auth: bool,
    /// When `true` (strict mode, default unless `--dev-bypass-auth` is set), applies `SERVICE_PIPE_SDDL`
    /// (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)`) when creating the Named Pipe.
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
            ipc_session_timeout_ms: DEFAULT_IPC_SESSION_TIMEOUT_MS,
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

/// Outcome of a successful [`DaemonEngine::resolve_alert_with_outcome`] call.
#[derive(Debug)]
pub struct ResolvedAlertOutcome {
    /// The alert after its status transition.
    pub alert: AlertRecord,
    /// `rule_id` of the allowlist/block rule persisted by this decision, or `None`
    /// when no rule was stored (e.g. `AllowOnce`, or `add_block_rule` requested but
    /// the executable path could not be resolved — `ANALYSIS_0001`).
    pub saved_rule_id: Option<String>,
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
    /// Serializes `resolve_alert` so concurrent resolves of sibling alerts cannot both
    /// observe "another unresolved suspended alert exists" and leave the process
    /// suspended forever (`BUG_0002`).
    resolve_lock: Mutex<()>,
    prior_running_candidates: Mutex<Vec<String>>,
    sender: TwoLaneSender,
    started_at: Instant,
    high_priority_processed: AtomicU64,
    telemetry_processed: AtomicU64,
    pruned_events: AtomicU64,
    alerts_emitted: AtomicU64,
    fail_record_alert_for_test: AtomicBool,
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
            resolve_lock: Mutex::new(()),
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

    #[doc(hidden)]
    pub fn set_fail_record_alert_for_test(&self, fail: bool) {
        self.fail_record_alert_for_test
            .store(fail, Ordering::Release);
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

    /// Applies a user triage decision (`AllowOnce`, `AllowPermanent`, `TerminateAndBlock`)
    /// to an unresolved (`Pending` or `ExpiredSuspended`) alert (`L-04`, `L-07`).
    pub fn resolve_alert(
        &self,
        alert_id: &str,
        decision: AlertDecision,
    ) -> Result<AlertRecord, String> {
        self.resolve_alert_with_outcome(alert_id, decision)
            .map(|outcome| outcome.alert)
    }

    /// Like [`DaemonEngine::resolve_alert`], additionally reporting whether the
    /// requested allowlist/block rule was actually persisted (`ANALYSIS_0001`).
    pub fn resolve_alert_with_outcome(
        &self,
        alert_id: &str,
        decision: AlertDecision,
    ) -> Result<ResolvedAlertOutcome, String> {
        let _resolve_guard = self.resolve_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut saved_rule_id: Option<String> = None;
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
            .filter(|id| id.create_time_100ns != 0);

        let mut seen_children = HashSet::new();
        let mut suspended_children = Vec::new();
        collect_suspended_children_from_ctx(&ctx_val, identity, &mut seen_children, &mut suspended_children);
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            if let Ok(all_alerts) = self.store.list_alerts_for_process(proc_inst_id, false, 1000) {
                for other in all_alerts {
                    if other.alert_id != alert_id
                    {
                        if let Ok(other_ctx) =
                            serde_json::from_str::<serde_json::Value>(&other.context_json)
                        {
                            collect_suspended_children_from_ctx(
                                &other_ctx,
                                identity,
                                &mut seen_children,
                                &mut suspended_children,
                            );
                        }
                    }
                }
            }
        }

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
        let is_terminate = matches!(decision, AlertDecision::TerminateAndBlock { .. });

        match decision {
            AlertDecision::AllowOnce => {
                if alert.process_suspended {
                    let ident = identity.ok_or_else(|| {
                        format!("missing process identity to resume suspended alert {alert_id}")
                    })?;
                    if !self.has_other_unresolved_suspended_alert(
                        alert_id,
                        alert.process_instance_id.as_deref(),
                    )? {
                        self.resume_process_and_children(
                            alert_id,
                            &ident,
                            &suspended_children,
                        )?;
                    }
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
                saved_rule_id = Some(rule.rule_id.clone());

                if alert.process_suspended {
                    let resume_result = (|| -> Result<(), String> {
                        let ident = identity.ok_or_else(|| {
                            format!(
                                "missing process identity to resume suspended alert {alert_id}"
                            )
                        })?;
                        if !self.has_other_unresolved_suspended_alert(
                            alert_id,
                            alert.process_instance_id.as_deref(),
                        )? {
                            self.resume_process_and_children(
                                alert_id,
                                &ident,
                                &suspended_children,
                            )?;
                        }
                        Ok(())
                    })();
                    if let Err(err) = resume_result {
                        self.rollback_saved_rule(&rule.rule_id);
                        return Err(err);
                    }
                }
            }
            AlertDecision::TerminateAndBlock { add_block_rule } => {
                if let Some(ident) = identity {
                    if let Err(err) = self.defense.terminate_process(&ident, true) {
                        if is_protected_process_refusal(&err) {
                            return Err(err);
                        }
                        // A suspended alert tolerates the target already being gone: a
                        // previous attempt may have terminated the process and then
                        // failed the status update (rolling back the block rule), so a
                        // retry must reach the rule save instead of erroring again.
                        // A failure on a still-running process stays fatal.
                        if alert.process_suspended && !is_process_gone_or_replaced(&err, ident.pid) {
                            for child in &suspended_children {
                                let _ = self.defense.terminate_process(child, true);
                            }
                            return Err(err);
                        }
                        tracing::warn!(
                            alert_id = %alert_id,
                            pid = ident.pid,
                            error = %err,
                            "terminate_process failed (target already terminated or PID reused); continuing block rule and alert resolution"
                        );
                    }
                } else if alert.process_suspended {
                    return Err(format!(
                        "missing process identity to terminate suspended alert {alert_id}"
                    ));
                }

                for child in &suspended_children {
                    if let Err(err) = self.defense.terminate_process(child, true) {
                        // Only tolerate a child confirmed gone or PID-reused: a still-
                        // running child that cannot be terminated must keep the alert
                        // unresolved so the triage can be retried (`BUG_0001`).
                        if is_protected_process_refusal(&err)
                            || !is_process_gone_or_replaced(&err, child.pid)
                        {
                            return Err(err);
                        }
                        tracing::warn!(
                            alert_id = %alert_id,
                            child_pid = child.pid,
                            error = %err,
                            "terminate_process failed for suspended child (already exited); continuing"
                        );
                    }
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
                        saved_rule_id = Some(block_rule.rule_id.clone());
                    }
                }
            }
        }

        let status_result = self
            .store
            .update_alert_status(alert_id, new_status, Some(now_ms))
            .map_err(|err| format!("failed to update alert status: {err}"))
            .and_then(|updated| {
                if updated {
                    Ok(())
                } else {
                    Err(format!("alert {alert_id} not found"))
                }
            });
        if let Err(err) = status_result {
            if let Some(rule_id) = saved_rule_id.take() {
                self.rollback_saved_rule(&rule_id);
            }
            return Err(err);
        }

        if let Some(ref proc_inst_id) = alert.process_instance_id {
            self.clear_canary_dedup_from_context_val(proc_inst_id, &ctx_val);
            if is_terminate {
                self.resolve_sibling_alerts_as_terminated(alert_id, proc_inst_id, now_ms);
            }
        }

        alert.status = new_status;
        alert.resolved_at_ms = Some(now_ms);
        Ok(ResolvedAlertOutcome {
            alert,
            saved_rule_id,
        })
    }

    fn has_other_unresolved_suspended_alert(
        &self,
        alert_id: &str,
        process_instance_id: Option<&str>,
    ) -> Result<bool, String> {
        let Some(proc_inst_id) = process_instance_id else {
            return Ok(false);
        };
        let unresolved = self
            .store
            .list_alerts_for_process(proc_inst_id, true, 1000)
            .map_err(|err| format!("failed to query unresolved alerts: {err}"))?;
        let exists = unresolved.into_iter().any(|other| {
            other.alert_id != alert_id && other.process_suspended
        });
        if exists {
            tracing::info!(
                alert_id = %alert_id,
                process_instance_id = %proc_inst_id,
                "keeping process suspended because another unresolved suspended alert exists"
            );
        }
        Ok(exists)
    }

    /// Best-effort rollback of a rule stored by a failed
    /// [`DaemonEngine::resolve_alert_with_outcome`] call so a rejected resume or status update
    /// cannot leave a permanent allow/block rule active (BUG_0001).
    fn rollback_saved_rule(&self, rule_id: &str) {
        if let Err(err) = self.store.delete_rule(rule_id) {
            tracing::warn!(
                rule_id = %rule_id,
                error = %err,
                "failed to roll back allowlist rule after resolve error"
            );
        }
    }

    fn resume_process_and_children(
        &self,
        alert_id: &str,
        ident: &ProcessIdentity,
        suspended_children: &[ProcessIdentity],
    ) -> Result<(), String> {
        if let Err(err) = self.defense.resume_process(ident) {
            if is_protected_process_refusal(&err) {
                return Err(err);
            }
            // BUG_0004: only swallow the failure when the target is actually gone
            // (exited or PID reused). A live process that failed to resume must keep
            // the alert unresolved so the operator can retry.
            if !is_process_gone_or_replaced(&err, ident.pid) {
                return Err(format!(
                    "resume_process failed for alert {alert_id} (PID {} still running): {err}",
                    ident.pid
                ));
            }
            tracing::warn!(
                alert_id = %alert_id,
                pid = ident.pid,
                error = %err,
                "resume_process failed for parent (process already exited or PID reused); continuing child resume and alert resolution"
            );
        }
        for child in suspended_children {
            if let Err(err) = self.defense.resume_process(child) {
                if is_protected_process_refusal(&err) {
                    return Err(err);
                }
                if !is_process_gone_or_replaced(&err, child.pid) {
                    return Err(format!(
                        "resume_process failed for suspended child PID {} of alert {alert_id}: {err}",
                        child.pid
                    ));
                }
                tracing::warn!(
                    alert_id = %alert_id,
                    child_pid = child.pid,
                    error = %err,
                    "resume_process failed for suspended child (already exited); continuing"
                );
            }
        }
        Ok(())
    }

    fn resolve_sibling_alerts_as_terminated(
        &self,
        resolved_alert_id: &str,
        proc_inst_id: &str,
        now_ms: i64,
    ) {
        let Ok(unresolved) = self.store.list_alerts_for_process(proc_inst_id, true, 1000) else {
            return;
        };
        for other in unresolved {
            if other.alert_id != resolved_alert_id {
                match self.store.update_alert_status(
                    &other.alert_id,
                    AlertStatus::TerminatedBlocked,
                    Some(now_ms),
                ) {
                    Ok(true) => {
                        let ctx: serde_json::Value = serde_json::from_str(&other.context_json)
                            .unwrap_or(serde_json::Value::Null);
                        self.clear_canary_dedup_from_context_val(proc_inst_id, &ctx);
                    }
                    Ok(false) => {}
                    Err(err) => {
                        tracing::warn!(
                            sibling_alert_id = %other.alert_id,
                            error = %err,
                            "failed to mark sibling alert as TerminatedBlocked"
                        );
                    }
                }
            }
        }
    }

    fn clear_canary_dedup_from_context_val(
        &self,
        instance_id: &str,
        ctx_val: &serde_json::Value,
    ) {
        if let (Some(category), Some(target_path)) = (
            json_non_empty_str(ctx_val, "/category"),
            json_non_empty_str(ctx_val, "/target_path"),
        ) {
            let dedup_key = format!(
                "CANARY:{}:{}",
                category.to_ascii_lowercase(),
                target_path.trim().replace('/', "\\").to_ascii_lowercase()
            );
            self.clear_rule_alert(instance_id, &dedup_key);
        }
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
                let record_result = if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(&alert)
        };

        if let Err(err) = record_result {
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

        // ANALYSIS_0002: dedup check BEFORE the expensive binary inspection so every
        // repeat event in a canary burst does not re-read the executable on the
        // high-priority lane. This is a read-only check; the dedup mark is only set
        // below once the event is confirmed non-allowed (single worker, no race).
        let dedup_key = format!(
            "CANARY:{}:{}",
            category.as_str(),
            target_path.trim().replace('/', "\\").to_ascii_lowercase()
        );
        let already_emitted = proc_ctx
            .proc_instance_id
            .as_deref()
            .is_some_and(|inst_id| self.has_rule_alert_emitted(inst_id, &dedup_key));
        if already_emitted {
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

        // First non-allowed event for this (process, category, target): mark the dedup
        // slot now. Allowed events never consume it, and `record_alert` failure clears
        // it again below (BUG_0004 compensation path).
        if let Some(inst_id) = proc_ctx.proc_instance_id.as_deref() {
            let _ = self.is_new_rule_alert(inst_id, &dedup_key);
        }

        let include_children = matches!(category, CanaryCategory::Honeypot);
        let verified_ident = proc_ctx
            .proc_identity
            .filter(|id| id.create_time_100ns != 0);

        let mut process_suspended = false;
        if is_never_suspend_process(&exe_path) {
            tracing::info!(
                pid = *pid,
                exe_path = %exe_path,
                target_path = %target_path,
                "never-suspend guard skipped suspension on canary alert"
            );
        } else if let Some(ident) = verified_ident {
            match self.defense.suspend_process(&ident, include_children) {
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
        } else {
            tracing::warn!(
                pid = *pid,
                exe_path = %exe_path,
                target_path = %target_path,
                "skipping process suspension on canary alert: missing non-zero ProcessIdentity create_time_100ns (BUG_0001)"
            );
        }

        // Record only children the actuator actually suspends: `suspend_process` skips
        // descendants it cannot freeze, so confirming each one keeps a never-frozen child
        // out of the resume list and prevents its resume failure from blocking resolution
        // (BUG_0002). The call is idempotent for already-suspended children.
        let suspended_child_idents = if include_children && process_suspended {
            verified_ident
                .as_ref()
                .map(|ident| {
                    self.collect_descendant_identities_for_pid(ident)
                        .into_iter()
                        .filter(|child| {
                            let confirmed = self.defense.suspend_process(child, false).is_ok();
                            if !confirmed {
                                tracing::debug!(
                                    child_pid = child.pid,
                                    "descendant not suspended by actuator; excluding from alert resume list"
                                );
                            }
                            confirmed
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let suspended_children: Vec<String> = suspended_child_idents
            .iter()
            .map(ProcessIdentity::instance_id)
            .collect();

        let mut context_obj = serde_json::json!({
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
        });
        if include_children && process_suspended {
            if let Some(map) = context_obj.as_object_mut() {
                map.insert(
                    "suspended_children".to_string(),
                    serde_json::json!(suspended_children),
                );
            }
        }
        let context_json = context_obj.to_string();

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

        let record_result = if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(&alert)
        };

        if let Err(err) = record_result {
            tracing::warn!(
                error = %err,
                alert_id = %alert.alert_id,
                "failed to record canary alert; compensating suspension and dedup state (BUG_0004)"
            );
            if process_suspended {
                if let Some(ident) = verified_ident {
                    if let Err(resume_err) = self.defense.resume_process(&ident) {
                        tracing::warn!(
                            pid = ident.pid,
                            error = %resume_err,
                            "compensation resume_process failed for parent after record_alert error"
                        );
                    }
                    for child in &suspended_child_idents {
                        if let Err(resume_err) = self.defense.resume_process(child) {
                            tracing::debug!(
                                child_pid = child.pid,
                                error = %resume_err,
                                "compensation resume_process skipped for child after record_alert error"
                            );
                        }
                    }
                }
                process_suspended = false;
            }
            if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                self.clear_rule_alert(inst_id, &dedup_key);
            }
            let action = if process_suspended {
                "SUSPENDED"
            } else {
                "ALERTED"
            };
            if let Err(ingest_err) = self.store.ingest_event_with_exit(
                event,
                proc_ctx.store_hint.as_deref(),
                None,
                false,
                action,
            ) {
                tracing::warn!(error = %ingest_err, "failed to ingest canary event after alert error");
            }
            return;
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);

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

    fn has_rule_alert_emitted(&self, instance_id: &str, rule_id: &str) -> bool {
        let table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.has_rule_alert_emitted(instance_id, rule_id)
    }

    fn is_new_rule_alert(&self, instance_id: &str, rule_id: &str) -> bool {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.mark_rule_alert_emitted(instance_id, rule_id)
    }

    fn clear_rule_alert(&self, instance_id: &str, rule_id: &str) -> bool {
        let mut table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table.clear_rule_alert_emitted(instance_id, rule_id)
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

fn collect_suspended_children_from_ctx(
    ctx_val: &serde_json::Value,
    parent_identity: Option<ProcessIdentity>,
    seen: &mut HashSet<ProcessIdentity>,
    out: &mut Vec<ProcessIdentity>,
) {
    if let Some(arr) = ctx_val.get("suspended_children").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(id) = item
                .as_str()
                .and_then(ProcessIdentity::from_instance_id)
                .filter(|id| id.create_time_100ns != 0 && Some(*id) != parent_identity)
            {
                if seen.insert(id) {
                    out.push(id);
                }
            }
        }
    }
}

fn is_protected_process_refusal(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("refusing to act on") || lower.contains("never-suspend")
}

/// Returns `true` when a failed suspend/resume/terminate target is confirmed gone —
/// the snapshot positively reports the PID absent or its PID was reused (CreationTime
/// mismatch). Live processes and unverifiable states are genuine failures the caller
/// must surface (`BUG_0004`, `BUG_0002`).
fn is_process_gone_or_replaced(err: &str, pid: u32) -> bool {
    tolerate_missing_target(err, ledr_sensor_win::defense::process_liveness(pid))
}

/// `true` only when the failed suspend/resume/terminate target is confirmed gone: a
/// `CreationTime mismatch` proves PID reuse, or the snapshot positively reports the
/// PID absent. An unconfirmed absence (`Unknown` — snapshot/enumeration failed) is NOT
/// tolerated, so the caller surfaces the error and the operation stays retryable
/// (`BUG_0002`).
fn tolerate_missing_target(
    err: &str,
    liveness: ledr_sensor_win::defense::ProcessLiveness,
) -> bool {
    err.contains("CreationTime mismatch")
        || matches!(liveness, ledr_sensor_win::defense::ProcessLiveness::Gone)
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

#[cfg(test)]
mod tests {
    use super::tolerate_missing_target;
    use ledr_sensor_win::defense::ProcessLiveness;

    /// `DAEMON-P2-28` (`BUG_0002`): a snapshot/enumeration failure (`Unknown`) must not
    /// be treated as "gone" — only a positively absent PID or a proven PID reuse may
    /// swallow a suspend/resume/terminate error.
    #[test]
    fn daemon_p2_28_bug_0002_unknown_liveness_is_not_tolerated() {
        assert!(tolerate_missing_target(
            "OpenProcess failed",
            ProcessLiveness::Gone
        ));
        assert!(tolerate_missing_target(
            "PID reused: CreationTime mismatch",
            ProcessLiveness::Running
        ));
        assert!(!tolerate_missing_target(
            "OpenProcess failed",
            ProcessLiveness::Running
        ));
        assert!(!tolerate_missing_target(
            "OpenProcess failed",
            ProcessLiveness::Unknown
        ));
    }
}
