//! Core Layer 2 daemon pipeline wiring [`TwoLaneChannel`], [`ActiveProcessTable`],
//! [`EarlyPruner`], [`SigmaEngine`], and [`LedrStore`].

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_proto::{
    is_never_suspend_process, ActiveDefenseController, AlertDecision, AlertRecord, AlertSeverity,
    AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, CanaryCategory, EventLane, PipelineMetrics,
    ProcessIdentity, RuleScope, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY,
    DEFAULT_ALERT_TIMEOUT_SECS, DEFAULT_TTL_RETENTION_DAYS, DNS_RESOLUTION_CACHE_CAPACITY,
    HIGH_PRIORITY_CHANNEL_CAPACITY, IPC_PIPE_NAME, SHUTDOWN_FLUSH_TIMEOUT_MS,
    STORE_BATCH_FLUSH_INTERVAL_MS, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{
    assess_domain_risk, canonical_ip, classify_outbound_risk, compute_file_sha256_hex,
    evaluate_outbound_policy, inspect_authenticode, is_allowed_by_rules, is_external_ip,
    matches_app_wide_network_allow, matches_app_wide_network_block, matches_network_block_rule,
    matches_network_target, matches_path_pattern, parse_cidr_target, refresh_nrd_cache_cancellable,
    validate_policy_rule, BinaryIdentity, DomainRiskAssessment, EarlyPruner, EventContext,
    NrdCache, NrdCancelToken, NrdRefreshStats, OutboundDecision, OutboundRiskClass, SigmaEngine,
    DEFAULT_NRD_FEED_URLS, NRD_MAX_ENTRIES, NRD_MAX_RESPONSE_BYTES, NRD_REFRESH_INTERVAL_MS,
};
use ledr_sensor_win::{NoopDefenseController, WfpDropEvent, WfpDropSinkFn};
use ledr_store::{LedrStore, PurgeStats, StoreError};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::channel::{
    ClassifiedEventSender, OutboundLaneClassifier, TwoLaneChannel, TwoLaneReceiver, TwoLaneSender,
};
use crate::firewall::{
    parse_literal_target_ip, WfpFailedOp, WfpFilterOrigin, WfpReconcileReport, WfpRuleManager,
};
use crate::notify::{NoopNotificationDispatcher, NotificationDispatcher};
use crate::process_table::ActiveProcessTable;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;
const DEFAULT_TTL_PURGE_INTERVAL_MS: u64 = 3_600_000;
const DEFAULT_MAX_CONCURRENT_IPC_CLIENTS: usize = 16;
const DEFAULT_IPC_FRAME_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IPC_SESSION_TIMEOUT_MS: u64 = 60_000;
const BINARY_INSPECTOR_CACHE_CAPACITY: usize = 512;
const WFP_DROP_DEDUP_CAPACITY: usize = 1024;
const WFP_DROP_DEDUP_WINDOW_MS: i64 = 250;
const DEFAULT_WFP_DROP_DNS_GRACE_MS: u64 = 300;
const MAX_PENDING_WFP_DROPS: usize = 512;
const APP_WFP_ALERT_DEDUP_CAPACITY: usize = 512;

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
    /// Enables Phase 3 outbound firewall (pre-emptive WFP restriction + unknown first-connect
    /// suspend & dynamic block coupling, `L-03`). Defaults to `true`.
    pub outbound_firewall_enabled: bool,
    /// Concrete executable paths (e.g., standard script interpreters discovered at daemon startup)
    /// that receive startup-pinned `Preemptive` WFP blocks before any `ProcessStart` event and
    /// remain protected across `ProcessStop` (`L-03`). Defaults to empty in `DaemonConfig::default()`
    /// so tests remain deterministic; `ledr-daemon` CLI populates it via
    /// [`ledr_rules::discover_default_prerestricted_interpreters`].
    pub preemptive_startup_executables: Vec<String>,
    /// Enables periodic daily NRD feed background refresh (`L-14`). Defaults to `false` in
    /// `DaemonConfig::default()` so offline unit tests never initiate outbound network requests;
    /// `ledr-daemon` CLI enables it unless `--disable-nrd-refresh` is passed.
    pub nrd_refresh_enabled: bool,
    /// Refresh interval in milliseconds for the daily NRD feed (`NRD_REFRESH_INTERVAL_MS` = 24h).
    pub nrd_refresh_interval_ms: u64,
    /// Optional local disk cache path for persisting the daily NRD feed (`L-14`).
    pub nrd_cache_path: Option<PathBuf>,
    /// Upstream NRD feed URLs (`https://`, `file://`, or loopback `http://` for offline tests).
    pub nrd_feed_urls: Vec<String>,
    /// Bounded grace window (ms) waiting for an out-of-band ETW `DnsQuery` when a pre-emptively
    /// blocked executable triggers a `WfpDropEvent` while a domain-scoped `NetworkAllow` rule is
    /// configured (`#5` / Thread 13). Defaults to `300 ms`.
    pub wfp_drop_dns_grace_ms: u64,
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
            outbound_firewall_enabled: true,
            preemptive_startup_executables: Vec::new(),
            nrd_refresh_enabled: false,
            nrd_refresh_interval_ms: NRD_REFRESH_INTERVAL_MS,
            nrd_cache_path: None,
            nrd_feed_urls: DEFAULT_NRD_FEED_URLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            wfp_drop_dns_grace_ms: DEFAULT_WFP_DROP_DNS_GRACE_MS,
        }
    }
}

/// Errors returned when validating or persisting a policy rule via [`DaemonEngine::upsert_policy_rule`].
#[derive(Debug)]
pub enum PolicyRuleError {
    /// Rule violated `L-04` identity constraints or `AUTO-02` Never-Block protection.
    Invalid(String),
    /// Underlying SQLite store failure.
    Store(StoreError),
    /// Live WFP firewall synchronization failed; SQLite change was rolled back (`#4`).
    FirewallSync(String),
}

impl std::fmt::Display for PolicyRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Store(err) => write!(f, "{err}"),
            Self::FirewallSync(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PolicyRuleError {}

impl From<StoreError> for PolicyRuleError {
    fn from(err: StoreError) -> Self {
        Self::Store(err)
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

/// Queued WFP net-event drop metadata passed from BFE callbacks into [`DaemonEngine::run_pipeline`]
/// over a bounded channel so correlation happens off the BFE callback thread in order behind
/// already-queued `ProcessStart` / `DnsQuery` / `NetworkConnect` events (`Thread 9`, `Thread 13`).
#[derive(Debug, Clone)]
struct QueuedWfpDrop {
    exe_path: String,
    exe_key: String,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: u8,
    timestamp_ms: i64,
    os_filter_id: u64,
}

#[derive(Debug, Clone)]
struct PendingWfpDrop {
    item: QueuedWfpDrop,
    deadline: tokio::time::Instant,
}

#[derive(Debug, Clone)]
struct WfpCandidate {
    identity: ProcessIdentity,
    instance_id: String,
    exe_path: String,
    command_line: Option<String>,
    parent_exe_path: Option<String>,
    parent_command_line: Option<String>,
}

/// Bounded overflow fallback queue for [`QueuedWfpDrop`] events when `wfp_drop_tx` is temporarily
/// full inside a non-blocking BFE net-event callback (`L-10`, `BUG_0006` overflow guarantee).
/// Deduplicates identical `(exe_key, dst_ip)` tuples and coalesces per `exe_key` if even the
/// secondary queue reaches `capacity` so blocked apps still reach operator triage.
#[derive(Debug, Default)]
struct WfpDropOverflowQueue {
    queue: VecDeque<QueuedWfpDrop>,
    active_keys: HashSet<(String, IpAddr)>,
    coalesced_by_exe: HashMap<String, QueuedWfpDrop>,
    coalesced_order: VecDeque<String>,
    capacity: usize,
}

impl WfpDropOverflowQueue {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            active_keys: HashSet::new(),
            coalesced_by_exe: HashMap::new(),
            coalesced_order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn push(&mut self, item: QueuedWfpDrop) -> bool {
        let dedup_key = (item.exe_key.clone(), canonical_ip(item.dst_ip));
        if self.active_keys.contains(&dedup_key) {
            return false;
        }
        if self.queue.len() < self.capacity {
            self.active_keys.insert(dedup_key);
            self.queue.push_back(item);
            return true;
        }
        let exe_k = item.exe_key.clone();
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.coalesced_by_exe.entry(exe_k.clone())
        {
            entry.insert(item);
            return false;
        }
        while self.coalesced_by_exe.len() >= self.capacity {
            let Some(evicted) = self.coalesced_order.pop_front() else {
                self.coalesced_by_exe.clear();
                break;
            };
            self.coalesced_by_exe.remove(&evicted);
        }
        self.coalesced_order.push_back(exe_k.clone());
        self.coalesced_by_exe.insert(exe_k, item);
        true
    }

    fn pop(&mut self) -> Option<QueuedWfpDrop> {
        if let Some(item) = self.queue.pop_front() {
            let dedup_key = (item.exe_key.clone(), canonical_ip(item.dst_ip));
            self.active_keys.remove(&dedup_key);
            return Some(item);
        }
        while let Some(exe_k) = self.coalesced_order.pop_front() {
            if let Some(item) = self.coalesced_by_exe.remove(&exe_k) {
                return Some(item);
            }
        }
        None
    }
}

/// Bounded deduplication set for unresolved app-level ambiguous WFP drop alerts keyed by
/// `(exe_key, canonical_dst_ip)` (`Thread 9`).
#[derive(Debug, Default)]
struct AppWfpAlertDedup {
    keys: HashSet<(String, IpAddr)>,
    order: VecDeque<(String, IpAddr)>,
    capacity: usize,
}

impl AppWfpAlertDedup {
    fn new(capacity: usize) -> Self {
        Self {
            keys: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn mark_if_new(&mut self, exe_key: &str, dst_ip: IpAddr) -> bool {
        let key = (exe_key.to_string(), canonical_ip(dst_ip));
        if self.keys.contains(&key) {
            return false;
        }
        while self.keys.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.keys.remove(&evicted);
            } else {
                self.keys.clear();
                break;
            }
        }
        self.keys.insert(key.clone());
        self.order.push_back(key);
        true
    }

    fn clear_key(&mut self, exe_key: &str, dst_ip: IpAddr) {
        let key = (exe_key.to_string(), canonical_ip(dst_ip));
        self.keys.remove(&key);
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
    firewall: Mutex<WfpRuleManager>,
    outbound_classifier: Arc<OutboundLaneClassifier>,
    process_dns_history: Mutex<ProcessDnsHistory>,
    wfp_drop_dedup: Mutex<WfpDropDedupCache>,
    wfp_drop_tx: tokio::sync::mpsc::Sender<QueuedWfpDrop>,
    wfp_drop_overflow: Mutex<WfpDropOverflowQueue>,
    wfp_drop_overflow_notify: tokio::sync::Notify,
    wfp_drop_overflow_pushed: AtomicU64,
    app_wfp_alert_dedup: Mutex<AppWfpAlertDedup>,
    nrd_cache: Arc<RwLock<NrdCache>>,
    nrd_cancel: NrdCancelToken,
    nrd_in_flight: Arc<AtomicBool>,
    nrd_thread_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
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
        wfp_manager.set_startup_preemptive_executables(&config.preemptive_startup_executables);
        let outbound_classifier = Arc::new(OutboundLaneClassifier::new(
            config.outbound_firewall_enabled,
        ));
        let process_dns_history =
            Mutex::new(ProcessDnsHistory::new(DNS_RESOLUTION_CACHE_CAPACITY));
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
            process_table,
            firewall: Mutex::new(wfp_manager),
            outbound_classifier,
            process_dns_history,
            wfp_drop_dedup,
            wfp_drop_tx,
            wfp_drop_overflow,
            wfp_drop_overflow_notify: tokio::sync::Notify::new(),
            wfp_drop_overflow_pushed: AtomicU64::new(0),
            app_wfp_alert_dedup: Mutex::new(AppWfpAlertDedup::new(APP_WFP_ALERT_DEDUP_CAPACITY)),
            nrd_cache: Arc::new(RwLock::new(initial_nrd)),
            nrd_cancel: NrdCancelToken::new(),
            nrd_in_flight: Arc::new(AtomicBool::new(false)),
            nrd_thread_handle: Mutex::new(None),
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
            worker_engine.run_pipeline(receiver, wfp_drop_rx).await;
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

    /// Returns a cloneable [`ClassifiedEventSender`] handle that promotes unverified external
    /// `NetworkConnect` events onto the non-dropping high-priority lane (`L-10`, `#6`).
    pub fn classified_sender(&self) -> ClassifiedEventSender {
        ClassifiedEventSender::new(self.sender.clone(), Arc::clone(&self.outbound_classifier))
    }

    /// Returns a [`WfpDropSinkFn`] callback capturing ONLY a [`std::sync::Weak`] reference to
    /// this engine (preventing reference cycles) that translates WFP block drop events into
    /// high-priority [`SensorEvent::NetworkConnect`] triage events (`#1`).
    pub fn wfp_drop_sink(self: &Arc<Self>) -> WfpDropSinkFn {
        let weak = Arc::downgrade(self);
        Arc::new(move |drop_ev| {
            if let Some(engine) = weak.upgrade() {
                let _ = engine.ingest_wfp_drop_event(drop_ev);
            }
        })
    }

    /// Correlates a [`WfpDropEvent`] against [`ActiveProcessTable`] (active processes first,
    /// then recently exited) and per-instance DNS history, deduplicates rapid connection retries
    /// within 250 ms per `(exe_key, dst_ip, dst_port)`, and enqueues a synthetic
    /// Accepts an asynchronous [`WfpDropEvent`] from [`WfpDynamicEngine`]'s BFE callback and
    /// enqueues it onto the dedicated bounded `wfp_drop_tx` channel for in-order pipeline
    /// attribution behind already-queued `ProcessStart` / `DnsQuery` / `NetworkConnect` events.
    ///
    /// Returns `true` when the drop event was queued.
    pub fn ingest_wfp_drop_event(&self, drop_ev: WfpDropEvent) -> bool {
        if !self.config.outbound_firewall_enabled {
            return false;
        }
        let canon_ip = canonical_ip(drop_ev.dst_ip);
        if !is_external_ip(canon_ip) {
            return false;
        }
        let trimmed_exe = drop_ev.exe_path.trim();
        if trimmed_exe.is_empty()
            || classify_outbound_risk(trimmed_exe) == OutboundRiskClass::ProtectedOs
        {
            return false;
        }
        let exe_key = WfpRuleManager::exe_key(trimmed_exe);
        let effective_ts = if drop_ev.timestamp_ms > 0 {
            drop_ev.timestamp_ms
        } else {
            current_unix_ms()
        };

        {
            let mut dedup = self
                .wfp_drop_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.should_emit(&exe_key, canon_ip, drop_ev.dst_port, effective_ts) {
                return false;
            }
        }

        let queued = QueuedWfpDrop {
            exe_path: trimmed_exe.to_string(),
            exe_key,
            dst_ip: canon_ip,
            dst_port: drop_ev.dst_port,
            protocol: drop_ev.protocol,
            timestamp_ms: effective_ts,
            os_filter_id: drop_ev.os_filter_id,
        };
        match self.wfp_drop_tx.try_send(queued) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(queued)) => {
                let pushed = self
                    .wfp_drop_overflow
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(queued);
                if pushed {
                    self.wfp_drop_overflow_pushed.fetch_add(1, Ordering::Relaxed);
                }
                self.wfp_drop_overflow_notify.notify_one();
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(
                    exe_path = %trimmed_exe,
                    dst_ip = %canon_ip,
                    dst_port = drop_ev.dst_port,
                    "WFP drop channel closed during shutdown"
                );
                false
            }
        }
    }

    fn pop_wfp_drop_overflow(&self) -> Option<QueuedWfpDrop> {
        self.wfp_drop_overflow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
    }

    /// Number of WFP drop events routed through the bounded overflow fallback (`L-10`).
    pub fn wfp_drop_overflow_pushed(&self) -> u64 {
        self.wfp_drop_overflow_pushed.load(Ordering::Relaxed)
    }

    fn invalidate_non_protected_steady_pids(&self) {
        self.outbound_classifier.clear_non_protected();
    }

    /// Returns `true` while a background daily NRD refresh OS thread is executing.
    pub fn is_nrd_refresh_in_flight(&self) -> bool {
        self.nrd_in_flight.load(Ordering::Acquire)
    }

    /// Returns a reference to the backing [`LedrStore`].
    pub fn store(&self) -> &LedrStore {
        &self.store
    }

    /// Returns the active [`DaemonConfig`].
    pub fn config(&self) -> &DaemonConfig {
        &self.config
    }

    /// Evaluates domain risk (NRD cache membership + Punycode/brand homograph detection, `L-14`)
    /// using the live in-memory [`NrdCache`] without cloning the domain set.
    pub fn assess_domain(&self, domain: &str) -> DomainRiskAssessment {
        let guard = self.nrd_cache.read().unwrap_or_else(|e| e.into_inner());
        assess_domain_risk(domain, Some(guard.domains()))
    }

    /// Returns the number of entries currently loaded in the live NRD cache.
    pub fn nrd_entry_count(&self) -> usize {
        self.nrd_cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Replaces the in-memory [`NrdCache`] (useful for tests or explicit cache injection).
    pub fn set_nrd_cache(&self, cache: NrdCache) {
        let mut guard = self.nrd_cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = cache;
    }

    /// Synchronously refreshes the NRD cache from `config.nrd_feed_urls`, persisting to
    /// `config.nrd_cache_path` when configured. Preserves the prior cache if all feeds fail.
    pub fn refresh_nrd_cache_once(&self) -> Result<NrdRefreshStats, String> {
        execute_nrd_refresh(
            &self.config.nrd_feed_urls,
            self.config.nrd_cache_path.as_deref(),
            &self.nrd_cache,
            &self.nrd_cancel,
        )
    }

    /// Reconciles live WFP dynamic filters against persisted `NetworkBlock` and `NetworkAllow`
    /// rules in SQLite with deny-overrides-allow precedence (`L-03`, `L-04`).
    pub fn deploy_persisted_network_rules(&self) -> WfpReconcileReport {
        if !self.config.outbound_firewall_enabled {
            self.outbound_classifier.set_has_domain_rules(false);
            return WfpReconcileReport::default();
        }
        let rules = match self.store.list_network_rules() {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(error = %err, "failed to load persisted network rules for WFP reconciliation");
                return WfpReconcileReport {
                    failed: 1,
                    failed_ops: vec![WfpFailedOp {
                        exe_key: "<store>".to_string(),
                        remote_ip: None,
                        is_remove: false,
                        is_startup_preemptive: false,
                        source_rule_ids: Vec::new(),
                        error: format!("failed to load persisted network rules: {err}"),
                    }],
                    ..Default::default()
                };
            }
        };
        let active_exes = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_exe_paths();
        let (mut report, has_domain_rules) = {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            let mut rep = fw.reconcile_persisted_rules(
                &rules,
                &active_exes,
                &*self.inspector,
                &*self.defense,
            );
            let unnamed = fw.unnamed_domain_permits();
            if !unnamed.is_empty() {
                let dns_hist = self
                    .process_dns_history
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                for (exe_k, exe_path, ip) in unnamed {
                    let doms = dns_hist.domains_for_ip(&ip);
                    if doms.is_empty() {
                        continue;
                    }
                    let identity = self.inspector.inspect(&exe_path);
                    let blocked = doms.iter().any(|dom| {
                        matches!(
                            evaluate_outbound_policy(&identity, ip, Some(dom), &rules),
                            OutboundDecision::BlockedByRule { .. }
                        )
                    });
                    if blocked {
                        match fw.remove_domain_policy_permit(&exe_path, ip, &*self.defense) {
                            Ok(Some(snap)) => {
                                rep.removed += 1;
                                rep.removed_domain_filters.push(snap);
                            }
                            Ok(None) => {}
                            Err(err) => {
                                rep.failed += 1;
                                rep.failed_ops.push(WfpFailedOp {
                                    exe_key: exe_k,
                                    remote_ip: Some(ip),
                                    is_remove: true,
                                    is_startup_preemptive: false,
                                    source_rule_ids: Vec::new(),
                                    error: err,
                                });
                            }
                        }
                    }
                }
            }
            (rep, fw.has_domain_network_rules())
        };
        let _ = &mut report;
        self.outbound_classifier
            .set_has_domain_rules(has_domain_rules);
        report
    }

    fn compensate_failed_wfp_report(&self, report: &WfpReconcileReport) {
        if !report.promoted_backups.is_empty() {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            fw.restore_promoted_filter_states(&report.promoted_backups);
        }
        let _ = self.deploy_persisted_network_rules();
        if !report.removed_domain_filters.is_empty() {
            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            fw.restore_removed_domain_filters(&report.removed_domain_filters, &*self.defense);
        }
    }

    /// Validates (`L-04`, `AUTO-02`) and persists an allowlist/blocklist rule via SQLite, then
    /// immediately reconciles live WFP filters when either the previous or new scope is a
    /// firewall scope (`NetworkBlock` / `NetworkAllow`).
    ///
    /// On target-relevant live WFP synchronization failure, restores the prior SQLite rule state,
    /// restores promoted/removed WFP filters, re-reconciles WFP, and returns
    /// [`PolicyRuleError::FirewallSync`] (`#4`, `Thread 10`, `Thread 18`).
    /// When an existing rule moves OUT of a network scope (`Analysis #7`), re-evaluates
    /// pre-emptive restrictions for all active executables.
    pub fn upsert_policy_rule(
        &self,
        rule: &AllowlistRuleRecord,
    ) -> Result<WfpReconcileReport, PolicyRuleError> {
        validate_policy_rule(rule).map_err(PolicyRuleError::Invalid)?;
        let previous = self.store.get_rule(&rule.rule_id)?;
        let previous_was_network = previous
            .as_ref()
            .is_some_and(|r| matches!(r.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow));
        let new_is_network = matches!(rule.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow);

        self.store.upsert_rule(rule)?;
        if self.config.outbound_firewall_enabled && (previous_was_network || new_is_network) {
            let report = self.deploy_persisted_network_rules();
            let mut affected: Vec<&AllowlistRuleRecord> = Vec::with_capacity(2);
            if new_is_network {
                affected.push(rule);
            }
            if let Some(ref prev) = previous {
                if previous_was_network {
                    affected.push(prev);
                }
            }
            if let Some(err_summary) = report.failure_summary_for_rules(&affected) {
                let comp_res = match previous {
                    Some(ref prev) => self.store.upsert_rule(prev),
                    None => self.store.delete_rule(&rule.rule_id).map(|_| ()),
                };
                if let Err(comp_err) = comp_res {
                    tracing::warn!(
                        rule_id = %rule.rule_id,
                        error = %comp_err,
                        "failed compensating SQLite after WFP sync failure in upsert_policy_rule"
                    );
                } else {
                    self.compensate_failed_wfp_report(&report);
                    if previous_was_network {
                        let active_exes = self
                            .process_table
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .active_exe_paths();
                        for exe in active_exes {
                            self.maybe_apply_preemptive_wfp_block(&exe);
                        }
                    }
                }
                return Err(PolicyRuleError::FirewallSync(err_summary));
            }

            self.invalidate_non_protected_steady_pids();
            if previous_was_network {
                let active_exes = self
                    .process_table
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .active_exe_paths();
                for exe in active_exes {
                    self.maybe_apply_preemptive_wfp_block(&exe);
                }
            }
            Ok(report)
        } else {
            Ok(WfpReconcileReport::default())
        }
    }

    /// Deletes a policy rule from SQLite and immediately reconciles live WFP filters (including
    /// restoring any shadowed `NetworkAllow` or re-applying pre-emptive restrictions for active
    /// high-risk/script processes).
    ///
    /// On target-relevant live WFP synchronization failure, re-inserts the deleted rule into
    /// SQLite, restores promoted/removed WFP filters, re-reconciles WFP, and returns
    /// [`PolicyRuleError::FirewallSync`] (`#4`, `Thread 10`, `Thread 18`).
    pub fn delete_policy_rule(
        &self,
        rule_id: &str,
    ) -> Result<(bool, WfpReconcileReport), PolicyRuleError> {
        let existing = self.store.get_rule(rule_id)?;
        let deleted = self.store.delete_rule(rule_id)?;
        if deleted
            && self.config.outbound_firewall_enabled
            && existing.as_ref().is_some_and(|r| {
                matches!(r.scope, RuleScope::NetworkBlock | RuleScope::NetworkAllow)
            })
        {
            let report = self.deploy_persisted_network_rules();
            let err_summary = existing
                .as_ref()
                .and_then(|prev| report.failure_summary_for_rules(&[prev]));
            if let Some(err_summary) = err_summary {
                if let Some(ref prev) = existing {
                    if let Err(comp_err) = self.store.upsert_rule(prev) {
                        tracing::warn!(
                            rule_id = %rule_id,
                            error = %comp_err,
                            "failed compensating SQLite after WFP sync failure in delete_policy_rule"
                        );
                    } else {
                        self.compensate_failed_wfp_report(&report);
                    }
                }
                return Err(PolicyRuleError::FirewallSync(err_summary));
            }
            self.invalidate_non_protected_steady_pids();
            let active_exes = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .active_exe_paths();
            for exe in active_exes {
                self.maybe_apply_preemptive_wfp_block(&exe);
            }
            Ok((true, report))
        } else {
            Ok((deleted, WfpReconcileReport::default()))
        }
    }

    /// Returns the number of live WFP dynamic rule handles currently tracked by the daemon.
    pub fn active_wfp_rule_count(&self) -> usize {
        self.firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_filter_count()
    }

    /// Returns `true` if the daemon currently tracks an active WFP filter for
    /// `(exe_path, remote_ip, allow)`.
    pub fn has_active_wfp_filter(
        &self,
        exe_path: &str,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> bool {
        self.firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_active_filter(exe_path, remote_ip, allow)
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
        let mut root_thumbprint = json_non_empty_str(&ctx_val, "/root_thumbprint")
            .filter(|tp| !tp.trim().is_empty() && !tp.trim().chars().all(|c| c == '0'));

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
                            let tp = auth.root_thumbprint.trim();
                            if !tp.is_empty() && !tp.chars().all(|c| c == '0') {
                                root_thumbprint = Some(auth.root_thumbprint);
                            }
                        }
                    }
                }
            }
        }

        let now_ms = current_unix_ms();
        let new_status = decision.resulting_status();
        let is_terminate = matches!(decision, AlertDecision::TerminateAndBlock { .. });
        let is_network_alert = alert.source_layer == "LAYER_3_NETWORK"
            || ctx_val.pointer("/event/NetworkConnect").is_some();
        let alert_dst_ip: Option<IpAddr> = json_non_empty_str(&ctx_val, "/dst_ip")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/NetworkConnect/dst_ip"))
            .and_then(|s| s.parse::<IpAddr>().ok());
        let alert_domain_hint = json_non_empty_str(&ctx_val, "/domain_hint")
            .or_else(|| json_non_empty_str(&ctx_val, "/event/NetworkConnect/domain_hint"));

        let mut lifted_wfp_block = None;
        let mut rebind_alert_exe: Option<String> = None;
        let mut displaced_bound_alerts: Vec<String> = Vec::new();
        let mut marked_once_allowed_procs: Vec<String> = Vec::new();
        let mut applied_wfp_report: Option<WfpReconcileReport> = None;

        match decision {
            AlertDecision::AllowOnce => {
                if is_network_alert && self.config.outbound_firewall_enabled {
                    if let Some(ref exe) = exe_path {
                        let has_persisted_block = self.has_matching_persisted_network_block(
                            exe,
                            alert_dst_ip,
                            alert_domain_hint.as_deref(),
                        );
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        let (lifted, was_bound) = fw.lift_block_for_allow_once(
                            alert_id,
                            exe,
                            has_persisted_block,
                            &*self.defense,
                        )?;
                        lifted_wfp_block = lifted;
                        if was_bound {
                            rebind_alert_exe = Some(exe.clone());
                        }
                        if !has_persisted_block {
                            if let Some(ref proc_inst_id) = alert.process_instance_id {
                                fw.mark_once_allowed(proc_inst_id, exe);
                                marked_once_allowed_procs.push(proc_inst_id.clone());
                            } else if let Some(cand_ids) =
                                ctx_val.pointer("/candidate_instance_ids").and_then(|v| v.as_array())
                            {
                                let table = self
                                    .process_table
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                for raw_id in cand_ids {
                                    if let Some(inst_id) = raw_id.as_str() {
                                        if table
                                            .get_by_instance_id(inst_id)
                                            .is_some_and(|e| e.exited_at_ms.is_none())
                                        {
                                            fw.mark_once_allowed(inst_id, exe);
                                            marked_once_allowed_procs.push(inst_id.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

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
                        self.rollback_allow_once_wfp(
                            alert_id,
                            lifted_wfp_block.take(),
                            rebind_alert_exe.take(),
                            Vec::new(),
                            std::mem::take(&mut marked_once_allowed_procs),
                        );
                        return Err(err);
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

                let scope = if is_network_alert {
                    RuleScope::NetworkAllow
                } else {
                    RuleScope::FileCanaryAllow
                };

                let valid_root_thumbprint = root_thumbprint
                    .filter(|tp| !tp.trim().is_empty() && !tp.trim().chars().all(|c| c == '0'));

                let (rule_sha256, rule_signer, rule_thumbprint) =
                    if use_signer_if_available
                        && signer_subject.is_some()
                        && valid_root_thumbprint.is_some()
                    {
                        (None, signer_subject, valid_root_thumbprint)
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
                    exe_path_pattern: exe.clone(),
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

                if scope == RuleScope::NetworkAllow && self.config.outbound_firewall_enabled {
                    let release_res = {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.release_transient_containment_for_alert(
                            alert_id,
                            Some(&exe),
                            &*self.defense,
                        )
                    };
                    match release_res {
                        Ok((snap, was_bound)) => {
                            lifted_wfp_block = snap;
                            if was_bound {
                                rebind_alert_exe = Some(exe.clone());
                            }
                        }
                        Err(err) => {
                            self.rollback_saved_rule(&rule.rule_id);
                            return Err(err);
                        }
                    }

                    // Snapshot any remaining Preemptive/TransientContainment app-wide block and
                    // sibling alert bindings before reconciliation potentially replaces it with a
                    // PersistedPolicy Permit so a subsequent resume/status rollback can restore
                    // both the block and every displaced alert binding.
                    {
                        let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        let (snap, sibs) = fw.snapshot_app_block_and_bindings(&exe);
                        if lifted_wfp_block.is_none() {
                            lifted_wfp_block = snap;
                        }
                        displaced_bound_alerts = sibs;
                    }

                    let sync_res =
                        (|| -> Result<WfpReconcileReport, Box<(String, WfpReconcileReport)>> {
                            let report = self.deploy_persisted_network_rules();
                            if let Some(summary) = report.failure_summary_for_rules(&[&rule]) {
                                return Err(Box::new((
                                    format!(
                                        "failed synchronizing WFP firewall rule for NetworkAllow {}: {}",
                                        rule.rule_id, summary
                                    ),
                                    report,
                                )));
                            }

                            // If the user allowed a domain target (not a literal IP) for an exe that still
                            // has a pre-emptive app-wide block, install a DomainPolicy IP-specific Permit
                            // for the resolved destination IP of this alert so traffic flows upon resume
                            // and survives unrelated rule reconciliations.
                            if let (Some(target_pat), Some(dst_ip)) =
                                (rule.allowed_target.as_deref(), alert_dst_ip)
                            {
                                if parse_literal_target_ip(target_pat).is_none()
                                    && matches_network_target(
                                        target_pat,
                                        dst_ip,
                                        alert_domain_hint.as_deref(),
                                    )
                                    && !self.has_matching_persisted_network_block(
                                        &exe,
                                        Some(dst_ip),
                                        alert_domain_hint.as_deref(),
                                    )
                                {
                                    let known_domain = alert_domain_hint
                                        .as_deref()
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(str::to_string)
                                        .or_else(|| {
                                            alert.process_instance_id.as_deref().and_then(|inst_id| {
                                                self.process_dns_history
                                                    .lock()
                                                    .unwrap_or_else(|e| e.into_inner())
                                                    .lookup_for_process(inst_id, dst_ip)
                                                    .map(|(dom, _)| dom)
                                            })
                                        });
                                    let domain_label = known_domain
                                        .as_deref()
                                        .or_else(|| {
                                            (parse_cidr_target(target_pat).is_err())
                                                .then_some(target_pat)
                                        })
                                        .unwrap_or("");
                                    let mut fw =
                                        self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                                    if fw.active_app_block(&exe).is_some() {
                                        if let Err(err) = fw.ensure_ip_permit_for_domain_rule(
                                            &exe,
                                            dst_ip,
                                            domain_label,
                                            &*self.defense,
                                        ) {
                                            return Err(Box::new((
                                                format!(
                                                    "failed installing IP permit for domain-scoped NetworkAllow {}: {err}",
                                                    rule.rule_id
                                                ),
                                                report,
                                            )));
                                        }
                                    }
                                }
                            }
                            Ok(report)
                        })();

                    match sync_res {
                        Ok(report) => applied_wfp_report = Some(report),
                        Err(boxed) => {
                            let (err, failed_report) = *boxed;
                            self.rollback_saved_rule(&rule.rule_id);
                            self.compensate_failed_wfp_report(&failed_report);
                            self.maybe_apply_preemptive_wfp_block(&exe);
                            self.rollback_allow_once_wfp(
                                alert_id,
                                lifted_wfp_block.take(),
                                rebind_alert_exe.take(),
                                std::mem::take(&mut displaced_bound_alerts),
                                Vec::new(),
                            );
                            return Err(err);
                        }
                    }
                    self.invalidate_non_protected_steady_pids();
                }

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
                        if scope == RuleScope::NetworkAllow && self.config.outbound_firewall_enabled
                        {
                            // Reconcile first so any newly added PersistedPolicy/DomainPolicy
                            // Permit is removed, then restore any promoted/removed filter state and
                            // re-arm any Preemptive Block BEFORE rebinding `alert_id`.
                            if let Some(rep) = applied_wfp_report.take() {
                                self.compensate_failed_wfp_report(&rep);
                            } else {
                                let _ = self.deploy_persisted_network_rules();
                            }
                            self.maybe_apply_preemptive_wfp_block(&exe);
                        }
                        self.rollback_allow_once_wfp(
                            alert_id,
                            lifted_wfp_block.take(),
                            rebind_alert_exe.take(),
                            std::mem::take(&mut displaced_bound_alerts),
                            Vec::new(),
                        );
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

                // Attempt every recorded child and defer the first real failure: a live
                // or unverifiable child keeps the alert unresolved, but remaining
                // descendants must still get their terminate attempt — once the parent
                // is gone, a recorded identifier is the only way to reach them.
                let mut child_terminate_err: Option<String> = None;
                for child in &suspended_children {
                    match self.defense.terminate_process(child, true) {
                        Ok(()) => {}
                        Err(err)
                            if is_protected_process_refusal(&err)
                                || !is_process_gone_or_replaced(&err, child.pid) =>
                        {
                            child_terminate_err.get_or_insert(err);
                        }
                        Err(err) => {
                            // Only tolerate a child confirmed gone or PID-reused
                            // (`BUG_0001`).
                            tracing::warn!(
                                alert_id = %alert_id,
                                child_pid = child.pid,
                                error = %err,
                                "terminate_process failed for suspended child (already exited); continuing"
                            );
                        }
                    }
                }
                if let Some(err) = child_terminate_err {
                    return Err(err);
                }

                if add_block_rule {
                    if let Some(exe) = exe_path.clone() {
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
                        if self.config.outbound_firewall_enabled {
                            let report = self.deploy_persisted_network_rules();
                            if let Some(summary) = report.failure_summary_for_rules(&[&block_rule]) {
                                self.rollback_saved_rule(&block_rule.rule_id);
                                self.compensate_failed_wfp_report(&report);
                                return Err(format!(
                                    "failed synchronizing WFP firewall rule for NetworkBlock {}: {summary}",
                                    block_rule.rule_id
                                ));
                            }
                            applied_wfp_report = Some(report);
                            self.invalidate_non_protected_steady_pids();
                        }
                    }
                } else if is_network_alert && self.config.outbound_firewall_enabled {
                    let release_res = {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.release_transient_containment_for_alert(
                            alert_id,
                            exe_path.as_deref(),
                            &*self.defense,
                        )
                    };
                    if let Err(err) = release_res {
                        tracing::warn!(
                            alert_id = %alert_id,
                            error = %err,
                            "best-effort transient WFP release after terminate without block failed"
                        );
                    }
                    if let Some(ref exe) = exe_path {
                        let target_key = WfpRuleManager::exe_key(exe);
                        let still_active = self
                            .process_table
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .has_active_exe_key(&target_key);
                        if !still_active {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            fw.remove_preemptive_block_if_unused(exe, &*self.defense);
                        }
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
                if self.config.outbound_firewall_enabled {
                    if let Some(rep) = applied_wfp_report.take() {
                        self.compensate_failed_wfp_report(&rep);
                    } else {
                        let _ = self.deploy_persisted_network_rules();
                    }
                }
            }
            if is_network_alert && self.config.outbound_firewall_enabled {
                if let Some(ref exe) = exe_path {
                    self.maybe_apply_preemptive_wfp_block(exe);
                }
            }
            self.rollback_allow_once_wfp(
                alert_id,
                lifted_wfp_block.take(),
                rebind_alert_exe.take(),
                std::mem::take(&mut displaced_bound_alerts),
                std::mem::take(&mut marked_once_allowed_procs),
            );
            return Err(err);
        }

        if is_network_alert {
            if let (Some(ref exe), Some(dst_ip)) = (&exe_path, alert_dst_ip) {
                self.app_wfp_alert_dedup
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear_key(&WfpRuleManager::exe_key(exe), dst_ip);
            }
        }
        if let Some(ref proc_inst_id) = alert.process_instance_id {
            self.clear_alert_dedup_from_context_val(proc_inst_id, &alert.source_layer, &ctx_val);
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
                        self.clear_alert_dedup_from_context_val(
                            proc_inst_id,
                            &other.source_layer,
                            &ctx,
                        );
                        if other.source_layer == "LAYER_3_NETWORK"
                            && self.config.outbound_firewall_enabled
                        {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            let _ = fw.release_transient_containment_for_alert(
                                &other.alert_id,
                                json_non_empty_str(&ctx, "/exe_path").as_deref(),
                                &*self.defense,
                            );
                        }
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

    fn clear_alert_dedup_from_context_val(
        &self,
        instance_id: &str,
        source_layer: &str,
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
        if source_layer == "LAYER_3_NETWORK" || ctx_val.pointer("/event/NetworkConnect").is_some() {
            self.clear_rule_alert(instance_id, "NET_OUTBOUND");
            self.clear_rule_alert(instance_id, "NET_POLICY_BLOCK");
        }
    }

    fn rollback_allow_once_wfp(
        &self,
        alert_id: &str,
        lifted_wfp_block: Option<crate::firewall::RemovedBlockSnapshot>,
        rebind_alert_exe: Option<String>,
        displaced_bound_alerts: Vec<String>,
        marked_once_allowed_procs: Vec<String>,
    ) {
        if lifted_wfp_block.is_none()
            && rebind_alert_exe.is_none()
            && displaced_bound_alerts.is_empty()
            && marked_once_allowed_procs.is_empty()
        {
            return;
        }
        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
        for proc_inst_id in marked_once_allowed_procs {
            fw.unmark_once_allowed(&proc_inst_id);
        }
        let rebind_self = rebind_alert_exe.is_some().then_some(alert_id);
        let sib_exe = lifted_wfp_block
            .as_ref()
            .map(|s| s.exe_path.clone())
            .or_else(|| rebind_alert_exe.clone());
        if let Some(snap) = lifted_wfp_block {
            fw.restore_lifted_block(rebind_self, snap, &*self.defense);
        } else if let Some(exe) = rebind_alert_exe {
            fw.bind_alert_to_app_block(alert_id, &exe);
        }
        if let Some(exe) = sib_exe {
            for sib_id in displaced_bound_alerts {
                fw.bind_alert_to_app_block(&sib_id, &exe);
            }
        }
    }

    fn has_matching_persisted_network_block(
        &self,
        exe_path: &str,
        dst_ip: Option<IpAddr>,
        domain_hint: Option<&str>,
    ) -> bool {
        let rules = self
            .store
            .list_rules(Some(RuleScope::NetworkBlock))
            .unwrap_or_default();
        let matching_path: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
            })
            .collect();
        if matching_path.is_empty() {
            return false;
        }
        let needs_inspect = matching_path.iter().any(|r| {
            r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                || r.signer_subject
                    .as_deref()
                    .is_some_and(|s| !s.trim().is_empty())
        });
        let identity = if needs_inspect {
            self.inspector.inspect(exe_path)
        } else {
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            }
        };
        matching_path.into_iter().any(|rule| match dst_ip {
            Some(ip) => matches_network_block_rule(rule, &identity, ip, domain_hint),
            None => matches_app_wide_network_block(rule, &identity),
        })
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

    /// Closes ingestion, drains remaining queued events, joins background worker & NRD refresh
    /// threads, flushes SQLite batches, and runs `PRAGMA wal_checkpoint(TRUNCATE)` within
    /// `SHUTDOWN_FLUSH_TIMEOUT_MS` (`3,000 ms`, `AUTO-10`).
    pub async fn shutdown_and_flush(&self) -> Result<(), anyhow::Error> {
        let shutdown_started = Instant::now();
        let total_budget = Duration::from_millis(self.config.shutdown_flush_timeout_ms.max(1));
        let checkpoint_reserve = Duration::from_millis(200).min(total_budget / 3);
        let drain_budget = total_budget.saturating_sub(checkpoint_reserve);
        self.nrd_cancel.cancel();
        self.store.request_shutdown();
        self.sender.close();

        let handle = {
            let mut guard = self.worker_handle.lock().await;
            guard.take()
        };

        if let Some(h) = handle {
            match tokio::time::timeout(drain_budget, h).await {
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

        let nrd_handle = {
            let mut guard = self
                .nrd_thread_handle
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        if let Some(jh) = nrd_handle {
            if jh.is_finished() {
                if jh.join().is_err() {
                    tracing::warn!("background NRD refresh thread panicked during shutdown");
                }
            } else {
                let remaining = drain_budget.saturating_sub(shutdown_started.elapsed());
                if !remaining.is_zero() {
                    let join_task = tokio::task::spawn_blocking(move || jh.join());
                    match tokio::time::timeout(remaining, join_task).await {
                        Ok(Ok(Ok(()))) => {}
                        Ok(Ok(Err(_panic_payload))) => {
                            tracing::warn!("background NRD refresh thread panicked during shutdown");
                        }
                        Ok(Err(join_err)) => {
                            tracing::warn!(error = %join_err, "blocking join task for NRD refresh thread failed");
                        }
                        Err(_) => {
                            tracing::warn!(
                                timeout_ms = self.config.shutdown_flush_timeout_ms,
                                "timed out waiting for background NRD refresh thread join during shutdown"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        timeout_ms = self.config.shutdown_flush_timeout_ms,
                        "shutdown budget exhausted prior to SQLite checkpoint; skipping NRD thread join wait"
                    );
                }
            }
        }

        self.store.checkpoint_truncate()?;
        Ok(())
    }

    async fn run_pipeline(
        self: Arc<Self>,
        mut receiver: TwoLaneReceiver,
        mut wfp_drop_rx: tokio::sync::mpsc::Receiver<QueuedWfpDrop>,
    ) {
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

        let nrd_refresh_enabled = self.config.nrd_refresh_enabled;
        let nrd_tick_ms = (self.config.nrd_refresh_interval_ms / 4).clamp(100, 3_600_000);
        let mut nrd_ticker = tokio::time::interval(Duration::from_millis(nrd_tick_ms));
        nrd_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut pending_wfp_drops: VecDeque<PendingWfpDrop> = VecDeque::new();
        let mut wfp_drop_rx_closed = false;
        let mut sync_telemetry_streak = 0usize;

        loop {
            // Tier 1: Drain non-dropping high-priority lane (ProcessStart/Stop, DnsQuery, Canary,
            // Script, unknown NetworkConnect) BEFORE WFP drops so process lineage and DNS history
            // are always up to date for attribution (`L-10`).
            if let Some(event) = receiver.try_recv_high_priority() {
                sync_telemetry_streak = 0;
                if let Some((dns_inst_id, dns_exe_key)) =
                    self.process_event_with_lane(&event, EventLane::HighPriority)
                {
                    if let SensorEvent::DnsQuery {
                        query_name,
                        resolved_ips,
                        ..
                    } = &event
                    {
                        self.flush_ready_pending_wfp_drops(
                            &dns_inst_id,
                            &dns_exe_key,
                            query_name,
                            resolved_ips,
                            &mut pending_wfp_drops,
                        );
                    }
                }
                continue;
            }

            // Tier 2a: Flush any grace-window WFP drops whose deadline has already expired.
            let earliest_drop_deadline = pending_wfp_drops.iter().map(|p| p.deadline).min();
            if earliest_drop_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                sync_telemetry_streak = 0;
                self.flush_expired_pending_wfp_drops(&mut pending_wfp_drops);
                continue;
            }

            // Tier 2b: Drain WFP drop events (primary bounded channel + bounded overflow queue)
            // STRICTLY BEFORE steady telemetry so telemetry bursts never starve or drop alerts (`L-10`).
            if !wfp_drop_rx_closed {
                match wfp_drop_rx.try_recv() {
                    Ok(drop_item) => {
                        sync_telemetry_streak = 0;
                        self.on_wfp_drop_dequeued(drop_item, &mut pending_wfp_drops);
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        wfp_drop_rx_closed = true;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                }
            }
            if let Some(overflow_item) = self.pop_wfp_drop_overflow() {
                sync_telemetry_streak = 0;
                self.on_wfp_drop_dequeued(overflow_item, &mut pending_wfp_drops);
                continue;
            }

            // Tier 3: Steady telemetry lane, yielding periodically so single-threaded runtimes and
            // grace timers remain responsive during bursts.
            if let Some(event) = receiver.try_recv_telemetry() {
                if let Some((dns_inst_id, dns_exe_key)) =
                    self.process_event_with_lane(&event, EventLane::Telemetry)
                {
                    if let SensorEvent::DnsQuery {
                        query_name,
                        resolved_ips,
                        ..
                    } = &event
                    {
                        self.flush_ready_pending_wfp_drops(
                            &dns_inst_id,
                            &dns_exe_key,
                            query_name,
                            resolved_ips,
                            &mut pending_wfp_drops,
                        );
                    }
                }
                sync_telemetry_streak += 1;
                if sync_telemetry_streak >= 32 {
                    sync_telemetry_streak = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }
            sync_telemetry_streak = 0;

            let next_drop_sleep = async move {
                match earliest_drop_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(next_drop_sleep);

            tokio::select! {
                biased;
                maybe_event = receiver.recv_with_lane() => {
                    match maybe_event {
                        Some((event, lane)) => {
                            if let Some((dns_inst_id, dns_exe_key)) =
                                self.process_event_with_lane(&event, lane)
                            {
                                if let SensorEvent::DnsQuery {
                                    query_name,
                                    resolved_ips,
                                    ..
                                } = &event
                                {
                                    self.flush_ready_pending_wfp_drops(
                                        &dns_inst_id,
                                        &dns_exe_key,
                                        query_name,
                                        resolved_ips,
                                        &mut pending_wfp_drops,
                                    );
                                }
                            }
                        }
                        None => break,
                    }
                }
                maybe_drop = wfp_drop_rx.recv(), if !wfp_drop_rx_closed => {
                    match maybe_drop {
                        Some(drop_item) => self.on_wfp_drop_dequeued(drop_item, &mut pending_wfp_drops),
                        None => wfp_drop_rx_closed = true,
                    }
                }
                _ = self.wfp_drop_overflow_notify.notified() => {
                    while let Some(overflow_item) = self.pop_wfp_drop_overflow() {
                        self.on_wfp_drop_dequeued(overflow_item, &mut pending_wfp_drops);
                    }
                }
                _ = &mut next_drop_sleep, if earliest_drop_deadline.is_some() => {
                    self.flush_expired_pending_wfp_drops(&mut pending_wfp_drops);
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
                _ = nrd_ticker.tick(), if nrd_refresh_enabled => {
                    if !self.nrd_cancel.is_cancelled() && !self.nrd_in_flight.load(Ordering::Acquire) {
                        let stale = {
                            let guard = self.nrd_cache.read().unwrap_or_else(|e| e.into_inner());
                            guard.is_stale(current_unix_ms(), self.config.nrd_refresh_interval_ms)
                        };
                        if stale
                            && self.nrd_in_flight
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok()
                        {
                            let feed_urls = self.config.nrd_feed_urls.clone();
                            let cache_path = self.config.nrd_cache_path.clone();
                            let nrd_cache = Arc::clone(&self.nrd_cache);
                            let nrd_cancel = self.nrd_cancel.clone();
                            let in_flight = Arc::clone(&self.nrd_in_flight);
                            match std::thread::Builder::new()
                                .name("ledr-nrd-refresh".to_string())
                                .spawn(move || {
                                    struct InFlightGuard(Arc<AtomicBool>);
                                    impl Drop for InFlightGuard {
                                        fn drop(&mut self) {
                                            self.0.store(false, Ordering::Release);
                                        }
                                    }
                                    let _guard = InFlightGuard(in_flight);
                                    match execute_nrd_refresh(
                                        &feed_urls,
                                        cache_path.as_deref(),
                                        &nrd_cache,
                                        &nrd_cancel,
                                    ) {
                                        Ok(stats) => tracing::info!(
                                            entries = stats.total_entries,
                                            feeds_succeeded = stats.feeds_succeeded,
                                            feeds_failed = stats.feeds_failed,
                                            truncated = stats.truncated,
                                            "refreshed daily NRD domain cache"
                                        ),
                                        Err(err) => tracing::warn!(
                                            error = %err,
                                            "daily NRD feed refresh failed; retaining existing cache"
                                        ),
                                    }
                                }) {
                                Ok(jh) => {
                                    let prev = {
                                        let mut guard = self
                                            .nrd_thread_handle
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        guard.replace(jh)
                                    };
                                    if let Some(old_jh) = prev {
                                        if old_jh.is_finished() {
                                            let _ = old_jh.join();
                                        }
                                    }
                                }
                                Err(err) => {
                                    self.nrd_in_flight.store(false, Ordering::Release);
                                    tracing::warn!(error = %err, "failed spawning ledr-nrd-refresh thread");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Cancel any in-flight NRD fetch immediately so slow upstream HTTP cannot delay
        // daemon shutdown or pin the 3-second WAL checkpoint budget (`AUTO-10`, `#5`).
        self.nrd_cancel.cancel();

        if let Some(handle) = purge_in_flight {
            if let Err(err) = handle.await {
                tracing::warn!(error = %err, "TTL purge task panicked during shutdown");
            }
        }

        for (remaining, lane) in receiver.drain_ready_with_lane() {
            let _ = self.process_event_with_lane(&remaining, lane);
        }
        while let Ok(drop_item) = wfp_drop_rx.try_recv() {
            self.handle_wfp_drop_event_now(&drop_item);
        }
        while let Some(overflow_item) = self.pop_wfp_drop_overflow() {
            self.handle_wfp_drop_event_now(&overflow_item);
        }
        while let Some(pending) = pending_wfp_drops.pop_front() {
            self.handle_wfp_drop_event_now(&pending.item);
        }

        if let Err(err) = self.store.checkpoint_truncate() {
            tracing::warn!(error = %err, "worker shutdown checkpoint_truncate failed");
        }
    }

    fn process_event(&self, event: &SensorEvent) {
        let _ = self.process_event_with_lane(event, event.default_lane());
    }

    fn process_event_with_lane(
        &self,
        event: &SensorEvent,
        lane: EventLane,
    ) -> Option<(String, String)> {
        if let SensorEvent::CanaryFileAccess {
            category: CanaryCategory::Honeypot,
            is_write_or_delete: false,
            ..
        } = event
        {
            // L-06: Read-only honeypot opens are ignored to avoid SearchIndexer/backup false positives.
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let now_ms = current_unix_ms();
        let event_ts_ms = event_timestamp_ms(event, now_ms);

        let proc_ctx = self.resolve_process_context(event, event_ts_ms);

        if matches!(event, SensorEvent::CanaryFileAccess { .. }) {
            self.handle_canary_file_access(event, &proc_ctx, event_ts_ms);
            self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            return None;
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
            self.assess_domain(query_name).is_nrd
        } else {
            false
        };

        let mut flush_now = false;
        let mut dns_correlation_key: Option<(String, String)> = None;
        let action = match event {
            SensorEvent::ProcessStart {
                identity, exe_path, ..
            } => {
                if proc_ctx.exited_at_ms.is_none() {
                    if classify_outbound_risk(exe_path) == OutboundRiskClass::ProtectedOs {
                        self.outbound_classifier.mark_protected_os(identity.pid);
                    } else {
                        self.outbound_classifier.remove_pid(identity.pid);
                    }
                    if self.config.outbound_firewall_enabled {
                        self.maybe_apply_preemptive_wfp_block(exe_path);
                    }
                }
                "OBSERVED"
            }
            SensorEvent::ProcessStop { pid, .. } => {
                if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                    self.outbound_classifier.remove_pid(*pid);
                    self.process_dns_history
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove_process(inst_id);
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let was_once_allowed = fw.on_process_stop(inst_id);
                    if self.config.outbound_firewall_enabled {
                        if let Some(ref exe_path) = proc_ctx.proc_exe_path {
                            let exe_k = WfpRuleManager::exe_key(exe_path);
                            let is_startup_pinned = fw.is_startup_preemptive(exe_path);
                            let is_preemptive = fw
                                .active_app_block(exe_path)
                                .is_some_and(|(_, origin)| origin == WfpFilterOrigin::Preemptive);
                            let has_any_filter = fw.has_any_app_filter(exe_path);
                            let has_other_once_allowed = fw.has_once_allowed_for_exe(&exe_k);
                            drop(fw);

                            if is_preemptive && !is_startup_pinned {
                                let still_active = self
                                    .process_table
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .has_active_exe_key(&exe_k);
                                if !still_active {
                                    let mut fw =
                                        self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                                    fw.remove_preemptive_block_if_unused(exe_path, &*self.defense);
                                }
                            } else if was_once_allowed
                                && !has_any_filter
                                && !has_other_once_allowed
                            {
                                let should_restore = is_startup_pinned
                                    || self
                                        .process_table
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner())
                                        .has_active_exe_key(&exe_k);
                                if should_restore {
                                    self.maybe_apply_preemptive_wfp_block(exe_path);
                                }
                            }
                        }
                    }
                }
                "OBSERVED"
            }
            SensorEvent::DnsQuery {
                query_name,
                resolved_ips,
                ..
            } => {
                if !resolved_ips.is_empty() {
                    if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                        self.process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .record(inst_id, query_name, resolved_ips, event_ts_ms);
                        if let Some(ref exe_path) = proc_ctx.proc_exe_path {
                            dns_correlation_key =
                                Some((inst_id.clone(), WfpRuleManager::exe_key(exe_path)));
                        }
                    }
                    if self.config.outbound_firewall_enabled {
                        self.prematerialize_domain_wfp_filters(query_name, resolved_ips, &proc_ctx);
                    }
                }
                "OBSERVED"
            }
            SensorEvent::NetworkConnect { .. } if self.config.outbound_firewall_enabled => {
                let (act, emitted_alert) =
                    self.handle_network_connect(event, &proc_ctx, event_ts_ms);
                flush_now = emitted_alert;
                act
            }
            _ => "OBSERVED",
        };

        if let Err(err) = self.store.ingest_event_with_exit(
            event,
            proc_ctx.store_hint.as_deref(),
            proc_ctx.exited_at_ms,
            is_nrd,
            action,
        ) {
            tracing::warn!(error = %err, "failed to ingest event into SQLite store");
        } else if flush_now {
            if let Err(err) = self.store.flush_batch() {
                tracing::warn!(error = %err, "failed to flush network alert telemetry batch");
            }
        }

        match lane {
            EventLane::HighPriority => {
                self.high_priority_processed.fetch_add(1, Ordering::Relaxed);
            }
            EventLane::Telemetry => {
                self.telemetry_processed.fetch_add(1, Ordering::Relaxed);
            }
        }

        dns_correlation_key
    }

    fn prematerialize_domain_wfp_filters(
        &self,
        query_name: &str,
        resolved_ips: &[IpAddr],
        proc_ctx: &ResolvedProcessContext,
    ) {
        // Zero-overhead fast path when no domain-scoped persisted network rules exist.
        let has_domain_rules = self
            .firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_domain_network_rules();
        if !has_domain_rules {
            return;
        }

        let norm_query = query_name.trim().trim_end_matches('.');
        if norm_query.is_empty() {
            return;
        }
        let Some(exe_path) = proc_ctx
            .proc_exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !WfpRuleManager::is_wildcard_pattern(s))
        else {
            return;
        };
        let clean_exe = exe_path.trim_end_matches(['.', ' ']);
        if classify_outbound_risk(exe_path) == OutboundRiskClass::ProtectedOs
            || is_never_suspend_process(clean_exe)
        {
            return;
        }

        let mut external_ips: Vec<IpAddr> = Vec::new();
        for &ip in resolved_ips {
            let canon = canonical_ip(ip);
            if is_external_ip(canon) && !external_ips.contains(&canon) {
                external_ips.push(canon);
            }
        }
        if external_ips.is_empty() {
            return;
        }

        let rules = self.store.list_network_rules().unwrap_or_default();
        let matching_path_rules: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(exe_path, &r.exe_path_pattern)
            })
            .collect();
        if matching_path_rules.is_empty() {
            return;
        }

        let any_domain_target_matches = matching_path_rules.iter().any(|r| {
            r.allowed_target
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && parse_literal_target_ip(s).is_none())
                .is_some_and(|pat| {
                    external_ips
                        .iter()
                        .any(|ip| matches_network_target(pat, *ip, Some(norm_query)))
                })
        });
        if !any_domain_target_matches {
            return;
        }

        let bin_identity = self.inspector.inspect(exe_path);
        for ip in external_ips {
            let decision = evaluate_outbound_policy(&bin_identity, ip, Some(norm_query), &rules);
            match decision {
                OutboundDecision::BlockedByRule { rule_id } => {
                    let matched_target = rules
                        .iter()
                        .find(|r| r.rule_id == rule_id)
                        .and_then(|r| r.allowed_target.as_deref())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let res = match matched_target {
                        None => fw.ensure_policy_block(exe_path, None, &*self.defense),
                        Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                            fw.ensure_policy_block(exe_path, Some(ip), &*self.defense)
                        }
                        Some(_) => fw.ensure_domain_policy_block(
                            exe_path,
                            ip,
                            norm_query,
                            &*self.defense,
                        ),
                    };
                    if let Err(err) = res {
                        tracing::debug!(
                            exe_path = %exe_path,
                            query_name = %norm_query,
                            dst_ip = %ip,
                            error = %err,
                            "failed pre-materializing DomainPolicy WFP Block on DnsQuery"
                        );
                    }
                }
                OutboundDecision::AllowedByRule { .. } => {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    if fw.active_app_block(exe_path).is_some() {
                        if let Err(err) = fw.ensure_ip_permit_for_domain_rule(
                            exe_path,
                            ip,
                            norm_query,
                            &*self.defense,
                        ) {
                            tracing::debug!(
                                exe_path = %exe_path,
                                query_name = %norm_query,
                                dst_ip = %ip,
                                error = %err,
                                "failed pre-materializing DomainPolicy WFP Permit on DnsQuery"
                            );
                        }
                    }
                }
                OutboundDecision::ProtectedOs
                | OutboundDecision::PreemptiveRestrict(_)
                | OutboundDecision::UnknownFirstConnect => {}
            }
        }
    }

    fn maybe_apply_preemptive_wfp_block(&self, exe_path: &str) {
        let trimmed = exe_path.trim();
        if trimmed.is_empty() || WfpRuleManager::is_wildcard_pattern(trimmed) {
            return;
        }
        let risk = classify_outbound_risk(trimmed);
        if risk == OutboundRiskClass::ProtectedOs {
            return;
        }

        // Security #8: Before fast-returning on an existing WFP filter, re-verify the binary's
        // identity on disk (fresh SHA-256 via `SEC_0005`) whenever any Permit filter is live.
        // If the binary was overwritten or no longer authorized, immediately revoke stale Permit
        // filters and re-evaluate normal block/pre-emptive rules.
        let (has_permit, has_app_wide_permit) = {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            (
                fw.has_any_permit_filter_for_exe(trimmed),
                fw.has_active_filter(trimmed, None, true),
            )
        };
        if has_permit {
            let rules = self.store.list_network_rules().unwrap_or_default();
            let identity = self.inspector.inspect(trimmed);
            let still_authorized = if has_app_wide_permit {
                rules
                    .iter()
                    .any(|r| matches_app_wide_network_allow(r, &identity))
            } else {
                rules
                    .iter()
                    .any(|r| network_allow_rule_identity_matches(r, &identity))
            };
            if !still_authorized {
                tracing::warn!(
                    exe_path = %trimmed,
                    sha256 = ?identity.sha256,
                    "binary identity no longer matches persisted NetworkAllow rule on ProcessStart; revoking stale WFP permit(s)"
                );
                self.invalidate_non_protected_steady_pids();
                let _ = self.deploy_persisted_network_rules();
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if fw.has_any_permit_filter_for_exe(trimmed) {
                    fw.revoke_permits_for_exe(trimmed, &*self.defense);
                }
            }
        }

        let exe_key = WfpRuleManager::exe_key(trimmed);
        let (has_wildcards, is_startup_pinned) = {
            let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
            if fw.has_any_app_filter(trimmed) {
                return;
            }
            (
                fw.has_wildcard_network_rules(),
                fw.is_startup_preemptive(trimmed),
            )
        };
        let is_preemptive_risk = is_startup_pinned
            || matches!(
                risk,
                OutboundRiskClass::HighRiskPath | OutboundRiskClass::ScriptInterpreter
            );
        if !is_preemptive_risk && !has_wildcards {
            return;
        }

        // Only run BinaryInspector on ProcessStart when a persisted network rule matches
        // `exe_path_pattern`, keeping the high-priority ProcessStart hot path I/O-free
        // when no matching rules exist (`ANALYSIS_0002`).
        let rules = self.store.list_network_rules().unwrap_or_default();
        let matching_rules: Vec<&AllowlistRuleRecord> = rules
            .iter()
            .filter(|r| {
                !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(trimmed, &r.exe_path_pattern)
            })
            .collect();

        if !matching_rules.is_empty() {
            let needs_inspect = matching_rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    || r.sha256.as_deref().is_some_and(|s| !s.trim().is_empty())
                    || r.signer_subject
                        .as_deref()
                        .is_some_and(|s| !s.trim().is_empty())
            });
            let identity = if needs_inspect {
                self.inspector.inspect(trimmed)
            } else {
                BinaryIdentity {
                    exe_path: trimmed.to_string(),
                    sha256: None,
                    authenticode: None,
                }
            };

            if matching_rules
                .iter()
                .any(|r| matches_app_wide_network_block(r, &identity))
            {
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(err) = fw.ensure_policy_block(trimmed, None, &*self.defense) {
                    tracing::warn!(
                        exe_path = %trimmed,
                        error = %err,
                        "failed to apply persisted NetworkBlock WFP filter on ProcessStart"
                    );
                }
                return;
            }

            // Apply any literal IP-specific NetworkBlock rules matching this newly started
            // concrete executable (e.g. from wildcard `exe_path_pattern` rules).
            for rule in &matching_rules {
                if rule.scope != RuleScope::NetworkBlock {
                    continue;
                }
                if let Some(ip) = rule
                    .allowed_target
                    .as_deref()
                    .and_then(parse_literal_target_ip)
                {
                    if matches_network_block_rule(rule, &identity, ip, None) {
                        let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        if let Err(err) = fw.ensure_policy_block(trimmed, Some(ip), &*self.defense) {
                            tracing::warn!(
                                exe_path = %trimmed,
                                remote_ip = %ip,
                                error = %err,
                                "failed to apply IP-scoped NetworkBlock WFP filter on ProcessStart"
                            );
                        }
                    }
                }
            }

            if matching_rules
                .iter()
                .any(|r| matches_app_wide_network_allow(r, &identity))
            {
                // App-wide NetworkAllow suppresses pre-emptive block.
                return;
            }
        }

        if !is_preemptive_risk {
            return;
        }

        // Bug #2: Do not re-apply an app-wide automatic Preemptive WFP block while another running
        // sibling instance holds an active AllowOnce grant.
        if self
            .firewall
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_once_allowed_for_exe(&exe_key)
        {
            tracing::debug!(
                exe_path = %trimmed,
                "deferring automatic pre-emptive WFP block while sibling instance holds AllowOnce"
            );
            return;
        }

        match self.defense.add_wfp_app_rule(Path::new(trimmed), None, false) {
            Ok(handle) => {
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if fw.register_preemptive_block(trimmed, handle, &*self.defense) {
                    tracing::info!(
                        exe_path = %trimmed,
                        risk = ?risk,
                        wfp_handle = handle,
                        "applied pre-emptive WFP dynamic outbound block"
                    );
                }
            }
            Err(err) => {
                tracing::debug!(
                    exe_path = %trimmed,
                    risk = ?risk,
                    error = %err,
                    "pre-emptive WFP block unavailable on ProcessStart"
                );
            }
        }
    }

    fn resolve_effective_domain_hint(
        &self,
        proc_instance_id: Option<&str>,
        dst_ip: IpAddr,
        raw_domain_hint: Option<&str>,
        event_ts_ms: i64,
    ) -> Option<String> {
        let clean_raw = raw_domain_hint
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('.').to_string());
        let history = self
            .process_dns_history
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let own_entry = proc_instance_id.and_then(|id| history.lookup_for_process(id, dst_ip));
        match (clean_raw, own_entry) {
            (None, Some((own_domain, _))) => Some(own_domain),
            (None, None) => None,
            (Some(hint), Some((own_domain, _))) => {
                if !hint.eq_ignore_ascii_case(&own_domain)
                    && history.another_process_resolved(proc_instance_id, &hint, dst_ip, event_ts_ms)
                {
                    tracing::debug!(
                        process_instance_id = ?proc_instance_id,
                        dst_ip = %dst_ip,
                        dropped_domain_hint = %hint,
                        own_domain = %own_domain,
                        "replacing cross-process domain_hint with process instance's own DNS record (SEC_0009)"
                    );
                    Some(own_domain)
                } else {
                    Some(hint)
                }
            }
            (Some(hint), None) => {
                if history.another_process_resolved(proc_instance_id, &hint, dst_ip, event_ts_ms) {
                    tracing::debug!(
                        process_instance_id = ?proc_instance_id,
                        dst_ip = %dst_ip,
                        dropped_domain_hint = %hint,
                        "dropping cross-process domain_hint not resolved by connecting process instance (SEC_0009)"
                    );
                    None
                } else {
                    Some(hint)
                }
            }
        }
    }

    fn collect_wfp_candidates(&self, exe_key: &str, event_ts_ms: i64) -> Vec<WfpCandidate> {
        let table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table
            .candidates_by_exe_key_at(exe_key, event_ts_ms)
            .into_iter()
            .map(|e| {
                let (parent_exe_path, parent_command_line) = e
                    .parent_instance_id
                    .as_deref()
                    .and_then(|pid_id| table.get_by_instance_id(pid_id))
                    .map(|p| {
                        (
                            Some(p.exe_path.clone()),
                            (!p.command_line.is_empty()).then(|| p.command_line.clone()),
                        )
                    })
                    .unwrap_or((None, None));
                WfpCandidate {
                    identity: e.identity,
                    instance_id: e.instance_id.clone(),
                    exe_path: e.exe_path.clone(),
                    command_line: (!e.command_line.is_empty()).then(|| e.command_line.clone()),
                    parent_exe_path,
                    parent_command_line,
                }
            })
            .collect()
    }

    fn on_wfp_drop_dequeued(
        &self,
        item: QueuedWfpDrop,
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if self.config.wfp_drop_dns_grace_ms > 0 {
            let rules = self.store.list_network_rules().unwrap_or_default();
            let has_domain_allow_for_exe = rules.iter().any(|r| {
                r.scope == RuleScope::NetworkAllow
                    && !r.exe_path_pattern.trim().is_empty()
                    && matches_path_pattern(&item.exe_path, &r.exe_path_pattern)
                    && r.allowed_target
                        .as_deref()
                        .map(str::trim)
                        .filter(|t| !t.is_empty())
                        .is_some_and(|t| {
                            parse_literal_target_ip(t).is_none() && parse_cidr_target(t).is_err()
                        })
            });
            if has_domain_allow_for_exe {
                let candidates = self.collect_wfp_candidates(&item.exe_key, item.timestamp_ms);
                if !candidates.is_empty() {
                    let any_cand_has_dns = {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        candidates.iter().any(|c| {
                            history
                                .lookup_for_process(&c.instance_id, item.dst_ip)
                                .is_some()
                        })
                    };
                    if !any_cand_has_dns {
                        let bin_identity = self.inspector.inspect(&item.exe_path);
                        let no_hint_decision = evaluate_outbound_policy(
                            &bin_identity,
                            item.dst_ip,
                            None,
                            &rules,
                        );
                        if matches!(
                            no_hint_decision,
                            OutboundDecision::PreemptiveRestrict(_)
                                | OutboundDecision::UnknownFirstConnect
                        ) {
                            while pending.len() >= MAX_PENDING_WFP_DROPS {
                                if let Some(oldest) = pending.pop_front() {
                                    self.handle_wfp_drop_event_now(&oldest.item);
                                }
                            }
                            let deadline = tokio::time::Instant::now()
                                + Duration::from_millis(self.config.wfp_drop_dns_grace_ms);
                            pending.push_back(PendingWfpDrop { item, deadline });
                            return;
                        }
                    }
                }
            }
        }
        self.handle_wfp_drop_event_now(&item);
    }

    fn flush_ready_pending_wfp_drops(
        &self,
        dns_inst_id: &str,
        dns_exe_key: &str,
        query_name: &str,
        resolved_ips: &[IpAddr],
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if pending.is_empty() || resolved_ips.is_empty() {
            return;
        }
        let canon_resolved: Vec<IpAddr> = resolved_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let norm_query = query_name.trim().trim_end_matches('.');
        let mut cached_rules: Option<Vec<AllowlistRuleRecord>> = None;
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut ready = Vec::new();
        while let Some(entry) = pending.pop_front() {
            if dns_exe_key != entry.item.exe_key || !canon_resolved.contains(&entry.item.dst_ip) {
                remaining.push_back(entry);
                continue;
            }
            let candidates =
                self.collect_wfp_candidates(&entry.item.exe_key, entry.item.timestamp_ms);
            let dns_matches_candidate = candidates.iter().any(|c| c.instance_id == dns_inst_id);
            if !dns_matches_candidate {
                remaining.push_back(entry);
                continue;
            }
            if candidates.len() == 1 {
                ready.push(entry.item);
            } else {
                // Multi-instance case: only wake early if this candidate's DNS actually matches an
                // allowed target for the executable so a sibling's unrelated DNS does not cut
                // another instance's grace window short.
                let rules = cached_rules
                    .get_or_insert_with(|| self.store.list_network_rules().unwrap_or_default());
                let bin_identity = self.inspector.inspect(&entry.item.exe_path);
                let allowed = !norm_query.is_empty()
                    && matches!(
                        evaluate_outbound_policy(
                            &bin_identity,
                            entry.item.dst_ip,
                            Some(norm_query),
                            rules,
                        ),
                        OutboundDecision::AllowedByRule { .. }
                    );
                if allowed {
                    ready.push(entry.item);
                } else {
                    remaining.push_back(entry);
                }
            }
        }
        *pending = remaining;
        for item in ready {
            self.handle_wfp_drop_event_now(&item);
        }
    }

    fn flush_expired_pending_wfp_drops(&self, pending: &mut VecDeque<PendingWfpDrop>) {
        if pending.is_empty() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut expired = Vec::new();
        while let Some(entry) = pending.pop_front() {
            if entry.deadline <= now {
                expired.push(entry.item);
            } else {
                remaining.push_back(entry);
            }
        }
        *pending = remaining;
        for item in expired {
            self.handle_wfp_drop_event_now(&item);
        }
    }

    fn handle_wfp_drop_event_now(&self, item: &QueuedWfpDrop) {
        let candidates = self.collect_wfp_candidates(&item.exe_key, item.timestamp_ms);
        if candidates.is_empty() {
            tracing::debug!(
                exe_path = %item.exe_path,
                dst_ip = %item.dst_ip,
                dst_port = item.dst_port,
                "dropping WFP net event with no active/in-window candidate in ActiveProcessTable"
            );
            return;
        }

        if candidates.len() > 1 {
            // WfpDropEvent carries no PID or local socket tuple (`BUG_0004`); never guess an
            // individual instance across concurrent siblings — keep multi-candidate drops app-level.
            self.handle_ambiguous_wfp_drop(item, &candidates);
            return;
        }
        let cand = &candidates[0];

        let effective_domain_hint = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            history
                .lookup_for_process(&cand.instance_id, item.dst_ip)
                .map(|(domain, _)| domain)
        };
        let connect_event = SensorEvent::NetworkConnect {
            pid: cand.identity.pid,
            protocol: item.protocol,
            dst_ip: item.dst_ip,
            dst_port: item.dst_port,
            domain_hint: effective_domain_hint.clone(),
            timestamp_ms: item.timestamp_ms,
        };
        let proc_ctx = ResolvedProcessContext {
            proc_identity: Some(cand.identity),
            proc_instance_id: Some(cand.instance_id.clone()),
            proc_exe_path: Some(cand.exe_path.clone()),
            proc_command_line: cand.command_line.clone(),
            store_hint: Some(cand.instance_id.clone()),
            parent_exe_path: cand.parent_exe_path.clone(),
            parent_command_line: cand.parent_command_line.clone(),
            should_evaluate_sigma: true,
            exited_at_ms: None,
        };
        let (_action, emitted_alert) = self.evaluate_and_handle_outbound_connect(
            &connect_event,
            &proc_ctx,
            &cand.exe_path,
            cand.identity.pid,
            item.protocol,
            item.dst_ip,
            item.dst_port,
            effective_domain_hint,
            item.timestamp_ms,
        );
        if emitted_alert {
            if let Err(err) = self.store.flush_batch() {
                tracing::warn!(error = %err, "failed flushing store after attributed WFP drop alert");
            }
        }
    }

    fn handle_ambiguous_wfp_drop(&self, item: &QueuedWfpDrop, candidates: &[WfpCandidate]) {
        let canonical_exe = candidates
            .first()
            .map(|c| c.exe_path.as_str())
            .unwrap_or(item.exe_path.as_str());
        let risk = classify_outbound_risk(canonical_exe);
        if risk == OutboundRiskClass::ProtectedOs {
            return;
        }
        let rules = self.store.list_network_rules().unwrap_or_default();
        let bin_identity = self.inspector.inspect(canonical_exe);
        let cand_domains: Vec<String> = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            candidates
                .iter()
                .filter_map(|c| history.lookup_for_process(&c.instance_id, item.dst_ip))
                .map(|(dom, _)| dom)
                .collect()
        };
        let mut decision = evaluate_outbound_policy(&bin_identity, item.dst_ip, None, &rules);
        if matches!(decision, OutboundDecision::AllowedByRule { .. }) {
            if let Some(blk_rule_id) = cand_domains.iter().find_map(|dom| {
                match evaluate_outbound_policy(&bin_identity, item.dst_ip, Some(dom), &rules) {
                    OutboundDecision::BlockedByRule { rule_id } => Some(rule_id),
                    _ => None,
                }
            }) {
                decision = OutboundDecision::BlockedByRule {
                    rule_id: blk_rule_id,
                };
            }
        }
        let mut permit_failure: Option<(String, String)> = None;
        match &decision {
            OutboundDecision::ProtectedOs => return,
            OutboundDecision::AllowedByRule { rule_id } => {
                // App-scoped IP/CIDR/wildcard allow: materialize a concrete IP WFP Permit even
                // when PID is ambiguous, respecting existing IP blocks (`deny overrides allow`)
                // and preserving known candidate domain hints (`SEC_0001`).
                // Never swallow a BFE failure silently without alerting.
                let matched_target = rules
                    .iter()
                    .find(|r| &r.rule_id == rule_id)
                    .and_then(|r| r.allowed_target.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let domain_label = cand_domains
                    .first()
                    .map(String::as_str)
                    .or_else(|| {
                        matched_target.filter(|t| {
                            parse_literal_target_ip(t).is_none() && parse_cidr_target(t).is_err()
                        })
                    })
                    .unwrap_or("");
                let permit_res = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    if fw.active_app_block(canonical_exe).is_some() {
                        fw.ensure_ip_permit_for_domain_rule(
                            canonical_exe,
                            item.dst_ip,
                            domain_label,
                            &*self.defense,
                        )
                    } else {
                        Ok(None)
                    }
                };
                match permit_res {
                    Ok(_) => return,
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %canonical_exe,
                            dst_ip = %item.dst_ip,
                            rule_id = %rule_id,
                            error = %err,
                            "failed installing IP-specific WFP permit for app-level allowed target"
                        );
                        permit_failure = Some((rule_id.clone(), err));
                    }
                }
            }
            OutboundDecision::PreemptiveRestrict(_) | OutboundDecision::UnknownFirstConnect => {
                // If an active candidate already resolved an allowed domain for `dst_ip` and
                // materialized a live IP Permit (with no overriding block), do not emit a false
                // ambiguous drop alert.
                let any_blocked_dom = cand_domains.iter().any(|dom| {
                    matches!(
                        evaluate_outbound_policy(&bin_identity, item.dst_ip, Some(dom), &rules),
                        OutboundDecision::BlockedByRule { .. }
                    )
                });
                let any_allowed_dom = cand_domains.iter().any(|dom| {
                    matches!(
                        evaluate_outbound_policy(&bin_identity, item.dst_ip, Some(dom), &rules),
                        OutboundDecision::AllowedByRule { .. }
                    )
                });
                if any_allowed_dom && !any_blocked_dom {
                    let has_live_ip_permit = {
                        let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.has_active_filter(canonical_exe, Some(item.dst_ip), true)
                            && !fw.has_active_filter(canonical_exe, Some(item.dst_ip), false)
                    };
                    if has_live_ip_permit {
                        return;
                    }
                }
            }
            OutboundDecision::BlockedByRule { .. } => {}
        }

        {
            let mut dedup = self
                .app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.mark_if_new(&item.exe_key, item.dst_ip) {
                return;
            }
        }

        let alert_id = Uuid::new_v4().to_string();
        let mut bound_existing = false;
        let mut wfp_permit_error: Option<String> = None;
        let (rule_id, severity, label, matched_rule_id, wfp_filter_id) =
            if let Some((rule_id, err_msg)) = permit_failure {
                let wfp_handle = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    bound_existing = fw.bind_alert_to_app_block(&alert_id, canonical_exe);
                    fw.active_app_block(canonical_exe)
                        .map(|(h, _)| h)
                        .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                };
                wfp_permit_error = Some(err_msg);
                (
                    "LEDR-NET-POLICY-PERMIT-FAILED",
                    AlertSeverity::High,
                    "Allowed Outbound WFP Permit Failed (App-Level)",
                    Some(rule_id),
                    wfp_handle,
                )
            } else {
                match decision {
                    OutboundDecision::BlockedByRule { rule_id } => {
                        let matched_target = rules
                            .iter()
                            .find(|r| r.rule_id == rule_id)
                            .and_then(|r| r.allowed_target.as_deref())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let wfp_handle = {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            let res = match matched_target {
                                None => fw.ensure_policy_block(canonical_exe, None, &*self.defense),
                                Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                                    fw.ensure_policy_block(
                                        canonical_exe,
                                        Some(item.dst_ip),
                                        &*self.defense,
                                    )
                                }
                                Some(target_pat) => fw.ensure_domain_policy_block(
                                    canonical_exe,
                                    item.dst_ip,
                                    target_pat,
                                    &*self.defense,
                                ),
                            };
                            res.ok()
                                .or_else(|| fw.active_app_block(canonical_exe).map(|(h, _)| h))
                                .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                        };
                        (
                            "LEDR-NET-POLICY-BLOCK",
                            AlertSeverity::High,
                            "Blocked Outbound Policy Match (App-Level)",
                            Some(rule_id),
                            wfp_handle,
                        )
                    }
                    OutboundDecision::PreemptiveRestrict(_)
                    | OutboundDecision::UnknownFirstConnect => {
                        let wfp_handle = {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            bound_existing = fw.bind_alert_to_app_block(&alert_id, canonical_exe);
                            fw.active_app_block(canonical_exe)
                                .map(|(h, _)| h)
                                .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                        };
                        let (rid, sev, lbl) = match risk {
                            OutboundRiskClass::HighRiskPath => (
                                "LEDR-NET-HIGH-RISK-PATH",
                                AlertSeverity::High,
                                "High-Risk Path Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                            OutboundRiskClass::ScriptInterpreter => (
                                "LEDR-NET-SCRIPT-INTERPRETER",
                                AlertSeverity::High,
                                "Script Interpreter Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                            _ => (
                                "LEDR-NET-UNKNOWN-OUTBOUND",
                                AlertSeverity::Medium,
                                "Unknown Process Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                        };
                        (rid, sev, lbl, None, wfp_handle)
                    }
                    OutboundDecision::ProtectedOs | OutboundDecision::AllowedByRule { .. } => {
                        unreachable!()
                    }
                }
            };

        let candidate_pids: Vec<u32> = candidates.iter().map(|c| c.identity.pid).collect();
        let candidate_instance_ids: Vec<&str> =
            candidates.iter().map(|c| c.instance_id.as_str()).collect();
        let context_json = serde_json::json!({
            "attribution": "app_level_ambiguous",
            "pid": serde_json::Value::Null,
            "candidate_pids": candidate_pids,
            "candidate_instance_ids": candidate_instance_ids,
            "exe_path": canonical_exe,
            "dst_ip": item.dst_ip.to_string(),
            "dst_port": item.dst_port,
            "protocol": item.protocol,
            "domain_hint": serde_json::Value::Null,
            "matched_rule_id": matched_rule_id,
            "wfp_permit_error": wfp_permit_error,
            "risk_class": format!("{risk:?}"),
            "wfp_blocked": wfp_filter_id.is_some(),
            "wfp_filter_id": wfp_filter_id,
            "sha256": bin_identity.sha256,
            "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
            "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
        })
        .to_string();

        let alert = AlertRecord {
            alert_id: alert_id.clone(),
            timestamp_ms: item.timestamp_ms,
            severity,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: rule_id.to_string(),
            title: outbound_alert_title(
                label,
                canonical_exe,
                item.dst_ip,
                item.dst_port,
                None,
            ),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        if let Err(err) = self.record_alert_checked(&alert) {
            tracing::warn!(
                error = %err,
                alert_id = %alert.alert_id,
                exe_path = %canonical_exe,
                "failed to record app-level ambiguous WFP drop alert"
            );
            if bound_existing {
                self.firewall
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .unbind_alert(&alert_id);
            }
            self.app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear_key(&item.exe_key, item.dst_ip);
            return;
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = self.notifier.notify_alert(&alert) {
            tracing::warn!(
                alert_id = %alert.alert_id,
                error = %err,
                "failed to dispatch toast notification for app-level WFP drop alert"
            );
        }
        if let Err(err) = self.store.flush_batch() {
            tracing::warn!(error = %err, "failed flushing store after app-level WFP drop alert");
        }
    }

    fn handle_network_connect(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        event_ts_ms: i64,
    ) -> (&'static str, bool) {
        let SensorEvent::NetworkConnect {
            pid,
            protocol,
            dst_ip,
            dst_port,
            domain_hint,
            ..
        } = event
        else {
            return ("OBSERVED", false);
        };

        if !is_external_ip(*dst_ip) {
            return ("OBSERVED", false);
        }

        let Some(exe_path) = proc_ctx
            .proc_exe_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return ("OBSERVED", false);
        };

        let risk = classify_outbound_risk(exe_path);
        if risk == OutboundRiskClass::ProtectedOs {
            self.outbound_classifier.mark_protected_os(*pid);
            return ("OBSERVED", false);
        }

        let effective_domain_hint = self.resolve_effective_domain_hint(
            proc_ctx.proc_instance_id.as_deref(),
            *dst_ip,
            domain_hint.as_deref(),
            event_ts_ms,
        );

        self.evaluate_and_handle_outbound_connect(
            event,
            proc_ctx,
            exe_path,
            *pid,
            *protocol,
            *dst_ip,
            *dst_port,
            effective_domain_hint,
            event_ts_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_and_handle_outbound_connect(
        &self,
        event: &SensorEvent,
        proc_ctx: &ResolvedProcessContext,
        exe_path: &str,
        pid: u32,
        protocol: u8,
        dst_ip: IpAddr,
        dst_port: u16,
        effective_domain_hint: Option<String>,
        event_ts_ms: i64,
    ) -> (&'static str, bool) {
        let risk = classify_outbound_risk(exe_path);

        let already_outbound_alerted = proc_ctx
            .proc_instance_id
            .as_deref()
            .is_some_and(|inst_id| self.has_rule_alert_emitted(inst_id, "NET_OUTBOUND"));
        let rules = self.store.list_network_rules().unwrap_or_default();
        // Fast path: when already alerted and no persisted network rules exist, avoid re-running
        // BinaryInspector on every repeated connect in a burst. When persisted rules exist, always
        // evaluate policy first so explicit NetworkBlock / NetworkAllow rules are never bypassed
        // by NET_OUTBOUND alert deduplication.
        if already_outbound_alerted && rules.is_empty() {
            self.outbound_classifier.mark_steady(pid);
            return ("DEDUP_SUPPRESSED", false);
        }

        let bin_identity = self.inspector.inspect(exe_path);
        let decision = evaluate_outbound_policy(
            &bin_identity,
            dst_ip,
            effective_domain_hint.as_deref(),
            &rules,
        );
        let has_block_rule_for_exe = rules.iter().any(|r| {
            r.scope == RuleScope::NetworkBlock
                && !r.exe_path_pattern.trim().is_empty()
                && matches_path_pattern(exe_path, &r.exe_path_pattern)
        });
        let has_domain_rules_for_exe = rules.iter().any(|r| {
            matches!(r.scope, RuleScope::NetworkAllow | RuleScope::NetworkBlock)
                && r.allowed_target
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|s| {
                        !s.is_empty()
                            && parse_literal_target_ip(s).is_none()
                            && parse_cidr_target(s).is_err()
                    })
                && !r.exe_path_pattern.trim().is_empty()
                && matches_path_pattern(exe_path, &r.exe_path_pattern)
        });

        match decision {
            OutboundDecision::ProtectedOs => {
                self.outbound_classifier.mark_protected_os(pid);
                ("OBSERVED", false)
            }
            OutboundDecision::AllowedByRule { rule_id } => {
                // If an app-wide pre-emptive block is active (e.g. script interpreter with a
                // domain/CIDR-scoped NetworkAllow), install an IP-specific Permit so this
                // destination flows cleanly through WFP and survives rule reconciliations.
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                if fw.active_app_block(exe_path).is_some() {
                    let matched_target = rules
                        .iter()
                        .find(|r| r.rule_id == rule_id)
                        .and_then(|r| r.allowed_target.as_deref())
                        .map(str::trim)
                        .filter(|s| !s.is_empty());
                    let fallback_domain = matched_target.filter(|t| {
                        parse_literal_target_ip(t).is_none() && parse_cidr_target(t).is_err()
                    });
                    let domain_label = effective_domain_hint
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .or(fallback_domain)
                        .unwrap_or("");
                    if let Err(err) = fw.ensure_ip_permit_for_domain_rule(
                        exe_path,
                        dst_ip,
                        domain_label,
                        &*self.defense,
                    ) {
                        tracing::debug!(
                            exe_path = %exe_path,
                            dst_ip = %dst_ip,
                            error = %err,
                            "could not install IP-specific WFP permit for allowed domain"
                        );
                    }
                }
                let has_app_wide_permit = fw.has_active_filter(exe_path, None, true);
                drop(fw);
                if has_app_wide_permit && !has_block_rule_for_exe && !has_domain_rules_for_exe {
                    self.outbound_classifier.mark_steady(pid);
                }
                ("ALLOWED", false)
            }
            OutboundDecision::BlockedByRule { rule_id } => {
                let matched_target = rules
                    .iter()
                    .find(|r| r.rule_id == rule_id)
                    .and_then(|r| r.allowed_target.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let wfp_handle = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    let res = match matched_target {
                        None => fw.ensure_policy_block(exe_path, None, &*self.defense),
                        Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                            fw.ensure_policy_block(exe_path, Some(dst_ip), &*self.defense)
                        }
                        Some(target_pat) => {
                            let label = effective_domain_hint
                                .as_deref()
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .unwrap_or(target_pat);
                            fw.ensure_domain_policy_block(exe_path, dst_ip, label, &*self.defense)
                        }
                    };
                    match res {
                        Ok(h) => Some(h),
                        Err(err) => {
                            tracing::warn!(
                                exe_path = %exe_path,
                                rule_id = %rule_id,
                                error = %err,
                                "failed to ensure WFP block filter for matched NetworkBlock rule"
                            );
                            None
                        }
                    }
                };
                let is_new_block_alert = proc_ctx
                    .proc_instance_id
                    .as_deref()
                    .is_none_or(|inst_id| self.is_new_rule_alert(inst_id, "NET_POLICY_BLOCK"));
                if !is_new_block_alert {
                    return ("BLOCKED", false);
                }

                let domain_risk = effective_domain_hint
                    .as_deref()
                    .map(|d| self.assess_domain(d));
                let is_first_seen_domain = effective_domain_hint
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some_and(|d| !self.store.has_seen_dns_domain(d).unwrap_or(false));
                let context_json = serde_json::json!({
                    "event": event,
                    "dst_ip": dst_ip.to_string(),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain_hint": effective_domain_hint,
                    "matched_rule_id": rule_id,
                    "risk_class": format!("{risk:?}"),
                    "wfp_blocked": wfp_handle.is_some(),
                    "wfp_filter_id": wfp_handle,
                    "pid": pid,
                    "exe_path": exe_path,
                    "command_line": proc_ctx.proc_command_line,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "sha256": bin_identity.sha256,
                    "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
                    "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
                    "is_nrd": domain_risk.as_ref().is_some_and(|r| r.is_nrd),
                    "is_homograph": domain_risk.as_ref().is_some_and(|r| r.is_homograph),
                    "matched_brand": domain_risk.and_then(|r| r.matched_brand),
                    "is_first_seen_domain": is_first_seen_domain,
                })
                .to_string();
                let alert = AlertRecord {
                    alert_id: Uuid::new_v4().to_string(),
                    timestamp_ms: event_ts_ms,
                    severity: AlertSeverity::High,
                    source_layer: "LAYER_3_NETWORK".to_string(),
                    rule_id: "LEDR-NET-POLICY-BLOCK".to_string(),
                    title: outbound_alert_title(
                        "Blocked Outbound Policy Match",
                        exe_path,
                        dst_ip,
                        dst_port,
                        effective_domain_hint.as_deref(),
                    ),
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended: false,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };
                if let Err(err) = self.record_alert_checked(&alert) {
                    tracing::warn!(error = %err, "failed to record network policy block alert");
                    if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                        self.clear_rule_alert(inst_id, "NET_POLICY_BLOCK");
                    }
                    return ("BLOCKED", false);
                }
                self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                ("BLOCKED", true)
            }
            OutboundDecision::PreemptiveRestrict(_) | OutboundDecision::UnknownFirstConnect => {
                // Respect per-process AllowOnce grant (only when no NetworkBlock matched above).
                if let Some(inst_id) = proc_ctx.proc_instance_id.as_deref() {
                    if self
                        .firewall
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .is_once_allowed(inst_id)
                    {
                        if !has_block_rule_for_exe {
                            self.outbound_classifier.mark_steady(pid);
                        }
                        return ("ALLOWED", false);
                    }
                    if already_outbound_alerted {
                        return ("DEDUP_SUPPRESSED", false);
                    }
                    let _ = self.is_new_rule_alert(inst_id, "NET_OUTBOUND");
                }

                // Security #8: If a stale WFP Permit filter remains in `firewall` (e.g., binary
                // replaced on disk after ProcessStart), revoke it before registering transient
                // containment so `register_transient_containment` is never shadowed by a stale Permit.
                let any_allow_identity_valid = rules
                    .iter()
                    .any(|r| network_allow_rule_identity_matches(r, &bin_identity));
                let revoked_permits = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    if !any_allow_identity_valid {
                        fw.revoke_permits_for_exe(exe_path, &*self.defense)
                    } else {
                        let mut count = 0usize;
                        if fw.revoke_permit_for_target(exe_path, None, &*self.defense) {
                            count += 1;
                        }
                        if fw.revoke_permit_for_target(exe_path, Some(dst_ip), &*self.defense) {
                            count += 1;
                        }
                        count
                    }
                };
                if revoked_permits > 0 {
                    tracing::warn!(
                        exe_path = %exe_path,
                        revoked_permits,
                        "revoked stale WFP Permit filter(s) before applying outbound containment"
                    );
                    self.invalidate_non_protected_steady_pids();
                }

                let alert_id = Uuid::new_v4().to_string();
                let verified_ident = proc_ctx
                    .proc_identity
                    .filter(|id| id.create_time_100ns != 0);

                let exe_key = WfpRuleManager::exe_key(exe_path);
                let (existing_preemptive, shared_allow_once_active) = {
                    let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    (
                        fw.active_app_block(exe_path),
                        fw.has_once_allowed_for_exe(&exe_key),
                    )
                };

                let mut process_suspended = false;
                let mut wfp_filter_id: Option<u64> = None;
                let mut newly_added_transient: Option<u64> = None;
                let mut bound_existing_alert = false;
                let mut wfp_shared_allow_once_deferred = false;

                if let Some((existing_handle, _existing_origin)) = existing_preemptive {
                    wfp_filter_id = Some(existing_handle);
                    bound_existing_alert = self
                        .firewall
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .bind_alert_to_app_block(&alert_id, exe_path);
                    if let Some(ident) = verified_ident {
                        match self.defense.suspend_process(&ident, false) {
                            Ok(()) => process_suspended = true,
                            Err(err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    error = %err,
                                    "suspend_process failed on pre-emptively blocked outbound connect"
                                );
                            }
                        }
                    }
                } else if shared_allow_once_active {
                    // Bug #2: Another running sibling instance of `exe_path` currently holds an
                    // AllowOnce exemption. Suspend this new instance and emit the alert while
                    // deferring an app-wide WFP block so the AllowOnce sibling is not severed.
                    wfp_shared_allow_once_deferred = true;
                    if let Some(ident) = verified_ident {
                        match self.defense.suspend_process(&ident, false) {
                            Ok(()) => process_suspended = true,
                            Err(err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    error = %err,
                                    "suspend_process failed on outbound connect with deferred AllowOnce WFP block"
                                );
                            }
                        }
                    } else {
                        tracing::warn!(
                            pid,
                            exe_path = %exe_path,
                            "skipping process suspension on outbound connect with deferred AllowOnce: missing non-zero ProcessIdentity create_time_100ns"
                        );
                    }
                } else if let Some(ident) = verified_ident {
                    // Coupled containment (`L-03`, `active-defense-guards.md` #5):
                    // Add dynamic WFP block first, then suspend process; if either side fails,
                    // roll back immediately so neither an orphaned WFP filter nor an isolated
                    // suspended process remains.
                    match self.defense.add_wfp_app_rule(Path::new(exe_path), None, false) {
                        Ok(handle) => match self.defense.suspend_process(&ident, false) {
                            Ok(()) => {
                                process_suspended = true;
                                let registered = self
                                    .firewall
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner())
                                    .register_transient_containment(
                                        &alert_id,
                                        exe_path,
                                        handle,
                                        &*self.defense,
                                    );
                                match registered {
                                    Some(h) => {
                                        wfp_filter_id = Some(h);
                                        newly_added_transient = Some(h);
                                    }
                                    None => {
                                        wfp_filter_id = self
                                            .firewall
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner())
                                            .active_app_block(exe_path)
                                            .map(|(h, _)| h);
                                        bound_existing_alert = wfp_filter_id.is_some();
                                    }
                                }
                            }
                            Err(susp_err) => {
                                tracing::warn!(
                                    pid,
                                    exe_path = %exe_path,
                                    wfp_handle = handle,
                                    error = %susp_err,
                                    "suspend_process failed during coupled outbound containment; rolling back WFP block filter"
                                );
                                if let Err(rm_err) = self.defense.remove_wfp_rule(handle) {
                                    tracing::warn!(
                                        pid,
                                        exe_path = %exe_path,
                                        wfp_handle = handle,
                                        error = %rm_err,
                                        "compensation remove_wfp_rule failed after suspend_process error"
                                    );
                                }
                            }
                        },
                        Err(wfp_err) => {
                            tracing::warn!(
                                pid,
                                exe_path = %exe_path,
                                error = %wfp_err,
                                "add_wfp_app_rule failed during coupled outbound containment; skipping suspend to avoid orphaned state"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        pid,
                        exe_path = %exe_path,
                        "skipping coupled outbound containment: missing non-zero ProcessIdentity create_time_100ns"
                    );
                }

                let domain_risk = effective_domain_hint
                    .as_deref()
                    .map(|d| self.assess_domain(d));
                let is_first_seen_domain = effective_domain_hint
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .is_some_and(|d| !self.store.has_seen_dns_domain(d).unwrap_or(false));
                let is_nrd_or_homograph = domain_risk
                    .as_ref()
                    .is_some_and(|r| r.is_nrd || r.is_homograph);

                let (rule_id, severity, label) = match risk {
                    OutboundRiskClass::HighRiskPath => (
                        "LEDR-NET-HIGH-RISK-PATH",
                        AlertSeverity::High,
                        "High-Risk Path Outbound Connection",
                    ),
                    OutboundRiskClass::ScriptInterpreter => (
                        "LEDR-NET-SCRIPT-INTERPRETER",
                        AlertSeverity::High,
                        "Script Interpreter Outbound Connection",
                    ),
                    _ => (
                        "LEDR-NET-UNKNOWN-OUTBOUND",
                        if is_nrd_or_homograph {
                            AlertSeverity::High
                        } else {
                            AlertSeverity::Medium
                        },
                        "Unknown Process Outbound Connection",
                    ),
                };

                let context_json = serde_json::json!({
                    "event": event,
                    "dst_ip": dst_ip.to_string(),
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "domain_hint": effective_domain_hint,
                    "risk_class": format!("{risk:?}"),
                    "wfp_blocked": wfp_filter_id.is_some(),
                    "wfp_filter_id": wfp_filter_id,
                    "wfp_shared_allow_once_deferred": wfp_shared_allow_once_deferred,
                    "pid": pid,
                    "exe_path": exe_path,
                    "command_line": proc_ctx.proc_command_line,
                    "parent_exe_path": proc_ctx.parent_exe_path,
                    "parent_command_line": proc_ctx.parent_command_line,
                    "sha256": bin_identity.sha256,
                    "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
                    "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
                    "is_nrd": domain_risk.as_ref().is_some_and(|r| r.is_nrd),
                    "is_homograph": domain_risk.as_ref().is_some_and(|r| r.is_homograph),
                    "matched_brand": domain_risk.and_then(|r| r.matched_brand),
                    "is_first_seen_domain": is_first_seen_domain,
                })
                .to_string();

                let alert = AlertRecord {
                    alert_id: alert_id.clone(),
                    timestamp_ms: event_ts_ms,
                    severity,
                    source_layer: "LAYER_3_NETWORK".to_string(),
                    rule_id: rule_id.to_string(),
                    title: outbound_alert_title(
                        label,
                        exe_path,
                        dst_ip,
                        dst_port,
                        effective_domain_hint.as_deref(),
                    ),
                    process_instance_id: proc_ctx.proc_instance_id.clone(),
                    process_suspended,
                    status: AlertStatus::Pending,
                    context_json,
                    resolved_at_ms: None,
                };

                if let Err(err) = self.record_alert_checked(&alert) {
                    tracing::warn!(
                        error = %err,
                        alert_id = %alert.alert_id,
                        "failed to record outbound alert; compensating suspension, transient WFP block, and dedup state"
                    );
                    if process_suspended {
                        if let Some(ident) = verified_ident {
                            if let Err(resume_err) = self.defense.resume_process(&ident) {
                                tracing::warn!(
                                    pid = ident.pid,
                                    error = %resume_err,
                                    "compensation resume_process failed after outbound record_alert error"
                                );
                            }
                        }
                    }
                    if let Some(handle) = newly_added_transient {
                        self.firewall
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .rollback_transient_containment(
                                &alert_id,
                                exe_path,
                                handle,
                                &*self.defense,
                            );
                    } else if bound_existing_alert {
                        self.firewall
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .unbind_alert(&alert_id);
                    }
                    if let Some(ref inst_id) = proc_ctx.proc_instance_id {
                        self.clear_rule_alert(inst_id, "NET_OUTBOUND");
                    }
                    return ("ALERT_RECORD_FAILED", false);
                }

                self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
                if let Err(err) = self.notifier.notify_alert(&alert) {
                    tracing::warn!(
                        alert_id = %alert.alert_id,
                        error = %err,
                        "failed to dispatch toast notification for outbound alert"
                    );
                }

                let action = match (process_suspended, wfp_filter_id.is_some()) {
                    (true, true) => "SUSPENDED_BLOCKED",
                    (false, true) => "BLOCKED",
                    (true, false) => "SUSPENDED",
                    (false, false) => "ALERTED",
                };
                (action, true)
            }
        }
    }

    fn record_alert_checked(&self, alert: &AlertRecord) -> Result<(), StoreError> {
        if self.fail_record_alert_for_test.load(Ordering::Acquire) {
            Err(StoreError::InvalidValue {
                field: "alerts.test_injection",
                value: "injected record_alert failure".to_string(),
            })
        } else {
            self.store.record_alert(alert)
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
                let exe_path = id
                    .as_deref()
                    .and_then(|inst_id| table.get_by_instance_id(inst_id))
                    .map(|entry| entry.exe_path.clone());
                ResolvedProcessContext {
                    proc_identity: None,
                    proc_instance_id: id.clone(),
                    proc_exe_path: exe_path,
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

fn outbound_alert_title(
    label: &str,
    exe_path: &str,
    dst_ip: IpAddr,
    dst_port: u16,
    domain_hint: Option<&str>,
) -> String {
    let exe_name = exe_path
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(exe_path);
    match domain_hint.map(str::trim).filter(|s| !s.is_empty()) {
        Some(domain) => format!("{label}: {exe_name} -> {domain} ({dst_ip}:{dst_port})"),
        None => format!("{label}: {exe_name} -> {dst_ip}:{dst_port}"),
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

fn execute_nrd_refresh(
    feed_urls: &[String],
    cache_path: Option<&Path>,
    nrd_cache: &Arc<RwLock<NrdCache>>,
    cancel: &NrdCancelToken,
) -> Result<NrdRefreshStats, String> {
    let now_ms = current_unix_ms();
    let (fresh, stats) = refresh_nrd_cache_cancellable(
        feed_urls,
        NRD_MAX_ENTRIES,
        NRD_MAX_RESPONSE_BYTES,
        now_ms,
        cancel,
    )?;
    if cancel.is_cancelled() {
        return Err("NRD cache refresh cancelled".to_string());
    }
    if let Some(path) = cache_path {
        if let Err(err) = fresh.save_to_file(path) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "failed persisting refreshed NRD cache to disk"
            );
        }
    }
    let mut guard = nrd_cache.write().unwrap_or_else(|e| e.into_inner());
    *guard = fresh;
    Ok(stats)
}

#[derive(Debug, Default)]
struct WfpDropDedupCache {
    capacity: usize,
    window_ms: i64,
    last_seen: HashMap<(String, IpAddr, u16), i64>,
    insertion_order: VecDeque<(String, IpAddr, u16)>,
}

impl WfpDropDedupCache {
    fn new(capacity: usize, window_ms: i64) -> Self {
        Self {
            capacity: capacity.max(1),
            window_ms: window_ms.max(1),
            last_seen: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn should_emit(&mut self, exe_key: &str, ip: IpAddr, port: u16, ts_ms: i64) -> bool {
        let key = (exe_key.to_string(), canonical_ip(ip), port);
        if let Some(prev_ts) = self.last_seen.get_mut(&key) {
            if ts_ms >= *prev_ts && ts_ms.saturating_sub(*prev_ts) < self.window_ms {
                return false;
            }
            *prev_ts = ts_ms;
            return true;
        }
        while self.last_seen.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.last_seen.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.last_seen.insert(key, ts_ms);
        true
    }
}

const CROSS_PROCESS_DNS_CONFLICT_WINDOW_MS: i64 = 3_600_000;

#[derive(Debug, Default)]
struct ProcessDnsHistory {
    capacity: usize,
    entries: HashMap<(String, IpAddr), (String, i64)>,
    insertion_order: VecDeque<(String, IpAddr)>,
}

impl ProcessDnsHistory {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn record(
        &mut self,
        process_instance_id: &str,
        query_name: &str,
        resolved_ips: &[IpAddr],
        timestamp_ms: i64,
    ) {
        let norm_domain = query_name.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_domain.is_empty() {
            return;
        }
        for &ip in resolved_ips {
            let canon = canonical_ip(ip);
            let key = (process_instance_id.to_string(), canon);
            if let Some(existing) = self.entries.get_mut(&key) {
                *existing = (norm_domain.clone(), timestamp_ms);
            } else {
                while self.entries.len() >= self.capacity {
                    let Some(oldest) = self.insertion_order.pop_front() else {
                        break;
                    };
                    self.entries.remove(&oldest);
                }
                self.insertion_order.push_back(key.clone());
                self.entries.insert(key, (norm_domain.clone(), timestamp_ms));
            }
        }
    }

    fn remove_process(&mut self, process_instance_id: &str) {
        self.entries
            .retain(|(inst_id, _), _| inst_id != process_instance_id);
        self.insertion_order
            .retain(|(inst_id, _)| inst_id != process_instance_id);
    }

    fn lookup_for_process(&self, process_instance_id: &str, ip: IpAddr) -> Option<(String, i64)> {
        self.entries
            .get(&(process_instance_id.to_string(), canonical_ip(ip)))
            .cloned()
    }

    fn domains_for_ip(&self, ip: &IpAddr) -> Vec<String> {
        let canon = canonical_ip(*ip);
        let mut out: Vec<String> = self
            .entries
            .iter()
            .filter(|((_, entry_ip), _)| *entry_ip == canon)
            .map(|(_, (dom, _))| dom.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn another_process_resolved(
        &self,
        current_inst_id: Option<&str>,
        domain: &str,
        ip: IpAddr,
        event_ts_ms: i64,
    ) -> bool {
        let norm_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if norm_domain.is_empty() {
            return false;
        }
        let canon = canonical_ip(ip);
        self.entries
            .iter()
            .any(|((inst_id, entry_ip), (entry_domain, ts_ms))| {
                Some(inst_id.as_str()) != current_inst_id
                    && *entry_ip == canon
                    && *entry_domain == norm_domain
                    && event_ts_ms.saturating_sub(*ts_ms) <= CROSS_PROCESS_DNS_CONFLICT_WINDOW_MS
                    && *ts_ms <= event_ts_ms.saturating_add(60_000)
            })
    }
}

fn network_allow_rule_identity_matches(
    rule: &AllowlistRuleRecord,
    identity: &BinaryIdentity,
) -> bool {
    if rule.scope != RuleScope::NetworkAllow {
        return false;
    }
    if rule
        .allowed_target
        .as_deref()
        .is_none_or(|s| s.trim().is_empty())
    {
        return matches_app_wide_network_allow(rule, identity);
    }
    let mut probe = rule.clone();
    probe.allowed_target = None;
    matches_app_wide_network_allow(&probe, identity)
}

#[cfg(test)]
mod tests {
    use super::{tolerate_missing_target, ProcessDnsHistory};
    use ledr_sensor_win::defense::ProcessLiveness;
    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn process_dns_history_is_bounded_and_scoped_by_instance() {
        let mut hist = ProcessDnsHistory::new(2);
        let ip1 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let ip3 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));

        hist.record("100:1", "Allowed.Example.", &[ip1], 1_000);
        hist.record("200:2", "Other.Example", &[ip2], 1_100);
        assert!(hist.another_process_resolved(Some("300:3"), "allowed.example", ip1, 1_200));
        assert!(!hist.another_process_resolved(Some("100:1"), "allowed.example", ip1, 1_200));

        hist.record("300:3", "Third.Example", &[ip3], 1_300);
        assert_eq!(hist.entries.len(), 2);
        assert!(hist.lookup_for_process("100:1", ip1).is_none());

        hist.remove_process("200:2");
        assert!(hist.lookup_for_process("200:2", ip2).is_none());
        assert_eq!(hist.entries.len(), 1);
    }
}
