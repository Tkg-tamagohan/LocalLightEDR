use std::path::PathBuf;

use ledr_proto::{
    ACTIVE_PROCESS_TABLE_CAPACITY, DEFAULT_ALERT_TIMEOUT_SECS, DEFAULT_TTL_RETENTION_DAYS,
    DNS_RESOLUTION_CACHE_CAPACITY, HIGH_PRIORITY_CHANNEL_CAPACITY, IPC_PIPE_NAME,
    SHUTDOWN_FLUSH_TIMEOUT_MS, STORE_BATCH_FLUSH_INTERVAL_MS, TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::{DEFAULT_NRD_FEED_URLS, NRD_REFRESH_INTERVAL_MS};

const DEFAULT_TTL_PURGE_INTERVAL_MS: u64 = 3_600_000;
pub const DEFAULT_MAX_CONCURRENT_IPC_CLIENTS: usize = 16;
const DEFAULT_IPC_FRAME_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IPC_SESSION_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_WFP_DROP_DNS_GRACE_MS: u64 = 300;
const DEFAULT_WFP_DROP_RECENT_EXIT_WINDOW_MS: u64 = 1_000;
const DEFAULT_WFP_DROP_OTHER_INSTANCE_DNS_WINDOW_MS: u64 = 10_000;
const DEFAULT_MOTW_SYNC_WAIT_BUDGET_MS: u64 = 50;

/// Controls how aggressively Phase 3 outbound firewall rules enforce containment (`L-03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutboundEnforcementMode {
    /// Full `L-03` enforcement: pre-restrict high-risk/script interpreters, enforce explicit
    /// `NetworkBlock` rules, and dynamically WFP-block + suspend `GeneralUnknown` first connects.
    #[default]
    Enforce,
    /// Enforce pre-emptive restrictions (`ScriptInterpreter`, `HighRiskPath`) and explicit
    /// `NetworkBlock` rules only; record `GeneralUnknown` outbound connects as non-suspended
    /// observation alerts without WFP blocking or suspension.
    PreemptiveOnly,
    /// Audit-only mode: never install WFP block filters or suspend processes on outbound
    /// connections; record policy decisions as observation alerts only.
    Audit,
}

impl OutboundEnforcementMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::PreemptiveOnly => "preemptive-only",
            Self::Audit => "audit",
        }
    }
}

/// Configuration options for [`super::DaemonEngine`] and the Named Pipe IPC server.
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
    /// When `true`, applies a strict Named Pipe DACL when creating the IPC endpoint:
    /// - Production (`dev_mode_bypass_ui_auth == false`): applies `SERVICE_PIPE_SDDL`
    ///   (`D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)`) together with `L-09` binary verification.
    /// - Dev bypass (`dev_mode_bypass_ui_auth == true`): omits `IU` and grants `0x12019B` only
    ///   to the launching process's current user SID (failing closed to `SY`/`BA` only under
    ///   `S-1-5-18` `LocalSystem`) so other interactive accounts cannot mutate rules.
    ///
    /// The `ledr-daemon` CLI always sets this to `true` (including under `--dev-bypass-auth`)
    /// so an elevated daemon grants the launching user's non-elevated `ledr-ui.exe` and
    /// `ledr-bridge-nm.exe` `0x12019B` read/write access; `DaemonConfig::default()` keeps `false`
    /// for same-privilege unit/integration tests.
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
    /// Controls whether outbound firewall containment enforces all unknown connections
    /// (`Enforce`), only pre-emptive / explicit block targets (`PreemptiveOnly`), or
    /// records audit alerts without blocking/suspending (`Audit`). Defaults to `Enforce`.
    pub outbound_enforcement_mode: OutboundEnforcementMode,
    /// When `true` (`--foreground` or `--resume-suspended-on-shutdown`), `shutdown_and_flush`
    /// issues best-effort `resume_process` calls for unresolved suspended parent/child
    /// processes so interactive hosts are not left frozen after daemon shutdown.
    /// Production Windows Service mode leaves this `false` to preserve `L-07` containment.
    pub resume_suspended_on_shutdown: bool,
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
    /// Unconditional post-exit inclusion window (ms) for exited siblings during WFP drop
    /// attribution (`FU-E2E-05`, Plan 1B). Defaults to `1_000 ms`.
    pub wfp_drop_recent_exit_window_ms: u64,
    /// Freshness window (ms) for negative same-executable other-instance DNS disambiguation during
    /// WFP drop attribution (`FU-E2E-05`, Plan 1B). Defaults to `10_000 ms`.
    pub wfp_drop_other_instance_dns_window_ms: u64,
    /// Bounded ETW attribution settling grace window (ms) when a `WfpDropEvent` initially resolves
    /// to a single candidate with no DNS record (`FU-E2E-05`, Plan 1C). Defaults to `0 ms` in
    /// `DaemonConfig::default()` for fast deterministic tests; CLI sets `1_200 ms`.
    pub wfp_drop_attribution_grace_ms: u64,
    /// Enables lightweight OS Toolhelp32 live-sibling probing for WFP drop attribution
    /// (`FU-E2E-05`, Plan 1C). Defaults to `false` in `DaemonConfig::default()` to isolate tests
    /// from host processes; CLI sets `true`.
    pub wfp_drop_live_sibling_os_check: bool,
    /// When `true`, `WindowsBinaryInspector::inspect_cancellable` skips cold SHA-256 hashing and
    /// `WinVerifyTrust` during post-shutdown drain (`FU-E2E-05`, Plan 2B-Lightweight). Defaults to
    /// `false` in `DaemonConfig::default()` for test determinism; CLI sets `true`.
    pub shutdown_skip_cold_binary_inspect: bool,
    /// Maximum number of `(process_instance_id, IpAddr)` entries and `(exe_key, domain)` latest
    /// records retained in `ProcessDnsHistory` (`L-10`). Defaults to
    /// [`DNS_RESOLUTION_CACHE_CAPACITY`] (`4,096`). Values of `0` are clamped to `1`.
    pub dns_history_capacity: usize,
    /// When `true`, `ReportBrowserEvent` (`LAYER_4_BROWSER`) alerts also trigger an OS toast
    /// notification (`L-19`). Defaults to `false` because the browser UI already shows an overlay.
    pub notify_browser_events: bool,
    /// Maximum file byte size hashed with SHA-256 during `ReportDownloadOrigin` and Stage 2 MOTW
    /// correlation. Defaults to 128 MiB (`MAX_DOWNLOAD_HASH_BYTES`).
    pub download_hash_max_bytes: u64,
    /// Bounded wait budget (ms) for offloading synchronous `ProcessStart` MOTW I/O onto the
    /// dedicated worker pool before continuing asynchronously with late backfill (`50 ms` default).
    pub motw_sync_wait_budget_ms: u64,
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
            outbound_enforcement_mode: OutboundEnforcementMode::Enforce,
            resume_suspended_on_shutdown: false,
            preemptive_startup_executables: Vec::new(),
            nrd_refresh_enabled: false,
            nrd_refresh_interval_ms: NRD_REFRESH_INTERVAL_MS,
            nrd_cache_path: None,
            nrd_feed_urls: DEFAULT_NRD_FEED_URLS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            wfp_drop_dns_grace_ms: DEFAULT_WFP_DROP_DNS_GRACE_MS,
            wfp_drop_recent_exit_window_ms: DEFAULT_WFP_DROP_RECENT_EXIT_WINDOW_MS,
            wfp_drop_other_instance_dns_window_ms: DEFAULT_WFP_DROP_OTHER_INSTANCE_DNS_WINDOW_MS,
            wfp_drop_attribution_grace_ms: 0,
            wfp_drop_live_sibling_os_check: false,
            shutdown_skip_cold_binary_inspect: false,
            dns_history_capacity: DNS_RESOLUTION_CACHE_CAPACITY,
            notify_browser_events: false,
            download_hash_max_bytes: super::motw::MAX_DOWNLOAD_HASH_BYTES,
            motw_sync_wait_budget_ms: DEFAULT_MOTW_SYNC_WAIT_BUDGET_MS,
        }
    }
}
