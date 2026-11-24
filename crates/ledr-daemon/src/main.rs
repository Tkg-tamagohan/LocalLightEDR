//! Layer 2 LocalEDR resident core daemon (`--foreground`, `--service`, and `--service-strict` modes).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::future::Future;
use std::os::windows::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ledr_daemon::{
    service_win::{self, ServiceRunError},
    start_ipc_server, DaemonConfig, DaemonEngine, OutboundEnforcementMode, Session0ToastLauncher,
    DEFAULT_MAX_CONCURRENT_IPC_CLIENTS,
};
use ledr_proto::{
    AlertRecord, AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH, HONEYPOT_DEFAULT_FILENAME,
    IPC_PIPE_NAME, ProcessIdentity, PROGRAM_DATA_DIR, SensorBackend,
};
use ledr_rules::{
    compute_file_sha256_hex, discover_default_prerestricted_interpreters, load_rules_dir,
    LoadedRulesDir, DEFAULT_NRD_FEED_URLS,
};
use ledr_sensor_win::defense::{
    process_liveness, remove_verified_honeypot_file, HoneypotManager, ProcessLiveness,
    WindowsDefenseController,
};
use ledr_sensor_win::etw::{
    try_capture_running_processes, EventSinkFn, NoopSensorBackend, WindowsEtwSensor,
    DEFAULT_ETW_SESSION_NAME,
};
use ledr_sensor_win::privileges::enable_required_privileges;
use ledr_store::LedrStore;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    foreground: bool,
    service: bool,
    check_unresolved_suspended: bool,
    cleanup_honeypots: bool,
    dev_bypass_auth: bool,
    disable_nrd_refresh: bool,
    disable_outbound_firewall: bool,
    outbound_mode: OutboundEnforcementMode,
    resume_suspended_on_shutdown: bool,
    db_path: Option<PathBuf>,
    rules_dir: Option<PathBuf>,
    nrd_cache_path: Option<PathBuf>,
    nrd_feed_urls: Vec<String>,
    pipe_name: String,
    ui_sha256: Option<String>,
    ui_signer: Option<String>,
    ui_root_thumbprint: Option<String>,
    bridge_sha256: Option<String>,
    bridge_signer: Option<String>,
    bridge_root_thumbprint: Option<String>,
    auth_helper_sha256: Option<String>,
    show_help: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            foreground: true,
            service: false,
            check_unresolved_suspended: false,
            cleanup_honeypots: false,
            dev_bypass_auth: false,
            disable_nrd_refresh: false,
            disable_outbound_firewall: false,
            outbound_mode: OutboundEnforcementMode::Enforce,
            resume_suspended_on_shutdown: false,
            db_path: None,
            rules_dir: None,
            nrd_cache_path: None,
            nrd_feed_urls: Vec::new(),
            pipe_name: IPC_PIPE_NAME.to_string(),
            ui_sha256: None,
            ui_signer: None,
            ui_root_thumbprint: None,
            bridge_sha256: None,
            bridge_signer: None,
            bridge_root_thumbprint: None,
            auth_helper_sha256: None,
            show_help: false,
        }
    }
}

fn parse_cli_args<I, S>(args: I) -> anyhow::Result<CliArgs>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let mut parsed = CliArgs::default();
    let mut saw_foreground = false;
    let mut saw_service = false;
    let mut saw_service_strict = false;
    let mut iter = args.into_iter().map(Into::into);
    let _exe = iter.next();

    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy();
        match text.as_ref() {
            "--foreground" => {
                saw_foreground = true;
                parsed.foreground = true;
            }
            "--service" => {
                saw_service = true;
                parsed.service = true;
                parsed.foreground = false;
            }
            "--service-strict" => {
                saw_service_strict = true;
                parsed.foreground = false;
            }
            "--check-unresolved-suspended" => parsed.check_unresolved_suspended = true,
            "--cleanup-honeypots" => parsed.cleanup_honeypots = true,
            "--dev-bypass-auth" => parsed.dev_bypass_auth = true,
            "--disable-nrd-refresh" => parsed.disable_nrd_refresh = true,
            "--disable-outbound-firewall" => parsed.disable_outbound_firewall = true,
            "--resume-suspended-on-shutdown" => parsed.resume_suspended_on_shutdown = true,
            "--outbound-mode" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!(
                        "--outbound-mode requires one of: enforce, preemptive-only, audit"
                    )
                })?;
                let raw = val.to_string_lossy().trim().to_ascii_lowercase();
                parsed.outbound_mode = match raw.as_str() {
                    "enforce" => OutboundEnforcementMode::Enforce,
                    "preemptive-only" => OutboundEnforcementMode::PreemptiveOnly,
                    "audit" => OutboundEnforcementMode::Audit,
                    other => anyhow::bail!(
                        "invalid --outbound-mode '{other}' (expected enforce, preemptive-only, or audit)"
                    ),
                };
            }
            "--nrd-feed-url" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--nrd-feed-url requires a URL argument"))?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--nrd-feed-url cannot be empty");
                }
                parsed.nrd_feed_urls.push(trimmed);
            }
            "--nrd-cache" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--nrd-cache requires a file path argument"))?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--nrd-cache cannot be empty");
                }
                parsed.nrd_cache_path = Some(PathBuf::from(val));
            }
            "--db" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--db requires a file path argument"))?;
                parsed.db_path = Some(PathBuf::from(val));
            }
            "--rules" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--rules requires a directory path argument"))?;
                parsed.rules_dir = Some(PathBuf::from(val));
            }
            "--pipe" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--pipe requires a Named Pipe path argument"))?;
                parsed.pipe_name = val.to_string_lossy().into_owned();
            }
            "--ui-sha256" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--ui-sha256 requires a SHA-256 hex argument"))?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--ui-sha256 cannot be empty");
                }
                parsed.ui_sha256 = Some(trimmed);
            }
            "--ui-signer" => {
                let val = iter
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--ui-signer requires a signer subject argument"))?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--ui-signer cannot be empty");
                }
                parsed.ui_signer = Some(trimmed);
            }
            "--ui-root-thumbprint" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--ui-root-thumbprint requires a thumbprint hex argument")
                })?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--ui-root-thumbprint cannot be empty");
                }
                parsed.ui_root_thumbprint = Some(trimmed);
            }
            "--bridge-sha256" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--bridge-sha256 requires a SHA-256 hex argument")
                })?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--bridge-sha256 cannot be empty");
                }
                parsed.bridge_sha256 = Some(trimmed);
            }
            "--bridge-signer" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--bridge-signer requires a signer subject argument")
                })?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--bridge-signer cannot be empty");
                }
                parsed.bridge_signer = Some(trimmed);
            }
            "--bridge-root-thumbprint" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--bridge-root-thumbprint requires a thumbprint hex argument")
                })?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.is_empty() {
                    anyhow::bail!("--bridge-root-thumbprint cannot be empty");
                }
                parsed.bridge_root_thumbprint = Some(trimmed);
            }
            "--auth-helper-sha256" => {
                let val = iter.next().ok_or_else(|| {
                    anyhow::anyhow!("--auth-helper-sha256 requires a SHA-256 hex argument")
                })?;
                let trimmed = val.to_string_lossy().trim().to_string();
                if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                    anyhow::bail!("--auth-helper-sha256 requires exactly 64 hexadecimal digits");
                }
                parsed.auth_helper_sha256 = Some(trimmed);
            }
            "--help" | "-h" => parsed.show_help = true,
            other => anyhow::bail!("unrecognized argument: {other}"),
        }
    }

    if saw_foreground && saw_service {
        anyhow::bail!("--service cannot be combined with --foreground");
    }
    if parsed.check_unresolved_suspended && (saw_foreground || saw_service || saw_service_strict) {
        anyhow::bail!(
            "--check-unresolved-suspended cannot be combined with --foreground, --service, or --service-strict"
        );
    }
    if parsed.cleanup_honeypots
        && (saw_foreground || saw_service || saw_service_strict || parsed.check_unresolved_suspended)
    {
        anyhow::bail!(
            "--cleanup-honeypots cannot be combined with --foreground, --service, --service-strict, or --check-unresolved-suspended"
        );
    }

    // `--ui-signer` without `--ui-root-thumbprint` can never verify: the caller check
    // requires the signer/root-thumbprint pair and would reject every mutating IPC
    // command at runtime. Fail fast at startup instead (BUG_0007). Under
    // `--dev-bypass-auth` no authorization runs at all, so the pair is not required.
    if !parsed.dev_bypass_auth && parsed.ui_signer.is_some() && parsed.ui_root_thumbprint.is_none() {
        anyhow::bail!("--ui-signer requires --ui-root-thumbprint");
    }
    if !parsed.dev_bypass_auth
        && parsed.bridge_signer.is_some()
        && parsed.bridge_root_thumbprint.is_none()
    {
        anyhow::bail!("--bridge-signer requires --bridge-root-thumbprint");
    }

    Ok(parsed)
}

fn resolve_existing_sha256(candidates: &[&Path]) -> Option<String> {
    for path in candidates {
        if path.is_file() {
            match compute_file_sha256_hex(path) {
                Ok(hash) => return Some(hash),
                Err(err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %err,
                        "failed to compute SHA-256 for authorized IPC binary"
                    );
                }
            }
        }
    }
    None
}

fn open_store_with_fallback(explicit_db: Option<&Path>) -> anyhow::Result<(LedrStore, PathBuf)> {
    if let Some(path) = explicit_db {
        let store = LedrStore::open(path)?;
        return Ok((store, path.to_path_buf()));
    }

    let primary = PathBuf::from(PROGRAM_DATA_DIR).join("localedr.db");
    match LedrStore::open(&primary) {
        Ok(store) => Ok((store, primary)),
        Err(primary_err) => {
            let fallback_dir = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join("LocalEDR");
            let fallback = fallback_dir.join("localedr.db");
            tracing::warn!(
                primary = %primary.display(),
                fallback = %fallback.display(),
                error = %primary_err,
                "could not open ProgramData store; falling back to local user directory"
            );
            let store = LedrStore::open(&fallback)?;
            Ok((store, fallback))
        }
    }
}

fn load_rules_or_default(explicit_dir: Option<&Path>) -> anyhow::Result<LoadedRulesDir> {
    if let Some(dir) = explicit_dir {
        let loaded = load_rules_dir(dir)?;
        return Ok(loaded);
    }

    let candidates = [
        PathBuf::from("rules"),
        PathBuf::from(PROGRAM_DATA_DIR).join("rules"),
    ];
    for dir in candidates {
        if dir.is_dir() {
            match load_rules_dir(&dir) {
                Ok(loaded) => {
                    tracing::info!(rules_dir = %dir.display(), "loaded Sigma rules and allowlists");
                    return Ok(loaded);
                }
                Err(err) => {
                    tracing::warn!(rules_dir = %dir.display(), error = %err, "failed loading rules directory");
                }
            }
        }
    }

    tracing::warn!("no rules directory found; running with empty Sigma rules and default EarlyPruner");
    Ok(LoadedRulesDir::default())
}

fn apply_startup_rules(store: &LedrStore, loaded: &LoadedRulesDir) {
    match store.seed_default_rules_once(&loaded.default_allowlists) {
        Ok(seeded) => {
            if seeded > 0 {
                tracing::info!(
                    seeded,
                    total = loaded.default_allowlists.len(),
                    "seeded default allowlist rules"
                );
            }
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed seeding default allowlist rules");
        }
    }

    let mut upserted = 0usize;
    for rule in &loaded.managed_rules {
        match store.upsert_rule(rule) {
            Ok(()) => upserted += 1,
            Err(err) => {
                tracing::warn!(
                    rule_id = %rule.rule_id,
                    error = %err,
                    "failed applying operator-managed rule"
                );
            }
        }
    }
    if upserted > 0 {
        tracing::info!(
            upserted,
            total = loaded.managed_rules.len(),
            "applied operator-managed policy rules"
        );
    }
}

fn resolve_ui_exe_path(foreground: bool, dev_bypass_auth: bool) -> PathBuf {
    let current_exe = std::env::current_exe().ok();
    resolve_ui_exe_path_from(current_exe.as_deref(), foreground, dev_bypass_auth)
}

fn resolve_ui_exe_path_from(
    current_exe: Option<&Path>,
    foreground: bool,
    dev_bypass_auth: bool,
) -> PathBuf {
    if !foreground || !dev_bypass_auth {
        return PathBuf::from(AUTHORIZED_UI_EXE_PATH);
    }
    if let Some(dir) = current_exe.and_then(Path::parent) {
        let sibling = dir.join("ledr-ui.exe");
        if sibling.is_file() {
            return sibling;
        }
    }
    PathBuf::from(AUTHORIZED_UI_EXE_PATH)
}

const DAEMON_TOKIO_WORKER_THREADS: usize = 2;
const DAEMON_TOKIO_MAX_BLOCKING_THREADS: usize = DEFAULT_MAX_CONCURRENT_IPC_CLIENTS + 4;
const DAEMON_TOKIO_BLOCKING_KEEP_ALIVE_SECS: u64 = 10;

fn build_daemon_runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(DAEMON_TOKIO_WORKER_THREADS)
        .max_blocking_threads(DAEMON_TOKIO_MAX_BLOCKING_THREADS)
        .thread_keep_alive(Duration::from_secs(DAEMON_TOKIO_BLOCKING_KEEP_ALIVE_SECS))
        .thread_name("ledr-tokio")
        .enable_all()
        .build()
        .context("failed to build Tokio runtime for ledr-daemon")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn run_service_mode(cli: CliArgs) -> Result<(), ServiceRunError> {
    service_win::run_windows_service(move |control| {
        let mut shutdown_rx = control.shutdown_receiver();
        let runtime = build_daemon_runtime()?;
        let result = runtime.block_on(run_daemon_until(
            cli,
            move || control.mark_running(),
            async move {
                let _ = shutdown_rx.wait_for(|&stopped| stopped).await;
                Ok(())
            },
        ));
        // Drop the Tokio runtime inside the service entrypoint before returning
        // so all worker/blocking threads unwind prior to reporting SERVICE_STOPPED.
        drop(runtime);
        result
    })
}

const UNRESOLVED_SUSPENDED_EXIT_CODE: u8 = 3;
const HONEYPOT_CLEANUP_PARTIAL_EXIT_CODE: u8 = 4;
const FILE_ATTRIBUTE_REPARSE_POINT_MASK: u32 = 0x0000_0400;
const HONEYPOT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

fn default_daemon_db_path() -> PathBuf {
    PathBuf::from(PROGRAM_DATA_DIR).join("localedr.db")
}

fn parse_pid_from_instance_id(instance_id: &str) -> Option<u32> {
    ProcessIdentity::from_instance_id(instance_id)
        .map(|id| id.pid)
        .or_else(|| {
            instance_id
                .trim()
                .split(':')
                .next()
                .and_then(|pid_part| pid_part.trim().parse::<u32>().ok())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveTargetState {
    Running { create_time_100ns: Option<u64> },
    Gone,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetLivenessCheck {
    /// Target is positively confirmed `Gone` or `CreationTime`-mismatched (PID reused).
    Excluded,
    /// Target is live with matching identity, or its absence/mismatch cannot be confirmed.
    Block(Option<u32>),
}

struct OwnedProcessHandle(windows::Win32::Foundation::HANDLE);

impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: `self.0` is an owned Win32 process handle obtained from `OpenProcess`.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
        }
    }
}

fn open_verified_process_handle(
    pid: u32,
    access: windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS,
) -> Result<OwnedProcessHandle, Option<windows::core::Error>> {
    use windows::Win32::System::Threading::{GetProcessId, OpenProcess};

    // SAFETY: `OpenProcess` takes integer flags and PID; non-null handles are RAII-closed.
    let raw = unsafe { OpenProcess(access, false, pid) }.map_err(Some)?;
    if raw.is_invalid() || raw.0.is_null() {
        return Err(None);
    }
    let handle = OwnedProcessHandle(raw);
    // Reject handles opened via Windows' low-2-bit PID masking (`pid & !3`).
    // SAFETY: `handle.0` is an open process handle with `PROCESS_QUERY_LIMITED_INFORMATION`.
    let actual_pid = unsafe { GetProcessId(handle.0) };
    if actual_pid != pid {
        return Err(None);
    }
    Ok(handle)
}

fn query_process_creation_time_100ns(handle: windows::Win32::Foundation::HANDLE) -> Option<u64> {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::GetProcessTimes;

    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` structs are valid.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.ok()?;
    let create_time_100ns =
        ((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64);
    (create_time_100ns != 0).then_some(create_time_100ns)
}

fn try_probe_live_target_fast(pid: u32) -> Option<LiveTargetState> {
    use windows::Win32::Foundation::{
        ERROR_ACCESS_DENIED, STILL_ACTIVE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    };

    match open_verified_process_handle(pid, PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)
    {
        Ok(handle) => {
            // Non-blocking 0ms check: `WAIT_OBJECT_0` positively confirms kernel process exit
            // (including exited zombie processes whose handles are still open elsewhere);
            // `WAIT_TIMEOUT` confirms the process object is unsignaled (genuinely running).
            // SAFETY: `handle.0` was opened with `PROCESS_SYNCHRONIZE`.
            let wait_status = unsafe { WaitForSingleObject(handle.0, 0) };
            if wait_status == WAIT_OBJECT_0 {
                return Some(LiveTargetState::Gone);
            }
            if wait_status == WAIT_TIMEOUT {
                if let Some(create_time_100ns) = query_process_creation_time_100ns(handle.0) {
                    return Some(LiveTargetState::Running {
                        create_time_100ns: Some(create_time_100ns),
                    });
                }
            }
            None
        }
        Err(Some(err)) if err.code() == ERROR_ACCESS_DENIED.to_hresult() => {
            let handle =
                open_verified_process_handle(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
            let mut exit_code = 0u32;
            // SAFETY: `handle.0` was opened with `PROCESS_QUERY_LIMITED_INFORMATION`.
            unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.ok()?;
            if exit_code != STILL_ACTIVE.0 as u32 {
                return Some(LiveTargetState::Gone);
            }
            query_process_creation_time_100ns(handle.0).map(|create_time_100ns| {
                LiveTargetState::Running {
                    create_time_100ns: Some(create_time_100ns),
                }
            })
        }
        Err(_) => None,
    }
}

fn probe_live_target_os(pid: u32) -> LiveTargetState {
    if pid == 0 {
        return LiveTargetState::Running {
            create_time_100ns: None,
        };
    }
    if let Some(state) = try_probe_live_target_fast(pid) {
        return state;
    }
    // Fall back to `process_liveness` when the fast handle probe cannot determine state
    // (e.g., PID no longer exists, protected process denied `OpenProcess`, or `CreationTime`
    // could not be read), preserving fail-closed `Unknown` and `Running { create_time_100ns: None }`
    // invariants (`PRG-002`, `PRG-007`).
    match process_liveness(pid) {
        ProcessLiveness::Gone => LiveTargetState::Gone,
        ProcessLiveness::Unknown => LiveTargetState::Unknown,
        ProcessLiveness::Running => LiveTargetState::Running {
            create_time_100ns: None,
        },
    }
}

fn probe_pid_memoized(
    pid: u32,
    probe_cache: &mut HashMap<u32, LiveTargetState>,
    probe: &dyn Fn(u32) -> LiveTargetState,
) -> LiveTargetState {
    if pid == 0 {
        return LiveTargetState::Running {
            create_time_100ns: None,
        };
    }
    if let Some(&cached) = probe_cache.get(&pid) {
        return cached;
    }
    let state = probe(pid);
    probe_cache.insert(pid, state);
    state
}

fn check_suspended_target_liveness(
    raw_instance_id: &str,
    probe_cache: &mut HashMap<u32, LiveTargetState>,
    probe: &dyn Fn(u32) -> LiveTargetState,
) -> TargetLivenessCheck {
    let trimmed = raw_instance_id.trim();
    if let Some(ident) = ProcessIdentity::from_instance_id(trimmed) {
        if ident.pid == 0 {
            return TargetLivenessCheck::Block(None);
        }
        if ident.create_time_100ns == 0 {
            return match probe_pid_memoized(ident.pid, probe_cache, probe) {
                LiveTargetState::Gone => TargetLivenessCheck::Excluded,
                LiveTargetState::Unknown | LiveTargetState::Running { .. } => {
                    TargetLivenessCheck::Block(Some(ident.pid))
                }
            };
        }
        return match probe_pid_memoized(ident.pid, probe_cache, probe) {
            LiveTargetState::Gone => TargetLivenessCheck::Excluded,
            LiveTargetState::Unknown => TargetLivenessCheck::Block(Some(ident.pid)),
            LiveTargetState::Running {
                create_time_100ns: Some(actual_ct),
            } if actual_ct != ident.create_time_100ns => TargetLivenessCheck::Excluded,
            LiveTargetState::Running { .. } => TargetLivenessCheck::Block(Some(ident.pid)),
        };
    }

    if let Some(pid) = parse_pid_from_instance_id(trimmed).filter(|&p| p > 0) {
        return match probe_pid_memoized(pid, probe_cache, probe) {
            LiveTargetState::Gone => TargetLivenessCheck::Excluded,
            LiveTargetState::Unknown | LiveTargetState::Running { .. } => {
                TargetLivenessCheck::Block(Some(pid))
            }
        };
    }
    TargetLivenessCheck::Block(None)
}

fn collect_live_unresolved_suspended_alerts(
    alerts: &[AlertRecord],
    probe: &dyn Fn(u32) -> LiveTargetState,
) -> (usize, BTreeSet<u32>) {
    let mut live_alerts = 0usize;
    let mut live_pids = BTreeSet::new();
    let mut probe_cache: HashMap<u32, LiveTargetState> = HashMap::new();

    for alert in alerts {
        let mut alert_blocked = false;
        if alert.process_suspended {
            match alert.process_instance_id.as_deref() {
                Some(inst) => {
                    match check_suspended_target_liveness(inst, &mut probe_cache, probe) {
                        TargetLivenessCheck::Excluded => {}
                        TargetLivenessCheck::Block(maybe_pid) => {
                            alert_blocked = true;
                            if let Some(pid) = maybe_pid {
                                live_pids.insert(pid);
                            }
                        }
                    }
                }
                None => {
                    alert_blocked = true;
                }
            }
        }

        match serde_json::from_str::<serde_json::Value>(&alert.context_json) {
            Ok(ctx) => match ctx.get("suspended_children") {
                Some(children_val) => {
                    if let Some(children) = children_val.as_array() {
                        for item in children {
                            if let Some(raw_id) = item.as_str() {
                                match check_suspended_target_liveness(
                                    raw_id,
                                    &mut probe_cache,
                                    probe,
                                ) {
                                    TargetLivenessCheck::Excluded => {}
                                    TargetLivenessCheck::Block(maybe_pid) => {
                                        alert_blocked = true;
                                        if let Some(pid) = maybe_pid {
                                            live_pids.insert(pid);
                                        }
                                    }
                                }
                            } else {
                                alert_blocked = true;
                            }
                        }
                    } else if !children_val.is_null() && !alert.process_suspended {
                        alert_blocked = true;
                    }
                }
                None if !alert.process_suspended => {
                    alert_blocked = true;
                }
                None => {}
            },
            Err(_) if !alert.process_suspended => {
                alert_blocked = true;
            }
            Err(_) => {}
        }

        if alert_blocked {
            live_alerts += 1;
        }
    }

    (live_alerts, live_pids)
}

fn check_unresolved_suspended_in_db(explicit_db: Option<&Path>) -> u8 {
    check_unresolved_suspended_in_db_with_probe(explicit_db, &probe_live_target_os)
}

fn check_unresolved_suspended_in_db_with_probe(
    explicit_db: Option<&Path>,
    probe: &dyn Fn(u32) -> LiveTargetState,
) -> u8 {
    let db_path = explicit_db
        .map(Path::to_path_buf)
        .unwrap_or_else(default_daemon_db_path);

    match std::fs::symlink_metadata(&db_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return 0,
        Err(err) => {
            eprintln!(
                "Error: failed inspecting LocalEDR database '{}': {err}",
                db_path.display()
            );
            return 1;
        }
        Ok(meta) if meta.is_dir() => {
            eprintln!(
                "Error: LocalEDR database path '{}' is a directory",
                db_path.display()
            );
            return 1;
        }
        Ok(_) => {}
    }

    let alerts = match LedrStore::list_unresolved_suspended_alerts_read_only(&db_path) {
        Ok(alerts) => alerts,
        Err(err) => {
            eprintln!(
                "Error: failed querying unresolved suspended alerts in '{}': {err}",
                db_path.display()
            );
            return 1;
        }
    };

    if alerts.is_empty() {
        return 0;
    }

    let (live_alerts, pids) = collect_live_unresolved_suspended_alerts(&alerts, probe);
    if live_alerts == 0 {
        return 0;
    }

    let pid_summary = if pids.is_empty() {
        "unknown".to_string()
    } else {
        pids.iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    eprintln!(
        "Blocked uninstall: {} unresolved suspended alert(s) found in '{}' (suspended PIDs: {}). Resolve all pending alerts in the LocalEDR UI before uninstalling.",
        live_alerts,
        db_path.display(),
        pid_summary
    );
    UNRESOLVED_SUSPENDED_EXIT_CODE
}

#[derive(Debug, Default, PartialEq, Eq)]
struct HoneypotCleanupOutcome {
    removed: usize,
    already_absent: usize,
    failed: usize,
    db_records_removed: usize,
    failed_details: Vec<String>,
}

fn normalize_honeypot_dedup_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn push_unique_honeypot_path(
    seen: &mut HashSet<String>,
    out: &mut Vec<PathBuf>,
    path: PathBuf,
) {
    let key = normalize_honeypot_dedup_key(&path);
    if !key.is_empty() && seen.insert(key) {
        out.push(path);
    }
}

fn collect_fallback_honeypot_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = HoneypotManager::for_service()
        .roots()
        .iter()
        .map(|root| root.join(HONEYPOT_DEFAULT_FILENAME))
        .collect();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let lower = profile.to_string_lossy().to_ascii_lowercase();
        if !lower.contains(r"\system32\config\systemprofile")
            && !lower.contains(r"\serviceprofiles\localservice")
            && !lower.contains(r"\serviceprofiles\networkservice")
        {
            let base = PathBuf::from(profile);
            for sub in ["Documents", "Desktop", "Pictures"] {
                paths.push(base.join(sub).join(HONEYPOT_DEFAULT_FILENAME));
            }
        }
    }
    paths
}

fn current_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn record_honeypots_best_effort(store: &LedrStore, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    if let Err(err) = store.record_honeypot_paths(paths, current_epoch_ms()) {
        tracing::warn!(
            error = %err,
            honeypots = paths.len(),
            "failed recording deployed honeypot paths in SQLite"
        );
    }
}

fn cleanup_honeypots_with_db_and_fallback(
    db_path: &Path,
    fallback_paths: &[PathBuf],
) -> HoneypotCleanupOutcome {
    let mut outcome = HoneypotCleanupOutcome::default();
    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let mut tracked_keys = HashSet::new();
    let mut db_readable = false;

    match std::fs::symlink_metadata(db_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            outcome.failed += 1;
            outcome.failed_details.push(format!(
                "failed inspecting LocalEDR database '{}': {err}",
                db_path.display()
            ));
        }
        Ok(meta) if meta.is_dir() => {
            outcome.failed += 1;
            outcome.failed_details.push(format!(
                "LocalEDR database path '{}' is a directory",
                db_path.display()
            ));
        }
        Ok(meta) if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_MASK) != 0 => {
            outcome.failed += 1;
            outcome.failed_details.push(format!(
                "refusing reparse point LocalEDR database '{}'",
                db_path.display()
            ));
        }
        Ok(_) => match LedrStore::list_tracked_honeypot_paths_read_only(db_path) {
            Ok(paths) => {
                db_readable = true;
                for path in paths {
                    let key = normalize_honeypot_dedup_key(&path);
                    if !key.is_empty() {
                        tracked_keys.insert(key);
                    }
                    push_unique_honeypot_path(&mut seen, &mut targets, path);
                }
            }
            Err(err) => {
                outcome.failed += 1;
                outcome.failed_details.push(format!(
                    "failed reading tracked honeypots from '{}': {err}",
                    db_path.display()
                ));
            }
        },
    }

    for path in fallback_paths {
        push_unique_honeypot_path(&mut seen, &mut targets, path.clone());
    }

    let mut cleaned_tracked_paths = Vec::new();
    for path in targets {
        match remove_verified_honeypot_file(&path) {
            Ok(true) => {
                outcome.removed += 1;
                if tracked_keys.contains(&normalize_honeypot_dedup_key(&path)) {
                    cleaned_tracked_paths.push(path);
                }
            }
            Ok(false) => {
                outcome.already_absent += 1;
                if tracked_keys.contains(&normalize_honeypot_dedup_key(&path)) {
                    cleaned_tracked_paths.push(path);
                }
            }
            Err(err) => {
                outcome.failed += 1;
                outcome
                    .failed_details
                    .push(format!("{}: {err}", path.display()));
            }
        }
    }

    if db_readable && !cleaned_tracked_paths.is_empty() {
        match LedrStore::open(db_path) {
            Ok(store) => {
                match store.remove_tracked_honeypot_paths(&cleaned_tracked_paths) {
                    Ok(removed_rows) => {
                        outcome.db_records_removed = removed_rows;
                    }
                    Err(err) => {
                        outcome.failed += 1;
                        outcome.failed_details.push(format!(
                            "failed removing tracked honeypot rows in '{}': {err}",
                            db_path.display()
                        ));
                    }
                }
                if let Err(err) = store.checkpoint_truncate() {
                    outcome.failed += 1;
                    outcome.failed_details.push(format!(
                        "failed checkpointing WAL for '{}': {err}",
                        db_path.display()
                    ));
                }
            }
            Err(err) => {
                outcome.failed += 1;
                outcome.failed_details.push(format!(
                    "failed opening LocalEDR database '{}' for honeypot cleanup: {err}",
                    db_path.display()
                ));
            }
        }
    }

    outcome
}

fn cleanup_honeypots_in_db(explicit_db: Option<&Path>) -> u8 {
    let db_path = explicit_db
        .map(Path::to_path_buf)
        .unwrap_or_else(default_daemon_db_path);
    let fallback_paths = collect_fallback_honeypot_paths();
    let outcome = cleanup_honeypots_with_db_and_fallback(&db_path, &fallback_paths);

    println!(
        "Honeypot cleanup summary (db='{}'): removed={}, already_absent={}, db_records_removed={}, failed={}",
        db_path.display(),
        outcome.removed,
        outcome.already_absent,
        outcome.db_records_removed,
        outcome.failed
    );
    for detail in &outcome.failed_details {
        eprintln!("Honeypot cleanup failure: {detail}");
    }
    if outcome.failed == 0 {
        0
    } else {
        HONEYPOT_CLEANUP_PARTIAL_EXIT_CODE
    }
}

fn run_cli_entrypoint_code<I, S>(args: I) -> u8
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let cli = match parse_cli_args(args) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("Error: {err:#}");
            return 1;
        }
    };

    if cli.show_help {
        println!(
            "ledr-daemon [--foreground | --service | --service-strict | --check-unresolved-suspended | --cleanup-honeypots] [--dev-bypass-auth] [--outbound-mode <enforce|preemptive-only|audit>] [--disable-outbound-firewall] [--resume-suspended-on-shutdown] [--disable-nrd-refresh] [--nrd-feed-url <url>] [--nrd-cache <path>] [--db <path>] [--rules <dir>] [--pipe <name>] [--ui-sha256 <hex>] [--ui-signer <dn>] [--ui-root-thumbprint <sha1>] [--bridge-sha256 <hex>] [--bridge-signer <dn>] [--bridge-root-thumbprint <sha1>] [--auth-helper-sha256 <hex>]"
        );
        return 0;
    }

    if cli.check_unresolved_suspended {
        return check_unresolved_suspended_in_db(cli.db_path.as_deref());
    }

    if cli.cleanup_honeypots {
        return cleanup_honeypots_in_db(cli.db_path.as_deref());
    }

    init_tracing();

    if cli.service {
        return match run_service_mode(cli) {
            Ok(()) => 0,
            Err(ServiceRunError::NotStartedByScm) => {
                eprintln!(
                    "ledr-daemon --service must be started by the Windows Service Control Manager (error 1063: ERROR_FAILED_SERVICE_CONTROLLER_CONNECT). Run with --foreground for interactive console execution."
                );
                service_win::NON_SCM_EXIT_CODE
            }
            Err(err) => {
                eprintln!("Error: {err}");
                1
            }
        };
    }

    let runtime = match build_daemon_runtime() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("Error: {err:#}");
            return 1;
        }
    };

    match runtime.block_on(run_daemon_until(cli, || {}, async {
        tokio::signal::ctrl_c().await.map_err(anyhow::Error::from)
    })) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("Error: {err:#}");
            1
        }
    }
}

fn main() -> ExitCode {
    ExitCode::from(run_cli_entrypoint_code(std::env::args_os()))
}

/// Builds the [`DaemonConfig`] for `ledr-daemon` CLI execution.
///
/// Always enables `strict_pipe_dacl` even when `--dev-bypass-auth` is set:
/// - Production (`--dev-bypass-auth` unset): applies `SERVICE_PIPE_SDDL` (`SY`, `BA`, `IU`)
///   alongside `L-09` caller binary verification.
/// - Dev bypass (`--dev-bypass-auth` set): restricts `0x12019B` read/write access to the
///   launching user's current SID (without `IU`, failing closed to `SY`/`BA` under `S-1-5-18`)
///   so non-elevated `ledr-ui.exe` / `ledr-bridge-nm.exe` running as the same user can connect
///   across UAC elevation boundaries while blocking other interactive accounts.
fn build_daemon_config(
    cli: &CliArgs,
    authorized_ui_sha256: Option<String>,
    authorized_bridge_sha256: Option<String>,
    nrd_cache_path: Option<PathBuf>,
    nrd_feed_urls: Vec<String>,
    preemptive_startup_executables: Vec<String>,
) -> DaemonConfig {
    let outbound_firewall_enabled = !cli.disable_outbound_firewall;
    let resume_suspended_on_shutdown = cli.resume_suspended_on_shutdown || cli.foreground;
    DaemonConfig {
        pipe_name: cli.pipe_name.clone(),
        dev_mode_bypass_ui_auth: cli.dev_bypass_auth,
        strict_pipe_dacl: true,
        authorized_ui_sha256,
        authorized_ui_signer: cli.ui_signer.clone(),
        authorized_ui_root_thumbprint: cli.ui_root_thumbprint.clone(),
        authorized_bridge_sha256,
        authorized_bridge_signer: cli.bridge_signer.clone(),
        authorized_bridge_root_thumbprint: cli.bridge_root_thumbprint.clone(),
        auth_helper_sha256: cli.auth_helper_sha256.clone(),
        outbound_firewall_enabled,
        outbound_enforcement_mode: cli.outbound_mode,
        resume_suspended_on_shutdown,
        preemptive_startup_executables,
        nrd_refresh_enabled: !cli.disable_nrd_refresh,
        nrd_cache_path,
        nrd_feed_urls,
        wfp_drop_attribution_grace_ms: 1_200,
        wfp_drop_live_sibling_os_check: true,
        shutdown_skip_cold_binary_inspect: true,
        ..DaemonConfig::default()
    }
}

enum ActiveSensorBackend {
    Etw(Box<WindowsEtwSensor>),
    Noop(NoopSensorBackend),
}

impl ActiveSensorBackend {
    fn set_honeypot_paths(&mut self, paths: Vec<PathBuf>) {
        if let Self::Etw(sensor) = self {
            sensor.set_honeypot_paths(paths);
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        match self {
            Self::Etw(sensor) => sensor.stop(),
            Self::Noop(noop) => noop.stop(),
        }
    }
}

fn apply_honeypot_refresh_if_changed(
    last_paths: &mut Vec<PathBuf>,
    updated_paths: Vec<PathBuf>,
    apply_fn: impl FnOnce(Vec<PathBuf>),
) -> bool {
    if HoneypotManager::path_sets_equal(last_paths, &updated_paths) {
        return false;
    }
    apply_fn(updated_paths.clone());
    *last_paths = updated_paths;
    true
}

async fn run_daemon_until<FReady, FWait>(
    cli: CliArgs,
    on_ready: FReady,
    shutdown_signal: FWait,
) -> anyhow::Result<()>
where
    FReady: FnOnce(),
    FWait: Future<Output = anyhow::Result<()>>,
{
    init_tracing();

    let priv_report = enable_required_privileges();
    tracing::info!(
        system_profile = priv_report.system_profile,
        debug = priv_report.debug,
        security = priv_report.security,
        error = ?priv_report.error_message,
        "privilege enablement completed"
    );

    let (store, db_path) = open_store_with_fallback(cli.db_path.as_deref())?;
    let honeypot_store = store.clone();
    let loaded_rules = load_rules_or_default(cli.rules_dir.as_deref())?;
    apply_startup_rules(&store, &loaded_rules);
    let LoadedRulesDir {
        sigma,
        pruner,
        ..
    } = loaded_rules;
    let rule_count = sigma.rule_count();

    let ui_exe = resolve_ui_exe_path(cli.foreground, cli.dev_bypass_auth);
    let authorized_ui_sha256 = cli.ui_sha256.clone().or_else(|| {
        if cli.ui_signer.is_some() {
            None
        } else if cli.foreground && cli.dev_bypass_auth {
            resolve_existing_sha256(&[Path::new(AUTHORIZED_UI_EXE_PATH), ui_exe.as_path()])
        } else {
            resolve_existing_sha256(&[Path::new(AUTHORIZED_UI_EXE_PATH)])
        }
    });
    let authorized_bridge_sha256 = cli.bridge_sha256.clone().or_else(|| {
        if cli.bridge_signer.is_some() {
            None
        } else {
            resolve_existing_sha256(&[Path::new(AUTHORIZED_BRIDGE_EXE_PATH)])
        }
    });

    let nrd_cache_path = cli.nrd_cache_path.clone().or_else(|| {
        db_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|dir| dir.join("nrd-cache.txt"))
    });
    let nrd_feed_urls = if cli.nrd_feed_urls.is_empty() {
        DEFAULT_NRD_FEED_URLS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    } else {
        cli.nrd_feed_urls.clone()
    };

    let outbound_firewall_enabled = !cli.disable_outbound_firewall;
    let defense_controller = Arc::new(WindowsDefenseController::new());
    if outbound_firewall_enabled && cli.outbound_mode != OutboundEnforcementMode::Audit {
        if let Err(err) = defense_controller.init_wfp_session() {
            tracing::warn!(
                error = %err,
                "WFP dynamic session could not be initialized (non-elevated session?); outbound WFP filtering will retry on demand"
            );
        }
    }

    let preemptive_startup_executables =
        if outbound_firewall_enabled && cli.outbound_mode != OutboundEnforcementMode::Audit {
            discover_default_prerestricted_interpreters()
        } else {
            Vec::new()
        };
    let config = build_daemon_config(
        &cli,
        authorized_ui_sha256,
        authorized_bridge_sha256,
        nrd_cache_path,
        nrd_feed_urls,
        preemptive_startup_executables,
    );
    let wfp_defense = Arc::clone(&defense_controller);
    let attach_wfp_drop_sink =
        config.outbound_firewall_enabled && config.outbound_enforcement_mode != OutboundEnforcementMode::Audit;
    let engine = DaemonEngine::start_with_controllers(
        store,
        sigma,
        pruner,
        config,
        defense_controller,
        Arc::new(Session0ToastLauncher::with_foreground_fallback(
            ui_exe,
            cli.foreground,
        )),
    );
    if attach_wfp_drop_sink {
        if let Err(err) = wfp_defense.set_wfp_drop_sink(engine.wfp_drop_sink()) {
            tracing::warn!(
                error = %err,
                "WFP net-event drop sink could not be attached (non-elevated session?); continuing without WFP drop capture"
            );
        }
    }

    let mut honeypot_mgr = if cli.foreground {
        HoneypotManager::new()
    } else {
        HoneypotManager::for_service()
    };
    let mut last_honeypot_paths = match honeypot_mgr.deploy_honeypots() {
        Ok(paths) => {
            tracing::info!(
                honeypots = paths.len(),
                service_mode = !cli.foreground,
                "deployed honeypot canary files"
            );
            honeypot_mgr.deployed_paths().to_vec()
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed deploying one or more honeypot canary files; continuing with partial list"
            );
            honeypot_mgr.deployed_paths().to_vec()
        }
    };
    record_honeypots_best_effort(&honeypot_store, &last_honeypot_paths);

    // Start ETW capture directly into ClassifiedEventSender BEFORE Toolhelp32 snapshot capture so
    // processes spawned or exiting during snapshot enumeration are not missed (BUG_0001, BUG_0006, L-10).
    let bridge_sender = engine.classified_sender();
    let etw_sink: EventSinkFn = Arc::new(move |ev| bridge_sender.blocking_send(ev).is_ok());
    let mut etw_sensor = WindowsEtwSensor::with_sink(etw_sink, DEFAULT_ETW_SESSION_NAME);
    etw_sensor.set_honeypot_paths(last_honeypot_paths.clone());
    let mut active_backend = match etw_sensor.start() {
        Ok(()) => {
            tracing::info!("WindowsEtwSensor real-time ETW trace started");
            ActiveSensorBackend::Etw(Box::new(etw_sensor))
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "WindowsEtwSensor could not start (non-elevated session?); falling back to NoopSensorBackend"
            );
            drop(etw_sensor);
            let mut noop = NoopSensorBackend;
            let _ = noop.start();
            ActiveSensorBackend::Noop(noop)
        }
    };

    let seeded_count = match try_capture_running_processes() {
        Ok(initial_processes) => engine.seed_processes(initial_processes)?,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "initial running-process snapshot failed; skipping process seeding and stale reconciliation"
            );
            0
        }
    };
    let wfp_report = engine.deploy_persisted_network_rules();
    tracing::info!(
        seeded_processes = seeded_count,
        sigma_rules = rule_count,
        wfp_applied = wfp_report.applied,
        wfp_failed = wfp_report.failed,
        nrd_entries = engine.nrd_entry_count(),
        db = %db_path.display(),
        "initialized ActiveProcessTable, WFP firewall rules, and SQLite WAL store"
    );

    let ipc_handle = start_ipc_server(Arc::clone(&engine))?;
    on_ready();
    tracing::info!(
        pipe = %ipc_handle.pipe_name(),
        foreground = cli.foreground,
        service = cli.service,
        "ledr-daemon listening on Named Pipe IPC"
    );

    if cli.foreground {
        shutdown_signal.await?;
    } else {
        let mut honeypot_mgr_opt = Some(honeypot_mgr);
        let mut refresh_ticker = tokio::time::interval(HONEYPOT_REFRESH_INTERVAL);
        refresh_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume immediate t=0 tick; startup deployment just ran above.
        refresh_ticker.tick().await;
        tokio::pin!(shutdown_signal);
        let mut refresh_in_flight: Option<
            tokio::task::JoinHandle<(HoneypotManager, Result<bool, ledr_sensor_win::SensorError>)>,
        > = None;

        loop {
            tokio::select! {
                res = &mut shutdown_signal => {
                    res?;
                    break;
                }
                done = async {
                    match refresh_in_flight.as_mut() {
                        Some(handle) => handle.await,
                        None => std::future::pending().await,
                    }
                }, if refresh_in_flight.is_some() => {
                    refresh_in_flight = None;
                    match done {
                        Ok((mgr, refresh_res)) => {
                            if let Err(err) = &refresh_res {
                                tracing::warn!(
                                    error = %err,
                                    "periodic service honeypot refresh encountered an error"
                                );
                            }
                            let updated_paths = mgr.deployed_paths().to_vec();
                            if apply_honeypot_refresh_if_changed(
                                &mut last_honeypot_paths,
                                updated_paths,
                                |paths| active_backend.set_honeypot_paths(paths),
                            ) {
                                tracing::info!(
                                    honeypots = last_honeypot_paths.len(),
                                    "updated ETW sensor honeypot paths after periodic profile refresh"
                                );
                            }
                            honeypot_mgr_opt = Some(mgr);
                        }
                        Err(join_err) => {
                            tracing::warn!(
                                error = %join_err,
                                "periodic service honeypot refresh task panicked"
                            );
                        }
                    }
                }
                _ = refresh_ticker.tick(), if refresh_in_flight.is_none() && honeypot_mgr_opt.is_some() => {
                    if let Some(mut mgr) = honeypot_mgr_opt.take() {
                        let refresh_store = honeypot_store.clone();
                        refresh_in_flight = Some(tokio::task::spawn_blocking(move || {
                            let prev_paths = mgr.deployed_paths().to_vec();
                            let res = mgr.refresh_service_profiles();
                            if !HoneypotManager::path_sets_equal(&prev_paths, mgr.deployed_paths()) {
                                record_honeypots_best_effort(&refresh_store, mgr.deployed_paths());
                            }
                            (mgr, res)
                        }));
                    }
                }
            }
        }
    }
    tracing::info!("shutdown signal received; initiating graceful shutdown and WAL checkpoint");
    engine.signal_early_shutdown();

    let stop_res = tokio::task::spawn_blocking(move || {
        let mut backend = active_backend;
        let res = backend.stop();
        drop(backend);
        res
    })
    .await;
    match stop_res {
        Ok(Err(err)) => tracing::warn!(error = %err, "sensor backend stop returned warning"),
        Err(err) => tracing::warn!(error = %err, "sensor backend stop task panicked"),
        Ok(Ok(())) => {}
    }

    wfp_defense.clear_wfp_drop_sink();
    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await?;
    tracing::info!("ledr-daemon shutdown complete");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledr_sensor_win::etw::inspect_live_process;

    #[test]
    fn cli_parses_defaults_and_flags() {
        let def = parse_cli_args(["ledr-daemon"]).expect("default args");
        assert!(def.foreground);
        assert!(!def.service);
        assert!(!def.dev_bypass_auth);
        assert!(!def.disable_nrd_refresh);
        assert_eq!(def.db_path, None);
        assert_eq!(def.rules_dir, None);
        assert_eq!(def.nrd_cache_path, None);
        assert!(def.nrd_feed_urls.is_empty());
        assert_eq!(def.pipe_name, IPC_PIPE_NAME);
        assert_eq!(def.ui_sha256, None);
        assert_eq!(def.ui_signer, None);
        assert_eq!(def.ui_root_thumbprint, None);
        assert_eq!(def.bridge_sha256, None);
        assert_eq!(def.bridge_signer, None);
        assert_eq!(def.bridge_root_thumbprint, None);

        let custom = parse_cli_args([
            "ledr-daemon",
            "--foreground",
            "--dev-bypass-auth",
            "--disable-nrd-refresh",
            "--nrd-feed-url",
            "file:///C:/Temp/nrd7.txt",
            "--nrd-feed-url",
            "file:///C:/Temp/nrd14-8.txt",
            "--nrd-cache",
            r"C:\Temp\nrd-cache.txt",
            "--db",
            r"C:\Temp\test.db",
            "--rules",
            r"C:\Temp\rules",
            "--pipe",
            r"\\.\pipe\custom-pipe",
            "--ui-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--ui-signer",
            "CN=LocalEDR",
            "--ui-root-thumbprint",
            "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
            "--bridge-sha256",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--bridge-signer",
            "CN=LocalEDR Bridge",
            "--bridge-root-thumbprint",
            "4C2EFD3A66EA28B16697394703A72CA340A05BD6",
            "--auth-helper-sha256",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ])
        .expect("custom args");
        assert!(custom.foreground);
        assert!(custom.dev_bypass_auth);
        assert!(custom.disable_nrd_refresh);
        assert_eq!(
            custom.nrd_feed_urls,
            vec![
                "file:///C:/Temp/nrd7.txt".to_string(),
                "file:///C:/Temp/nrd14-8.txt".to_string(),
            ]
        );
        assert_eq!(
            custom.nrd_cache_path,
            Some(PathBuf::from(r"C:\Temp\nrd-cache.txt"))
        );
        assert_eq!(custom.db_path, Some(PathBuf::from(r"C:\Temp\test.db")));
        assert_eq!(custom.rules_dir, Some(PathBuf::from(r"C:\Temp\rules")));
        assert_eq!(custom.pipe_name, r"\\.\pipe\custom-pipe");
        assert_eq!(
            custom.ui_sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(custom.ui_signer.as_deref(), Some("CN=LocalEDR"));
        assert_eq!(
            custom.ui_root_thumbprint.as_deref(),
            Some("3B1EFD3A66EA28B16697394703A72CA340A05BD5")
        );
        assert_eq!(
            custom.bridge_sha256.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert_eq!(custom.bridge_signer.as_deref(), Some("CN=LocalEDR Bridge"));
        assert_eq!(
            custom.bridge_root_thumbprint.as_deref(),
            Some("4C2EFD3A66EA28B16697394703A72CA340A05BD6")
        );
        assert_eq!(
            custom.auth_helper_sha256.as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );
        let custom_cfg = build_daemon_config(&custom, None, None, None, Vec::new(), Vec::new());
        assert_eq!(
            custom_cfg.auth_helper_sha256.as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );

        let service_strict = parse_cli_args(["ledr-daemon", "--service-strict"]).expect("service strict");
        assert!(!service_strict.foreground);
        assert!(!service_strict.dev_bypass_auth);
        assert_eq!(service_strict.outbound_mode, OutboundEnforcementMode::Enforce);
        assert!(!service_strict.disable_outbound_firewall);
        assert!(!service_strict.resume_suspended_on_shutdown);

        let safe_host = parse_cli_args([
            "ledr-daemon",
            "--service-strict",
            "--outbound-mode",
            "preemptive-only",
            "--disable-outbound-firewall",
            "--resume-suspended-on-shutdown",
        ])
        .expect("safe host flags");
        assert_eq!(safe_host.outbound_mode, OutboundEnforcementMode::PreemptiveOnly);
        assert!(safe_host.disable_outbound_firewall);
        assert!(safe_host.resume_suspended_on_shutdown);

        let audit_mode = parse_cli_args(["ledr-daemon", "--outbound-mode", "audit"])
            .expect("audit mode");
        assert_eq!(audit_mode.outbound_mode, OutboundEnforcementMode::Audit);

        // BUG_0007: --ui-signer without --ui-root-thumbprint must be rejected at startup.
        // BUG_0004: under --dev-bypass-auth no authorization runs, so the signer/thumbprint
        // pair is not required.
        let cases: &[(&str, &[&str], bool)] = &[
            ("--outbound-mode missing value", &["ledr-daemon", "--outbound-mode"], false),
            ("--outbound-mode invalid value", &["ledr-daemon", "--outbound-mode", "bogus"], false),
            ("--db missing value", &["ledr-daemon", "--db"], false),
            ("--ui-sha256 missing value", &["ledr-daemon", "--ui-sha256"], false),
            ("--ui-signer missing value", &["ledr-daemon", "--ui-signer"], false),
            (
                "--ui-signer alone must fail (root thumbprint pin required)",
                &["ledr-daemon", "--ui-signer", "CN=LocalEDR"],
                false,
            ),
            (
                "--dev-bypass-auth + --ui-signer must be accepted",
                &["ledr-daemon", "--dev-bypass-auth", "--ui-signer", "CN=LocalEDR"],
                true,
            ),
            (
                "signer + root thumbprint pair must be accepted",
                &[
                    "ledr-daemon",
                    "--ui-signer",
                    "CN=LocalEDR",
                    "--ui-root-thumbprint",
                    "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
                ],
                true,
            ),
            ("--ui-root-thumbprint missing value", &["ledr-daemon", "--ui-root-thumbprint"], false),
            ("--bridge-sha256 missing value", &["ledr-daemon", "--bridge-sha256"], false),
            ("--bridge-sha256 empty", &["ledr-daemon", "--bridge-sha256", "   "], false),
            ("--bridge-signer missing value", &["ledr-daemon", "--bridge-signer"], false),
            (
                "--bridge-signer alone must fail (root thumbprint pin required)",
                &["ledr-daemon", "--bridge-signer", "CN=LocalEDR Bridge"],
                false,
            ),
            (
                "--dev-bypass-auth + --bridge-signer must be accepted",
                &[
                    "ledr-daemon",
                    "--dev-bypass-auth",
                    "--bridge-signer",
                    "CN=LocalEDR Bridge",
                ],
                true,
            ),
            (
                "bridge signer + root thumbprint pair must be accepted",
                &[
                    "ledr-daemon",
                    "--bridge-signer",
                    "CN=LocalEDR Bridge",
                    "--bridge-root-thumbprint",
                    "4C2EFD3A66EA28B16697394703A72CA340A05BD6",
                ],
                true,
            ),
            ("--bridge-root-thumbprint missing value", &["ledr-daemon", "--bridge-root-thumbprint"], false),
            ("--auth-helper-sha256 missing value", &["ledr-daemon", "--auth-helper-sha256"], false),
            ("--auth-helper-sha256 empty", &["ledr-daemon", "--auth-helper-sha256", "   "], false),
            ("--auth-helper-sha256 short", &["ledr-daemon", "--auth-helper-sha256", "abcd"], false),
            (
                "--auth-helper-sha256 too long (65 hex)",
                &[
                    "ledr-daemon",
                    "--auth-helper-sha256",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ],
                false,
            ),
            (
                "--auth-helper-sha256 non-hex chars",
                &[
                    "ledr-daemon",
                    "--auth-helper-sha256",
                    "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
                ],
                false,
            ),
            (
                "--auth-helper-sha256 valid uppercase 64 hex",
                &[
                    "ledr-daemon",
                    "--auth-helper-sha256",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ],
                true,
            ),
            ("--nrd-feed-url missing value", &["ledr-daemon", "--nrd-feed-url"], false),
            ("--nrd-feed-url whitespace", &["ledr-daemon", "--nrd-feed-url", "   "], false),
            ("--nrd-cache missing value", &["ledr-daemon", "--nrd-cache"], false),
            ("--nrd-cache empty", &["ledr-daemon", "--nrd-cache", ""], false),
            ("unknown flag", &["ledr-daemon", "--unknown"], false),
        ];
        for (label, args, expect_ok) in cases {
            assert_eq!(parse_cli_args(args.iter().copied()).is_ok(), *expect_ok, "{label}");
        }
    }

    #[test]
    fn startup_rules_seed_defaults_once_and_upsert_edited_managed_rules_across_restarts() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-rules-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create tmp rules dir");

        let default_path = tmp_dir.join("default_allowlist.json");
        let ops_path = tmp_dir.join("ops_network_policy.json");

        std::fs::write(
            &default_path,
            serde_json::json!({
                "allowlist_rules": [
                    {
                        "rule_id": "DEF-ALLOW-DELETE-ME",
                        "scope": "NetworkAllow",
                        "exe_path_pattern": r"C:\Apps\browser.exe",
                        "sha256": null,
                        "signer_subject": "CN=Example",
                        "root_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "allowed_target": null,
                        "created_at_ms": 0,
                        "created_by": "default_allowlist"
                    },
                    {
                        "rule_id": "DEF-ALLOW-KEEP-EDIT",
                        "scope": "NetworkAllow",
                        "exe_path_pattern": r"C:\Apps\edge.exe",
                        "sha256": null,
                        "signer_subject": "CN=Example",
                        "root_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "allowed_target": null,
                        "created_at_ms": 0,
                        "created_by": "default_allowlist"
                    }
                ]
            })
            .to_string(),
        )
        .expect("write default_allowlist.json");

        // Boot 1: operator sets an app-wide NetworkBlock rule via --rules.
        std::fs::write(
            &ops_path,
            serde_json::json!({
                "allowlist_rules": [
                    {
                        "rule_id": "OPS-NET-BLOCK-1",
                        "scope": "NetworkBlock",
                        "exe_path_pattern": r"C:\Apps\tool.exe",
                        "sha256": null,
                        "signer_subject": null,
                        "root_thumbprint": null,
                        "allowed_target": null,
                        "created_at_ms": 1000,
                        "created_by": "operator"
                    }
                ]
            })
            .to_string(),
        )
        .expect("write initial ops_network_policy.json");

        let store = LedrStore::open_in_memory().expect("in-memory store");
        let loaded_boot1 = load_rules_or_default(Some(&tmp_dir)).expect("boot1 load rules");
        apply_startup_rules(&store, &loaded_boot1);

        assert!(store.get_rule("DEF-ALLOW-DELETE-ME").unwrap().is_some());
        let block_boot1 = store
            .get_rule("OPS-NET-BLOCK-1")
            .unwrap()
            .expect("OPS-NET-BLOCK-1 exists after boot 1");
        assert_eq!(block_boot1.allowed_target, None);

        // Between boots: operator deletes one default rule, customizes another in SQLite,
        // and narrows OPS-NET-BLOCK-1 in the --rules file to a specific IP.
        assert!(store.delete_rule("DEF-ALLOW-DELETE-ME").unwrap());
        let mut edited_default = store.get_rule("DEF-ALLOW-KEEP-EDIT").unwrap().unwrap();
        edited_default.allowed_target = Some("allowed.example.com".to_string());
        edited_default.created_by = "user_triage".to_string();
        store.upsert_rule(&edited_default).unwrap();

        std::fs::write(
            &ops_path,
            serde_json::json!({
                "allowlist_rules": [
                    {
                        "rule_id": "OPS-NET-BLOCK-1",
                        "scope": "NetworkBlock",
                        "exe_path_pattern": r"C:\Apps\tool.exe",
                        "sha256": null,
                        "signer_subject": null,
                        "root_thumbprint": null,
                        "allowed_target": "203.0.113.10",
                        "created_at_ms": 2000,
                        "created_by": "operator"
                    }
                ]
            })
            .to_string(),
        )
        .expect("update ops_network_policy.json");

        // Boot 2: reload from --rules and apply startup rules.
        let loaded_boot2 = load_rules_or_default(Some(&tmp_dir)).expect("boot2 load rules");
        apply_startup_rules(&store, &loaded_boot2);

        assert!(
            store.get_rule("DEF-ALLOW-DELETE-ME").unwrap().is_none(),
            "deleted shipped default rule must NOT be resurrected on restart"
        );
        let kept = store
            .get_rule("DEF-ALLOW-KEEP-EDIT")
            .unwrap()
            .expect("DEF-ALLOW-KEEP-EDIT exists");
        assert_eq!(
            kept.allowed_target.as_deref(),
            Some("allowed.example.com"),
            "SQLite edit to shipped default rule must NOT be overwritten on restart"
        );
        let block_boot2 = store
            .get_rule("OPS-NET-BLOCK-1")
            .unwrap()
            .expect("OPS-NET-BLOCK-1 exists after boot 2");
        assert_eq!(
            block_boot2.allowed_target.as_deref(),
            Some("203.0.113.10"),
            "edited operator-managed rule in --rules must update SQLite on restart"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn daemon_rt_01_build_daemon_runtime_is_bounded_multithread() {
        assert_eq!(DAEMON_TOKIO_WORKER_THREADS, 2);
        assert_eq!(
            DAEMON_TOKIO_MAX_BLOCKING_THREADS,
            DEFAULT_MAX_CONCURRENT_IPC_CLIENTS + 4
        );
        assert_eq!(DAEMON_TOKIO_MAX_BLOCKING_THREADS, 20);
        assert_eq!(DAEMON_TOKIO_BLOCKING_KEEP_ALIVE_SECS, 10);

        let rt = build_daemon_runtime().expect("build bounded daemon runtime");
        let handle = rt.handle();
        assert_eq!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
        assert_eq!(rt.metrics().num_workers(), DAEMON_TOKIO_WORKER_THREADS);
    }

    #[test]
    fn cli_dacl_01_strict_pipe_dacl_always_enabled_for_cli_modes() {
        let cases = [
            ("default", &["ledr-daemon"][..], false, true),
            (
                "foreground dev bypass",
                &["ledr-daemon", "--foreground", "--dev-bypass-auth"][..],
                true,
                true,
            ),
            ("service strict", &["ledr-daemon", "--service-strict"][..], false, false),
        ];

        for (label, argv, expected_bypass, expected_resume) in cases {
            let cli = parse_cli_args(argv.iter().copied()).expect(label);
            let cfg = build_daemon_config(&cli, None, None, None, Vec::new(), Vec::new());
            assert!(cfg.strict_pipe_dacl, "{label}: strict_pipe_dacl must be true");
            assert_eq!(
                cfg.dev_mode_bypass_ui_auth, expected_bypass,
                "{label}: dev_mode_bypass_ui_auth mismatch"
            );
            assert_eq!(
                cfg.resume_suspended_on_shutdown, expected_resume,
                "{label}: resume_suspended_on_shutdown mismatch"
            );
        }
    }

    #[test]
    fn cli_ui_path_01_foreground_sibling_ui_only_used_with_dev_bypass() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-ui-path-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");
        let daemon_exe = tmp_dir.join("ledr-daemon.exe");
        let sibling_ui = tmp_dir.join("ledr-ui.exe");
        std::fs::write(&sibling_ui, b"stub").expect("create sibling ledr-ui.exe");

        assert_eq!(
            resolve_ui_exe_path_from(Some(&daemon_exe), true, false),
            PathBuf::from(AUTHORIZED_UI_EXE_PATH),
            "foreground without --dev-bypass-auth must target AUTHORIZED_UI_EXE_PATH to match L-25 IPC auth"
        );
        assert_eq!(
            resolve_ui_exe_path_from(Some(&daemon_exe), true, true),
            sibling_ui,
            "foreground with --dev-bypass-auth prefers sibling ledr-ui.exe"
        );
        assert_eq!(
            resolve_ui_exe_path_from(Some(&daemon_exe), false, true),
            PathBuf::from(AUTHORIZED_UI_EXE_PATH),
            "service/non-foreground mode must target AUTHORIZED_UI_EXE_PATH"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_svc_01_service_flag_combinations_and_conflicts() {
        let svc = parse_cli_args(["ledr-daemon", "--service"]).expect("--service parses");
        assert!(svc.service);
        assert!(!svc.foreground, "--service must clear foreground to false");

        let svc_strict = parse_cli_args(["ledr-daemon", "--service", "--service-strict"])
            .expect("--service --service-strict parses");
        assert!(svc_strict.service);
        assert!(!svc_strict.foreground);

        let strict_svc = parse_cli_args(["ledr-daemon", "--service-strict", "--service"])
            .expect("--service-strict --service parses");
        assert!(strict_svc.service);
        assert!(!strict_svc.foreground);

        let svc_fg = parse_cli_args(["ledr-daemon", "--service", "--foreground"])
            .expect_err("--service --foreground must be rejected");
        assert!(svc_fg.to_string().contains("--foreground"));

        let fg_svc = parse_cli_args(["ledr-daemon", "--foreground", "--service"])
            .expect_err("--foreground --service must be rejected");
        assert!(fg_svc.to_string().contains("--foreground"));

        assert_eq!(
            run_cli_entrypoint_code(["ledr-daemon", "--help"]),
            0,
            "--help must return exit code 0"
        );
        assert_eq!(
            run_cli_entrypoint_code(["ledr-daemon", "--service", "--foreground"]),
            1,
            "invalid CLI args must return exit code 1"
        );
    }

    #[test]
    fn cli_svc_02_service_mode_preserves_security_invariants() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-svc-inv-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");
        let daemon_exe = tmp_dir.join("ledr-daemon.exe");
        let sibling_ui = tmp_dir.join("ledr-ui.exe");
        std::fs::write(&sibling_ui, b"stub").expect("create sibling ledr-ui.exe");

        for argv in [
            &["ledr-daemon", "--service"][..],
            &["ledr-daemon", "--service", "--dev-bypass-auth"][..],
            &["ledr-daemon", "--service", "--service-strict"][..],
        ] {
            let cli = parse_cli_args(argv.iter().copied()).expect("parse service args");
            assert!(cli.service);
            assert!(!cli.foreground);
            assert_eq!(
                resolve_ui_exe_path_from(Some(&daemon_exe), cli.foreground, cli.dev_bypass_auth),
                PathBuf::from(AUTHORIZED_UI_EXE_PATH),
                "non-foreground --service must always target AUTHORIZED_UI_EXE_PATH"
            );
            let cfg = build_daemon_config(&cli, None, None, None, Vec::new(), Vec::new());
            assert!(cfg.strict_pipe_dacl);
            assert!(!cfg.resume_suspended_on_shutdown);
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_svc_03_non_scm_service_launch_exits_2_with_guidance() {
        use std::io::Read as _;
        use std::process::{Child, Command, Stdio};
        use std::time::Instant;

        if std::env::var_os("LEDR_TEST_SCM_1063_CHILD").is_some() {
            let code = run_cli_entrypoint_code(["ledr-daemon", "--service"]);
            std::process::exit(i32::from(code));
        }

        struct ChildGuard(Option<Child>);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let mut child = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "tests::cli_svc_03_non_scm_service_launch_exits_2_with_guidance",
                "--nocapture",
            ])
            .env("LEDR_TEST_SCM_1063_CHILD", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn --service 1063 child");

        let mut stdout_pipe = child.stdout.take().expect("stdout pipe");
        let mut stderr_pipe = child.stderr.take().expect("stderr pipe");
        let stdout_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut buf);
            buf
        });
        let stderr_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut buf);
            buf
        });

        let mut guard = ChildGuard(Some(child));
        let deadline = Duration::from_millis(45_000);
        let start = Instant::now();
        let status = loop {
            if let Some(status) = guard
                .0
                .as_mut()
                .expect("child present")
                .try_wait()
                .expect("try_wait")
            {
                guard.0 = None;
                break status;
            }
            assert!(
                start.elapsed() <= deadline,
                "ledr-daemon --service child did not return 1063 within {deadline:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        };

        let stdout = String::from_utf8_lossy(&stdout_handle.join().expect("stdout join")).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_handle.join().expect("stderr join")).into_owned();
        assert_eq!(
            status.code(),
            Some(i32::from(service_win::NON_SCM_EXIT_CODE)),
            "expected exit code 2 for non-SCM 1063 launch; stdout={stdout:?}, stderr={stderr:?}"
        );
        assert!(
            stderr.contains("1063") && stderr.contains("--foreground"),
            "expected 1063 and --foreground guidance in stderr, got: {stderr:?}"
        );
    }

    #[test]
    fn cli_check_01_parses_check_unresolved_suspended_and_rejects_mode_conflicts() {
        let check = parse_cli_args(["ledr-daemon", "--check-unresolved-suspended"])
            .expect("--check-unresolved-suspended parses");
        assert!(check.check_unresolved_suspended);
        assert_eq!(check.db_path, None);

        let check_with_db = parse_cli_args([
            "ledr-daemon",
            "--check-unresolved-suspended",
            "--db",
            r"C:\Temp\check.db",
        ])
        .expect("--check-unresolved-suspended --db parses");
        assert!(check_with_db.check_unresolved_suspended);
        assert_eq!(
            check_with_db.db_path,
            Some(PathBuf::from(r"C:\Temp\check.db"))
        );

        for conflict in ["--foreground", "--service", "--service-strict"] {
            let err = parse_cli_args(["ledr-daemon", "--check-unresolved-suspended", conflict])
                .expect_err("mode conflict must fail");
            assert!(
                err.to_string().contains("--check-unresolved-suspended"),
                "unexpected conflict error for {conflict}: {err}"
            );
        }
    }

    #[test]
    fn cli_check_02_missing_db_exits_0_and_corrupt_or_dir_exits_1() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-check-missing-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");

        let missing_db = tmp_dir.join("nonexistent.db");
        let missing_str = missing_db.to_string_lossy().into_owned();
        assert_eq!(
            run_cli_entrypoint_code([
                "ledr-daemon",
                "--check-unresolved-suspended",
                "--db",
                &missing_str,
            ]),
            0,
            "missing DB must exit 0"
        );
        assert!(
            !missing_db.exists(),
            "read-only check must NOT create missing DB file"
        );

        // Passing a directory as --db must fail closed with exit code 1.
        let dir_str = tmp_dir.to_string_lossy().into_owned();
        assert_eq!(
            run_cli_entrypoint_code([
                "ledr-daemon",
                "--check-unresolved-suspended",
                "--db",
                &dir_str,
            ]),
            1,
            "directory as --db must fail closed with exit 1"
        );

        // Corrupt non-SQLite file must fail closed with exit code 1.
        let corrupt_db = tmp_dir.join("corrupt.db");
        std::fs::write(&corrupt_db, b"not a valid sqlite database").expect("write corrupt db");
        let corrupt_str = corrupt_db.to_string_lossy().into_owned();
        assert_eq!(
            run_cli_entrypoint_code([
                "ledr-daemon",
                "--check-unresolved-suspended",
                "--db",
                &corrupt_str,
            ]),
            1,
            "corrupt DB must fail closed with exit 1"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_check_03_clean_and_resolved_alerts_exit_0_while_wal_store_open() {
        use ledr_proto::{AlertSeverity, AlertStatus};

        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-check-clean-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");
        let db_path = tmp_dir.join("localedr.db");
        let store = LedrStore::open(&db_path).expect("open WAL store");

        let alerts = [
            AlertRecord {
                alert_id: "al-pending-unsuspended".to_string(),
                timestamp_ms: 1_000,
                severity: AlertSeverity::Medium,
                source_layer: "LAYER_4_BROWSER".to_string(),
                rule_id: "R-1".to_string(),
                title: "Pending non-suspended alert".to_string(),
                process_instance_id: Some("1111:50001".to_string()),
                process_suspended: false,
                status: AlertStatus::Pending,
                context_json: r#"{"suspended_children":[]}"#.to_string(),
                resolved_at_ms: None,
            },
            AlertRecord {
                alert_id: "al-approved-once".to_string(),
                timestamp_ms: 2_000,
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "R-2".to_string(),
                title: "Resolved alert".to_string(),
                process_instance_id: Some("2222:50002".to_string()),
                process_suspended: true,
                status: AlertStatus::ApprovedOnce,
                context_json: r#"{"suspended_children":["3333:50003"]}"#.to_string(),
                resolved_at_ms: Some(2_500),
            },
            AlertRecord {
                alert_id: "al-terminated".to_string(),
                timestamp_ms: 3_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "R-3".to_string(),
                title: "Terminated alert".to_string(),
                process_instance_id: Some("4444:50004".to_string()),
                process_suspended: true,
                status: AlertStatus::TerminatedBlocked,
                context_json: "{}".to_string(),
                resolved_at_ms: Some(3_500),
            },
        ];
        for alert in &alerts {
            store.record_alert(alert).expect("insert alert");
        }

        // Deliberately keep `store` open in WAL mode without checkpointing.
        let db_str = db_path.to_string_lossy().into_owned();
        assert_eq!(
            run_cli_entrypoint_code([
                "ledr-daemon",
                "--check-unresolved-suspended",
                "--db",
                &db_str,
            ]),
            0,
            "clean/resolved alerts must exit 0 even while WAL writer is open"
        );

        drop(store);
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_check_04_unresolved_suspended_parent_and_children_exit_3_with_pids() {
        use ledr_proto::{AlertSeverity, AlertStatus};
        use std::io::Read as _;
        use std::process::{Child, Command, Stdio};

        if let Some(db_env) = std::env::var_os("LEDR_TEST_CHECK_SUSPENDED_DB") {
            let db_str = db_env.to_string_lossy().into_owned();
            let code = run_cli_entrypoint_code([
                "ledr-daemon",
                "--check-unresolved-suspended",
                "--db",
                &db_str,
            ]);
            std::process::exit(i32::from(code));
        }

        struct ChildKillGuard(Option<Child>);
        impl Drop for ChildKillGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let spawn_live_dummy = || -> (ChildKillGuard, ProcessIdentity) {
            let child = Command::new("cmd.exe")
                .args(["/c", "findstr", ".*"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn harmless live cmd child");
            let pid = child.id();
            let ct = inspect_live_process(pid)
                .map(|info| info.create_time_100ns)
                .filter(|&ct| ct != 0)
                .expect("query CreationTime for live cmd child");
            (ChildKillGuard(Some(child)), ProcessIdentity::new(pid, ct))
        };

        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-check-susp-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");

        let run_child_check = |db_path: &Path| -> (Option<i32>, String) {
            let mut child = Command::new(std::env::current_exe().expect("current test binary"))
                .args([
                    "--exact",
                    "tests::cli_check_04_unresolved_suspended_parent_and_children_exit_3_with_pids",
                    "--nocapture",
                ])
                .env("LEDR_TEST_CHECK_SUSPENDED_DB", db_path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn check child");
            let mut stderr_pipe = child.stderr.take().expect("stderr");
            let stderr_handle = std::thread::spawn(move || {
                let mut buf = Vec::new();
                let _ = stderr_pipe.read_to_end(&mut buf);
                buf
            });
            let status = child.wait().expect("wait child");
            let stderr =
                String::from_utf8_lossy(&stderr_handle.join().expect("stderr join")).into_owned();
            (status.code(), stderr)
        };

        let (_parent_guard, parent_ident) = spawn_live_dummy();
        let (_child1_guard, child1_ident) = spawn_live_dummy();
        let (_child2_guard, child2_ident) = spawn_live_dummy();

        // Case A: Unresolved Pending alert with process_suspended = true and matching live
        // `(pid, create_time_100ns)` (while WAL writer is open).
        let db_parent = tmp_dir.join("parent_suspended.db");
        let store_parent = LedrStore::open(&db_parent).expect("open parent db");
        store_parent
            .record_alert(&AlertRecord {
                alert_id: "al-susp-parent".to_string(),
                timestamp_ms: 10_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Honeypot write".to_string(),
                process_instance_id: Some(parent_ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("insert parent suspended alert");
        let (code_a, stderr_a) = run_child_check(&db_parent);
        assert_eq!(code_a, Some(3), "expected exit 3; stderr={stderr_a:?}");
        let parent_pid_str = parent_ident.pid.to_string();
        assert!(
            stderr_a.contains(&parent_pid_str) && stderr_a.contains("1 unresolved suspended alert"),
            "expected PID {parent_pid_str} and count in stderr: {stderr_a:?}"
        );
        drop(store_parent);

        // Case B: Unresolved ExpiredSuspended alert with process_suspended = false and live
        // `suspended_children`.
        let db_children = tmp_dir.join("children_suspended.db");
        let store_children = LedrStore::open(&db_children).expect("open children db");
        let unsuspended_parent_pid = 999_991u32;
        store_children
            .record_alert(&AlertRecord {
                alert_id: "al-susp-children".to_string(),
                timestamp_ms: 20_000,
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "L-05".to_string(),
                title: "Credential canary access".to_string(),
                process_instance_id: Some(format!("{unsuspended_parent_pid}:200001")),
                process_suspended: false,
                status: AlertStatus::ExpiredSuspended,
                context_json: serde_json::json!({
                    "suspended_children": [child1_ident.instance_id(), child2_ident.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("insert suspended_children alert");
        store_children.checkpoint_truncate().expect("checkpoint");
        drop(store_children);

        let (code_b, stderr_b) = run_child_check(&db_children);
        assert_eq!(code_b, Some(3), "expected exit 3; stderr={stderr_b:?}");
        let c1_str = child1_ident.pid.to_string();
        let c2_str = child2_ident.pid.to_string();
        assert!(
            stderr_b.contains(&c1_str)
                && stderr_b.contains(&c2_str)
                && !stderr_b.contains(&unsuspended_parent_pid.to_string()),
            "expected suspended child PIDs {c1_str}, {c2_str} (not unsuspended parent) in stderr: {stderr_b:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_check_05_exited_and_reused_pids_exit_0_while_unknown_and_missing_ct_exit_3() {
        use ledr_proto::{AlertSeverity, AlertStatus};
        use std::process::{Child, Command, Stdio};

        struct ChildKillGuard(Option<Child>);
        impl Drop for ChildKillGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-check-liveness-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");

        // Spawn a real child, capture its (pid, create_time_100ns), then terminate it -> `Gone`.
        let mut dead_child = Command::new("cmd.exe")
            .args(["/c", "findstr", ".*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child to exit");
        let dead_pid = dead_child.id();
        let dead_ct = inspect_live_process(dead_pid)
            .map(|info| info.create_time_100ns)
            .filter(|&ct| ct != 0)
            .expect("dead child create_time_100ns");
        let _ = dead_child.kill();
        let _ = dead_child.wait();
        let dead_ident = ProcessIdentity::new(dead_pid, dead_ct);

        let db_gone = tmp_dir.join("gone.db");
        let store_gone = LedrStore::open(&db_gone).expect("open gone db");
        store_gone
            .record_alert(&AlertRecord {
                alert_id: "al-gone".to_string(),
                timestamp_ms: 1_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Exited suspended process".to_string(),
                process_instance_id: Some(dead_ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "suspended_children": [dead_ident.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("insert gone alert");
        drop(store_gone);
        assert_eq!(
            check_unresolved_suspended_in_db(Some(&db_gone)),
            0,
            "positively confirmed Gone suspended process must exit 0"
        );

        // Live child process with mismatched create_time_100ns (PID reused) -> exit 0.
        let live_child = Command::new("cmd.exe")
            .args(["/c", "findstr", ".*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live child");
        let live_pid = live_child.id();
        let live_ct = inspect_live_process(live_pid)
            .map(|info| info.create_time_100ns)
            .filter(|&ct| ct != 0)
            .expect("live child create_time_100ns");
        let _live_guard = ChildKillGuard(Some(live_child));

        let db_reused = tmp_dir.join("reused.db");
        let store_reused = LedrStore::open(&db_reused).expect("open reused db");
        let mismatched_ident = ProcessIdentity::new(live_pid, live_ct.saturating_add(1));
        store_reused
            .record_alert(&AlertRecord {
                alert_id: "al-reused".to_string(),
                timestamp_ms: 2_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Reused PID alert".to_string(),
                process_instance_id: Some(mismatched_ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("insert reused alert");
        drop(store_reused);
        assert_eq!(
            check_unresolved_suspended_in_db(Some(&db_reused)),
            0,
            "live PID with CreationTime mismatch (PID reused) must exit 0"
        );

        // Live PID with missing creation time (`pid:0` and `pid` only) -> fail closed exit 3.
        for (label, raw_id) in [
            ("zero_ct", format!("{live_pid}:0")),
            ("missing_ct", live_pid.to_string()),
        ] {
            let db_missing_ct = tmp_dir.join(format!("missing_{label}.db"));
            let store_missing = LedrStore::open(&db_missing_ct).expect("open missing ct db");
            store_missing
                .record_alert(&AlertRecord {
                    alert_id: format!("al-missing-{label}"),
                    timestamp_ms: 3_000,
                    severity: AlertSeverity::Critical,
                    source_layer: "LAYER_1_HONEYPOT".to_string(),
                    rule_id: "L-06".to_string(),
                    title: "Missing creation time".to_string(),
                    process_instance_id: Some(raw_id),
                    process_suspended: true,
                    status: AlertStatus::Pending,
                    context_json: "{}".to_string(),
                    resolved_at_ms: None,
                })
                .expect("insert missing ct alert");
            drop(store_missing);
            assert_eq!(
                check_unresolved_suspended_in_db(Some(&db_missing_ct)),
                3,
                "live PID with missing creation time ({label}) must fail closed with exit 3"
            );
        }

        // `Unknown` liveness or `Running` without CreationTime must fail closed with exit 3.
        let db_probe = tmp_dir.join("probe_unknown.db");
        let store_probe = LedrStore::open(&db_probe).expect("open probe db");
        let live_ident = ProcessIdentity::new(live_pid, live_ct);
        store_probe
            .record_alert(&AlertRecord {
                alert_id: "al-probe-unknown".to_string(),
                timestamp_ms: 4_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Probe unknown".to_string(),
                process_instance_id: Some(live_ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: "{}".to_string(),
                resolved_at_ms: None,
            })
            .expect("insert probe unknown alert");
        drop(store_probe);
        assert_eq!(
            check_unresolved_suspended_in_db_with_probe(Some(&db_probe), &|_| {
                LiveTargetState::Unknown
            }),
            3,
            "ProcessLiveness::Unknown must fail closed with exit 3"
        );
        assert_eq!(
            check_unresolved_suspended_in_db_with_probe(Some(&db_probe), &|_| {
                LiveTargetState::Running {
                    create_time_100ns: None,
                }
            }),
            3,
            "Running process with unavailable CreationTime must fail closed with exit 3"
        );

        // Mixed alert: parent is Gone, but one child is Running with matching identity -> exit 3.
        let db_mixed = tmp_dir.join("mixed.db");
        let store_mixed = LedrStore::open(&db_mixed).expect("open mixed db");
        store_mixed
            .record_alert(&AlertRecord {
                alert_id: "al-mixed".to_string(),
                timestamp_ms: 5_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Mixed parent gone child running".to_string(),
                process_instance_id: Some(dead_ident.instance_id()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "suspended_children": [dead_ident.instance_id(), live_ident.instance_id()]
                })
                .to_string(),
                resolved_at_ms: None,
            })
            .expect("insert mixed alert");
        drop(store_mixed);
        assert_eq!(
            check_unresolved_suspended_in_db(Some(&db_mixed)),
            3,
            "live suspended child must still block with exit 3 even when parent exited"
        );

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_check_06_memoizes_probe_per_unique_pid_across_alerts_and_children() {
        use ledr_proto::{AlertSeverity, AlertStatus};
        use std::cell::RefCell;

        let make_alert = |id: &str,
                          pid_inst: Option<&str>,
                          suspended: bool,
                          children: &[&str]|
         -> AlertRecord {
            AlertRecord {
                alert_id: id.to_string(),
                timestamp_ms: 1_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_HONEYPOT".to_string(),
                rule_id: "L-06".to_string(),
                title: "Memoization test".to_string(),
                process_instance_id: pid_inst.map(str::to_string),
                process_suspended: suspended,
                status: AlertStatus::Pending,
                context_json: serde_json::json!({
                    "suspended_children": children
                })
                .to_string(),
                resolved_at_ms: None,
            }
        };

        let counts: RefCell<HashMap<u32, usize>> = RefCell::new(HashMap::new());
        let probe = |pid: u32| -> LiveTargetState {
            *counts.borrow_mut().entry(pid).or_insert(0) += 1;
            match pid {
                1001 => LiveTargetState::Running {
                    create_time_100ns: Some(5000),
                },
                1002 => LiveTargetState::Gone,
                1003 => LiveTargetState::Running {
                    create_time_100ns: Some(7001),
                },
                1005 => LiveTargetState::Unknown,
                1006 => LiveTargetState::Running {
                    create_time_100ns: None,
                },
                _ => panic!("unexpected probe call for pid {pid}"),
            }
        };

        let alerts = vec![
            // Parent 1001 live; children duplicate 1001, plus Gone 1002 and PID-reused 1003.
            make_alert("a1", Some("1001:5000"), true, &["1001:5000", "1002:6000", "1003:7000"]),
            // All targets are Gone or PID-reused -> alert excluded; no extra probes.
            make_alert("a2", Some("1002:6000"), true, &["1003:7000", "1002:0"]),
            // Unsuspended parent 1004 must NOT be probed; children reuse 1001 and probe Unknown 1005.
            make_alert("a3", Some("1004:8000"), false, &["1001:5000", "1005:9000", "1005:9000"]),
            // Running without CreationTime (1006) fails closed; pid 0 must not invoke probe.
            make_alert("a4", Some("1006:1000"), true, &["1006:0", "1006", "0:123"]),
            // Different expected CreationTime on same PIDs uses cached state accurately:
            // 1001:4999 != 5000 (excluded), 1003:7001 == 7001 (blocked).
            make_alert("a5", Some("1001:4999"), true, &["1003:7001"]),
        ];

        let (live_alerts, live_pids) = collect_live_unresolved_suspended_alerts(&alerts, &probe);
        assert_eq!(live_alerts, 4);
        assert_eq!(live_pids, BTreeSet::from([1001, 1003, 1005, 1006]));
        {
            let recorded = counts.borrow();
            assert_eq!(recorded.get(&1001).copied(), Some(1));
            assert_eq!(recorded.get(&1002).copied(), Some(1));
            assert_eq!(recorded.get(&1003).copied(), Some(1));
            assert_eq!(recorded.get(&1005).copied(), Some(1));
            assert_eq!(recorded.get(&1006).copied(), Some(1));
            assert!(!recorded.contains_key(&1004));
            assert!(!recorded.contains_key(&0));
        }

        // Verify DB-backed `check_unresolved_suspended_in_db_with_probe` also invokes probe once per unique PID.
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-main-check-memo-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create temp test dir");

        let db_blocked = tmp_dir.join("memo_blocked.db");
        let store_blocked = LedrStore::open(&db_blocked).expect("open blocked memo db");
        for alert in &alerts {
            store_blocked.record_alert(alert).expect("insert alert");
        }
        drop(store_blocked);

        counts.borrow_mut().clear();
        assert_eq!(
            check_unresolved_suspended_in_db_with_probe(Some(&db_blocked), &probe),
            3
        );
        {
            let recorded = counts.borrow();
            assert_eq!(recorded.len(), 5);
            for pid in [1001u32, 1002, 1003, 1005, 1006] {
                assert_eq!(
                    recorded.get(&pid).copied(),
                    Some(1),
                    "expected exactly 1 probe call for pid {pid}"
                );
            }
        }

        // When all duplicate PIDs resolve to Gone or CreationTime-mismatched (reused), exit 0 with 1 probe per unique PID.
        let db_clear = tmp_dir.join("memo_clear.db");
        let store_clear = LedrStore::open(&db_clear).expect("open clear memo db");
        store_clear
            .record_alert(&make_alert(
                "c1",
                Some("1002:6000"),
                true,
                &["1002:6000", "1003:7000"],
            ))
            .expect("insert c1");
        store_clear
            .record_alert(&make_alert(
                "c2",
                Some("1003:7000"),
                true,
                &["1002:0", "1003:7000"],
            ))
            .expect("insert c2");
        drop(store_clear);

        counts.borrow_mut().clear();
        assert_eq!(
            check_unresolved_suspended_in_db_with_probe(Some(&db_clear), &probe),
            0
        );
        {
            let recorded = counts.borrow();
            assert_eq!(recorded.len(), 2);
            assert_eq!(recorded.get(&1002).copied(), Some(1));
            assert_eq!(recorded.get(&1003).copied(), Some(1));
        }

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn cli_check_07_fast_os_probe_distinguishes_live_from_exited_zombie_handle() {
        use std::process::{Child, Command, Stdio};
        use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

        struct ChildKillGuard(Option<Child>);
        impl Drop for ChildKillGuard {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        assert_eq!(
            probe_live_target_os(0),
            LiveTargetState::Running {
                create_time_100ns: None
            }
        );

        let live_child = Command::new("cmd.exe")
            .args(["/c", "findstr", ".*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live child");
        let live_pid = live_child.id();
        let live_ct = inspect_live_process(live_pid)
            .map(|info| info.create_time_100ns)
            .filter(|&ct| ct != 0)
            .expect("live child create_time_100ns");
        let _live_guard = ChildKillGuard(Some(live_child));

        assert_eq!(
            probe_live_target_os(live_pid),
            LiveTargetState::Running {
                create_time_100ns: Some(live_ct)
            },
            "fast OS probe must return exact CreationTime for live process"
        );

        // Spawn a child, hold an open `PROCESS_QUERY_LIMITED_INFORMATION` handle so the kernel
        // process object remains alive after termination (zombie state), then terminate it.
        let mut zombie_child = Command::new("cmd.exe")
            .args(["/c", "findstr", ".*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zombie child");
        let zombie_pid = zombie_child.id();
        let _held_handle =
            open_verified_process_handle(zombie_pid, PROCESS_QUERY_LIMITED_INFORMATION)
                .expect("open handle to hold zombie process object");
        let _ = zombie_child.kill();
        let _ = zombie_child.wait();

        assert_eq!(
            probe_live_target_os(zombie_pid),
            LiveTargetState::Gone,
            "exited zombie process with an open handle must be reported as Gone, not Running"
        );
    }

    #[test]
    fn honeypot_refresh_01_updates_sensor_only_when_path_set_changes() {
        let mut last = vec![
            PathBuf::from(r"C:\Users\Alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
            PathBuf::from(r"C:\Users\Alice\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx"),
        ];
        let mut calls = 0usize;

        // Same set in reverse order & different casing -> must NOT trigger update.
        let unchanged = apply_honeypot_refresh_if_changed(
            &mut last,
            vec![
                PathBuf::from(r"c:\users\alice\desktop\!00_LocalEDR_Canary_DoNotEdit.docx"),
                PathBuf::from(r"c:\users\alice\documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
            ],
            |_| calls += 1,
        );
        assert!(!unchanged);
        assert_eq!(calls, 0);

        // New user profile path added -> MUST trigger update and update `last`.
        let mut applied_paths = Vec::new();
        let changed = apply_honeypot_refresh_if_changed(
            &mut last,
            vec![
                PathBuf::from(r"C:\Users\Alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
                PathBuf::from(r"C:\Users\Alice\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx"),
                PathBuf::from(r"C:\Users\Bob\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
            ],
            |paths| {
                calls += 1;
                applied_paths = paths;
            },
        );
        assert!(changed);
        assert_eq!(calls, 1);
        assert_eq!(applied_paths.len(), 3);
        assert_eq!(last.len(), 3);
    }

    #[test]
    fn cli_cleanup_honeypots_parses_and_rejects_conflicting_modes() {
        let parsed = parse_cli_args([
            "ledr-daemon",
            "--cleanup-honeypots",
            "--db",
            r"C:\Temp\localedr.db",
        ])
        .expect("parse --cleanup-honeypots with --db");
        assert!(parsed.cleanup_honeypots);
        assert_eq!(parsed.db_path, Some(PathBuf::from(r"C:\Temp\localedr.db")));

        for conflict in [
            "--foreground",
            "--service",
            "--service-strict",
            "--check-unresolved-suspended",
        ] {
            let err = parse_cli_args(["ledr-daemon", "--cleanup-honeypots", conflict])
                .expect_err("conflicting mode must be rejected");
            assert!(
                err.to_string().contains("--cleanup-honeypots"),
                "unexpected error for {conflict}: {err}"
            );
        }
    }

    #[test]
    fn honeypot_cleanup_02_deletes_tracked_and_fallback_and_preserves_rejected_records() {
        use std::process::Command;

        struct TempCleanupDir(PathBuf);
        impl Drop for TempCleanupDir {
            fn drop(&mut self) {
                fn clear(dir: &Path) {
                    let Ok(entries) = std::fs::read_dir(dir) else {
                        return;
                    };
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if let Ok(meta) = std::fs::symlink_metadata(&p) {
                            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_MASK) != 0 {
                                let _ = std::fs::remove_dir(&p);
                                continue;
                            }
                            if meta.is_dir() {
                                clear(&p);
                            } else {
                                let _ = Command::new("attrib")
                                    .args(["-R", "-H", "-S", &p.to_string_lossy()])
                                    .output();
                            }
                        }
                    }
                }
                clear(&self.0);
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir().join(format!(
            "ledr-daemon-hp-cleanup-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let _guard = TempCleanupDir(base.clone());

        let db_path = base.join("localedr.db");
        let profile = base.join("UserA");
        let docs = profile.join("Documents");
        let desktop = profile.join("Desktop");
        let pictures = profile.join("Pictures");
        let victim = base.join("Victim");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::create_dir_all(&desktop).unwrap();
        std::fs::create_dir_all(&pictures).unwrap();
        std::fs::create_dir_all(&victim).unwrap();

        let mut mgr = HoneypotManager::for_user_profiles(vec![profile]);
        let deployed = mgr.deploy_honeypots().expect("deploy userA honeypots");
        assert_eq!(deployed.len(), 3);

        // Fallback-only decoy not tracked in SQLite.
        let fallback_dir = base.join("UserB").join("Documents");
        std::fs::create_dir_all(&fallback_dir).unwrap();
        let fallback_decoy = fallback_dir.join(HONEYPOT_DEFAULT_FILENAME);
        std::fs::write(&fallback_decoy, b"fallback-decoy").unwrap();

        // Junction-backed decoy tracked in SQLite must be rejected without deleting victim file.
        let victim_decoy = victim.join(HONEYPOT_DEFAULT_FILENAME);
        std::fs::write(&victim_decoy, b"victim-decoy").unwrap();
        let junc_root = base.join("EvilJunction");
        let mklink = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junc_root.to_string_lossy(),
                &victim.to_string_lossy(),
            ])
            .output()
            .expect("create junction");
        assert!(mklink.status.success(), "mklink failed");
        let evil_decoy = junc_root.join(HONEYPOT_DEFAULT_FILENAME);

        let store = LedrStore::open(&db_path).expect("open db");
        let mut tracked = deployed.clone();
        tracked.push(evil_decoy.clone());
        store
            .record_honeypot_paths(&tracked, 1_700_000_000_000)
            .expect("record tracked honeypots");
        drop(store);

        let outcome =
            cleanup_honeypots_with_db_and_fallback(&db_path, std::slice::from_ref(&fallback_decoy));
        assert_eq!(outcome.removed, 4, "3 tracked + 1 fallback decoy removed");
        assert_eq!(outcome.already_absent, 0);
        assert_eq!(outcome.failed, 1, "junction target must fail safely");
        assert_eq!(outcome.db_records_removed, 3);
        for path in &deployed {
            assert!(!path.exists(), "tracked decoy {} must be deleted", path.display());
        }
        assert!(!fallback_decoy.exists(), "fallback decoy must be deleted");
        assert!(victim_decoy.exists(), "victim decoy behind junction must remain intact");

        let remaining =
            LedrStore::list_tracked_honeypot_paths_read_only(&db_path).expect("list remaining");
        assert_eq!(
            remaining,
            vec![evil_decoy],
            "failed tracked path must remain in SQLite while cleaned paths are removed"
        );

        // Missing DB must NOT create a new DB and still deletes fallback decoys cleanly.
        let missing_db = base.join("absent").join("localedr.db");
        let fallback_only = fallback_dir.join(HONEYPOT_DEFAULT_FILENAME);
        std::fs::write(&fallback_only, b"fallback-only").unwrap();
        let outcome_no_db = cleanup_honeypots_with_db_and_fallback(
            &missing_db,
            std::slice::from_ref(&fallback_only),
        );
        assert_eq!(outcome_no_db.removed, 1);
        assert_eq!(outcome_no_db.failed, 0);
        assert!(!fallback_only.exists());
        assert!(!missing_db.exists());
        assert!(!base.join("absent").exists());

        // CLI entrypoint returns HONEYPOT_CLEANUP_PARTIAL_EXIT_CODE (4) when failures remain.
        let rc = run_cli_entrypoint_code([
            "ledr-daemon",
            "--cleanup-honeypots",
            "--db",
            &db_path.to_string_lossy(),
        ]);
        assert_eq!(rc, HONEYPOT_CLEANUP_PARTIAL_EXIT_CODE);
    }
}
