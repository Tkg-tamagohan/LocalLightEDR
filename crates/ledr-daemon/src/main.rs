//! Layer 2 LocalEDR resident core daemon (`--foreground` dev mode and Windows Service scaffold).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use ledr_daemon::{
    start_ipc_server, DaemonConfig, DaemonEngine, OutboundEnforcementMode, Session0ToastLauncher,
    DEFAULT_MAX_CONCURRENT_IPC_CLIENTS,
};
use ledr_proto::{
    AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH, IPC_PIPE_NAME, PROGRAM_DATA_DIR,
    SensorBackend,
};
use ledr_rules::{
    compute_file_sha256_hex, discover_default_prerestricted_interpreters, load_rules_dir,
    LoadedRulesDir, DEFAULT_NRD_FEED_URLS,
};
use ledr_sensor_win::defense::{HoneypotManager, WindowsDefenseController};
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
    show_help: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            foreground: true,
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
    let mut iter = args.into_iter().map(Into::into);
    let _exe = iter.next();

    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy();
        match text.as_ref() {
            "--foreground" => parsed.foreground = true,
            "--service-strict" => parsed.foreground = false,
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
            "--help" | "-h" => parsed.show_help = true,
            other => anyhow::bail!("unrecognized argument: {other}"),
        }
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

fn resolve_ui_exe_path(foreground: bool) -> PathBuf {
    if !foreground {
        return PathBuf::from(AUTHORIZED_UI_EXE_PATH);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("ledr-ui.exe");
            if sibling.is_file() {
                return sibling;
            }
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

fn main() -> anyhow::Result<()> {
    let cli = parse_cli_args(std::env::args_os())?;
    if cli.show_help {
        println!(
            "ledr-daemon [--foreground | --service-strict] [--dev-bypass-auth] [--outbound-mode <enforce|preemptive-only|audit>] [--disable-outbound-firewall] [--resume-suspended-on-shutdown] [--disable-nrd-refresh] [--nrd-feed-url <url>] [--nrd-cache <path>] [--db <path>] [--rules <dir>] [--pipe <name>] [--ui-sha256 <hex>] [--ui-signer <dn>] [--ui-root-thumbprint <sha1>] [--bridge-sha256 <hex>] [--bridge-signer <dn>] [--bridge-root-thumbprint <sha1>]"
        );
        return Ok(());
    }

    let runtime = build_daemon_runtime()?;
    runtime.block_on(run_daemon(cli))
}

/// Builds the [`DaemonConfig`] for `ledr-daemon` CLI execution.
///
/// Always enables `strict_pipe_dacl` (`SERVICE_PIPE_SDDL`) even when `--dev-bypass-auth`
/// is set, so an elevated daemon grants Interactive Users (`ledr-ui.exe` / `ledr-bridge-nm.exe`)
/// read/write access (`0x12019B`) across elevation boundaries.
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
        outbound_firewall_enabled,
        outbound_enforcement_mode: cli.outbound_mode,
        resume_suspended_on_shutdown,
        preemptive_startup_executables,
        nrd_refresh_enabled: !cli.disable_nrd_refresh,
        nrd_cache_path,
        nrd_feed_urls,
        ..DaemonConfig::default()
    }
}

async fn run_daemon(cli: CliArgs) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let priv_report = enable_required_privileges();
    tracing::info!(
        system_profile = priv_report.system_profile,
        debug = priv_report.debug,
        security = priv_report.security,
        error = ?priv_report.error_message,
        "privilege enablement completed"
    );

    let (store, db_path) = open_store_with_fallback(cli.db_path.as_deref())?;
    let loaded_rules = load_rules_or_default(cli.rules_dir.as_deref())?;
    apply_startup_rules(&store, &loaded_rules);
    let LoadedRulesDir {
        sigma,
        pruner,
        ..
    } = loaded_rules;
    let rule_count = sigma.rule_count();

    let ui_exe = resolve_ui_exe_path(cli.foreground);
    let authorized_ui_sha256 = cli.ui_sha256.clone().or_else(|| {
        if cli.ui_signer.is_some() {
            None
        } else {
            resolve_existing_sha256(&[Path::new(AUTHORIZED_UI_EXE_PATH), ui_exe.as_path()])
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

    let mut honeypot_mgr = HoneypotManager::new();
    let honeypot_paths = match honeypot_mgr.deploy_honeypots() {
        Ok(paths) => {
            tracing::info!(honeypots = paths.len(), "deployed honeypot canary files");
            paths
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed deploying one or more honeypot canary files; continuing with partial list"
            );
            honeypot_mgr.deployed_paths().to_vec()
        }
    };

    // Start ETW capture directly into ClassifiedEventSender BEFORE Toolhelp32 snapshot capture so
    // processes spawned or exiting during snapshot enumeration are not missed (BUG_0001, BUG_0006, L-10).
    let bridge_sender = engine.classified_sender();
    let etw_sink: EventSinkFn = Arc::new(move |ev| bridge_sender.blocking_send(ev).is_ok());
    let mut etw_sensor = WindowsEtwSensor::with_sink(etw_sink, DEFAULT_ETW_SESSION_NAME);
    etw_sensor.set_honeypot_paths(honeypot_paths);
    let active_backend: Box<dyn SensorBackend> = match etw_sensor.start() {
        Ok(()) => {
            tracing::info!("WindowsEtwSensor real-time ETW trace started");
            Box::new(etw_sensor)
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "WindowsEtwSensor could not start (non-elevated session?); falling back to NoopSensorBackend"
            );
            drop(etw_sensor);
            let mut noop = NoopSensorBackend;
            let _ = noop.start();
            Box::new(noop)
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
    tracing::info!(
        pipe = %ipc_handle.pipe_name(),
        foreground = cli.foreground,
        "ledr-daemon listening on Named Pipe IPC; press Ctrl+C to shut down"
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("Ctrl+C received; initiating graceful shutdown and WAL checkpoint");

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

    #[test]
    fn cli_parses_defaults_and_flags() {
        let def = parse_cli_args(["ledr-daemon"]).expect("default args");
        assert!(def.foreground);
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
}
