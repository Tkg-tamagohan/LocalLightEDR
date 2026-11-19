//! Layer 2 LocalEDR resident core daemon (`--foreground` dev mode and Windows Service scaffold).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ledr_daemon::{start_ipc_server, DaemonConfig, DaemonEngine, Session0ToastLauncher};
use ledr_proto::{
    AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH, IPC_PIPE_NAME, PROGRAM_DATA_DIR,
    SensorBackend,
};
use ledr_rules::{
    compute_file_sha256_hex, discover_default_prerestricted_interpreters,
    load_rules_and_pruner_from_dir, EarlyPruner, SigmaEngine, DEFAULT_NRD_FEED_URLS,
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
    db_path: Option<PathBuf>,
    rules_dir: Option<PathBuf>,
    nrd_cache_path: Option<PathBuf>,
    nrd_feed_urls: Vec<String>,
    pipe_name: String,
    ui_sha256: Option<String>,
    ui_signer: Option<String>,
    ui_root_thumbprint: Option<String>,
    show_help: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            foreground: true,
            dev_bypass_auth: false,
            disable_nrd_refresh: false,
            db_path: None,
            rules_dir: None,
            nrd_cache_path: None,
            nrd_feed_urls: Vec::new(),
            pipe_name: IPC_PIPE_NAME.to_string(),
            ui_sha256: None,
            ui_signer: None,
            ui_root_thumbprint: None,
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

fn load_rules_or_default(
    explicit_dir: Option<&Path>,
) -> anyhow::Result<(SigmaEngine, EarlyPruner, Vec<ledr_proto::AllowlistRuleRecord>)> {
    if let Some(dir) = explicit_dir {
        let loaded = load_rules_and_pruner_from_dir(dir)?;
        return Ok(loaded);
    }

    let candidates = [
        PathBuf::from("rules"),
        PathBuf::from(PROGRAM_DATA_DIR).join("rules"),
    ];
    for dir in candidates {
        if dir.is_dir() {
            match load_rules_and_pruner_from_dir(&dir) {
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
    Ok((SigmaEngine::default(), EarlyPruner::default(), Vec::new()))
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli_args(std::env::args_os())?;
    if cli.show_help {
        println!(
            "ledr-daemon [--foreground | --service-strict] [--dev-bypass-auth] [--disable-nrd-refresh] [--nrd-feed-url <url>] [--nrd-cache <path>] [--db <path>] [--rules <dir>] [--pipe <name>] [--ui-sha256 <hex>] [--ui-signer <dn>] [--ui-root-thumbprint <sha1>]"
        );
        return Ok(());
    }

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
    let (sigma, pruner, default_allowlists) = load_rules_or_default(cli.rules_dir.as_deref())?;
    let rule_count = sigma.rule_count();

    for rule in &default_allowlists {
        if let Err(err) = store.upsert_rule(rule) {
            tracing::warn!(rule_id = %rule.rule_id, error = %err, "failed seeding default allowlist rule");
        }
    }

    let ui_exe = resolve_ui_exe_path(cli.foreground);
    let authorized_ui_sha256 = cli.ui_sha256.clone().or_else(|| {
        if cli.ui_signer.is_some() {
            None
        } else {
            resolve_existing_sha256(&[Path::new(AUTHORIZED_UI_EXE_PATH), ui_exe.as_path()])
        }
    });
    let authorized_bridge_sha256 =
        resolve_existing_sha256(&[Path::new(AUTHORIZED_BRIDGE_EXE_PATH)]);

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

    let defense_controller = Arc::new(WindowsDefenseController::new());
    if let Err(err) = defense_controller.init_wfp_session() {
        tracing::warn!(
            error = %err,
            "WFP dynamic session could not be initialized (non-elevated session?); outbound WFP filtering will retry on demand"
        );
    }

    let preemptive_startup_executables = discover_default_prerestricted_interpreters();
    let config = DaemonConfig {
        pipe_name: cli.pipe_name.clone(),
        dev_mode_bypass_ui_auth: cli.dev_bypass_auth,
        strict_pipe_dacl: !cli.dev_bypass_auth,
        authorized_ui_sha256,
        authorized_ui_signer: cli.ui_signer.clone(),
        authorized_ui_root_thumbprint: cli.ui_root_thumbprint.clone(),
        authorized_bridge_sha256,
        preemptive_startup_executables,
        nrd_refresh_enabled: !cli.disable_nrd_refresh,
        nrd_cache_path,
        nrd_feed_urls,
        ..DaemonConfig::default()
    };
    let wfp_defense = Arc::clone(&defense_controller);
    let outbound_firewall_enabled = config.outbound_firewall_enabled;
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
    if outbound_firewall_enabled {
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

        let service_strict = parse_cli_args(["ledr-daemon", "--service-strict"]).expect("service strict");
        assert!(!service_strict.foreground);
        assert!(!service_strict.dev_bypass_auth);

        assert!(parse_cli_args(["ledr-daemon", "--db"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--ui-sha256"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--ui-signer"]).is_err());
        // BUG_0007: --ui-signer without --ui-root-thumbprint must be rejected at startup.
        assert!(
            parse_cli_args(["ledr-daemon", "--ui-signer", "CN=LocalEDR"]).is_err(),
            "--ui-signer alone must fail (root thumbprint pin required)"
        );
        // Under --dev-bypass-auth no authorization runs, so the signer/thumbprint
        // pair is not required.
        assert!(
            parse_cli_args([
                "ledr-daemon",
                "--dev-bypass-auth",
                "--ui-signer",
                "CN=LocalEDR",
            ])
            .is_ok(),
            "--dev-bypass-auth + --ui-signer must be accepted"
        );
        assert!(
            parse_cli_args([
                "ledr-daemon",
                "--ui-signer",
                "CN=LocalEDR",
                "--ui-root-thumbprint",
                "3B1EFD3A66EA28B16697394703A72CA340A05BD5",
            ])
            .is_ok(),
            "signer + root thumbprint pair must be accepted"
        );
        assert!(parse_cli_args(["ledr-daemon", "--ui-root-thumbprint"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--nrd-feed-url"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--nrd-feed-url", "   "]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--nrd-cache"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--nrd-cache", ""]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--unknown"]).is_err());
    }
}
