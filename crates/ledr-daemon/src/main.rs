//! Layer 2 LocalEDR resident core daemon (`--foreground` dev mode and Windows Service scaffold).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ledr_daemon::{start_ipc_server, DaemonConfig, DaemonEngine};
use ledr_proto::{SensorBackend, IPC_PIPE_NAME, PROGRAM_DATA_DIR};
use ledr_rules::{load_rules_and_pruner_from_dir, EarlyPruner, SigmaEngine};
use ledr_sensor_win::etw::{
    capture_running_processes, EventSinkFn, NoopSensorBackend, WindowsEtwSensor,
    DEFAULT_ETW_SESSION_NAME,
};
use ledr_sensor_win::privileges::enable_required_privileges;
use ledr_store::LedrStore;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliArgs {
    foreground: bool,
    db_path: Option<PathBuf>,
    rules_dir: Option<PathBuf>,
    pipe_name: String,
    show_help: bool,
}

impl Default for CliArgs {
    fn default() -> Self {
        Self {
            foreground: true,
            db_path: None,
            rules_dir: None,
            pipe_name: IPC_PIPE_NAME.to_string(),
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
            "--help" | "-h" => parsed.show_help = true,
            other => anyhow::bail!("unrecognized argument: {other}"),
        }
    }

    Ok(parsed)
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = parse_cli_args(std::env::args_os())?;
    if cli.show_help {
        println!(
            "ledr-daemon [--foreground] [--db <path>] [--rules <dir>] [--pipe <name>]"
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

    let config = DaemonConfig {
        pipe_name: cli.pipe_name.clone(),
        dev_mode_bypass_ui_auth: cli.foreground,
        ..DaemonConfig::default()
    };
    let engine = DaemonEngine::start(store, sigma, pruner, config);

    // Start ETW capture directly into TwoLaneSender BEFORE Toolhelp32 snapshot capture so
    // processes spawned or exiting during snapshot enumeration are not missed (BUG_0001, BUG_0006).
    let bridge_sender = engine.sender();
    let etw_sink: EventSinkFn = Arc::new(move |ev| bridge_sender.blocking_send(ev).is_ok());
    let mut etw_sensor = WindowsEtwSensor::with_sink(etw_sink, DEFAULT_ETW_SESSION_NAME);
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

    let initial_processes = capture_running_processes();
    let seeded_count = engine.seed_processes(initial_processes)?;
    tracing::info!(
        seeded_processes = seeded_count,
        sigma_rules = rule_count,
        db = %db_path.display(),
        "initialized ActiveProcessTable and SQLite WAL store"
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
        assert_eq!(def.db_path, None);
        assert_eq!(def.rules_dir, None);
        assert_eq!(def.pipe_name, IPC_PIPE_NAME);

        let custom = parse_cli_args([
            "ledr-daemon",
            "--foreground",
            "--db",
            r"C:\Temp\test.db",
            "--rules",
            r"C:\Temp\rules",
            "--pipe",
            r"\\.\pipe\custom-pipe",
        ])
        .expect("custom args");
        assert!(custom.foreground);
        assert_eq!(custom.db_path, Some(PathBuf::from(r"C:\Temp\test.db")));
        assert_eq!(custom.rules_dir, Some(PathBuf::from(r"C:\Temp\rules")));
        assert_eq!(custom.pipe_name, r"\\.\pipe\custom-pipe");

        assert!(parse_cli_args(["ledr-daemon", "--db"]).is_err());
        assert!(parse_cli_args(["ledr-daemon", "--unknown"]).is_err());
    }
}
