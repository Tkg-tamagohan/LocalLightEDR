//! Harmless attack-simulation CLI for validating LocalEDR detection and active defense (`AUTO-15`).

mod cli;
mod fs_scenarios;
mod lotl;
mod net;
mod types;

pub use cli::parse_cli_args;
pub use fs_scenarios::{
    prepare_sim_dir, run_cookies_open_scenario, run_cookies_open_scenario_in,
    run_cookies_open_scenario_with_hold, run_cookies_open_scenario_with_options,
    run_honeypot_write_scenario, run_honeypot_write_scenario_in,
    run_honeypot_write_scenario_with_hold, run_honeypot_write_scenario_with_options,
    run_motw_download_scenario, run_motw_download_scenario_in,
    run_motw_download_scenario_with_options, SIM_MOTW_FILENAME, SIM_MOTW_HOST_URL,
    SIM_MOTW_REFERRER_URL,
};
pub use lotl::{
    LOTL_HARMLESS_SCRIPT, build_lotl_cmd_args, encode_powershell_command_utf16le,
    run_lotl_scenario,
};
pub use net::{
    run_dns_tcp_scenario, run_dns_tcp_scenario_with_hold, run_loopback_tcp_exchange,
};
pub use types::{
    CliAction, CookiesOpenOutcome, DnsTcpOutcome, HoneypotWriteOutcome, LotlOutcome,
    MotwDownloadOutcome, PrepareDirOutcome, Scenario, SimConfig, SimReport,
};

use std::future::Future;

use anyhow::Result;
use ledr_proto::IPC_PIPE_NAME;

use cli::{print_report, print_usage};
use fs_scenarios::{
    run_cookies_open_scenario_with_cancel, run_honeypot_write_scenario_with_cancel,
    run_motw_download_scenario_with_cancel,
};
use net::{HoldOutcome, ctrl_c_signal, run_dns_tcp_scenario_with_cancel};

pub(crate) async fn execute_sim_report<F, Fut>(
    config: &SimConfig,
    mut make_cancel: F,
) -> Result<SimReport>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let mut interrupted = false;

    let lotl = match config.scenario {
        Scenario::Lotl | Scenario::All => Some(run_lotl_scenario().await?),
        Scenario::DnsTcp
        | Scenario::CookiesOpen
        | Scenario::HoneypotWrite
        | Scenario::MotwDownload => None,
    };

    let dns_tcp = if !interrupted && matches!(config.scenario, Scenario::DnsTcp | Scenario::All) {
        let (outcome, hold_outcome) = run_dns_tcp_scenario_with_cancel(
            &config.domain,
            config.port,
            config.loopback,
            config.hold_ms,
            make_cancel(),
        )
        .await?;
        if hold_outcome == HoldOutcome::Interrupted {
            interrupted = true;
        }
        Some(outcome)
    } else {
        None
    };

    let cookies_open =
        if !interrupted && matches!(config.scenario, Scenario::CookiesOpen | Scenario::All) {
            let (outcome, hold_outcome) = run_cookies_open_scenario_with_cancel(
                config.base_dir.clone(),
                config.hold_ms,
                make_cancel(),
            )
            .await?;
            if hold_outcome == HoldOutcome::Interrupted {
                interrupted = true;
            }
            Some(outcome)
        } else {
            None
        };

    let honeypot_write =
        if !interrupted && matches!(config.scenario, Scenario::HoneypotWrite | Scenario::All) {
            let (outcome, hold_outcome) = run_honeypot_write_scenario_with_cancel(
                config.base_dir.clone(),
                config.hold_ms,
                make_cancel(),
            )
            .await?;
            if hold_outcome == HoldOutcome::Interrupted {
                interrupted = true;
            }
            Some(outcome)
        } else {
            None
        };

    let motw_download =
        if !interrupted && matches!(config.scenario, Scenario::MotwDownload | Scenario::All) {
            let (outcome, _hold_outcome) = run_motw_download_scenario_with_cancel(
                config.base_dir.clone(),
                config.hold_ms,
                make_cancel(),
            )
            .await?;
            Some(outcome)
        } else {
            None
        };

    Ok(SimReport {
        target_pipe: IPC_PIPE_NAME.to_string(),
        scenario: config.scenario,
        lotl,
        dns_tcp,
        cookies_open,
        honeypot_write,
        motw_download,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match parse_cli_args(&args)? {
        CliAction::Help => {
            print_usage();
            return Ok(());
        }
        CliAction::Run(cfg) => cfg,
    };

    if let Some(prepare_dir) = &config.prepare_dir {
        let prepared = prepare_sim_dir(prepare_dir)?;
        if config.json_output {
            println!("{}", serde_json::to_string_pretty(&prepared)?);
        } else {
            println!(
                "[prepare-dir] base_dir={} cookies={} honeypot={}",
                prepared.base_dir, prepared.cookies_path, prepared.honeypot_path
            );
        }
        return Ok(());
    }

    let report = execute_sim_report(&config, ctrl_c_signal).await?;
    print_report(&report, config.json_output)
}

#[cfg(test)]
mod tests;
