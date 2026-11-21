//! CLI argument parsing and stdout usage/report formatting for `ledr-sim`.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use ledr_proto::IPC_PIPE_NAME;

use super::types::{
    CliAction, DEFAULT_SIM_DOMAIN, DEFAULT_SIM_PORT, Scenario, SimConfig, SimReport,
};

/// Parses CLI arguments (excluding `argv[0]`) into [`CliAction`].
pub fn parse_cli_args<I, S>(args: I) -> Result<CliAction>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let items: Vec<String> = args.into_iter().map(|s| s.as_ref().to_string()).collect();
    if items.is_empty() {
        return Ok(CliAction::Help);
    }

    let mut config = SimConfig::default();
    let mut scenario_set = false;
    let mut idx = 0;

    while idx < items.len() {
        let arg = items[idx].as_str();
        match arg {
            "-h" | "--help" | "help" => return Ok(CliAction::Help),
            "--loopback" => {
                config.loopback = true;
                idx += 1;
            }
            "--json" => {
                config.json_output = true;
                idx += 1;
            }
            "--scenario" => {
                let val = items
                    .get(idx + 1)
                    .context("missing value after `--scenario`")?;
                config.scenario = Scenario::parse(val)?;
                scenario_set = true;
                idx += 2;
            }
            "--domain" => {
                let val = items
                    .get(idx + 1)
                    .context("missing value after `--domain`")?;
                if val.trim().is_empty() {
                    bail!("`--domain` value must not be empty");
                }
                config.domain = val.trim().to_string();
                idx += 2;
            }
            "--port" => {
                let val = items.get(idx + 1).context("missing value after `--port`")?;
                let port: u16 = val
                    .parse()
                    .with_context(|| format!("invalid `--port` value `{val}`"))?;
                if port == 0 {
                    bail!("`--port` must be between 1 and 65535");
                }
                config.port = port;
                idx += 2;
            }
            "--hold-ms" => {
                let val = items
                    .get(idx + 1)
                    .context("missing value after `--hold-ms`")?;
                config.hold_ms = val
                    .parse()
                    .with_context(|| format!("invalid `--hold-ms` value `{val}`"))?;
                idx += 2;
            }
            "--prepare-dir" => {
                let val = items
                    .get(idx + 1)
                    .context("missing value after `--prepare-dir`")?;
                config.prepare_dir = Some(parse_nonempty_dir("--prepare-dir", val)?);
                idx += 2;
            }
            "--base-dir" => {
                let val = items
                    .get(idx + 1)
                    .context("missing value after `--base-dir`")?;
                config.base_dir = Some(parse_nonempty_dir("--base-dir", val)?);
                idx += 2;
            }
            val if val.starts_with("--scenario=") => {
                let raw = &val["--scenario=".len()..];
                config.scenario = Scenario::parse(raw)?;
                scenario_set = true;
                idx += 1;
            }
            val if val.starts_with("--domain=") => {
                let raw = val["--domain=".len()..].trim();
                if raw.is_empty() {
                    bail!("`--domain` value must not be empty");
                }
                config.domain = raw.to_string();
                idx += 1;
            }
            val if val.starts_with("--port=") => {
                let raw = &val["--port=".len()..];
                let port: u16 = raw
                    .parse()
                    .with_context(|| format!("invalid `--port` value `{raw}`"))?;
                if port == 0 {
                    bail!("`--port` must be between 1 and 65535");
                }
                config.port = port;
                idx += 1;
            }
            val if val.starts_with("--hold-ms=") => {
                let raw = &val["--hold-ms=".len()..];
                config.hold_ms = raw
                    .parse()
                    .with_context(|| format!("invalid `--hold-ms` value `{raw}`"))?;
                idx += 1;
            }
            val if val.starts_with("--prepare-dir=") => {
                let raw = &val["--prepare-dir=".len()..];
                config.prepare_dir = Some(parse_nonempty_dir("--prepare-dir", raw)?);
                idx += 1;
            }
            val if val.starts_with("--base-dir=") => {
                let raw = &val["--base-dir=".len()..];
                config.base_dir = Some(parse_nonempty_dir("--base-dir", raw)?);
                idx += 1;
            }
            positional if !positional.starts_with('-') => {
                if scenario_set {
                    bail!("unexpected positional argument `{positional}`");
                }
                config.scenario = Scenario::parse(positional)?;
                scenario_set = true;
                idx += 1;
            }
            unknown => bail!("unknown argument `{unknown}`"),
        }
    }

    Ok(CliAction::Run(config))
}

fn parse_nonempty_dir(flag: &str, raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("`{flag}` value must not be empty");
    }
    Ok(PathBuf::from(trimmed))
}

pub(crate) fn print_usage() {
    println!("ledr-sim (Phase 2 harmless telemetry and defense simulator)");
    println!("Target daemon pipe: {IPC_PIPE_NAME}");
    println!();
    println!("Usage:");
    println!("  ledr-sim <lotl|dns-tcp|cookies-open|honeypot-write|motw-download|run-all> [OPTIONS]");
    println!("  ledr-sim --scenario <lotl|dns-tcp|cookies-open|honeypot-write|motw-download|all> [OPTIONS]");
    println!("  ledr-sim --prepare-dir <DIR> [--json]");
    println!();
    println!("Options:");
    println!("  --domain <HOST>      Domain to resolve/connect in dns-tcp (default: {DEFAULT_SIM_DOMAIN})");
    println!("  --port <PORT>        TCP port for dns-tcp (default: {DEFAULT_SIM_PORT})");
    println!("  --loopback           Use local 127.0.0.1 TCP listener without external traffic");
    println!("  --hold-ms <MS>       Keep process alive after canary/honeypot access for E2E checks");
    println!("  --prepare-dir <DIR>  Pre-create dummy canary/honeypot fixtures in <DIR> and exit");
    println!("  --base-dir <DIR>     Run file scenarios inside <DIR> without creating/deleting a temp dir");
    println!("  --json               Print structured JSON simulation report");
    println!("  -h, --help           Show this help message");
}

pub(crate) fn print_report(report: &SimReport, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("ledr-sim target pipe: {}", report.target_pipe);
    if let Some(lotl) = &report.lotl {
        println!(
            "[lotl] pid={} exit_code={} stdout={:?} cmd={}",
            lotl.spawned_pid, lotl.exit_code, lotl.stdout, lotl.command_line
        );
    }
    if let Some(net) = &report.dns_tcp {
        println!(
            "[dns-tcp] domain={} ips={:?} connected={} addr={} loopback={} ({})",
            net.domain,
            net.resolved_ips,
            net.connected,
            net.connected_addr.as_deref().unwrap_or("none"),
            net.used_loopback,
            net.note
        );
    }
    if let Some(cookies) = &report.cookies_open {
        println!(
            "[cookies-open] opened={} bytes_read={} path={}",
            cookies.opened, cookies.bytes_read, cookies.target_path
        );
    }
    if let Some(honeypot) = &report.honeypot_write {
        println!(
            "[honeypot-write] initial_bytes={} appended_bytes={} final_bytes={} path={}",
            honeypot.initial_bytes,
            honeypot.appended_bytes,
            honeypot.final_bytes,
            honeypot.target_path
        );
    }
    if let Some(motw) = &report.motw_download {
        println!(
            "[motw-download] verified={} zone_id={} sha256={} host_url={} referrer_url={} path={}",
            motw.verified_roundtrip,
            motw.zone_id,
            motw.sha256,
            motw.host_url,
            motw.referrer_url,
            motw.target_path
        );
    }
    Ok(())
}
