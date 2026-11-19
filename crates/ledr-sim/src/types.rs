//! Shared configuration, scenario, and outcome types for `ledr-sim`.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

pub(crate) const DEFAULT_SIM_DOMAIN: &str = "example.com";
pub(crate) const DEFAULT_SIM_PORT: u16 = 80;

/// Simulation scenarios supported by `ledr-sim`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scenario {
    Lotl,
    DnsTcp,
    CookiesOpen,
    HoneypotWrite,
    All,
}

impl Scenario {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lotl" => Ok(Self::Lotl),
            "dns-tcp" => Ok(Self::DnsTcp),
            "cookies-open" => Ok(Self::CookiesOpen),
            "honeypot-write" => Ok(Self::HoneypotWrite),
            "all" | "run-all" => Ok(Self::All),
            other => bail!(
                "unknown scenario `{other}`; expected one of: lotl, dns-tcp, cookies-open, honeypot-write, all, run-all"
            ),
        }
    }
}

/// Parsed CLI configuration for a simulation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimConfig {
    pub scenario: Scenario,
    pub domain: String,
    pub port: u16,
    pub loopback: bool,
    pub json_output: bool,
    pub hold_ms: u64,
    pub prepare_dir: Option<PathBuf>,
    pub base_dir: Option<PathBuf>,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            scenario: Scenario::All,
            domain: DEFAULT_SIM_DOMAIN.to_string(),
            port: DEFAULT_SIM_PORT,
            loopback: false,
            json_output: false,
            hold_ms: 0,
            prepare_dir: None,
            base_dir: None,
        }
    }
}

/// Outcome of pre-creating dummy canary and honeypot fixtures via `--prepare-dir`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareDirOutcome {
    pub base_dir: String,
    pub cookies_path: String,
    pub honeypot_path: String,
}

/// Top-level parsed CLI directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Help,
    Run(SimConfig),
}

/// Outcome of the harmless LOTL `cmd.exe -> powershell.exe -EncodedCommand` simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotlOutcome {
    pub spawned_pid: u32,
    pub exit_code: i32,
    pub command_line: String,
    pub stdout: String,
}

/// Outcome of the harmless DNS resolution + brief TCP connection simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTcpOutcome {
    pub domain: String,
    pub resolved_ips: Vec<IpAddr>,
    pub connected_addr: Option<String>,
    pub used_loopback: bool,
    pub connected: bool,
    pub note: String,
}

/// Outcome of the harmless dummy Chrome `Cookies` open/read simulation (`L-05`, `AUTO-15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookiesOpenOutcome {
    pub target_path: String,
    pub bytes_read: usize,
    pub opened: bool,
}

/// Outcome of the harmless honeypot decoy 1-byte append simulation (`L-06`, `AUTO-15`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneypotWriteOutcome {
    pub target_path: String,
    pub initial_bytes: usize,
    pub appended_bytes: usize,
    pub final_bytes: usize,
}

/// Combined structured report emitted by `ledr-sim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimReport {
    pub target_pipe: String,
    pub scenario: Scenario,
    pub lotl: Option<LotlOutcome>,
    pub dns_tcp: Option<DnsTcpOutcome>,
    pub cookies_open: Option<CookiesOpenOutcome>,
    pub honeypot_write: Option<HoneypotWriteOutcome>,
}
