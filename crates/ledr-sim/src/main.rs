//! Harmless attack-simulation CLI for validating LocalEDR detection and active defense (`AUTO-15`).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ledr_proto::{HONEYPOT_DEFAULT_FILENAME, IPC_PIPE_NAME};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::process::Command;

/// Harmless PowerShell command encoded into UTF-16LE Base64 for the LOTL scenario.
pub const LOTL_HARMLESS_SCRIPT: &str = "Write-Output LocalEDR-Sim-LOTL";
const DEFAULT_SIM_DOMAIN: &str = "example.com";
const DEFAULT_SIM_PORT: u16 = 80;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);
const LOTL_TIMEOUT: Duration = Duration::from_secs(20);
static TEMP_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

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
    fn parse(value: &str) -> Result<Self> {
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
        }
    }
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

/// Parses CLI arguments (excluding argv[0]) into [`CliAction`].
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

/// Encodes `script` into PowerShell `-EncodedCommand` UTF-16LE Base64 format.
pub fn encode_powershell_command_utf16le(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    base64_encode(&bytes)
}

/// Builds the argument vector passed to `cmd.exe` for the harmless LOTL simulation.
pub fn build_lotl_cmd_args() -> Vec<String> {
    let encoded = encode_powershell_command_utf16le(LOTL_HARMLESS_SCRIPT);
    vec![
        "/c".to_string(),
        "powershell.exe".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-EncodedCommand".to_string(),
        encoded,
    ]
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;

    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        out.push(TABLE[(n & 0x3F) as usize] as char);
        i += 3;
    }

    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

/// Spawns `cmd.exe /c powershell.exe -NoProfile -NonInteractive -EncodedCommand <b64>`.
pub async fn run_lotl_scenario() -> Result<LotlOutcome> {
    let args = build_lotl_cmd_args();
    let command_line = format!("cmd.exe {}", args.join(" "));

    let child = Command::new("cmd.exe")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn cmd.exe for LOTL simulation")?;

    let spawned_pid = child.id().unwrap_or(0);
    let output = tokio::time::timeout(LOTL_TIMEOUT, child.wait_with_output())
        .await
        .context("timed out waiting for harmless LOTL powershell command")?
        .context("failed waiting for cmd.exe child process")?;

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    Ok(LotlOutcome {
        spawned_pid,
        exit_code,
        command_line,
        stdout,
    })
}

/// Resolves `domain:port` and connects briefly over TCP, falling back to an in-process
/// loopback TCP listener when `--loopback` is requested or the host is offline.
pub async fn run_dns_tcp_scenario(
    domain: &str,
    port: u16,
    force_loopback: bool,
) -> Result<DnsTcpOutcome> {
    if force_loopback {
        return run_loopback_tcp_exchange("forced --loopback mode").await;
    }

    let lookup_res = tokio::time::timeout(NETWORK_TIMEOUT, lookup_host((domain, port))).await;
    let addrs: Vec<SocketAddr> = match lookup_res {
        Ok(Ok(iter)) => iter.collect(),
        Ok(Err(err)) => {
            return run_loopback_tcp_exchange(&format!(
                "DNS lookup for `{domain}:{port}` unavailable ({err}); fell back to loopback"
            ))
            .await;
        }
        Err(_) => {
            return run_loopback_tcp_exchange(&format!(
                "DNS lookup for `{domain}:{port}` timed out; fell back to loopback"
            ))
            .await;
        }
    };

    let mut resolved_ips = Vec::new();
    for addr in &addrs {
        if !resolved_ips.contains(&addr.ip()) {
            resolved_ips.push(addr.ip());
        }
    }

    for addr in addrs {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(NETWORK_TIMEOUT, TcpStream::connect(addr)).await
        {
            let _ = stream.shutdown().await;
            return Ok(DnsTcpOutcome {
                domain: domain.to_string(),
                resolved_ips,
                connected_addr: Some(addr.to_string()),
                used_loopback: false,
                connected: true,
                note: "DNS resolution and TCP connect completed".to_string(),
            });
        }
    }

    run_loopback_tcp_exchange(&format!(
        "TCP connect to `{domain}:{port}` unreachable offline; fell back to loopback"
    ))
    .await
}

/// Runs a self-contained loopback TCP listener + client exchange for offline validation.
pub async fn run_loopback_tcp_exchange(reason: &str) -> Result<DnsTcpOutcome> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind loopback TCP listener")?;
    let bound_addr = listener.local_addr()?;

    let mut resolved_ips = Vec::new();
    if let Ok(iter) = lookup_host(("localhost", bound_addr.port())).await {
        for addr in iter {
            if !resolved_ips.contains(&addr.ip()) {
                resolved_ips.push(addr.ip());
            }
        }
    }
    if resolved_ips.is_empty() {
        resolved_ips.push(bound_addr.ip());
    }

    let server_task = tokio::spawn(async move {
        if let Ok((mut sock, _peer)) = listener.accept().await {
            let _ = handle_ping_server(&mut sock).await;
        }
    });

    let mut client = match TcpStream::connect(bound_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            server_task.abort();
            return Err(err).context("failed to connect to loopback TCP listener");
        }
    };
    let _ = exchange_ping_ack(&mut client).await?;
    let _ = server_task.await;

    Ok(DnsTcpOutcome {
        domain: "localhost".to_string(),
        resolved_ips,
        connected_addr: Some(bound_addr.to_string()),
        used_loopback: true,
        connected: true,
        note: reason.to_string(),
    })
}

async fn handle_ping_server<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<String> {
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).await?;
    stream.write_all(b"LocalEDR-Sim-Ack\n").await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

async fn exchange_ping_ack<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Result<String> {
    stream.write_all(b"LocalEDR-Sim-Ping\n").await?;
    stream.flush().await?;
    let mut ack = [0u8; 64];
    let n = match tokio::time::timeout(NETWORK_TIMEOUT, stream.read(&mut ack)).await {
        Ok(Ok(count)) => count,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => 0,
    };
    let _ = stream.shutdown().await;
    Ok(String::from_utf8_lossy(&ack[..n]).into_owned())
}

struct TempSimDir(PathBuf);

impl TempSimDir {
    fn new(prefix: &str) -> Result<Self> {
        let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ledr-sim-{prefix}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create temp simulation dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempSimDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Creates a harmless dummy `Google\Chrome\User Data\Default\Cookies` file in a temporary
/// directory, opens and reads it cleanly, and returns [`CookiesOpenOutcome`].
pub async fn run_cookies_open_scenario() -> Result<CookiesOpenOutcome> {
    run_cookies_open_scenario_with_hold(0).await
}

/// Like [`run_cookies_open_scenario`], holding the process alive for `hold_ms` milliseconds
/// after opening `Cookies` so real-time ETW + `NtSuspendProcess` E2E tests can observe suspension.
pub async fn run_cookies_open_scenario_with_hold(hold_ms: u64) -> Result<CookiesOpenOutcome> {
    tokio::task::spawn_blocking(move || {
        let temp_dir = TempSimDir::new("cookies")?;
        let outcome = run_cookies_open_scenario_in(temp_dir.path())?;
        if hold_ms > 0 {
            std::thread::sleep(Duration::from_millis(hold_ms));
        }
        Ok(outcome)
    })
    .await
    .context("cookies-open simulation task panicked")?
}

/// Runs the dummy `Cookies` open/read simulation under `base_dir` without removing `base_dir`.
pub fn run_cookies_open_scenario_in(base_dir: &Path) -> Result<CookiesOpenOutcome> {
    const DUMMY_COOKIE_PAYLOAD: &[u8] = b"SQLite format 3\0LocalEDR-Sim-Dummy-Cookies";
    let cookie_path = base_dir
        .join("Google")
        .join("Chrome")
        .join("User Data")
        .join("Default")
        .join("Cookies");
    if let Some(parent) = cookie_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create dummy Chrome profile dir {}", parent.display())
        })?;
    }

    {
        let mut writer = File::create(&cookie_path)
            .with_context(|| format!("failed to create dummy Cookies {}", cookie_path.display()))?;
        writer.write_all(DUMMY_COOKIE_PAYLOAD)?;
        writer.flush()?;
    }

    let mut reader = File::open(&cookie_path)
        .with_context(|| format!("failed to open dummy Cookies {}", cookie_path.display()))?;
    let mut buf = Vec::new();
    let bytes_read = reader
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read dummy Cookies {}", cookie_path.display()))?;

    Ok(CookiesOpenOutcome {
        target_path: cookie_path.display().to_string(),
        bytes_read,
        opened: true,
    })
}

/// Creates a harmless temp `!00_LocalEDR_Canary_DoNotEdit.docx` file, appends 1 byte, and
/// returns [`HoneypotWriteOutcome`].
pub async fn run_honeypot_write_scenario() -> Result<HoneypotWriteOutcome> {
    run_honeypot_write_scenario_with_hold(0).await
}

/// Like [`run_honeypot_write_scenario`], spawning a harmless child process and holding for
/// `hold_ms` milliseconds after modifying the decoy file so tree-level `NtSuspendProcess` E2E
/// tests can verify parent + child suspension (`L-07`).
pub async fn run_honeypot_write_scenario_with_hold(hold_ms: u64) -> Result<HoneypotWriteOutcome> {
    tokio::task::spawn_blocking(move || {
        let temp_dir = TempSimDir::new("honeypot")?;
        let _child_guard = if hold_ms > 0 {
            let ping_count = (hold_ms / 1000).saturating_add(2).clamp(2, 120);
            let cmd = format!("ping -n {ping_count} 127.0.0.1 >nul");
            let child = std::process::Command::new("cmd.exe")
                .args(["/c", &cmd])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok();
            ChildGuard(child)
        } else {
            ChildGuard(None)
        };

        let outcome = run_honeypot_write_scenario_in(temp_dir.path())?;
        if hold_ms > 0 {
            std::thread::sleep(Duration::from_millis(hold_ms));
        }
        Ok(outcome)
    })
    .await
    .context("honeypot-write simulation task panicked")?
}

/// Runs the dummy honeypot 1-byte append simulation under `base_dir` without removing `base_dir`.
pub fn run_honeypot_write_scenario_in(base_dir: &Path) -> Result<HoneypotWriteOutcome> {
    const INITIAL_HONEYPOT_BYTES: &[u8] = b"LocalEDR-Sim-Honeypot-Decoy\n";
    const APPEND_ONE_BYTE: &[u8] = b"!";

    std::fs::create_dir_all(base_dir)
        .with_context(|| format!("failed to create honeypot dir {}", base_dir.display()))?;
    let honeypot_path = base_dir.join(HONEYPOT_DEFAULT_FILENAME);

    {
        let mut creator = File::create(&honeypot_path)
            .with_context(|| format!("failed to create honeypot {}", honeypot_path.display()))?;
        creator.write_all(INITIAL_HONEYPOT_BYTES)?;
        creator.flush()?;
    }

    {
        let mut appender = OpenOptions::new()
            .append(true)
            .open(&honeypot_path)
            .with_context(|| format!("failed to open honeypot {} for append", honeypot_path.display()))?;
        appender.write_all(APPEND_ONE_BYTE)?;
        appender.flush()?;
    }

    let final_bytes = std::fs::metadata(&honeypot_path)
        .with_context(|| format!("failed to stat honeypot {}", honeypot_path.display()))?
        .len() as usize;

    Ok(HoneypotWriteOutcome {
        target_path: honeypot_path.display().to_string(),
        initial_bytes: INITIAL_HONEYPOT_BYTES.len(),
        appended_bytes: APPEND_ONE_BYTE.len(),
        final_bytes,
    })
}

fn print_usage() {
    println!("ledr-sim (Phase 2 harmless telemetry and defense simulator)");
    println!("Target daemon pipe: {IPC_PIPE_NAME}");
    println!();
    println!("Usage:");
    println!("  ledr-sim <lotl|dns-tcp|cookies-open|honeypot-write|run-all> [OPTIONS]");
    println!("  ledr-sim --scenario <lotl|dns-tcp|cookies-open|honeypot-write|all> [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --domain <HOST>   Domain to resolve/connect in dns-tcp (default: {DEFAULT_SIM_DOMAIN})");
    println!("  --port <PORT>     TCP port for dns-tcp (default: {DEFAULT_SIM_PORT})");
    println!("  --loopback        Use local 127.0.0.1 TCP listener without external traffic");
    println!("  --hold-ms <MS>    Keep process alive after canary/honeypot access for E2E checks");
    println!("  --json            Print structured JSON simulation report");
    println!("  -h, --help        Show this help message");
}

fn print_report(report: &SimReport, json_output: bool) -> Result<()> {
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
    Ok(())
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

    let lotl = match config.scenario {
        Scenario::Lotl | Scenario::All => Some(run_lotl_scenario().await?),
        Scenario::DnsTcp | Scenario::CookiesOpen | Scenario::HoneypotWrite => None,
    };

    let dns_tcp = match config.scenario {
        Scenario::DnsTcp | Scenario::All => {
            Some(run_dns_tcp_scenario(&config.domain, config.port, config.loopback).await?)
        }
        Scenario::Lotl | Scenario::CookiesOpen | Scenario::HoneypotWrite => None,
    };

    let cookies_open = match config.scenario {
        Scenario::CookiesOpen | Scenario::All => {
            Some(run_cookies_open_scenario_with_hold(config.hold_ms).await?)
        }
        Scenario::Lotl | Scenario::DnsTcp | Scenario::HoneypotWrite => None,
    };

    let honeypot_write = match config.scenario {
        Scenario::HoneypotWrite | Scenario::All => {
            Some(run_honeypot_write_scenario_with_hold(config.hold_ms).await?)
        }
        Scenario::Lotl | Scenario::DnsTcp | Scenario::CookiesOpen => None,
    };

    let report = SimReport {
        target_pipe: IPC_PIPE_NAME.to_string(),
        scenario: config.scenario,
        lotl,
        dns_tcp,
        cookies_open,
        honeypot_write,
    };

    print_report(&report, config.json_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_decode(input: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let vals: Vec<u8> = input
            .bytes()
            .filter(|&b| b != b'=')
            .map(|b| match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64 byte: {b}"),
            })
            .collect();

        for chunk in vals.chunks(4) {
            if chunk.len() >= 2 {
                out.push((chunk[0] << 2) | (chunk[1] >> 4));
            }
            if chunk.len() >= 3 {
                out.push((chunk[1] << 4) | (chunk[2] >> 2));
            }
            if chunk.len() == 4 {
                out.push((chunk[2] << 6) | chunk[3]);
            }
        }
        out
    }

    #[test]
    fn sim_01_cli_arg_parsing() {
        assert_eq!(parse_cli_args::<[&str; 0], &str>([]).unwrap(), CliAction::Help);
        assert_eq!(parse_cli_args(["--help"]).unwrap(), CliAction::Help);

        assert_eq!(
            parse_cli_args(["lotl"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::Lotl,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["dns-tcp", "--domain", "example.org", "--port", "8443", "--loopback"])
                .unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::DnsTcp,
                domain: "example.org".to_string(),
                port: 8443,
                loopback: true,
                json_output: false,
                hold_ms: 0,
            })
        );
        assert_eq!(
            parse_cli_args(["cookies-open", "--hold-ms", "1500"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::CookiesOpen,
                hold_ms: 1500,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["honeypot-write", "--hold-ms=250"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::HoneypotWrite,
                hold_ms: 250,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["--scenario", "all", "--json"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::All,
                json_output: true,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["run-all"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::All,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["cookies-open", "--json"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::CookiesOpen,
                json_output: true,
                ..SimConfig::default()
            })
        );
        assert_eq!(
            parse_cli_args(["--scenario=honeypot-write"]).unwrap(),
            CliAction::Run(SimConfig {
                scenario: Scenario::HoneypotWrite,
                ..SimConfig::default()
            })
        );

        assert!(parse_cli_args(["--scenario"]).is_err());
        assert!(parse_cli_args(["--scenario", "unknown"]).is_err());
        assert!(parse_cli_args(["--port", "0"]).is_err());
        assert!(parse_cli_args(["--unknown-flag"]).is_err());
    }

    #[tokio::test]
    async fn sim_02_loopback_tcp_and_encoded_command() {
        let args = build_lotl_cmd_args();
        assert_eq!(args[0], "/c");
        assert_eq!(args[1], "powershell.exe");
        assert_eq!(args[2], "-NoProfile");
        assert_eq!(args[3], "-NonInteractive");
        assert_eq!(args[4], "-EncodedCommand");

        let decoded_bytes = base64_decode(&args[5]);
        let decoded_u16: Vec<u16> = decoded_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        let decoded_script = String::from_utf16(&decoded_u16).expect("valid UTF-16LE");
        assert_eq!(decoded_script, LOTL_HARMLESS_SCRIPT);

        let (mut client_dup, mut server_dup) = tokio::io::duplex(128);
        let srv = tokio::spawn(async move { handle_ping_server(&mut server_dup).await });
        let ack = exchange_ping_ack(&mut client_dup)
            .await
            .expect("duplex ping/ack exchange should succeed");
        let ping = srv.await.expect("server task").expect("server read/write");
        assert_eq!(ping, "LocalEDR-Sim-Ping\n");
        assert_eq!(ack, "LocalEDR-Sim-Ack\n");

        match run_dns_tcp_scenario("example.com", 80, true).await {
            Ok(outcome) => {
                assert!(outcome.used_loopback);
                assert!(outcome.connected);
                assert!(!outcome.resolved_ips.is_empty());
                assert!(
                    outcome
                        .connected_addr
                        .as_deref()
                        .is_some_and(|a| a.starts_with("127.0.0.1:"))
                );
            }
            Err(err) => {
                // Restricted Windows AppContainer sandboxes block Winsock connect() with WSAEACCES (10013).
                let is_sandbox_socket_block = err.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io_err| {
                            io_err.kind() == std::io::ErrorKind::PermissionDenied
                                || io_err.raw_os_error() == Some(10013)
                        })
                });
                assert!(
                    is_sandbox_socket_block,
                    "unexpected loopback dns-tcp failure: {err:#}"
                );
            }
        }
    }

    #[tokio::test]
    async fn sim_p2_01_cookies_open_scenario() {
        let outcome = run_cookies_open_scenario()
            .await
            .expect("cookies-open scenario should succeed");
        assert!(outcome.opened);
        assert!(outcome.bytes_read > 0);
        assert!(
            outcome
                .target_path
                .ends_with(r"Google\Chrome\User Data\Default\Cookies")
                || outcome
                    .target_path
                    .ends_with("Google/Chrome/User Data/Default/Cookies"),
            "unexpected cookie path: {}",
            outcome.target_path
        );
        // Temporary scenario file must have been cleaned up on completion.
        assert!(
            !Path::new(&outcome.target_path).exists(),
            "temp cookie path should be cleaned up"
        );

        let temp = TempSimDir::new("test-cookies").expect("temp dir");
        let in_dir = run_cookies_open_scenario_in(temp.path()).expect("cookies-open in temp dir");
        assert!(in_dir.opened);
        assert!(in_dir.bytes_read > 0);
        assert!(Path::new(&in_dir.target_path).is_file());
    }

    #[tokio::test]
    async fn sim_p2_02_honeypot_write_scenario() {
        let outcome = run_honeypot_write_scenario()
            .await
            .expect("honeypot-write scenario should succeed");
        assert_eq!(outcome.appended_bytes, 1);
        assert_eq!(outcome.final_bytes, outcome.initial_bytes + 1);
        assert!(
            outcome.target_path.ends_with(HONEYPOT_DEFAULT_FILENAME),
            "unexpected honeypot path: {}",
            outcome.target_path
        );
        // Temporary scenario file must have been cleaned up on completion.
        assert!(
            !Path::new(&outcome.target_path).exists(),
            "temp honeypot path should be cleaned up"
        );

        let temp = TempSimDir::new("test-honeypot").expect("temp dir");
        let in_dir =
            run_honeypot_write_scenario_in(temp.path()).expect("honeypot-write in temp dir");
        assert_eq!(in_dir.appended_bytes, 1);
        assert_eq!(in_dir.final_bytes, in_dir.initial_bytes + 1);
        assert_eq!(
            std::fs::metadata(&in_dir.target_path)
                .expect("honeypot metadata")
                .len() as usize,
            in_dir.final_bytes
        );
    }

    #[tokio::test]
    async fn sim_p2_03_hold_ms_keeps_scenario_clean() {
        let cookie_res = run_cookies_open_scenario_with_hold(30)
            .await
            .expect("cookies-open with short hold should succeed");
        assert!(cookie_res.opened);
        assert!(!Path::new(&cookie_res.target_path).exists());

        let honeypot_res = run_honeypot_write_scenario_with_hold(30)
            .await
            .expect("honeypot-write with short hold should succeed");
        assert_eq!(honeypot_res.appended_bytes, 1);
        assert!(!Path::new(&honeypot_res.target_path).exists());
    }
}
