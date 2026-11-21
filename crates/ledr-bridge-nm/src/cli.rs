//! CLI parser supporting Chrome Native Messaging launch arguments and management subcommands.

use std::path::PathBuf;

use anyhow::{bail, Result};
use ledr_proto::IPC_PIPE_NAME;
use serde::Serialize;

use crate::extension_id::{is_valid_extension_id, DEFAULT_CHROME_EXTENSION_ID};

/// Registry / manifest target scope for `setup` and `unregister`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    User,
    Machine,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Machine => "machine",
        }
    }

    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "user" => Ok(Self::User),
            "machine" => Ok(Self::Machine),
            other => bail!("invalid --scope '{other}': expected 'user' or 'machine'"),
        }
    }
}

/// Registry inspection scope for `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusScope {
    All,
    User,
    Machine,
}

impl StatusScope {
    fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "user" => Ok(Self::User),
            "machine" => Ok(Self::Machine),
            other => bail!("invalid --scope '{other}': expected 'all', 'user', or 'machine'"),
        }
    }
}

/// Supported Chromium-family browsers for Native Messaging Host registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserKind {
    Chrome,
    Edge,
    Brave,
}

impl BrowserKind {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Chrome => "Google Chrome",
            Self::Edge => "Microsoft Edge",
            Self::Brave => "Brave",
        }
    }

    pub fn parse_list(raw: &str) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        for token in raw.split(',') {
            let trimmed = token.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                continue;
            }
            let browser = match trimmed.as_str() {
                "chrome" => Self::Chrome,
                "edge" => Self::Edge,
                "brave" => Self::Brave,
                other => {
                    bail!("unsupported browser '{other}' in --browsers (expected chrome, edge, brave)")
                }
            };
            if !out.contains(&browser) {
                out.push(browser);
            }
        }
        if out.is_empty() {
            bail!("--browsers must specify at least one browser (chrome, edge, brave)");
        }
        Ok(out)
    }
}

/// Arguments for the default Native Messaging relay mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayArgs {
    pub pipe_name: String,
    pub caller_origin: Option<String>,
    pub parent_window: Option<String>,
}

/// Arguments for `ledr-bridge-nm setup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupArgs {
    pub scope: Scope,
    pub browsers: Vec<BrowserKind>,
    pub extension_id: String,
    pub bridge_exe: Option<PathBuf>,
    pub ui_exe: Option<PathBuf>,
    pub manifest_dir: Option<PathBuf>,
    pub skip_uri: bool,
    pub json: bool,
}

/// Arguments for `ledr-bridge-nm unregister`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnregisterArgs {
    pub scope: Scope,
    pub browsers: Vec<BrowserKind>,
    pub manifest_dir: Option<PathBuf>,
    pub keep_uri: bool,
    pub json: bool,
}

/// Arguments for `ledr-bridge-nm status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusArgs {
    pub scope: StatusScope,
    pub ping: bool,
    pub pipe_name: String,
    pub json: bool,
}

/// Parsed CLI command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Relay(RelayArgs),
    Setup(SetupArgs),
    Unregister(UnregisterArgs),
    Status(StatusArgs),
    Help,
}

/// Resolves the target Named Pipe from CLI override, environment override, or [`IPC_PIPE_NAME`].
pub fn resolve_pipe_name(cli_override: Option<&str>, env_override: Option<&str>) -> String {
    cli_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| env_override.map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or(IPC_PIPE_NAME)
        .to_string()
}

/// Parses command-line arguments from the current process environment.
pub fn parse_args() -> Result<Command> {
    let env_pipe = std::env::var(crate::pipe_client::IPC_PIPE_OVERRIDE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("IPC_PIPE_NAME")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
    parse_args_from(std::env::args(), env_pipe.as_deref())
}

/// Parses command-line arguments from an iterator starting with `argv[0]`.
pub fn parse_args_from<I, S>(args: I, env_pipe: Option<&str>) -> Result<Command>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let items: Vec<String> = args.into_iter().map(Into::into).collect();
    let rest = if items.len() > 1 { &items[1..] } else { &[][..] };

    let Some(first) = rest.first().map(String::as_str) else {
        return Ok(Command::Relay(RelayArgs {
            pipe_name: resolve_pipe_name(None, env_pipe),
            caller_origin: None,
            parent_window: None,
        }));
    };

    match first {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "setup" => parse_setup_args(&rest[1..]),
        "unregister" => parse_unregister_args(&rest[1..]),
        "status" => parse_status_args(&rest[1..], env_pipe),
        _ => parse_relay_args(rest, env_pipe),
    }
}

/// Returns concise CLI help text.
pub fn usage_text() -> &'static str {
    concat!(
        "LocalEDR Native Messaging Bridge (ledr-bridge-nm)\n\n",
        "Usage:\n",
        "  ledr-bridge-nm [chrome-extension://<id>/] [--parent-window=<hwnd>] [--pipe <name>]\n",
        "  ledr-bridge-nm setup [--scope user|machine] [--browsers chrome,edge,brave]\n",
        "                       [--extension-id <id>] [--bridge-exe <path>] [--ui-exe <path>]\n",
        "                       [--manifest-dir <dir>] [--skip-uri] [--json]\n",
        "  ledr-bridge-nm unregister [--scope user|machine] [--browsers chrome,edge,brave]\n",
        "                            [--manifest-dir <dir>] [--keep-uri] [--json]\n",
        "  ledr-bridge-nm status [--scope all|user|machine] [--ping] [--pipe <name>] [--json]\n",
    )
}

fn parse_relay_args(args: &[String], env_pipe: Option<&str>) -> Result<Command> {
    let mut pipe_override: Option<String> = None;
    let mut caller_origin: Option<String> = None;
    let mut parent_window: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(val) = arg.strip_prefix("--pipe=") {
            if val.trim().is_empty() {
                bail!("--pipe requires a non-empty pipe name");
            }
            pipe_override = Some(val.to_string());
        } else if arg == "--pipe" {
            i += 1;
            let val = args
                .get(i)
                .map(String::as_str)
                .filter(|s| !s.trim().is_empty())
                .ok_or_else(|| anyhow::anyhow!("--pipe requires a value"))?;
            pipe_override = Some(val.to_string());
        } else if let Some(val) = arg.strip_prefix("--parent-window=") {
            parent_window = Some(val.to_string());
        } else if arg == "--parent-window" {
            if let Some(val) = args.get(i + 1) {
                i += 1;
                parent_window = Some(val.clone());
            }
        } else if arg.starts_with("chrome-extension://") && caller_origin.is_none() {
            caller_origin = Some(arg.to_string());
        }
        // Chrome / Edge may append additional Chromium-specific flags or positional arguments;
        // ignore unknown arguments in relay mode so Native Messaging startup never aborts.
        i += 1;
    }

    Ok(Command::Relay(RelayArgs {
        pipe_name: resolve_pipe_name(pipe_override.as_deref(), env_pipe),
        caller_origin,
        parent_window,
    }))
}

fn parse_setup_args(args: &[String]) -> Result<Command> {
    let mut scope = Scope::User;
    let mut browsers = vec![BrowserKind::Chrome, BrowserKind::Edge];
    let mut extension_id = DEFAULT_CHROME_EXTENSION_ID.to_string();
    let mut bridge_exe: Option<PathBuf> = None;
    let mut ui_exe: Option<PathBuf> = None;
    let mut manifest_dir: Option<PathBuf> = None;
    let mut skip_uri = false;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(Command::Help),
            "--skip-uri" => skip_uri = true,
            "--json" => json = true,
            _ => {
                if let Some((flag, val, consumed_next)) = take_flag_value(arg, args.get(i + 1))? {
                    if consumed_next {
                        i += 1;
                    }
                    match flag {
                        "--scope" => scope = Scope::parse(val)?,
                        "--browsers" => browsers = BrowserKind::parse_list(val)?,
                        "--extension-id" => {
                            let trimmed = val.trim();
                            if !is_valid_extension_id(trimmed) {
                                bail!(
                                    "invalid --extension-id '{trimmed}': expected 32 lowercase characters in 'a'..='p'"
                                );
                            }
                            extension_id = trimmed.to_string();
                        }
                        "--bridge-exe" => bridge_exe = Some(require_non_empty_path(flag, val)?),
                        "--ui-exe" => ui_exe = Some(require_non_empty_path(flag, val)?),
                        "--manifest-dir" => manifest_dir = Some(require_non_empty_path(flag, val)?),
                        other => bail!("unknown flag for setup: {other}"),
                    }
                } else {
                    bail!("unexpected argument for setup: {arg}");
                }
            }
        }
        i += 1;
    }

    Ok(Command::Setup(SetupArgs {
        scope,
        browsers,
        extension_id,
        bridge_exe,
        ui_exe,
        manifest_dir,
        skip_uri,
        json,
    }))
}

fn parse_unregister_args(args: &[String]) -> Result<Command> {
    let mut scope = Scope::User;
    let mut browsers = vec![BrowserKind::Chrome, BrowserKind::Edge];
    let mut manifest_dir: Option<PathBuf> = None;
    let mut keep_uri = false;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(Command::Help),
            "--keep-uri" => keep_uri = true,
            "--json" => json = true,
            _ => {
                if let Some((flag, val, consumed_next)) = take_flag_value(arg, args.get(i + 1))? {
                    if consumed_next {
                        i += 1;
                    }
                    match flag {
                        "--scope" => scope = Scope::parse(val)?,
                        "--browsers" => browsers = BrowserKind::parse_list(val)?,
                        "--manifest-dir" => manifest_dir = Some(require_non_empty_path(flag, val)?),
                        other => bail!("unknown flag for unregister: {other}"),
                    }
                } else {
                    bail!("unexpected argument for unregister: {arg}");
                }
            }
        }
        i += 1;
    }

    Ok(Command::Unregister(UnregisterArgs {
        scope,
        browsers,
        manifest_dir,
        keep_uri,
        json,
    }))
}

fn parse_status_args(args: &[String], env_pipe: Option<&str>) -> Result<Command> {
    let mut scope = StatusScope::All;
    let mut ping = false;
    let mut pipe_override: Option<String> = None;
    let mut json = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "-h" | "--help" => return Ok(Command::Help),
            "--ping" => ping = true,
            "--json" => json = true,
            _ => {
                if let Some((flag, val, consumed_next)) = take_flag_value(arg, args.get(i + 1))? {
                    if consumed_next {
                        i += 1;
                    }
                    match flag {
                        "--scope" => scope = StatusScope::parse(val)?,
                        "--pipe" => {
                            if val.trim().is_empty() {
                                bail!("--pipe requires a non-empty value");
                            }
                            pipe_override = Some(val.trim().to_string());
                        }
                        other => bail!("unknown flag for status: {other}"),
                    }
                } else {
                    bail!("unexpected argument for status: {arg}");
                }
            }
        }
        i += 1;
    }

    Ok(Command::Status(StatusArgs {
        scope,
        ping,
        pipe_name: resolve_pipe_name(pipe_override.as_deref(), env_pipe),
        json,
    }))
}

fn take_flag_value<'a>(
    arg: &'a str,
    next: Option<&'a String>,
) -> Result<Option<(&'a str, &'a str, bool)>> {
    if !arg.starts_with("--") {
        return Ok(None);
    }
    if let Some((flag, val)) = arg.split_once('=') {
        return Ok(Some((flag, val, false)));
    }
    let val = next
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("flag '{arg}' requires a value"))?;
    Ok(Some((arg, val, true)))
}

fn require_non_empty_path(flag: &str, raw: &str) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{flag} requires a non-empty path");
    }
    Ok(PathBuf::from(trimmed))
}
