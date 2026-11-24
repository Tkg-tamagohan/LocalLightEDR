use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Launch mode for the on-demand LocalEDR UI binary (`決定記録 L-08`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "alert_id", rename_all = "snake_case")]
pub enum LaunchMode {
    Normal,
    Notify(String),
    AlertFocus(String),
    RegisterUri,
}

/// Verified update arguments for elevated `--apply-verified-update` execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApplyVerifiedUpdateArgs {
    pub(crate) manifest: PathBuf,
    pub(crate) sig: PathBuf,
    pub(crate) installer: PathBuf,
}

/// Top-level CLI action parsed from process arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CliAction {
    Launch(LaunchMode),
    ApplyVerifiedUpdate(ApplyVerifiedUpdateArgs),
}

fn parse_flag_value<I, S>(flag: &str, arg: &str, iter: &mut I) -> Result<Option<String>, String>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    if arg == flag {
        let value = iter
            .next()
            .map(|v| v.as_ref().to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("missing value for {flag}"))?;
        return Ok(Some(value));
    }
    let prefix = format!("{flag}=");
    if let Some(value) = arg.strip_prefix(&prefix) {
        if value.is_empty() {
            return Err(format!("missing value for {prefix}"));
        }
        return Ok(Some(value.to_string()));
    }
    Ok(None)
}

/// Parses a `ledr://alert/<id>` protocol URI (case-insensitive scheme/host, stripping
/// query string, fragment, and trailing slashes) into an alert ID (`L-08`, `AUTO-14`).
pub(crate) fn parse_ledr_alert_uri(raw: &str) -> Result<Option<String>, String> {
    let trimmed = raw.trim();
    let Some(scheme) = trimmed.get(..7) else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("ledr://") {
        return Ok(None);
    }

    let after_scheme = &trimmed[7..];
    let without_query_frag = after_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(after_scheme);

    let Some(host_prefix) = without_query_frag.get(..6) else {
        return Err(format!("invalid ledr URI '{trimmed}': expected ledr://alert/<id>"));
    };
    if !host_prefix.eq_ignore_ascii_case("alert/") {
        return Err(format!("unsupported ledr URI host in '{trimmed}'"));
    }

    let id = without_query_frag[6..].trim_end_matches('/');
    if id.is_empty() || id.contains('/') {
        return Err(format!("missing or invalid alert id in URI '{trimmed}'"));
    }

    Ok(Some(id.to_string()))
}

/// Parses CLI arguments into a [`CliAction`].
///
/// Supports `--apply-verified-update --manifest <p> --sig <p> --installer <p>`
/// as well as all GUI [`LaunchMode`] flags (`--notify`, `--alert-id`, `--register-uri`,
/// `--uri`, `ledr://alert/<id>`).
pub(crate) fn parse_cli_action<I, S>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let raw_args: Vec<String> = args
        .into_iter()
        .skip(1)
        .map(|s| s.as_ref().to_string())
        .collect();

    let has_apply_flag = raw_args
        .iter()
        .any(|s| s == "--apply-verified-update" || s.starts_with("--apply-verified-update="));
    let has_apply_subflag = raw_args.iter().any(|s| {
        s == "--manifest"
            || s.starts_with("--manifest=")
            || s == "--sig"
            || s.starts_with("--sig=")
            || s == "--installer"
            || s.starts_with("--installer=")
    });

    if !has_apply_flag && !has_apply_subflag {
        return parse_launch_mode_inner(&raw_args).map(CliAction::Launch);
    }

    if !has_apply_flag {
        return Err("--manifest, --sig, and --installer require --apply-verified-update".to_string());
    }

    let mut seen_apply = false;
    let mut manifest: Option<PathBuf> = None;
    let mut sig: Option<PathBuf> = None;
    let mut installer: Option<PathBuf> = None;

    let mut iter = raw_args.iter().map(String::as_str);
    while let Some(s) = iter.next() {
        if s == "--apply-verified-update" {
            if seen_apply {
                return Err("duplicate --apply-verified-update flag".to_string());
            }
            seen_apply = true;
            continue;
        }
        if s.starts_with("--apply-verified-update=") {
            return Err("--apply-verified-update does not accept a value".to_string());
        }
        if let Some(val) = parse_flag_value("--manifest", s, &mut iter)? {
            if manifest.is_some() {
                return Err("duplicate --manifest flag".to_string());
            }
            manifest = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = parse_flag_value("--sig", s, &mut iter)? {
            if sig.is_some() {
                return Err("duplicate --sig flag".to_string());
            }
            sig = Some(PathBuf::from(val));
            continue;
        }
        if let Some(val) = parse_flag_value("--installer", s, &mut iter)? {
            if installer.is_some() {
                return Err("duplicate --installer flag".to_string());
            }
            installer = Some(PathBuf::from(val));
            continue;
        }
        return Err(format!(
            "unexpected argument '{s}' combined with --apply-verified-update"
        ));
    }

    let manifest = manifest.ok_or_else(|| "missing --manifest for --apply-verified-update".to_string())?;
    let sig = sig.ok_or_else(|| "missing --sig for --apply-verified-update".to_string())?;
    let installer =
        installer.ok_or_else(|| "missing --installer for --apply-verified-update".to_string())?;

    Ok(CliAction::ApplyVerifiedUpdate(ApplyVerifiedUpdateArgs {
        manifest,
        sig,
        installer,
    }))
}

fn parse_launch_mode_inner(raw_args: &[String]) -> Result<LaunchMode, String> {
    let mut iter = raw_args.iter().map(String::as_str);
    while let Some(s) = iter.next() {
        if s == "--register-uri" {
            return Ok(LaunchMode::RegisterUri);
        }
        if s.starts_with("--register-uri=") {
            return Err("--register-uri does not accept a value".to_string());
        }
        if let Some(alert_id) = parse_flag_value("--notify", s, &mut iter)? {
            return Ok(LaunchMode::Notify(alert_id));
        }
        if let Some(alert_id) = parse_flag_value("--alert-id", s, &mut iter)? {
            return Ok(LaunchMode::AlertFocus(alert_id));
        }
        if let Some(uri) = parse_flag_value("--uri", s, &mut iter)? {
            let alert_id = parse_ledr_alert_uri(&uri)?
                .ok_or_else(|| format!("invalid --uri value '{uri}': expected ledr://alert/<id>"))?;
            return Ok(LaunchMode::AlertFocus(alert_id));
        }
        if let Some(alert_id) = parse_ledr_alert_uri(s)? {
            return Ok(LaunchMode::AlertFocus(alert_id));
        }
    }
    Ok(LaunchMode::Normal)
}

/// Parses CLI arguments into a [`LaunchMode`].
///
/// Supports `--notify <alert_id>` (one-shot WinRT toast mode),
/// `--alert-id <id>` (direct alert triage focus mode),
/// `--register-uri` (per-user `HKCU\Software\Classes\ledr` protocol handler registration),
/// and `ledr://alert/<id>` / `--uri ledr://alert/<id>` protocol activation (`L-08`, `AUTO-14`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_launch_mode<I, S>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    match parse_cli_action(args)? {
        CliAction::Launch(mode) => Ok(mode),
        CliAction::ApplyVerifiedUpdate(_) => {
            Err("--apply-verified-update is not a GUI launch mode".to_string())
        }
    }
}
