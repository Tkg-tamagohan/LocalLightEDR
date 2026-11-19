use serde::{Deserialize, Serialize};

/// Launch mode for the on-demand LocalEDR UI binary (`決定記録 L-08`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "alert_id", rename_all = "snake_case")]
pub enum LaunchMode {
    Normal,
    Notify(String),
    AlertFocus(String),
    RegisterUri,
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

/// Parses CLI arguments into a [`LaunchMode`].
///
/// Supports `--notify <alert_id>` (one-shot WinRT toast mode),
/// `--alert-id <id>` (direct alert triage focus mode),
/// `--register-uri` (per-user `HKCU\Software\Classes\ledr` protocol handler registration),
/// and `ledr://alert/<id>` / `--uri ledr://alert/<id>` protocol activation (`L-08`, `AUTO-14`).
pub(crate) fn parse_launch_mode<I, S>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        let s = arg.as_ref();
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
