use serde::Serialize;

/// Launch mode for the on-demand LocalEDR UI binary (`決定記録 L-08`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "mode", content = "alert_id", rename_all = "snake_case")]
enum LaunchMode {
    Normal,
    Notify(String),
    AlertFocus(String),
}

#[derive(Debug, Serialize)]
struct UiSkeletonStatus<'a> {
    app: &'static str,
    ipc_pipe: &'static str,
    launch_mode: &'a LaunchMode,
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

/// Parses CLI arguments into a [`LaunchMode`].
///
/// Supports `--notify <alert_id>` (one-shot WinRT toast mode) and
/// `--alert-id <id>` (direct alert triage focus mode).
fn parse_launch_mode<I, S>(args: I) -> Result<LaunchMode, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter().skip(1);
    while let Some(arg) = iter.next() {
        let s = arg.as_ref();
        if let Some(alert_id) = parse_flag_value("--notify", s, &mut iter)? {
            return Ok(LaunchMode::Notify(alert_id));
        }
        if let Some(alert_id) = parse_flag_value("--alert-id", s, &mut iter)? {
            return Ok(LaunchMode::AlertFocus(alert_id));
        }
    }
    Ok(LaunchMode::Normal)
}

fn main() {
    let mode = match parse_launch_mode(std::env::args()) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("ledr-ui argument error: {err}");
            std::process::exit(2);
        }
    };

    let status = UiSkeletonStatus {
        app: "ledr-ui",
        ipc_pipe: ledr_proto::IPC_PIPE_NAME,
        launch_mode: &mode,
    };

    match serde_json::to_string(&status) {
        Ok(json) => println!("{json}"),
        Err(err) => {
            eprintln!("failed to serialize status: {err}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normal_mode() {
        assert_eq!(parse_launch_mode(["ledr-ui"]), Ok(LaunchMode::Normal));
    }

    #[test]
    fn parses_notify_flag() {
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--notify", "alert-123"]),
            Ok(LaunchMode::Notify("alert-123".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--notify=alert-456"]),
            Ok(LaunchMode::Notify("alert-456".to_string()))
        );
    }

    #[test]
    fn parses_alert_id_flag() {
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--alert-id", "alert-789"]),
            Ok(LaunchMode::AlertFocus("alert-789".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--alert-id=alert-000"]),
            Ok(LaunchMode::AlertFocus("alert-000".to_string()))
        );
    }

    #[test]
    fn rejects_missing_flag_value() {
        assert!(parse_launch_mode(["ledr-ui", "--notify"]).is_err());
        assert!(parse_launch_mode(["ledr-ui", "--alert-id="]).is_err());
    }
}
