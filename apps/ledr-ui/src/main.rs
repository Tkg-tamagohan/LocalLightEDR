#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;
mod tree;

use ipc::{DomainRiskView, IpcClient};
use ledr_proto::{
    AUTHORIZED_BRIDGE_EXE_PATH, AlertDecision, AlertRecord, AlertStatus, AllowlistRuleRecord,
    FlightRecorderSnapshot, PipelineMetrics, RuleScope,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::Manager;

/// Environment variable disabling OS WinRT toast emission during headless/CI tests.
pub const DISABLE_OS_TOAST_ENV: &str = "LEDR_UI_DISABLE_OS_TOAST";

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Launch mode for the on-demand LocalEDR UI binary (`決定記録 L-08`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "alert_id", rename_all = "snake_case")]
pub enum LaunchMode {
    Normal,
    Notify(String),
    AlertFocus(String),
    RegisterUri,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UriRegistrationOutcome {
    pub(crate) registry_key: String,
    pub(crate) command: String,
    pub(crate) updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegisterUriEvent {
    mode: String,
    scheme: String,
    registry_key: String,
    command: String,
    updated: bool,
    status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToastAlertSummary {
    pub(crate) alert_id: String,
    pub(crate) title: String,
    pub(crate) target_path: Option<String>,
    pub(crate) exe_path: Option<String>,
    pub(crate) rule_id: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) process_suspended: bool,
    pub(crate) is_expired_suspended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NotifyOneshotEvent {
    mode: String,
    alert_id: String,
    launch_uri: String,
    ipc_pipe: String,
    daemon_reachable: bool,
    alert_found: bool,
    title: String,
    target_path: Option<String>,
    process_suspended: bool,
    toast_xml: String,
    os_toast_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_toast_error: Option<String>,
    status: String,
}

struct OsToastOutcome {
    status: &'static str,
    error: Option<String>,
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
fn parse_ledr_alert_uri(raw: &str) -> Result<Option<String>, String> {
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
fn parse_launch_mode<I, S>(args: I) -> Result<LaunchMode, String>
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

#[tauri::command]
async fn fetch_flight_recorder(
    client: tauri::State<'_, IpcClient>,
    limit: usize,
    process_instance_id: Option<String>,
) -> Result<FlightRecorderSnapshot, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        client.get_flight_recorder(limit, process_instance_id)
    })
    .await
    .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn fetch_pipeline_metrics(
    client: tauri::State<'_, IpcClient>,
) -> Result<PipelineMetrics, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.get_pipeline_metrics())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn fetch_alerts(
    client: tauri::State<'_, IpcClient>,
    status: Option<AlertStatus>,
    limit: usize,
) -> Result<Vec<AlertRecord>, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.get_alerts(status, limit))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn resolve_alert_action(
    client: tauri::State<'_, IpcClient>,
    alert_id: String,
    decision: AlertDecision,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.resolve_alert(alert_id, decision))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn fetch_rules(
    client: tauri::State<'_, IpcClient>,
    scope: Option<RuleScope>,
) -> Result<Vec<AllowlistRuleRecord>, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.list_rules(scope))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn upsert_rule_action(
    client: tauri::State<'_, IpcClient>,
    rule: AllowlistRuleRecord,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.upsert_rule(rule))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn delete_rule_action(
    client: tauri::State<'_, IpcClient>,
    rule_id: String,
) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.delete_rule(rule_id))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
async fn check_domain_risk_action(
    client: tauri::State<'_, IpcClient>,
    domain: String,
) -> Result<DomainRiskView, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.check_domain_risk(domain))
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
fn fetch_local_defense_status() -> LocalDefenseStatus {
    collect_local_defense_status()
}

#[tauri::command]
async fn ping_daemon(client: tauri::State<'_, IpcClient>) -> Result<String, String> {
    let client = client.inner().clone();
    tauri::async_runtime::spawn_blocking(move || client.ping())
        .await
        .map_err(|err| format!("IPC background task failed: {err}"))?
}

#[tauri::command]
fn get_launch_mode(mode: tauri::State<'_, LaunchMode>) -> LaunchMode {
    mode.inner().clone()
}

#[tauri::command]
fn build_process_tree_view(snapshot: FlightRecorderSnapshot) -> Vec<tree::ProcessTreeNode> {
    tree::build_process_tree(&snapshot)
}

pub(crate) fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn non_empty_str_field(val: &serde_json::Value, key: &str) -> Option<String> {
    val.get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn extract_context_paths(context_json: &str) -> (Option<String>, Option<String>) {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(context_json) else {
        return (None, None);
    };

    let target_path = non_empty_str_field(&val, "target_path")
        .or_else(|| {
            val.get("event")
                .and_then(|e| e.get("CanaryFileAccess"))
                .and_then(|c| non_empty_str_field(c, "target_path"))
        })
        .or_else(|| {
            let dst_ip = non_empty_str_field(&val, "dst_ip").or_else(|| {
                val.get("event")
                    .and_then(|e| e.get("NetworkConnect"))
                    .and_then(|n| non_empty_str_field(n, "dst_ip"))
            })?;
            let dst_port = val
                .get("dst_port")
                .or_else(|| {
                    val.get("event")
                        .and_then(|e| e.get("NetworkConnect"))
                        .and_then(|n| n.get("dst_port"))
                })
                .and_then(serde_json::Value::as_u64);
            let domain = non_empty_str_field(&val, "domain_hint").or_else(|| {
                val.get("event")
                    .and_then(|e| e.get("NetworkConnect"))
                    .and_then(|n| non_empty_str_field(n, "domain_hint"))
            });
            let endpoint = match dst_port {
                Some(port) => format!("{dst_ip}:{port}"),
                None => dst_ip,
            };
            Some(match domain {
                Some(d) => format!("{d} ({endpoint})"),
                None => endpoint,
            })
        })
        .or_else(|| {
            val.get("event")
                .and_then(|e| e.get("DnsQuery"))
                .and_then(|d| non_empty_str_field(d, "query_name"))
        })
        .or_else(|| non_empty_str_field(&val, "url"));

    let exe_path = non_empty_str_field(&val, "exe_path")
        .or_else(|| {
            val.get("event")
                .and_then(|e| e.get("ProcessStart"))
                .and_then(|p| non_empty_str_field(p, "exe_path"))
        })
        .or_else(|| non_empty_str_field(&val, "process_exe_path"));

    (target_path, exe_path)
}

fn summarize_alert_for_toast(alert_id: &str, alert: Option<&AlertRecord>) -> ToastAlertSummary {
    match alert {
        Some(rec) => {
            let (target_path, exe_path) = extract_context_paths(&rec.context_json);
            ToastAlertSummary {
                alert_id: rec.alert_id.clone(),
                title: rec.title.clone(),
                target_path,
                exe_path,
                rule_id: Some(rec.rule_id.clone()),
                severity: Some(rec.severity.as_db_str().to_string()),
                process_suspended: rec.process_suspended,
                is_expired_suspended: rec.status == AlertStatus::ExpiredSuspended,
            }
        }
        None => ToastAlertSummary {
            alert_id: alert_id.to_string(),
            title: "LocalEDR Security Alert".to_string(),
            target_path: None,
            exe_path: None,
            rule_id: None,
            severity: None,
            process_suspended: false,
            is_expired_suspended: false,
        },
    }
}

/// Builds a WinRT `ToastGeneric` XML payload with `ledr://alert/{alert_id}` protocol activation (`L-08`).
pub(crate) fn build_winrt_toast_xml(summary: &ToastAlertSummary) -> String {
    let launch_uri = format!("ledr://alert/{}", summary.alert_id);
    let escaped_uri = xml_escape(&launch_uri);

    let suspended_badge = if summary.is_expired_suspended {
        "[EXPIRED_SUSPENDED · FROZEN]"
    } else if summary.process_suspended {
        "[SUSPENDED]"
    } else {
        "[ALERT]"
    };
    let sev_prefix = summary
        .severity
        .as_deref()
        .map(|s| format!("{s} "))
        .unwrap_or_default();

    let header = xml_escape(&format!(
        "[LocalEDR] {suspended_badge} {sev_prefix}{}",
        summary.title
    ));
    let target_line = match summary
        .target_path
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(target) => xml_escape(&format!("Target: {target}")),
        None => xml_escape(&format!("Alert ID: {}", summary.alert_id)),
    };
    let detail_line = match (
        summary.exe_path.as_deref().filter(|s| !s.trim().is_empty()),
        summary.rule_id.as_deref().filter(|s| !s.trim().is_empty()),
    ) {
        (Some(exe), Some(rule)) => xml_escape(&format!("Process: {exe} | Rule: {rule}")),
        (Some(exe), None) => xml_escape(&format!("Process: {exe}")),
        (None, Some(rule)) => xml_escape(&format!("Rule: {rule} | ID: {}", summary.alert_id)),
        (None, None) => xml_escape(&format!("ID: {}", summary.alert_id)),
    };

    format!(
        "<toast launch=\"{escaped_uri}\" activationType=\"protocol\" scenario=\"urgent\">\
         <visual><binding template=\"ToastGeneric\">\
         <text>{header}</text>\
         <text>{target_line}</text>\
         <text>{detail_line}</text>\
         </binding></visual>\
         <actions>\
         <action content=\"Triage Alert\" activationType=\"protocol\" arguments=\"{escaped_uri}\" />\
         </actions>\
         </toast>"
    )
}

pub(crate) fn is_os_toast_disabled_value(val: Option<&str>) -> bool {
    val.map(str::trim).is_some_and(|trimmed| {
        !trimmed.is_empty()
            && !trimmed.eq_ignore_ascii_case("0")
            && !trimmed.eq_ignore_ascii_case("false")
            && !trimmed.eq_ignore_ascii_case("no")
    })
}

fn is_os_toast_disabled() -> bool {
    is_os_toast_disabled_value(std::env::var(DISABLE_OS_TOAST_ENV).ok().as_deref())
}

#[cfg(windows)]
fn dispatch_os_toast_nonblocking(toast_xml: &str, disable_os_toast: bool) -> OsToastOutcome {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    if disable_os_toast {
        return OsToastOutcome {
            status: "disabled_by_env",
            error: None,
        };
    }

    let xml_b64 = base64_encode(toast_xml.as_bytes());
    let ps_script = format!(
        "$ErrorActionPreference = 'Stop';\n\
         $xml = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{xml_b64}'));\n\
         [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;\n\
         [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;\n\
         $doc = New-Object Windows.Data.Xml.Dom.XmlDocument;\n\
         $doc.LoadXml($xml);\n\
         $toast = [Windows.UI.Notifications.ToastNotification]::new($doc);\n\
         $appId = '{{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}}\\WindowsPowerShell\\v1.0\\powershell.exe';\n\
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast);"
    );
    let utf16_le: Vec<u8> = ps_script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let encoded_cmd = base64_encode(&utf16_le);

    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        &encoded_cmd,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .creation_flags(CREATE_NO_WINDOW);

    match cmd.spawn() {
        Ok(_child) => OsToastOutcome {
            status: "dispatched",
            error: None,
        },
        Err(err) => OsToastOutcome {
            status: "spawn_failed",
            error: Some(err.to_string()),
        },
    }
}

#[cfg(not(windows))]
fn dispatch_os_toast_nonblocking(_toast_xml: &str, disable_os_toast: bool) -> OsToastOutcome {
    if disable_os_toast {
        OsToastOutcome {
            status: "disabled_by_env",
            error: None,
        }
    } else {
        OsToastOutcome {
            status: "unsupported_platform",
            error: None,
        }
    }
}

pub(crate) fn build_notify_oneshot_event(
    alert_id: &str,
    ipc_pipe: &str,
    alerts_result: Result<Vec<AlertRecord>, String>,
    disable_os_toast: bool,
) -> NotifyOneshotEvent {
    let (daemon_reachable, matched_alert) = match alerts_result {
        Ok(alerts) => (true, alerts.into_iter().find(|a| a.alert_id == alert_id)),
        Err(_) => (false, None),
    };
    let alert_found = matched_alert.is_some();
    let summary = summarize_alert_for_toast(alert_id, matched_alert.as_ref());
    let toast_xml = build_winrt_toast_xml(&summary);
    let outcome = dispatch_os_toast_nonblocking(&toast_xml, disable_os_toast);
    let overall_status = match outcome.status {
        "dispatched" => "dispatched",
        "disabled_by_env" => "disabled_by_env",
        _ => "toast_unavailable",
    };

    NotifyOneshotEvent {
        mode: "notify_oneshot".to_string(),
        alert_id: alert_id.to_string(),
        launch_uri: format!("ledr://alert/{alert_id}"),
        ipc_pipe: ipc_pipe.to_string(),
        daemon_reachable,
        alert_found,
        title: summary.title,
        target_path: summary.target_path,
        process_suspended: summary.process_suspended,
        toast_xml,
        os_toast_status: outcome.status.to_string(),
        os_toast_error: outcome.error,
        status: overall_status.to_string(),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
const LEDR_URI_REG_SUBKEY: &str = r"Software\Classes\ledr";
#[cfg_attr(not(windows), allow(dead_code))]
const LEDR_URI_DESCRIPTION: &str = "URL:LocalEDR Alert Protocol";

pub(crate) fn format_ledr_uri_command(exe_path: &std::path::Path) -> String {
    let raw = exe_path.to_string_lossy();
    let normalized = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    };
    format!("\"{normalized}\" \"%1\"")
}

#[cfg(windows)]
mod win_uri_reg {
    use super::{LEDR_URI_DESCRIPTION, UriRegistrationOutcome, format_ledr_uri_command};
    use std::ffi::c_void;
    use std::path::Path;
    use std::ptr;

    const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_MORE_DATA: i32 = 234;

    #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut isize,
        ) -> i32;
        fn RegCreateKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *const u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *const c_void,
            phk_result: *mut isize,
            lpdw_disposition: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;
        fn RegCloseKey(h_key: isize) -> i32;
        #[cfg(test)]
        fn RegDeleteTreeW(h_key: isize, lp_sub_key: *const u16) -> i32;
    }

    pub(crate) struct OwnedRegKey(isize);

    impl Drop for OwnedRegKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: `self.0` is an open HKEY acquired from `RegOpenKeyExW` or `RegCreateKeyExW`.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    pub(crate) fn to_utf16_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(crate) fn reg_open_hkcu(subkey: &str, access: u32) -> Result<Option<OwnedRegKey>, String> {
        let subkey_w = to_utf16_nul(subkey);
        let mut handle: isize = 0;
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and `handle` is valid out-pointer storage.
        let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey_w.as_ptr(), 0, access, &mut handle) };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyExW('HKCU\\{subkey}') failed: OS status {status}"));
        }
        Ok(Some(OwnedRegKey(handle)))
    }

    fn reg_create_hkcu(subkey: &str, access: u32) -> Result<OwnedRegKey, String> {
        let subkey_w = to_utf16_nul(subkey);
        let mut handle: isize = 0;
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and `handle` is valid out-pointer storage.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegCreateKeyExW('HKCU\\{subkey}') failed: OS status {status}"
            ));
        }
        Ok(OwnedRegKey(handle))
    }

    pub(crate) fn reg_query_sz(key: &OwnedRegKey, value_name: Option<&str>) -> Result<Option<String>, String> {
        let name_w = value_name.map(to_utf16_nul);
        let name_ptr = name_w.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let mut val_type: u32 = 0;
        let mut buf = vec![0u8; 512];
        let mut byte_len = buf.len() as u32;
        // SAFETY: `key.0` is an open HKEY, `name_ptr` is NULL or NUL-terminated UTF-16, and `buf` is writable.
        let mut status = unsafe {
            RegQueryValueExW(
                key.0,
                name_ptr,
                ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr(),
                &mut byte_len,
            )
        };
        if status == ERROR_MORE_DATA {
            buf.resize(byte_len as usize, 0);
            // SAFETY: `buf` was resized to `byte_len` bytes reported by `RegQueryValueExW`.
            status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name_ptr,
                    ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr(),
                    &mut byte_len,
                )
            };
        }
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueExW failed: OS status {status}"));
        }
        if val_type != REG_SZ {
            return Ok(None);
        }
        let used = (byte_len as usize).min(buf.len());
        let mut units: Vec<u16> = buf[..used]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    fn reg_set_sz(key: &OwnedRegKey, value_name: Option<&str>, value: &str) -> Result<(), String> {
        let name_w = value_name.map(to_utf16_nul);
        let name_ptr = name_w.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let data_w = to_utf16_nul(value);
        let byte_len = u32::try_from(data_w.len() * std::mem::size_of::<u16>())
            .map_err(|_| "registry string exceeds u32 byte length".to_string())?;
        // SAFETY: `key.0` is an open HKEY with write access and `data_w` is NUL-terminated UTF-16 of `byte_len` bytes.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name_ptr,
                0,
                REG_SZ,
                data_w.as_ptr() as *const u8,
                byte_len,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW failed: OS status {status}"));
        }
        Ok(())
    }

    pub(crate) fn ensure_hkcu_uri_registered_at(
        base_subkey: &str,
        exe_path: &Path,
    ) -> Result<UriRegistrationOutcome, String> {
        let expected_cmd = format_ledr_uri_command(exe_path);
        let cmd_subkey = format!(r"{base_subkey}\shell\open\command");
        let display_key = format!(r"HKCU\{base_subkey}");

        // Fast read-only check so repeated `--notify` launches avoid registry writes.
        if let (Ok(Some(base_key)), Ok(Some(cmd_key))) = (
            reg_open_hkcu(base_subkey, KEY_QUERY_VALUE),
            reg_open_hkcu(&cmd_subkey, KEY_QUERY_VALUE),
        ) {
            let desc_ok =
                reg_query_sz(&base_key, None).ok().flatten().as_deref() == Some(LEDR_URI_DESCRIPTION);
            let proto_ok =
                reg_query_sz(&base_key, Some("URL Protocol")).ok().flatten().as_deref() == Some("");
            let cmd_ok =
                reg_query_sz(&cmd_key, None).ok().flatten().as_deref() == Some(expected_cmd.as_str());
            if desc_ok && proto_ok && cmd_ok {
                return Ok(UriRegistrationOutcome {
                    registry_key: display_key,
                    command: expected_cmd,
                    updated: false,
                });
            }
        }

        let base_key = reg_create_hkcu(base_subkey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        reg_set_sz(&base_key, None, LEDR_URI_DESCRIPTION)?;
        reg_set_sz(&base_key, Some("URL Protocol"), "")?;

        let cmd_key = reg_create_hkcu(&cmd_subkey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        reg_set_sz(&cmd_key, None, &expected_cmd)?;

        Ok(UriRegistrationOutcome {
            registry_key: display_key,
            command: expected_cmd,
            updated: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn reg_delete_hkcu_tree(subkey: &str) {
        let subkey_w = to_utf16_nul(subkey);
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 under `HKEY_CURRENT_USER`.
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr());
        }
    }
}

/// Ensures per-user `HKCU\Software\Classes\ledr` protocol handler registration matches the
/// current `ledr-ui` executable path (idempotent; checks existing values before writing).
#[cfg(windows)]
pub(crate) fn ensure_hkcu_ledr_uri_registered() -> Result<UriRegistrationOutcome, String> {
    let exe_path =
        std::env::current_exe().map_err(|err| format!("failed to resolve current_exe: {err}"))?;
    win_uri_reg::ensure_hkcu_uri_registered_at(LEDR_URI_REG_SUBKEY, &exe_path)
}

#[cfg(not(windows))]
pub(crate) fn ensure_hkcu_ledr_uri_registered() -> Result<UriRegistrationOutcome, String> {
    Err("HKCU ledr:// URI registration is only supported on Windows".to_string())
}

pub(crate) fn build_register_uri_event(outcome: &UriRegistrationOutcome) -> RegisterUriEvent {
    RegisterUriEvent {
        mode: "register_uri".to_string(),
        scheme: "ledr".to_string(),
        registry_key: outcome.registry_key.clone(),
        command: outcome.command.clone(),
        updated: outcome.updated,
        status: if outcome.updated {
            "registered".to_string()
        } else {
            "already_registered".to_string()
        },
    }
}

fn dispatch_register_uri() -> Result<(), String> {
    let outcome = ensure_hkcu_ledr_uri_registered()?;
    let event = build_register_uri_event(&outcome);
    let json = serde_json::to_string(&event)
        .map_err(|err| format!("failed to serialize URI registration event: {err}"))?;
    println!("{json}");
    Ok(())
}

fn dispatch_notify_oneshot(alert_id: &str, ipc_client: &IpcClient) -> Result<(), String> {
    let disable_os_toast = is_os_toast_disabled();
    if !disable_os_toast {
        if let Err(err) = ensure_hkcu_ledr_uri_registered() {
            eprintln!("ledr-ui warning: failed to ensure HKCU ledr:// URI registration: {err}");
        }
    }
    let alerts_result = ipc_client.get_alerts(None, 50);
    let event = build_notify_oneshot_event(
        alert_id,
        ipc_client.pipe_name(),
        alerts_result,
        disable_os_toast,
    );
    let json = serde_json::to_string(&event)
        .map_err(|err| format!("failed to serialize notify oneshot event: {err}"))?;
    println!("{json}");
    Ok(())
}

const HONEYPOT_FILENAME: &str = "!00_LocalEDR_Canary_DoNotEdit.docx";
const HONEYPOT_FOLDERS: [&str; 3] = ["Documents", "Desktop", "Pictures"];
#[cfg_attr(not(windows), allow(dead_code))]
const CHROME_NMH_REG_SUBKEY: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge";
#[cfg_attr(not(windows), allow(dead_code))]
const EDGE_NMH_REG_SUBKEY: &str = r"Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HoneypotStatusItem {
    pub(crate) folder: String,
    pub(crate) path: String,
    pub(crate) deployed: bool,
    pub(crate) size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProtectedPathTemplate {
    pub(crate) category: String,
    pub(crate) label: String,
    pub(crate) path_template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BrowserShieldStatus {
    pub(crate) bridge_binary_path: String,
    pub(crate) bridge_binary_present: bool,
    pub(crate) native_host_registered: bool,
    pub(crate) uri_scheme_registered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LocalDefenseStatus {
    pub(crate) honeypots: Vec<HoneypotStatusItem>,
    pub(crate) protected_paths: Vec<ProtectedPathTemplate>,
    pub(crate) browser_shield: BrowserShieldStatus,
}

pub(crate) fn static_protected_path_templates() -> Vec<ProtectedPathTemplate> {
    vec![
        ProtectedPathTemplate {
            category: "CookieDb".to_string(),
            label: "Browser Cookies, Login Data & Local State".to_string(),
            path_template: r"%LOCALAPPDATA%\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave-Browser}\User Data\*\(Cookies|Login Data|Local State), %APPDATA%\Mozilla\Firefox\Profiles\*\(cookies.sqlite|logins.json|key4.db)".to_string(),
        },
        ProtectedPathTemplate {
            category: "SshKey".to_string(),
            label: "SSH Private Keys".to_string(),
            path_template: r"%USERPROFILE%\.ssh\*".to_string(),
        },
        ProtectedPathTemplate {
            category: "CloudCreds".to_string(),
            label: "AWS / GCP Credentials".to_string(),
            path_template: r"%USERPROFILE%\.aws\{credentials,config}, %USERPROFILE%\.config\gcloud\*".to_string(),
        },
        ProtectedPathTemplate {
            category: "EnvFile".to_string(),
            label: "Project .env Secrets (Registered Dev Roots)".to_string(),
            path_template: r"<DevRoots>\**\.env*".to_string(),
        },
        ProtectedPathTemplate {
            category: "Honeypot".to_string(),
            label: "Ransomware Decoy Files (Write/Delete)".to_string(),
            path_template: format!(r"%USERPROFILE%\{{Documents,Desktop,Pictures}}\{HONEYPOT_FILENAME}"),
        },
        ProtectedPathTemplate {
            category: "AutorunRegistry".to_string(),
            label: "Windows Autorun Registry Keys".to_string(),
            path_template: r"{HKCU,HKLM}\Software\Microsoft\Windows\CurrentVersion\{Run,RunOnce}".to_string(),
        },
    ]
}

/// Collects View 3 local defense status strictly without touching any real sensitive user files
/// (`Cookies`, `.ssh`, `.aws`, `gcloud`): only `std::fs::metadata` on decoy honeypot paths and
/// `ledr-bridge-nm.exe`, plus read-only registry readiness flags (Decision #4).
pub(crate) fn collect_local_defense_status_with(
    user_profile: Option<&Path>,
    bridge_path: &Path,
    native_host_registered: bool,
    uri_scheme_registered: bool,
) -> LocalDefenseStatus {
    let honeypots = HONEYPOT_FOLDERS
        .iter()
        .map(|folder| {
            let full_path = match user_profile {
                Some(profile) => profile.join(folder).join(HONEYPOT_FILENAME),
                None => PathBuf::from(format!(r"%USERPROFILE%\{folder}\{HONEYPOT_FILENAME}")),
            };
            let meta = if user_profile.is_some() {
                std::fs::metadata(&full_path).ok().filter(|m| m.is_file())
            } else {
                None
            };
            HoneypotStatusItem {
                folder: (*folder).to_string(),
                path: full_path.to_string_lossy().into_owned(),
                deployed: meta.is_some(),
                size_bytes: meta.map(|m| m.len()),
            }
        })
        .collect();

    let bridge_binary_present = std::fs::metadata(bridge_path)
        .map(|m| m.is_file())
        .unwrap_or(false);

    LocalDefenseStatus {
        honeypots,
        protected_paths: static_protected_path_templates(),
        browser_shield: BrowserShieldStatus {
            bridge_binary_path: bridge_path.to_string_lossy().into_owned(),
            bridge_binary_present,
            native_host_registered,
            uri_scheme_registered,
        },
    }
}

#[cfg(windows)]
fn is_hkcu_subkey_present(subkey: &str) -> bool {
    // `0x0001` = `KEY_QUERY_VALUE` (read-only probe).
    matches!(win_uri_reg::reg_open_hkcu(subkey, 0x0001), Ok(Some(_)))
}

#[cfg(not(windows))]
fn is_hkcu_subkey_present(_subkey: &str) -> bool {
    false
}

pub(crate) fn collect_local_defense_status() -> LocalDefenseStatus {
    let user_profile = std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let uri_cmd_key = format!(r"{LEDR_URI_REG_SUBKEY}\shell\open\command");
    let uri_scheme_registered = is_hkcu_subkey_present(&uri_cmd_key);
    let native_host_registered =
        is_hkcu_subkey_present(CHROME_NMH_REG_SUBKEY) || is_hkcu_subkey_present(EDGE_NMH_REG_SUBKEY);

    collect_local_defense_status_with(
        user_profile.as_deref(),
        Path::new(AUTHORIZED_BRIDGE_EXE_PATH),
        native_host_registered,
        uri_scheme_registered,
    )
}

fn run_gui(launch_mode: LaunchMode, ipc_client: IpcClient) -> Result<(), String> {
    let app = tauri::Builder::default()
        .manage(launch_mode)
        .manage(ipc_client)
        .invoke_handler(tauri::generate_handler![
            fetch_flight_recorder,
            fetch_pipeline_metrics,
            fetch_alerts,
            resolve_alert_action,
            fetch_rules,
            upsert_rule_action,
            delete_rule_action,
            check_domain_risk_action,
            fetch_local_defense_status,
            ping_daemon,
            get_launch_mode,
            build_process_tree_view,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                window.app_handle().exit(0);
            }
        })
        .build(tauri::generate_context!())
        .map_err(|err| format!("failed to build Tauri application: {err}"))?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { .. } = event {
            // Do not call `api.prevent_exit()`: closing the window must terminate
            // the UI process and WebView2 completely with 0 MB resident (`決定記録 L-08`).
        }
    });

    Ok(())
}

fn main() {
    let mode = match parse_launch_mode(std::env::args()) {
        Ok(mode) => mode,
        Err(err) => {
            eprintln!("ledr-ui argument error: {err}");
            std::process::exit(2);
        }
    };
    let ipc_client = IpcClient::default_endpoint();

    if matches!(mode, LaunchMode::RegisterUri) {
        if let Err(err) = dispatch_register_uri() {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if let LaunchMode::Notify(ref alert_id) = mode {
        if let Err(err) = dispatch_notify_oneshot(alert_id, &ipc_client) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(err) = run_gui(mode, ipc_client) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipc::{
        parse_ack_response, parse_alerts_response, parse_flight_recorder_response,
        parse_metrics_response, parse_ping_response, parse_rules_response,
    };
    use ledr_proto::{
        AlertSeverity, CanaryCategory, DnsQueryRecord, FileCanaryEventRecord, IpcRequest,
        IpcResponse, NetworkEventRecord, ProcessRecord, decode_ipc_frame, encode_ipc_frame,
    };
    use std::io::{self, Read, Write};
    use tree::build_process_tree;

    fn sample_process(
        pid: u32,
        create_ms: i64,
        parent_instance_id: Option<&str>,
        ppid: u32,
        exe_path: &str,
    ) -> ProcessRecord {
        ProcessRecord {
            process_instance_id: format!("{pid}:{}", create_ms * 10_000),
            pid,
            parent_instance_id: parent_instance_id.map(str::to_string),
            ppid,
            exe_path: exe_path.to_string(),
            command_line: Some(format!("{exe_path} --test")),
            sha256: None,
            signer_subject: None,
            is_trusted_os: false,
            user_sid: Some("S-1-5-21-1000".to_string()),
            origin_url: None,
            created_at_ms: create_ms,
            exited_at_ms: None,
        }
    }

    struct MockIpcStream<F> {
        tx_buf: Vec<u8>,
        rx_buf: Vec<u8>,
        rx_pos: usize,
        handler: F,
    }

    impl<F> MockIpcStream<F> {
        fn new(handler: F) -> Self {
            Self {
                tx_buf: Vec::new(),
                rx_buf: Vec::new(),
                rx_pos: 0,
                handler,
            }
        }
    }

    impl<F> Write for MockIpcStream<F>
    where
        F: FnMut(IpcRequest) -> IpcResponse,
    {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.tx_buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.tx_buf.len() >= 4 {
                let req: IpcRequest = decode_ipc_frame(&self.tx_buf)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                self.tx_buf.clear();
                let resp = (self.handler)(req);
                let frame = encode_ipc_frame(&resp)
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                self.rx_buf.extend_from_slice(&frame);
            }
            Ok(())
        }
    }

    impl<F> Read for MockIpcStream<F> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = self.rx_buf.len().saturating_sub(self.rx_pos);
            let n = remaining.min(buf.len());
            if n > 0 {
                buf[..n].copy_from_slice(&self.rx_buf[self.rx_pos..self.rx_pos + n]);
                self.rx_pos += n;
            }
            Ok(n)
        }
    }

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

    #[test]
    fn ui_05_build_process_tree_hierarchy_and_orphans() {
        let explorer = sample_process(100, 1_000, None, 0, r"C:\Windows\explorer.exe");
        let cmd = sample_process(
            200,
            2_000,
            Some(&explorer.process_instance_id),
            100,
            r"C:\Windows\System32\cmd.exe",
        );
        let ps_late = sample_process(
            302,
            3_500,
            Some(&cmd.process_instance_id),
            200,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        let ps_early = sample_process(
            301,
            3_000,
            Some(&cmd.process_instance_id),
            200,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        );
        let orphan_missing_parent_id = sample_process(
            400,
            1_500,
            Some("9999:999"),
            9999,
            r"C:\Users\dev\AppData\Local\Temp\dropper.exe",
        );
        let orphan_missing_ppid = sample_process(
            500,
            4_000,
            None,
            8888,
            r"C:\Windows\System32\svchost.exe",
        );

        let snapshot = FlightRecorderSnapshot {
            processes: vec![
                ps_late.clone(),
                orphan_missing_ppid.clone(),
                cmd.clone(),
                orphan_missing_parent_id.clone(),
                explorer.clone(),
                ps_early.clone(),
            ],
            dns_queries: vec![DnsQueryRecord {
                id: Some(1),
                timestamp_ms: 3_100,
                process_instance_id: ps_early.process_instance_id.clone(),
                query_name: "cdn-update.example".to_string(),
                query_type: 1,
                resolved_ips: vec!["203.0.113.10".to_string()],
                is_nrd: true,
            }],
            network_events: vec![
                NetworkEventRecord {
                    id: Some(1),
                    timestamp_ms: 3_120,
                    process_instance_id: ps_early.process_instance_id.clone(),
                    protocol: 6,
                    dst_ip: "203.0.113.10".to_string(),
                    dst_port: 443,
                    domain_hint: Some("cdn-update.example".to_string()),
                    action: "LOG".to_string(),
                },
                NetworkEventRecord {
                    id: Some(2),
                    timestamp_ms: 3_600,
                    process_instance_id: ps_late.process_instance_id.clone(),
                    protocol: 6,
                    dst_ip: "198.51.100.7".to_string(),
                    dst_port: 8443,
                    domain_hint: None,
                    action: "LOG".to_string(),
                },
            ],
            file_canary_events: vec![FileCanaryEventRecord {
                id: Some(1),
                timestamp_ms: 1_600,
                process_instance_id: orphan_missing_parent_id.process_instance_id.clone(),
                target_path: r"C:\Users\dev\.ssh\id_ed25519".to_string(),
                category: CanaryCategory::SshKey,
                access_mask: 0x0012_0089,
                action_taken: "SUSPENDED".to_string(),
            }],
            download_origins: Vec::new(),
        };

        let roots = build_process_tree(&snapshot);
        assert_eq!(roots.len(), 3);

        // Roots sorted by created_at_ms: explorer (1000), orphan_missing_parent_id (1500), orphan_missing_ppid (4000)
        assert_eq!(roots[0].process.pid, 100);
        assert!(!roots[0].is_orphan_root);
        assert_eq!(roots[0].children.len(), 1);

        let cmd_node = &roots[0].children[0];
        assert_eq!(cmd_node.process.pid, 200);
        assert!(!cmd_node.is_orphan_root);
        assert_eq!(cmd_node.children.len(), 2);
        assert_eq!(cmd_node.children[0].process.pid, 301);
        assert_eq!(cmd_node.children[0].dns_count, 1);
        assert_eq!(cmd_node.children[0].network_count, 1);
        assert_eq!(cmd_node.children[1].process.pid, 302);
        assert_eq!(cmd_node.children[1].network_count, 1);

        assert_eq!(roots[1].process.pid, 400);
        assert!(roots[1].is_orphan_root);
        assert_eq!(roots[1].canary_count, 1);

        assert_eq!(roots[2].process.pid, 500);
        assert!(roots[2].is_orphan_root);

        // Verify cycle protection never drops nodes or recurses infinitely.
        let mut cyc_a = sample_process(701, 5_000, Some("702:50000000"), 702, "a.exe");
        cyc_a.process_instance_id = "701:50000000".to_string();
        let mut cyc_b = sample_process(702, 5_000, Some("701:50000000"), 701, "b.exe");
        cyc_b.process_instance_id = "702:50000000".to_string();
        let cyclic_roots = build_process_tree(&FlightRecorderSnapshot {
            processes: vec![cyc_a, cyc_b],
            ..Default::default()
        });
        assert_eq!(cyclic_roots.len(), 1);
        assert!(cyclic_roots[0].is_orphan_root);
        assert_eq!(cyclic_roots[0].children.len(), 1);
    }

    #[test]
    fn ui_06_ipc_client_frame_roundtrip() {
        let expected_snapshot = FlightRecorderSnapshot {
            processes: vec![sample_process(
                420,
                10_000,
                None,
                0,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )],
            ..Default::default()
        };
        let expected_metrics = PipelineMetrics {
            high_priority_depth: 1,
            high_priority_capacity: ledr_proto::HIGH_PRIORITY_CHANNEL_CAPACITY,
            high_priority_processed: 42,
            telemetry_depth: 5,
            telemetry_capacity: ledr_proto::TELEMETRY_CHANNEL_CAPACITY,
            telemetry_processed: 128,
            telemetry_dropped: 0,
            active_processes: 1,
            pending_alerts: 0,
            uptime_secs: 99,
        };

        let snapshot_clone = expected_snapshot.clone();
        let metrics_clone = expected_metrics.clone();

        let mut stream = MockIpcStream::new(move |req| match req {
            IpcRequest::Ping => IpcResponse::Pong {
                daemon_version: "0.1.0".to_string(),
                protocol_version: ledr_proto::IPC_PROTOCOL_VERSION,
            },
            IpcRequest::GetFlightRecorder {
                limit,
                process_instance_id,
            } => {
                assert_eq!(limit, 50);
                assert_eq!(process_instance_id.as_deref(), Some("420:100000000"));
                IpcResponse::FlightRecorder(snapshot_clone.clone())
            }
            IpcRequest::GetPipelineMetrics => IpcResponse::Metrics(metrics_clone.clone()),
            IpcRequest::CheckDomainRisk { .. } => IpcResponse::Error {
                code: "NOT_IMPLEMENTED".to_string(),
                message: "stub error".to_string(),
            },
            other => panic!("unexpected request: {other:?}"),
        });

        let ping_resp = IpcClient::send_request_over_stream(&mut stream, &IpcRequest::Ping)
            .expect("ping roundtrip");
        assert_eq!(
            parse_ping_response(ping_resp).expect("parse pong"),
            "ledr-daemon v0.1.0 (proto v1)"
        );

        let fr_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::GetFlightRecorder {
                limit: 50,
                process_instance_id: Some("420:100000000".to_string()),
            },
        )
        .expect("flight recorder roundtrip");
        assert_eq!(
            parse_flight_recorder_response(fr_resp).expect("parse snapshot"),
            expected_snapshot
        );

        let metrics_resp =
            IpcClient::send_request_over_stream(&mut stream, &IpcRequest::GetPipelineMetrics)
                .expect("metrics roundtrip");
        assert_eq!(
            parse_metrics_response(metrics_resp).expect("parse metrics"),
            expected_metrics
        );

        let err_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::CheckDomainRisk {
                domain: "example.com".to_string(),
            },
        )
        .expect("error response roundtrip");
        let err_msg = parse_ping_response(err_resp).expect_err("error variant returns Err");
        assert!(err_msg.contains("NOT_IMPLEMENTED"));

        // Non-existent pipe endpoint returns a clean offline error without panicking.
        let offline_client = IpcClient::new(r"\\.\pipe\localedr-ui-nonexistent-test-pipe");
        let offline_err = offline_client
            .ping()
            .expect_err("missing pipe should fail gracefully");
        assert!(offline_err.contains("offline") || offline_err.contains("failed"));
    }

    #[test]
    fn ui_p2_01_parse_launch_mode_ledr_alert_uri() {
        assert_eq!(
            parse_launch_mode(["ledr-ui", "ledr://alert/alert-123"]),
            Ok(LaunchMode::AlertFocus("alert-123".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "LEDR://alert/alert-456/"]),
            Ok(LaunchMode::AlertFocus("alert-456".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "LeDr://Alert/Alert-Case-789/?source=toast#focus"]),
            Ok(LaunchMode::AlertFocus("Alert-Case-789".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--uri", "ledr://alert/uri-001"]),
            Ok(LaunchMode::AlertFocus("uri-001".to_string()))
        );
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--uri=LEDR://alert/uri-002/#action"]),
            Ok(LaunchMode::AlertFocus("uri-002".to_string()))
        );

        for invalid in [
            vec!["ledr-ui", "ledr://alert/"],
            vec!["ledr-ui", "ledr://alert/?q=1"],
            vec!["ledr-ui", "ledr://unknown/123"],
            vec!["ledr-ui", "ledr://alert/a/b"],
            vec!["ledr-ui", "--uri"],
            vec!["ledr-ui", "--uri="],
            vec!["ledr-ui", "--uri", "https://example.invalid/alert/1"],
        ] {
            assert!(
                parse_launch_mode(invalid.iter().copied()).is_err(),
                "expected invalid URI rejection for {invalid:?}"
            );
        }
    }

    #[test]
    fn ui_p2_02_winrt_toast_xml_escaping_and_launch_uri() {
        let summary = ToastAlertSummary {
            alert_id: "alert-&\"'<1>".to_string(),
            title: "Canary <Access> & 'Exfil' \"Attempt\"".to_string(),
            target_path: Some(r"C:\Users\A&B\<dev>\Cookies".to_string()),
            exe_path: Some(r"C:\Temp\steal&run.exe".to_string()),
            rule_id: Some("CANARY-COOKIE-01".to_string()),
            severity: Some("CRITICAL".to_string()),
            process_suspended: true,
            is_expired_suspended: false,
        };

        let xml = build_winrt_toast_xml(&summary);
        let expected_escaped_uri = "ledr://alert/alert-&amp;&quot;&apos;&lt;1&gt;";
        assert!(xml.contains(&format!("launch=\"{expected_escaped_uri}\"")));
        assert!(xml.contains("activationType=\"protocol\""));
        assert!(xml.contains(&format!("arguments=\"{expected_escaped_uri}\"")));
        assert!(xml.contains("[SUSPENDED]"));
        assert!(xml.contains("CRITICAL Canary &lt;Access&gt; &amp; &apos;Exfil&apos; &quot;Attempt&quot;"));
        assert!(xml.contains(r"Target: C:\Users\A&amp;B\&lt;dev&gt;\Cookies"));
        assert!(xml.contains(r"Process: C:\Temp\steal&amp;run.exe | Rule: CANARY-COOKIE-01"));
        assert!(xml.contains("<action content=\"Triage Alert\""));

        // Verify EXPIRED_SUSPENDED badge wording and absence of unescaped raw special chars inside text nodes.
        let expired_summary = ToastAlertSummary {
            alert_id: "alert-exp-1".to_string(),
            title: "Honeypot Modified".to_string(),
            target_path: Some(r"C:\Users\user\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string()),
            exe_path: None,
            rule_id: Some("CANARY-HONEYPOT".to_string()),
            severity: Some("CRITICAL".to_string()),
            process_suspended: true,
            is_expired_suspended: true,
        };
        let expired_xml = build_winrt_toast_xml(&expired_summary);
        assert!(expired_xml.contains("[EXPIRED_SUSPENDED · FROZEN]"));
        assert!(expired_xml.contains("launch=\"ledr://alert/alert-exp-1\""));

        // RFC 4648 base64 sanity check for PowerShell -EncodedCommand encoding.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ui_p2_03_ipc_get_alerts_and_list_rules_roundtrip() {
        let sample_alerts = vec![
            AlertRecord {
                alert_id: "alert-pending-1".to_string(),
                timestamp_ms: 1_700_000_010_000,
                severity: AlertSeverity::High,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "CANARY-COOKIE-DB".to_string(),
                title: "Chrome Cookies Read".to_string(),
                process_instance_id: Some("1001:133765432100000000".to_string()),
                process_suspended: true,
                status: AlertStatus::Pending,
                context_json: r#"{"target_path":"C:\\Users\\dev\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies","category":"cookie_db"}"#.to_string(),
                resolved_at_ms: None,
            },
            AlertRecord {
                alert_id: "alert-expired-2".to_string(),
                timestamp_ms: 1_700_000_000_000,
                severity: AlertSeverity::Critical,
                source_layer: "LAYER_1_CANARY".to_string(),
                rule_id: "CANARY-HONEYPOT".to_string(),
                title: "Honeypot Write Detected".to_string(),
                process_instance_id: Some("2002:133765432100000000".to_string()),
                process_suspended: true,
                status: AlertStatus::ExpiredSuspended,
                context_json: r#"{"target_path":"C:\\Users\\dev\\Documents\\!00_LocalEDR_Canary_DoNotEdit.docx","category":"honeypot","is_write_or_delete":true}"#.to_string(),
                resolved_at_ms: None,
            },
        ];

        let sample_rules = vec![AllowlistRuleRecord {
            rule_id: "rule-allow-1".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: r"C:\Program Files\DevTool\tool.exe".to_string(),
            sha256: Some("deadbeef".repeat(8)),
            signer_subject: Some("CN=DevTool Corp".to_string()),
            root_thumbprint: Some("00112233445566778899AABBCCDDEEFF00112233".to_string()),
            allowed_target: Some(r"C:\Users\*\Cookies".to_string()),
            created_at_ms: 1_700_000_020_000,
            created_by: "user".to_string(),
        }];

        let alerts_clone = sample_alerts.clone();
        let rules_clone = sample_rules.clone();

        let mut stream = MockIpcStream::new(move |req| match req {
            IpcRequest::GetAlerts { status, limit } => {
                assert_eq!(limit, 50);
                let filtered = match status {
                    Some(st) => alerts_clone
                        .iter()
                        .filter(|a| a.status == st)
                        .cloned()
                        .collect(),
                    None => alerts_clone.clone(),
                };
                IpcResponse::Alerts(filtered)
            }
            IpcRequest::ListRules { scope } => {
                let filtered = match scope {
                    Some(sc) => rules_clone
                        .iter()
                        .filter(|r| r.scope == sc)
                        .cloned()
                        .collect(),
                    None => rules_clone.clone(),
                };
                IpcResponse::Rules(filtered)
            }
            other => panic!("unexpected request: {other:?}"),
        });

        let all_alerts_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::GetAlerts {
                status: None,
                limit: 50,
            },
        )
        .expect("get_alerts roundtrip");
        assert_eq!(
            parse_alerts_response(all_alerts_resp).expect("parse alerts"),
            sample_alerts
        );

        let expired_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::GetAlerts {
                status: Some(AlertStatus::ExpiredSuspended),
                limit: 50,
            },
        )
        .expect("filtered get_alerts roundtrip");
        let expired_alerts = parse_alerts_response(expired_resp).expect("parse filtered alerts");
        assert_eq!(expired_alerts.len(), 1);
        assert_eq!(expired_alerts[0].alert_id, "alert-expired-2");

        let rules_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::ListRules {
                scope: Some(RuleScope::FileCanaryAllow),
            },
        )
        .expect("list_rules roundtrip");
        assert_eq!(
            parse_rules_response(rules_resp).expect("parse rules"),
            sample_rules
        );

        let err = parse_rules_response(IpcResponse::Error {
            code: "STORE_ERROR".to_string(),
            message: "db locked".to_string(),
        })
        .expect_err("error variant should return Err");
        assert!(err.contains("STORE_ERROR"));
    }

    #[test]
    fn ui_p2_04_ipc_resolve_alert_all_decisions_roundtrip() {
        let decisions = vec![
            (
                "alert-1",
                AlertDecision::TerminateAndBlock {
                    add_block_rule: true,
                },
                "resolved TERMINATED_BLOCKED",
            ),
            ("alert-2", AlertDecision::AllowOnce, "resolved APPROVED_ONCE"),
            (
                "alert-3",
                AlertDecision::AllowPermanent {
                    use_signer_if_available: true,
                    allow_dest: Some(r"C:\Users\*\Cookies".to_string()),
                },
                "resolved APPROVED_RULE",
            ),
        ];

        let mut stream = MockIpcStream::new(|req| match req {
            IpcRequest::ResolveAlert { alert_id, decision } => {
                if alert_id == "missing-alert" {
                    IpcResponse::Error {
                        code: "NOT_FOUND".to_string(),
                        message: "alert not found".to_string(),
                    }
                } else {
                    IpcResponse::Ack {
                        message: format!(
                            "resolved {} for {alert_id}",
                            decision.resulting_status().as_db_str()
                        ),
                    }
                }
            }
            other => panic!("unexpected request: {other:?}"),
        });

        for (alert_id, decision, expected_fragment) in decisions {
            let resp = IpcClient::send_request_over_stream(
                &mut stream,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_id.to_string(),
                    decision,
                },
            )
            .expect("resolve_alert roundtrip");
            let msg = parse_ack_response(resp).expect("parse ack");
            assert!(msg.contains(expected_fragment), "got ack: {msg}");
            assert!(msg.contains(alert_id));
        }

        let err_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::ResolveAlert {
                alert_id: "missing-alert".to_string(),
                decision: AlertDecision::AllowOnce,
            },
        )
        .expect("missing alert roundtrip");
        let err = parse_ack_response(err_resp).expect_err("not found returns Err");
        assert!(err.contains("NOT_FOUND"));
    }

    #[test]
    fn ui_p2_05_notify_oneshot_json_output() {
        assert!(is_os_toast_disabled_value(Some("1")));
        assert!(is_os_toast_disabled_value(Some("true")));
        assert!(is_os_toast_disabled_value(Some("YES")));
        assert!(!is_os_toast_disabled_value(None));
        assert!(!is_os_toast_disabled_value(Some("")));
        assert!(!is_os_toast_disabled_value(Some("0")));
        assert!(!is_os_toast_disabled_value(Some("false")));

        let live_alert = AlertRecord {
            alert_id: "alert-cookie-42".to_string(),
            timestamp_ms: 1_700_000_050_000,
            severity: AlertSeverity::Critical,
            source_layer: "LAYER_1_CANARY".to_string(),
            rule_id: "CANARY-COOKIE-DB".to_string(),
            title: "Chrome Cookies Accessed".to_string(),
            process_instance_id: Some("4242:133765432100000000".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "target_path": r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Cookies",
                "exe_path": r"C:\Users\dev\Downloads\stealer.exe",
                "category": "cookie_db",
                "is_write_or_delete": false,
                "access_mask": 0x00120089
            })
            .to_string(),
            resolved_at_ms: None,
        };

        let online_event = build_notify_oneshot_event(
            "alert-cookie-42",
            r"\\.\pipe\localedr-ipc",
            Ok(vec![live_alert]),
            true,
        );
        let online_json = serde_json::to_string(&online_event).expect("serialize online event");
        let parsed: serde_json::Value =
            serde_json::from_str(&online_json).expect("valid JSON output");

        assert_eq!(parsed["mode"], "notify_oneshot");
        assert_eq!(parsed["alert_id"], "alert-cookie-42");
        assert_eq!(parsed["launch_uri"], "ledr://alert/alert-cookie-42");
        assert_eq!(parsed["daemon_reachable"], true);
        assert_eq!(parsed["alert_found"], true);
        assert_eq!(parsed["process_suspended"], true);
        assert_eq!(parsed["os_toast_status"], "disabled_by_env");
        assert_eq!(parsed["status"], "disabled_by_env");
        assert_eq!(
            parsed["target_path"],
            r"C:\Users\dev\AppData\Local\Google\Chrome\User Data\Default\Cookies"
        );
        let toast_xml = parsed["toast_xml"].as_str().expect("toast_xml string");
        assert!(toast_xml.contains("launch=\"ledr://alert/alert-cookie-42\""));
        assert!(toast_xml.contains("[SUSPENDED]"));
        assert!(toast_xml.contains("Chrome Cookies Accessed"));

        // Graceful fallback when daemon is offline.
        let offline_client = IpcClient::new(r"\\.\pipe\localedr-ui-nonexistent-test-pipe");
        let offline_event = build_notify_oneshot_event(
            "alert-offline-99",
            offline_client.pipe_name(),
            offline_client.get_alerts(None, 50),
            true,
        );
        assert!(!offline_event.daemon_reachable);
        assert!(!offline_event.alert_found);
        assert_eq!(offline_event.launch_uri, "ledr://alert/alert-offline-99");
        assert!(offline_event
            .toast_xml
            .contains("launch=\"ledr://alert/alert-offline-99\""));
        assert!(dispatch_notify_oneshot_disabled_check(&offline_client).is_ok());
    }

    fn dispatch_notify_oneshot_disabled_check(offline_client: &IpcClient) -> Result<(), String> {
        let ev = build_notify_oneshot_event(
            "alert-check",
            offline_client.pipe_name(),
            offline_client.get_alerts(None, 50),
            true,
        );
        serde_json::to_string(&ev)
            .map(|_| ())
            .map_err(|err| err.to_string())
    }

    #[test]
    fn ui_p2_06_register_uri_args_and_hkcu_idempotent() {
        assert_eq!(
            parse_launch_mode(["ledr-ui", "--register-uri"]),
            Ok(LaunchMode::RegisterUri)
        );
        assert!(parse_launch_mode(["ledr-ui", "--register-uri=true"]).is_err());

        assert_eq!(
            format_ledr_uri_command(std::path::Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe")),
            r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
        );
        assert_eq!(
            format_ledr_uri_command(std::path::Path::new(r"\\?\C:\Program Files\LocalEDR\ledr-ui.exe")),
            r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
        );

        let sample_outcome = UriRegistrationOutcome {
            registry_key: format!(r"HKCU\{LEDR_URI_REG_SUBKEY}"),
            command: r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#.to_string(),
            updated: true,
        };
        let event = build_register_uri_event(&sample_outcome);
        let json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).expect("serialize register_uri"))
                .expect("valid JSON");
        assert_eq!(json["mode"], "register_uri");
        assert_eq!(json["scheme"], "ledr");
        assert_eq!(json["registry_key"], r"HKCU\Software\Classes\ledr");
        assert_eq!(json["updated"], true);
        assert_eq!(json["status"], "registered");

        #[cfg(windows)]
        {
            struct TestKeyCleanup(String);
            impl Drop for TestKeyCleanup {
                fn drop(&mut self) {
                    win_uri_reg::reg_delete_hkcu_tree(&self.0);
                }
            }

            let root_cleanup = format!(r"Software\LocalEDRTest\ui-p2-06-{}", std::process::id());
            let subkey = format!(r"{root_cleanup}\ledr");
            let _guard = TestKeyCleanup(root_cleanup);

            let first_exe = std::path::Path::new(r"C:\Temp\LocalEDR\v1\ledr-ui.exe");
            let first = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, first_exe)
                .expect("initial test HKCU registration");
            assert!(first.updated);
            assert_eq!(first.command, r#""C:\Temp\LocalEDR\v1\ledr-ui.exe" "%1""#);

            let base_key = win_uri_reg::reg_open_hkcu(&subkey, 0x0001)
                .expect("open base key")
                .expect("base key exists");
            assert_eq!(
                win_uri_reg::reg_query_sz(&base_key, None).expect("query default"),
                Some(LEDR_URI_DESCRIPTION.to_string())
            );
            assert_eq!(
                win_uri_reg::reg_query_sz(&base_key, Some("URL Protocol"))
                    .expect("query URL Protocol"),
                Some(String::new())
            );

            // Second call with identical path must be idempotent (`updated == false`).
            let second = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, first_exe)
                .expect("idempotent check");
            assert!(!second.updated);
            assert_eq!(build_register_uri_event(&second).status, "already_registered");

            // Changing executable path updates `shell\open\command` (`updated == true`).
            let next_exe = std::path::Path::new(r"C:\Program Files\LocalEDR\ledr-ui.exe");
            let third = win_uri_reg::ensure_hkcu_uri_registered_at(&subkey, next_exe)
                .expect("update path");
            assert!(third.updated);
            assert_eq!(
                third.command,
                r#""C:\Program Files\LocalEDR\ledr-ui.exe" "%1""#
            );
        }
    }

    #[test]
    fn ui_p3_01_ipc_upsert_delete_rule_and_domain_risk_roundtrip() {
        let rule = AllowlistRuleRecord {
            rule_id: "RULE-UI-P3-01".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Tools\bad.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.5".to_string()),
            created_at_ms: 1_732_070_000_000,
            created_by: "user_policy".to_string(),
        };

        let mut stream = MockIpcStream::new(|req| match req {
            IpcRequest::UpsertRule { rule: r } => IpcResponse::Ack {
                message: format!("rule {} saved", r.rule_id),
            },
            IpcRequest::DeleteRule { rule_id } => IpcResponse::Ack {
                message: format!("rule {rule_id} deleted"),
            },
            IpcRequest::CheckDomainRisk { domain } => IpcResponse::DomainRisk {
                domain: domain.clone(),
                is_nrd: domain.ends_with(".fresh-c2.example"),
                is_homograph: domain.contains("xn--"),
                matched_brand: if domain.contains("xn--") {
                    Some("paypal.com".to_string())
                } else {
                    None
                },
            },
            other => IpcResponse::Error {
                code: "UNEXPECTED".to_string(),
                message: format!("{other:?}"),
            },
        });

        let upsert_resp =
            IpcClient::send_request_over_stream(&mut stream, &IpcRequest::UpsertRule { rule })
                .expect("upsert roundtrip");
        let upsert_msg = parse_ack_response(upsert_resp).expect("parse upsert ack");
        assert!(upsert_msg.contains("RULE-UI-P3-01"));

        let del_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::DeleteRule {
                rule_id: "RULE-UI-P3-01".to_string(),
            },
        )
        .expect("delete roundtrip");
        let del_msg = parse_ack_response(del_resp).expect("parse delete ack");
        assert!(del_msg.contains("RULE-UI-P3-01"));

        let risk_resp = IpcClient::send_request_over_stream(
            &mut stream,
            &IpcRequest::CheckDomainRisk {
                domain: "api.fresh-c2.example".to_string(),
            },
        )
        .expect("domain risk roundtrip");
        let risk = ipc::parse_domain_risk_response(risk_resp).expect("parse domain risk");
        assert_eq!(risk.domain, "api.fresh-c2.example");
        assert!(risk.is_nrd);
        assert!(!risk.is_homograph);
        assert!(risk.matched_brand.is_none());
    }

    #[test]
    fn ui_p3_02_local_defense_status_honeypot_detection_and_static_templates() {
        let tmp_root = std::env::temp_dir().join(format!(
            "ledr-ui-p3-status-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp_root);
        let docs = tmp_root.join("Documents");
        let desk = tmp_root.join("Desktop");
        std::fs::create_dir_all(&docs).expect("create Documents");
        std::fs::create_dir_all(&desk).expect("create Desktop");
        std::fs::write(docs.join(HONEYPOT_FILENAME), b"decoy-docx-bytes-1")
            .expect("write Documents honeypot");
        std::fs::write(desk.join(HONEYPOT_FILENAME), b"decoy-docx-2")
            .expect("write Desktop honeypot");
        let fake_bridge = tmp_root.join("ledr-bridge-nm.exe");
        std::fs::write(&fake_bridge, b"stub-bridge").expect("write bridge stub");

        let status = collect_local_defense_status_with(
            Some(&tmp_root),
            &fake_bridge,
            true,
            false,
        );
        assert_eq!(status.honeypots.len(), 3);
        let doc_item = status
            .honeypots
            .iter()
            .find(|h| h.folder == "Documents")
            .expect("Documents item");
        assert!(doc_item.deployed);
        assert_eq!(doc_item.size_bytes, Some(18));

        let desk_item = status
            .honeypots
            .iter()
            .find(|h| h.folder == "Desktop")
            .expect("Desktop item");
        assert!(desk_item.deployed);
        assert_eq!(desk_item.size_bytes, Some(12));

        let pic_item = status
            .honeypots
            .iter()
            .find(|h| h.folder == "Pictures")
            .expect("Pictures item");
        assert!(!pic_item.deployed);
        assert_eq!(pic_item.size_bytes, None);

        assert_eq!(status.protected_paths.len(), 6);
        assert!(status.protected_paths.iter().any(|p| p.category == "CookieDb"));
        assert!(status.protected_paths.iter().any(|p| p.category == "SshKey"));
        assert!(status.protected_paths.iter().any(|p| p.category == "CloudCreds"));
        assert!(status.protected_paths.iter().any(|p| p.category == "EnvFile"));
        assert!(status.protected_paths.iter().any(|p| p.category == "Honeypot"));
        assert!(status.protected_paths.iter().any(|p| p.category == "AutorunRegistry"));

        assert!(status.browser_shield.bridge_binary_present);
        assert!(status.browser_shield.native_host_registered);
        assert!(!status.browser_shield.uri_scheme_registered);

        let _ = std::fs::remove_dir_all(&tmp_root);
    }

    #[test]
    fn ui_p3_03_network_alert_toast_extracts_dst_and_domain() {
        let net_alert = AlertRecord {
            alert_id: "net-alert-p3".to_string(),
            timestamp_ms: 1_732_070_000_000,
            severity: AlertSeverity::High,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: "LEDR-NET-UNKNOWN-OUTBOUND".to_string(),
            title: "Unknown Process Outbound Connection".to_string(),
            process_instance_id: Some("6000:133765432100000000".to_string()),
            process_suspended: true,
            status: AlertStatus::Pending,
            context_json: serde_json::json!({
                "dst_ip": "198.51.100.42",
                "dst_port": 443,
                "domain_hint": "c2.fresh-nrd.example",
                "exe_path": r"C:\Tools\probe.exe",
            })
            .to_string(),
            resolved_at_ms: None,
        };
        let summary = summarize_alert_for_toast(&net_alert.alert_id, Some(&net_alert));
        assert_eq!(
            summary.target_path.as_deref(),
            Some("c2.fresh-nrd.example (198.51.100.42:443)")
        );
        assert_eq!(summary.exe_path.as_deref(), Some(r"C:\Tools\probe.exe"));
        let xml = build_winrt_toast_xml(&summary);
        assert!(xml.contains("c2.fresh-nrd.example (198.51.100.42:443)"));
    }
}
