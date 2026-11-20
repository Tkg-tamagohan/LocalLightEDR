use crate::ipc::IpcClient;
#[cfg(windows)]
use crate::uri_reg::LEDR_AUMID;
use crate::uri_reg::ensure_hkcu_ledr_uri_registered;
use ledr_proto::{AlertRecord, AlertStatus};
use serde::{Deserialize, Serialize};

/// Environment variable disabling OS WinRT toast emission during headless/CI tests.
pub const DISABLE_OS_TOAST_ENV: &str = "LEDR_UI_DISABLE_OS_TOAST";

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
    pub(crate) launch_uri: String,
    ipc_pipe: String,
    pub(crate) daemon_reachable: bool,
    pub(crate) alert_found: bool,
    title: String,
    target_path: Option<String>,
    process_suspended: bool,
    pub(crate) toast_xml: String,
    os_toast_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_toast_error: Option<String>,
    status: String,
}

struct OsToastOutcome {
    status: &'static str,
    error: Option<String>,
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

#[cfg(test)]
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

pub(crate) fn summarize_alert_for_toast(alert_id: &str, alert: Option<&AlertRecord>) -> ToastAlertSummary {
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

/// Returns `true` when Windows global toast notifications are explicitly disabled
/// (`HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications\ToastEnabled == 0`).
pub(crate) fn is_os_toast_suppressed_by_setting(toast_enabled: Option<u32>) -> bool {
    toast_enabled == Some(0)
}

#[cfg(windows)]
fn read_hkcu_toast_enabled() -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\PushNotifications")
        .ok()?;
    key.get_value::<u32, _>("ToastEnabled").ok()
}

#[cfg(windows)]
struct ComGuard {
    should_uninit: bool,
}

#[cfg(windows)]
impl ComGuard {
    fn init_multithreaded() -> Self {
        use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
        // SAFETY: `CoInitializeEx` with `None` reserved pointer is valid on the calling thread.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self {
            should_uninit: hr.is_ok(),
        }
    }
}

#[cfg(windows)]
impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            use windows::Win32::System::Com::CoUninitialize;
            // SAFETY: Paired with a successful `CoInitializeEx` on this thread.
            unsafe {
                CoUninitialize();
            }
        }
    }
}

#[cfg(windows)]
fn dispatch_winrt_toast_native(toast_xml: &str, aumid: &str) -> Result<(), String> {
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows::core::HSTRING;

    let _com = ComGuard::init_multithreaded();
    let doc = XmlDocument::new().map_err(|err| format!("XmlDocument::new failed: {err}"))?;
    doc.LoadXml(&HSTRING::from(toast_xml))
        .map_err(|err| format!("XmlDocument::LoadXml failed: {err}"))?;
    let toast = ToastNotification::CreateToastNotification(&doc)
        .map_err(|err| format!("ToastNotification::CreateToastNotification failed: {err}"))?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))
        .map_err(|err| format!("CreateToastNotifierWithId('{aumid}') failed: {err}"))?;
    notifier
        .Show(&toast)
        .map_err(|err| format!("ToastNotifier::Show failed: {err}"))?;
    Ok(())
}

#[cfg(windows)]
fn dispatch_os_toast_nonblocking(toast_xml: &str, disable_os_toast: bool) -> OsToastOutcome {
    if disable_os_toast {
        return OsToastOutcome {
            status: "disabled_by_env",
            error: None,
        };
    }

    if is_os_toast_suppressed_by_setting(read_hkcu_toast_enabled()) {
        return OsToastOutcome {
            status: "suppressed_by_os_settings",
            error: Some(
                "Windows notifications are disabled (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\ToastEnabled = 0). Enable 'Settings > System > Notifications' to display alert toasts.".to_string(),
            ),
        };
    }

    match dispatch_winrt_toast_native(toast_xml, LEDR_AUMID) {
        Ok(()) => OsToastOutcome {
            status: "dispatched",
            error: None,
        },
        Err(err) => OsToastOutcome {
            status: "winrt_toast_failed",
            error: Some(err),
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
        "suppressed_by_os_settings" => "suppressed_by_os_settings",
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

pub(crate) fn dispatch_notify_oneshot(alert_id: &str, ipc_client: &IpcClient) -> Result<(), String> {
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
