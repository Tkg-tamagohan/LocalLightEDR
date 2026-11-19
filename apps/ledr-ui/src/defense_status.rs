#[cfg(windows)]
use crate::uri_reg::win_uri_reg;
use crate::uri_reg::LEDR_URI_REG_SUBKEY;
use ledr_proto::AUTHORIZED_BRIDGE_EXE_PATH;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const HONEYPOT_FILENAME: &str = "!00_LocalEDR_Canary_DoNotEdit.docx";
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
