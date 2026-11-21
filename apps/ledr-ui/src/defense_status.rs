#[cfg(windows)]
use crate::uri_reg::{RegDefaultSzProbe, win_uri_reg};
#[cfg(windows)]
use crate::uri_reg::LEDR_URI_REG_SUBKEY;
use ledr_proto::AUTHORIZED_BRIDGE_EXE_PATH;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) const HONEYPOT_FILENAME: &str = "!00_LocalEDR_Canary_DoNotEdit.docx";
const HONEYPOT_FOLDERS: [&str; 3] = ["Documents", "Desktop", "Pictures"];
#[cfg_attr(not(windows), allow(dead_code))]
const CHROME_NMH_REG_SUBKEY: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge";
#[cfg_attr(not(windows), allow(dead_code))]
const EDGE_NMH_REG_SUBKEY: &str = r"Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge";
#[cfg_attr(not(windows), allow(dead_code))]
const BRAVE_NMH_REG_SUBKEY: &str =
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.localedr.bridge";

pub(crate) const NATIVE_HOST_NAME: &str = "com.localedr.bridge";
pub(crate) const EXPECTED_CHROME_EXTENSION_ID: &str = "ecelachfiiiiiibpjeomfncgpegbpanh";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistryStringProbe {
    Absent,
    Present(String),
    EmptyOrInvalidType,
    AccessError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserRegistryProbe {
    pub(crate) browser: String,
    pub(crate) hkcu: RegistryStringProbe,
    pub(crate) hklm: RegistryStringProbe,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BrowserShieldProbe {
    pub(crate) browsers: Vec<BrowserRegistryProbe>,
    pub(crate) uri_hkcu: bool,
    pub(crate) uri_hklm: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BrowserRegistrationDetail {
    pub(crate) browser: String,
    pub(crate) effective_scope: Option<String>,
    pub(crate) hkcu_registered: bool,
    pub(crate) hklm_registered: bool,
    pub(crate) manifest_path: Option<String>,
    pub(crate) manifest_valid: bool,
    pub(crate) manifest_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BrowserShieldStatus {
    pub(crate) bridge_binary_path: String,
    pub(crate) bridge_binary_present: bool,
    pub(crate) native_host_registered: bool,
    pub(crate) uri_scheme_registered: bool,
    pub(crate) native_host_scope: Option<String>,
    pub(crate) registered_browsers: Vec<String>,
    pub(crate) manifest_path: Option<String>,
    pub(crate) manifest_valid: bool,
    pub(crate) manifest_error: Option<String>,
    pub(crate) uri_scheme_scope: Option<String>,
    pub(crate) expected_extension_id: String,
    pub(crate) browsers: Vec<BrowserRegistrationDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LocalDefenseStatus {
    pub(crate) honeypots: Vec<HoneypotStatusItem>,
    pub(crate) protected_paths: Vec<ProtectedPathTemplate>,
    pub(crate) browser_shield: BrowserShieldStatus,
}

#[derive(Debug, Deserialize)]
struct NativeMessagingManifestDoc {
    name: String,
    #[serde(rename = "type")]
    host_type: String,
    path: String,
    allowed_origins: Vec<String>,
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

/// Validates an on-disk Native Messaging Host manifest without trusting oversized or malformed files.
pub(crate) fn validate_manifest_file(
    path: &Path,
    expected_extension_id: &str,
) -> Result<(), String> {
    let path_meta = std::fs::metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            "manifest file does not exist".to_string()
        } else {
            format!("failed to stat manifest: {err}")
        }
    })?;
    if !path_meta.is_file() {
        return Err("manifest path is not a regular file".to_string());
    }

    let file = std::fs::File::open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            "manifest file does not exist".to_string()
        } else {
            format!("failed to open manifest: {err}")
        }
    })?;
    let meta = file
        .metadata()
        .map_err(|err| format!("failed to stat manifest: {err}"))?;
    if !meta.is_file() {
        return Err("manifest path is not a regular file".to_string());
    }

    let mut buf = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|err| format!("failed to read manifest: {err}"))?;
    if buf.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest exceeds 64 KiB limit".to_string());
    }

    let parsed: NativeMessagingManifestDoc = serde_json::from_slice(&buf)
        .map_err(|err| format!("invalid manifest JSON: {err}"))?;

    let mut problems = Vec::new();
    if parsed.name != NATIVE_HOST_NAME {
        problems.push(format!(
            "manifest 'name' is '{}', expected '{NATIVE_HOST_NAME}'",
            parsed.name
        ));
    }
    if parsed.host_type != "stdio" {
        problems.push(format!(
            "manifest 'type' is '{}', expected 'stdio'",
            parsed.host_type
        ));
    }

    let exe_trimmed = parsed.path.trim();
    if exe_trimmed.is_empty() {
        problems.push("manifest 'path' is empty".to_string());
    } else {
        let exe_path = Path::new(exe_trimmed);
        if !exe_path.is_absolute() {
            problems.push(format!("manifest 'path' must be absolute: '{exe_trimmed}'"));
        } else if !exe_path.is_file() {
            problems.push(format!("bridge executable '{exe_trimmed}' not found"));
        }
    }

    let expected_origin = format!("chrome-extension://{expected_extension_id}/");
    if !parsed
        .allowed_origins
        .iter()
        .any(|origin| origin.eq_ignore_ascii_case(&expected_origin))
    {
        problems.push(format!(
            "allowed_origins does not contain '{expected_origin}'"
        ));
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

fn format_scope(has_hkcu: bool, has_hklm: bool) -> Option<String> {
    match (has_hkcu, has_hklm) {
        (true, true) => Some("HKCU+HKLM".to_string()),
        (true, false) => Some("HKCU".to_string()),
        (false, true) => Some("HKLM".to_string()),
        (false, false) => None,
    }
}

fn browser_sort_rank(name: &str) -> usize {
    match name {
        "Chrome" => 0,
        "Edge" => 1,
        "Brave" => 2,
        _ => 3,
    }
}

/// Collects View 3 local defense status strictly without touching any real sensitive user files
/// (`Cookies`, `.ssh`, `.aws`, `gcloud`): only `std::fs::metadata` on decoy honeypot paths and
/// `ledr-bridge-nm.exe`, read-only `HKCU`/`HKLM` registry probes, and validation of the referenced
/// Native Messaging Host manifest files.
pub(crate) fn collect_local_defense_status_with_probe(
    user_profile: Option<&Path>,
    bridge_path: &Path,
    probe: &BrowserShieldProbe,
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

    let mut ordered_probes: Vec<&BrowserRegistryProbe> = probe.browsers.iter().collect();
    ordered_probes.sort_by_key(|entry| browser_sort_rank(&entry.browser));

    let mut seen_browsers = HashSet::new();
    let mut details = Vec::new();
    let mut registered_browsers = Vec::new();
    let mut any_hkcu = false;
    let mut any_hklm = false;

    for entry in ordered_probes {
        if !seen_browsers.insert(entry.browser.as_str()) {
            continue;
        }
        let hkcu_registered = !matches!(entry.hkcu, RegistryStringProbe::Absent);
        let hklm_registered = !matches!(entry.hklm, RegistryStringProbe::Absent);
        any_hkcu |= hkcu_registered;
        any_hklm |= hklm_registered;

        // Chromium resolves HKCU NativeMessagingHosts before HKLM when both exist.
        let (effective_scope, active_probe) = if hkcu_registered {
            (Some("HKCU".to_string()), Some(&entry.hkcu))
        } else if hklm_registered {
            (Some("HKLM".to_string()), Some(&entry.hklm))
        } else {
            (None, None)
        };

        let (manifest_path, manifest_valid, manifest_error) = match active_probe {
            None | Some(RegistryStringProbe::Absent) => (None, false, None),
            Some(RegistryStringProbe::Present(path_str)) => {
                match validate_manifest_file(Path::new(path_str), EXPECTED_CHROME_EXTENSION_ID) {
                    Ok(()) => (Some(path_str.clone()), true, None),
                    Err(err) => (Some(path_str.clone()), false, Some(err)),
                }
            }
            Some(RegistryStringProbe::EmptyOrInvalidType) => (
                None,
                false,
                Some("registry default value is empty or not REG_SZ".to_string()),
            ),
            Some(RegistryStringProbe::AccessError(err)) => (None, false, Some(err.clone())),
        };

        if hkcu_registered || hklm_registered {
            registered_browsers.push(entry.browser.clone());
        }

        details.push(BrowserRegistrationDetail {
            browser: entry.browser.clone(),
            effective_scope,
            hkcu_registered,
            hklm_registered,
            manifest_path,
            manifest_valid,
            manifest_error,
        });
    }

    let native_host_registered = !registered_browsers.is_empty();
    let native_host_scope = format_scope(any_hkcu, any_hklm);
    let registered_details: Vec<&BrowserRegistrationDetail> = details
        .iter()
        .filter(|d| d.hkcu_registered || d.hklm_registered)
        .collect();
    let all_valid = !registered_details.is_empty()
        && registered_details.iter().all(|d| d.manifest_valid);

    let (manifest_path, manifest_valid, manifest_error) = if all_valid {
        (
            registered_details
                .first()
                .and_then(|d| d.manifest_path.clone()),
            true,
            None,
        )
    } else {
        let first_invalid = registered_details.iter().find(|d| !d.manifest_valid);
        let chosen_path = first_invalid
            .and_then(|d| d.manifest_path.clone())
            .or_else(|| registered_details.iter().find_map(|d| d.manifest_path.clone()));
        let errors: Vec<String> = registered_details
            .iter()
            .filter(|d| !d.manifest_valid)
            .map(|d| {
                format!(
                    "{}: {}",
                    d.browser,
                    d.manifest_error
                        .as_deref()
                        .unwrap_or("invalid manifest")
                )
            })
            .collect();
        (
            chosen_path,
            false,
            (!errors.is_empty()).then(|| errors.join("; ")),
        )
    };

    let uri_scheme_scope = format_scope(probe.uri_hkcu, probe.uri_hklm);
    let uri_scheme_registered = uri_scheme_scope.is_some();

    LocalDefenseStatus {
        honeypots,
        protected_paths: static_protected_path_templates(),
        browser_shield: BrowserShieldStatus {
            bridge_binary_path: bridge_path.to_string_lossy().into_owned(),
            bridge_binary_present,
            native_host_registered,
            uri_scheme_registered,
            native_host_scope,
            registered_browsers,
            manifest_path,
            manifest_valid,
            manifest_error,
            uri_scheme_scope,
            expected_extension_id: EXPECTED_CHROME_EXTENSION_ID.to_string(),
            browsers: details,
        },
    }
}

/// Backward-compatible wrapper retained for existing Phase 3 callers/tests (`ui_p3_02`).
#[cfg(test)]
pub(crate) fn collect_local_defense_status_with(
    user_profile: Option<&Path>,
    bridge_path: &Path,
    native_host_registered: bool,
    uri_scheme_registered: bool,
) -> LocalDefenseStatus {
    let browsers = if native_host_registered {
        vec![BrowserRegistryProbe {
            browser: "Chrome".to_string(),
            hkcu: RegistryStringProbe::EmptyOrInvalidType,
            hklm: RegistryStringProbe::Absent,
        }]
    } else {
        Vec::new()
    };
    collect_local_defense_status_with_probe(
        user_profile,
        bridge_path,
        &BrowserShieldProbe {
            browsers,
            uri_hkcu: uri_scheme_registered,
            uri_hklm: false,
        },
    )
}

#[cfg(windows)]
fn probe_reg_string(is_hklm: bool, subkey: &str) -> RegistryStringProbe {
    match win_uri_reg::reg_query_default_sz_in_hive(is_hklm, subkey) {
        Ok(RegDefaultSzProbe::Absent) => RegistryStringProbe::Absent,
        Ok(RegDefaultSzProbe::Present(val)) => RegistryStringProbe::Present(val),
        Ok(RegDefaultSzProbe::EmptyOrInvalidType) => RegistryStringProbe::EmptyOrInvalidType,
        Err(err) => RegistryStringProbe::AccessError(err),
    }
}

#[cfg(windows)]
fn probe_browser_shield_registry() -> BrowserShieldProbe {
    let browsers = [
        ("Chrome", CHROME_NMH_REG_SUBKEY),
        ("Edge", EDGE_NMH_REG_SUBKEY),
        ("Brave", BRAVE_NMH_REG_SUBKEY),
    ]
    .into_iter()
    .map(|(browser, subkey)| BrowserRegistryProbe {
        browser: browser.to_string(),
        hkcu: probe_reg_string(false, subkey),
        hklm: probe_reg_string(true, subkey),
    })
    .collect();

    let uri_cmd_key = format!(r"{LEDR_URI_REG_SUBKEY}\shell\open\command");
    let uri_hkcu = matches!(
        win_uri_reg::reg_query_default_sz_in_hive(false, &uri_cmd_key),
        Ok(RegDefaultSzProbe::Present(_))
    );
    let uri_hklm = matches!(
        win_uri_reg::reg_query_default_sz_in_hive(true, &uri_cmd_key),
        Ok(RegDefaultSzProbe::Present(_))
    );

    BrowserShieldProbe {
        browsers,
        uri_hkcu,
        uri_hklm,
    }
}

#[cfg(not(windows))]
fn probe_browser_shield_registry() -> BrowserShieldProbe {
    BrowserShieldProbe::default()
}

pub(crate) fn collect_local_defense_status() -> LocalDefenseStatus {
    let user_profile = std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let probe = probe_browser_shield_registry();
    collect_local_defense_status_with_probe(
        user_profile.as_deref(),
        Path::new(AUTHORIZED_BRIDGE_EXE_PATH),
        &probe,
    )
}
