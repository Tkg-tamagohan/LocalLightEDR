//! Idempotent HKCU/HKLM Native Messaging Host, `ledr://` URI scheme, and AUMID setup/unregister/status.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ledr_proto::{AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH, PROGRAM_DATA_DIR};
use serde::Serialize;

use crate::cli::{BrowserKind, Scope, SetupArgs, StatusArgs, StatusScope, UnregisterArgs};
use crate::manifest::{
    build_manifest, manifest_filename_for, normalize_display_path, validate_manifest_file,
    write_manifest_atomic, ManifestValidation,
};
use crate::pipe_client::PipeClient;

pub const CHROME_NMH_SUBKEY: &str = r"Software\Google\Chrome\NativeMessagingHosts\com.localedr.bridge";
pub const EDGE_NMH_SUBKEY: &str = r"Software\Microsoft\Edge\NativeMessagingHosts\com.localedr.bridge";
pub const BRAVE_NMH_SUBKEY: &str =
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.localedr.bridge";

pub const CHROME_POLICY_SUBKEY: &str = r"Software\Policies\Google\Chrome";
pub const EDGE_POLICY_SUBKEY: &str = r"Software\Policies\Microsoft\Edge";
pub const NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE: &str = "NativeHostsExecutablesLaunchDirectly";

pub const LEDR_URI_SUBKEY: &str = r"Software\Classes\ledr";
pub const LEDR_URI_DESCRIPTION: &str = "URL:LocalEDR Alert Protocol";
pub const LEDR_AUMID_SUBKEY: &str = r"Software\Classes\AppUserModelId\LocalEDR.AlertUI";
pub const LEDR_AUMID_DISPLAY_NAME: &str = "LocalEDR";

/// Target registry hive and optional subkey prefix (used to isolate unit tests under `HKCU\Software\LocalEDR-Test\...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryTarget {
    pub scope: Scope,
    pub key_prefix: Option<String>,
}

impl RegistryTarget {
    pub fn for_scope(scope: Scope) -> Self {
        Self {
            scope,
            key_prefix: None,
        }
    }

    pub fn hive_name(&self) -> &'static str {
        match self.scope {
            Scope::User => "HKCU",
            Scope::Machine => "HKLM",
        }
    }

    pub fn qualify_subkey(&self, subkey: &str) -> String {
        let trimmed = subkey.trim_matches('\\');
        match self
            .key_prefix
            .as_deref()
            .map(|p| p.trim_matches('\\'))
            .filter(|p| !p.is_empty())
        {
            Some(prefix) => format!(r"{prefix}\{trimmed}"),
            None => trimmed.to_string(),
        }
    }

    pub fn browser_subkey(&self, browser: BrowserKind) -> String {
        let base = match browser {
            BrowserKind::Chrome => CHROME_NMH_SUBKEY,
            BrowserKind::Edge => EDGE_NMH_SUBKEY,
            BrowserKind::Brave => BRAVE_NMH_SUBKEY,
        };
        self.qualify_subkey(base)
    }

    pub fn browser_policy_subkey(&self, browser: BrowserKind) -> Option<String> {
        let base = match browser {
            BrowserKind::Chrome => CHROME_POLICY_SUBKEY,
            BrowserKind::Edge => EDGE_POLICY_SUBKEY,
            BrowserKind::Brave => return None,
        };
        Some(self.qualify_subkey(base))
    }

    pub fn uri_subkey(&self) -> String {
        self.qualify_subkey(LEDR_URI_SUBKEY)
    }

    pub fn aumid_subkey(&self) -> String {
        self.qualify_subkey(LEDR_AUMID_SUBKEY)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserRegistrationOutcome {
    pub browser: BrowserKind,
    pub registry_key: String,
    pub manifest_path: String,
    pub manifest_written: bool,
    pub updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SetupOutcome {
    pub scope: Scope,
    pub manifest_dir: String,
    pub manifest_written: bool,
    pub bridge_exe: String,
    pub ui_exe: String,
    pub extension_id: String,
    pub browsers: Vec<BrowserRegistrationOutcome>,
    pub uri_registered: bool,
    pub uri_updated: bool,
    pub aumid_updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserUnregisterOutcome {
    pub browser: BrowserKind,
    pub registry_key: String,
    pub manifest_path: Option<String>,
    pub removed: bool,
    pub manifest_removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnregisterOutcome {
    pub scope: Scope,
    pub manifest_dir: String,
    pub manifest_paths_removed: Vec<String>,
    pub manifest_removed: bool,
    pub browsers: Vec<BrowserUnregisterOutcome>,
    pub uri_removed: bool,
    pub aumid_removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegWow64View {
    Wow6432,
    Wow6464,
}

impl RegWow64View {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wow6432 => "wow64-32",
            Self::Wow6464 => "wow64-64",
        }
    }

    #[cfg(windows)]
    fn access_flag(self) -> u32 {
        match self {
            Self::Wow6432 => win_reg_ops::KEY_WOW64_32KEY,
            Self::Wow6464 => win_reg_ops::KEY_WOW64_64KEY,
        }
    }
}

/// Result of probing a Native Messaging Host registry key's default (`""`) value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeHostRegProbe {
    Present(String),
    EmptyString,
    Absent,
    InvalidType,
    AccessError(String),
}

/// Selects the effective `HKLM` Native Messaging Host registry probe across WOW64 32-bit
/// (`KEY_WOW64_32KEY`) and 64-bit (`KEY_WOW64_64KEY`) views following Chromium's precedence,
/// returning both the effective probe and the view that produced it (`None` when both are `Absent`).
///
/// Chromium stops at the 32-bit view whenever `RegKey::ReadValue(nullptr, &path)` returns
/// `ERROR_SUCCESS`, including when the `REG_SZ` value is empty (`EmptyString`). Only failed
/// reads (`Absent`, `InvalidType`, or `AccessError`) fall back to the 64-bit view.
pub fn select_effective_hklm_probe(
    view32: NativeHostRegProbe,
    view64: NativeHostRegProbe,
) -> (NativeHostRegProbe, Option<RegWow64View>) {
    match (&view32, &view64) {
        (NativeHostRegProbe::Present(_) | NativeHostRegProbe::EmptyString, _) => {
            (view32, Some(RegWow64View::Wow6432))
        }
        (_, NativeHostRegProbe::Present(_) | NativeHostRegProbe::EmptyString) => {
            (view64, Some(RegWow64View::Wow6464))
        }
        (NativeHostRegProbe::Absent, NativeHostRegProbe::Absent) => {
            (NativeHostRegProbe::Absent, None)
        }
        (NativeHostRegProbe::Absent, _) => (view64, Some(RegWow64View::Wow6464)),
        (_, NativeHostRegProbe::Absent) => (view32, Some(RegWow64View::Wow6432)),
        _ => (view32, Some(RegWow64View::Wow6432)),
    }
}

/// Registry operations abstracted for explicit WOW64 view handling and non-privileged unit tests.
pub trait RegistryViewOps {
    fn ensure_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
        expected: &str,
    ) -> Result<bool>;

    fn probe_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> NativeHostRegProbe;

    fn delete_subkey_tree_idempotent(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> Result<bool>;

    fn ensure_uri_registered(&self, target: &RegistryTarget, ui_exe: &Path) -> Result<bool>;

    fn ensure_aumid_registered(&self, target: &RegistryTarget) -> Result<bool>;

    fn read_uri_status(&self, target: &RegistryTarget) -> (bool, Option<String>);

    fn read_aumid_status(&self, target: &RegistryTarget) -> (bool, Option<String>);

    fn read_native_hosts_launch_directly_policy(
        &self,
        target: &RegistryTarget,
        browser: BrowserKind,
    ) -> Option<bool>;

    fn any_existing_shares_identity(&self, candidate: &Path, existing_paths: &[String]) -> bool {
        win_reg_ops::any_existing_shares_identity(candidate, existing_paths)
    }

    fn verify_local_manifest_for_removal(&self, path: &Path) -> bool {
        win_reg_ops::verify_local_manifest_for_removal(path)
    }
}

/// Production Windows Registry implementation of [`RegistryViewOps`].
pub struct WinRegistryViewOps;

impl RegistryViewOps for WinRegistryViewOps {
    fn ensure_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
        expected: &str,
    ) -> Result<bool> {
        win_reg_ops::ensure_default_sz(target, subkey, view, expected)
    }

    fn probe_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> NativeHostRegProbe {
        win_reg_ops::probe_default_sz(target, subkey, view)
    }

    fn delete_subkey_tree_idempotent(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> Result<bool> {
        win_reg_ops::delete_subkey_tree_idempotent(target, subkey, view)
    }

    fn ensure_uri_registered(&self, target: &RegistryTarget, ui_exe: &Path) -> Result<bool> {
        win_reg_ops::ensure_uri_registered(target, ui_exe)
    }

    fn ensure_aumid_registered(&self, target: &RegistryTarget) -> Result<bool> {
        win_reg_ops::ensure_aumid_registered(target)
    }

    fn read_uri_status(&self, target: &RegistryTarget) -> (bool, Option<String>) {
        win_reg_ops::read_uri_status(target)
    }

    fn read_aumid_status(&self, target: &RegistryTarget) -> (bool, Option<String>) {
        win_reg_ops::read_aumid_status(target)
    }

    fn read_native_hosts_launch_directly_policy(
        &self,
        target: &RegistryTarget,
        browser: BrowserKind,
    ) -> Option<bool> {
        win_reg_ops::read_native_hosts_launch_directly_policy(target, browser)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserStatusEntry {
    pub browser: BrowserKind,
    pub registry_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_view: Option<String>,
    pub registered: bool,
    pub manifest_path: Option<String>,
    pub manifest: Option<ManifestValidation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_hosts_launch_directly: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScopeStatusReport {
    pub scope: Scope,
    pub default_manifest_dir: String,
    pub browsers: Vec<BrowserStatusEntry>,
    pub uri_registered: bool,
    pub uri_command: Option<String>,
    pub aumid_registered: bool,
    pub aumid_display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DaemonPingStatus {
    pub pipe_name: String,
    pub online: bool,
    pub daemon_version: Option<String>,
    pub protocol_version: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusReport {
    pub expected_extension_id: String,
    pub scopes: Vec<ScopeStatusReport>,
    pub daemon_ping: Option<DaemonPingStatus>,
}

/// Formats `ledr://` protocol shell command matching `apps/ledr-ui/src/uri_reg.rs`.
pub fn format_ledr_uri_command(ui_exe: &Path) -> String {
    let normalized = normalize_display_path(ui_exe);
    format!("\"{normalized}\" \"%1\"")
}

fn absolutize_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("path must not be empty");
    }
    let abs = std::path::absolute(path)
        .with_context(|| format!("failed to resolve absolute path for '{}'", path.display()))?;
    Ok(PathBuf::from(normalize_display_path(&abs)))
}

/// Resolves the Native Messaging manifest directory for `scope`.
pub fn resolve_manifest_dir(scope: Scope, override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return absolutize_path(dir);
    }
    match scope {
        Scope::User => {
            let local_app_data = std::env::var_os("LOCALAPPDATA")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "LOCALAPPDATA environment variable is unset; pass --manifest-dir explicitly"
                    )
                })?;
            absolutize_path(&local_app_data.join("LocalEDR").join("native-messaging"))
        }
        Scope::Machine => Ok(PathBuf::from(PROGRAM_DATA_DIR).join("native-messaging")),
    }
}

/// Resolves the `ledr-bridge-nm.exe` path for manifest generation, preferring `installed_authorized_exe`
/// when present on disk even under [`Scope::User`].
pub fn resolve_bridge_exe_with(
    scope: Scope,
    override_exe: Option<&Path>,
    installed_authorized_exe: &Path,
) -> Result<PathBuf> {
    if let Some(exe) = override_exe {
        return absolutize_path(exe);
    }
    match scope {
        Scope::Machine => Ok(PathBuf::from(AUTHORIZED_BRIDGE_EXE_PATH)),
        Scope::User => {
            if installed_authorized_exe.is_file() {
                return absolutize_path(installed_authorized_exe);
            }
            if let Some(exe) = std::env::current_exe().ok().filter(|p| p.is_absolute()) {
                return Ok(exe);
            }
            Ok(PathBuf::from(AUTHORIZED_BRIDGE_EXE_PATH))
        }
    }
}

/// Resolves the `ledr-bridge-nm.exe` path for manifest generation.
pub fn resolve_bridge_exe(scope: Scope, override_exe: Option<&Path>) -> Result<PathBuf> {
    resolve_bridge_exe_with(scope, override_exe, Path::new(AUTHORIZED_BRIDGE_EXE_PATH))
}

/// Resolves the `ledr-ui.exe` path for `ledr://` URI scheme registration, preferring
/// `installed_authorized_exe` when present on disk even under [`Scope::User`].
pub fn resolve_ui_exe_with(
    scope: Scope,
    bridge_exe: &Path,
    override_exe: Option<&Path>,
    installed_authorized_exe: &Path,
) -> Result<PathBuf> {
    if let Some(exe) = override_exe {
        return absolutize_path(exe);
    }
    match scope {
        Scope::Machine => Ok(PathBuf::from(AUTHORIZED_UI_EXE_PATH)),
        Scope::User => {
            if installed_authorized_exe.is_file() {
                return absolutize_path(installed_authorized_exe);
            }
            if let Some(sibling) = bridge_exe.parent().map(|dir| dir.join("ledr-ui.exe")) {
                if sibling.is_file() {
                    return absolutize_path(&sibling);
                }
            }
            Ok(PathBuf::from(AUTHORIZED_UI_EXE_PATH))
        }
    }
}

/// Resolves the `ledr-ui.exe` path for `ledr://` URI scheme registration.
pub fn resolve_ui_exe(
    scope: Scope,
    bridge_exe: &Path,
    override_exe: Option<&Path>,
) -> Result<PathBuf> {
    resolve_ui_exe_with(
        scope,
        bridge_exe,
        override_exe,
        Path::new(AUTHORIZED_UI_EXE_PATH),
    )
}

pub(crate) const DRIVE_REMOVABLE: u32 = 2;
pub(crate) const DRIVE_FIXED: u32 = 3;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const DRIVE_REMOTE: u32 = 4;
pub(crate) const DRIVE_RAMDISK: u32 = 6;

pub(crate) const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
pub(crate) const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
pub(crate) const IO_REPARSE_TAG_DFS: u32 = 0x8000_000A;
pub(crate) const IO_REPARSE_TAG_DFSR: u32 = 0x8000_0012;
pub(crate) const IO_REPARSE_TAG_NFS: u32 = 0x8000_0014;
pub(crate) const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

pub(crate) fn is_local_drive_type(drive_type: u32) -> bool {
    matches!(drive_type, DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_RAMDISK)
}

fn parse_local_drive_path(path: &Path) -> Option<(char, Vec<String>, bool)> {
    let raw = path.to_str()?;
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return None;
        }
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let mut segments = Vec::new();
        for seg in rest[3..].split('\\') {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." || seg.contains('/') {
                return None;
            }
            segments.push(seg.to_string());
        }
        return Some((drive, segments, true));
    }

    let bytes = raw.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || (bytes[2] != b'\\' && bytes[2] != b'/')
    {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    let mut segments = Vec::new();
    for seg in raw[3..].split(['\\', '/']) {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other.to_string()),
        }
    }
    Some((drive, segments, false))
}

fn build_drive_path(drive: char, segments: &[String], force_verbatim: bool) -> PathBuf {
    let mut s = String::new();
    if force_verbatim {
        s.push_str(r"\\?\");
    }
    s.push(drive.to_ascii_uppercase());
    s.push_str(":\\");
    for (idx, seg) in segments.iter().enumerate() {
        if idx > 0 {
            s.push('\\');
        }
        s.push_str(seg);
    }
    if !force_verbatim && s.len() >= 248 {
        PathBuf::from(format!(r"\\?\{s}"))
    } else {
        PathBuf::from(s)
    }
}

/// Extracts the uppercase local drive letter (`A`..=`Z`) from an absolute drive path (`X:\...` or
/// `\\?\X:\...`), rejecting UNC (`\\...`, `//...`, `\\?\UNC\...`), device (`\\.\...`), NT
/// (`\??\...`), volume GUID, and relative paths (`SEC_0001`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn extract_local_drive_letter(path: &Path) -> Option<char> {
    parse_local_drive_path(path).map(|(drive, _, _)| drive)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedReparseTarget {
    pub tag: u32,
    pub substitute_name: String,
    pub is_relative: bool,
}

/// Classification of a raw `REPARSE_DATA_BUFFER` distinguishing supported symlink/junction targets,
/// known remote/network reparse tags (`DFS`, `DFSR`, `NFS`), and unrecognized/local filter tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsedReparseBuffer {
    Target(ParsedReparseTarget),
    RemoteTag(u32),
    Unsupported,
}

/// Parses a raw `REPARSE_DATA_BUFFER`, separating symlink/mount-point targets from known remote
/// network reparse tags (`DFS`/`DFSR`/`NFS`) and unrecognized local/filter tags.
pub(crate) fn parse_reparse_data_buffer(buf: &[u8]) -> ParsedReparseBuffer {
    if buf.len() < 8 {
        return ParsedReparseBuffer::Unsupported;
    }
    let tag = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if matches!(tag, IO_REPARSE_TAG_DFS | IO_REPARSE_TAG_DFSR | IO_REPARSE_TAG_NFS) {
        return ParsedReparseBuffer::RemoteTag(tag);
    }
    let data_len = usize::from(u16::from_le_bytes([buf[4], buf[5]]));
    let Some(total_end) = 8usize.checked_add(data_len) else {
        return ParsedReparseBuffer::Unsupported;
    };
    if total_end > buf.len() {
        return ParsedReparseBuffer::Unsupported;
    }
    let (sub_offset, sub_len, is_relative, path_buf_start) = match tag {
        IO_REPARSE_TAG_SYMLINK => {
            if total_end < 20 {
                return ParsedReparseBuffer::Unsupported;
            }
            let sub_off = usize::from(u16::from_le_bytes([buf[8], buf[9]]));
            let sub_len = usize::from(u16::from_le_bytes([buf[10], buf[11]]));
            let flags = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
            (sub_off, sub_len, (flags & SYMLINK_FLAG_RELATIVE) != 0, 20usize)
        }
        IO_REPARSE_TAG_MOUNT_POINT => {
            if total_end < 16 {
                return ParsedReparseBuffer::Unsupported;
            }
            let sub_off = usize::from(u16::from_le_bytes([buf[8], buf[9]]));
            let sub_len = usize::from(u16::from_le_bytes([buf[10], buf[11]]));
            (sub_off, sub_len, false, 16usize)
        }
        _ => return ParsedReparseBuffer::Unsupported,
    };
    if sub_offset % 2 != 0 || sub_len % 2 != 0 || sub_len == 0 {
        return ParsedReparseBuffer::Unsupported;
    }
    let path_buf = &buf[path_buf_start..total_end];
    let Some(sub_end) = sub_offset.checked_add(sub_len) else {
        return ParsedReparseBuffer::Unsupported;
    };
    if sub_end > path_buf.len() {
        return ParsedReparseBuffer::Unsupported;
    }
    let sub_bytes = &path_buf[sub_offset..sub_end];
    let wide: Vec<u16> = (0..sub_bytes.len())
        .step_by(2)
        .map(|i| u16::from_le_bytes([sub_bytes[i], sub_bytes[i + 1]]))
        .collect();
    let Ok(substitute_name) = String::from_utf16(&wide) else {
        return ParsedReparseBuffer::Unsupported;
    };
    ParsedReparseBuffer::Target(ParsedReparseTarget {
        tag,
        substitute_name,
        is_relative,
    })
}

fn is_ascii_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (idx, &ch) in b.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !ch.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// Parses a Windows local Volume GUID path (`\\?\Volume{uuid}\...` or `\??\Volume{uuid}\...`),
/// returning the canonical `\\?\Volume{uuid}\` root and validated relative segments.
pub(crate) fn parse_volume_guid_path(raw: &str) -> Option<(String, Vec<String>)> {
    if raw.is_empty() || raw.contains('\0') {
        return None;
    }
    let after_prefix = raw
        .strip_prefix(r"\\?\")
        .or_else(|| raw.strip_prefix(r"\??\"))?;
    // Match `Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` case-insensitively on `Volume`.
    let vol_head = after_prefix.get(..7)?;
    if !vol_head.eq_ignore_ascii_case("Volume{") {
        return None;
    }
    let guid = after_prefix.get(7..43)?;
    if !is_ascii_uuid(guid) || after_prefix.as_bytes().get(43) != Some(&b'}') {
        return None;
    }
    let tail = &after_prefix[44..];
    let mut segments = Vec::new();
    if !tail.is_empty() {
        let rest = tail.strip_prefix('\\')?;
        for seg in rest.split('\\') {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." || seg.contains('/') {
                return None;
            }
            segments.push(seg.to_string());
        }
    }
    let volume_root = format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase());
    Some((volume_root, segments))
}

/// Resolution outcome for a reparse point's `SubstituteName` (`SEC_0001` / `BUG_0001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReparseTargetResolution {
    LocalDrive(PathBuf),
    VolumeGuid {
        volume_root: String,
        segments: Vec<String>,
    },
    Remote,
}

/// Classification of a Win32 `QueryDosDeviceW("X:")` target before calling `GetDriveTypeW` or
/// traversing the filesystem (`SEC_0001`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DosDeviceTarget {
    VolumeDevice,
    Subst(PathBuf),
    NonLocal,
}

/// Classifies a Win32 `QueryDosDeviceW("X:")` target so `SUBST` / DOS device aliases (`\??\...`,
/// `\GLOBAL??\...`, `\DosDevices\...`) are expanded and recursively validated from their real
/// root, while network redirectors (`LanmanRedirector`, `Mup`, `WebDavRedirector`, etc.) are
/// rejected before any filesystem or SMB call (`SEC_0001`).
pub(crate) fn classify_dos_device_target(target: &str) -> DosDeviceTarget {
    if target.is_empty() || target.contains('\0') {
        return DosDeviceTarget::NonLocal;
    }
    let normalized_lower = target.replace('/', "\\").to_ascii_lowercase();
    let dos_prefix_len = if normalized_lower.starts_with(r"\??\") {
        Some(4usize)
    } else if normalized_lower.starts_with(r"\global??\") {
        Some(10usize)
    } else if normalized_lower.starts_with(r"\dosdevices\") {
        Some(12usize)
    } else {
        None
    };
    if let Some(prefix_len) = dos_prefix_len {
        let Some(rest) = target.get(prefix_len..) else {
            return DosDeviceTarget::NonLocal;
        };
        let synthetic = format!(r"\??\{rest}");
        return match resolve_local_reparse_target(&synthetic, false, Path::new(r"C:\")) {
            ReparseTargetResolution::LocalDrive(local_base) => DosDeviceTarget::Subst(local_base),
            ReparseTargetResolution::VolumeGuid { .. } => DosDeviceTarget::VolumeDevice,
            ReparseTargetResolution::Remote => DosDeviceTarget::NonLocal,
        };
    }

    if normalized_lower.starts_with(r"\\")
        || normalized_lower == r"\device\mup"
        || normalized_lower.starts_with(r"\device\mup\")
        || normalized_lower == r"\device\lanmanredirector"
        || normalized_lower.starts_with(r"\device\lanmanredirector\")
        || normalized_lower == r"\device\webdavredirector"
        || normalized_lower.starts_with(r"\device\webdavredirector\")
        || normalized_lower == r"\device\rdpdr"
        || normalized_lower.starts_with(r"\device\rdpdr\")
        || normalized_lower == r"\device\hgfs"
        || normalized_lower.starts_with(r"\device\hgfs\")
        || normalized_lower == r"\device\vboxminirdr"
        || normalized_lower.starts_with(r"\device\vboxminirdr\")
    {
        return DosDeviceTarget::NonLocal;
    }

    if normalized_lower.starts_with(r"\device\") {
        DosDeviceTarget::VolumeDevice
    } else {
        DosDeviceTarget::NonLocal
    }
}

/// Verifies that a drive letter's current per-session `QueryDosDeviceW("X:")` target resolves to
/// the exact same local volume device as `QueryDosDeviceW("Volume{guid}")` (`BUG_0001`), preventing
/// session-local drive-letter overrides (e.g. `SUBST` or reassigned drives) from comparing against
/// the wrong volume.
pub(crate) fn dos_device_targets_match_volume(
    volume_device_target: &str,
    drive_device_target: &str,
) -> bool {
    classify_dos_device_target(volume_device_target) == DosDeviceTarget::VolumeDevice
        && classify_dos_device_target(drive_device_target) == DosDeviceTarget::VolumeDevice
        && volume_device_target.eq_ignore_ascii_case(drive_device_target)
}

/// Classifies a reparse point's `SubstituteName` into a local drive target, a local Volume GUID
/// mount target (which must never be falsely skipped as remote), or a remote/non-local target
/// (`\??\UNC\`, `\\`, `\Device\Mup\`, `\Device\LanmanRedirector\`, `\Device\`, `\??\GlobalRoot\`).
pub(crate) fn resolve_local_reparse_target(
    substitute_name: &str,
    is_relative: bool,
    link_path: &Path,
) -> ReparseTargetResolution {
    if substitute_name.is_empty() || substitute_name.contains('\0') {
        return ReparseTargetResolution::Remote;
    }
    if !is_relative {
        if let Some((volume_root, segments)) = parse_volume_guid_path(substitute_name) {
            return ReparseTargetResolution::VolumeGuid {
                volume_root,
                segments,
            };
        }
    }
    let normalized_lower = substitute_name.replace('/', "\\").to_ascii_lowercase();
    if normalized_lower.starts_with(r"\??\unc\")
        || normalized_lower == r"\??\unc"
        || normalized_lower.starts_with(r"\\?\unc\")
        || normalized_lower == r"\\?\unc"
        || normalized_lower.starts_with(r"\??\globalroot\")
        || normalized_lower.starts_with(r"\\?\globalroot\")
        || normalized_lower.starts_with(r"\\.\")
        || (normalized_lower.starts_with(r"\\") && !substitute_name.starts_with(r"\\?\"))
        || normalized_lower.starts_with(r"\device\mup\")
        || normalized_lower == r"\device\mup"
        || normalized_lower.starts_with(r"device\mup\")
        || normalized_lower.starts_with(r"\device\lanmanredirector\")
        || normalized_lower == r"\device\lanmanredirector"
        || normalized_lower.starts_with(r"device\lanmanredirector\")
        || normalized_lower.starts_with(r"\device\")
        || normalized_lower.starts_with(r"device\")
    {
        return ReparseTargetResolution::Remote;
    }

    if is_relative {
        if substitute_name.starts_with('\\')
            || substitute_name.starts_with('/')
            || substitute_name.as_bytes().get(1) == Some(&b':')
        {
            return ReparseTargetResolution::Remote;
        }
        // Resolve relative to `link_path`'s parent segments directly so verbatim `\\?\` or long
        // (>= 248 byte) `link_path` values still support `.` / `..` / `/` relative symlink targets.
        let Some((drive, mut segments, _)) = parse_local_drive_path(link_path) else {
            return ReparseTargetResolution::Remote;
        };
        if segments.pop().is_none() {
            return ReparseTargetResolution::Remote;
        }
        for seg in substitute_name.split(['\\', '/']) {
            match seg {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                other => segments.push(other.to_string()),
            }
        }
        return ReparseTargetResolution::LocalDrive(build_drive_path(drive, &segments, false));
    }

    if let Some(rest) = substitute_name.strip_prefix(r"\\?\") {
        let candidate = if rest.len() == 2
            && rest.as_bytes()[0].is_ascii_alphabetic()
            && rest.as_bytes()[1] == b':'
        {
            format!(r"\\?\{}:\", (rest.as_bytes()[0] as char).to_ascii_uppercase())
        } else {
            substitute_name.to_string()
        };
        return match parse_local_drive_path(Path::new(&candidate)) {
            Some((drive, segments, _)) => {
                ReparseTargetResolution::LocalDrive(build_drive_path(drive, &segments, false))
            }
            None => ReparseTargetResolution::Remote,
        };
    }

    let stripped = substitute_name.strip_prefix(r"\??\").unwrap_or(substitute_name);
    let candidate = if stripped.len() == 2
        && stripped.as_bytes()[0].is_ascii_alphabetic()
        && stripped.as_bytes()[1] == b':'
    {
        format!("{}:\\", (stripped.as_bytes()[0] as char).to_ascii_uppercase())
    } else {
        stripped.to_string()
    };
    match parse_local_drive_path(Path::new(&candidate)) {
        Some((drive, segments, _)) => {
            ReparseTargetResolution::LocalDrive(build_drive_path(drive, &segments, false))
        }
        None => ReparseTargetResolution::Remote,
    }
}

#[cfg(windows)]
pub(crate) mod win_reg_ops {
    use super::{
        build_drive_path, classify_dos_device_target, dos_device_targets_match_volume,
        format_ledr_uri_command, is_local_drive_type, parse_local_drive_path,
        parse_reparse_data_buffer, parse_volume_guid_path, resolve_local_reparse_target,
        BrowserKind, DosDeviceTarget, NativeHostRegProbe, ParsedReparseBuffer, RegWow64View,
        RegistryTarget, ReparseTargetResolution, Scope, LEDR_AUMID_DISPLAY_NAME,
        LEDR_URI_DESCRIPTION, NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE,
    };
    use anyhow::Result;
    use std::ffi::c_void;
    use std::io::ErrorKind;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_SZ};
    use winreg::RegKey;

    pub(crate) const KEY_WOW64_64KEY: u32 = 0x0100;
    pub(crate) const KEY_WOW64_32KEY: u32 = 0x0200;
    const HKEY_CURRENT_USER_RAW: isize = 0x8000_0001_u32 as i32 as isize;
    const HKEY_LOCAL_MACHINE_RAW: isize = 0x8000_0002_u32 as i32 as isize;
    const DELETE: u32 = 0x0001_0000;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;

    #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut isize,
        ) -> i32;
        fn RegDeleteTreeW(h_key: isize, lp_sub_key: *const u16) -> i32;
        fn RegDeleteKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            sam_desired: u32,
            reserved: u32,
        ) -> i32;
        fn RegCloseKey(h_key: isize) -> i32;
    }

    struct OwnedRegKey(isize);

    impl Drop for OwnedRegKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: `self.0` is an open HKEY acquired from `RegOpenKeyExW`.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
    const ERROR_MORE_DATA: i32 = 234;
    const FSCTL_GET_REPARSE_POINT: u32 = 0x0009_00A8;
    const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
    const MAX_REPARSE_HOPS: usize = 16;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: [u32; 2],
        ft_last_access_time: [u32; 2],
        ft_last_write_time: [u32; 2],
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn QueryDosDeviceW(
            device_name: *const u16,
            target_path: *mut u16,
            max_chars: u32,
        ) -> u32;
        fn GetVolumePathNamesForVolumeNameW(
            lpsz_volume_name: *const u16,
            lpsz_volume_path_names: *mut u16,
            cch_buffer_length: u32,
            lpcch_return_length: *mut u32,
        ) -> i32;
        fn GetFullPathNameW(
            lp_file_name: *const u16,
            n_buffer_length: u32,
            lp_buffer: *mut u16,
            lp_file_part: *mut *mut u16,
        ) -> u32;
        fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *const c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> *mut c_void;
        fn DeviceIoControl(
            h_device: *mut c_void,
            dw_io_control_code: u32,
            lp_in_buffer: *const c_void,
            n_in_buffer_size: u32,
            lp_out_buffer: *mut c_void,
            n_out_buffer_size: u32,
            lp_bytes_returned: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        fn GetFileInformationByHandle(
            h_file: *mut c_void,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn CloseHandle(object: *mut c_void) -> i32;
    }

    struct OwnedFileHandle(*mut c_void);

    impl Drop for OwnedFileHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is a valid file handle returned by `CreateFileW`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        volume_serial_number: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FileIdentityLookup {
        Found(FileIdentity),
        NotFound,
        NonLocal,
        Indeterminate,
    }

    enum PathLocality {
        Local(PathBuf),
        NonLocal,
        NotFound,
        Indeterminate,
    }

    fn is_local_drive(drive: char) -> bool {
        let root_wide = [drive.to_ascii_uppercase() as u16, b':' as u16, b'\\' as u16, 0];
        // SAFETY: `root_wide` is a NUL-terminated UTF-16 drive root string (`X:\`).
        let drive_type = unsafe { GetDriveTypeW(root_wide.as_ptr()) };
        is_local_drive_type(drive_type)
    }

    fn resolve_volume_guid_to_drive_letter(volume_root: &str) -> Option<char> {
        let volume_dev_name = volume_root
            .strip_prefix(r"\\?\")?
            .strip_suffix('\\')?;
        let expected_vol_target = query_dos_device_by_name(volume_dev_name)?;
        if classify_dos_device_target(&expected_vol_target) != DosDeviceTarget::VolumeDevice {
            return None;
        }

        let mut wide_vol: Vec<u16> = volume_root.encode_utf16().collect();
        if wide_vol.is_empty() || wide_vol.contains(&0) {
            return None;
        }
        wide_vol.push(0);

        let mut cap: usize = 512;
        for _ in 0..3 {
            let mut buf = vec![0u16; cap];
            let mut ret_len: u32 = 0;
            // SAFETY: `wide_vol` is NUL-terminated UTF-16 (`\\?\Volume{uuid}\`) and `buf` holds `cap` writable units.
            let ok = unsafe {
                GetVolumePathNamesForVolumeNameW(
                    wide_vol.as_ptr(),
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    &mut ret_len,
                )
            };
            if ok != 0 {
                let used = usize::try_from(ret_len).unwrap_or(buf.len()).min(buf.len());
                for entry in buf[..used].split(|&c| c == 0) {
                    if entry.is_empty() {
                        break;
                    }
                    if entry.len() == 3
                        && entry[0] <= 0x7F
                        && (entry[0] as u8).is_ascii_alphabetic()
                        && entry[1] == u16::from(b':')
                        && entry[2] == u16::from(b'\\')
                    {
                        let drive = (entry[0] as u8 as char).to_ascii_uppercase();
                        if let Some(drive_target) = query_dos_device_target(drive) {
                            if dos_device_targets_match_volume(&expected_vol_target, &drive_target)
                            {
                                return Some(drive);
                            }
                        }
                    }
                }
                return None;
            }
            let err = std::io::Error::last_os_error();
            let needed = usize::try_from(ret_len).unwrap_or(0);
            if err.raw_os_error() == Some(ERROR_MORE_DATA) && needed > cap && needed <= 32_768 {
                cap = needed;
                continue;
            }
            return None;
        }
        None
    }

    fn normalize_win32_local_path_once(path: &Path) -> Option<PathBuf> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return None;
        }
        wide.push(0);

        let mut cap: usize = 512;
        for _ in 0..3 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `wide` is NUL-terminated UTF-16 and `buf` holds `cap` writable `u16` units.
            // `GetFullPathNameW` performs pure user-mode lexical normalization (zero filesystem/network I/O).
            let ret = unsafe {
                GetFullPathNameW(
                    wide.as_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    buf.as_mut_ptr(),
                    ptr::null_mut(),
                )
            };
            if ret == 0 {
                return None;
            }
            let needed = usize::try_from(ret).unwrap_or(0);
            if needed < buf.len() {
                let normalized = String::from_utf16(&buf[..needed]).ok()?;
                return Some(PathBuf::from(normalized));
            }
            if needed < 32_768 {
                cap = needed.saturating_add(1);
                continue;
            }
            return None;
        }
        None
    }

    fn resolve_volume_guid_path_locality(
        volume_root: &str,
        segments: &[String],
        remaining_depth: usize,
    ) -> PathLocality {
        if remaining_depth == 0 {
            return PathLocality::Indeterminate;
        }
        let Some(drive) = resolve_volume_guid_to_drive_letter(volume_root) else {
            // Local volume GUID without a verified matching drive letter in the current logon
            // session (e.g. folder-only mount or session-shadowed drive): never open via
            // CreateFileW, conservatively keep manifest.
            return PathLocality::Indeterminate;
        };
        // Preserve verbatim `\\?\X:\...` semantics because `\\?\Volume{guid}\...` and reparse
        // targets bypass Win32 trailing-dot/space stripping (e.g. `Data.\manifest.json`).
        let rewritten = build_drive_path(drive, segments, true);
        verify_local_path_recursive(&rewritten, true, remaining_depth - 1)
    }

    fn inspect_reparse_point_target(
        current: &Path,
    ) -> Result<ReparseTargetResolution, PathLocality> {
        let mut wide: Vec<u16> = current.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(PathLocality::Indeterminate);
        }
        wide.push(0);

        // SAFETY: `wide` is NUL-terminated UTF-16; `FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS`
        // opens the reparse point itself (directory or file) without traversing to its target.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw as isize == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(if err.kind() == ErrorKind::NotFound {
                PathLocality::NotFound
            } else {
                PathLocality::Indeterminate
            });
        }
        let handle = OwnedFileHandle(raw);

        let mut buf = vec![0u8; MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
        let mut bytes_returned: u32 = 0;
        // SAFETY: `handle.0` is an open reparse-point handle and `buf` holds `MAXIMUM_REPARSE_DATA_BUFFER_SIZE` bytes.
        let ok = unsafe {
            DeviceIoControl(
                handle.0,
                FSCTL_GET_REPARSE_POINT,
                ptr::null(),
                0,
                buf.as_mut_ptr().cast::<c_void>(),
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(PathLocality::Indeterminate);
        }
        let used = usize::try_from(bytes_returned)
            .unwrap_or(0)
            .min(buf.len());
        match parse_reparse_data_buffer(&buf[..used]) {
            ParsedReparseBuffer::Target(parsed) => Ok(resolve_local_reparse_target(
                &parsed.substitute_name,
                parsed.is_relative,
                current,
            )),
            ParsedReparseBuffer::RemoteTag(_) => Err(PathLocality::NonLocal),
            ParsedReparseBuffer::Unsupported => Err(PathLocality::Indeterminate),
        }
    }

    fn query_dos_device_by_name(device_name: &str) -> Option<String> {
        let mut wide_name: Vec<u16> = device_name.encode_utf16().collect();
        if wide_name.is_empty() || wide_name.contains(&0) {
            return None;
        }
        wide_name.push(0);
        let mut cap: usize = 512;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `wide_name` is NUL-terminated UTF-16 and `buf` holds `cap` writable `u16` units.
            let copied = unsafe {
                QueryDosDeviceW(
                    wide_name.as_ptr(),
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                )
            };
            if copied != 0 {
                let used = (copied as usize).min(buf.len());
                let slice = &buf[..used];
                let first_len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
                if first_len == 0 {
                    return None;
                }
                return String::from_utf16(&slice[..first_len]).ok();
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER) && cap < 32_768 {
                cap *= 2;
                continue;
            }
            return None;
        }
        None
    }

    fn query_dos_device_target(drive: char) -> Option<String> {
        let name = format!("{}:", drive.to_ascii_uppercase());
        query_dos_device_by_name(&name)
    }

    fn verify_local_path_recursive(
        path: &Path,
        already_normalized: bool,
        remaining_depth: usize,
    ) -> PathLocality {
        if remaining_depth == 0 {
            return PathLocality::Indeterminate;
        }
        // Layer 1: syntactic local drive absolute path only (resolve local Volume GUIDs safely via
        // MountMgr or preserve conservatively as `Indeterminate`; reject UNC, device, relative).
        let (drive, segments) = match parse_local_drive_path(path) {
            Some((drive, segments, verbatim)) => {
                if !verbatim && !already_normalized {
                    // Normalize non-verbatim Win32 DOS paths ONCE via `GetFullPathNameW` (exact OS
                    // rules for trailing dots/spaces and `..`), then treat the normalized components
                    // as verbatim `\\?\` so subsequent reparse/Volume-GUID rewrites never double-strip.
                    let Some(norm_path) = normalize_win32_local_path_once(path) else {
                        return PathLocality::Indeterminate;
                    };
                    let Some((norm_drive, norm_segments, _)) = parse_local_drive_path(&norm_path)
                    else {
                        return PathLocality::NonLocal;
                    };
                    (norm_drive, norm_segments)
                } else {
                    (drive, segments)
                }
            }
            None => {
                if let Some((volume_root, vol_segments)) =
                    path.to_str().and_then(parse_volume_guid_path)
                {
                    return resolve_volume_guid_path_locality(
                        &volume_root,
                        &vol_segments,
                        remaining_depth,
                    );
                }
                return PathLocality::NonLocal;
            }
        };
        // Layer 2: inspect DOS device target (`QueryDosDeviceW`) before any filesystem call so
        // `SUBST` aliases are expanded/verified from their real root and network redirectors are
        // rejected without SMB I/O, then verify OS drive type (`DRIVE_REMOVABLE | DRIVE_FIXED | DRIVE_RAMDISK`).
        let Some(dos_target) = query_dos_device_target(drive) else {
            return PathLocality::NonLocal;
        };
        match classify_dos_device_target(&dos_target) {
            DosDeviceTarget::Subst(local_base) => {
                let mut rewritten = local_base;
                for seg in &segments {
                    rewritten.push(seg);
                }
                return verify_local_path_recursive(&rewritten, true, remaining_depth - 1);
            }
            DosDeviceTarget::NonLocal => return PathLocality::NonLocal,
            DosDeviceTarget::VolumeDevice => {}
        }
        if !is_local_drive(drive) {
            return PathLocality::NonLocal;
        }

        // Layer 3: walk from `\\?\X:\` down to the target verbatim, inspecting reparse points without traversal.
        for prefix_len in 0..=segments.len() {
            let current = build_drive_path(drive, &segments[..prefix_len], true);
            let mut wide: Vec<u16> = current.as_os_str().encode_wide().collect();
            if wide.is_empty() || wide.contains(&0) {
                return PathLocality::Indeterminate;
            }
            wide.push(0);

            // SAFETY: `wide` is NUL-terminated UTF-16; `GetFileAttributesW` inspects the last
            // component directly without traversing it when it is a reparse point.
            let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
            if attrs == INVALID_FILE_ATTRIBUTES {
                let err = std::io::Error::last_os_error();
                return if err.kind() == ErrorKind::NotFound {
                    PathLocality::NotFound
                } else {
                    PathLocality::Indeterminate
                };
            }

            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                match inspect_reparse_point_target(&current) {
                    Ok(ReparseTargetResolution::LocalDrive(local_target)) => {
                        let mut rewritten = local_target;
                        for rest in &segments[prefix_len..] {
                            rewritten.push(rest);
                        }
                        return verify_local_path_recursive(&rewritten, true, remaining_depth - 1);
                    }
                    Ok(ReparseTargetResolution::VolumeGuid {
                        volume_root,
                        segments: mut vol_segments,
                    }) => {
                        vol_segments.extend(segments[prefix_len..].iter().cloned());
                        return resolve_volume_guid_path_locality(
                            &volume_root,
                            &vol_segments,
                            remaining_depth,
                        );
                    }
                    Ok(ReparseTargetResolution::Remote) => return PathLocality::NonLocal,
                    Err(status) => return status,
                }
            }
        }

        PathLocality::Local(build_drive_path(drive, &segments, true))
    }

    pub(crate) fn verify_local_manifest_for_removal(path: &Path) -> bool {
        matches!(
            verify_local_path_recursive(path, false, MAX_REPARSE_HOPS),
            PathLocality::Local(_)
        )
    }

    fn query_file_identity(path: &Path) -> FileIdentityLookup {
        let resolved_local = match verify_local_path_recursive(path, false, MAX_REPARSE_HOPS) {
            PathLocality::Local(p) => p,
            PathLocality::NonLocal => return FileIdentityLookup::NonLocal,
            PathLocality::NotFound => return FileIdentityLookup::NotFound,
            PathLocality::Indeterminate => return FileIdentityLookup::Indeterminate,
        };

        let mut wide: Vec<u16> = resolved_local.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return FileIdentityLookup::Indeterminate;
        }
        wide.push(0);

        // SAFETY: `wide` is NUL-terminated UTF-16 pointing to a verified local non-reparse target;
        // `FILE_FLAG_OPEN_REPARSE_POINT` prevents following a leaf symlink swapped in via TOCTOU,
        // and `FILE_FLAG_BACKUP_SEMANTICS` allows opening local directories without `ERROR_ACCESS_DENIED`.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw as isize == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return if err.kind() == ErrorKind::NotFound {
                FileIdentityLookup::NotFound
            } else {
                FileIdentityLookup::Indeterminate
            };
        }

        let handle = OwnedFileHandle(raw);
        let mut info = ByHandleFileInformation::default();
        // SAFETY: `handle.0` is a valid handle and `info` matches `BY_HANDLE_FILE_INFORMATION`.
        let ok = unsafe { GetFileInformationByHandle(handle.0, &mut info) };
        if ok == 0 {
            return FileIdentityLookup::Indeterminate;
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return FileIdentityLookup::Indeterminate;
        }
        FileIdentityLookup::Found(FileIdentity {
            volume_serial_number: info.dw_volume_serial_number,
            file_index_high: info.n_file_index_high,
            file_index_low: info.n_file_index_low,
        })
    }

    fn root_key(scope: Scope) -> RegKey {
        match scope {
            Scope::User => RegKey::predef(HKEY_CURRENT_USER),
            Scope::Machine => RegKey::predef(HKEY_LOCAL_MACHINE),
        }
    }

    fn raw_hive(scope: Scope) -> isize {
        match scope {
            Scope::User => HKEY_CURRENT_USER_RAW,
            Scope::Machine => HKEY_LOCAL_MACHINE_RAW,
        }
    }

    fn format_key_display(
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> String {
        match view {
            Some(v) => format!(r"{}\{subkey} [{}]", target.hive_name(), v.as_str()),
            None => format!(r"{}\{subkey}", target.hive_name()),
        }
    }

    fn to_utf16_nul(s: &str) -> Result<Vec<u16>> {
        if s.is_empty() || s.contains('\0') {
            anyhow::bail!("registry subkey must be non-empty and must not contain NUL bytes");
        }
        Ok(s.encode_utf16().chain(std::iter::once(0)).collect())
    }

    fn decode_reg_sz_bytes(bytes: &[u8]) -> Option<String> {
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        let mut units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        Some(String::from_utf16_lossy(&units))
    }

    fn annotate_reg_err(scope: Scope, key_display: &str, err: std::io::Error) -> anyhow::Error {
        if scope == Scope::Machine && err.kind() == ErrorKind::PermissionDenied {
            anyhow::anyhow!(
                "access denied writing '{key_display}': Administrator elevation is required for --scope machine (or use --scope user): {err}"
            )
        } else {
            anyhow::Error::new(err).context(format!("registry write failed for '{key_display}'"))
        }
    }

    pub(crate) fn ensure_default_sz(
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
        expected: &str,
    ) -> Result<bool> {
        let root = root_key(target.scope);
        let view_flag = view.map_or(0, RegWow64View::access_flag);
        let key_display = format_key_display(target, subkey, view);

        if let Ok(existing_key) = root.open_subkey_with_flags(subkey, KEY_READ | view_flag) {
            if let Ok(raw) = existing_key.get_raw_value("") {
                if raw.vtype == REG_SZ {
                    if let Some(current) = decode_reg_sz_bytes(&raw.bytes) {
                        if current == expected {
                            return Ok(false);
                        }
                    }
                }
            }
        }

        let (key, _) = root
            .create_subkey_with_flags(subkey, KEY_READ | KEY_WRITE | view_flag)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        key.set_value("", &expected)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        Ok(true)
    }

    pub(crate) fn ensure_uri_registered(
        target: &RegistryTarget,
        ui_exe: &Path,
    ) -> Result<bool> {
        let base_subkey = target.uri_subkey();
        let cmd_subkey = format!(r"{base_subkey}\shell\open\command");
        let expected_cmd = format_ledr_uri_command(ui_exe);
        let root = root_key(target.scope);
        let key_display = format!(r"{}\{base_subkey}", target.hive_name());

        if let (Ok(base_key), Ok(cmd_key)) = (
            root.open_subkey_with_flags(&base_subkey, KEY_READ),
            root.open_subkey_with_flags(&cmd_subkey, KEY_READ),
        ) {
            let desc_ok = base_key.get_value::<String, _>("").ok().as_deref()
                == Some(LEDR_URI_DESCRIPTION);
            let proto_ok =
                base_key.get_value::<String, _>("URL Protocol").ok().as_deref() == Some("");
            let cmd_ok =
                cmd_key.get_value::<String, _>("").ok().as_deref() == Some(expected_cmd.as_str());
            if desc_ok && proto_ok && cmd_ok {
                return Ok(false);
            }
        }

        let (base_key, _) = root
            .create_subkey(&base_subkey)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        base_key
            .set_value("", &LEDR_URI_DESCRIPTION)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        base_key
            .set_value("URL Protocol", &"")
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;

        let cmd_display = format!(r"{}\{cmd_subkey}", target.hive_name());
        let (cmd_key, _) = root
            .create_subkey(&cmd_subkey)
            .map_err(|err| annotate_reg_err(target.scope, &cmd_display, err))?;
        cmd_key
            .set_value("", &expected_cmd)
            .map_err(|err| annotate_reg_err(target.scope, &cmd_display, err))?;

        Ok(true)
    }

    pub(crate) fn ensure_aumid_registered(target: &RegistryTarget) -> Result<bool> {
        let subkey = target.aumid_subkey();
        let root = root_key(target.scope);
        let key_display = format!(r"{}\{subkey}", target.hive_name());

        if let Ok(base_key) = root.open_subkey_with_flags(&subkey, KEY_READ) {
            if base_key
                .get_value::<String, _>("DisplayName")
                .ok()
                .as_deref()
                == Some(LEDR_AUMID_DISPLAY_NAME)
            {
                return Ok(false);
            }
        }

        let (base_key, _) = root
            .create_subkey(&subkey)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        base_key
            .set_value("DisplayName", &LEDR_AUMID_DISPLAY_NAME)
            .map_err(|err| annotate_reg_err(target.scope, &key_display, err))?;
        Ok(true)
    }

    pub(crate) fn delete_subkey_tree_idempotent(
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> Result<bool> {
        let key_display = format_key_display(target, subkey, view);
        let Some(wow64_view) = view else {
            let root = root_key(target.scope);
            return match root.delete_subkey_all(subkey) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
                Err(err) => Err(annotate_reg_err(target.scope, &key_display, err)),
            };
        };

        let hive = raw_hive(target.scope);
        let subkey_w = to_utf16_nul(subkey)?;
        let view_flag = wow64_view.access_flag();
        let mut hkey: isize = 0;
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and `hkey` is valid out-pointer storage.
        let open_status = unsafe {
            RegOpenKeyExW(
                hive,
                subkey_w.as_ptr(),
                0,
                KEY_READ | KEY_WRITE | DELETE | view_flag,
                &mut hkey,
            )
        };
        if open_status == ERROR_FILE_NOT_FOUND || open_status == ERROR_PATH_NOT_FOUND {
            return Ok(false);
        }
        if open_status != ERROR_SUCCESS {
            return Err(annotate_reg_err(
                target.scope,
                &key_display,
                std::io::Error::from_raw_os_error(open_status),
            ));
        }

        let opened = OwnedRegKey(hkey);
        // SAFETY: `opened.0` is a valid open HKEY in `view_flag`; `NULL` deletes all child subkeys and values while leaving the key itself for `RegDeleteKeyExW`.
        let tree_status = unsafe { RegDeleteTreeW(opened.0, ptr::null()) };
        drop(opened);
        if tree_status != ERROR_SUCCESS
            && tree_status != ERROR_FILE_NOT_FOUND
            && tree_status != ERROR_PATH_NOT_FOUND
        {
            return Err(annotate_reg_err(
                target.scope,
                &key_display,
                std::io::Error::from_raw_os_error(tree_status),
            ));
        }

        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and all child subkeys have been removed; `view_flag` targets the explicit WOW64 view.
        let del_status = unsafe { RegDeleteKeyExW(hive, subkey_w.as_ptr(), view_flag, 0) };
        if del_status == ERROR_SUCCESS {
            Ok(true)
        } else if del_status == ERROR_FILE_NOT_FOUND || del_status == ERROR_PATH_NOT_FOUND {
            Ok(false)
        } else {
            Err(annotate_reg_err(
                target.scope,
                &key_display,
                std::io::Error::from_raw_os_error(del_status),
            ))
        }
    }

    pub(crate) fn probe_default_sz(
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> NativeHostRegProbe {
        let root = root_key(target.scope);
        let view_flag = view.map_or(0, RegWow64View::access_flag);
        let key_display = format_key_display(target, subkey, view);
        let key = match root.open_subkey_with_flags(subkey, KEY_READ | view_flag) {
            Ok(k) => k,
            Err(err) if err.kind() == ErrorKind::NotFound => return NativeHostRegProbe::Absent,
            Err(err) => {
                return NativeHostRegProbe::AccessError(format!(
                    "failed to read {key_display}: {err}"
                ));
            }
        };

        match key.get_raw_value("") {
            Ok(raw) if raw.vtype == REG_SZ => match decode_reg_sz_bytes(&raw.bytes) {
                Some(val) if val.trim().is_empty() => NativeHostRegProbe::EmptyString,
                Some(val) => NativeHostRegProbe::Present(val.trim().to_string()),
                None => NativeHostRegProbe::InvalidType,
            },
            Ok(_) => NativeHostRegProbe::InvalidType,
            Err(err) if err.kind() == ErrorKind::NotFound => NativeHostRegProbe::InvalidType,
            Err(err) => {
                NativeHostRegProbe::AccessError(format!("failed to read {key_display}: {err}"))
            }
        }
    }

    pub(crate) fn read_uri_status(target: &RegistryTarget) -> (bool, Option<String>) {
        let root = root_key(target.scope);
        let base_subkey = target.uri_subkey();
        let cmd_subkey = format!(r"{base_subkey}\shell\open\command");
        let Ok(base_key) = root.open_subkey_with_flags(&base_subkey, KEY_READ) else {
            return (false, None);
        };
        let Ok(cmd_key) = root.open_subkey_with_flags(&cmd_subkey, KEY_READ) else {
            return (false, None);
        };
        let has_proto = base_key.get_value::<String, _>("URL Protocol").is_ok();
        let cmd = cmd_key.get_value::<String, _>("").ok();
        (has_proto && cmd.is_some(), cmd)
    }

    pub(crate) fn read_aumid_status(target: &RegistryTarget) -> (bool, Option<String>) {
        let root = root_key(target.scope);
        let subkey = target.aumid_subkey();
        let Ok(key) = root.open_subkey_with_flags(&subkey, KEY_READ) else {
            return (false, None);
        };
        let name = key.get_value::<String, _>("DisplayName").ok();
        (name.is_some(), name)
    }

    pub(crate) fn read_native_hosts_launch_directly_policy(
        target: &RegistryTarget,
        browser: BrowserKind,
    ) -> Option<bool> {
        let subkey = target.browser_policy_subkey(browser)?;
        let root = root_key(target.scope);
        let key = root.open_subkey_with_flags(&subkey, KEY_READ).ok()?;
        let val = key
            .get_value::<u32, _>(NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE)
            .ok()?;
        Some(val != 0)
    }

    pub(crate) fn any_existing_shares_identity(
        candidate: &Path,
        remaining_existing: &[String],
    ) -> bool {
        if remaining_existing.is_empty() {
            return false;
        }

        let candidate_id = match query_file_identity(candidate) {
            FileIdentityLookup::Found(id) => id,
            FileIdentityLookup::NotFound => return false,
            FileIdentityLookup::NonLocal | FileIdentityLookup::Indeterminate => return true,
        };

        for existing in remaining_existing {
            match query_file_identity(Path::new(existing)) {
                FileIdentityLookup::Found(existing_id) if existing_id == candidate_id => {
                    return true;
                }
                FileIdentityLookup::Found(_)
                | FileIdentityLookup::NotFound
                | FileIdentityLookup::NonLocal => {}
                FileIdentityLookup::Indeterminate => return true,
            }
        }
        false
    }
}

#[cfg(not(windows))]
pub(crate) mod win_reg_ops {
    use super::{BrowserKind, NativeHostRegProbe, RegWow64View, RegistryTarget};
    use anyhow::{bail, Result};
    use std::path::Path;

    pub(crate) fn ensure_default_sz(
        _target: &RegistryTarget,
        _subkey: &str,
        _view: Option<RegWow64View>,
        _expected: &str,
    ) -> Result<bool> {
        bail!("Windows Registry setup is only supported on Windows")
    }

    pub(crate) fn ensure_uri_registered(
        _target: &RegistryTarget,
        _ui_exe: &Path,
    ) -> Result<bool> {
        bail!("Windows Registry setup is only supported on Windows")
    }

    pub(crate) fn ensure_aumid_registered(_target: &RegistryTarget) -> Result<bool> {
        bail!("Windows Registry setup is only supported on Windows")
    }

    pub(crate) fn delete_subkey_tree_idempotent(
        _target: &RegistryTarget,
        _subkey: &str,
        _view: Option<RegWow64View>,
    ) -> Result<bool> {
        bail!("Windows Registry unregister is only supported on Windows")
    }

    pub(crate) fn probe_default_sz(
        _target: &RegistryTarget,
        _subkey: &str,
        _view: Option<RegWow64View>,
    ) -> NativeHostRegProbe {
        NativeHostRegProbe::Absent
    }

    pub(crate) fn read_uri_status(_target: &RegistryTarget) -> (bool, Option<String>) {
        (false, None)
    }

    pub(crate) fn read_aumid_status(_target: &RegistryTarget) -> (bool, Option<String>) {
        (false, None)
    }

    pub(crate) fn read_native_hosts_launch_directly_policy(
        _target: &RegistryTarget,
        _browser: BrowserKind,
    ) -> Option<bool> {
        None
    }

    pub(crate) fn any_existing_shares_identity(
        _candidate: &Path,
        _remaining_existing: &[String],
    ) -> bool {
        false
    }

    pub(crate) fn verify_local_manifest_for_removal(_path: &Path) -> bool {
        true
    }
}

pub(crate) fn any_browser_references_manifest_with<O: RegistryViewOps + ?Sized>(
    ops: &O,
    target: &RegistryTarget,
    manifest_display_path: &str,
) -> Result<bool> {
    let views: &[Option<RegWow64View>] = if target.scope == Scope::Machine {
        &[Some(RegWow64View::Wow6432), Some(RegWow64View::Wow6464)]
    } else {
        &[None]
    };

    let mut remaining_existing = Vec::new();
    for browser in [BrowserKind::Chrome, BrowserKind::Edge, BrowserKind::Brave] {
        let subkey = target.browser_subkey(browser);
        for &view in views {
            match ops.probe_default_sz(target, &subkey, view) {
                NativeHostRegProbe::Present(existing) => {
                    if existing.eq_ignore_ascii_case(manifest_display_path)
                        || normalize_display_path(Path::new(&existing))
                            .eq_ignore_ascii_case(manifest_display_path)
                    {
                        return Ok(true);
                    }
                    remaining_existing.push(existing);
                }
                NativeHostRegProbe::Absent
                | NativeHostRegProbe::EmptyString
                | NativeHostRegProbe::InvalidType => {}
                NativeHostRegProbe::AccessError(err) => bail!("{err}"),
            }
        }
    }
    if remaining_existing.is_empty() {
        return Ok(false);
    }

    Ok(ops.any_existing_shares_identity(Path::new(manifest_display_path), &remaining_existing))
}

/// Runs `ledr-bridge-nm setup` against the standard `HKCU` / `HKLM` registry keys.
pub fn run_setup(args: &SetupArgs) -> Result<SetupOutcome> {
    run_setup_with(args, &RegistryTarget::for_scope(args.scope))
}

/// Runs `setup` against an explicit [`RegistryTarget`] (allowing isolated unit-test prefixes).
pub fn run_setup_with(args: &SetupArgs, target: &RegistryTarget) -> Result<SetupOutcome> {
    run_setup_with_ops(args, target, &WinRegistryViewOps)
}

/// Runs `setup` against an explicit [`RegistryTarget`] and [`RegistryViewOps`] backend.
pub fn run_setup_with_ops<O: RegistryViewOps + ?Sized>(
    args: &SetupArgs,
    target: &RegistryTarget,
    ops: &O,
) -> Result<SetupOutcome> {
    if args.browsers.is_empty() {
        bail!("at least one browser must be specified");
    }
    let manifest_dir = resolve_manifest_dir(args.scope, args.manifest_dir.as_deref())?;
    let manifest_dir_display = normalize_display_path(&manifest_dir);

    let bridge_exe = resolve_bridge_exe(args.scope, args.bridge_exe.as_deref())?;
    let ui_exe = resolve_ui_exe(args.scope, &bridge_exe, args.ui_exe.as_deref())?;

    let manifest = build_manifest(&bridge_exe, &args.extension_id)?;

    let mut any_manifest_written = false;
    let mut browser_outcomes = Vec::with_capacity(args.browsers.len());
    for &browser in &args.browsers {
        let manifest_path = manifest_dir.join(manifest_filename_for(args.scope, browser));
        let manifest_display = normalize_display_path(&manifest_path);
        let manifest_written = write_manifest_atomic(&manifest_path, &manifest)?;
        any_manifest_written |= manifest_written;
        let subkey = target.browser_subkey(browser);
        let updated = match target.scope {
            Scope::User => ops.ensure_default_sz(target, &subkey, None, &manifest_display)?,
            Scope::Machine => {
                // Option A1: write identical manifest path to both 32-bit and 64-bit HKLM views
                // so stale/empty 32-bit shadows are repaired idempotently.
                let updated_32 = ops.ensure_default_sz(
                    target,
                    &subkey,
                    Some(RegWow64View::Wow6432),
                    &manifest_display,
                )?;
                let updated_64 = ops.ensure_default_sz(
                    target,
                    &subkey,
                    Some(RegWow64View::Wow6464),
                    &manifest_display,
                )?;
                updated_32 || updated_64
            }
        };
        browser_outcomes.push(BrowserRegistrationOutcome {
            browser,
            registry_key: format!(r"{}\{subkey}", target.hive_name()),
            manifest_path: manifest_display,
            manifest_written,
            updated,
        });
    }

    let (uri_registered, uri_updated, aumid_updated) = if args.skip_uri {
        (false, false, false)
    } else {
        let u_upd = ops.ensure_uri_registered(target, &ui_exe)?;
        let a_upd = ops.ensure_aumid_registered(target)?;
        (true, u_upd, a_upd)
    };

    Ok(SetupOutcome {
        scope: args.scope,
        manifest_dir: manifest_dir_display,
        manifest_written: any_manifest_written,
        bridge_exe: normalize_display_path(&bridge_exe),
        ui_exe: normalize_display_path(&ui_exe),
        extension_id: args.extension_id.clone(),
        browsers: browser_outcomes,
        uri_registered,
        uri_updated,
        aumid_updated,
    })
}

fn is_localedr_manifest_filename(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.starts_with("com.localedr.bridge") && lower.ends_with(".json")
}

/// Runs `ledr-bridge-nm unregister` against the standard `HKCU` / `HKLM` registry keys,
/// checking the opposite registry scope before deleting manifest files.
pub fn run_unregister(args: &UnregisterArgs) -> Result<UnregisterOutcome> {
    let target = RegistryTarget::for_scope(args.scope);
    let peer_target = RegistryTarget::for_scope(args.scope.other());
    run_unregister_with(args, &target, Some(&peer_target))
}

/// Runs `unregister` against an explicit [`RegistryTarget`] and optional opposite-scope `peer_target`.
pub fn run_unregister_with(
    args: &UnregisterArgs,
    target: &RegistryTarget,
    peer_target: Option<&RegistryTarget>,
) -> Result<UnregisterOutcome> {
    run_unregister_with_ops(args, target, peer_target, &WinRegistryViewOps)
}

/// Runs `unregister` against an explicit [`RegistryTarget`], optional `peer_target`, and [`RegistryViewOps`] backend.
pub fn run_unregister_with_ops<O: RegistryViewOps + ?Sized>(
    args: &UnregisterArgs,
    target: &RegistryTarget,
    peer_target: Option<&RegistryTarget>,
    ops: &O,
) -> Result<UnregisterOutcome> {
    let manifest_dir = resolve_manifest_dir(args.scope, args.manifest_dir.as_deref())?;
    let manifest_dir_display = normalize_display_path(&manifest_dir);

    let mut per_browser_candidates = Vec::with_capacity(args.browsers.len());
    let mut candidate_paths = BTreeSet::new();
    for &browser in &args.browsers {
        let subkey = target.browser_subkey(browser);
        let reg_val = match target.scope {
            Scope::User => {
                let probe = ops.probe_default_sz(target, &subkey, None);
                if let NativeHostRegProbe::AccessError(err) = probe {
                    bail!("{err}");
                }
                if let NativeHostRegProbe::Present(ref raw_path) = probe {
                    let reg_path = PathBuf::from(raw_path);
                    if is_localedr_manifest_filename(&reg_path) {
                        candidate_paths.insert(reg_path);
                    }
                    Some(raw_path.clone())
                } else {
                    None
                }
            }
            Scope::Machine => {
                let probe32 = ops.probe_default_sz(target, &subkey, Some(RegWow64View::Wow6432));
                let probe64 = ops.probe_default_sz(target, &subkey, Some(RegWow64View::Wow6464));
                if let NativeHostRegProbe::AccessError(err) = &probe32 {
                    bail!("{err}");
                }
                if let NativeHostRegProbe::AccessError(err) = &probe64 {
                    bail!("{err}");
                }
                for probe in [&probe32, &probe64] {
                    if let NativeHostRegProbe::Present(ref raw_path) = probe {
                        let reg_path = PathBuf::from(raw_path);
                        if is_localedr_manifest_filename(&reg_path) {
                            candidate_paths.insert(reg_path);
                        }
                    }
                }
                match (&probe32, &probe64) {
                    (NativeHostRegProbe::Present(p), _) | (_, NativeHostRegProbe::Present(p)) => {
                        Some(p.clone())
                    }
                    _ => None,
                }
            }
        };
        let default_browser_path = manifest_dir.join(manifest_filename_for(args.scope, browser));
        candidate_paths.insert(default_browser_path.clone());
        per_browser_candidates.push((browser, reg_val, default_browser_path));
    }

    let mut browser_outcomes = Vec::with_capacity(args.browsers.len());
    for (browser, reg_val, _) in &per_browser_candidates {
        let subkey = target.browser_subkey(*browser);
        let removed = match target.scope {
            Scope::User => ops.delete_subkey_tree_idempotent(target, &subkey, None)?,
            Scope::Machine => {
                let rem32 = ops.delete_subkey_tree_idempotent(
                    target,
                    &subkey,
                    Some(RegWow64View::Wow6432),
                )?;
                let rem64 = ops.delete_subkey_tree_idempotent(
                    target,
                    &subkey,
                    Some(RegWow64View::Wow6464),
                )?;
                rem32 || rem64
            }
        };
        browser_outcomes.push(BrowserUnregisterOutcome {
            browser: *browser,
            registry_key: format!(r"{}\{subkey}", target.hive_name()),
            manifest_path: reg_val.clone(),
            removed,
            manifest_removed: false,
        });
    }

    let (uri_removed, aumid_removed) = if args.keep_uri {
        (false, false)
    } else {
        let u_rem = ops.delete_subkey_tree_idempotent(target, &target.uri_subkey(), None)?;
        let a_rem = ops.delete_subkey_tree_idempotent(target, &target.aumid_subkey(), None)?;
        (u_rem, a_rem)
    };

    let mut manifest_paths_removed = Vec::new();
    for candidate in &candidate_paths {
        let candidate_display = normalize_display_path(candidate);
        let still_in_self =
            any_browser_references_manifest_with(ops, target, &candidate_display).unwrap_or(true);
        let still_in_peer = match peer_target {
            Some(peer) => {
                any_browser_references_manifest_with(ops, peer, &candidate_display).unwrap_or(true)
            }
            None => false,
        };
        if still_in_self || still_in_peer {
            continue;
        }
        if !ops.verify_local_manifest_for_removal(candidate) {
            continue;
        }
        match std::fs::remove_file(candidate) {
            Ok(()) => manifest_paths_removed.push(candidate_display),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to remove Native Messaging manifest '{}'",
                        candidate.display()
                    )
                });
            }
        }
    }

    for (entry, (_, reg_val, default_browser_path)) in
        browser_outcomes.iter_mut().zip(per_browser_candidates.iter())
    {
        let default_display = normalize_display_path(default_browser_path);
        entry.manifest_removed = manifest_paths_removed.iter().any(|removed| {
            removed.eq_ignore_ascii_case(&default_display)
                || reg_val
                    .as_deref()
                    .is_some_and(|reg| removed.eq_ignore_ascii_case(reg))
        });
    }

    let manifest_removed = !manifest_paths_removed.is_empty();
    Ok(UnregisterOutcome {
        scope: args.scope,
        manifest_dir: manifest_dir_display,
        manifest_paths_removed,
        manifest_removed,
        browsers: browser_outcomes,
        uri_removed,
        aumid_removed,
    })
}

/// Runs `ledr-bridge-nm status` against the standard `HKCU` / `HKLM` registry keys.
pub fn run_status(args: &StatusArgs) -> Result<StatusReport> {
    let targets = match args.scope {
        StatusScope::All => vec![
            RegistryTarget::for_scope(Scope::User),
            RegistryTarget::for_scope(Scope::Machine),
        ],
        StatusScope::User => vec![RegistryTarget::for_scope(Scope::User)],
        StatusScope::Machine => vec![RegistryTarget::for_scope(Scope::Machine)],
    };
    run_status_with(args, &targets, None)
}

/// Runs `status` against explicit [`RegistryTarget`] entries (allowing isolated tests).
pub fn run_status_with(
    args: &StatusArgs,
    targets: &[RegistryTarget],
    manifest_dir_override: Option<&Path>,
) -> Result<StatusReport> {
    run_status_with_ops(args, targets, manifest_dir_override, &WinRegistryViewOps)
}

fn synthetic_invalid_manifest(error: String) -> ManifestValidation {
    ManifestValidation {
        exists: false,
        valid: false,
        bridge_exe_exists: false,
        extension_id_matched: false,
        allowed_origins: Vec::new(),
        path: String::new(),
        error: Some(error),
    }
}

/// Runs `status` against explicit [`RegistryTarget`] entries and a [`RegistryViewOps`] backend.
pub fn run_status_with_ops<O: RegistryViewOps + ?Sized>(
    args: &StatusArgs,
    targets: &[RegistryTarget],
    manifest_dir_override: Option<&Path>,
    ops: &O,
) -> Result<StatusReport> {
    let expected_extension_id = args.extension_id.clone();
    let mut scopes = Vec::with_capacity(targets.len());

    for target in targets {
        let default_manifest_dir = resolve_manifest_dir(target.scope, manifest_dir_override)
            .map(|d| normalize_display_path(&d))
            .unwrap_or_default();

        let mut browsers = Vec::with_capacity(3);
        for browser in [BrowserKind::Chrome, BrowserKind::Edge, BrowserKind::Brave] {
            let subkey = target.browser_subkey(browser);
            let (probe, effective_view) = match target.scope {
                Scope::User => (ops.probe_default_sz(target, &subkey, None), None),
                Scope::Machine => {
                    let view32 =
                        ops.probe_default_sz(target, &subkey, Some(RegWow64View::Wow6432));
                    let view64 =
                        ops.probe_default_sz(target, &subkey, Some(RegWow64View::Wow6464));
                    select_effective_hklm_probe(view32, view64)
                }
            };
            let (registered, manifest_path, manifest) = match probe {
                NativeHostRegProbe::Absent => (false, None, None),
                NativeHostRegProbe::Present(path) => {
                    let validation = validate_manifest_file(Path::new(&path), &expected_extension_id);
                    (true, Some(path), Some(validation))
                }
                NativeHostRegProbe::EmptyString => (
                    true,
                    None,
                    Some(synthetic_invalid_manifest(
                        "registry default value is empty REG_SZ".to_string(),
                    )),
                ),
                NativeHostRegProbe::InvalidType => (
                    true,
                    None,
                    Some(synthetic_invalid_manifest(
                        "registry default value is missing or not REG_SZ".to_string(),
                    )),
                ),
                NativeHostRegProbe::AccessError(err) => {
                    (true, None, Some(synthetic_invalid_manifest(err)))
                }
            };
            let native_hosts_launch_directly =
                ops.read_native_hosts_launch_directly_policy(target, browser);
            browsers.push(BrowserStatusEntry {
                browser,
                registry_key: format!(r"{}\{subkey}", target.hive_name()),
                registry_view: effective_view.map(|v| v.as_str().to_string()),
                registered,
                manifest_path,
                manifest,
                native_hosts_launch_directly,
            });
        }

        let (uri_registered, uri_command) = ops.read_uri_status(target);
        let (aumid_registered, aumid_display_name) = ops.read_aumid_status(target);

        scopes.push(ScopeStatusReport {
            scope: target.scope,
            default_manifest_dir,
            browsers,
            uri_registered,
            uri_command,
            aumid_registered,
            aumid_display_name,
        });
    }

    let daemon_ping = if args.ping {
        let client = PipeClient::new(&args.pipe_name);
        Some(match client.ping() {
            Ok((daemon_version, protocol_version)) => DaemonPingStatus {
                pipe_name: args.pipe_name.clone(),
                online: true,
                daemon_version: Some(daemon_version),
                protocol_version: Some(protocol_version),
                error: None,
            },
            Err(err) => DaemonPingStatus {
                pipe_name: args.pipe_name.clone(),
                online: false,
                daemon_version: None,
                protocol_version: None,
                error: Some(err.to_string()),
            },
        })
    } else {
        None
    };

    Ok(StatusReport {
        expected_extension_id,
        scopes,
        daemon_ping,
    })
}

/// Formats `SetupOutcome` for human-readable CLI output.
pub fn format_setup_text(outcome: &SetupOutcome) -> String {
    let mut lines = vec![
        format!("LocalEDR Native Messaging setup ({})", outcome.scope.as_str()),
        format!(
            "  Manifest Dir: {} ({})",
            outcome.manifest_dir,
            if outcome.manifest_written {
                "written"
            } else {
                "unchanged"
            }
        ),
        format!("  Extension ID: {}", outcome.extension_id),
        format!("  Bridge EXE: {}", outcome.bridge_exe),
    ];
    for b in &outcome.browsers {
        lines.push(format!(
            "  {}: {} -> {} ({}, manifest {})",
            b.browser.display_name(),
            b.registry_key,
            b.manifest_path,
            if b.updated { "updated" } else { "unchanged" },
            if b.manifest_written {
                "written"
            } else {
                "unchanged"
            }
        ));
    }
    if outcome.uri_registered {
        lines.push(format!(
            "  ledr:// URI: {} (UI: {}, AUMID: {})",
            if outcome.uri_updated {
                "updated"
            } else {
                "unchanged"
            },
            outcome.ui_exe,
            if outcome.aumid_updated {
                "updated"
            } else {
                "unchanged"
            }
        ));
    } else {
        lines.push("  ledr:// URI: skipped (--skip-uri)".to_string());
    }
    lines.join("\n")
}

/// Formats `UnregisterOutcome` for human-readable CLI output.
pub fn format_unregister_text(outcome: &UnregisterOutcome) -> String {
    let mut lines = vec![
        format!(
            "LocalEDR Native Messaging unregister ({})",
            outcome.scope.as_str()
        ),
        format!("  Manifest Dir: {}", outcome.manifest_dir),
    ];
    for b in &outcome.browsers {
        lines.push(format!(
            "  {}: {} ({}, manifest {})",
            b.browser.display_name(),
            b.registry_key,
            if b.removed { "removed" } else { "absent" },
            if b.manifest_removed {
                "removed"
            } else {
                "kept/absent"
            }
        ));
    }
    lines.push(format!(
        "  Manifest files: {} ({})",
        if outcome.manifest_paths_removed.is_empty() {
            "-".to_string()
        } else {
            outcome.manifest_paths_removed.join(", ")
        },
        if outcome.manifest_removed {
            "removed"
        } else {
            "kept/absent"
        }
    ));
    lines.push(format!(
        "  ledr:// URI: {}, AUMID: {}",
        if outcome.uri_removed { "removed" } else { "kept/absent" },
        if outcome.aumid_removed {
            "removed"
        } else {
            "kept/absent"
        }
    ));
    lines.join("\n")
}

/// Formats `StatusReport` for human-readable CLI output.
pub fn format_status_text(report: &StatusReport) -> String {
    let mut lines = vec![format!(
        "LocalEDR Native Messaging status (expected extension ID: {})",
        report.expected_extension_id
    )];
    for scope in &report.scopes {
        lines.push(format!("Scope [{}]:", scope.scope.as_str()));
        for b in &scope.browsers {
            let state = match (&b.registered, &b.manifest) {
                (false, _) => "not registered".to_string(),
                (true, Some(m)) if m.valid => format!("registered & valid ({})", m.path),
                (true, Some(m)) if m.path.is_empty() => format!(
                    "registered but INVALID: {}",
                    m.error.as_deref().unwrap_or("unknown error")
                ),
                (true, Some(m)) => format!(
                    "registered but INVALID ({}): {}",
                    m.path,
                    m.error.as_deref().unwrap_or("unknown error")
                ),
                (true, None) => "registered".to_string(),
            };
            let view_note = b
                .registry_view
                .as_deref()
                .map(|v| format!(" [{v}]"))
                .unwrap_or_default();
            let policy_note = match b.native_hosts_launch_directly {
                Some(true) => " [policy NativeHostsExecutablesLaunchDirectly=1 (direct)]",
                Some(false) => {
                    " [policy NativeHostsExecutablesLaunchDirectly=0 (cmd.exe mediated)]"
                }
                None => "",
            };
            lines.push(format!(
                "  {}: {state}{view_note}{policy_note}",
                b.browser.display_name()
            ));
        }
        lines.push(format!(
            "  ledr:// URI: {}",
            if scope.uri_registered {
                scope
                    .uri_command
                    .as_deref()
                    .unwrap_or("registered")
                    .to_string()
            } else {
                "not registered".to_string()
            }
        ));
        lines.push(format!(
            "  AUMID: {}",
            if scope.aumid_registered {
                scope
                    .aumid_display_name
                    .as_deref()
                    .unwrap_or("registered")
                    .to_string()
            } else {
                "not registered".to_string()
            }
        ));
    }
    if let Some(ping) = &report.daemon_ping {
        if ping.online {
            lines.push(format!(
                "Daemon Ping ({}): online (v{}, proto v{})",
                ping.pipe_name,
                ping.daemon_version.as_deref().unwrap_or("?"),
                ping.protocol_version.unwrap_or(0)
            ));
        } else {
            lines.push(format!(
                "Daemon Ping ({}): offline ({})",
                ping.pipe_name,
                ping.error.as_deref().unwrap_or("unreachable")
            ));
        }
    }
    lines.join("\n")
}
