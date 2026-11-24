//! Honeypot decoy file deployment and removal lifecycle (`L-06`).

use std::collections::HashSet;
use std::ffi::{c_void, OsString};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use ledr_proto::HONEYPOT_DEFAULT_FILENAME;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
use windows::Win32::Storage::FileSystem::{
    SetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SYSTEM,
    FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::RemoteDesktop::{
    WTSActive, WTSConnected, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQueryUserToken, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};

use crate::SensorError;

const HONEYPOT_DECOY_CONTENT: &[u8] = b"LocalEDR Canary Decoy File - Do Not Modify or Delete.\r\n";
const HONEYPOT_SUBDIRS: [&str; 3] = ["Documents", "Desktop", "Pictures"];
const PROFILE_LIST_SUBKEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";

const HKEY_LOCAL_MACHINE: *mut c_void = 0x8000_0002_u32 as usize as *mut c_void;
const KEY_READ: u32 = 0x0002_0019;
const KEY_WOW64_64KEY: u32 = 0x0100;
const ERROR_SUCCESS_U32: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER_I32: i32 = 122;
const ERROR_MORE_DATA_U32: u32 = 234;
const ERROR_NO_MORE_ITEMS_U32: u32 = 259;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;

/// Manages deployment and removal of lexicographically-first honeypot decoy files (`L-06`).
#[derive(Debug, Clone)]
pub struct HoneypotManager {
    roots: Vec<PathBuf>,
    create_missing_roots: bool,
    deployed_paths: Vec<PathBuf>,
}

impl Default for HoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotManager {
    /// Creates a [`HoneypotManager`] targeting the current process's `%USERPROFILE%` folders:
    /// `%USERPROFILE%\Documents`, `%USERPROFILE%\Desktop`, and `%USERPROFILE%\Pictures`.
    pub fn new() -> Self {
        let roots = default_honeypot_roots();
        Self {
            roots,
            create_missing_roots: false,
            deployed_paths: Vec::new(),
        }
    }

    /// Creates a [`HoneypotManager`] for `LocalSystem` service execution by discovering active
    /// WTS user sessions and non-system user profiles in `ProfileList` (`Documents`, `Desktop`,
    /// `Pictures`), validating directory existence and rejecting reparse points.
    pub fn for_service() -> Self {
        let profiles = discover_service_user_profiles();
        Self::for_user_profiles(profiles)
    }

    /// Creates a [`HoneypotManager`] targeting `Documents`, `Desktop`, and `Pictures` under an
    /// explicit list of user profile directories without creating missing directories.
    pub fn for_user_profiles(profiles: Vec<PathBuf>) -> Self {
        let roots = roots_for_user_profiles(&profiles);
        Self {
            roots,
            create_missing_roots: false,
            deployed_paths: Vec::new(),
        }
    }

    /// Creates a [`HoneypotManager`] targeting an explicit list of root directories (for tests or
    /// custom policies).
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            create_missing_roots: true,
            deployed_paths: Vec::new(),
        }
    }

    /// Returns the configured directory roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Returns the paths currently tracked as deployed honeypots.
    pub fn deployed_paths(&self) -> &[PathBuf] {
        &self.deployed_paths
    }

    /// Returns `true` if `a` and `b` represent the same set of honeypot file paths
    /// (case-insensitive on Windows).
    pub fn path_sets_equal(a: &[PathBuf], b: &[PathBuf]) -> bool {
        honeypot_path_sets_equal(a, b)
    }

    /// Refreshes service-discovered user profiles, deploying decoy files for any newly logged-in
    /// or newly provisioned user folders. Returns `Ok(true)` if the tracked deployed path set
    /// changed.
    pub fn refresh_service_profiles(&mut self) -> Result<bool, SensorError> {
        let profiles = discover_service_user_profiles();
        self.refresh_user_profiles(profiles)
    }

    /// Refreshes managed honeypot roots against an explicit list of user profile directories.
    /// Returns `Ok(true)` if the tracked deployed path set changed.
    pub fn refresh_user_profiles(&mut self, profiles: Vec<PathBuf>) -> Result<bool, SensorError> {
        let previous = self.deployed_paths.clone();
        self.roots = roots_for_user_profiles(&profiles);

        let allowed_roots: HashSet<String> = self
            .roots
            .iter()
            .map(|root| normalize_windows_path_key(root))
            .collect();
        self.deployed_paths.retain(|path| {
            let parent_allowed = path
                .parent()
                .map(normalize_windows_path_key)
                .is_some_and(|key| allowed_roots.contains(&key));
            parent_allowed && is_safe_existing_file(path)
        });

        let deploy_result = self.deploy_honeypots();
        let changed = !honeypot_path_sets_equal(&previous, &self.deployed_paths);
        deploy_result.map(|_| changed)
    }

    /// Deploys `!00_LocalEDR_Canary_DoNotEdit.docx` into configured roots and tracks created paths.
    ///
    /// Preserves inherited folder ACLs so user-space processes can touch the decoy, sets
    /// `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM` (never `READONLY`), and rejects reparse
    /// points when `create_missing_roots` is `false`.
    pub fn deploy_honeypots(&mut self) -> Result<Vec<PathBuf>, SensorError> {
        let mut created = Vec::new();
        let mut first_error: Option<SensorError> = None;

        for root in &self.roots {
            if self.create_missing_roots {
                if let Err(err) = std::fs::create_dir_all(root) {
                    if first_error.is_none() {
                        first_error = Some(SensorError::Io(err));
                    }
                    continue;
                }
            } else {
                if !is_safe_existing_directory(root) {
                    continue;
                }
                if let Some(profile_root) = root.parent() {
                    if !is_safe_existing_directory(profile_root) {
                        continue;
                    }
                }
            }

            let target = root.join(HONEYPOT_DEFAULT_FILENAME);
            let deploy_res = deploy_single_honeypot(&target);
            match deploy_res {
                Ok(()) => {
                    if !self
                        .deployed_paths
                        .iter()
                        .any(|p| normalize_windows_path_key(p) == normalize_windows_path_key(&target))
                    {
                        self.deployed_paths.push(target.clone());
                    }
                    created.push(target);
                }
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(created)
    }

    /// Deletes all tracked honeypot files cleanly, returning the number of files removed.
    pub fn remove_honeypots(&mut self) -> Result<usize, SensorError> {
        let tracked = std::mem::take(&mut self.deployed_paths);
        let mut removed = 0usize;
        let mut remaining = Vec::new();

        for (idx, path) in tracked.iter().enumerate() {
            match std::fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    remaining.extend_from_slice(&tracked[idx..]);
                    self.deployed_paths = remaining;
                    return Err(SensorError::Io(err));
                }
            }
        }

        Ok(removed)
    }
}

/// Returns `true` if `a` and `b` contain the same set of honeypot paths (case-insensitive on
/// Windows).
pub fn honeypot_path_sets_equal(a: &[PathBuf], b: &[PathBuf]) -> bool {
    let set_a: HashSet<String> = a.iter().map(|p| normalize_windows_path_key(p)).collect();
    let set_b: HashSet<String> = b.iter().map(|p| normalize_windows_path_key(p)).collect();
    set_a == set_b
}

fn deploy_single_honeypot(target: &Path) -> Result<(), SensorError> {
    match std::fs::symlink_metadata(target) {
        Ok(meta) => {
            let attrs = meta.file_attributes();
            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
                return Err(SensorError::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "refusing to deploy honeypot onto reparse point: {}",
                        target.display()
                    ),
                )));
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0 || !meta.is_file() {
                return Err(SensorError::Io(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "refusing to deploy honeypot onto non-file target: {}",
                        target.display()
                    ),
                )));
            }
            set_hidden_system_attributes(target, attrs)?;
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            // Default OpenOptions preserves the parent folder's inherited DACL so non-elevated
            // user processes / ransomware can open and touch the decoy file (`L-06`).
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(target)?;
            file.write_all(HONEYPOT_DECOY_CONTENT)?;
            file.flush()?;
            drop(file);
            let attrs = std::fs::symlink_metadata(target)
                .map(|m| m.file_attributes())
                .unwrap_or(0);
            set_hidden_system_attributes(target, attrs)?;
            Ok(())
        }
        Err(err) => Err(SensorError::Io(err)),
    }
}

fn set_hidden_system_attributes(path: &Path, existing_attrs: u32) -> Result<(), SensorError> {
    let desired = (existing_attrs & !FILE_ATTRIBUTE_READONLY.0)
        | FILE_ATTRIBUTE_HIDDEN.0
        | FILE_ATTRIBUTE_SYSTEM.0;
    let wide = encode_wide_nul(path.as_os_str());
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 path string.
    unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(desired)) }
        .map_err(|err| SensorError::Win32 {
            api: "SetFileAttributesW",
            message: format!("failed setting HIDDEN|SYSTEM on {}: {err}", path.display()),
        })
}

fn default_honeypot_roots() -> Vec<PathBuf> {
    let Some(profile) = std::env::var_os("USERPROFILE") else {
        return Vec::new();
    };
    let base = PathBuf::from(profile);
    HONEYPOT_SUBDIRS
        .iter()
        .map(|sub| base.join(sub))
        .collect()
}

pub(crate) fn roots_for_user_profiles(profiles: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen_profiles = HashSet::new();
    let mut seen_roots = HashSet::new();
    let mut roots = Vec::new();

    for profile in profiles {
        let Some(clean_profile) = sanitize_local_profile_path(profile) else {
            continue;
        };
        let profile_key = normalize_windows_path_key(&clean_profile);
        if !seen_profiles.insert(profile_key) {
            continue;
        }
        if !is_safe_existing_directory(&clean_profile) {
            continue;
        }
        for sub in HONEYPOT_SUBDIRS {
            let candidate = clean_profile.join(sub);
            if !is_safe_existing_directory(&candidate) {
                continue;
            }
            let root_key = normalize_windows_path_key(&candidate);
            if seen_roots.insert(root_key) {
                roots.push(candidate);
            }
        }
    }

    roots
}

pub(crate) fn is_safe_existing_directory(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let attrs = meta.file_attributes();
    (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) == 0 && (attrs & FILE_ATTRIBUTE_DIRECTORY.0) != 0
}

fn is_safe_existing_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let attrs = meta.file_attributes();
    (attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) == 0
        && (attrs & FILE_ATTRIBUTE_DIRECTORY.0) == 0
        && meta.is_file()
}

fn sanitize_local_profile_path(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy();
    let trimmed = raw.trim().trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with(r"\\") || trimmed.starts_with("//") {
        return None;
    }
    let clean = PathBuf::from(trimmed);
    let mut components = clean.components();
    match (components.next(), components.next()) {
        (Some(Component::Prefix(_)), Some(Component::RootDir)) => {}
        _ => return None,
    }
    if clean
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return None;
    }
    Some(clean)
}

fn normalize_windows_path_key(path: &Path) -> String {
    path.to_string_lossy()
        .trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

/// Returns `true` if `sid` belongs to a built-in Windows system or service account whose profile
/// should not receive interactive user honeypot files.
pub(crate) fn is_excluded_profile_sid(sid: &str) -> bool {
    let trimmed = sid.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.eq_ignore_ascii_case("S-1-5-18")
        || trimmed.eq_ignore_ascii_case("S-1-5-19")
        || trimmed.eq_ignore_ascii_case("S-1-5-20")
        || trimmed.eq_ignore_ascii_case(".DEFAULT")
    {
        return true;
    }
    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("S-1-") {
        return true;
    }
    upper.starts_with("S-1-5-80-")
        || upper.starts_with("S-1-5-82-")
        || upper.starts_with("S-1-5-90-")
        || upper.starts_with("S-1-5-96-")
}

pub(crate) fn filter_profile_entries<I>(entries: I) -> Vec<PathBuf>
where
    I: IntoIterator<Item = (String, PathBuf)>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (sid, path) in entries {
        if is_excluded_profile_sid(&sid) {
            continue;
        }
        let Some(clean) = sanitize_local_profile_path(&path) else {
            continue;
        };
        let key = normalize_windows_path_key(&clean);
        if seen.insert(key) {
            out.push(clean);
        }
    }
    out
}

/// Discovers interactive / logged-on and registered non-system Windows user profile directories
/// suitable for service-mode (`LocalSystem`) honeypot deployment.
pub fn discover_service_user_profiles() -> Vec<PathBuf> {
    let mut entries = Vec::new();
    entries.extend(discover_wts_session_profiles());
    entries.extend(discover_registry_profile_list());
    filter_profile_entries(entries)
}

fn discover_wts_session_profiles() -> Vec<(String, PathBuf)> {
    let mut sessions_ptr: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count: u32 = 0;

    // SAFETY: `sessions_ptr` and `count` are valid out pointers; freed via `WtsMemoryGuard`.
    if let Err(err) = unsafe {
        WTSEnumerateSessionsW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            0,
            1,
            &mut sessions_ptr,
            &mut count,
        )
    } {
        tracing::debug!(error = %err, "WTSEnumerateSessionsW failed during honeypot profile discovery");
        return Vec::new();
    }
    if sessions_ptr.is_null() || count == 0 {
        if !sessions_ptr.is_null() {
            // SAFETY: Non-null pointer allocated by `WTSEnumerateSessionsW`.
            unsafe { WTSFreeMemory(sessions_ptr as *mut c_void) };
        }
        return Vec::new();
    }
    let _mem_guard = WtsMemoryGuard(sessions_ptr as *mut c_void);

    // SAFETY: `sessions_ptr` points to `count` valid `WTS_SESSION_INFOW` entries until `_mem_guard` drops.
    let sessions = unsafe { std::slice::from_raw_parts(sessions_ptr, count as usize) };
    let mut discovered = Vec::new();

    for session in sessions {
        if session.SessionId == 0 {
            continue;
        }
        if session.State != WTSActive
            && session.State != WTSConnected
            && session.State != WTSDisconnected
        {
            continue;
        }

        let mut raw_token = HANDLE::default();
        // SAFETY: `session.SessionId` is non-zero; on success `raw_token` is closed via `OwnedHandle`.
        if unsafe { WTSQueryUserToken(session.SessionId, &mut raw_token) }.is_err() {
            continue;
        }
        let token = OwnedHandle(raw_token);

        let sid = query_token_user_sid(token.0).unwrap_or_default();
        if !sid.is_empty() && is_excluded_profile_sid(&sid) {
            continue;
        }
        if let Some(profile_dir) = query_user_profile_directory(token.0) {
            let effective_sid = if sid.is_empty() {
                format!("S-1-5-21-wts-session-{}", session.SessionId)
            } else {
                sid
            };
            discovered.push((effective_sid, profile_dir));
        }
    }

    discovered
}

fn query_token_user_sid(token: HANDLE) -> Option<String> {
    let mut needed: u32 = 0;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed == 0 || needed > 4096 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: `buf` is sized to `needed` bytes for `TOKEN_USER` output.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
    }
    .ok()?;

    // SAFETY: `GetTokenInformation(TokenUser)` initializes `TOKEN_USER` at buffer start.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut sid_str_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: `token_user.User.Sid` is valid for the lifetime of `buf`.
    let ok = unsafe { ConvertSidToStringSidW(token_user.User.Sid.0, &mut sid_str_ptr) };
    if ok == 0 || sid_str_ptr.is_null() {
        return None;
    }
    let _sid_guard = LocalAllocGuard(sid_str_ptr as *mut c_void);

    // SAFETY: `ConvertSidToStringSidW` returns a NUL-terminated UTF-16 string.
    let mut len = 0usize;
    unsafe {
        while *sid_str_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(sid_str_ptr, len);
        Some(String::from_utf16_lossy(slice))
    }
}

fn query_user_profile_directory(token: HANDLE) -> Option<PathBuf> {
    let mut cap: u32 = 512;
    for _ in 0..2 {
        let mut buf = vec![0u16; cap as usize];
        let mut size = cap;
        // SAFETY: `token.0` is an open user token and `buf` holds `size` writable `u16` code units.
        let ok = unsafe { GetUserProfileDirectoryW(token.0, buf.as_mut_ptr(), &mut size) };
        if ok != 0 {
            let used = usize::try_from(size).unwrap_or(buf.len()).min(buf.len());
            let slice = &buf[..used];
            let str_len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
            if str_len == 0 {
                return None;
            }
            return Some(PathBuf::from(OsString::from_wide(&slice[..str_len])));
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER_I32)
            && size > cap
            && size <= 32_768
        {
            cap = size;
            continue;
        }
        return None;
    }
    None
}

fn discover_registry_profile_list() -> Vec<(String, PathBuf)> {
    let Some(list_key) = reg_open_read_hklm(PROFILE_LIST_SUBKEY) else {
        return Vec::new();
    };

    let mut discovered = Vec::new();
    let mut index: u32 = 0;
    while let Some(subkey_name) = reg_enum_key_name(list_key.0, index) {
        index = index.saturating_add(1);

        if is_excluded_profile_sid(&subkey_name) {
            continue;
        }
        let Some(profile_key) = reg_open_read_subkey(list_key.0, &subkey_name) else {
            continue;
        };
        let Some(raw_profile_path) = reg_query_string_value(profile_key.0, "ProfileImagePath")
        else {
            continue;
        };
        let Some(expanded) = expand_profile_image_path(&raw_profile_path) else {
            continue;
        };
        discovered.push((subkey_name, expanded));
    }

    discovered
}

fn expand_profile_image_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.to_ascii_uppercase().contains("%USERPROFILE%") {
        return None;
    }
    let expanded_str = if trimmed.contains('%') {
        expand_env_strings(trimmed)?
    } else {
        trimmed.to_string()
    };
    if expanded_str.contains('%') {
        return None;
    }
    Some(PathBuf::from(expanded_str))
}

fn expand_env_strings(input: &str) -> Option<String> {
    let src_w = encode_wide_nul_str(input);
    let mut cap: u32 = 512;
    for _ in 0..2 {
        let mut dst = vec![0u16; cap as usize];
        // SAFETY: `src_w` is NUL-terminated UTF-16 and `dst` has `cap` writable `u16` elements.
        let required = unsafe { ExpandEnvironmentStringsW(src_w.as_ptr(), dst.as_mut_ptr(), cap) };
        if required == 0 {
            return None;
        }
        if required <= cap {
            let len = dst.iter().position(|&c| c == 0).unwrap_or(dst.len());
            return Some(String::from_utf16_lossy(&dst[..len]));
        }
        if required > 32_768 {
            return None;
        }
        cap = required;
    }
    None
}

fn reg_open_read_hklm(subkey: &str) -> Option<OwnedHkey> {
    reg_open_read_subkey(HKEY_LOCAL_MACHINE, subkey)
}

fn reg_open_read_subkey(parent: *mut c_void, subkey: &str) -> Option<OwnedHkey> {
    let subkey_w = encode_wide_nul_str(subkey);
    let mut handle: *mut c_void = std::ptr::null_mut();
    // SAFETY: `parent` is a valid HKEY and `subkey_w` is NUL-terminated UTF-16.
    let status = unsafe {
        RegOpenKeyExW(
            parent,
            subkey_w.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut handle,
        )
    };
    if status == ERROR_SUCCESS_U32 && !handle.is_null() {
        Some(OwnedHkey(handle))
    } else {
        None
    }
}

fn reg_enum_key_name(key: *mut c_void, index: u32) -> Option<String> {
    let mut buf = vec![0u16; 260];
    let mut len = buf.len() as u32;
    // SAFETY: `key` is an open registry key and `buf` holds `len` UTF-16 code units.
    let status = unsafe {
        RegEnumKeyExW(
            key,
            index,
            buf.as_mut_ptr(),
            &mut len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status == ERROR_NO_MORE_ITEMS_U32 || status != ERROR_SUCCESS_U32 {
        return None;
    }
    let used = usize::try_from(len).unwrap_or(0).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..used]))
}

fn reg_query_string_value(key: *mut c_void, value_name: &str) -> Option<String> {
    let name_w = encode_wide_nul_str(value_name);
    let mut val_type: u32 = 0;
    let mut byte_len: u32 = 1024;
    for _ in 0..2 {
        let mut buf = vec![0u8; byte_len as usize];
        let mut actual = byte_len;
        // SAFETY: `key` is open and `buf` holds `actual` writable bytes.
        let status = unsafe {
            RegQueryValueExW(
                key,
                name_w.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr(),
                &mut actual,
            )
        };
        if status == ERROR_MORE_DATA_U32 && actual > byte_len && actual <= 65_536 {
            byte_len = actual;
            continue;
        }
        if status != ERROR_SUCCESS_U32 {
            return None;
        }
        if val_type != REG_SZ && val_type != REG_EXPAND_SZ {
            return None;
        }
        let used_bytes = usize::try_from(actual).unwrap_or(0).min(buf.len());
        let units: Vec<u16> = buf[..used_bytes]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let str_len = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        return Some(String::from_utf16_lossy(&units[..str_len]));
    }
    None
}

fn encode_wide_nul_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn encode_wide_nul(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: Handle was returned by `WTSQueryUserToken` and is closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct WtsMemoryGuard(*mut c_void);

impl Drop for WtsMemoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Buffer was allocated by `WTSEnumerateSessionsW`.
            unsafe {
                WTSFreeMemory(self.0);
            }
        }
    }
}

struct LocalAllocGuard(*mut c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Buffer was allocated by `ConvertSidToStringSidW`.
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct OwnedHkey(*mut c_void);

impl Drop for OwnedHkey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Handle was opened by `RegOpenKeyExW`.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

#[link(name = "userenv.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn GetUserProfileDirectoryW(
        h_token: *mut c_void,
        lp_profile_dir: *mut u16,
        lpcch_size: *mut u32,
    ) -> i32;
}

#[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn RegOpenKeyExW(
        h_key: *mut c_void,
        lp_sub_key: *const u16,
        ul_options: u32,
        sam_desired: u32,
        phk_result: *mut *mut c_void,
    ) -> u32;
    fn RegEnumKeyExW(
        h_key: *mut c_void,
        dw_index: u32,
        lp_name: *mut u16,
        lpcch_name: *mut u32,
        lp_reserved: *mut u32,
        lp_class: *mut u16,
        lpcch_class: *mut u32,
        lpft_last_write_time: *mut c_void,
    ) -> u32;
    fn RegQueryValueExW(
        h_key: *mut c_void,
        lp_value_name: *const u16,
        lp_reserved: *mut u32,
        lp_type: *mut u32,
        lp_data: *mut u8,
        lpcb_data: *mut u32,
    ) -> u32;
    fn RegCloseKey(h_key: *mut c_void) -> u32;
}

#[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn ExpandEnvironmentStringsW(lp_src: *const u16, lp_dst: *mut u16, n_size: u32) -> u32;
    fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempHoneypotDir(PathBuf);

    impl TempHoneypotDir {
        fn new(label: &str) -> Self {
            let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "ledr-honeypot-unit-{label}-{}-{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp honeypot dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempHoneypotDir {
        fn drop(&mut self) {
            // Clear HIDDEN|SYSTEM attributes if needed and remove junctions cleanly before remove_dir_all.
            fn clear_attrs_recursive(dir: &Path) {
                let Ok(entries) = std::fs::read_dir(dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Ok(meta) = std::fs::symlink_metadata(&p) {
                        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
                            let _ = std::fs::remove_dir(&p);
                            continue;
                        }
                        if meta.is_dir() {
                            clear_attrs_recursive(&p);
                        } else {
                            let wide = encode_wide_nul(p.as_os_str());
                            let _ = unsafe {
                                SetFileAttributesW(
                                    PCWSTR(wide.as_ptr()),
                                    FILE_FLAGS_AND_ATTRIBUTES(0x80), // FILE_ATTRIBUTE_NORMAL
                                )
                            };
                        }
                    }
                }
            }
            clear_attrs_recursive(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn create_ntfs_junction(junction: &Path, target: &Path) {
        let out = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &junction.to_string_lossy(),
                &target.to_string_lossy(),
            ])
            .output()
            .expect("invoke cmd /C mklink /J");
        assert!(
            out.status.success(),
            "mklink /J {} -> {} failed: stdout={} stderr={}",
            junction.display(),
            target.display(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn honeypot_p4_srv_01_system_sid_filtering_and_dedup() {
        assert!(is_excluded_profile_sid("S-1-5-18"));
        assert!(is_excluded_profile_sid("s-1-5-19"));
        assert!(is_excluded_profile_sid("S-1-5-20"));
        assert!(is_excluded_profile_sid(".DEFAULT"));
        assert!(is_excluded_profile_sid("S-1-5-80-12345"));
        assert!(!is_excluded_profile_sid("S-1-5-21-123456-789-1001"));
        assert!(!is_excluded_profile_sid("S-1-12-1-123456-789-1001"));

        let filtered = filter_profile_entries([
            (
                "S-1-5-18".to_string(),
                PathBuf::from(r"C:\Windows\system32\config\systemprofile"),
            ),
            (
                "S-1-5-19".to_string(),
                PathBuf::from(r"C:\Windows\ServiceProfiles\LocalService"),
            ),
            (
                "S-1-5-20".to_string(),
                PathBuf::from(r"C:\Windows\ServiceProfiles\NetworkService"),
            ),
            (
                "S-1-5-21-100-1001".to_string(),
                PathBuf::from(r"C:\Users\Alice"),
            ),
            (
                "S-1-5-21-100-1001".to_string(),
                PathBuf::from(r"c:\users\alice\"),
            ),
            (
                "S-1-12-1-200-1002".to_string(),
                PathBuf::from(r"C:\Users\Bob"),
            ),
            (
                "S-1-5-21-100-1003".to_string(),
                PathBuf::from(r"\\fileserver\profiles\Carol"),
            ),
        ]);
        assert_eq!(
            filtered,
            vec![
                PathBuf::from(r"C:\Users\Alice"),
                PathBuf::from(r"C:\Users\Bob"),
            ]
        );
        assert!(expand_profile_image_path(r"%USERPROFILE%\Evil").is_none());
    }

    #[test]
    fn honeypot_p4_srv_02_multi_profile_deployment_and_refresh() {
        let tmp = TempHoneypotDir::new("multi");
        let user_a = tmp.path().join("Alice");
        let user_b = tmp.path().join("Bob");
        let user_missing = tmp.path().join("Ghost");

        std::fs::create_dir_all(user_a.join("Documents")).unwrap();
        std::fs::create_dir_all(user_a.join("Desktop")).unwrap();
        // user_a intentionally has no Pictures folder yet.
        std::fs::create_dir_all(user_b.join("Documents")).unwrap();
        std::fs::create_dir_all(user_b.join("Pictures")).unwrap();

        let mut mgr = HoneypotManager::for_user_profiles(vec![
            user_a.clone(),
            user_b.clone(),
            user_missing.clone(),
        ]);
        assert_eq!(mgr.roots().len(), 4);
        assert!(!user_a.join("Pictures").exists());
        assert!(!user_b.join("Desktop").exists());
        assert!(!user_missing.exists());

        let deployed = mgr.deploy_honeypots().expect("deploy multi-profile");
        assert_eq!(deployed.len(), 4);
        assert!(!user_a.join("Pictures").exists(), "must never create missing roots");
        assert!(!user_missing.exists(), "must never create missing profile dir");

        for path in &deployed {
            let meta = std::fs::symlink_metadata(path).expect("honeypot metadata");
            let attrs = meta.file_attributes();
            assert_ne!(attrs & FILE_ATTRIBUTE_HIDDEN.0, 0, "expected HIDDEN on {}", path.display());
            assert_ne!(attrs & FILE_ATTRIBUTE_SYSTEM.0, 0, "expected SYSTEM on {}", path.display());
            assert_eq!(attrs & FILE_ATTRIBUTE_READONLY.0, 0, "must NOT set READONLY on {}", path.display());
            // Verify standard write open succeeds (inherited folder ACLs, not locked down).
            let f = OpenOptions::new().append(true).open(path).expect("append honeypot");
            drop(f);
        }

        let before_refresh = mgr.deployed_paths().to_vec();
        let changed_same = mgr
            .refresh_user_profiles(vec![user_a.clone(), user_b.clone()])
            .expect("idempotent refresh");
        assert!(!changed_same, "unchanged profiles must report changed = false");
        assert!(HoneypotManager::path_sets_equal(
            &before_refresh,
            mgr.deployed_paths()
        ));

        // Simulate a user creating/provisioning Pictures after service startup.
        std::fs::create_dir_all(user_a.join("Pictures")).unwrap();
        let changed_new = mgr
            .refresh_user_profiles(vec![user_a.clone(), user_b.clone()])
            .expect("refresh after new folder");
        assert!(changed_new, "newly discovered root must report changed = true");
        assert_eq!(mgr.deployed_paths().len(), 5);
        assert!(!HoneypotManager::path_sets_equal(
            &before_refresh,
            mgr.deployed_paths()
        ));

        let mut reversed = mgr.deployed_paths().to_vec();
        reversed.reverse();
        assert!(HoneypotManager::path_sets_equal(&reversed, mgr.deployed_paths()));
    }

    #[test]
    fn honeypot_p4_srv_03_reparse_point_rejected_on_profile_root_and_subdir() {
        let tmp = TempHoneypotDir::new("reparse");
        let victim_target = tmp.path().join("SystemTarget");
        std::fs::create_dir_all(victim_target.join("Documents")).unwrap();

        // Case 1: Profile root itself is a junction pointing to SystemTarget.
        let evil_profile_junction = tmp.path().join("EvilProfileJunction");
        create_ntfs_junction(&evil_profile_junction, &victim_target);

        // Case 2: Profile root is normal, but Documents is a junction pointing to SystemTarget.
        let mixed_profile = tmp.path().join("MixedUser");
        std::fs::create_dir_all(mixed_profile.join("Desktop")).unwrap();
        create_ntfs_junction(&mixed_profile.join("Documents"), &victim_target);

        let mut mgr = HoneypotManager::for_user_profiles(vec![
            evil_profile_junction.clone(),
            mixed_profile.clone(),
        ]);
        assert_eq!(
            mgr.roots(),
            &[mixed_profile.join("Desktop")],
            "reparse profile root and reparse Documents subdir must both be excluded"
        );

        let deployed = mgr.deploy_honeypots().expect("deploy safe roots only");
        assert_eq!(deployed, vec![mixed_profile.join("Desktop").join(HONEYPOT_DEFAULT_FILENAME)]);
        assert!(
            !victim_target.join(HONEYPOT_DEFAULT_FILENAME).exists(),
            "honeypot must NEVER be written through Documents junction"
        );
        assert!(
            !victim_target
                .join("Documents")
                .join(HONEYPOT_DEFAULT_FILENAME)
                .exists(),
            "honeypot must NEVER be written through profile root junction"
        );

        // Case 3: Target path itself is a directory/junction inside a valid root -> rejected without writing.
        let decoy_junction = mixed_profile.join("Desktop").join("decoy_dir_target");
        std::fs::create_dir_all(&decoy_junction).unwrap();
        let normal_profile = tmp.path().join("NormalWithBadTarget");
        std::fs::create_dir_all(normal_profile.join("Documents")).unwrap();
        create_ntfs_junction(
            &normal_profile.join("Documents").join(HONEYPOT_DEFAULT_FILENAME),
            &victim_target,
        );
        let mut mgr2 = HoneypotManager::for_user_profiles(vec![normal_profile]);
        let err = mgr2
            .deploy_honeypots()
            .expect_err("reparse target at decoy filename must be rejected");
        assert!(
            err.to_string().contains("reparse point"),
            "unexpected error for reparse target: {err}"
        );
    }

    #[test]
    fn honeypot_p4_srv_04_service_discovery_excludes_system_profiles() {
        let profiles = discover_service_user_profiles();
        for profile in &profiles {
            let lower = profile.to_string_lossy().to_ascii_lowercase();
            assert!(
                !lower.contains(r"\system32\config\systemprofile")
                    && !lower.contains(r"\serviceprofiles\localservice")
                    && !lower.contains(r"\serviceprofiles\networkservice"),
                "system profile leaked into service discovery: {}",
                profile.display()
            );
        }
        let mgr = HoneypotManager::for_service();
        for root in mgr.roots() {
            assert!(
                is_safe_existing_directory(root),
                "discovered root must exist and not be a reparse point: {}",
                root.display()
            );
        }
    }
}
