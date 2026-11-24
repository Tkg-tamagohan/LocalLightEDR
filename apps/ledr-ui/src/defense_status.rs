#[cfg(windows)]
use crate::uri_reg::{
    LEDR_URI_REG_SUBKEY, RegDefaultSzProbe, RegNativeHostSzProbe, RegWow64View, win_uri_reg,
};
use ledr_proto::{AUTHORIZED_BRIDGE_EXE_PATH, PROGRAM_DATA_DIR};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    EmptyString,
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
    pub(crate) manifest_status: String,
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
    pub(crate) manifest_status: String,
    pub(crate) manifest_error: Option<String>,
    pub(crate) uri_scheme_scope: Option<String>,
    pub(crate) expected_extension_id: String,
    pub(crate) browsers: Vec<BrowserRegistrationDetail>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManifestReadError {
    UnverifiedCustomPath(String),
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManifestValidationOutcome {
    Valid,
    UnverifiedCustomPath(String),
    Invalid(String),
}

pub(crate) const MANIFEST_STATUS_VALID: &str = "valid";
pub(crate) const MANIFEST_STATUS_UNVERIFIED: &str = "unverified";
pub(crate) const MANIFEST_STATUS_INVALID: &str = "invalid";
pub(crate) const MANIFEST_STATUS_NOT_REGISTERED: &str = "not_registered";

const UNVERIFIED_CUSTOM_MANIFEST_MSG: &str = "manifest path is outside default LocalEDR manifest directories (unverified by UI; inspect the listed manifest file directly or run 'ledr-bridge-nm status')";

fn is_custom_localedr_manifest_filename(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    lower.starts_with("com.localedr.bridge") && lower.ends_with(".json")
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
    #[serde(rename = "description")]
    _description: String,
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

/// Returns the allowlisted default LocalEDR Native Messaging manifest directories
/// (`%LOCALAPPDATA%\LocalEDR\native-messaging` and `C:\ProgramData\LocalEDR\native-messaging`).
pub(crate) fn default_allowed_manifest_dirs_from(
    local_app_data: Option<&Path>,
    program_data_dir: &Path,
) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(2);
    if let Some(local) = local_app_data {
        dirs.push(local.join("LocalEDR").join("native-messaging"));
    }
    dirs.push(program_data_dir.join("native-messaging"));
    dirs
}

/// Resolves the production allowlist of LocalEDR Native Messaging manifest directories.
pub(crate) fn default_allowed_manifest_dirs() -> Vec<PathBuf> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    default_allowed_manifest_dirs_from(local_app_data.as_deref(), Path::new(PROGRAM_DATA_DIR))
}

#[cfg(windows)]
mod win_manifest_io {
    use super::{
        MAX_MANIFEST_BYTES, ManifestReadError, UNVERIFIED_CUSTOM_MANIFEST_MSG,
        is_custom_localedr_manifest_filename,
    };
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::{ErrorKind, Read};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr;

    const INVALID_HANDLE_VALUE: isize = -1;
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_TYPE_DISK: u32 = 0x0001;
    const VOLUME_NAME_DOS: u32 = 0x0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: FileTime,
        ft_last_access_time: FileTime,
        ft_last_write_time: FileTime,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn GetLongPathNameW(
            lpsz_short_path: *const u16,
            lpsz_long_path: *mut u16,
            cch_buffer: u32,
        ) -> u32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *const c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> *mut c_void;
        fn ReOpenFile(
            h_original_file: *mut c_void,
            dw_desired_access: u32,
            dw_share_mode: u32,
            dw_flags_and_attributes: u32,
        ) -> *mut c_void;
        fn GetFileType(h_file: *mut c_void) -> u32;
        fn GetFileInformationByHandle(
            h_file: *mut c_void,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            h_file: *mut c_void,
            lpsz_file_path: *mut u16,
            cch_file_path: u32,
            dw_flags: u32,
        ) -> u32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
    }

    struct OwnedHandle(*mut c_void);

    impl OwnedHandle {
        fn into_raw(mut self) -> *mut c_void {
            let raw = self.0;
            self.0 = ptr::null_mut();
            raw
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is an owned Win32 HANDLE obtained from `CreateFileW` or `ReOpenFile`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn encode_wide_nul(path: &Path) -> Option<Vec<u16>> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return None;
        }
        wide.push(0);
        Some(wide)
    }

    /// Parses a strict local drive-letter absolute path (`X:\...` or `\\?\X:\...`) without
    /// touching the filesystem. Rejects UNC, device, volume GUID, relative, `..`, `.`,
    /// Alternate Data Streams (`:`), and Win32 trailing-dot/space components.
    pub(super) fn parse_strict_local_drive_path(path: &Path) -> Option<(char, Vec<String>)> {
        let raw = path.to_str()?;
        if raw.is_empty() || raw.contains('\0') {
            return None;
        }

        let rest = if let Some(verbatim) = raw.strip_prefix(r"\\?\") {
            // Reject `\\?\UNC\...` and `\\?\Volume{...}\...`.
            let bytes = verbatim.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_alphabetic()
                || bytes[1] != b':'
                || bytes[2] != b'\\'
            {
                return None;
            }
            verbatim
        } else if raw.starts_with(r"\\") || raw.starts_with("//") {
            // Reject UNC (`\\server\share`) and Win32 device (`\\.\...`) paths.
            return None;
        } else {
            raw
        };

        let bytes = rest.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || (bytes[2] != b'\\' && bytes[2] != b'/')
        {
            return None;
        }
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let tail = &rest[3..];
        let mut segments = Vec::new();
        for seg in tail.split(['\\', '/']) {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." {
                return None;
            }
            if seg.contains(':') || seg.ends_with('.') || seg.ends_with(' ') {
                return None;
            }
            segments.push(seg.to_string());
        }
        Some((drive, segments))
    }

    fn build_verbatim_drive_path(drive: char, segments: &[String]) -> PathBuf {
        let mut s = format!(r"\\?\{}:\", drive.to_ascii_uppercase());
        for (i, seg) in segments.iter().enumerate() {
            if i > 0 {
                s.push('\\');
            }
            s.push_str(seg);
        }
        PathBuf::from(s)
    }

    fn query_long_path(verbatim_path: &Path) -> Option<PathBuf> {
        let wide = encode_wide_nul(verbatim_path)?;
        let mut cap: usize = 512;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `wide` is NUL-terminated UTF-16 and `buf` holds `cap` writable `u16` elements.
            let ret = unsafe {
                GetLongPathNameW(
                    wide.as_ptr(),
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                )
            };
            if ret == 0 {
                return None;
            }
            let len = ret as usize;
            if len < buf.len() {
                return String::from_utf16(&buf[..len]).ok().map(PathBuf::from);
            }
            if len < 32_768 {
                cap = len.saturating_add(1);
                continue;
            }
            return None;
        }
        None
    }

    fn query_final_path_dos(handle: *mut c_void) -> Option<PathBuf> {
        let mut cap: usize = 512;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `handle` is an open file handle and `buf` holds `cap` writable `u16` elements.
            let ret = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    VOLUME_NAME_DOS,
                )
            };
            if ret == 0 {
                return None;
            }
            let len = ret as usize;
            if len < buf.len() {
                return String::from_utf16(&buf[..len]).ok().map(PathBuf::from);
            }
            if len < 32_768 {
                cap = len.saturating_add(1);
                continue;
            }
            return None;
        }
        None
    }

    fn segment_eq_case_insensitive(a: &str, b: &str) -> bool {
        if a.is_ascii() && b.is_ascii() {
            a.eq_ignore_ascii_case(b)
        } else {
            a.to_lowercase() == b.to_lowercase()
        }
    }

    fn expand_long_segments(drive: char, segments: &[String]) -> Option<(char, Vec<String>)> {
        let verbatim = build_verbatim_drive_path(drive, segments);
        if let Some(long_path) = query_long_path(&verbatim) {
            if let Some((ld, lsegs)) = parse_strict_local_drive_path(&long_path) {
                if !lsegs.is_empty() {
                    return Some((ld, lsegs));
                }
            }
        }
        // When the leaf directory (e.g. `LocalEDR\native-messaging`) does not yet exist on disk,
        // expand the longest existing ancestor prefix so 8.3 usernames still match long paths.
        for prefix_len in (1..segments.len()).rev() {
            let prefix_verbatim = build_verbatim_drive_path(drive, &segments[..prefix_len]);
            if let Some(long_prefix) = query_long_path(&prefix_verbatim) {
                if let Some((ld, mut lsegs)) = parse_strict_local_drive_path(&long_prefix) {
                    if !lsegs.is_empty() {
                        lsegs.extend(segments[prefix_len..].iter().cloned());
                        return Some((ld, lsegs));
                    }
                }
            }
        }
        None
    }

    fn expand_allowed_dirs(allowed_dirs: &[PathBuf]) -> Vec<(char, Vec<String>)> {
        let mut out: Vec<(char, Vec<String>)> = Vec::new();
        for dir in allowed_dirs {
            let Some((drive, segments)) = parse_strict_local_drive_path(dir) else {
                continue;
            };
            if segments.is_empty() {
                continue;
            }
            let push_unique = |list: &mut Vec<(char, Vec<String>)>, d: char, segs: Vec<String>| {
                let exists = list.iter().any(|(ed, es)| {
                    *ed == d
                        && es.len() == segs.len()
                        && es
                            .iter()
                            .zip(&segs)
                            .all(|(a, b)| segment_eq_case_insensitive(a, b))
                });
                if !exists {
                    list.push((d, segs));
                }
            };
            let long_expanded = expand_long_segments(drive, &segments);
            push_unique(&mut out, drive, segments);
            if let Some((ld, lsegs)) = long_expanded {
                push_unique(&mut out, ld, lsegs);
            }
        }
        out
    }

    fn is_direct_child_of_allowed(
        drive: char,
        segments: &[String],
        allowed: &[(char, Vec<String>)],
    ) -> bool {
        if segments.len() < 2 {
            return false;
        }
        let parent = &segments[..segments.len() - 1];
        allowed.iter().any(|(ad, aseg)| {
            *ad == drive
                && parent.len() == aseg.len()
                && parent
                    .iter()
                    .zip(aseg)
                    .all(|(a, b)| segment_eq_case_insensitive(a, b))
        })
    }

    fn is_not_found_os_err(err: &std::io::Error) -> bool {
        err.kind() == ErrorKind::NotFound
            || matches!(
                err.raw_os_error(),
                Some(ERROR_FILE_NOT_FOUND) | Some(ERROR_PATH_NOT_FOUND)
            )
    }

    /// Reads manifest bytes strictly inside `allowed_dirs` while guaranteeing zero data-read
    /// access to out-of-scope files, reparse points (junctions/symlinks on leaf or any parent),
    /// directories, non-disk devices, or hard links (`nNumberOfLinks != 1`).
    pub(super) fn safe_read_manifest_bytes(
        path: &Path,
        allowed_dirs: &[PathBuf],
    ) -> Result<Vec<u8>, ManifestReadError> {
        // Step 1: Pure syntactic allowlist verification before touching the untrusted path.
        if path
            .to_str()
            .is_some_and(|s| s.ends_with('\\') || s.ends_with('/'))
        {
            return Err(ManifestReadError::Invalid(
                "manifest path is not a regular file".to_string(),
            ));
        }
        let allowed_candidates = expand_allowed_dirs(allowed_dirs);
        let Some((drive, segments)) = parse_strict_local_drive_path(path) else {
            return Err(ManifestReadError::Invalid(
                "manifest path is outside allowed LocalEDR manifest directories".to_string(),
            ));
        };
        if !is_direct_child_of_allowed(drive, &segments, &allowed_candidates) {
            // Preserve zero I/O outside allowlisted directories while distinguishing a clean
            // custom `--manifest-dir` LocalEDR manifest filename from unsafe/arbitrary paths.
            if segments.len() >= 2
                && segments
                    .last()
                    .is_some_and(|leaf| is_custom_localedr_manifest_filename(leaf))
            {
                return Err(ManifestReadError::UnverifiedCustomPath(
                    UNVERIFIED_CUSTOM_MANIFEST_MSG.to_string(),
                ));
            }
            return Err(ManifestReadError::Invalid(
                "manifest path is outside allowed LocalEDR manifest directories".to_string(),
            ));
        }

        // Step 2: Walk every ancestor component and the leaf via verbatim `\\?\` `GetFileAttributesW`
        // (no reparse traversal), rejecting any reparse point or directory leaf.
        for prefix_len in 1..=segments.len() {
            let current = build_verbatim_drive_path(drive, &segments[..prefix_len]);
            let Some(wide) = encode_wide_nul(&current) else {
                return Err(ManifestReadError::Invalid(
                    "manifest path contains invalid characters".to_string(),
                ));
            };
            // SAFETY: `wide` is NUL-terminated UTF-16; `GetFileAttributesW` inspects the
            // component itself without traversing a trailing reparse point.
            let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
            if attrs == INVALID_FILE_ATTRIBUTES {
                let err = std::io::Error::last_os_error();
                if is_not_found_os_err(&err) {
                    return Err(ManifestReadError::Invalid(
                        "manifest file does not exist".to_string(),
                    ));
                }
                return Err(ManifestReadError::Invalid(format!(
                    "failed to stat manifest: {err}"
                )));
            }
            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return Err(ManifestReadError::Invalid(
                    "manifest path or parent directory is a reparse point (rejected)".to_string(),
                ));
            }
            if prefix_len == segments.len() && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                return Err(ManifestReadError::Invalid(
                    "manifest path is not a regular file".to_string(),
                ));
            }
        }

        // Step 3: Attribute-only handle inspection (`FILE_READ_ATTRIBUTES` +
        // `FILE_FLAG_OPEN_REPARSE_POINT`) — never requests data read access before proving
        // `FILE_TYPE_DISK`, non-reparse, regular file, `nNumberOfLinks == 1`, bounded size,
        // and final kernel path containment inside `allowed_dirs`.
        let leaf_verbatim = build_verbatim_drive_path(drive, &segments);
        let Some(leaf_wide) = encode_wide_nul(&leaf_verbatim) else {
            return Err(ManifestReadError::Invalid(
                "manifest path contains invalid characters".to_string(),
            ));
        };
        let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        // SAFETY: `leaf_wide` is NUL-terminated UTF-16; attribute-only access with
        // `FILE_FLAG_OPEN_REPARSE_POINT` does not follow symlinks or read file contents.
        let attr_raw = unsafe {
            CreateFileW(
                leaf_wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                share_all,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if attr_raw.is_null() || attr_raw as isize == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            if is_not_found_os_err(&err) {
                return Err(ManifestReadError::Invalid(
                    "manifest file does not exist".to_string(),
                ));
            }
            return Err(ManifestReadError::Invalid(format!(
                "failed to inspect manifest attributes: {err}"
            )));
        }
        let attr_handle = OwnedHandle(attr_raw);

        // SAFETY: `attr_handle.0` is an open Win32 file handle.
        let file_type = unsafe { GetFileType(attr_handle.0) };
        if file_type != FILE_TYPE_DISK {
            return Err(ManifestReadError::Invalid(
                "manifest path is not a regular file".to_string(),
            ));
        }

        let mut info = ByHandleFileInformation::default();
        // SAFETY: `attr_handle.0` is an open Win32 file handle and `info` is valid out storage.
        if unsafe { GetFileInformationByHandle(attr_handle.0, &mut info) } == 0 {
            let err = std::io::Error::last_os_error();
            return Err(ManifestReadError::Invalid(format!(
                "failed to query manifest file info: {err}"
            )));
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(ManifestReadError::Invalid(
                "manifest path is a reparse point (rejected)".to_string(),
            ));
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(ManifestReadError::Invalid(
                "manifest path is not a regular file".to_string(),
            ));
        }
        if info.n_number_of_links != 1 {
            return Err(ManifestReadError::Invalid(format!(
                "manifest file has {} hard links (expected 1; rejected)",
                info.n_number_of_links
            )));
        }
        let initial_size = (u64::from(info.n_file_size_high) << 32) | u64::from(info.n_file_size_low);
        if initial_size > MAX_MANIFEST_BYTES {
            return Err(ManifestReadError::Invalid(
                "manifest exceeds 64 KiB limit".to_string(),
            ));
        }

        let Some(final_path) = query_final_path_dos(attr_handle.0) else {
            return Err(ManifestReadError::Invalid(
                "failed to verify manifest final path".to_string(),
            ));
        };
        let Some((final_drive, final_segments)) = parse_strict_local_drive_path(&final_path) else {
            return Err(ManifestReadError::Invalid(
                "manifest final path escaped allowed LocalEDR manifest directories".to_string(),
            ));
        };
        if !is_direct_child_of_allowed(final_drive, &final_segments, &allowed_candidates) {
            return Err(ManifestReadError::Invalid(
                "manifest final path escaped allowed LocalEDR manifest directories".to_string(),
            ));
        }

        // Step 4: Upgrade the exact verified kernel file object via `ReOpenFile` (no path
        // re-resolution / TOCTOU), re-verify identity + `nNumberOfLinks == 1`, then read bounded bytes.
        // SAFETY: `attr_handle.0` is an open verified disk file handle.
        let read_raw = unsafe {
            ReOpenFile(
                attr_handle.0,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                share_all,
                0,
            )
        };
        if read_raw.is_null() || read_raw as isize == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(ManifestReadError::Invalid(format!(
                "failed to open manifest: {err}"
            )));
        }
        let read_handle = OwnedHandle(read_raw);

        let mut info2 = ByHandleFileInformation::default();
        // SAFETY: `read_handle.0` is an open Win32 file handle and `info2` is valid out storage.
        if unsafe { GetFileInformationByHandle(read_handle.0, &mut info2) } == 0 {
            let err = std::io::Error::last_os_error();
            return Err(ManifestReadError::Invalid(format!(
                "failed to stat manifest: {err}"
            )));
        }
        if (info2.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(ManifestReadError::Invalid(
                "manifest path is a reparse point (rejected)".to_string(),
            ));
        }
        if (info2.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(ManifestReadError::Invalid(
                "manifest path is not a regular file".to_string(),
            ));
        }
        if info2.n_number_of_links != 1 {
            return Err(ManifestReadError::Invalid(format!(
                "manifest file has {} hard links (expected 1; rejected)",
                info2.n_number_of_links
            )));
        }
        if info2.dw_volume_serial_number != info.dw_volume_serial_number
            || info2.n_file_index_high != info.n_file_index_high
            || info2.n_file_index_low != info.n_file_index_low
        {
            return Err(ManifestReadError::Invalid(
                "manifest file identity changed during open (rejected)".to_string(),
            ));
        }

        // SAFETY: `read_handle.into_raw()` transfers unique ownership of a valid Win32 file handle.
        let file = unsafe { File::from_raw_handle(read_handle.into_raw()) };
        drop(attr_handle);

        let mut buf = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|err| ManifestReadError::Invalid(format!("failed to read manifest: {err}")))?;
        if buf.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(ManifestReadError::Invalid(
                "manifest exceeds 64 KiB limit".to_string(),
            ));
        }
        Ok(buf)
    }
}

#[cfg(not(windows))]
fn safe_read_manifest_bytes(
    path: &Path,
    allowed_dirs: &[PathBuf],
) -> Result<Vec<u8>, ManifestReadError> {
    use std::io::Read;
    use std::path::Component;

    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(ManifestReadError::Invalid(
            "manifest path is outside allowed LocalEDR manifest directories".to_string(),
        ));
    }
    let Some(parent) = path.parent() else {
        return Err(ManifestReadError::Invalid(
            "manifest path is outside allowed LocalEDR manifest directories".to_string(),
        ));
    };
    if !allowed_dirs.iter().any(|dir| dir == parent) {
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(is_custom_localedr_manifest_filename)
        {
            return Err(ManifestReadError::UnverifiedCustomPath(
                UNVERIFIED_CUSTOM_MANIFEST_MSG.to_string(),
            ));
        }
        return Err(ManifestReadError::Invalid(
            "manifest path is outside allowed LocalEDR manifest directories".to_string(),
        ));
    }

    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        let meta = std::fs::symlink_metadata(&cur).map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                ManifestReadError::Invalid("manifest file does not exist".to_string())
            } else {
                ManifestReadError::Invalid(format!("failed to stat manifest: {err}"))
            }
        })?;
        if meta.file_type().is_symlink() {
            return Err(ManifestReadError::Invalid(
                "manifest path or parent directory is a symlink (rejected)".to_string(),
            ));
        }
    }

    let leaf_meta = std::fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ManifestReadError::Invalid("manifest file does not exist".to_string())
        } else {
            ManifestReadError::Invalid(format!("failed to stat manifest: {err}"))
        }
    })?;
    if !leaf_meta.is_file() {
        return Err(ManifestReadError::Invalid(
            "manifest path is not a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if leaf_meta.nlink() != 1 {
            return Err(ManifestReadError::Invalid(format!(
                "manifest file has {} hard links (expected 1; rejected)",
                leaf_meta.nlink()
            )));
        }
    }
    if leaf_meta.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestReadError::Invalid(
            "manifest exceeds 64 KiB limit".to_string(),
        ));
    }

    let file = std::fs::File::open(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            ManifestReadError::Invalid("manifest file does not exist".to_string())
        } else {
            ManifestReadError::Invalid(format!("failed to open manifest: {err}"))
        }
    })?;
    let meta = file
        .metadata()
        .map_err(|err| ManifestReadError::Invalid(format!("failed to stat manifest: {err}")))?;
    if !meta.is_file() {
        return Err(ManifestReadError::Invalid(
            "manifest path is not a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(ManifestReadError::Invalid(format!(
                "manifest file has {} hard links (expected 1; rejected)",
                meta.nlink()
            )));
        }
        if meta.dev() != leaf_meta.dev() || meta.ino() != leaf_meta.ino() {
            return Err(ManifestReadError::Invalid(
                "manifest file identity changed during open (rejected)".to_string(),
            ));
        }
    }
    let mut buf = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|err| ManifestReadError::Invalid(format!("failed to read manifest: {err}")))?;
    if buf.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(ManifestReadError::Invalid(
            "manifest exceeds 64 KiB limit".to_string(),
        ));
    }
    Ok(buf)
}

#[cfg(windows)]
fn is_safe_bridge_exe_candidate(path: &Path) -> bool {
    let Some((_, segments)) = win_manifest_io::parse_strict_local_drive_path(path) else {
        return false;
    };
    segments
        .last()
        .is_some_and(|leaf| leaf.to_ascii_lowercase().ends_with(".exe"))
}

#[cfg(not(windows))]
fn is_safe_bridge_exe_candidate(path: &Path) -> bool {
    use std::path::Component;
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
}

#[cfg(windows)]
fn safe_read_manifest_bytes(
    path: &Path,
    allowed_dirs: &[PathBuf],
) -> Result<Vec<u8>, ManifestReadError> {
    win_manifest_io::safe_read_manifest_bytes(path, allowed_dirs)
}

/// Classifies an on-disk Native Messaging Host manifest strictly within `allowed_dirs`
/// without trusting out-of-scope paths, reparse points, hard links, oversized, or malformed files.
pub(crate) fn classify_manifest_file_in_allowed_dirs(
    path: &Path,
    expected_extension_id: &str,
    allowed_dirs: &[PathBuf],
) -> ManifestValidationOutcome {
    let buf = match safe_read_manifest_bytes(path, allowed_dirs) {
        Ok(b) => b,
        Err(ManifestReadError::UnverifiedCustomPath(msg)) => {
            return ManifestValidationOutcome::UnverifiedCustomPath(msg);
        }
        Err(ManifestReadError::Invalid(msg)) => {
            return ManifestValidationOutcome::Invalid(msg);
        }
    };

    let parsed: NativeMessagingManifestDoc = match serde_json::from_slice(&buf) {
        Ok(p) => p,
        Err(err) => {
            return ManifestValidationOutcome::Invalid(format!("invalid manifest JSON: {err}"));
        }
    };

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
        } else if !is_safe_bridge_exe_candidate(exe_path) {
            problems.push(format!(
                "manifest 'path' must reference a local .exe executable: '{exe_trimmed}'"
            ));
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
        ManifestValidationOutcome::Valid
    } else {
        ManifestValidationOutcome::Invalid(problems.join("; "))
    }
}

/// Validates an on-disk Native Messaging Host manifest strictly within `allowed_dirs`
/// without trusting out-of-scope paths, reparse points, hard links, oversized, or malformed files.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_manifest_file_in_allowed_dirs(
    path: &Path,
    expected_extension_id: &str,
    allowed_dirs: &[PathBuf],
) -> Result<(), String> {
    match classify_manifest_file_in_allowed_dirs(path, expected_extension_id, allowed_dirs) {
        ManifestValidationOutcome::Valid => Ok(()),
        ManifestValidationOutcome::UnverifiedCustomPath(msg)
        | ManifestValidationOutcome::Invalid(msg) => Err(msg),
    }
}

/// Validates an on-disk Native Messaging Host manifest strictly within the default
/// LocalEDR manifest directories (`%LOCALAPPDATA%\LocalEDR\native-messaging` and
/// `C:\ProgramData\LocalEDR\native-messaging`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_manifest_file(
    path: &Path,
    expected_extension_id: &str,
) -> Result<(), String> {
    validate_manifest_file_in_allowed_dirs(
        path,
        expected_extension_id,
        &default_allowed_manifest_dirs(),
    )
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
/// `ledr-bridge-nm.exe`, read-only `HKCU`/`HKLM` registry probes, and allowlisted validation of
/// Native Messaging Host manifest files inside `allowed_manifest_dirs`.
pub(crate) fn collect_local_defense_status_with_probe_in_allowed_dirs(
    user_profile: Option<&Path>,
    bridge_path: &Path,
    probe: &BrowserShieldProbe,
    allowed_manifest_dirs: &[PathBuf],
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

        let (manifest_path, manifest_valid, manifest_status, manifest_error) = match active_probe {
            None | Some(RegistryStringProbe::Absent) => {
                (None, false, MANIFEST_STATUS_NOT_REGISTERED.to_string(), None)
            }
            Some(RegistryStringProbe::Present(path_str)) => {
                match classify_manifest_file_in_allowed_dirs(
                    Path::new(path_str),
                    EXPECTED_CHROME_EXTENSION_ID,
                    allowed_manifest_dirs,
                ) {
                    ManifestValidationOutcome::Valid => {
                        (Some(path_str.clone()), true, MANIFEST_STATUS_VALID.to_string(), None)
                    }
                    ManifestValidationOutcome::UnverifiedCustomPath(note) => (
                        Some(path_str.clone()),
                        false,
                        MANIFEST_STATUS_UNVERIFIED.to_string(),
                        Some(note),
                    ),
                    ManifestValidationOutcome::Invalid(err) => (
                        Some(path_str.clone()),
                        false,
                        MANIFEST_STATUS_INVALID.to_string(),
                        Some(err),
                    ),
                }
            }
            Some(RegistryStringProbe::EmptyString) => (
                None,
                false,
                MANIFEST_STATUS_INVALID.to_string(),
                Some("registry default value is empty REG_SZ".to_string()),
            ),
            Some(RegistryStringProbe::EmptyOrInvalidType) => (
                None,
                false,
                MANIFEST_STATUS_INVALID.to_string(),
                Some("registry default value is empty or not REG_SZ".to_string()),
            ),
            Some(RegistryStringProbe::AccessError(err)) => (
                None,
                false,
                MANIFEST_STATUS_INVALID.to_string(),
                Some(err.clone()),
            ),
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
            manifest_status,
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
    let any_invalid = registered_details
        .iter()
        .any(|d| d.manifest_status == MANIFEST_STATUS_INVALID);

    let (manifest_path, manifest_valid, manifest_status, manifest_error) =
        if registered_details.is_empty() {
            (None, false, MANIFEST_STATUS_NOT_REGISTERED.to_string(), None)
        } else if all_valid {
            (
                registered_details
                    .first()
                    .and_then(|d| d.manifest_path.clone()),
                true,
                MANIFEST_STATUS_VALID.to_string(),
                None,
            )
        } else if any_invalid {
            let first_invalid = registered_details
                .iter()
                .find(|d| d.manifest_status == MANIFEST_STATUS_INVALID);
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
                MANIFEST_STATUS_INVALID.to_string(),
                (!errors.is_empty()).then(|| errors.join("; ")),
            )
        } else {
            let first_unverified = registered_details
                .iter()
                .find(|d| d.manifest_status == MANIFEST_STATUS_UNVERIFIED);
            let chosen_path = first_unverified
                .and_then(|d| d.manifest_path.clone())
                .or_else(|| registered_details.iter().find_map(|d| d.manifest_path.clone()));
            let notes: Vec<String> = registered_details
                .iter()
                .filter(|d| d.manifest_status == MANIFEST_STATUS_UNVERIFIED)
                .map(|d| {
                    format!(
                        "{}: {}",
                        d.browser,
                        d.manifest_error
                            .as_deref()
                            .unwrap_or(UNVERIFIED_CUSTOM_MANIFEST_MSG)
                    )
                })
                .collect();
            (
                chosen_path,
                false,
                MANIFEST_STATUS_UNVERIFIED.to_string(),
                (!notes.is_empty()).then(|| notes.join("; ")),
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
            manifest_status,
            manifest_error,
            uri_scheme_scope,
            expected_extension_id: EXPECTED_CHROME_EXTENSION_ID.to_string(),
            browsers: details,
        },
    }
}

/// Collects View 3 local defense status enforcing the default LocalEDR manifest directory allowlist.
pub(crate) fn collect_local_defense_status_with_probe(
    user_profile: Option<&Path>,
    bridge_path: &Path,
    probe: &BrowserShieldProbe,
) -> LocalDefenseStatus {
    collect_local_defense_status_with_probe_in_allowed_dirs(
        user_profile,
        bridge_path,
        probe,
        &default_allowed_manifest_dirs(),
    )
}

/// Selects the effective Native Messaging Host registry probe across WOW64 32-bit and 64-bit
/// views following Chromium's precedence (`KEY_WOW64_32KEY` first, then `KEY_WOW64_64KEY`).
///
/// Chromium stops at the 32-bit view whenever `RegKey::ReadValue(nullptr, &path)` returns
/// `ERROR_SUCCESS`, including when the `REG_SZ` value is empty (`EmptyString`). Only failed
/// reads (`Absent`, `EmptyOrInvalidType` for missing/non-`REG_SZ`, or `AccessError`) fall back
/// to the 64-bit view.
pub(crate) fn select_preferred_wow64_probe(
    view32: RegistryStringProbe,
    view64: RegistryStringProbe,
) -> RegistryStringProbe {
    match (&view32, &view64) {
        (RegistryStringProbe::Present(_) | RegistryStringProbe::EmptyString, _) => view32,
        (_, RegistryStringProbe::Present(_) | RegistryStringProbe::EmptyString) => view64,
        (RegistryStringProbe::Absent, _) => view64,
        (_, RegistryStringProbe::Absent) => view32,
        _ => view32,
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
fn probe_native_host_reg_string_with_view(
    is_hklm: bool,
    subkey: &str,
    view: RegWow64View,
) -> RegistryStringProbe {
    match win_uri_reg::reg_query_native_host_sz_in_hive_with_view(is_hklm, subkey, view) {
        Ok(RegNativeHostSzProbe::Absent) => RegistryStringProbe::Absent,
        Ok(RegNativeHostSzProbe::Present(val)) => RegistryStringProbe::Present(val),
        Ok(RegNativeHostSzProbe::EmptyString) => RegistryStringProbe::EmptyString,
        Ok(RegNativeHostSzProbe::MissingOrInvalidType) => RegistryStringProbe::EmptyOrInvalidType,
        Err(err) => RegistryStringProbe::AccessError(err),
    }
}

/// Probes a Native Messaging Host registry key in Chromium's lookup order:
/// 32-bit view (`KEY_WOW64_32KEY`) first, falling back to 64-bit view (`KEY_WOW64_64KEY`)
/// only when the 32-bit read does not yield a `REG_SZ` string (empty `REG_SZ` stops fallback).
#[cfg(windows)]
pub(crate) fn probe_native_host_reg_string(
    is_hklm: bool,
    subkey: &str,
) -> RegistryStringProbe {
    let view32 = probe_native_host_reg_string_with_view(is_hklm, subkey, RegWow64View::View32);
    if matches!(
        view32,
        RegistryStringProbe::Present(_) | RegistryStringProbe::EmptyString
    ) {
        return view32;
    }
    let view64 = probe_native_host_reg_string_with_view(is_hklm, subkey, RegWow64View::View64);
    select_preferred_wow64_probe(view32, view64)
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
        hkcu: probe_native_host_reg_string(false, subkey),
        hklm: probe_native_host_reg_string(true, subkey),
    })
    .collect();

    // URI protocol handler probe stays separate from Native Messaging WOW64 probing.
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
