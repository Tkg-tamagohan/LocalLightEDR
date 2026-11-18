//! Zero-allocation UTF-16 primary pre-filter, Folder Canary classifier (`L-05`),
//! honeypot write detector (`L-06`), and autorun registry key matcher (`AUTO-08`).

use std::path::Path;

use ledr_proto::{CanaryCategory, HONEYPOT_DEFAULT_FILENAME};

use crate::path_norm::{DosVolumeMap, starts_with_ignore_ascii_case_u16};

const fn ascii_u16<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut out = [0u16; N];
    let mut i = 0;
    while i < N {
        out[i] = bytes[i] as u16;
        i += 1;
    }
    out
}

const HONEYPOT_BYTES: &[u8] = HONEYPOT_DEFAULT_FILENAME.as_bytes();
const HONEYPOT_LEN: usize = HONEYPOT_BYTES.len();
const HONEYPOT_FILENAME_U16: [u16; HONEYPOT_LEN] = {
    let mut out = [0u16; HONEYPOT_LEN];
    let mut i = 0;
    while i < HONEYPOT_LEN {
        assert!(HONEYPOT_BYTES[i] < 0x80);
        out[i] = HONEYPOT_BYTES[i] as u16;
        i += 1;
    }
    out
};

// Browser user-data path segments (relative segment boundary, case-insensitive).
const CHROME_USER_DATA_U16: [u16; 24] = ascii_u16(b"Google\\Chrome\\User Data\\");
const EDGE_USER_DATA_U16: [u16; 25] = ascii_u16(b"Microsoft\\Edge\\User Data\\");
const BRAVE_USER_DATA_U16: [u16; 38] = ascii_u16(b"BraveSoftware\\Brave-Browser\\User Data\\");
const FIREFOX_PROFILES_U16: [u16; 25] = ascii_u16(b"Mozilla\\Firefox\\Profiles\\");

// Browser target filenames / suffixes.
const COOKIES_U16: [u16; 7] = ascii_u16(b"Cookies");
const NETWORK_COOKIES_U16: [u16; 15] = ascii_u16(b"Network\\Cookies");
const COOKIES_SQLITE_U16: [u16; 14] = ascii_u16(b"cookies.sqlite");
const LOGIN_DATA_U16: [u16; 10] = ascii_u16(b"Login Data");
const LOGIN_DATA_FOR_ACCOUNT_U16: [u16; 22] = ascii_u16(b"Login Data For Account");
const LOCAL_STATE_U16: [u16; 11] = ascii_u16(b"Local State");
const LOGINS_JSON_U16: [u16; 11] = ascii_u16(b"logins.json");
const KEY4_DB_U16: [u16; 7] = ascii_u16(b"key4.db");

// User credential path segments.
const USERS_SEG_U16: [u16; 6] = ascii_u16(b"Users\\");
const SSH_SEG_U16: [u16; 5] = ascii_u16(b".ssh\\");
const AWS_CREDS_U16: [u16; 16] = ascii_u16(b".aws\\credentials");
const AWS_CONFIG_U16: [u16; 11] = ascii_u16(b".aws\\config");
const GCLOUD_SEG_U16: [u16; 15] = ascii_u16(b".config\\gcloud\\");

// `.env` matching and template exclusions.
const DOT_ENV_U16: [u16; 4] = ascii_u16(b".env");
const DOT_ENV_EXAMPLE_U16: [u16; 12] = ascii_u16(b".env.example");
const DOT_ENV_SAMPLE_U16: [u16; 11] = ascii_u16(b".env.sample");
const DOT_ENV_TEMPLATE_U16: [u16; 13] = ascii_u16(b".env.template");

// Autorun registry key markers.
const REG_RUN_U16: [u16; 18] = ascii_u16(b"CurrentVersion\\Run");
const REG_RUN_ONCE_U16: [u16; 22] = ascii_u16(b"CurrentVersion\\RunOnce");
const REG_WINLOGON_U16: [u16; 8] = ascii_u16(b"Winlogon");
const REG_SERVICES_U16: [u16; 9] = ascii_u16(b"Services\\");

#[derive(Debug, Clone)]
struct EncodedPathPrefix {
    drive: Option<[u16; 2]>,
    is_unc: bool,
    rest_u16: Vec<u16>,
}

impl EncodedPathPrefix {
    fn from_path(path: &Path) -> Option<Self> {
        let raw = path.to_string_lossy();
        let trimmed = raw.trim().trim_end_matches(['\\', '/', '\0']);
        if trimmed.is_empty() {
            return None;
        }
        let mut units: Vec<u16> = trimmed
            .encode_utf16()
            .map(|c| if c == b'/' as u16 { b'\\' as u16 } else { c })
            .collect();
        while matches!(units.last().copied(), Some(0 | 0x005C)) {
            units.pop();
        }
        if units.is_empty() {
            return None;
        }
        let empty_map = DosVolumeMap::with_mappings(Vec::new());
        let (drive, rest, is_unc) = empty_map.split_dos_prefix_u16(&units);
        Some(Self {
            drive,
            is_unc,
            rest_u16: rest.to_vec(),
        })
    }

    #[inline]
    fn matches_prefix(&self, drive: Option<[u16; 2]>, rest: &[u16], is_unc: bool) -> bool {
        if self.is_unc != is_unc || !drives_match(self.drive, drive) {
            return false;
        }
        if self.rest_u16.is_empty() {
            return rest.first().copied().is_some_and(is_sep_u16);
        }
        starts_with_path_ignore_ascii_case_u16(rest, &self.rest_u16)
            && rest.len() > self.rest_u16.len()
            && is_sep_u16(rest[self.rest_u16.len()])
    }

    #[inline]
    fn matches_exact(&self, drive: Option<[u16; 2]>, rest: &[u16], is_unc: bool) -> bool {
        if self.is_unc != is_unc || !drives_match(self.drive, drive) {
            return false;
        }
        eq_path_ignore_ascii_case_u16(rest, &self.rest_u16)
    }
}

/// Zero-allocation UTF-16 path pre-filter and Folder Canary / Honeypot classifier (`L-05`, `L-06`,
/// `AUTO-08`).
#[derive(Debug, Clone, Default)]
pub struct CanaryMatcher {
    dev_roots: Vec<EncodedPathPrefix>,
    honeypot_paths: Vec<EncodedPathPrefix>,
    user_profiles: Vec<EncodedPathPrefix>,
}

impl CanaryMatcher {
    /// Creates a new [`CanaryMatcher`] with user-registered development roots (for `.env*`
    /// protection) and explicit honeypot decoy file paths.
    pub fn new<I, P, J, Q>(dev_roots: I, honeypot_paths: J) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
        J: IntoIterator<Item = Q>,
        Q: AsRef<Path>,
    {
        let dev_roots = dev_roots
            .into_iter()
            .filter_map(|p| EncodedPathPrefix::from_path(p.as_ref()))
            .collect();
        let honeypot_paths = honeypot_paths
            .into_iter()
            .filter_map(|p| EncodedPathPrefix::from_path(p.as_ref()))
            .collect();
        Self {
            dev_roots,
            honeypot_paths,
            user_profiles: Vec::new(),
        }
    }

    /// Attaches explicit user profile root paths (used to match `<profile>\.ssh\*` and cloud
    /// credentials when profiles live outside `\Users\<user>\`).
    pub fn with_user_profiles<I, P>(mut self, profiles: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.user_profiles = profiles
            .into_iter()
            .filter_map(|p| EncodedPathPrefix::from_path(p.as_ref()))
            .collect();
        self
    }

    /// Returns the number of registered development roots.
    pub fn dev_root_count(&self) -> usize {
        self.dev_roots.len()
    }

    /// Returns the number of registered explicit honeypot paths.
    pub fn honeypot_path_count(&self) -> usize {
        self.honeypot_paths.len()
    }

    /// Returns `true` if `raw_u16` refers to a honeypot decoy path (regardless of read/write mode).
    ///
    /// Used by the ETW `Kernel-File` handler to track `FileObject` handles opened with
    /// `FILE_OPEN` so subsequent `Write`/`SetDelete`/`Rename` events fire without alerting on
    /// read-only scans (`L-06`).
    #[inline]
    pub fn is_honeypot_u16(&self, raw_u16: &[u16], volume_map: &DosVolumeMap) -> bool {
        let (drive, rest, is_unc) = volume_map.split_dos_prefix_u16(raw_u16);
        if rest.is_empty() {
            return false;
        }
        self.matches_honeypot(drive, rest, is_unc)
    }

    /// Zero-allocation UTF-16 path classification after `DosVolumeMap` prefix translation.
    ///
    /// Returns `None` without heap allocation for non-protected files and for read-only
    /// opens of honeypot decoy files (`L-06`).
    #[inline]
    pub fn classify_u16(
        &self,
        raw_u16: &[u16],
        volume_map: &DosVolumeMap,
        is_write_or_delete: bool,
    ) -> Option<CanaryCategory> {
        prefilter_and_classify_canary_u16(self, raw_u16, volume_map, is_write_or_delete)
    }

    /// String wrapper around [`Self::classify_u16`] using a stack UTF-16 buffer for typical paths.
    pub fn classify_str(
        &self,
        raw_path: &str,
        volume_map: &DosVolumeMap,
        is_write_or_delete: bool,
    ) -> Option<CanaryCategory> {
        prefilter_and_classify_canary(self, raw_path, volume_map, is_write_or_delete)
    }

    #[inline]
    fn matches_honeypot(&self, drive: Option<[u16; 2]>, rest: &[u16], is_unc: bool) -> bool {
        if let Some(filename) = trailing_filename_u16(rest) {
            if eq_ignore_ascii_case_u16(filename, &HONEYPOT_FILENAME_U16) {
                return true;
            }
        }
        self.honeypot_paths
            .iter()
            .any(|hp| hp.matches_exact(drive, rest, is_unc))
    }

    #[inline]
    fn matches_dev_env(&self, drive: Option<[u16; 2]>, rest: &[u16], is_unc: bool) -> bool {
        if self.dev_roots.is_empty() {
            return false;
        }
        let Some(filename) = trailing_filename_u16(rest) else {
            return false;
        };
        if !is_protected_env_filename_u16(filename) {
            return false;
        }
        self.dev_roots
            .iter()
            .any(|root| root.matches_prefix(drive, rest, is_unc))
    }

    #[inline]
    fn matches_configured_profile(&self, drive: Option<[u16; 2]>, rest: &[u16], is_unc: bool) -> Option<CanaryCategory> {
        for profile in &self.user_profiles {
            if profile.matches_prefix(drive, rest, is_unc) {
                let offset = if profile.rest_u16.is_empty() {
                    1
                } else {
                    profile.rest_u16.len() + 1
                };
                if offset < rest.len() {
                    if let Some(cat) = classify_user_profile_subpath(&rest[offset..]) {
                        return Some(cat);
                    }
                }
            }
        }
        None
    }
}

/// Zero-allocation primary UTF-16 pre-filter and canary classifier (`AUTO-08`, `L-02`, `L-05`,
/// `L-06`).
///
/// Discards non-protected `Kernel-File` I/O directly from raw UTF-16 slices after `DosVolumeMap`
/// prefix resolution before any `String` allocation occurs.
#[inline]
pub fn prefilter_and_classify_canary_u16(
    matcher: &CanaryMatcher,
    raw_u16: &[u16],
    volume_map: &DosVolumeMap,
    is_write_or_delete: bool,
) -> Option<CanaryCategory> {
    let (drive, rest, is_unc) = volume_map.split_dos_prefix_u16(raw_u16);
    if rest.is_empty() {
        return None;
    }

    // 1. Honeypot decoy files: strictly fire ONLY on write, delete, rename, or create/overwrite (`L-06`).
    if matcher.matches_honeypot(drive, rest, is_unc) {
        return if is_write_or_delete {
            Some(CanaryCategory::Honeypot)
        } else {
            None
        };
    }

    // 2. Tier 2: User-registered development root `.env*` files (`L-05`).
    if matcher.matches_dev_env(drive, rest, is_unc) {
        return Some(CanaryCategory::EnvFile);
    }

    // 3. Tier 1: Default credential path templates (`L-05`).
    if let Some(category) = classify_default_credentials_u16(rest) {
        return Some(category);
    }

    // 4. Optional explicitly configured user profiles (for profiles outside `\Users\*`).
    matcher.matches_configured_profile(drive, rest, is_unc)
}

/// String convenience wrapper around [`prefilter_and_classify_canary_u16`].
pub fn prefilter_and_classify_canary(
    matcher: &CanaryMatcher,
    raw_path: &str,
    volume_map: &DosVolumeMap,
    is_write_or_delete: bool,
) -> Option<CanaryCategory> {
    if raw_path.is_empty() {
        return None;
    }
    let mut stack = [0u16; 512];
    let mut len = 0usize;
    for unit in raw_path.encode_utf16() {
        if len >= stack.len() {
            let heap: Vec<u16> = raw_path.encode_utf16().collect();
            return prefilter_and_classify_canary_u16(
                matcher,
                &heap,
                volume_map,
                is_write_or_delete,
            );
        }
        stack[len] = unit;
        len += 1;
    }
    prefilter_and_classify_canary_u16(matcher, &stack[..len], volume_map, is_write_or_delete)
}

/// Returns `true` if a raw UTF-16 registry key path matches a monitored Windows autorun persistence
/// location (`\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `\Winlogon`, or `\Services\*`).
#[inline]
pub fn is_autorun_registry_key_u16(raw_u16: &[u16]) -> bool {
    let end = raw_u16
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(raw_u16.len());
    let slice = &raw_u16[..end];
    if slice.is_empty() {
        return false;
    }

    if let Some(after) = find_segment_ci_u16(slice, &REG_RUN_U16) {
        if after == slice.len() || is_sep_u16(slice[after]) {
            return true;
        }
    }
    if let Some(after) = find_segment_ci_u16(slice, &REG_RUN_ONCE_U16) {
        if after == slice.len() || is_sep_u16(slice[after]) {
            return true;
        }
    }
    if let Some(after) = find_segment_ci_u16(slice, &REG_WINLOGON_U16) {
        if after == slice.len() || is_sep_u16(slice[after]) {
            return true;
        }
    }
    if let Some(after) = find_segment_ci_u16(slice, &REG_SERVICES_U16) {
        if after < slice.len() {
            return true;
        }
    }

    false
}

/// String wrapper around [`is_autorun_registry_key_u16`].
pub fn is_autorun_registry_key(key_path: &str) -> bool {
    if key_path.is_empty() {
        return false;
    }
    let mut stack = [0u16; 512];
    let mut len = 0usize;
    for unit in key_path.encode_utf16() {
        if len >= stack.len() {
            let heap: Vec<u16> = key_path.encode_utf16().collect();
            return is_autorun_registry_key_u16(&heap);
        }
        stack[len] = unit;
        len += 1;
    }
    is_autorun_registry_key_u16(&stack[..len])
}

#[inline]
fn classify_default_credentials_u16(rest: &[u16]) -> Option<CanaryCategory> {
    if let Some(filename) = trailing_filename_u16(rest) {
        // Check browser stores only when the filename itself matches a sensitive store filename.
        if eq_ignore_ascii_case_u16(filename, &COOKIES_U16) {
            if contains_chromium_user_data_u16(rest)
                && (ends_with_path_segment_ci_u16(rest, &NETWORK_COOKIES_U16)
                    || ends_with_path_segment_ci_u16(rest, &COOKIES_U16))
            {
                return Some(CanaryCategory::CookieDb);
            }
        } else if eq_ignore_ascii_case_u16(filename, &COOKIES_SQLITE_U16) {
            if find_segment_ci_u16(rest, &FIREFOX_PROFILES_U16).is_some() {
                return Some(CanaryCategory::CookieDb);
            }
        } else if eq_ignore_ascii_case_u16(filename, &LOGIN_DATA_U16)
            || eq_ignore_ascii_case_u16(filename, &LOGIN_DATA_FOR_ACCOUNT_U16)
            || eq_ignore_ascii_case_u16(filename, &LOCAL_STATE_U16)
        {
            if contains_chromium_user_data_u16(rest) {
                return Some(CanaryCategory::LoginData);
            }
        } else if (eq_ignore_ascii_case_u16(filename, &LOGINS_JSON_U16)
            || eq_ignore_ascii_case_u16(filename, &KEY4_DB_U16))
            && find_segment_ci_u16(rest, &FIREFOX_PROFILES_U16).is_some()
        {
            return Some(CanaryCategory::LoginData);
        }
    }

    // Check `*\Users\<user>\.ssh\*`, `*\Users\<user>\.aws\*`, `*\Users\<user>\.config\gcloud\*`.
    if let Some(after_users) = find_segment_ci_u16(rest, &USERS_SEG_U16) {
        let user_rest = &rest[after_users..];
        if let Some(sep_pos) = user_rest.iter().position(|&c| is_sep_u16(c)) {
            if sep_pos > 0 && sep_pos + 1 < user_rest.len() {
                let after_user = &user_rest[sep_pos + 1..];
                if let Some(cat) = classify_user_profile_subpath(after_user) {
                    return Some(cat);
                }
            }
        }
    }

    None
}

#[inline]
fn classify_user_profile_subpath(after_user: &[u16]) -> Option<CanaryCategory> {
    if starts_with_path_ignore_ascii_case_u16(after_user, &SSH_SEG_U16)
        && after_user.len() > SSH_SEG_U16.len()
    {
        return Some(CanaryCategory::SshKey);
    }
    if eq_path_ignore_ascii_case_u16(after_user, &AWS_CREDS_U16)
        || eq_path_ignore_ascii_case_u16(after_user, &AWS_CONFIG_U16)
    {
        return Some(CanaryCategory::CloudCredential);
    }
    if starts_with_path_ignore_ascii_case_u16(after_user, &GCLOUD_SEG_U16)
        && after_user.len() > GCLOUD_SEG_U16.len()
    {
        return Some(CanaryCategory::CloudCredential);
    }
    None
}

#[inline]
fn contains_chromium_user_data_u16(rest: &[u16]) -> bool {
    find_segment_ci_u16(rest, &CHROME_USER_DATA_U16).is_some()
        || find_segment_ci_u16(rest, &EDGE_USER_DATA_U16).is_some()
        || find_segment_ci_u16(rest, &BRAVE_USER_DATA_U16).is_some()
}

#[inline]
fn is_protected_env_filename_u16(filename: &[u16]) -> bool {
    if filename.len() < DOT_ENV_U16.len()
        || !starts_with_ignore_ascii_case_u16(filename, &DOT_ENV_U16)
    {
        return false;
    }
    if filename.len() == DOT_ENV_U16.len() {
        return true;
    }
    if filename.len() <= DOT_ENV_U16.len() + 1 || filename[DOT_ENV_U16.len()] != b'.' as u16 {
        return false;
    }
    !(eq_ignore_ascii_case_u16(filename, &DOT_ENV_EXAMPLE_U16)
        || eq_ignore_ascii_case_u16(filename, &DOT_ENV_SAMPLE_U16)
        || eq_ignore_ascii_case_u16(filename, &DOT_ENV_TEMPLATE_U16))
}

#[inline]
const fn fold_ascii_u16(c: u16) -> u16 {
    if c >= b'A' as u16 && c <= b'Z' as u16 {
        c + 32
    } else {
        c
    }
}

#[inline]
const fn is_sep_u16(c: u16) -> bool {
    c == b'\\' as u16 || c == b'/' as u16
}

#[inline]
fn drives_match(expected: Option<[u16; 2]>, actual: Option<[u16; 2]>) -> bool {
    match (expected, actual) {
        (Some(a), Some(b)) => fold_ascii_u16(a[0]) == fold_ascii_u16(b[0]) && a[1] == b[1],
        (None, None) => true,
        _ => false,
    }
}

#[inline]
fn trailing_filename_u16(path: &[u16]) -> Option<&[u16]> {
    if path.is_empty() || is_sep_u16(*path.last()?) {
        return None;
    }
    let start = path
        .iter()
        .rposition(|&c| is_sep_u16(c))
        .map_or(0, |pos| pos + 1);
    let tail = &path[start..];
    if tail.is_empty() { None } else { Some(tail) }
}

#[inline]
fn eq_ignore_ascii_case_u16(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && starts_with_ignore_ascii_case_u16(a, b)
}

#[inline]
fn starts_with_path_ignore_ascii_case_u16(haystack: &[u16], needle: &[u16]) -> bool {
    if starts_with_ignore_ascii_case_u16(haystack, needle) {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack[..needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(&a, &b)| fold_ascii_u16(a) == fold_ascii_u16(b) || (is_sep_u16(a) && is_sep_u16(b)))
}

#[inline]
fn eq_path_ignore_ascii_case_u16(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && starts_with_path_ignore_ascii_case_u16(a, b)
}

#[inline]
fn ends_with_path_segment_ci_u16(haystack: &[u16], suffix: &[u16]) -> bool {
    if haystack.len() < suffix.len() {
        return false;
    }
    let offset = haystack.len() - suffix.len();
    if offset > 0 && !is_sep_u16(haystack[offset - 1]) {
        return false;
    }
    eq_path_ignore_ascii_case_u16(&haystack[offset..], suffix)
}

#[inline]
fn find_segment_ci_u16(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut idx = 0usize;
    let limit = haystack.len() - needle.len();
    while idx <= limit {
        let at_boundary = idx == 0 || is_sep_u16(haystack[idx - 1]);
        if at_boundary && starts_with_path_ignore_ascii_case_u16(&haystack[idx..], needle) {
            return Some(idx + needle.len());
        }
        // Advance directly to after the next path separator instead of scanning every code unit.
        match haystack[idx..].iter().position(|&c| is_sep_u16(c)) {
            Some(sep_rel) => idx += sep_rel + 1,
            None => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_volume_map() -> DosVolumeMap {
        DosVolumeMap::with_mappings(vec![
            (
                r"\Device\HarddiskVolume3".encode_utf16().collect(),
                "C:".to_string(),
            ),
            (
                r"\Device\HarddiskVolume4".encode_utf16().collect(),
                "D:".to_string(),
            ),
        ])
    }

    #[test]
    fn sens_p2_01_utf16_prefilter_and_volume_translation() {
        let vmap = test_volume_map();
        let matcher = CanaryMatcher::new([PathBuf::from(r"D:\Workspace\secret-app")], Vec::<PathBuf>::new());

        // Non-protected Windows system and build artifacts are rejected cleanly.
        for benign in [
            r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
            r"\Device\HarddiskVolume3\Users\Alice\AppData\Local\Temp\cargo_build.obj",
            r"\Device\HarddiskVolume3\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\Cookies-journal",
            r"\Device\HarddiskVolume3\Users\Alice\.ssh",
            r"\Device\HarddiskVolume3\Users\Alice\.ssh\",
            r"\Device\HarddiskVolume3\Users\Alice\.aws\cli_cache.json",
            r"\Device\HarddiskVolume4\Workspace\secret-app-other\.env",
            "",
        ] {
            let u16_path: Vec<u16> = benign.encode_utf16().chain(std::iter::once(0)).collect();
            assert_eq!(
                prefilter_and_classify_canary_u16(&matcher, &u16_path, &vmap, false),
                None,
                "expected None for benign path `{benign}`"
            );
            assert_eq!(
                prefilter_and_classify_canary(&matcher, benign, &vmap, true),
                None,
                "expected None on write for benign path `{benign}`"
            );
        }

        // Verify NT device translation + case-insensitive UTF-16 slice classification.
        let nt_cookie: Vec<u16> =
            r"\device\harddiskvolume3\USERS\Alice\AppData\Local\Google\Chrome\User Data\Default\Network\COOKIES"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
        assert_eq!(
            prefilter_and_classify_canary_u16(&matcher, &nt_cookie, &vmap, false),
            Some(CanaryCategory::CookieDb)
        );

        let nt_env: Vec<u16> = r"\Device\HarddiskVolume4\Workspace\secret-app\api\.ENV.PRODUCTION"
            .encode_utf16()
            .collect();
        assert_eq!(
            prefilter_and_classify_canary_u16(&matcher, &nt_env, &vmap, false),
            Some(CanaryCategory::EnvFile)
        );
    }

    #[test]
    fn sens_p2_02_folder_canary_two_tiers_and_honeypot_write_gate() {
        let vmap = test_volume_map();
        let matcher = CanaryMatcher::new(
            [PathBuf::from(r"C:\dev\my-project")],
            [PathBuf::from(r"D:\Traps\custom_trap.docx")],
        )
        .with_user_profiles([PathBuf::from(r"E:\Profiles\customuser")]);

        // Tier 1: CookieDb across Chrome, Edge, Brave, Firefox.
        for cookie_path in [
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Profile 2\Network\Cookies",
            r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
            r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default-release\cookies.sqlite",
        ] {
            assert_eq!(
                matcher.classify_str(cookie_path, &vmap, false),
                Some(CanaryCategory::CookieDb),
                "expected CookieDb for `{cookie_path}`"
            );
        }

        // Tier 1: LoginData across Chrome, Edge, Brave, Firefox.
        for login_path in [
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Login Data For Account",
            r"C:\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State",
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default\logins.json",
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd1234.default\key4.db",
        ] {
            assert_eq!(
                matcher.classify_str(login_path, &vmap, false),
                Some(CanaryCategory::LoginData),
                "expected LoginData for `{login_path}`"
            );
        }

        // Tier 1: SshKey & CloudCredential.
        assert_eq!(
            matcher.classify_str(r"C:\Users\alice\.ssh\id_ed25519", &vmap, false),
            Some(CanaryCategory::SshKey)
        );
        assert_eq!(
            matcher.classify_str(r"E:\Profiles\customuser\.ssh\id_rsa", &vmap, false),
            Some(CanaryCategory::SshKey)
        );
        assert_eq!(
            matcher.classify_str(r"C:\Users\alice\.aws\credentials", &vmap, false),
            Some(CanaryCategory::CloudCredential)
        );
        assert_eq!(
            matcher.classify_str(r"C:\Users\alice\.aws\config", &vmap, false),
            Some(CanaryCategory::CloudCredential)
        );
        assert_eq!(
            matcher.classify_str(
                r"C:\Users\alice\.config\gcloud\application_default_credentials.json",
                &vmap,
                false
            ),
            Some(CanaryCategory::CloudCredential)
        );

        // Tier 2: Registered dev_roots `.env` / `.env.*`, skipping sample templates.
        assert_eq!(
            matcher.classify_str(r"C:\dev\my-project\.env", &vmap, false),
            Some(CanaryCategory::EnvFile)
        );
        assert_eq!(
            matcher.classify_str(r"C:\dev\my-project\sub\.env.local", &vmap, true),
            Some(CanaryCategory::EnvFile)
        );
        for skipped in [
            r"C:\dev\my-project\.env.example",
            r"C:\dev\my-project\.env.sample",
            r"C:\dev\my-project\.env.template",
            r"C:\dev\my-project\.ENV.EXAMPLE",
            r"C:\dev\my-project\.envrc",
            r"C:\other\.env",
        ] {
            assert_eq!(
                matcher.classify_str(skipped, &vmap, true),
                None,
                "expected None for `{skipped}`"
            );
        }

        // Honeypot (L-06): read-only open MUST return None; write/delete MUST return Some(Honeypot).
        let default_hp = format!(r"C:\Users\alice\Documents\{HONEYPOT_DEFAULT_FILENAME}");
        assert_eq!(matcher.classify_str(&default_hp, &vmap, false), None);
        assert_eq!(
            matcher.classify_str(&default_hp, &vmap, true),
            Some(CanaryCategory::Honeypot)
        );
        assert_eq!(
            matcher.classify_str(r"D:\Traps\custom_trap.docx", &vmap, false),
            None
        );
        assert_eq!(
            matcher.classify_str(r"D:\Traps\custom_trap.docx", &vmap, true),
            Some(CanaryCategory::Honeypot)
        );
    }

    #[test]
    fn sens_p2_03_autorun_registry_key_matching() {
        for matched in [
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"\REGISTRY\USER\S-1-5-21-123\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"\registry\machine\software\microsoft\windows nt\currentversion\winlogon",
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
            r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\EvilPersistence",
        ] {
            assert!(
                is_autorun_registry_key(matched),
                "expected autorun match for `{matched}`"
            );
        }

        for benign in [
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunMRU",
            r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App",
            r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services",
            r"\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\",
            "",
        ] {
            assert!(
                !is_autorun_registry_key(benign),
                "expected no autorun match for `{benign}`"
            );
        }
    }
}
