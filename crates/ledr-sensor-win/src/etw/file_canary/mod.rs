//! Zero-allocation UTF-16 primary pre-filter, Folder Canary classifier (`L-05`),
//! honeypot write detector (`L-06`), and autorun registry key matcher (`AUTO-08`).

mod registry;
mod utf16;

pub use registry::{
    is_autorun_registry_key, is_autorun_registry_key_u16, is_autorun_registry_value_target,
    is_autorun_registry_value_target_u16,
};

use std::path::Path;

use ledr_proto::{CanaryCategory, HONEYPOT_DEFAULT_FILENAME};

use crate::path_norm::{DosVolumeMap, starts_with_ignore_ascii_case_u16};

use utf16::{
    ascii_u16, drives_match, ends_with_path_segment_ci_u16, eq_ignore_ascii_case_u16,
    eq_path_ignore_ascii_case_u16, find_segment_ci_u16, is_sep_u16,
    starts_with_path_ignore_ascii_case_u16, trailing_filename_u16,
};

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

#[cfg(test)]
mod tests;
