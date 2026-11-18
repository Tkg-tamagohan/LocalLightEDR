//! NT device path to DOS drive normalization via `QueryDosDeviceW` lookup tables
//! and zero-allocation UTF-16 prefix comparison (`AUTO-08`).

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

/// Folds ASCII `'A'..='Z'` to lowercase without allocations.
#[inline]
const fn fold_ascii_u16(c: u16) -> u16 {
    if c >= b'A' as u16 && c <= b'Z' as u16 {
        c + 32
    } else {
        c
    }
}

/// Performs a zero-allocation ASCII case-insensitive prefix comparison on UTF-16 slices.
///
/// Designed for fast ETW `Kernel-File` callback pre-filtering before any heap allocation.
#[inline]
pub fn starts_with_ignore_ascii_case_u16(haystack: &[u16], needle: &[u16]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack[..needle.len()]
        .iter()
        .zip(needle.iter())
        .all(|(&a, &b)| fold_ascii_u16(a) == fold_ascii_u16(b))
}

/// Mapping table translating NT device object paths (e.g. `\Device\HarddiskVolume3`)
/// to DOS drive prefixes (e.g. `C:`) (`AUTO-08`).
#[derive(Debug, Clone)]
pub struct DosVolumeMap {
    /// Sorted longest-prefix-first `(nt_device_utf16, dos_drive)` pairs.
    mappings: Vec<(Vec<u16>, String)>,
}

impl Default for DosVolumeMap {
    fn default() -> Self {
        Self::from_system()
    }
}

impl DosVolumeMap {
    /// Queries `A:`..`Z:` via `QueryDosDeviceW` to construct the current system volume map.
    pub fn from_system() -> Self {
        let mut mappings = Vec::new();
        let mut buf = vec![0u16; 512];

        for letter in b'A'..=b'Z' {
            let device_name = [letter as u16, b':' as u16, 0u16];
            if let Some(target_u16) = query_dos_device(&device_name, &mut buf) {
                mappings.push((target_u16, format!("{}:", letter as char)));
            }
        }

        Self::with_mappings(mappings)
    }

    /// Creates a [`DosVolumeMap`] from explicit `(nt_device_utf16, dos_drive)` pairs.
    pub fn with_mappings(mappings: Vec<(Vec<u16>, String)>) -> Self {
        let mut cleaned: Vec<(Vec<u16>, String)> = mappings
            .into_iter()
            .filter_map(|(mut dev_u16, drive)| {
                while matches!(dev_u16.last().copied(), Some(0 | 0x005C | 0x002F)) {
                    dev_u16.pop();
                }
                let drive_trimmed = drive.trim_end_matches(['\\', '/']).to_string();
                if dev_u16.is_empty() || drive_trimmed.is_empty() {
                    None
                } else {
                    Some((dev_u16, drive_trimmed))
                }
            })
            .collect();

        // Sort longest device prefix first so `\Device\HarddiskVolume10` matches
        // before `\Device\HarddiskVolume1`.
        cleaned.sort_by_key(|a| std::cmp::Reverse(a.0.len()));
        Self { mappings: cleaned }
    }

    /// Returns the number of registered device-to-drive mappings.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Returns `true` if no volume mappings are present.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// Normalizes a raw NT/Win32 path string into a canonical DOS path when possible.
    ///
    /// Converts `\Device\HarddiskVolumeX\...` using the volume map and strips `\??\` or `\\?\`
    /// prefixes (including `\??\UNC\...` -> `\\...`).
    pub fn normalize_path(&self, raw_path: &str) -> String {
        let trimmed = raw_path.trim_end_matches('\0');
        if trimmed.is_empty() {
            return String::new();
        }

        if let Some(unc_rest) = strip_unc_prefix(trimmed) {
            return format!(r"\\{unc_rest}");
        }

        if let Some(stripped) = strip_nt_dos_prefix(trimmed) {
            if starts_with_drive_letter(stripped) {
                return stripped.to_string();
            }
            let stripped_u16: Vec<u16> = stripped.encode_utf16().collect();
            if let Some((drive, prefix_len)) = self.match_device_u16(&stripped_u16) {
                let rest = String::from_utf16_lossy(&stripped_u16[prefix_len..]);
                return format!("{drive}{rest}");
            }
        }

        let u16_path: Vec<u16> = trimmed.encode_utf16().collect();
        self.normalize_u16_inner(&u16_path)
            .unwrap_or_else(|| trimmed.to_string())
    }

    /// Normalizes a raw UTF-16 slice (trimmed at the first NUL if present) into a DOS path.
    pub fn normalize_u16(&self, raw_u16: &[u16]) -> String {
        let end = raw_u16
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(raw_u16.len());
        let slice = &raw_u16[..end];
        if slice.is_empty() {
            return String::new();
        }

        if let Some(normalized) = self.normalize_u16_inner(slice) {
            return normalized;
        }

        let text = String::from_utf16_lossy(slice);
        if let Some(unc_rest) = strip_unc_prefix(&text) {
            return format!(r"\\{unc_rest}");
        }
        if let Some(stripped) = strip_nt_dos_prefix(&text).filter(|s| starts_with_drive_letter(s)) {
            return stripped.to_string();
        }
        text
    }

    fn normalize_u16_inner(&self, path_u16: &[u16]) -> Option<String> {
        let (drive, prefix_len) = self.match_device_u16(path_u16)?;
        let rest = String::from_utf16_lossy(&path_u16[prefix_len..]);
        Some(format!("{drive}{rest}"))
    }

    #[inline]
    fn match_device_u16(&self, path_u16: &[u16]) -> Option<(&str, usize)> {
        for (dev_u16, drive) in &self.mappings {
            if starts_with_ignore_ascii_case_u16(path_u16, dev_u16)
                && (path_u16.len() == dev_u16.len()
                    || path_u16[dev_u16.len()] == b'\\' as u16
                    || path_u16[dev_u16.len()] == b'/' as u16)
            {
                return Some((drive.as_str(), dev_u16.len()));
            }
        }
        None
    }
}

fn query_dos_device(device_name_nul: &[u16], buf: &mut Vec<u16>) -> Option<Vec<u16>> {
    // SAFETY: `device_name_nul` is NUL-terminated UTF-16 (e.g. `"C:\0"`) and `buf` is valid writable storage.
    let mut copied = unsafe {
        QueryDosDeviceW(
            PCWSTR(device_name_nul.as_ptr()),
            Some(buf.as_mut_slice()),
        )
    };

    // SAFETY: reads thread-local error set by `QueryDosDeviceW`.
    if copied == 0 && unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
        buf.resize(4096, 0);
        // SAFETY: same preconditions as above with enlarged buffer.
        copied = unsafe {
            QueryDosDeviceW(
                PCWSTR(device_name_nul.as_ptr()),
                Some(buf.as_mut_slice()),
            )
        };
    }

    if copied == 0 {
        return None;
    }

    let valid = &buf[..(copied as usize).min(buf.len())];
    let first_len = valid.iter().position(|&c| c == 0).unwrap_or(valid.len());
    if first_len == 0 {
        None
    } else {
        Some(valid[..first_len].to_vec())
    }
}

fn strip_nt_dos_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(r"\??\").or_else(|| path.strip_prefix(r"\\?\"))
}

fn strip_unc_prefix(path: &str) -> Option<&str> {
    let rest = strip_nt_dos_prefix(path)?;
    if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(r"UNC\") {
        Some(&rest[4..])
    } else {
        None
    }
}

fn starts_with_drive_letter(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sens_01_dos_volume_map_and_utf16_prefix() {
        let map = DosVolumeMap::with_mappings(vec![
            (
                r"\Device\HarddiskVolume3".encode_utf16().collect(),
                "C:".to_string(),
            ),
            (
                r"\Device\HarddiskVolume30".encode_utf16().collect(),
                "D:".to_string(),
            ),
        ]);

        assert_eq!(
            map.normalize_path(r"\Device\HarddiskVolume3\Users\test\a.txt"),
            r"C:\Users\test\a.txt"
        );
        assert_eq!(
            map.normalize_path(r"\device\harddiskvolume3\Users\test\a.txt"),
            r"C:\Users\test\a.txt"
        );
        assert_eq!(
            map.normalize_path(r"\Device\HarddiskVolume30\Data\b.txt"),
            r"D:\Data\b.txt"
        );
        assert_eq!(
            map.normalize_path(r"\??\C:\Users\test\a.txt"),
            r"C:\Users\test\a.txt"
        );
        assert_eq!(
            map.normalize_path(r"\\?\UNC\fileserver\share\doc.txt"),
            r"\\fileserver\share\doc.txt"
        );

        let hay: Vec<u16> = r"\Device\HarddiskVolume3\Users\Alice\AppData"
            .encode_utf16()
            .collect();
        let needle_ci: Vec<u16> = r"\device\harddiskvolume3\users\".encode_utf16().collect();
        let needle_miss: Vec<u16> = r"\Device\HarddiskVolume3\Windows\".encode_utf16().collect();

        assert!(starts_with_ignore_ascii_case_u16(&hay, &needle_ci));
        assert!(!starts_with_ignore_ascii_case_u16(&hay, &needle_miss));
        assert!(!starts_with_ignore_ascii_case_u16(&needle_ci, &hay));

        // Verify live `from_system()` executes cleanly without panicking (note: AppContainer
        // sandboxes may return ERROR_ACCESS_DENIED from QueryDosDeviceW, yielding <= 26 entries).
        let sys_map = DosVolumeMap::from_system();
        assert!(sys_map.len() <= 26);
        assert_eq!(
            sys_map.normalize_path(r"\??\C:\Windows\System32\cmd.exe"),
            r"C:\Windows\System32\cmd.exe"
        );
    }
}
