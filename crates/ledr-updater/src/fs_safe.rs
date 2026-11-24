//! Reparse-point-safe Windows filesystem primitives, exclusive file creation,
//! atomic file replacement, and bounded staging directory cleanup.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::UpdaterError;

const WINDOWS_RESERVED_STEMS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Validates that `filename` is a non-empty single path segment safe for Windows filesystems.
pub(crate) fn validate_single_segment_filename(filename: &str) -> Result<(), UpdaterError> {
    if filename.is_empty() || filename == "." || filename == ".." {
        return Err(UpdaterError::UnsafePath(format!(
            "filename {filename:?} is empty or a relative traversal segment"
        )));
    }
    if filename.ends_with('.') || filename.ends_with(' ') {
        return Err(UpdaterError::UnsafePath(format!(
            "filename {filename:?} must not end with '.' or space"
        )));
    }
    for ch in filename.chars() {
        if ch == '\0'
            || (ch as u32) < 0x20
            || ch as u32 == 0x7F
            || matches!(ch, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        {
            return Err(UpdaterError::UnsafePath(format!(
                "filename {filename:?} contains forbidden character {ch:?}"
            )));
        }
    }
    let stem = filename.split('.').next().unwrap_or(filename);
    if WINDOWS_RESERVED_STEMS
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return Err(UpdaterError::UnsafePath(format!(
            "filename {filename:?} uses reserved Windows device name"
        )));
    }
    Ok(())
}

/// Verifies that no existing path component at or above `path` is a Windows reparse point.
pub(crate) fn ensure_no_reparse_points(path: &Path) -> Result<(), UpdaterError> {
    platform::ensure_no_reparse_points(path)
}

/// Creates a fresh UUID subdirectory under `staging_root` after checking for reparse points.
pub(crate) fn create_staging_session_dir(
    staging_root: &Path,
) -> Result<(Uuid, PathBuf), UpdaterError> {
    platform::create_session_dir(staging_root)
}

/// Creates a fresh UUID subdirectory under `verified_root` after checking for reparse points.
pub(crate) fn create_verified_session_dir(
    verified_root: &Path,
) -> Result<(Uuid, PathBuf), UpdaterError> {
    platform::create_session_dir(verified_root)
}

/// Exclusively creates a new regular file (`create_new(true)`) after reparse-point verification.
pub(crate) fn create_exclusive_file(path: &Path) -> Result<File, UpdaterError> {
    platform::create_exclusive_file(path)
}

/// Atomically writes `contents` to `dest_path` using a sibling temp file and atomic replacement.
pub(crate) fn atomic_write_file(dest_path: &Path, contents: &[u8]) -> Result<(), UpdaterError> {
    platform::atomic_write_file(dest_path, contents)
}

/// Opens an existing regular file for read-only access after full reparse-point, hardlink,
/// disk-type, and final-path containment verification.
pub(crate) fn open_verified_read_file(path: &Path, max_bytes: u64) -> Result<File, UpdaterError> {
    platform::open_verified_read_file(path, max_bytes)
}

/// Removes UUID-named staging subdirectories older than `max_age` without following reparse points.
pub(crate) fn cleanup_stale_staging_dirs(
    staging_root: &Path,
    max_age: Duration,
) -> Result<usize, UpdaterError> {
    platform::cleanup_stale_staging_dirs(staging_root, max_age)
}

fn validate_file_path_leaf(path: &Path) -> Result<String, UpdaterError> {
    if let Some(raw) = path.to_str() {
        if raw.ends_with('\\') || raw.ends_with('/') {
            return Err(UpdaterError::UnsafePath(format!(
                "file path {raw:?} ends with a directory separator"
            )));
        }
    }
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| UpdaterError::UnsafePath(format!("missing valid filename in {path:?}")))?;
    validate_single_segment_filename(leaf)?;
    Ok(leaf.to_string())
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::io::ErrorKind;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, FALSE, HANDLE,
        INVALID_HANDLE_VALUE,
    };

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
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    const FILE_TYPE_DISK: u32 = 0x0001;
    const VOLUME_NAME_DOS: u32 = 0x0;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
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
            h_template_file: HANDLE,
        ) -> HANDLE;
        fn ReOpenFile(
            h_original_file: HANDLE,
            dw_desired_access: u32,
            dw_share_mode: u32,
            dw_flags_and_attributes: u32,
        ) -> HANDLE;
        fn GetFileType(h_file: HANDLE) -> u32;
        fn GetFileInformationByHandle(
            h_file: HANDLE,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            h_file: HANDLE,
            lpsz_file_path: *mut u16,
            cch_file_path: u32,
            dw_flags: u32,
        ) -> u32;
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        fn into_raw(mut self) -> HANDLE {
            let raw = self.0;
            self.0 = ptr::null_mut();
            raw
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is an owned Win32 HANDLE opened by `CreateFileW` or `ReOpenFile`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn encode_wide_nul(path: &Path) -> Result<Vec<u16>, UpdaterError> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(UpdaterError::UnsafePath(format!(
                "path {path:?} is empty or contains NUL"
            )));
        }
        let mut out = wide;
        out.push(0);
        Ok(out)
    }

    fn is_not_found_code(code: u32) -> bool {
        code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND
    }

    fn is_not_found_io(err: &std::io::Error) -> bool {
        err.kind() == ErrorKind::NotFound
            || err
                .raw_os_error()
                .is_some_and(|c| is_not_found_code(c as u32))
    }

    fn parse_strict_local_drive_path(path: &Path) -> Result<(char, Vec<String>), UpdaterError> {
        let raw = path.to_str().ok_or_else(|| {
            UpdaterError::UnsafePath(format!("path {path:?} is not valid UTF-8"))
        })?;
        if raw.is_empty() || raw.contains('\0') {
            return Err(UpdaterError::UnsafePath(format!(
                "path {raw:?} is empty or contains NUL"
            )));
        }

        let rest = if let Some(verbatim) = raw.strip_prefix(r"\\?\") {
            let bytes = verbatim.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_alphabetic()
                || bytes[1] != b':'
                || bytes[2] != b'\\'
            {
                return Err(UpdaterError::UnsafePath(format!(
                    "unsupported verbatim path {raw:?}"
                )));
            }
            verbatim
        } else if raw.starts_with(r"\\") || raw.starts_with("//") {
            return Err(UpdaterError::UnsafePath(format!(
                "UNC or device path {raw:?} is rejected"
            )));
        } else {
            raw
        };

        let bytes = rest.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || (bytes[2] != b'\\' && bytes[2] != b'/')
        {
            return Err(UpdaterError::UnsafePath(format!(
                "path {raw:?} must be an absolute local drive path"
            )));
        }

        let drive = (bytes[0] as char).to_ascii_uppercase();
        let tail = &rest[3..];
        let mut segments = Vec::new();
        for seg in tail.split(['\\', '/']) {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." {
                return Err(UpdaterError::UnsafePath(format!(
                    "path {raw:?} contains relative traversal segment {seg:?}"
                )));
            }
            if seg.contains(':')
                || seg.ends_with('.')
                || seg.ends_with(' ')
                || seg
                    .chars()
                    .any(|c| (c as u32) < 0x20 || c as u32 == 0x7F || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
            {
                return Err(UpdaterError::UnsafePath(format!(
                    "path {raw:?} contains unsafe segment {seg:?}"
                )));
            }
            segments.push(seg.to_string());
        }
        Ok((drive, segments))
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

    fn build_display_drive_path(drive: char, segments: &[String]) -> PathBuf {
        let mut s = format!(r"{}:\", drive.to_ascii_uppercase());
        for (i, seg) in segments.iter().enumerate() {
            if i > 0 {
                s.push('\\');
            }
            s.push_str(seg);
        }
        PathBuf::from(s)
    }

    fn segment_eq_case_insensitive(a: &str, b: &str) -> bool {
        if a.is_ascii() && b.is_ascii() {
            a.eq_ignore_ascii_case(b)
        } else {
            a.to_lowercase() == b.to_lowercase()
        }
    }

    fn paths_equal_case_insensitive(a: (char, &[String]), b: (char, &[String])) -> bool {
        a.0 == b.0
            && a.1.len() == b.1.len()
            && a.1
                .iter()
                .zip(b.1)
                .all(|(sa, sb)| segment_eq_case_insensitive(sa, sb))
    }

    fn query_long_path(verbatim_path: &Path) -> Option<PathBuf> {
        let wide = encode_wide_nul(verbatim_path).ok()?;
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

    fn expand_long_segments(drive: char, segments: &[String]) -> (char, Vec<String>) {
        let verbatim = build_verbatim_drive_path(drive, segments);
        if let Some(long_path) = query_long_path(&verbatim) {
            if let Ok((ld, lsegs)) = parse_strict_local_drive_path(&long_path) {
                return (ld, lsegs);
            }
        }
        for prefix_len in (1..segments.len()).rev() {
            let prefix_verbatim = build_verbatim_drive_path(drive, &segments[..prefix_len]);
            if let Some(long_prefix) = query_long_path(&prefix_verbatim) {
                if let Ok((ld, mut lsegs)) = parse_strict_local_drive_path(&long_prefix) {
                    lsegs.extend(segments[prefix_len..].iter().cloned());
                    return (ld, lsegs);
                }
            }
        }
        (drive, segments.to_vec())
    }

    fn query_final_path_dos(handle: HANDLE) -> Result<(char, Vec<String>), UpdaterError> {
        let mut cap: usize = 512;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `handle` is an open Win32 handle and `buf` holds `cap` writable `u16` elements.
            let ret = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    VOLUME_NAME_DOS,
                )
            };
            if ret == 0 {
                return Err(UpdaterError::UnsafePath(format!(
                    "GetFinalPathNameByHandleW failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let len = ret as usize;
            if len < buf.len() {
                let s = String::from_utf16(&buf[..len]).map_err(|_| {
                    UpdaterError::UnsafePath("GetFinalPathNameByHandleW returned invalid UTF-16".into())
                })?;
                return parse_strict_local_drive_path(Path::new(&s));
            }
            if len < 32_768 {
                cap = len.saturating_add(1);
                continue;
            }
            break;
        }
        Err(UpdaterError::UnsafePath(
            "GetFinalPathNameByHandleW exceeded maximum path buffer".to_string(),
        ))
    }

    fn get_file_info(handle: HANDLE) -> Result<ByHandleFileInformation, UpdaterError> {
        let mut info = std::mem::MaybeUninit::<ByHandleFileInformation>::zeroed();
        // SAFETY: `handle` is open and `info` points to writable `ByHandleFileInformation`.
        let ok = unsafe { GetFileInformationByHandle(handle, info.as_mut_ptr()) };
        if ok == FALSE {
            return Err(UpdaterError::UnsafePath(format!(
                "GetFileInformationByHandle failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `GetFileInformationByHandle` succeeded and initialized `info`.
        Ok(unsafe { info.assume_init() })
    }

    fn open_attribute_handle(
        verbatim_path: &Path,
        is_dir_or_unknown: bool,
    ) -> Result<Option<OwnedHandle>, UpdaterError> {
        let wide = encode_wide_nul(verbatim_path)?;
        let share_all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        let flags = if is_dir_or_unknown {
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS
        } else {
            FILE_FLAG_OPEN_REPARSE_POINT
        };
        // SAFETY: `wide` is NUL-terminated UTF-16; attribute-only access never follows reparse points.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                share_all,
                ptr::null(),
                OPEN_EXISTING,
                flags,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            // SAFETY: `GetLastError` reads thread-local Win32 error immediately after failure.
            let code = unsafe { GetLastError() };
            if is_not_found_code(code) {
                return Ok(None);
            }
            return Err(UpdaterError::UnsafePath(format!(
                "CreateFileW({verbatim_path:?}) attribute open failed: {}",
                std::io::Error::from_raw_os_error(code as i32)
            )));
        }
        Ok(Some(OwnedHandle(raw)))
    }

    fn verify_existing_component(
        drive: char,
        segments: &[String],
        prefix_len: usize,
        must_be_dir: bool,
    ) -> Result<bool, UpdaterError> {
        let current = build_verbatim_drive_path(drive, &segments[..prefix_len]);
        let wide = encode_wide_nul(&current)?;
        // SAFETY: `wide` is NUL-terminated UTF-16; `GetFileAttributesW` does not traverse a trailing reparse point.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let code = unsafe { GetLastError() };
            if is_not_found_code(code) {
                return Ok(false);
            }
            return Err(UpdaterError::UnsafePath(format!(
                "GetFileAttributesW({current:?}) failed: {}",
                std::io::Error::from_raw_os_error(code as i32)
            )));
        }
        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "reparse point rejected at {current:?}"
            )));
        }
        if must_be_dir && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "expected directory at {current:?}"
            )));
        }

        let Some(handle) = open_attribute_handle(&current, true)? else {
            return Ok(false);
        };
        let info = get_file_info(handle.0)?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "reparse point handle rejected at {current:?}"
            )));
        }
        if must_be_dir && (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "expected directory handle at {current:?}"
            )));
        }
        let final_dos = query_final_path_dos(handle.0)?;
        let expected_long = expand_long_segments(drive, &segments[..prefix_len]);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(UpdaterError::UnsafePath(format!(
                "path {current:?} resolved outside expected hierarchy"
            )));
        }
        Ok(true)
    }

    pub(super) fn ensure_no_reparse_points(path: &Path) -> Result<(), UpdaterError> {
        let (drive, segments) = parse_strict_local_drive_path(path)?;
        let root_verbatim = build_verbatim_drive_path(drive, &[]);
        let root_wide = encode_wide_nul(&root_verbatim)?;
        // SAFETY: `root_wide` is NUL-terminated UTF-16 for `\\?\X:\`.
        let root_attrs = unsafe { GetFileAttributesW(root_wide.as_ptr()) };
        if root_attrs == INVALID_FILE_ATTRIBUTES {
            return Err(UpdaterError::UnsafePath(format!(
                "drive root {root_verbatim:?} inaccessible: {}",
                std::io::Error::last_os_error()
            )));
        }
        if (root_attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "drive root {root_verbatim:?} is a reparse point"
            )));
        }

        for prefix_len in 1..=segments.len() {
            let must_be_dir = prefix_len < segments.len();
            if !verify_existing_component(drive, &segments, prefix_len, must_be_dir)? {
                break;
            }
        }
        Ok(())
    }

    fn verify_existing_dir(drive: char, segments: &[String]) -> Result<(char, Vec<String>), UpdaterError> {
        let dir_verbatim = build_verbatim_drive_path(drive, segments);
        let Some(handle) = open_attribute_handle(&dir_verbatim, true)? else {
            return Err(UpdaterError::UnsafePath(format!(
                "directory {dir_verbatim:?} does not exist"
            )));
        };
        let info = get_file_info(handle.0)?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "directory {dir_verbatim:?} is a reparse point"
            )));
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            return Err(UpdaterError::UnsafePath(format!(
                "path {dir_verbatim:?} is not a directory"
            )));
        }
        let final_dos = query_final_path_dos(handle.0)?;
        let expected_long = expand_long_segments(drive, segments);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(UpdaterError::UnsafePath(format!(
                "directory {dir_verbatim:?} resolved outside expected hierarchy"
            )));
        }
        Ok(final_dos)
    }

    fn create_dir_all_no_reparse(dir: &Path) -> Result<(char, Vec<String>), UpdaterError> {
        ensure_no_reparse_points(dir)?;
        let (drive, segments) = parse_strict_local_drive_path(dir)?;
        if segments.is_empty() {
            return Err(UpdaterError::UnsafePath(
                "cannot use bare drive root as staging/destination directory".to_string(),
            ));
        }

        for prefix_len in 1..=segments.len() {
            let prefix_verbatim = build_verbatim_drive_path(drive, &segments[..prefix_len]);
            match std::fs::create_dir(&prefix_verbatim) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => return Err(UpdaterError::Io(err)),
            }
            if !verify_existing_component(drive, &segments, prefix_len, true)? {
                return Err(UpdaterError::UnsafePath(format!(
                    "directory disappeared during creation: {prefix_verbatim:?}"
                )));
            }
        }
        verify_existing_dir(drive, &segments)
    }

    pub(super) fn create_session_dir(root: &Path) -> Result<(Uuid, PathBuf), UpdaterError> {
        let root_final = create_dir_all_no_reparse(root)?;
        let (drive, mut segments) = parse_strict_local_drive_path(root)?;
        let session_id = Uuid::new_v4();
        let session_seg = session_id.to_string();
        segments.push(session_seg.clone());

        let session_verbatim = build_verbatim_drive_path(drive, &segments);
        std::fs::create_dir(&session_verbatim)?;

        let session_final = verify_existing_dir(drive, &segments).inspect_err(|_| {
            let _ = std::fs::remove_dir(&session_verbatim);
        })?;

        let mut expected_final_segs = root_final.1;
        expected_final_segs.push(session_seg);
        if !paths_equal_case_insensitive(
            (session_final.0, &session_final.1),
            (root_final.0, &expected_final_segs),
        ) {
            let _ = std::fs::remove_dir(&session_verbatim);
            return Err(UpdaterError::UnsafePath(format!(
                "created session directory {session_verbatim:?} escaped root"
            )));
        }

        Ok((session_id, build_display_drive_path(drive, &segments)))
    }

    pub(super) fn create_exclusive_file(path: &Path) -> Result<File, UpdaterError> {
        let leaf = validate_file_path_leaf(path)?;
        ensure_no_reparse_points(path)?;
        let (drive, segments) = parse_strict_local_drive_path(path)?;
        if segments.is_empty() {
            return Err(UpdaterError::UnsafePath(
                "file path must include a filename".to_string(),
            ));
        }
        let parent_segs = &segments[..segments.len() - 1];
        if parent_segs.is_empty() {
            return Err(UpdaterError::UnsafePath(
                "refusing to create file directly at drive root".to_string(),
            ));
        }
        let parent_final = verify_existing_dir(drive, parent_segs)?;

        let verbatim = build_verbatim_drive_path(drive, &segments);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&verbatim)?;

        let verify_result = (|| -> Result<(), UpdaterError> {
            let raw_handle = file.as_raw_handle() as HANDLE;
            // SAFETY: `raw_handle` is the live handle owned by `file`.
            let file_type = unsafe { GetFileType(raw_handle) };
            if file_type != FILE_TYPE_DISK {
                return Err(UpdaterError::UnsafePath(format!(
                    "created file {verbatim:?} is not a disk file"
                )));
            }
            let info = get_file_info(raw_handle)?;
            if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
                || info.n_number_of_links != 1
            {
                return Err(UpdaterError::UnsafePath(format!(
                    "created file {verbatim:?} failed reparse/regular/link-count check"
                )));
            }
            let final_dos = query_final_path_dos(raw_handle)?;
            let mut expected_segs = parent_final.1;
            expected_segs.push(leaf);
            if !paths_equal_case_insensitive(
                (final_dos.0, &final_dos.1),
                (parent_final.0, &expected_segs),
            ) {
                return Err(UpdaterError::UnsafePath(format!(
                    "created file {verbatim:?} resolved outside parent directory"
                )));
            }
            Ok(())
        })();

        if let Err(err) = verify_result {
            drop(file);
            let _ = std::fs::remove_file(&verbatim);
            return Err(err);
        }

        Ok(file)
    }

    pub(super) fn atomic_write_file(dest_path: &Path, contents: &[u8]) -> Result<(), UpdaterError> {
        let leaf = validate_file_path_leaf(dest_path)?;
        ensure_no_reparse_points(dest_path)?;
        let (drive, segments) = parse_strict_local_drive_path(dest_path)?;
        if segments.len() < 2 {
            return Err(UpdaterError::UnsafePath(
                "destination file path must include a non-root parent directory".to_string(),
            ));
        }

        let parent_display = build_display_drive_path(drive, &segments[..segments.len() - 1]);
        let _ = create_dir_all_no_reparse(&parent_display)?;

        let tmp_name = format!(".{}.{}.tmp", leaf, Uuid::new_v4());
        let mut tmp_segs = segments[..segments.len() - 1].to_vec();
        tmp_segs.push(tmp_name);
        let tmp_display = build_display_drive_path(drive, &tmp_segs);
        let tmp_verbatim = build_verbatim_drive_path(drive, &tmp_segs);
        let dst_verbatim = build_verbatim_drive_path(drive, &segments);

        let mut tmp_file = create_exclusive_file(&tmp_display)?;
        if let Err(err) = tmp_file.write_all(contents).and_then(|_| tmp_file.sync_all()) {
            drop(tmp_file);
            let _ = std::fs::remove_file(&tmp_verbatim);
            return Err(UpdaterError::Io(err));
        }
        drop(tmp_file);

        // Re-verify destination hierarchy before atomic rename to catch concurrent junction/symlink swap.
        if let Err(err) = ensure_no_reparse_points(dest_path) {
            let _ = std::fs::remove_file(&tmp_verbatim);
            return Err(err);
        }

        let tmp_wide = encode_wide_nul(&tmp_verbatim).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_verbatim);
        })?;
        let dst_wide = encode_wide_nul(&dst_verbatim).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_verbatim);
        })?;

        // SAFETY: Both `tmp_wide` and `dst_wide` are NUL-terminated UTF-16 verbatim paths.
        let moved = unsafe {
            MoveFileExW(
                tmp_wide.as_ptr(),
                dst_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == FALSE {
            let err = std::io::Error::last_os_error();
            let _ = std::fs::remove_file(&tmp_verbatim);
            return Err(UpdaterError::Io(err));
        }
        Ok(())
    }

    pub(super) fn open_verified_read_file(path: &Path, max_bytes: u64) -> Result<File, UpdaterError> {
        let _ = validate_file_path_leaf(path)?;
        ensure_no_reparse_points(path)?;
        let (drive, segments) = parse_strict_local_drive_path(path)?;
        let leaf_verbatim = build_verbatim_drive_path(drive, &segments);

        let attr_handle = open_attribute_handle(&leaf_verbatim, false)?
            .ok_or_else(|| UpdaterError::Io(std::io::Error::from(ErrorKind::NotFound)))?;

        // SAFETY: `attr_handle.0` is an open Win32 handle.
        if unsafe { GetFileType(attr_handle.0) } != FILE_TYPE_DISK {
            return Err(UpdaterError::UnsafePath(format!(
                "file {leaf_verbatim:?} is not a regular disk file"
            )));
        }

        let info1 = get_file_info(attr_handle.0)?;
        if (info1.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info1.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || info1.n_number_of_links != 1
        {
            return Err(UpdaterError::UnsafePath(format!(
                "file {leaf_verbatim:?} failed reparse/regular/link-count verification"
            )));
        }
        let file_size = ((info1.n_file_size_high as u64) << 32) | (info1.n_file_size_low as u64);
        if file_size > max_bytes {
            return Err(UpdaterError::ResponseTooLarge {
                kind: "file",
                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                actual_bytes: file_size.min(usize::MAX as u64) as usize,
            });
        }

        let final_dos = query_final_path_dos(attr_handle.0)?;
        let expected_long = expand_long_segments(drive, &segments);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(UpdaterError::UnsafePath(format!(
                "file {leaf_verbatim:?} resolved outside expected path"
            )));
        }

        // Upgrade via `ReOpenFile` holding `FILE_SHARE_READ` to block concurrent writers while hashing.
        // SAFETY: `attr_handle.0` is a verified regular disk file handle.
        let read_raw = unsafe {
            ReOpenFile(
                attr_handle.0,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ,
                0,
            )
        };
        if read_raw == INVALID_HANDLE_VALUE {
            return Err(UpdaterError::Io(std::io::Error::last_os_error()));
        }
        let read_handle = OwnedHandle(read_raw);
        let info2 = get_file_info(read_handle.0)?;
        if (info2.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info2.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || info2.n_number_of_links != 1
            || info2.dw_volume_serial_number != info1.dw_volume_serial_number
            || info2.n_file_index_high != info1.n_file_index_high
            || info2.n_file_index_low != info1.n_file_index_low
        {
            return Err(UpdaterError::UnsafePath(format!(
                "file {leaf_verbatim:?} changed identity during handle upgrade"
            )));
        }

        // SAFETY: `read_handle` is a newly opened owned Win32 file handle.
        Ok(unsafe { File::from_raw_handle(read_handle.into_raw() as _) })
    }

    fn is_reparse_entry(verbatim_path: &Path) -> Result<bool, UpdaterError> {
        let wide = encode_wide_nul(verbatim_path)?;
        // SAFETY: `wide` is NUL-terminated UTF-16; `GetFileAttributesW` inspects the entry itself.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let code = unsafe { GetLastError() };
            if is_not_found_code(code) {
                return Ok(false);
            }
            return Err(UpdaterError::UnsafePath(format!(
                "GetFileAttributesW({verbatim_path:?}) failed: {}",
                std::io::Error::from_raw_os_error(code as i32)
            )));
        }
        Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    }

    fn remove_dir_all_no_reparse(dir_verbatim: &Path) -> Result<(), UpdaterError> {
        if is_reparse_entry(dir_verbatim)? {
            return Err(UpdaterError::UnsafePath(format!(
                "refusing to remove reparse directory {dir_verbatim:?}"
            )));
        }
        let Some(handle) = open_attribute_handle(dir_verbatim, true)? else {
            return Ok(());
        };
        let info = get_file_info(handle.0)?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        {
            return Err(UpdaterError::UnsafePath(format!(
                "refusing to recurse into non-regular directory {dir_verbatim:?}"
            )));
        }
        drop(handle);

        for entry_res in std::fs::read_dir(dir_verbatim)? {
            let entry = entry_res?;
            let child_path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_symlink() || is_reparse_entry(&child_path)? {
                return Err(UpdaterError::UnsafePath(format!(
                    "reparse child {child_path:?} encountered inside staging cleanup"
                )));
            }
            if ft.is_dir() {
                remove_dir_all_no_reparse(&child_path)?;
            } else {
                std::fs::remove_file(&child_path)?;
            }
        }
        std::fs::remove_dir(dir_verbatim)?;
        Ok(())
    }

    pub(super) fn cleanup_stale_staging_dirs(
        staging_root: &Path,
        max_age: Duration,
    ) -> Result<usize, UpdaterError> {
        let (drive, segments) = parse_strict_local_drive_path(staging_root)?;
        let root_verbatim = build_verbatim_drive_path(drive, &segments);
        let root_wide = encode_wide_nul(&root_verbatim)?;
        // SAFETY: `root_wide` is NUL-terminated UTF-16.
        let attrs = unsafe { GetFileAttributesW(root_wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let code = unsafe { GetLastError() };
            if is_not_found_code(code) {
                return Ok(0);
            }
            return Err(UpdaterError::Io(std::io::Error::from_raw_os_error(
                code as i32,
            )));
        }

        ensure_no_reparse_points(staging_root)?;
        let _ = verify_existing_dir(drive, &segments)?;

        let now = SystemTime::now();
        let mut removed = 0usize;

        for entry_res in std::fs::read_dir(&root_verbatim)? {
            let entry = entry_res?;
            let file_name_os = entry.file_name();
            let Some(file_name) = file_name_os.to_str() else {
                continue;
            };
            if Uuid::parse_str(file_name).is_err() {
                continue;
            }

            let entry_verbatim = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(err) if is_not_found_io(&err) => continue,
                Err(err) => return Err(UpdaterError::Io(err)),
            };

            if ft.is_symlink() || is_reparse_entry(&entry_verbatim)? {
                tracing::warn!(
                    path = %entry_verbatim.display(),
                    "skipping reparse point during staging cleanup"
                );
                continue;
            }
            if !ft.is_dir() {
                continue;
            }

            let meta = match std::fs::symlink_metadata(&entry_verbatim) {
                Ok(m) => m,
                Err(err) if is_not_found_io(&err) => continue,
                Err(err) => return Err(UpdaterError::Io(err)),
            };
            let ts = match meta.modified().or_else(|_| meta.created()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let Ok(age) = now.duration_since(ts) else {
                // Future timestamp: treat as fresh and never remove.
                continue;
            };
            if age < max_age {
                continue;
            }

            match remove_dir_all_no_reparse(&entry_verbatim) {
                Ok(()) => {
                    removed += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        path = %entry_verbatim.display(),
                        error = %err,
                        "failed to remove stale staging directory"
                    );
                }
            }
        }

        Ok(removed)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::io::ErrorKind;
    use std::path::Component;

    pub(super) fn ensure_no_reparse_points(path: &Path) -> Result<(), UpdaterError> {
        if !path.is_absolute() {
            return Err(UpdaterError::UnsafePath(format!(
                "path {path:?} must be absolute"
            )));
        }
        for comp in path.components() {
            if matches!(comp, Component::CurDir | Component::ParentDir) {
                return Err(UpdaterError::UnsafePath(format!(
                    "path {path:?} contains relative traversal"
                )));
            }
        }
        for ancestor in path.ancestors() {
            match std::fs::symlink_metadata(ancestor) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(UpdaterError::UnsafePath(format!(
                            "symlink rejected at {ancestor:?}"
                        )));
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(UpdaterError::Io(err)),
            }
        }
        Ok(())
    }

    pub(super) fn create_session_dir(root: &Path) -> Result<(Uuid, PathBuf), UpdaterError> {
        ensure_no_reparse_points(root)?;
        std::fs::create_dir_all(root)?;
        ensure_no_reparse_points(root)?;
        let id = Uuid::new_v4();
        let session_dir = root.join(id.to_string());
        std::fs::create_dir(&session_dir)?;
        Ok((id, session_dir))
    }

    pub(super) fn create_exclusive_file(path: &Path) -> Result<File, UpdaterError> {
        let _ = validate_file_path_leaf(path)?;
        ensure_no_reparse_points(path)?;
        Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
    }

    pub(super) fn atomic_write_file(dest_path: &Path, contents: &[u8]) -> Result<(), UpdaterError> {
        let leaf = validate_file_path_leaf(dest_path)?;
        ensure_no_reparse_points(dest_path)?;
        let parent = dest_path
            .parent()
            .ok_or_else(|| UpdaterError::UnsafePath("missing parent directory".to_string()))?;
        std::fs::create_dir_all(parent)?;
        ensure_no_reparse_points(parent)?;
        let tmp_path = parent.join(format!(".{}.{}.tmp", leaf, Uuid::new_v4()));
        let mut tmp_file = create_exclusive_file(&tmp_path)?;
        if let Err(err) = tmp_file.write_all(contents).and_then(|_| tmp_file.sync_all()) {
            drop(tmp_file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(UpdaterError::Io(err));
        }
        drop(tmp_file);
        if let Err(err) = ensure_no_reparse_points(dest_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Err(err) = std::fs::rename(&tmp_path, dest_path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(UpdaterError::Io(err));
        }
        Ok(())
    }

    pub(super) fn open_verified_read_file(path: &Path, max_bytes: u64) -> Result<File, UpdaterError> {
        let _ = validate_file_path_leaf(path)?;
        ensure_no_reparse_points(path)?;
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(UpdaterError::UnsafePath(format!(
                "path {path:?} is not a regular file"
            )));
        }
        if meta.len() > max_bytes {
            return Err(UpdaterError::ResponseTooLarge {
                kind: "file",
                limit_bytes: max_bytes.min(usize::MAX as u64) as usize,
                actual_bytes: meta.len().min(usize::MAX as u64) as usize,
            });
        }
        Ok(File::open(path)?)
    }

    pub(super) fn cleanup_stale_staging_dirs(
        staging_root: &Path,
        max_age: Duration,
    ) -> Result<usize, UpdaterError> {
        match std::fs::symlink_metadata(staging_root) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(0),
            Err(err) => return Err(UpdaterError::Io(err)),
        }
        ensure_no_reparse_points(staging_root)?;
        let now = SystemTime::now();
        let mut removed = 0usize;
        for entry_res in std::fs::read_dir(staging_root)? {
            let entry = entry_res?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if Uuid::parse_str(&name).is_err() {
                continue;
            }
            let ft = entry.file_type()?;
            if ft.is_symlink() || !ft.is_dir() {
                continue;
            }
            let meta = std::fs::symlink_metadata(entry.path())?;
            let Ok(ts) = meta.modified().or_else(|_| meta.created()) else {
                continue;
            };
            let Ok(age) = now.duration_since(ts) else {
                continue;
            };
            if age < max_age {
                continue;
            }
            if std::fs::remove_dir_all(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}
