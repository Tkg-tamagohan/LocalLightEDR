//! SDDL conversion and Windows security descriptor FFI for the Named Pipe IPC server.

use std::ffi::c_void;
use std::io::ErrorKind;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows::core::PWSTR;
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SDDL_REVISION_1: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SE_KERNEL_OBJECT: u32 = 6;
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Strict Named Pipe SDDL permitting full access to `SYSTEM` and `Administrators`,
/// and `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES` (`0x12019B`)
/// to `Interactive` users (`決定記録 L-09`, `SEC_0003` — omits `FILE_CREATE_PIPE_INSTANCE = 0x0004`).
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)";

/// Fail-closed Named Pipe SDDL used when `--dev-bypass-auth` is invoked under `LocalSystem`
/// (`S-1-5-18`), granting access only to `SYSTEM` and `Administrators` without exposing the pipe
/// to arbitrary interactive users.
pub const DEV_BYPASS_SYSTEM_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

struct OwnedTokenHandle(HANDLE);

impl Drop for OwnedTokenHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: Handle was opened by `OpenProcessToken` and is closed once on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct LocalWideGuard(*mut u16);

impl Drop for LocalWideGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Buffer was allocated by an Advapi32 conversion API and freed once via `LocalFree`.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 as *mut c_void)));
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

struct LocalVoidGuard(*mut c_void);

impl Drop for LocalVoidGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Buffer was allocated by `GetSecurityInfo` and freed once via `LocalFree`.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// Owned self-relative Windows security descriptor converted from SDDL (`L-09`).
pub struct PipeSecurityDescriptor {
    sd: PSECURITY_DESCRIPTOR,
    sd_len: u32,
}

// SAFETY: A converted Windows self-relative security descriptor is immutable raw buffer
// memory freed exactly once via `LocalFree` on `Drop` with no thread affinity.
unsafe impl Send for PipeSecurityDescriptor {}
// SAFETY: Shared references only expose read-only pointer metadata.
unsafe impl Sync for PipeSecurityDescriptor {}

impl PipeSecurityDescriptor {
    /// Parses an SDDL string into an owned Windows `SECURITY_DESCRIPTOR` via
    /// `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    pub fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw_sd: *mut c_void = std::ptr::null_mut();
        let mut sd_len: u32 = 0;

        // SAFETY: `sddl_w` is NUL-terminated UTF-16; `raw_sd` is owned and freed by `LocalFree`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut raw_sd,
                &mut sd_len,
            )
        };
        if ok == 0 || raw_sd.is_null() {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            sd: PSECURITY_DESCRIPTOR(raw_sd),
            sd_len,
        })
    }

    /// Returns a `SECURITY_ATTRIBUTES` struct referencing this security descriptor.
    /// The returned value must not outlive `self`.
    pub fn security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: false.into(),
        }
    }

    /// Returns the size in bytes of the converted self-relative security descriptor.
    pub fn byte_len(&self) -> u32 {
        self.sd_len
    }

    /// Formats the DACL back into an SDDL string via `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
    pub fn to_sddl_string(&self) -> std::io::Result<String> {
        security_descriptor_to_sddl(self.sd.0)
    }
}

impl Drop for PipeSecurityDescriptor {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            // SAFETY: `self.sd.0` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
            self.sd.0 = std::ptr::null_mut();
        }
    }
}

fn security_descriptor_to_sddl(sd: *const c_void) -> std::io::Result<String> {
    if sd.is_null() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "security descriptor pointer is null",
        ));
    }

    let mut string_sd: *mut u16 = std::ptr::null_mut();
    let mut string_sd_len: u32 = 0;
    // SAFETY: `sd` is a valid security descriptor pointer; `string_sd` is freed by `LocalWideGuard`.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut string_sd,
            &mut string_sd_len,
        )
    };
    if ok == 0 || string_sd.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = LocalWideGuard(string_sd);
    // SAFETY: `string_sd` contains at least `string_sd_len` UTF-16 code units.
    let slice = unsafe { std::slice::from_raw_parts(string_sd, string_sd_len as usize) };
    let nul_trimmed = slice.split(|&ch| ch == 0).next().unwrap_or(slice);
    Ok(String::from_utf16_lossy(nul_trimmed))
}

fn is_valid_numeric_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    let Some("S") = parts.next() else {
        return false;
    };
    let mut count = 0usize;
    for part in parts {
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    // Require at least revision and identifier authority (`S-<rev>-<auth>`).
    count >= 2
}

/// Queries the current process token user SID as a canonical string (e.g., `S-1-5-21-...`).
pub fn current_process_user_sid() -> std::io::Result<String> {
    let mut raw_token = HANDLE::default();
    // SAFETY: `GetCurrentProcess()` returns the pseudo-handle for this process; `raw_token` is closed by `OwnedTokenHandle`.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token)
            .map_err(std::io::Error::from)?;
    }
    let token = OwnedTokenHandle(raw_token);

    let mut needed: u32 = 0;
    // SAFETY: First call with `None` buffer queries required byte length for `TokenUser`.
    let first = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
    if let Err(err) = first {
        if err.code() != ERROR_INSUFFICIENT_BUFFER.to_hresult() {
            return Err(std::io::Error::from(err));
        }
    }
    let min_len = std::mem::size_of::<TOKEN_USER>() as u32;
    if needed < min_len {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("GetTokenInformation(TokenUser) returned invalid buffer size {needed}"),
        ));
    }

    let word_count = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut aligned_buf = vec![0usize; word_count];
    let mut returned_len: u32 = 0;
    // SAFETY: `aligned_buf` is properly aligned for `TOKEN_USER` and at least `needed` bytes long.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(aligned_buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut returned_len,
        )
        .map_err(std::io::Error::from)?;
    }
    if returned_len < min_len {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("GetTokenInformation(TokenUser) populated only {returned_len} bytes"),
        ));
    }

    // SAFETY: `aligned_buf` begins with a valid `TOKEN_USER` populated by `GetTokenInformation`.
    let token_user = unsafe { &*(aligned_buf.as_ptr() as *const TOKEN_USER) };
    if token_user.User.Sid.is_invalid() || token_user.User.Sid.0.is_null() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "TokenUser contained a null SID",
        ));
    }

    let mut string_sid: *mut u16 = std::ptr::null_mut();
    // SAFETY: `token_user.User.Sid.0` points into `aligned_buf`; `string_sid` is freed by `LocalWideGuard`.
    let ok = unsafe { ConvertSidToStringSidW(token_user.User.Sid.0, &mut string_sid) };
    if ok == 0 || string_sid.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = LocalWideGuard(string_sid);
    let sid_pwstr = PWSTR(string_sid);
    // SAFETY: `ConvertSidToStringSidW` returns a NUL-terminated UTF-16 string.
    let wide = unsafe { sid_pwstr.as_wide() };
    Ok(String::from_utf16_lossy(wide))
}

/// Formats the strict Named Pipe SDDL for `--dev-bypass-auth` mode scoped to `user_sid`.
///
/// Omits `IU` (all Interactive Users) so other interactive Windows accounts cannot connect
/// to a `--dev-bypass-auth` daemon. When `user_sid` is `S-1-5-18` (`LocalSystem`), fails
/// closed to [`DEV_BYPASS_SYSTEM_PIPE_SDDL`] (`SYSTEM` and `Administrators` only).
pub fn format_dev_bypass_pipe_sddl(user_sid: &str) -> std::io::Result<String> {
    let sid = user_sid.trim();
    if !is_valid_numeric_sid(sid) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid Windows SID for dev-bypass pipe DACL: {user_sid:?}"),
        ));
    }
    if sid.eq_ignore_ascii_case(LOCAL_SYSTEM_SID) {
        return Ok(DEV_BYPASS_SYSTEM_PIPE_SDDL.to_string());
    }
    Ok(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;{sid})"))
}

/// Builds the Phase 2+ production strict Named Pipe security descriptor (`SERVICE_PIPE_SDDL`, `L-09`).
pub fn build_service_pipe_security_descriptor() -> std::io::Result<PipeSecurityDescriptor> {
    PipeSecurityDescriptor::from_sddl(SERVICE_PIPE_SDDL)
}

/// Builds the `--dev-bypass-auth` strict Named Pipe security descriptor for an explicit user SID.
pub fn build_dev_bypass_pipe_security_descriptor_for_sid(
    user_sid: &str,
) -> std::io::Result<PipeSecurityDescriptor> {
    let sddl = format_dev_bypass_pipe_sddl(user_sid)?;
    PipeSecurityDescriptor::from_sddl(&sddl)
}

/// Builds the `--dev-bypass-auth` strict Named Pipe security descriptor scoped to the current
/// process token user SID (or fail-closed `SYSTEM`/`Administrators` only under `S-1-5-18`).
pub fn build_dev_bypass_pipe_security_descriptor() -> std::io::Result<PipeSecurityDescriptor> {
    let sid = current_process_user_sid()?;
    build_dev_bypass_pipe_security_descriptor_for_sid(&sid)
}

/// Selects the appropriate strict Named Pipe security descriptor based on `dev_mode_bypass_ui_auth`.
pub(super) fn build_strict_pipe_security_descriptor(
    dev_mode_bypass_ui_auth: bool,
) -> std::io::Result<PipeSecurityDescriptor> {
    if dev_mode_bypass_ui_auth {
        build_dev_bypass_pipe_security_descriptor()
    } else {
        build_service_pipe_security_descriptor()
    }
}

/// Returns the canonical SDDL trustee string (either a numeric SID or a Windows well-known
/// SDDL alias such as `LA` for local built-in Administrator RID `-500` or `LS` for `S-1-5-19`)
/// emitted by `ConvertSecurityDescriptorToStringSecurityDescriptorW` for `user_sid`.
pub fn canonical_sddl_trustee_for_sid(user_sid: &str) -> std::io::Result<String> {
    let sid = user_sid.trim();
    if !is_valid_numeric_sid(sid) {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid Windows SID for SDDL trustee lookup: {user_sid:?}"),
        ));
    }
    let probe = PipeSecurityDescriptor::from_sddl(&format!("D:P(A;;0x12019B;;;{sid})"))?;
    let roundtrip = probe.to_sddl_string()?;
    let ace = roundtrip
        .split('(')
        .nth(1)
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("unexpected single-ACE SDDL roundtrip: {roundtrip}"),
            )
        })?;
    let trustee = ace
        .split(';')
        .nth(5)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                ErrorKind::InvalidData,
                format!("missing trustee in SDDL roundtrip ACE: {ace}"),
            )
        })?;
    Ok(trustee.to_string())
}

/// Reads the live DACL of a Windows kernel object handle (such as a Named Pipe opened with
/// `READ_CONTROL`) and formats it as an SDDL string.
pub fn read_kernel_object_dacl_sddl(handle: BorrowedHandle<'_>) -> std::io::Result<String> {
    let raw_handle = handle.as_raw_handle();
    if raw_handle.is_null() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "kernel object handle is null",
        ));
    }
    let mut raw_dacl: *mut c_void = std::ptr::null_mut();
    let mut raw_sd: *mut c_void = std::ptr::null_mut();
    // SAFETY: `handle` is a live OS handle for the duration of this call; `raw_sd` is freed by `LocalVoidGuard`.
    let status = unsafe {
        GetSecurityInfo(
            raw_handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut raw_dacl,
            std::ptr::null_mut(),
            &mut raw_sd,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    if raw_sd.is_null() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "GetSecurityInfo succeeded but returned a null security descriptor",
        ));
    }
    let _guard = LocalVoidGuard(raw_sd);
    security_descriptor_to_sddl(raw_sd)
}

#[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        security_descriptor: *const c_void,
        requested_string_sd_revision: u32,
        security_information: u32,
        string_security_descriptor: *mut *mut u16,
        string_security_descriptor_len: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        security_info: u32,
        ppsid_owner: *mut *mut c_void,
        ppsid_group: *mut *mut c_void,
        pp_dacl: *mut *mut c_void,
        pp_sacl: *mut *mut c_void,
        pp_security_descriptor: *mut *mut c_void,
    ) -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ace_hex_mask(sddl: &str, trustee: &str) -> u32 {
        let suffix = format!(";;;{trustee})");
        let ace = sddl
            .split('(')
            .find(|part| part.contains(&suffix))
            .unwrap_or_else(|| panic!("expected ACE for trustee {trustee} in SDDL: {sddl}"));
        let rights = ace
            .split(';')
            .nth(2)
            .unwrap_or_else(|| panic!("missing rights field in ACE: {ace}"));
        let hex = rights
            .strip_prefix("0x")
            .or_else(|| rights.strip_prefix("0X"))
            .unwrap_or_else(|| panic!("expected hex rights mask for {trustee}, got {ace}"));
        u32::from_str_radix(hex, 16)
            .unwrap_or_else(|e| panic!("failed to parse hex mask {rights} in {ace}: {e}"))
    }

    #[test]
    fn ipc_dacl_02_dev_bypass_sddl_restricts_to_current_user_sid_without_iu() {
        let sample_sid = "S-1-5-21-3623811015-3361044348-30300820-1013";
        let formatted = format_dev_bypass_pipe_sddl(sample_sid).expect("format dev-bypass SDDL");
        assert_eq!(
            formatted,
            format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;{sample_sid})")
        );
        assert!(!formatted.contains(";;;IU)"));

        let sd = build_dev_bypass_pipe_security_descriptor_for_sid(sample_sid)
            .expect("build dev-bypass SD for sample SID");
        let roundtrip = sd.to_sddl_string().expect("roundtrip dev-bypass SDDL");
        assert!(
            !roundtrip.contains(";;;IU)"),
            "dev-bypass DACL must not grant Interactive Users: {roundtrip}"
        );
        assert!(roundtrip.contains("(A;;GA;;;SY)"));
        assert!(roundtrip.contains("(A;;GA;;;BA)"));
        let mask = parse_ace_hex_mask(&roundtrip, sample_sid);
        assert_eq!(
            mask & 0x0004,
            0,
            "dev-bypass user ACE must exclude FILE_CREATE_PIPE_INSTANCE (0x0004): {roundtrip}"
        );
        assert_eq!(mask & 0x0012_019B, 0x0012_019B);

        // Well-known SID canonicalization: Windows serializes SIDs like S-1-5-19 (`LS`) and the
        // local machine's built-in Administrator RID `-500` (`LA`, e.g., GitHub Actions runneradmin)
        // using 2-letter SDDL aliases. Verify both canonicalization and ACE rights.
        let local_service_trustee =
            canonical_sddl_trustee_for_sid("S-1-5-19").expect("canonicalize S-1-5-19");
        assert_eq!(local_service_trustee, "LS");
        let ls_sd = build_dev_bypass_pipe_security_descriptor_for_sid("S-1-5-19")
            .expect("build dev-bypass SD for S-1-5-19");
        let ls_sddl = ls_sd.to_sddl_string().expect("roundtrip S-1-5-19 SDDL");
        assert!(!ls_sddl.contains(";;;IU)"));
        let ls_mask = parse_ace_hex_mask(&ls_sddl, &local_service_trustee);
        assert_eq!(ls_mask & 0x0004, 0);
        assert_eq!(ls_mask & 0x0012_019B, 0x0012_019B);

        // Live process user SID path (handles both numeric SIDs and well-known aliases like `LA`).
        let current_sid = current_process_user_sid().expect("query current process user SID");
        assert!(
            is_valid_numeric_sid(&current_sid),
            "unexpected current process SID: {current_sid}"
        );
        let live_sd = build_dev_bypass_pipe_security_descriptor()
            .expect("build dev-bypass SD for current user");
        let live_sddl = live_sd.to_sddl_string().expect("roundtrip live dev-bypass SDDL");
        assert!(
            !live_sddl.contains(";;;IU)"),
            "live dev-bypass DACL must not contain IU: {live_sddl}"
        );
        assert!(live_sddl.contains("(A;;GA;;;SY)"));
        assert!(live_sddl.contains("(A;;GA;;;BA)"));
        if !current_sid.eq_ignore_ascii_case(LOCAL_SYSTEM_SID) {
            let expected_trustee = canonical_sddl_trustee_for_sid(&current_sid)
                .expect("canonicalize current process user SID");
            assert_ne!(
                expected_trustee, "IU",
                "current process SID must never map to Interactive Users"
            );
            assert_eq!(
                live_sddl.matches('(').count(),
                3,
                "live dev-bypass DACL must contain exactly 3 ACEs (SY, BA, current user): {live_sddl}"
            );
            let live_mask = parse_ace_hex_mask(&live_sddl, &expected_trustee);
            assert_eq!(live_mask & 0x0004, 0);
            assert_eq!(live_mask & 0x0012_019B, 0x0012_019B);
        }

        // Explicitly exercise the local machine's built-in Administrator SID (`...-500` -> `LA`)
        // when running under a standard S-1-5-21-* account so CI `runneradmin` canonicalization
        // is verified on developer workstations too.
        let parts: Vec<&str> = current_sid.split('-').collect();
        if parts.len() == 8 && parts[0] == "S" && parts[1] == "1" && parts[2] == "5" && parts[3] == "21" {
            let local_admin_sid = format!(
                "S-1-5-21-{}-{}-{}-500",
                parts[4], parts[5], parts[6]
            );
            let la_trustee = canonical_sddl_trustee_for_sid(&local_admin_sid)
                .expect("canonicalize local built-in admin SID");
            let la_sd = build_dev_bypass_pipe_security_descriptor_for_sid(&local_admin_sid)
                .expect("build dev-bypass SD for local built-in admin SID");
            let la_sddl = la_sd.to_sddl_string().expect("roundtrip local admin SDDL");
            assert!(!la_sddl.contains(";;;IU)"));
            let la_mask = parse_ace_hex_mask(&la_sddl, &la_trustee);
            assert_eq!(la_mask & 0x0004, 0);
            assert_eq!(la_mask & 0x0012_019B, 0x0012_019B);
        }
    }

    #[test]
    fn ipc_dacl_03_dev_bypass_sddl_fails_closed_for_system_and_rejects_invalid_sid() {
        let system_sddl =
            format_dev_bypass_pipe_sddl("S-1-5-18").expect("format LocalSystem dev-bypass SDDL");
        assert_eq!(system_sddl, DEV_BYPASS_SYSTEM_PIPE_SDDL);
        assert_eq!(system_sddl, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert!(!system_sddl.contains(";;;IU)"));
        assert!(!system_sddl.contains("0x12019B"));

        let sd = build_dev_bypass_pipe_security_descriptor_for_sid("S-1-5-18")
            .expect("build LocalSystem fail-closed SD");
        let roundtrip = sd.to_sddl_string().expect("roundtrip LocalSystem SDDL");
        assert!(roundtrip.contains("(A;;GA;;;SY)"));
        assert!(roundtrip.contains("(A;;GA;;;BA)"));
        assert!(
            !roundtrip.contains(";;;IU)"),
            "LocalSystem fail-closed DACL must not contain IU: {roundtrip}"
        );
        assert!(
            !roundtrip.to_ascii_lowercase().contains("0x12019b"),
            "LocalSystem fail-closed DACL must not grant 0x12019B: {roundtrip}"
        );

        for invalid in ["", "   ", "IU", "S-1", "S-1-5-abc", "S-1-5-21-1)(A;;GA;;;WD"] {
            let err = format_dev_bypass_pipe_sddl(invalid)
                .expect_err(&format!("expected invalid SID rejection for {invalid:?}"));
            assert_eq!(err.kind(), ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn ipc_dacl_04_production_service_pipe_sddl_unchanged() {
        assert_eq!(
            SERVICE_PIPE_SDDL,
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)"
        );
        let sd = build_strict_pipe_security_descriptor(false)
            .expect("build production strict SD");
        let roundtrip = sd.to_sddl_string().expect("roundtrip production SDDL");
        assert!(roundtrip.contains("(A;;GA;;;SY)"));
        assert!(roundtrip.contains("(A;;GA;;;BA)"));
        let mask = parse_ace_hex_mask(&roundtrip, "IU");
        assert_eq!(mask & 0x0004, 0);
        assert_eq!(mask & 0x0012_019B, 0x0012_019B);
    }
}
