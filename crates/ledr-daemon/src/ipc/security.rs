//! SDDL conversion and Windows security descriptor FFI for the Named Pipe IPC server.

use std::ffi::c_void;

use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

const SDDL_REVISION_1: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

/// Strict Named Pipe SDDL permitting full access to `SYSTEM` and `Administrators`,
/// and `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES` (`0x12019B`)
/// to `Interactive` users (`決定記録 L-09`, `SEC_0003` — omits `FILE_CREATE_PIPE_INSTANCE = 0x0004`).
pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)";

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
        struct LocalWideGuard(*mut u16);
        impl Drop for LocalWideGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: Buffer was allocated by `ConvertSecurityDescriptorToStringSecurityDescriptorW`.
                    unsafe {
                        let _ = LocalFree(Some(HLOCAL(self.0 as *mut c_void)));
                    }
                    self.0 = std::ptr::null_mut();
                }
            }
        }

        let mut string_sd: *mut u16 = std::ptr::null_mut();
        let mut string_sd_len: u32 = 0;
        // SAFETY: `self.sd.0` is a valid self-relative security descriptor; `string_sd` is freed by `LocalWideGuard`.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.sd.0,
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

/// Builds the Phase 2+ strict Named Pipe security descriptor (`SERVICE_PIPE_SDDL`, `L-09`).
pub fn build_service_pipe_security_descriptor() -> std::io::Result<PipeSecurityDescriptor> {
    PipeSecurityDescriptor::from_sddl(SERVICE_PIPE_SDDL)
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
}
