//! Token privilege enablement (`SeSystemProfilePrivilege`, `SeDebugPrivilege`,
//! `SeSecurityPrivilege`) for Layer 1 ETW and process inspection (`AUTO-13`).

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_NOT_ALL_ASSIGNED, ERROR_SUCCESS, GetLastError, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_DEBUG_NAME,
    SE_PRIVILEGE_ENABLED, SE_SECURITY_NAME, SE_SYSTEM_PROFILE_NAME, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::OwnedHandle;

/// Outcome of attempting to enable required privileges on the current process token (`AUTO-13`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegeReport {
    pub system_profile: bool,
    pub debug: bool,
    pub security: bool,
    pub error_message: Option<String>,
}

impl PrivilegeReport {
    /// Returns `true` if all three required privileges were enabled.
    pub const fn all_enabled(&self) -> bool {
        self.system_profile && self.debug && self.security
    }
}

/// Attempts to enable `SeSystemProfilePrivilege`, `SeDebugPrivilege`, and `SeSecurityPrivilege`
/// on the current process token (`AUTO-13`).
///
/// Non-elevated executions are handled gracefully without panicking: unavailable privileges
/// remain `false` and diagnostic details are recorded in `error_message`.
pub fn enable_required_privileges() -> PrivilegeReport {
    let mut raw_token = HANDLE::default();
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle to the current process;
    // `raw_token` is valid writable storage for the opened token handle.
    let open_res = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut raw_token,
        )
    };
    if let Err(err) = open_res {
        let msg = format!("OpenProcessToken failed: {err}");
        tracing::warn!("{msg}");
        return PrivilegeReport {
            system_profile: false,
            debug: false,
            security: false,
            error_message: Some(msg),
        };
    }

    let Some(token) = OwnedHandle::new(raw_token) else {
        let msg = "OpenProcessToken returned an invalid handle".to_string();
        tracing::warn!("{msg}");
        return PrivilegeReport {
            system_profile: false,
            debug: false,
            security: false,
            error_message: Some(msg),
        };
    };

    let mut errors = Vec::new();

    let system_profile = match enable_single_privilege(
        token.as_raw(),
        SE_SYSTEM_PROFILE_NAME,
        "SeSystemProfilePrivilege",
    ) {
        Ok(()) => true,
        Err(err) => {
            errors.push(err);
            false
        }
    };

    let debug = match enable_single_privilege(token.as_raw(), SE_DEBUG_NAME, "SeDebugPrivilege") {
        Ok(()) => true,
        Err(err) => {
            errors.push(err);
            false
        }
    };

    let security =
        match enable_single_privilege(token.as_raw(), SE_SECURITY_NAME, "SeSecurityPrivilege") {
            Ok(()) => true,
            Err(err) => {
                errors.push(err);
                false
            }
        };

    let error_message = if errors.is_empty() {
        tracing::debug!("all required ETW/process privileges enabled");
        None
    } else {
        let joined = errors.join("; ");
        tracing::debug!(error = %joined, "not all privileges could be enabled (expected if non-elevated)");
        Some(joined)
    };

    PrivilegeReport {
        system_profile,
        debug,
        security,
        error_message,
    }
}

fn enable_single_privilege(
    token: HANDLE,
    privilege_name: PCWSTR,
    label: &str,
) -> Result<(), String> {
    let mut luid = LUID::default();
    // SAFETY: `privilege_name` is a valid null-terminated UTF-16 constant from `windows::Win32::Security`
    // and `luid` points to stack-allocated writable memory.
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut luid) }
        .map_err(|err| format!("{label}: LookupPrivilegeValueW failed: {err}"))?;

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` is a valid open process token handle with `TOKEN_ADJUST_PRIVILEGES`,
    // and `tp` is a properly initialized `TOKEN_PRIVILEGES` struct with `PrivilegeCount == 1`.
    let adjust_res = unsafe { AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None) };
    // SAFETY: `GetLastError` reads the thread-local Win32 error code set by `AdjustTokenPrivileges`.
    let last_err = unsafe { GetLastError() };

    if let Err(err) = adjust_res {
        return Err(format!("{label}: AdjustTokenPrivileges failed: {err}"));
    }
    if last_err == ERROR_NOT_ALL_ASSIGNED {
        return Err(format!("{label}: not assigned (ERROR_NOT_ALL_ASSIGNED)"));
    }
    if last_err != ERROR_SUCCESS {
        return Err(format!("{label}: Win32 error {}", last_err.0));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sens_04_enable_required_privileges_non_panicking() {
        let report = enable_required_privileges();
        if report.all_enabled() {
            assert_eq!(report.error_message, None);
        } else {
            assert!(
                report.error_message.is_some(),
                "expected diagnostic error_message when privileges are missing"
            );
        }
    }
}
