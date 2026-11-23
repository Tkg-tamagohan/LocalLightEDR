//! Never-Suspend and `CreationTime` target process safety validation (`AUTO-02`, `AUTO-03`).

use ledr_proto::{ProcessIdentity, is_never_suspend_process};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use super::process_probe::{
    OpenProcessError, find_process_exe_toolhelp32, open_process_checked_detailed,
    query_full_image_name, query_process_creation_time,
};

#[derive(Debug, Clone)]
pub(crate) struct ValidatedTarget {
    pub(crate) identity: ProcessIdentity,
    pub(crate) exe_path: String,
}

#[derive(Debug, Clone)]
pub(super) enum TargetValidationError {
    /// Forbidden PID (0, 4, self), Never-Suspend protected process, or unverified `create_time_100ns == 0`.
    PolicyRejected(String),
    /// Live process at `target.pid` has a different `CreationTime` (PID reuse).
    IdentityMismatch(String),
    /// Target process could not be opened or queried (e.g. already exited).
    Unavailable(String),
}

impl TargetValidationError {
    fn into_message(self) -> String {
        match self {
            Self::PolicyRejected(msg)
            | Self::IdentityMismatch(msg)
            | Self::Unavailable(msg) => msg,
        }
    }
}

/// Validates that `target` is safe to suspend, resume, or terminate (`AUTO-02`, `AUTO-03`):
///
/// 1. Rejects `pid == 0`, `pid == 4`, and `pid == std::process::id()`.
/// 2. Resolves the image path (`QueryFullProcessImageNameW` with Toolhelp32 fallback) and rejects
///    any [`ledr_proto::is_never_suspend_process`] match.
/// 3. Requires a non-zero `target.create_time_100ns` and verifies `GetProcessTimes` `CreationTime`
///    matches it to prevent PID reuse errors.
pub fn validate_target_process(target: &ProcessIdentity) -> Result<(), String> {
    validate_and_inspect_target(target).map(|_| ())
}

pub(super) fn validate_and_inspect_target(target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
    validate_and_inspect_target_detailed(target).map_err(TargetValidationError::into_message)
}

pub(super) fn validate_and_inspect_target_detailed(
    target: &ProcessIdentity,
) -> Result<ValidatedTarget, TargetValidationError> {
    let self_pid = std::process::id();
    validate_pid_basics(target.pid, self_pid)
        .map_err(TargetValidationError::PolicyRejected)?;
    validate_live_pid_aliases(target.pid, self_pid)
        .map_err(TargetValidationError::PolicyRejected)?;

    let handle = match open_process_checked_detailed(target.pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(h) => h,
        Err(OpenProcessError::PidZero) => {
            return Err(TargetValidationError::PolicyRejected(
                "refusing to act on Idle process (PID 0)".to_string(),
            ));
        }
        Err(OpenProcessError::PidMismatch { requested, actual }) => {
            return Err(TargetValidationError::PolicyRejected(format!(
                "refusing to act on aliased PID {requested}: OpenProcess(PID {requested}) resolved to mismatched PID {actual}"
            )));
        }
        Err(OpenProcessError::Failed(open_err)) => {
            let fallback_exe = find_process_exe_toolhelp32(target.pid).or_else(|| {
                (target.pid & 3 != 0)
                    .then(|| find_process_exe_toolhelp32(target.pid & !3))
                    .flatten()
            });
            if let Some(fallback_exe) = fallback_exe {
                if is_never_suspend_process(&fallback_exe) {
                    return Err(TargetValidationError::PolicyRejected(format!(
                        "refusing to act on protected process `{fallback_exe}` (PID {})",
                        target.pid
                    )));
                }
            }
            if target.create_time_100ns == 0 {
                return Err(TargetValidationError::PolicyRejected(format!(
                    "refusing active defense on PID {}: create_time_100ns is 0 (unverified identity)",
                    target.pid
                )));
            }
            return Err(TargetValidationError::Unavailable(open_err));
        }
    };

    validate_open_handle_detailed(handle.as_raw(), target)
}

fn validate_live_pid_aliases(pid: u32, self_pid: u32) -> Result<(), String> {
    let canonical = pid & !3;
    if canonical == 0 {
        return Err(format!("refusing to act on Idle process alias (PID {pid})"));
    }
    if canonical == 4 {
        return Err(format!("refusing to act on System process alias (PID {pid})"));
    }
    if canonical == (self_pid & !3) {
        return Err(format!("refusing to act on self process alias (PID {pid})"));
    }
    Ok(())
}

fn validate_pid_basics(pid: u32, self_pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("refusing to act on Idle process (PID 0)".to_string());
    }
    if pid == 4 {
        return Err("refusing to act on System process (PID 4)".to_string());
    }
    if pid == self_pid {
        return Err(format!("refusing to act on self process (PID {pid})"));
    }
    Ok(())
}

pub(super) fn validate_open_handle(handle: HANDLE, target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
    validate_open_handle_detailed(handle, target).map_err(TargetValidationError::into_message)
}

pub(super) fn validate_open_handle_detailed(
    handle: HANDLE,
    target: &ProcessIdentity,
) -> Result<ValidatedTarget, TargetValidationError> {
    let exe_path = query_full_image_name(handle).ok_or_else(|| {
        TargetValidationError::Unavailable(format!(
            "unable to resolve image name for PID {}; refusing action fail-closed",
            target.pid
        ))
    })?;

    let actual_create_time = query_process_creation_time(handle);
    if let Err(err) = validate_process_metadata(
        target.pid,
        std::process::id(),
        Some(&exe_path),
        target.create_time_100ns,
        actual_create_time,
    ) {
        if target.create_time_100ns == 0
            || is_never_suspend_process(&exe_path)
            || validate_pid_basics(target.pid, std::process::id()).is_err()
        {
            return Err(TargetValidationError::PolicyRejected(err));
        }
        if actual_create_time.is_none() {
            return Err(TargetValidationError::Unavailable(err));
        }
        return Err(TargetValidationError::IdentityMismatch(err));
    }

    let resolved_create_time = actual_create_time.unwrap_or(target.create_time_100ns);
    Ok(ValidatedTarget {
        identity: ProcessIdentity::new(target.pid, resolved_create_time),
        exe_path,
    })
}

pub(super) fn validate_process_metadata(
    pid: u32,
    self_pid: u32,
    exe_path: Option<&str>,
    expected_create_time_100ns: u64,
    actual_create_time_100ns: Option<u64>,
) -> Result<(), String> {
    validate_pid_basics(pid, self_pid)?;

    let exe = exe_path.ok_or_else(|| format!("missing image path for PID {pid}"))?;
    if is_never_suspend_process(exe) {
        return Err(format!(
            "refusing to act on protected process `{exe}` (PID {pid})"
        ));
    }

    if expected_create_time_100ns == 0 {
        return Err(format!(
            "refusing active defense on PID {pid} (`{exe}`): create_time_100ns is 0 (unverified identity)"
        ));
    }

    let actual = actual_create_time_100ns.ok_or_else(|| {
        format!("unable to query CreationTime for PID {pid} to verify ProcessIdentity")
    })?;
    if actual != expected_create_time_100ns {
        return Err(format!(
            "CreationTime mismatch for PID {pid} (expected {expected_create_time_100ns}, actual {actual}): possible PID reuse"
        ));
    }

    Ok(())
}
