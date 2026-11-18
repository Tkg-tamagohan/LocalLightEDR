//! Session 0 toast notification dispatcher (`決定記録 L-08`).
//!
//! Keeps resident UI memory at 0 MB by launching `ledr-ui.exe --notify <alert_id>` as a
//! one-shot Medium Integrity process in the active console user's desktop session via
//! `WTSGetActiveConsoleSessionId` -> `WTSQueryUserToken` -> `DuplicateTokenEx` ->
//! `CreateProcessAsUserW`, with graceful fallback for `--foreground` dev sessions.

use std::ffi::{c_void, OsStr};
use std::io::ErrorKind;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;

use ledr_proto::{AlertRecord, AUTHORIZED_UI_EXE_PATH};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
};
use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    STARTUPINFOW,
};

const WTS_NO_CONSOLE_SESSION: u32 = 0xFFFF_FFFF;

/// Abstraction boundary for dispatching alert notifications (`L-08`).
pub trait NotificationDispatcher: Send + Sync {
    fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String>;
}

/// Headless no-op [`NotificationDispatcher`] for unit tests and non-GUI harnesses.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNotificationDispatcher;

impl NotificationDispatcher for NoopNotificationDispatcher {
    fn notify_alert(&self, _alert: &AlertRecord) -> Result<(), String> {
        Ok(())
    }
}

/// Launches `ledr-ui.exe --notify <alert_id>` one-shot notifications (`L-08`).
///
/// When running in Session 0 (`LocalSystem` Windows Service), transitions across the session
/// boundary into the active interactive user's token via `WTSQueryUserToken`, `DuplicateTokenEx`,
/// and `CreateProcessAsUserW(..., CREATE_NO_WINDOW)`. When running non-privileged in `--foreground`
/// dev mode (`ERROR_PRIVILEGE_NOT_HELD`, etc.), falls back to normal child spawning if
/// `ui_exe_path` exists, or logs a warning and returns `Ok(())` if missing.
#[derive(Debug, Clone)]
pub struct Session0ToastLauncher {
    ui_exe_path: PathBuf,
}

impl Session0ToastLauncher {
    /// Creates a [`Session0ToastLauncher`] targeting the specified `ledr-ui.exe` path.
    pub fn new(ui_exe_path: impl Into<PathBuf>) -> Self {
        Self {
            ui_exe_path: ui_exe_path.into(),
        }
    }

    /// Creates a [`Session0ToastLauncher`] pointing at [`AUTHORIZED_UI_EXE_PATH`].
    pub fn default_install_path() -> Self {
        Self::new(AUTHORIZED_UI_EXE_PATH)
    }

    /// Returns the configured UI executable path.
    pub fn ui_exe_path(&self) -> &Path {
        &self.ui_exe_path
    }
}

impl NotificationDispatcher for Session0ToastLauncher {
    fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String> {
        let alert_id = alert.alert_id.trim();
        if alert_id.is_empty() || alert_id.chars().any(|c| c == '\0' || c == '\r' || c == '\n') {
            return Err("invalid alert_id for toast notification".to_string());
        }

        if let Err(session0_err) = self.try_launch_in_active_session(alert_id) {
            tracing::debug!(
                alert_id = %alert_id,
                ui_exe = %self.ui_exe_path.display(),
                reason = %session0_err,
                "Session 0 WTS toast launch unavailable; attempting foreground fallback"
            );
            return self.spawn_foreground_fallback(alert_id, &session0_err);
        }

        Ok(())
    }
}

impl Session0ToastLauncher {
    fn try_launch_in_active_session(&self, alert_id: &str) -> Result<(), String> {
        // SAFETY: Win32 query returning active console session ID or 0xFFFFFFFF if none.
        let session_id = unsafe { WTSGetActiveConsoleSessionId() };
        if session_id == WTS_NO_CONSOLE_SESSION {
            return Err("no active console session (WTSGetActiveConsoleSessionId = 0xFFFFFFFF)"
                .to_string());
        }

        let mut raw_user_token = HANDLE::default();
        // SAFETY: `session_id` is valid and `raw_user_token` receives an owned handle on success.
        unsafe { WTSQueryUserToken(session_id, &mut raw_user_token) }
            .map_err(|err| format!("WTSQueryUserToken(session={session_id}) failed: {err}"))?;
        let user_token = OwnedHandle(raw_user_token);

        let mut raw_primary_token = HANDLE::default();
        // SAFETY: Duplicates `user_token.0` into a primary token usable by `CreateProcessAsUserW`.
        unsafe {
            DuplicateTokenEx(
                user_token.0,
                TOKEN_ALL_ACCESS,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut raw_primary_token,
            )
        }
        .map_err(|err| format!("DuplicateTokenEx failed: {err}"))?;
        let primary_token = OwnedHandle(raw_primary_token);

        if !self.ui_exe_path.is_file() {
            return Err(format!(
                "UI binary missing at {}",
                self.ui_exe_path.display()
            ));
        }

        let env_guard = EnvBlockGuard::for_token(primary_token.0);
        let mut desktop_w = encode_wide_nul_str(r"winsta0\default");
        let app_w = encode_wide_nul(self.ui_exe_path.as_os_str());
        let cmd_str = format!(
            "\"{}\" --notify {}",
            self.ui_exe_path.display(),
            quote_cli_arg(alert_id)
        );
        let mut cmd_w = encode_wide_nul_str(&cmd_str);

        let startup_info = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop_w.as_mut_ptr()),
            ..Default::default()
        };
        let mut proc_info = PROCESS_INFORMATION::default();

        let mut flags = CREATE_NO_WINDOW;
        let env_opt = env_guard.as_ptr();
        if env_opt.is_some() {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }

        // SAFETY: `primary_token.0`, wide string pointers, `startup_info`, and `proc_info` remain
        // valid for the duration of `CreateProcessAsUserW`.
        unsafe {
            CreateProcessAsUserW(
                Some(primary_token.0),
                PCWSTR(app_w.as_ptr()),
                Some(PWSTR(cmd_w.as_mut_ptr())),
                None,
                None,
                false,
                flags,
                env_opt,
                PCWSTR::null(),
                &startup_info,
                &mut proc_info,
            )
        }
        .map_err(|err| format!("CreateProcessAsUserW failed: {err}"))?;

        let _proc = OwnedHandle(proc_info.hProcess);
        let _thread = OwnedHandle(proc_info.hThread);
        Ok(())
    }

    fn spawn_foreground_fallback(&self, alert_id: &str, session0_reason: &str) -> Result<(), String> {
        if !self.ui_exe_path.is_file() {
            tracing::warn!(
                alert_id = %alert_id,
                ui_exe = %self.ui_exe_path.display(),
                session0_reason = %session0_reason,
                "toast notification skipped: UI binary does not exist"
            );
            return Ok(());
        }

        match Command::new(&self.ui_exe_path)
            .arg("--notify")
            .arg(alert_id)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn()
        {
            Ok(_child) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                tracing::warn!(
                    alert_id = %alert_id,
                    ui_exe = %self.ui_exe_path.display(),
                    error = %err,
                    "toast notification skipped: UI binary vanished before spawn"
                );
                Ok(())
            }
            Err(err) => Err(format!(
                "failed to launch UI toast fallback ({}): {err}",
                self.ui_exe_path.display()
            )),
        }
    }
}

fn quote_cli_arg(arg: &str) -> String {
    if !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let escaped = arg.replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn encode_wide_nul_str(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn encode_wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: Handle was returned by WTS/Token/CreateProcess APIs and is closed once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct EnvBlockGuard(*mut c_void);

impl EnvBlockGuard {
    fn for_token(token: HANDLE) -> Self {
        let mut env: *mut c_void = ptr::null_mut();
        // SAFETY: `token.0` is an open user token; `env` is freed by `DestroyEnvironmentBlock`.
        let ok = unsafe { CreateEnvironmentBlock(&mut env, token.0, 0) };
        if ok != 0 && !env.is_null() {
            Self(env)
        } else {
            Self(ptr::null_mut())
        }
    }

    fn as_ptr(&self) -> Option<*const c_void> {
        (!self.0.is_null()).then_some(self.0 as *const c_void)
    }
}

impl Drop for EnvBlockGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `CreateEnvironmentBlock`.
            unsafe {
                let _ = DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

#[link(name = "userenv.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn CreateEnvironmentBlock(
        lp_environment: *mut *mut c_void,
        h_token: *mut c_void,
        b_inherit: i32,
    ) -> i32;
    fn DestroyEnvironmentBlock(lp_environment: *const c_void) -> i32;
}
