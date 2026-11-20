use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UriRegistrationOutcome {
    pub(crate) registry_key: String,
    pub(crate) command: String,
    pub(crate) updated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegisterUriEvent {
    mode: String,
    scheme: String,
    registry_key: String,
    command: String,
    updated: bool,
    pub(crate) status: String,
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LEDR_URI_REG_SUBKEY: &str = r"Software\Classes\ledr";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LEDR_URI_DESCRIPTION: &str = "URL:LocalEDR Alert Protocol";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LEDR_AUMID: &str = "LocalEDR.AlertUI";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LEDR_AUMID_REG_SUBKEY: &str =
    r"Software\Classes\AppUserModelId\LocalEDR.AlertUI";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LEDR_AUMID_DISPLAY_NAME: &str = "LocalEDR";

pub(crate) fn format_ledr_uri_command(exe_path: &std::path::Path) -> String {
    let raw = exe_path.to_string_lossy();
    let normalized = if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    };
    format!("\"{normalized}\" \"%1\"")
}

#[cfg(windows)]
pub(crate) mod win_uri_reg {
    use super::{LEDR_URI_DESCRIPTION, UriRegistrationOutcome, format_ledr_uri_command};
    use std::ffi::c_void;
    use std::path::Path;
    use std::ptr;

    const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const KEY_CREATE_SUB_KEY: u32 = 0x0004;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;
    const ERROR_SUCCESS: i32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_MORE_DATA: i32 = 234;

    #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn RegOpenKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            ul_options: u32,
            sam_desired: u32,
            phk_result: *mut isize,
        ) -> i32;
        fn RegCreateKeyExW(
            h_key: isize,
            lp_sub_key: *const u16,
            reserved: u32,
            lp_class: *const u16,
            dw_options: u32,
            sam_desired: u32,
            lp_security_attributes: *const c_void,
            phk_result: *mut isize,
            lpdw_disposition: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            lp_reserved: *mut u32,
            lp_type: *mut u32,
            lp_data: *mut u8,
            lpcb_data: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            h_key: isize,
            lp_value_name: *const u16,
            reserved: u32,
            dw_type: u32,
            lp_data: *const u8,
            cb_data: u32,
        ) -> i32;
        fn RegCloseKey(h_key: isize) -> i32;
        #[cfg(test)]
        fn RegDeleteTreeW(h_key: isize, lp_sub_key: *const u16) -> i32;
    }

    pub(crate) struct OwnedRegKey(isize);

    impl Drop for OwnedRegKey {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: `self.0` is an open HKEY acquired from `RegOpenKeyExW` or `RegCreateKeyExW`.
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    pub(crate) fn to_utf16_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub(crate) fn reg_open_hkcu(subkey: &str, access: u32) -> Result<Option<OwnedRegKey>, String> {
        let subkey_w = to_utf16_nul(subkey);
        let mut handle: isize = 0;
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and `handle` is valid out-pointer storage.
        let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, subkey_w.as_ptr(), 0, access, &mut handle) };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegOpenKeyExW('HKCU\\{subkey}') failed: OS status {status}"));
        }
        Ok(Some(OwnedRegKey(handle)))
    }

    fn reg_create_hkcu(subkey: &str, access: u32) -> Result<OwnedRegKey, String> {
        let subkey_w = to_utf16_nul(subkey);
        let mut handle: isize = 0;
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 and `handle` is valid out-pointer storage.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                subkey_w.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                access,
                ptr::null(),
                &mut handle,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!(
                "RegCreateKeyExW('HKCU\\{subkey}') failed: OS status {status}"
            ));
        }
        Ok(OwnedRegKey(handle))
    }

    pub(crate) fn reg_query_sz(key: &OwnedRegKey, value_name: Option<&str>) -> Result<Option<String>, String> {
        let name_w = value_name.map(to_utf16_nul);
        let name_ptr = name_w.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let mut val_type: u32 = 0;
        let mut buf = vec![0u8; 512];
        let mut byte_len = buf.len() as u32;
        // SAFETY: `key.0` is an open HKEY, `name_ptr` is NULL or NUL-terminated UTF-16, and `buf` is writable.
        let mut status = unsafe {
            RegQueryValueExW(
                key.0,
                name_ptr,
                ptr::null_mut(),
                &mut val_type,
                buf.as_mut_ptr(),
                &mut byte_len,
            )
        };
        if status == ERROR_MORE_DATA {
            buf.resize(byte_len as usize, 0);
            // SAFETY: `buf` was resized to `byte_len` bytes reported by `RegQueryValueExW`.
            status = unsafe {
                RegQueryValueExW(
                    key.0,
                    name_ptr,
                    ptr::null_mut(),
                    &mut val_type,
                    buf.as_mut_ptr(),
                    &mut byte_len,
                )
            };
        }
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(format!("RegQueryValueExW failed: OS status {status}"));
        }
        if val_type != REG_SZ {
            return Ok(None);
        }
        let used = (byte_len as usize).min(buf.len());
        let mut units: Vec<u16> = buf[..used]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        Ok(Some(String::from_utf16_lossy(&units)))
    }

    fn reg_set_sz(key: &OwnedRegKey, value_name: Option<&str>, value: &str) -> Result<(), String> {
        let name_w = value_name.map(to_utf16_nul);
        let name_ptr = name_w.as_ref().map_or(ptr::null(), |v| v.as_ptr());
        let data_w = to_utf16_nul(value);
        let byte_len = u32::try_from(data_w.len() * std::mem::size_of::<u16>())
            .map_err(|_| "registry string exceeds u32 byte length".to_string())?;
        // SAFETY: `key.0` is an open HKEY with write access and `data_w` is NUL-terminated UTF-16 of `byte_len` bytes.
        let status = unsafe {
            RegSetValueExW(
                key.0,
                name_ptr,
                0,
                REG_SZ,
                data_w.as_ptr() as *const u8,
                byte_len,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(format!("RegSetValueExW failed: OS status {status}"));
        }
        Ok(())
    }

    pub(crate) fn ensure_hkcu_uri_registered_at(
        base_subkey: &str,
        exe_path: &Path,
    ) -> Result<UriRegistrationOutcome, String> {
        let expected_cmd = format_ledr_uri_command(exe_path);
        let cmd_subkey = format!(r"{base_subkey}\shell\open\command");
        let display_key = format!(r"HKCU\{base_subkey}");

        // Fast read-only check so repeated `--notify` launches avoid registry writes.
        if let (Ok(Some(base_key)), Ok(Some(cmd_key))) = (
            reg_open_hkcu(base_subkey, KEY_QUERY_VALUE),
            reg_open_hkcu(&cmd_subkey, KEY_QUERY_VALUE),
        ) {
            let desc_ok =
                reg_query_sz(&base_key, None).ok().flatten().as_deref() == Some(LEDR_URI_DESCRIPTION);
            let proto_ok =
                reg_query_sz(&base_key, Some("URL Protocol")).ok().flatten().as_deref() == Some("");
            let cmd_ok =
                reg_query_sz(&cmd_key, None).ok().flatten().as_deref() == Some(expected_cmd.as_str());
            if desc_ok && proto_ok && cmd_ok {
                return Ok(UriRegistrationOutcome {
                    registry_key: display_key,
                    command: expected_cmd,
                    updated: false,
                });
            }
        }

        let base_key = reg_create_hkcu(base_subkey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        reg_set_sz(&base_key, None, LEDR_URI_DESCRIPTION)?;
        reg_set_sz(&base_key, Some("URL Protocol"), "")?;

        let cmd_key = reg_create_hkcu(&cmd_subkey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        reg_set_sz(&cmd_key, None, &expected_cmd)?;

        Ok(UriRegistrationOutcome {
            registry_key: display_key,
            command: expected_cmd,
            updated: true,
        })
    }

    /// Ensures `HKCU\Software\Classes\AppUserModelId\<AUMID>` has `DisplayName = display_name`
    /// so WinRT `ToastNotificationManager::CreateToastNotifierWithId` resolves LocalEDR's
    /// dedicated AUMID without borrowing PowerShell's AppID.
    pub(crate) fn ensure_hkcu_aumid_registered_at(
        base_subkey: &str,
        display_name: &str,
    ) -> Result<bool, String> {
        if let Ok(Some(base_key)) = reg_open_hkcu(base_subkey, KEY_QUERY_VALUE) {
            let name_ok = reg_query_sz(&base_key, Some("DisplayName"))
                .ok()
                .flatten()
                .as_deref()
                == Some(display_name);
            if name_ok {
                return Ok(false);
            }
        }

        let base_key = reg_create_hkcu(base_subkey, KEY_SET_VALUE | KEY_CREATE_SUB_KEY)?;
        reg_set_sz(&base_key, Some("DisplayName"), display_name)?;
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn reg_delete_hkcu_tree(subkey: &str) {
        let subkey_w = to_utf16_nul(subkey);
        // SAFETY: `subkey_w` is NUL-terminated UTF-16 under `HKEY_CURRENT_USER`.
        unsafe {
            let _ = RegDeleteTreeW(HKEY_CURRENT_USER, subkey_w.as_ptr());
        }
    }
}

/// Ensures per-user `HKCU\Software\Classes\ledr` protocol handler registration and
/// `HKCU\Software\Classes\AppUserModelId\LocalEDR.AlertUI` AUMID registration match the
/// current `ledr-ui` executable path (idempotent; checks existing values before writing).
#[cfg(windows)]
pub(crate) fn ensure_hkcu_ledr_uri_registered() -> Result<UriRegistrationOutcome, String> {
    let exe_path =
        std::env::current_exe().map_err(|err| format!("failed to resolve current_exe: {err}"))?;
    let mut outcome = win_uri_reg::ensure_hkcu_uri_registered_at(LEDR_URI_REG_SUBKEY, &exe_path)?;
    let aumid_updated = win_uri_reg::ensure_hkcu_aumid_registered_at(
        LEDR_AUMID_REG_SUBKEY,
        LEDR_AUMID_DISPLAY_NAME,
    )?;
    outcome.updated |= aumid_updated;
    Ok(outcome)
}

#[cfg(not(windows))]
pub(crate) fn ensure_hkcu_ledr_uri_registered() -> Result<UriRegistrationOutcome, String> {
    Err("HKCU ledr:// URI registration is only supported on Windows".to_string())
}

pub(crate) fn build_register_uri_event(outcome: &UriRegistrationOutcome) -> RegisterUriEvent {
    RegisterUriEvent {
        mode: "register_uri".to_string(),
        scheme: "ledr".to_string(),
        registry_key: outcome.registry_key.clone(),
        command: outcome.command.clone(),
        updated: outcome.updated,
        status: if outcome.updated {
            "registered".to_string()
        } else {
            "already_registered".to_string()
        },
    }
}

pub(crate) fn dispatch_register_uri() -> Result<(), String> {
    let outcome = ensure_hkcu_ledr_uri_registered()?;
    let event = build_register_uri_event(&outcome);
    let json = serde_json::to_string(&event)
        .map_err(|err| format!("failed to serialize URI registration event: {err}"))?;
    println!("{json}");
    Ok(())
}
