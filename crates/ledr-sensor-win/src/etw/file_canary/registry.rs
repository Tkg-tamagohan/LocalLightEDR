//! Zero-allocation UTF-16 autorun registry key and value-target matchers (`AUTO-08`).

use super::utf16::{ascii_u16, find_segment_ci_u16, is_sep_u16};

// Autorun registry key markers.
const REG_RUN_U16: [u16; 18] = ascii_u16(b"CurrentVersion\\Run");
const REG_RUN_ONCE_U16: [u16; 22] = ascii_u16(b"CurrentVersion\\RunOnce");
const REG_WINLOGON_U16: [u16; 8] = ascii_u16(b"Winlogon");
const REG_SERVICES_U16: [u16; 9] = ascii_u16(b"Services\\");

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

/// Returns `true` if a raw UTF-16 registry key path is an autorun location where a
/// *value write* indicates persistence (`\CurrentVersion\Run`, `\CurrentVersion\RunOnce`,
/// or `\Winlogon`). `Services\*` is excluded: service-key persistence is already covered by
/// new-key creation events, while existing service keys (e.g. `Services\Tcpip\Parameters`)
/// see constant benign value writes from the OS itself.
#[inline]
pub fn is_autorun_registry_value_target_u16(raw_u16: &[u16]) -> bool {
    let end = raw_u16
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(raw_u16.len());
    let slice = &raw_u16[..end];
    if slice.is_empty() {
        return false;
    }
    [
        &REG_RUN_U16[..],
        &REG_RUN_ONCE_U16[..],
        &REG_WINLOGON_U16[..],
    ]
    .iter()
        .any(|marker| {
            find_segment_ci_u16(slice, marker).is_some_and(|after| {
                after == slice.len() || is_sep_u16(slice[after])
            })
        })
}

/// String wrapper around [`is_autorun_registry_value_target_u16`].
pub fn is_autorun_registry_value_target(key_path: &str) -> bool {
    if key_path.is_empty() {
        return false;
    }
    let mut stack = [0u16; 512];
    let mut len = 0usize;
    for unit in key_path.encode_utf16() {
        if len >= stack.len() {
            let heap: Vec<u16> = key_path.encode_utf16().collect();
            return is_autorun_registry_value_target_u16(&heap);
        }
        stack[len] = unit;
        len += 1;
    }
    is_autorun_registry_value_target_u16(&stack[..len])
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
