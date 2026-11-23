//! Caller binary authorization and Named Pipe client process inspection FFI (`L-09`).

use std::os::windows::io::AsRawHandle;
use std::path::Path;

use ledr_proto::{AUTHORIZED_BRIDGE_EXE_PATH, AUTHORIZED_UI_EXE_PATH};
use ledr_rules::{signer_subject_matches, BinaryIdentity};

use crate::engine::{BinaryInspector, WindowsBinaryInspector};
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Checks whether a caller executable path is authorized to execute mutating UI commands (`L-09`).
pub fn is_authorized_ui_caller(caller_exe_path: Option<&str>, dev_mode_bypass: bool) -> bool {
    verify_authorized_caller_binary(
        caller_exe_path,
        AUTHORIZED_UI_EXE_PATH,
        None,
        None,
        None,
        dev_mode_bypass,
    )
}

/// Checks whether a caller executable path is authorized to submit browser bridge events (`L-09`).
pub fn is_authorized_bridge_caller(caller_exe_path: Option<&str>, dev_mode_bypass: bool) -> bool {
    verify_authorized_caller_binary(
        caller_exe_path,
        AUTHORIZED_BRIDGE_EXE_PATH,
        None,
        None,
        None,
        dev_mode_bypass,
    )
}

/// Verifies an IPC caller executable against an expected protected path AND cryptographic
/// identity (`L-09`, `SEC_0002`, `SEC_0006`), preserving `dev_mode_bypass`.
///
/// When a SHA-256 pin suffices (no signer/root thumbprint pins), computes SHA-256 in-process
/// without spawning an out-of-process Authenticode worker; otherwise routes through
/// `WindowsBinaryInspector` (`FU-E2E-03` Track 2).
pub fn verify_authorized_caller_binary(
    caller_exe_path: Option<&str>,
    expected_exe_path: &str,
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
    dev_mode_bypass: bool,
) -> bool {
    if dev_mode_bypass {
        return true;
    }
    let Some(caller_path) = caller_exe_path.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if !normalized_path_eq_ascii_ci(caller_path, expected_exe_path) {
        return false;
    }

    if sha256_pin_suffices(expected_sha256, expected_signer, expected_root_thumbprint) {
        let identity = BinaryIdentity::from_path_sha256_only(Path::new(caller_path));
        return verify_caller_identity(
            Some(&identity),
            expected_exe_path,
            expected_sha256,
            expected_signer,
            expected_root_thumbprint,
            false,
        );
    }

    let inspector = WindowsBinaryInspector::new();
    verify_authorized_caller_binary_with_inspector(
        &inspector,
        Some(caller_path),
        expected_exe_path,
        expected_sha256,
        expected_signer,
        expected_root_thumbprint,
        false,
    )
}

/// Verifies an IPC caller executable using a supplied [`BinaryInspector`] when Authenticode
/// inspection is required, while computing SHA-256 in-process when a SHA-256 pin suffices.
pub fn verify_authorized_caller_binary_with_inspector(
    inspector: &dyn BinaryInspector,
    caller_exe_path: Option<&str>,
    expected_exe_path: &str,
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
    dev_mode_bypass: bool,
) -> bool {
    if dev_mode_bypass {
        return true;
    }
    let Some(caller_path) = caller_exe_path.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    if !normalized_path_eq_ascii_ci(caller_path, expected_exe_path) {
        return false;
    }

    let identity = if sha256_pin_suffices(expected_sha256, expected_signer, expected_root_thumbprint)
    {
        BinaryIdentity::from_path_sha256_only(Path::new(caller_path))
    } else {
        inspector.inspect_uncached(caller_path)
    };
    verify_caller_identity(
        Some(&identity),
        expected_exe_path,
        expected_sha256,
        expected_signer,
        expected_root_thumbprint,
        false,
    )
}

fn sha256_pin_suffices(
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
) -> bool {
    let has_sha = expected_sha256
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    let has_signer = expected_signer
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    has_sha && !has_signer && expected_root_thumbprint.is_none()
}

/// Pure identity verification helper matching path, optional SHA-256, and Authenticode
/// signer + non-zero root thumbprint (`L-09`, `SEC_0002`, `SEC_0006`).
pub fn verify_caller_identity(
    caller_identity: Option<&BinaryIdentity>,
    expected_exe_path: &str,
    expected_sha256: Option<&str>,
    expected_signer: Option<&str>,
    expected_root_thumbprint: Option<&str>,
    dev_mode_bypass: bool,
) -> bool {
    if dev_mode_bypass {
        return true;
    }
    let Some(identity) = caller_identity else {
        return false;
    };
    if !normalized_path_eq_ascii_ci(identity.exe_path.trim(), expected_exe_path) {
        return false;
    }

    let sha_pin = expected_sha256.map(str::trim).filter(|s| !s.is_empty());
    let signer_pin = expected_signer.map(str::trim).filter(|s| !s.is_empty());

    if let Some(expected_sha) = sha_pin {
        let matches = identity
            .sha256
            .as_deref()
            .map(str::trim)
            .is_some_and(|actual| !actual.is_empty() && actual.eq_ignore_ascii_case(expected_sha));
        if !matches {
            return false;
        }
    }

    if let Some(expected_subj) = signer_pin {
        let Some(auth) = identity.authenticode.as_ref() else {
            return false;
        };
        if !signer_subject_matches(&auth.signer_subject, expected_subj) {
            return false;
        }
        let Some(expected_tp) = expected_root_thumbprint
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.chars().all(|c| c == '0'))
        else {
            return false;
        };
        let actual_tp = auth.root_thumbprint.trim();
        if actual_tp.is_empty()
            || actual_tp.chars().all(|c| c == '0')
            || !actual_tp.eq_ignore_ascii_case(expected_tp)
        {
            return false;
        }
    } else if let Some(raw_tp) = expected_root_thumbprint {
        let expected_tp = raw_tp.trim();
        if expected_tp.is_empty() || expected_tp.chars().all(|c| c == '0') {
            return false;
        }
        let Some(auth) = identity.authenticode.as_ref() else {
            return false;
        };
        let actual_tp = auth.root_thumbprint.trim();
        if actual_tp.is_empty()
            || actual_tp.chars().all(|c| c == '0')
            || !actual_tp.eq_ignore_ascii_case(expected_tp)
        {
            return false;
        }
    }

    // SEC_0002: If neither SHA-256 nor signer was pinned, never allow on path match alone;
    // require a valid Authenticode signature with a non-empty, non-zero root thumbprint.
    if sha_pin.is_none() && signer_pin.is_none() {
        let has_valid_authenticode = identity.authenticode.as_ref().is_some_and(|auth| {
            let subj = auth.signer_subject.trim();
            let tp = auth.root_thumbprint.trim();
            !subj.is_empty() && !tp.is_empty() && !tp.chars().all(|c| c == '0')
        });
        if !has_valid_authenticode {
            return false;
        }
    }

    true
}

fn normalized_path_eq_ascii_ci(a: &str, b: &str) -> bool {
    let na = a.trim().replace('/', "\\");
    let nb = b.trim().replace('/', "\\");
    !na.is_empty() && na.eq_ignore_ascii_case(&nb)
}

/// Resolves the connected client process PID and executable image path via `GetNamedPipeClientProcessId`.
pub fn inspect_pipe_client_exe(pipe: &NamedPipeServer) -> Result<(u32, String), String> {
    let raw = HANDLE(pipe.as_raw_handle());
    let mut client_pid: u32 = 0;

    // Safety: `raw` is a live Named Pipe server handle owned by `pipe` for this call duration.
    unsafe {
        GetNamedPipeClientProcessId(raw, &mut client_pid)
            .map_err(|err| format!("GetNamedPipeClientProcessId failed: {err}"))?;
    }
    if client_pid == 0 {
        return Err("GetNamedPipeClientProcessId returned PID 0".to_string());
    }

    let proc_handle = OwnedWinHandle(unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
            .map_err(|err| format!("OpenProcess({client_pid}) failed: {err}"))?
    });

    let mut buf = vec![0u16; 1024];
    let mut len = u32::try_from(buf.len()).unwrap_or(1024);

    // Safety: `buf` is valid writable UTF-16 memory of length `len`.
    unsafe {
        QueryFullProcessImageNameW(
            proc_handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .map_err(|err| format!("QueryFullProcessImageNameW({client_pid}) failed: {err}"))?;
    }

    let exe_len = usize::try_from(len).unwrap_or(0).min(buf.len());
    let exe_path = String::from_utf16_lossy(&buf[..exe_len]);
    Ok((client_pid, exe_path))
}

struct OwnedWinHandle(HANDLE);

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // Safety: handle was opened by `OpenProcess` and is closed exactly once on drop.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledr_proto::AuthenticodeInfo;
    use ledr_rules::compute_file_sha256_hex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct SpyInspector {
        calls: AtomicUsize,
        uncached_calls: AtomicUsize,
        authenticode: Option<AuthenticodeInfo>,
    }

    impl BinaryInspector for SpyInspector {
        fn inspect(&self, exe_path: &str) -> BinaryIdentity {
            self.calls.fetch_add(1, Ordering::AcqRel);
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: compute_file_sha256_hex(Path::new(exe_path)).ok(),
                authenticode: self.authenticode.clone(),
            }
        }

        fn inspect_uncached(&self, exe_path: &str) -> BinaryIdentity {
            self.uncached_calls.fetch_add(1, Ordering::AcqRel);
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: compute_file_sha256_hex(Path::new(exe_path)).ok(),
                authenticode: self.authenticode.clone(),
            }
        }
    }

    #[test]
    fn ipc_auth_sha256_pin_skips_inspector_while_authenticode_routes_through_inspector() {
        let tmp_dir = std::env::temp_dir().join(format!("ledr-ipc-auth-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).expect("create tmp");
        let exe = tmp_dir.join("ledr-ui.exe");
        std::fs::write(&exe, b"ipc-auth-test-payload").expect("write exe");
        let exe_str = exe.to_string_lossy().into_owned();
        let sha = compute_file_sha256_hex(&exe).expect("hash exe");

        let spy = SpyInspector {
            calls: AtomicUsize::new(0),
            uncached_calls: AtomicUsize::new(0),
            authenticode: Some(AuthenticodeInfo {
                signer_subject: "CN=LocalEDR".to_string(),
                root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
            }),
        };

        // 1. SHA-256 pin alone computes hash in-process and does NOT invoke BinaryInspector.
        assert!(verify_authorized_caller_binary_with_inspector(
            &spy,
            Some(&exe_str),
            &exe_str,
            Some(&sha),
            None,
            None,
            false
        ));
        assert_eq!(spy.calls.load(Ordering::Acquire), 0);
        assert_eq!(spy.uncached_calls.load(Ordering::Acquire), 0);

        // 2. Without SHA-256 pin, Authenticode routes through `inspect_uncached` (never cached `inspect`).
        assert!(verify_authorized_caller_binary_with_inspector(
            &spy,
            Some(&exe_str),
            &exe_str,
            None,
            None,
            None,
            false
        ));
        assert_eq!(spy.calls.load(Ordering::Acquire), 0);
        assert_eq!(spy.uncached_calls.load(Ordering::Acquire), 1);

        // 3. Option X fail-closed when BinaryInspector returns `authenticode: None`.
        let fail_closed_spy = SpyInspector {
            calls: AtomicUsize::new(0),
            uncached_calls: AtomicUsize::new(0),
            authenticode: None,
        };
        assert!(!verify_authorized_caller_binary_with_inspector(
            &fail_closed_spy,
            Some(&exe_str),
            &exe_str,
            None,
            None,
            None,
            false
        ));
        assert_eq!(fail_closed_spy.calls.load(Ordering::Acquire), 0);
        assert_eq!(fail_closed_spy.uncached_calls.load(Ordering::Acquire), 1);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn ipc_auth_revoked_01_trust_revocation_without_file_change_denies_mutating_ipc() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "ledr-ipc-auth-revoked-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp_dir).expect("create tmp");
        let exe = tmp_dir.join("ledr-ui.exe");
        std::fs::write(&exe, b"MZ-immutable-ui-binary").expect("write exe");
        let exe_str = exe.to_string_lossy().into_owned();

        struct RevokingInspector {
            cached_calls: AtomicUsize,
            uncached_calls: AtomicUsize,
        }
        impl BinaryInspector for RevokingInspector {
            fn inspect(&self, exe_path: &str) -> BinaryIdentity {
                self.cached_calls.fetch_add(1, Ordering::AcqRel);
                BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: compute_file_sha256_hex(Path::new(exe_path)).ok(),
                    authenticode: Some(AuthenticodeInfo {
                        signer_subject: "CN=LocalEDR".to_string(),
                        root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
                    }),
                }
            }
            fn inspect_uncached(&self, exe_path: &str) -> BinaryIdentity {
                let n = self.uncached_calls.fetch_add(1, Ordering::AcqRel);
                let authenticode = if n == 0 {
                    Some(AuthenticodeInfo {
                        signer_subject: "CN=LocalEDR".to_string(),
                        root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
                    })
                } else {
                    None
                };
                BinaryIdentity {
                    exe_path: exe_path.to_string(),
                    sha256: compute_file_sha256_hex(Path::new(exe_path)).ok(),
                    authenticode,
                }
            }
        }

        let inspector = RevokingInspector {
            cached_calls: AtomicUsize::new(0),
            uncached_calls: AtomicUsize::new(0),
        };
        assert!(verify_authorized_caller_binary_with_inspector(
            &inspector,
            Some(&exe_str),
            &exe_str,
            None,
            Some("CN=LocalEDR"),
            Some("0123456789ABCDEF0123456789ABCDEF01234567"),
            false
        ));
        // Second call with identical file on disk after trust revocation MUST fail closed.
        assert!(!verify_authorized_caller_binary_with_inspector(
            &inspector,
            Some(&exe_str),
            &exe_str,
            None,
            Some("CN=LocalEDR"),
            Some("0123456789ABCDEF0123456789ABCDEF01234567"),
            false
        ));
        assert_eq!(inspector.cached_calls.load(Ordering::Acquire), 0);
        assert_eq!(inspector.uncached_calls.load(Ordering::Acquire), 2);

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
