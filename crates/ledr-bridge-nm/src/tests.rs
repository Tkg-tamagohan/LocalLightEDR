//! Specification-driven unit and Named Pipe tests for `ledr-bridge-nm` (`BRIDGE-01`..`BRIDGE-17`).

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ledr_proto::{decode_ipc_frame, encode_ipc_frame, IpcRequest, IpcResponse, IPC_MAX_FRAME_BYTES};

use crate::cli::{
    parse_args_from, BrowserKind, Command, RelayArgs, Scope, SetupArgs, StatusArgs, StatusScope,
    UnregisterArgs,
};
use crate::extension_id::{
    chrome_extension_origin, decode_base64, derive_extension_id_from_base64_key,
    derive_extension_id_from_der, is_valid_extension_id, sha256, DEFAULT_CHROME_EXTENSION_ID,
};
use crate::manifest::{
    build_manifest, manifest_filename_for, validate_manifest_file, write_manifest_atomic,
    MANIFEST_FILENAME,
};
use crate::pipe_client::{
    evaluate_browser_caller_chain, is_authorized_browser_parent_exe_with,
    is_authorized_cmd_exe_with, is_authorized_pipe_server_exe_with, is_default_ipc_pipe,
    is_valid_caller_origin, verify_browser_relay_caller, verify_browser_relay_caller_with,
    BridgeTransportError, BrowserCallerChain, PipeClient, ProcessSnapshot, StdHandleTransport,
};
use crate::relay::{read_raw_frame, run_relay_loop, write_raw_frame, FrameExchange, RawFrameError};
use crate::setup::{
    format_status_text, has_unresolved_env_token, resolve_bridge_exe_with, resolve_manifest_dir,
    resolve_ui_exe_with, run_setup_with, run_setup_with_ops, run_status_with, run_status_with_ops,
    run_unregister_with, run_unregister_with_ops, select_effective_hklm_probe,
    NativeHostRegProbe, RegWow64View, RegistryTarget, RegistryViewOps,
    NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE,
};

static UNIQUE_SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(prefix: &str) -> Self {
        let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn frame_bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[test]
fn bridge_01_cli_accepts_chrome_native_messaging_launch_args() {
    let origin = format!("chrome-extension://{DEFAULT_CHROME_EXTENSION_ID}/");

    // Default invocation (no args) enters Relay mode using default IPC pipe.
    let cmd = parse_args_from(["ledr-bridge-nm.exe"], None).expect("empty args");
    assert!(matches!(cmd, Command::Relay(ref r) if r.pipe_name == ledr_proto::IPC_PIPE_NAME));

    // Chrome Native Messaging invocation on Windows includes extension origin, --parent-window=<hwnd>,
    // and potentially unknown Chromium switches; relay parser must accept them without failing.
    let cmd = parse_args_from(
        [
            "ledr-bridge-nm.exe",
            origin.as_str(),
            "--parent-window=196842",
            "--unknown-chromium-flag=abc",
            "--pipe",
            r"\\.\pipe\custom-test-pipe",
        ],
        Some(r"\\.\pipe\env-fallback"),
    )
    .expect("chrome launch args");
    match cmd {
        Command::Relay(r) => {
            assert_eq!(r.pipe_name, r"\\.\pipe\custom-test-pipe");
            assert_eq!(r.caller_origin.as_deref(), Some(origin.as_str()));
            assert_eq!(r.parent_window.as_deref(), Some("196842"));
        }
        other => panic!("expected Relay command, got {other:?}"),
    }

    // Setup defaults and overrides
    let setup = parse_args_from(
        [
            "ledr-bridge-nm.exe",
            "setup",
            "--scope=machine",
            "--browsers",
            "chrome,brave",
            "--skip-uri",
            "--json",
        ],
        None,
    )
    .expect("setup args");
    match setup {
        Command::Setup(s) => {
            assert_eq!(s.scope, Scope::Machine);
            assert_eq!(s.browsers, vec![BrowserKind::Chrome, BrowserKind::Brave]);
            assert_eq!(s.extension_id, DEFAULT_CHROME_EXTENSION_ID);
            assert!(s.skip_uri);
            assert!(s.json);
        }
        other => panic!("expected Setup command, got {other:?}"),
    }

    // Reject invalid extension ID and unknown subcommand flags
    assert!(parse_args_from(
        ["ledr-bridge-nm.exe", "setup", "--extension-id", "not-valid-id"],
        None
    )
    .is_err());
    assert!(parse_args_from(
        ["ledr-bridge-nm.exe", "setup", "--browsers", "firefox"],
        None
    )
    .is_err());
    assert!(parse_args_from(["ledr-bridge-nm.exe", "status", "--bogus"], None).is_err());
}

#[test]
fn bridge_02_rejects_empty_oversized_and_truncated_frames() {
    // 0-byte frame rejected
    let mut empty_cur = Cursor::new(0u32.to_le_bytes().to_vec());
    assert!(matches!(
        read_raw_frame(&mut empty_cur, IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::EmptyFrame)
    ));

    // > 1 MiB frame rejected prior to allocating full payload
    let mut big_cur = Cursor::new(((IPC_MAX_FRAME_BYTES as u32) + 1).to_le_bytes().to_vec());
    assert!(matches!(
        read_raw_frame(&mut big_cur, IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::FrameTooLarge { .. })
    ));

    // Truncated 2-byte header rejected
    let mut short_hdr = Cursor::new(vec![10u8, 0u8]);
    assert!(matches!(
        read_raw_frame(&mut short_hdr, IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::TruncatedHeader { actual: 2 })
    ));

    // Truncated payload rejected
    let mut trunc_payload = Cursor::new(vec![5u8, 0, 0, 0, b'a', b'b']);
    assert!(matches!(
        read_raw_frame(&mut trunc_payload, IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::TruncatedPayload {
            expected: 5,
            actual: 2
        })
    ));

    // Clean EOF at frame boundary returns Ok(None)
    let mut eof_cur = Cursor::new(Vec::<u8>::new());
    assert!(matches!(
        read_raw_frame(&mut eof_cur, IPC_MAX_FRAME_BYTES),
        Ok(None)
    ));

    // Write limits enforced
    let mut out = Vec::new();
    assert!(matches!(
        write_raw_frame(&mut out, &[], IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::EmptyFrame)
    ));
    let oversized = vec![b'x'; IPC_MAX_FRAME_BYTES + 1];
    assert!(matches!(
        write_raw_frame(&mut out, &oversized, IPC_MAX_FRAME_BYTES),
        Err(RawFrameError::FrameTooLarge { .. })
    ));
}

#[cfg(windows)]
mod win_pipe_test_helpers {
    use std::ffi::c_void;

    pub const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    pub const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
    pub const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
    pub const PIPE_WAIT: u32 = 0x0000_0000;
    pub const SDDL_REVISION_1: u32 = 1;
    pub const ERROR_NO_DATA: i32 = 232;
    pub const ERROR_PIPE_CONNECTED: i32 = 535;
    pub const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    pub const SERVICE_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)";

    #[repr(C)]
    pub struct SecurityAttributes {
        pub n_length: u32,
        pub lp_security_descriptor: *mut c_void,
        pub b_inherit_handle: i32,
    }

    #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: u32,
            pipe_mode: u32,
            max_instances: u32,
            out_buffer_size: u32,
            in_buffer_size: u32,
            default_time_out: u32,
            security_attributes: *const SecurityAttributes,
        ) -> *mut c_void;
        pub fn ConnectNamedPipe(pipe: *mut c_void, overlapped: *mut c_void) -> i32;
        pub fn DisconnectNamedPipe(pipe: *mut c_void) -> i32;
        pub fn FlushFileBuffers(pipe: *mut c_void) -> i32;
        pub fn CreatePipe(
            h_read_pipe: *mut *mut c_void,
            h_write_pipe: *mut *mut c_void,
            lp_pipe_attributes: *const SecurityAttributes,
            n_size: u32,
        ) -> i32;
        pub fn SetHandleInformation(
            h_object: *mut c_void,
            dw_mask: u32,
            dw_flags: u32,
        ) -> i32;
        pub fn GetVolumeNameForVolumeMountPointW(
            lpsz_volume_mount_point: *const u16,
            lpsz_volume_name: *mut u16,
            cch_buffer_length: u32,
        ) -> i32;
        pub fn CloseHandle(object: *mut c_void) -> i32;
        pub fn ReadFile(
            h_file: *mut c_void,
            lp_buffer: *mut u8,
            n_number_of_bytes_to_read: u32,
            lp_number_of_bytes_read: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
        pub fn WriteFile(
            h_file: *mut c_void,
            lp_buffer: *const u8,
            n_number_of_bytes_to_write: u32,
            lp_number_of_bytes_written: *mut u32,
            lp_overlapped: *mut c_void,
        ) -> i32;
    }

    pub struct PipeServerHandle(pub *mut c_void);
    unsafe impl Send for PipeServerHandle {}

    impl Drop for PipeServerHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != -1 {
                // SAFETY: `self.0` was created by `CreateNamedPipeW`.
                unsafe {
                    let _ = DisconnectNamedPipe(self.0);
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub fn create_single_instance_pipe(pipe_name: &str, with_service_sddl: bool) -> PipeServerHandle {
        let name_w: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let mut sa = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: std::ptr::null_mut(),
            b_inherit_handle: 0,
        };
        if with_service_sddl {
            let sddl_w: Vec<u16> = SERVICE_PIPE_SDDL
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            let mut sd_len: u32 = 0;
            // SAFETY: Valid UTF-16 SDDL pointer and stack out-parameters.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    &mut sd_len,
                )
            };
            assert_ne!(ok, 0, "ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
            sa.lp_security_descriptor = sd;
        }

        // SAFETY: `name_w` is NUL-terminated UTF-16; `sa` is valid for the duration of the call.
        let raw = unsafe {
            CreateNamedPipeW(
                name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                65536,
                65536,
                0,
                if with_service_sddl {
                    &sa as *const SecurityAttributes
                } else {
                    std::ptr::null()
                },
            )
        };
        if !sd.is_null() {
            // SAFETY: `sd` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
            unsafe {
                let _ = LocalFree(sd);
            }
        }
        assert_ne!(
            raw as isize,
            -1,
            "CreateNamedPipeW({pipe_name}) failed: {}",
            std::io::Error::last_os_error()
        );
        PipeServerHandle(raw)
    }

    pub fn accept_pipe_client(pipe: &PipeServerHandle) {
        // SAFETY: `pipe.0` is an open server Named Pipe handle.
        let ok = unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            assert_eq!(
                err.raw_os_error(),
                Some(ERROR_PIPE_CONNECTED),
                "ConnectNamedPipe failed: {err}"
            );
        }
    }

    pub fn accept_pipe_client_allow_early_close(pipe: &PipeServerHandle) {
        // SAFETY: `pipe.0` is an open server Named Pipe handle.
        let ok = unsafe { ConnectNamedPipe(pipe.0, std::ptr::null_mut()) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            assert!(
                matches!(err.raw_os_error(), Some(ERROR_PIPE_CONNECTED | ERROR_NO_DATA)),
                "ConnectNamedPipe failed unexpectedly: {err}"
            );
        }
    }

    pub fn server_read_exact(pipe: &PipeServerHandle, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let mut read = 0u32;
            // SAFETY: `pipe.0` is connected and `buf` is writable.
            let ok = unsafe {
                ReadFile(
                    pipe.0,
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap(),
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "ReadFile failed: {}", std::io::Error::last_os_error());
            assert!(read > 0, "unexpected EOF on server pipe");
            buf = &mut buf[read as usize..];
        }
    }

    pub fn server_write_all(pipe: &PipeServerHandle, mut data: &[u8]) {
        while !data.is_empty() {
            let mut written = 0u32;
            // SAFETY: `pipe.0` is connected and `data` is readable.
            let ok = unsafe {
                WriteFile(
                    pipe.0,
                    data.as_ptr(),
                    u32::try_from(data.len()).unwrap(),
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            assert_ne!(ok, 0, "WriteFile failed: {}", std::io::Error::last_os_error());
            data = &data[written as usize..];
        }
    }

    pub fn server_read_frame(pipe: &PipeServerHandle) -> Vec<u8> {
        let mut hdr = [0u8; 4];
        server_read_exact(pipe, &mut hdr);
        let len = u32::from_le_bytes(hdr) as usize;
        let mut payload = vec![0u8; len];
        server_read_exact(pipe, &mut payload);
        payload
    }

    pub fn server_write_frame(pipe: &PipeServerHandle, payload: &[u8]) {
        let len = (payload.len() as u32).to_le_bytes();
        server_write_all(pipe, &len);
        server_write_all(pipe, payload);
        // Wait until the client reads the buffered response before disconnecting/closing.
        // SAFETY: `pipe.0` is a connected Named Pipe server handle.
        unsafe {
            let _ = FlushFileBuffers(pipe.0);
        }
    }

    pub fn server_wait_client_close(pipe: &PipeServerHandle) {
        let mut byte = [0u8; 1];
        let mut read = 0u32;
        // SAFETY: `pipe.0` is connected; reads until client closes its pipe handle (EOF / broken pipe).
        unsafe {
            let _ = ReadFile(pipe.0, byte.as_mut_ptr(), 1, &mut read, std::ptr::null_mut());
        }
        assert_eq!(read, 0, "expected client to close pipe without extra bytes");
    }
}

#[cfg(windows)]
#[test]
fn bridge_03_zero_parse_relay_roundtrip_over_real_named_pipe() {
    use std::thread;
    use win_pipe_test_helpers::*;

    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pipe_name = format!(r"\\.\pipe\localedr-bridge-b03-{}-{seq}", std::process::id());
    let server_pipe = create_single_instance_pipe(&pipe_name, false);

    let opaque_req_1 = br#"{"opaque_untyped_field":true,"payload":[1,2,3]}"#;
    let opaque_resp_1 = br#"{"opaque_reply":"ok-1"}"#;
    let ping_req_2 = &encode_ipc_frame(&IpcRequest::Ping).unwrap()[4..];
    let ping_resp_2 = &encode_ipc_frame(&IpcResponse::Pong {
        daemon_version: "0.1.0-test".to_string(),
        protocol_version: 1,
    })
    .unwrap()[4..];

    let req1_expected = opaque_req_1.to_vec();
    let resp1_send = opaque_resp_1.to_vec();
    let req2_expected = ping_req_2.to_vec();
    let resp2_send = ping_resp_2.to_vec();

    let server_thread = thread::spawn(move || {
        // Connection 1 on single-instance pipe (proves client drops handle per request)
        accept_pipe_client(&server_pipe);
        let got1 = server_read_frame(&server_pipe);
        assert_eq!(got1, req1_expected);
        server_write_frame(&server_pipe, &resp1_send);
        server_wait_client_close(&server_pipe);
        // SAFETY: Disconnect first client so next request must open a fresh pipe connection.
        unsafe {
            let _ = DisconnectNamedPipe(server_pipe.0);
        }

        // Connection 2
        accept_pipe_client(&server_pipe);
        let got2 = server_read_frame(&server_pipe);
        assert_eq!(got2, req2_expected);
        server_write_frame(&server_pipe, &resp2_send);
        server_wait_client_close(&server_pipe);
    });

    let mut stdin_bytes = Vec::new();
    stdin_bytes.extend_from_slice(&frame_bytes(opaque_req_1));
    stdin_bytes.extend_from_slice(&frame_bytes(ping_req_2));
    let mut stdin = Cursor::new(stdin_bytes);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let client = PipeClient::new(&pipe_name);
    let stats =
        run_relay_loop(&mut stdin, &mut stdout, &mut stderr, &client).expect("relay succeeds");
    server_thread.join().expect("server thread");

    assert_eq!(stats.frames_relayed, 2);
    assert_eq!(stats.frames_errored, 0);
    assert!(
        stderr.is_empty(),
        "successful relay must emit nothing to stderr, got: {}",
        String::from_utf8_lossy(&stderr)
    );

    let mut out_cur = Cursor::new(stdout);
    let out1 = read_raw_frame(&mut out_cur, IPC_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    let out2 = read_raw_frame(&mut out_cur, IPC_MAX_FRAME_BYTES)
        .unwrap()
        .unwrap();
    assert!(read_raw_frame(&mut out_cur, IPC_MAX_FRAME_BYTES)
        .unwrap()
        .is_none());
    assert_eq!(out1, opaque_resp_1);
    assert_eq!(out2, ping_resp_2);
}

#[cfg(windows)]
#[test]
fn bridge_04_connects_under_service_pipe_sddl() {
    use std::thread;
    use win_pipe_test_helpers::*;

    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pipe_name = format!(r"\\.\pipe\localedr-bridge-b04-sddl-{}-{seq}", std::process::id());
    let server_pipe = create_single_instance_pipe(&pipe_name, true);

    let server_thread = thread::spawn(move || {
        accept_pipe_client(&server_pipe);
        let req_bytes = server_read_frame(&server_pipe);
        let mut framed_req = frame_bytes(&req_bytes);
        let decoded: IpcRequest = decode_ipc_frame(&framed_req).expect("decode Ping");
        assert_eq!(decoded, IpcRequest::Ping);
        framed_req.clear();

        let resp_framed = encode_ipc_frame(&IpcResponse::Pong {
            daemon_version: "0.1.0-sddl".to_string(),
            protocol_version: 1,
        })
        .unwrap();
        server_write_frame(&server_pipe, &resp_framed[4..]);
        server_wait_client_close(&server_pipe);
    });

    let client = PipeClient::new(&pipe_name);
    let (ver, proto) = client.ping().expect("connect and ping under SERVICE_PIPE_SDDL");
    server_thread.join().expect("server thread");
    assert_eq!(ver, "0.1.0-sddl");
    assert_eq!(proto, 1);
}

#[test]
fn bridge_05_sec_0003_rejects_untrusted_pipe_server_and_allows_authorized_paths() {
    // 1. Default pipe matching & path allowlist checks
    assert!(is_default_ipc_pipe(ledr_proto::IPC_PIPE_NAME));
    assert!(is_default_ipc_pipe(r"\\.\PIPE\LocalEDR-IPC"));
    assert!(!is_default_ipc_pipe(r"\\.\pipe\localedr-test-custom"));

    let prod_bridge = Path::new(r"C:\Program Files\LocalEDR\ledr-bridge-nm.exe");
    assert!(is_authorized_pipe_server_exe_with(
        r"C:\Program Files\LocalEDR\ledr-daemon.exe",
        Some(prod_bridge),
        true,
        false
    ));
    assert!(is_authorized_pipe_server_exe_with(
        r"\\?\c:/Program Files/LocalEDR/ledr-daemon.exe",
        Some(prod_bridge),
        true,
        false
    ));
    assert!(is_authorized_pipe_server_exe_with(
        r"D:\LocalEDR\target\debug\ledr-daemon.exe",
        Some(Path::new(r"D:\LocalEDR\target\debug\ledr-bridge-nm.exe")),
        false,
        false
    ));
    assert!(!is_authorized_pipe_server_exe_with(
        r"C:\Users\alice\Downloads\ledr-daemon.exe",
        Some(prod_bridge),
        false,
        true
    ));
    assert!(!is_authorized_pipe_server_exe_with("", Some(prod_bridge), false, true));

    // 2. Real Win32 Named Pipe server from untrusted test binary is rejected BEFORE sending bytes
    #[cfg(windows)]
    {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        use std::thread;
        use win_pipe_test_helpers::*;

        let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
        let pipe_name = format!(r"\\.\pipe\localedr-bridge-b05-spoof-{}-{seq}", std::process::id());
        let server_pipe = create_single_instance_pipe(&pipe_name, false);
        let client_connected = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&client_connected);

        let server_thread = thread::spawn(move || {
            accept_pipe_client_allow_early_close(&server_pipe);
            flag_clone.store(true, Ordering::SeqCst);
            // Server waits for client disconnect without receiving any request payload.
            server_wait_client_close(&server_pipe);
        });

        let req_frame = frame_bytes(&encode_ipc_frame(&IpcRequest::Ping).unwrap()[4..]);
        let mut stdin = Cursor::new(req_frame);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let client = PipeClient::new(&pipe_name).with_verify_server(true);
        let stats =
            run_relay_loop(&mut stdin, &mut stdout, &mut stderr, &client).expect("relay returns error frame");
        server_thread.join().expect("server thread");

        assert!(client_connected.load(Ordering::SeqCst));
        assert_eq!(stats.frames_relayed, 0);
        assert_eq!(stats.frames_errored, 1);

        let resp: IpcResponse = decode_ipc_frame(&stdout).expect("valid error frame on stdout");
        match resp {
            IpcResponse::Error { code, .. } => assert_eq!(code, "BRIDGE_TRANSPORT_ERROR"),
            other => panic!("expected Error frame, got {other:?}"),
        }
        assert!(String::from_utf8_lossy(&stderr).contains("pipe server verification failed"));
    }
}

#[test]
fn bridge_06_offline_daemon_returns_daemon_offline_json_and_logs_only_to_stderr() {
    struct MockOffline;
    impl FrameExchange for MockOffline {
        fn exchange_raw_frame(&self, _payload: &[u8]) -> Result<Vec<u8>, BridgeTransportError> {
            Err(BridgeTransportError::DaemonOffline("pipe not found".to_string()))
        }
    }

    let req = encode_ipc_frame(&IpcRequest::Ping).unwrap();
    let mut stdin = Cursor::new(req.clone());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let stats =
        run_relay_loop(&mut stdin, &mut stdout, &mut stderr, &MockOffline).expect("relay handles offline");
    assert_eq!(stats.frames_relayed, 0);
    assert_eq!(stats.frames_errored, 1);

    let resp: IpcResponse = decode_ipc_frame(&stdout).expect("decode offline response");
    match resp {
        IpcResponse::Error { code, message } => {
            assert_eq!(code, "DAEMON_OFFLINE");
            assert!(message.contains("offline"));
        }
        other => panic!("expected DAEMON_OFFLINE Error, got {other:?}"),
    }
    let stderr_str = String::from_utf8_lossy(&stderr);
    assert!(stderr_str.contains("DAEMON_OFFLINE") || stderr_str.contains("offline"));

    // Also test real nonexistent Windows Named Pipe path when running on Windows
    #[cfg(windows)]
    {
        let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
        let pipe_name = format!(r"\\.\pipe\localedr-missing-{}-{seq}", std::process::id());
        let client = PipeClient::new(&pipe_name);
        let mut stdin2 = Cursor::new(req);
        let mut stdout2 = Vec::new();
        let mut stderr2 = Vec::new();
        let stats2 = run_relay_loop(&mut stdin2, &mut stdout2, &mut stderr2, &client).unwrap();
        assert_eq!(stats2.frames_errored, 1);
        let resp2: IpcResponse = decode_ipc_frame(&stdout2).unwrap();
        assert!(matches!(
            resp2,
            IpcResponse::Error { ref code, .. } if code == "DAEMON_OFFLINE"
        ));
    }
}

#[cfg(windows)]
#[test]
fn bridge_07_pipe_io_enforces_bounded_read_timeout() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use win_pipe_test_helpers::*;

    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let pipe_name = format!(r"\\.\pipe\localedr-bridge-b07-timeout-{}-{seq}", std::process::id());
    let server_pipe = create_single_instance_pipe(&pipe_name, false);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);

    let server_thread = thread::spawn(move || {
        accept_pipe_client(&server_pipe);
        let _req = server_read_frame(&server_pipe);
        // Intentionally withhold response until client times out and releases the barrier.
        let _ = release_rx.recv();
    });

    let client = PipeClient::new(&pipe_name)
        .with_timeouts(Duration::from_millis(500), Duration::from_millis(80));
    let payload = &encode_ipc_frame(&IpcRequest::Ping).unwrap()[4..];
    let err = client
        .exchange_raw_frame(payload)
        .expect_err("stalled server must hit read timeout");
    assert!(matches!(err, BridgeTransportError::Timeout(_)), "unexpected err: {err:?}");
    assert_eq!(err.ipc_error_code(), "BRIDGE_TRANSPORT_ERROR");

    let _ = release_tx.send(());
    server_thread.join().expect("server thread joins cleanly");
}

#[cfg(windows)]
struct RegTestGuard {
    root_subkey: String,
}

#[cfg(windows)]
impl RegTestGuard {
    fn new(tag: &str) -> (Self, String) {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
        let root_subkey = format!(r"Software\LocalEDR-Test\{tag}-{}-{seq}", std::process::id());
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&root_subkey);
        (Self { root_subkey: root_subkey.clone() }, root_subkey)
    }
}

#[cfg(windows)]
impl Drop for RegTestGuard {
    fn drop(&mut self) {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(&self.root_subkey);
    }
}

#[cfg(windows)]
#[test]
fn bridge_08_setup_status_unregister_idempotent_roundtrip() {
    let (_reg_guard, prefix) = RegTestGuard::new("bridge-nm-b08");
    let temp_dir = TempDirGuard::new("ledr-bridge-nm-b08");
    let fake_bridge = temp_dir.path().join("ledr-bridge-nm.exe");
    let fake_ui = temp_dir.path().join("ledr-ui.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    fs::write(&fake_ui, b"MZ-test-ui").unwrap();

    let manifest_dir = temp_dir.path().join("nm");
    let target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(prefix),
    };

    let setup_args = SetupArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome, BrowserKind::Edge, BrowserKind::Brave],
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        bridge_exe: Some(fake_bridge.clone()),
        ui_exe: Some(fake_ui.clone()),
        manifest_dir: Some(manifest_dir.clone()),
        skip_uri: false,
        json: false,
    };

    let chrome_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Chrome));
    let edge_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Edge));
    let brave_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Brave));

    // 1. First setup writes per-browser manifests + 3 browser keys + ledr:// URI + AUMID
    let first = run_setup_with(&setup_args, &target).expect("first setup");
    assert!(first.manifest_written);
    assert!(first.uri_registered);
    assert!(first.uri_updated);
    assert!(first.aumid_updated);
    assert!(first.browsers.iter().all(|b| b.updated && b.manifest_written));
    assert!(chrome_manifest.is_file());
    assert!(edge_manifest.is_file());
    assert!(brave_manifest.is_file());

    // 2. Second setup is strictly idempotent
    let second = run_setup_with(&setup_args, &target).expect("second setup");
    assert!(!second.manifest_written);
    assert!(!second.uri_updated);
    assert!(!second.aumid_updated);
    assert!(second.browsers.iter().all(|b| !b.updated && !b.manifest_written));

    // 3. Status reads all 3 browsers + valid manifests + URI + AUMID
    let status_args = StatusArgs {
        scope: StatusScope::User,
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        ping: false,
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        json: false,
    };
    let report =
        run_status_with(&status_args, std::slice::from_ref(&target), Some(&manifest_dir))
            .expect("status");
    assert_eq!(report.scopes.len(), 1);
    let scope_report = &report.scopes[0];
    assert!(scope_report.uri_registered);
    assert!(scope_report.aumid_registered);
    assert_eq!(scope_report.browsers.len(), 3);
    assert!(scope_report
        .browsers
        .iter()
        .all(|b| b.registered && b.manifest.as_ref().is_some_and(|m| m.valid)));

    // 4. Unregistering only Chrome deletes Chrome's own manifest while Edge & Brave remain intact
    let unreg_chrome = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let res_chrome = run_unregister_with(&unreg_chrome, &target, None).expect("unreg chrome");
    assert!(res_chrome.manifest_removed);
    assert!(!chrome_manifest.exists());
    assert!(edge_manifest.is_file());
    assert!(brave_manifest.is_file());

    // 5. Unregistering remaining browsers without --keep-uri deletes remaining manifests + URI + AUMID
    let unreg_all = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Edge, BrowserKind::Brave],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: false,
        json: false,
    };
    let res_all = run_unregister_with(&unreg_all, &target, None).expect("unreg all");
    assert!(res_all.manifest_removed);
    assert!(res_all.uri_removed);
    assert!(res_all.aumid_removed);
    assert!(!edge_manifest.exists());
    assert!(!brave_manifest.exists());

    // 6. Repeat unregister is cleanly idempotent
    let res_repeat = run_unregister_with(&unreg_all, &target, None).expect("repeat unreg");
    assert!(!res_repeat.manifest_removed);
    assert!(!res_repeat.uri_removed);
    assert!(!res_repeat.aumid_removed);
    assert!(res_repeat.browsers.iter().all(|b| !b.removed));
}

#[test]
fn bridge_09_extension_id_derivation_and_validation() {
    // Known FIPS 180-4 SHA-256 vectors
    let empty_digest = sha256(b"");
    assert_eq!(
        empty_digest,
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55
        ]
    );
    let abc_digest = sha256(b"abc");
    assert_eq!(
        abc_digest,
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );

    assert_eq!(decode_base64("YWJj").unwrap(), b"abc");
    assert_eq!(decode_base64("YWI=").unwrap(), b"ab");
    assert_eq!(decode_base64("YQ==").unwrap(), b"a");
    assert!(decode_base64("").is_err());
    assert!(decode_base64("abc").is_err());
    assert!(decode_base64("ab=c").is_err());
    assert!(derive_extension_id_from_der(&[]).is_err());

    // Extension ID validator & origin formatter
    assert!(is_valid_extension_id(DEFAULT_CHROME_EXTENSION_ID));
    assert!(!is_valid_extension_id("ecelachfiiiiiibpjeomfncgpegbpan")); // 31 chars
    assert!(!is_valid_extension_id("ecelachfiiiiiibpjeomfncgpegbpanq")); // 'q' out of a..p
    assert!(!is_valid_extension_id("ECELACHFIIIIIIBPEOMFNCGPEGBPANHH")); // uppercase
    assert_eq!(
        chrome_extension_origin(DEFAULT_CHROME_EXTENSION_ID).unwrap(),
        format!("chrome-extension://{DEFAULT_CHROME_EXTENSION_ID}/")
    );
    assert!(chrome_extension_origin("invalid").is_err());

    // Verify extensions/ledr-chrome-mv3/manifest.json pinned "key" matches DEFAULT_CHROME_EXTENSION_ID
    let manifest_raw = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("extensions")
            .join("ledr-chrome-mv3")
            .join("manifest.json"),
    )
    .expect("read extension manifest.json");
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest_raw).expect("parse extension manifest.json");
    let pinned_key = manifest_json
        .get("key")
        .and_then(|v| v.as_str())
        .expect("manifest.json must contain string 'key'");
    let derived_id = derive_extension_id_from_base64_key(pinned_key).expect("derive extension ID");
    assert_eq!(derived_id, DEFAULT_CHROME_EXTENSION_ID);
}

#[test]
fn bridge_10_manifest_validation_rejects_corrupt_or_mismatched_origins() {
    let temp = TempDirGuard::new("ledr-bridge-nm-b10");
    let manifest_path = temp.path().join(MANIFEST_FILENAME);

    // 1. Missing manifest
    let missing = validate_manifest_file(&manifest_path, DEFAULT_CHROME_EXTENSION_ID);
    assert!(!missing.exists);
    assert!(!missing.valid);

    // 2. Corrupt JSON
    fs::write(&manifest_path, "{broken json").unwrap();
    let corrupt = validate_manifest_file(&manifest_path, DEFAULT_CHROME_EXTENSION_ID);
    assert!(corrupt.exists);
    assert!(!corrupt.valid);
    assert!(corrupt.error.unwrap().contains("invalid manifest JSON"));

    // 3. Valid JSON but missing bridge exe + mismatched extension ID
    let fake_exe = temp.path().join("ledr-bridge-nm.exe");
    let mut bad_manifest = build_manifest(&fake_exe, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    bad_manifest.host_type = "websocket".to_string();
    write_manifest_atomic(&manifest_path, &bad_manifest).unwrap();
    let invalid = validate_manifest_file(&manifest_path, DEFAULT_CHROME_EXTENSION_ID);
    assert!(invalid.exists);
    assert!(!invalid.valid);
    assert!(!invalid.bridge_exe_exists);
    assert!(!invalid.extension_id_matched);

    // 4. Create exe + matching manifest -> passes
    fs::write(&fake_exe, b"MZ-test").unwrap();
    let good_manifest = build_manifest(&fake_exe, DEFAULT_CHROME_EXTENSION_ID).unwrap();
    assert!(write_manifest_atomic(&manifest_path, &good_manifest).unwrap());
    let valid = validate_manifest_file(&manifest_path, DEFAULT_CHROME_EXTENSION_ID);
    assert!(valid.exists);
    assert!(valid.valid);
    assert!(valid.bridge_exe_exists);
    assert!(valid.extension_id_matched);
    assert_eq!(
        valid.allowed_origins,
        vec![format!("chrome-extension://{DEFAULT_CHROME_EXTENSION_ID}/")]
    );
    assert!(valid.error.is_none());
}

#[test]
fn bridge_11_user_scope_prefers_installed_authorized_paths() {
    let temp = TempDirGuard::new("ledr-bridge-nm-b11");
    let installed_bridge = temp.path().join("ledr-bridge-nm.exe");
    let installed_ui = temp.path().join("ledr-ui.exe");
    let nonexistent_bridge = temp.path().join("missing-bridge.exe");
    let nonexistent_ui = temp.path().join("missing-ui.exe");
    let override_bridge = temp.path().join("custom-bridge.exe");

    fs::write(&installed_bridge, b"MZ-installed-bridge").unwrap();
    fs::write(&installed_ui, b"MZ-installed-ui").unwrap();

    // When installed authorized binaries exist on disk, User scope must choose them over current_exe().
    let resolved_bridge =
        resolve_bridge_exe_with(Scope::User, None, &installed_bridge).expect("installed bridge");
    assert_eq!(resolved_bridge, installed_bridge);

    let resolved_ui =
        resolve_ui_exe_with(Scope::User, Path::new(r"C:\Temp\other\ledr-bridge-nm.exe"), None, &installed_ui)
            .expect("installed ui");
    assert_eq!(resolved_ui, installed_ui);

    // When installed binaries do not exist yet, User scope falls back to current_exe() / AUTHORIZED_UI_EXE_PATH.
    let fallback_bridge =
        resolve_bridge_exe_with(Scope::User, None, &nonexistent_bridge).expect("fallback bridge");
    assert_ne!(fallback_bridge, nonexistent_bridge);
    assert_eq!(fallback_bridge, std::env::current_exe().unwrap());

    let sibling_dir = temp.path().join("sibling");
    fs::create_dir_all(&sibling_dir).unwrap();
    let sibling_bridge = sibling_dir.join("ledr-bridge-nm.exe");
    let sibling_ui = sibling_dir.join("ledr-ui.exe");
    fs::write(&sibling_ui, b"MZ-sibling-ui").unwrap();
    let fallback_ui =
        resolve_ui_exe_with(Scope::User, &sibling_bridge, None, &nonexistent_ui).expect("sibling ui");
    assert_eq!(fallback_ui, sibling_ui);

    // Explicit --bridge-exe always overrides installed binary.
    let explicit = resolve_bridge_exe_with(Scope::User, Some(&override_bridge), &installed_bridge)
        .expect("override bridge");
    assert_eq!(explicit, override_bridge);
}

#[cfg(windows)]
#[test]
fn bridge_12_per_browser_manifests_and_cross_scope_unregister_protection() {
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let (_user_guard, user_prefix) = RegTestGuard::new("bridge-nm-b12-user");
    let (_peer_guard, peer_prefix) = RegTestGuard::new("bridge-nm-b12-peer");
    let temp = TempDirGuard::new("ledr-bridge-nm-b12");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    let fake_ui = temp.path().join("ledr-ui.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    fs::write(&fake_ui, b"MZ-test-ui").unwrap();

    let manifest_dir = temp.path().join("shared-nm");
    let alt_ext_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    let user_target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(user_prefix),
    };
    let peer_target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(peer_prefix),
    };

    // BUG_0004: Setting up Edge with a different --extension-id must not overwrite Chrome's manifest.
    let setup_chrome = SetupArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        bridge_exe: Some(fake_bridge.clone()),
        ui_exe: Some(fake_ui.clone()),
        manifest_dir: Some(manifest_dir.clone()),
        skip_uri: true,
        json: false,
    };
    let setup_edge = SetupArgs {
        browsers: vec![BrowserKind::Edge],
        extension_id: alt_ext_id.to_string(),
        ..setup_chrome.clone()
    };
    run_setup_with(&setup_chrome, &user_target).expect("setup chrome");
    run_setup_with(&setup_edge, &user_target).expect("setup edge");

    let chrome_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Chrome));
    let edge_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Edge));
    assert!(validate_manifest_file(&chrome_manifest, DEFAULT_CHROME_EXTENSION_ID).valid);
    assert!(validate_manifest_file(&edge_manifest, alt_ext_id).valid);
    assert!(!validate_manifest_file(&chrome_manifest, alt_ext_id).extension_id_matched);

    // Clean up Edge before testing BUG_0005.
    run_unregister_with(
        &UnregisterArgs {
            scope: Scope::User,
            browsers: vec![BrowserKind::Chrome, BrowserKind::Edge],
            manifest_dir: Some(manifest_dir.clone()),
            keep_uri: true,
            json: false,
        },
        &user_target,
        None,
    )
    .expect("cleanup isolated manifests");

    // BUG_0005: If both current scope and opposite peer scope reference the same manifest path
    // (e.g. legacy shared com.localedr.bridge.json), unregistering one scope must keep the file.
    let shared_manifest = manifest_dir.join(MANIFEST_FILENAME);
    let m = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();
    write_manifest_atomic(&shared_manifest, &m).unwrap();
    let shared_display = shared_manifest.to_string_lossy().into_owned();

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (u_key, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key.set_value("", &shared_display).unwrap();
    let (p_key, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key.set_value("", &shared_display).unwrap();

    let unreg_chrome = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let first_unreg =
        run_unregister_with(&unreg_chrome, &user_target, Some(&peer_target)).expect("first unreg");
    assert!(!first_unreg.manifest_removed);
    assert!(shared_manifest.is_file(), "shared manifest must remain while peer scope still points to it");

    // Once the peer scope also unregisters, no references remain so the shared manifest is removed.
    let second_unreg =
        run_unregister_with(&unreg_chrome, &peer_target, Some(&user_target)).expect("second unreg");
    assert!(second_unreg.manifest_removed);
    assert!(!shared_manifest.exists());
}

#[cfg(windows)]
#[test]
fn bridge_13_status_extension_id_and_relative_manifest_dir_absolutized() {
    let (_reg_guard, prefix) = RegTestGuard::new("bridge-nm-b13");
    let temp = TempDirGuard::new("ledr-bridge-nm-b13");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    let fake_ui = temp.path().join("ledr-ui.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    fs::write(&fake_ui, b"MZ-test-ui").unwrap();

    // BUG_0007: Relative overrides must be absolutized rather than stored verbatim as relative paths.
    let rel_manifest_dir =
        resolve_manifest_dir(Scope::User, Some(Path::new("relative-nm-dir"))).expect("abs manifest dir");
    assert!(rel_manifest_dir.is_absolute());
    let rel_bridge =
        resolve_bridge_exe_with(Scope::User, Some(Path::new(r"bin\ledr-bridge-nm.exe")), &fake_bridge)
            .expect("abs bridge exe");
    assert!(rel_bridge.is_absolute());
    let rel_ui = resolve_ui_exe_with(Scope::User, &fake_bridge, Some(Path::new(r"bin\ledr-ui.exe")), &fake_ui)
        .expect("abs ui exe");
    assert!(rel_ui.is_absolute());

    // BUG_0006: CLI --extension-id flows into status validation against custom extension IDs.
    let custom_ext_id = "cccccccccccccccccccccccccccccccc";
    let parsed_status = parse_args_from(
        ["ledr-bridge-nm.exe", "status", "--scope", "user", "--extension-id", custom_ext_id],
        None,
    )
    .expect("parse status --extension-id");
    let status_custom = match parsed_status {
        Command::Status(s) => {
            assert_eq!(s.extension_id, custom_ext_id);
            s
        }
        other => panic!("expected Status command, got {other:?}"),
    };

    let manifest_dir = temp.path().join("nm");
    let target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(prefix),
    };
    run_setup_with(
        &SetupArgs {
            scope: Scope::User,
            browsers: vec![BrowserKind::Chrome],
            extension_id: custom_ext_id.to_string(),
            bridge_exe: Some(fake_bridge),
            ui_exe: Some(fake_ui),
            manifest_dir: Some(manifest_dir.clone()),
            skip_uri: true,
            json: false,
        },
        &target,
    )
    .expect("setup custom extension id");

    let status_default = StatusArgs {
        scope: StatusScope::User,
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        ping: false,
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        json: false,
    };
    let mismatch_report =
        run_status_with(&status_default, std::slice::from_ref(&target), Some(&manifest_dir))
            .expect("status default mismatch");
    let mismatch_chrome = &mismatch_report.scopes[0].browsers[0];
    assert!(mismatch_chrome.registered);
    let mismatch_val = mismatch_chrome.manifest.as_ref().unwrap();
    assert!(!mismatch_val.valid);
    assert!(!mismatch_val.extension_id_matched);

    let matched_report =
        run_status_with(&status_custom, std::slice::from_ref(&target), Some(&manifest_dir))
            .expect("status custom match");
    let matched_chrome = &matched_report.scopes[0].browsers[0];
    let matched_val = matched_chrome.manifest.as_ref().unwrap();
    assert!(matched_val.valid);
    assert!(matched_val.extension_id_matched);
    assert_eq!(
        matched_val.allowed_origins,
        vec![format!("chrome-extension://{custom_ext_id}/")]
    );
}

#[test]
fn bridge_14_relay_caller_origin_and_authorized_browser_parent_checks() {
    let valid_origin = format!("chrome-extension://{DEFAULT_CHROME_EXTENSION_ID}/");
    assert!(is_valid_caller_origin(&valid_origin));
    assert!(!is_valid_caller_origin(""));
    assert!(!is_valid_caller_origin(&format!(
        "chrome-extension://{DEFAULT_CHROME_EXTENSION_ID}"
    )));
    assert!(!is_valid_caller_origin("chrome-extension://invalid-id/"));
    assert!(!is_valid_caller_origin("https://example.com/"));
    assert!(!is_valid_caller_origin(&format!("{valid_origin}extra")));

    let roots = [
        Path::new(r"C:\Program Files"),
        Path::new(r"C:\Program Files (x86)"),
        Path::new(r"C:\Users\Alice\AppData\Local"),
    ];
    assert!(is_authorized_browser_parent_exe_with(
        Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
        &roots
    ));
    assert!(is_authorized_browser_parent_exe_with(
        Path::new(r"\\?\C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
        &roots
    ));
    assert!(is_authorized_browser_parent_exe_with(
        Path::new(r"C:\Users\Alice\AppData\Local\BraveSoftware\Brave-Browser-Nightly\Application\brave.exe"),
        &roots
    ));
    // Reject traversal, arbitrary binaries, or non-standard parent shells
    assert!(!is_authorized_browser_parent_exe_with(
        Path::new(r"C:\Program Files\Google\Chrome\Application\..\..\Temp\chrome.exe"),
        &roots
    ));
    assert!(!is_authorized_browser_parent_exe_with(
        Path::new(r"C:\Temp\chrome.exe"),
        &roots
    ));
    assert!(!is_authorized_browser_parent_exe_with(
        Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        &roots
    ));

    // Production default pipe requires both valid caller_origin and authorized browser parent
    let missing_origin = RelayArgs {
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        caller_origin: None,
        parent_window: None,
    };
    assert!(verify_browser_relay_caller_with(&missing_origin, || Ok(())).is_err());

    let bad_origin = RelayArgs {
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        caller_origin: Some("chrome-extension://notvalid/".to_string()),
        parent_window: None,
    };
    assert!(verify_browser_relay_caller_with(&bad_origin, || Ok(())).is_err());

    let good_origin = RelayArgs {
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        caller_origin: Some(valid_origin.clone()),
        parent_window: None,
    };
    assert!(verify_browser_relay_caller_with(&good_origin, || anyhow::bail!("bad parent")).is_err());
    assert!(verify_browser_relay_caller_with(&good_origin, || Ok(())).is_ok());

    // Custom --pipe overrides bypass parent/origin checks for local test harnesses
    let custom_pipe = RelayArgs {
        pipe_name: r"\\.\pipe\localedr-test-harness".to_string(),
        caller_origin: None,
        parent_window: None,
    };
    assert!(verify_browser_relay_caller_with(&custom_pipe, || anyhow::bail!("must not run")).is_ok());

    // Live OS inspection under `cargo test` must reject the test runner / shell parent
    #[cfg(windows)]
    {
        assert!(verify_browser_relay_caller(&good_origin).is_err());
    }
}

#[cfg(windows)]
#[test]
fn bridge_15_unregister_preserves_shared_manifest_across_junction_hardlink_and_indeterminate_error() {
    use std::process::Command;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    let (_user_guard, user_prefix) = RegTestGuard::new("bridge-nm-b15-user");
    let (_peer_guard, peer_prefix) = RegTestGuard::new("bridge-nm-b15-peer");
    let temp = TempDirGuard::new("ledr-bridge-nm-b15");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();

    let real_dir = temp.path().join("real");
    let junction_dir = temp.path().join("junction");
    fs::create_dir_all(&real_dir).unwrap();

    let mklink_out = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &junction_dir.to_string_lossy(),
            &real_dir.to_string_lossy(),
        ])
        .output()
        .expect("run mklink /J");
    assert!(
        mklink_out.status.success(),
        "mklink /J must succeed without elevation: {}",
        String::from_utf8_lossy(&mklink_out.stderr)
    );

    let user_target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(user_prefix),
    };
    let peer_target = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(peer_prefix),
    };
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let manifest = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();

    // 1. Directory junction alias: HKCU points through junction while peer points to real path.
    let real_manifest = real_dir.join(MANIFEST_FILENAME);
    let junction_manifest = junction_dir.join(MANIFEST_FILENAME);
    write_manifest_atomic(&real_manifest, &manifest).unwrap();
    assert!(junction_manifest.is_file());

    let (u_key, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key
        .set_value("", &junction_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key
        .set_value("", &real_manifest.to_string_lossy().into_owned())
        .unwrap();

    let unreg_user = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(junction_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let res_junc =
        run_unregister_with(&unreg_user, &user_target, Some(&peer_target)).expect("unreg user");
    assert!(
        !res_junc.manifest_removed,
        "shared manifest via directory junction must be preserved while peer references real path"
    );
    assert!(real_manifest.is_file());

    let unreg_peer = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(real_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let res_peer =
        run_unregister_with(&unreg_peer, &peer_target, Some(&user_target)).expect("unreg peer");
    assert!(res_peer.manifest_removed);
    assert!(!real_manifest.exists());

    // Remove junction reparse point cleanly before continuing.
    fs::remove_dir(&junction_dir).expect("remove junction reparse point");

    // 1b. Chained 2-hop local junction (hop2 -> hop1 -> real) and extended verbatim path (\\?\C:\...)
    // must both resolve locally and preserve the shared manifest.
    let hop1_dir = temp.path().join("hop1");
    let hop2_dir = temp.path().join("hop2");
    let mk_hop1 = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &hop1_dir.to_string_lossy(),
            &real_dir.to_string_lossy(),
        ])
        .output()
        .expect("run mklink /J hop1");
    assert!(mk_hop1.status.success());
    let mk_hop2 = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &hop2_dir.to_string_lossy(),
            &hop1_dir.to_string_lossy(),
        ])
        .output()
        .expect("run mklink /J hop2");
    assert!(mk_hop2.status.success());

    let chained_real_manifest = real_dir.join("com.localedr.bridge.chained.json");
    let chained_hop2_manifest = hop2_dir.join("com.localedr.bridge.chained.json");
    write_manifest_atomic(&chained_real_manifest, &manifest).unwrap();
    let verbatim_real = format!(r"\\?\{}", chained_real_manifest.display());

    let (u_key1b, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key1b
        .set_value("", &chained_hop2_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key1b, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key1b.set_value("", &verbatim_real).unwrap();

    let res_chained = run_unregister_with(
        &UnregisterArgs {
            scope: Scope::User,
            browsers: vec![BrowserKind::Chrome],
            manifest_dir: Some(hop2_dir.clone()),
            keep_uri: true,
            json: false,
        },
        &user_target,
        Some(&peer_target),
    )
    .expect("unreg chained junction user");
    assert!(
        !res_chained.manifest_removed,
        "2-hop local junction and \\\\?\\ verbatim peer reference must preserve shared manifest"
    );
    assert!(chained_real_manifest.is_file());
    let _ = fs::remove_file(&chained_real_manifest);
    fs::remove_dir(&hop2_dir).expect("remove hop2 junction");
    fs::remove_dir(&hop1_dir).expect("remove hop1 junction");

    // 2. Hard link alias: distinct paths sharing the same NTFS file index must protect the manifest.
    let orig_manifest = real_dir.join("com.localedr.bridge.hardorig.json");
    let hardlink_manifest = temp.path().join("com.localedr.bridge.hardalias.json");
    write_manifest_atomic(&orig_manifest, &manifest).unwrap();
    fs::hard_link(&orig_manifest, &hardlink_manifest).expect("create hard link");

    let (u_key2, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key2
        .set_value("", &hardlink_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key2, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key2
        .set_value("", &orig_manifest.to_string_lossy().into_owned())
        .unwrap();

    let res_hl_user = run_unregister_with(
        &UnregisterArgs {
            scope: Scope::User,
            browsers: vec![BrowserKind::Chrome],
            manifest_dir: Some(temp.path().to_path_buf()),
            keep_uri: true,
            json: false,
        },
        &user_target,
        Some(&peer_target),
    )
    .expect("unreg hardlink user");
    assert!(
        !res_hl_user.manifest_removed,
        "hard-linked manifest alias must not be deleted while peer references same file ID"
    );
    assert!(hardlink_manifest.is_file());
    assert!(orig_manifest.is_file());

    let res_hl_peer = run_unregister_with(
        &UnregisterArgs {
            scope: Scope::User,
            browsers: vec![BrowserKind::Chrome],
            manifest_dir: Some(real_dir.clone()),
            keep_uri: true,
            json: false,
        },
        &peer_target,
        Some(&user_target),
    )
    .expect("unreg hardlink peer");
    assert!(res_hl_peer.manifest_removed);
    assert!(!orig_manifest.exists());
    let _ = fs::remove_file(&hardlink_manifest);

    // 3. Non-NotFound file identity error (e.g. ERROR_INVALID_NAME on peer entry) must conservatively keep file.
    let protected_manifest = real_dir.join("com.localedr.bridge.protected.json");
    write_manifest_atomic(&protected_manifest, &manifest).unwrap();
    let (u_key3, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key3
        .set_value("", &protected_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key3, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key3
        .set_value("", &r"C:\invalid<bad>path\com.localedr.bridge.json")
        .unwrap();

    let res_err = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg with indeterminate peer path");
    assert!(
        !res_err.manifest_removed,
        "non-NotFound identity lookup failure must conservatively skip deletion"
    );
    assert!(protected_manifest.is_file());

    // 4. Distinct existing file on peer scope does NOT block deletion of unrelated manifest.
    let other_manifest = real_dir.join("com.localedr.bridge.other.json");
    write_manifest_atomic(&other_manifest, &manifest).unwrap();
    let (u_key4, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key4
        .set_value("", &protected_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key4, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key4
        .set_value("", &other_manifest.to_string_lossy().into_owned())
        .unwrap();

    let res_distinct = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg distinct manifest");
    assert!(res_distinct.manifest_removed);
    assert!(!protected_manifest.exists());
    assert!(other_manifest.is_file());

    // 4b. Existing local directory on peer scope (e.g. `real_dir` or `C:\Windows`) must open via
    // `FILE_FLAG_BACKUP_SEMANTICS`, yield a distinct identity (not `Indeterminate`), and not block removal.
    for local_dir_peer in [real_dir.to_string_lossy().into_owned(), r"C:\Windows".to_string()] {
        let dir_peer_manifest = real_dir.join("com.localedr.bridge.dirpeer.json");
        write_manifest_atomic(&dir_peer_manifest, &manifest).unwrap();
        let (u_key_dp, _) = hkcu
            .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
            .unwrap();
        u_key_dp
            .set_value("", &dir_peer_manifest.to_string_lossy().into_owned())
            .unwrap();
        let (p_key_dp, _) = hkcu
            .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
            .unwrap();
        p_key_dp.set_value("", &local_dir_peer).unwrap();

        let res_dp = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
            .expect("unreg with local directory peer entry");
        assert!(
            res_dp.manifest_removed,
            "local directory peer entry '{local_dir_peer}' must not yield Indeterminate and block local manifest deletion"
        );
        assert!(!dir_peer_manifest.exists());
    }

    // 5. Non-local peer registry entries (UNC, extended UNC, device, relative) must be skipped
    // without invoking CreateFileW or touching SMB, allowing local manifest removal (SEC_0001).
    let non_local_peer_entries = [
        r"\\attacker.invalid\share\com.localedr.bridge.json",
        "//attacker.invalid/share/com.localedr.bridge.json",
        r"\\?\UNC\attacker.invalid\share\com.localedr.bridge.json",
        r"\\.\pipe\localedr-nonlocal-probe",
        r"relative\com.localedr.bridge.json",
    ];
    for (idx, non_local_entry) in non_local_peer_entries.iter().enumerate() {
        let local_manifest = real_dir.join(format!("com.localedr.bridge.nonlocal-{idx}.json"));
        write_manifest_atomic(&local_manifest, &manifest).unwrap();
        let (u_key_nl, _) = hkcu
            .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
            .unwrap();
        u_key_nl
            .set_value("", &local_manifest.to_string_lossy().into_owned())
            .unwrap();
        let (p_key_nl, _) = hkcu
            .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
            .unwrap();
        p_key_nl.set_value("", non_local_entry).unwrap();

        let res_nl = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
            .expect("unreg with non-local peer entry");
        assert!(
            res_nl.manifest_removed,
            "non-local peer entry '{non_local_entry}' must be skipped without blocking local unregister"
        );
        assert!(!local_manifest.exists());
    }

    // 5b. Non-local target registry entries (when no peer exists) must remove the registry key and
    // skip `remove_file` without touching SMB or device paths (SEC_0001).
    let _ = hkcu.delete_subkey_all(peer_target.browser_subkey(BrowserKind::Chrome));
    for non_local_target in [
        r"\\attacker.invalid\share\com.localedr.bridge.json",
        "//attacker.invalid/share/com.localedr.bridge.json",
        r"\\?\UNC\attacker.invalid\share\com.localedr.bridge.json",
        r"\\.\pipe\com.localedr.bridge.json",
        r"relative\com.localedr.bridge.json",
    ] {
        let (u_key_nlt, _) = hkcu
            .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
            .unwrap();
        u_key_nlt.set_value("", &non_local_target).unwrap();

        let res_nlt = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
            .expect("unreg with non-local target entry");
        assert!(
            res_nlt.browsers[0].removed,
            "registry key for non-local target '{non_local_target}' must still be removed"
        );
        assert!(
            !res_nlt.manifest_removed,
            "non-local target entry '{non_local_target}' must never invoke remove_file"
        );
    }

    // 5c. Local Volume GUID references (e.g. volume mounted at both a drive letter and a folder,
    // or folder-only volume mount without a drive letter) must never be misclassified as remote
    // and cause shared manifest deletion (BUG_0001).
    let vol_manifest = real_dir.join("com.localedr.bridge.volguid.json");
    let vol_other = real_dir.join("com.localedr.bridge.volguid-other.json");
    write_manifest_atomic(&vol_manifest, &manifest).unwrap();
    write_manifest_atomic(&vol_other, &manifest).unwrap();

    // Unmounted/folder-only Volume GUID peer must conservatively return Indeterminate and preserve file.
    let (u_key_vg_unm, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_unm
        .set_value("", &vol_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key_vg_unm, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_unm
        .set_value(
            "",
            &r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\LEDR\com.localedr.bridge.json",
        )
        .unwrap();
    let res_vg_unm = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg with unmounted Volume GUID peer");
    assert!(
        !res_vg_unm.manifest_removed,
        "unresolvable local Volume GUID peer must conservatively keep shared manifest"
    );
    assert!(vol_manifest.is_file());

    // Live OS Volume GUID for `real_dir`'s drive: resolves via GetVolumePathNamesForVolumeNameW
    // to the same file ID (preserving shared manifest) and distinguishes a different file on that volume.
    let drive_letter = crate::setup::extract_local_drive_letter(&vol_manifest)
        .expect("temp manifest path must have a local drive letter");
    let root_wide = [drive_letter as u16, b':' as u16, b'\\' as u16, 0];
    let mut vol_name_buf = [0u16; 128];
    // SAFETY: `root_wide` is NUL-terminated `X:\` and `vol_name_buf` holds 128 writable UTF-16 units.
    let got_vol = unsafe {
        win_pipe_test_helpers::GetVolumeNameForVolumeMountPointW(
            root_wide.as_ptr(),
            vol_name_buf.as_mut_ptr(),
            u32::try_from(vol_name_buf.len()).unwrap(),
        )
    };
    assert_ne!(got_vol, 0, "GetVolumeNameForVolumeMountPointW must succeed for local temp drive");
    let vol_len = vol_name_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(vol_name_buf.len());
    let live_vol_root = String::from_utf16(&vol_name_buf[..vol_len]).unwrap();
    let vol_manifest_str = vol_manifest.to_string_lossy();
    let vol_other_str = vol_other.to_string_lossy();
    let live_vol_same = format!("{live_vol_root}{}", &vol_manifest_str[3..]);
    let live_vol_diff = format!("{live_vol_root}{}", &vol_other_str[3..]);

    let (u_key_vg_same, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_same
        .set_value("", &vol_manifest_str.into_owned())
        .unwrap();
    let (p_key_vg_same, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_same.set_value("", &live_vol_same).unwrap();
    let res_vg_same = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg with live Volume GUID matching same manifest");
    assert!(
        !res_vg_same.manifest_removed,
        "live Volume GUID pointing to same manifest must preserve shared manifest"
    );
    assert!(vol_manifest.is_file());

    let (u_key_vg_diff, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_diff
        .set_value("", &vol_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key_vg_diff, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_diff.set_value("", &live_vol_diff).unwrap();
    let res_vg_diff = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg with live Volume GUID pointing to distinct file");
    assert!(
        res_vg_diff.manifest_removed,
        "live Volume GUID pointing to a different file must not block removing unrelated manifest"
    );
    assert!(!vol_manifest.exists());

    // Live Volume GUID as the deletion candidate itself (preserves `\\?\Volume{...}` through
    // normalize_display_path): preserved when peer references same file, deleted when peer
    // references an unrelated manifest.
    write_manifest_atomic(&vol_manifest, &manifest).unwrap();
    assert_eq!(
        crate::manifest::normalize_display_path(Path::new(&live_vol_same)),
        live_vol_same,
        "normalize_display_path must preserve \\\\?\\Volume{{guid}}\\... paths verbatim"
    );
    let (u_key_vg_cand_same, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_cand_same.set_value("", &live_vol_same).unwrap();
    let (p_key_vg_cand_same, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_cand_same
        .set_value("", &vol_manifest.to_string_lossy().into_owned())
        .unwrap();
    let res_vg_cand_same = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg Volume GUID candidate with matching drive-path peer");
    assert!(
        !res_vg_cand_same.manifest_removed,
        "Volume GUID deletion candidate must be preserved when peer references same file via drive letter"
    );
    assert!(vol_manifest.is_file());

    let (u_key_vg_cand_diff, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_cand_diff.set_value("", &live_vol_same).unwrap();
    let (p_key_vg_cand_diff, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_cand_diff
        .set_value("", &vol_other.to_string_lossy().into_owned())
        .unwrap();
    let res_vg_cand_diff = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg Volume GUID candidate with unrelated peer");
    assert!(
        res_vg_cand_diff.manifest_removed && res_vg_cand_diff.browsers[0].manifest_removed,
        "Volume GUID deletion candidate must be removed when peer references an unrelated manifest"
    );
    assert!(!vol_manifest.exists());
    assert!(vol_other.is_file());

    // Verbatim Volume GUID path containing a trailing-dot directory (`Data.`) must preserve
    // verbatim semantics during drive-letter rewriting rather than falling back to Win32 dot-stripping.
    let dot_dir_verbatim = PathBuf::from(format!(r"\\?\{}\Data.", real_dir.display()));
    let dot_manifest_verbatim = dot_dir_verbatim.join("com.localedr.bridge.dotvol.json");
    let dot_dir_display = format!(r"{}\Data.", real_dir.display());
    let live_vol_dot_manifest = format!(
        "{live_vol_root}{}\\com.localedr.bridge.dotvol.json",
        &dot_dir_display[3..]
    );
    fs::create_dir(&dot_dir_verbatim).expect("create verbatim trailing-dot dir Data.");
    write_manifest_atomic(&dot_manifest_verbatim, &manifest).unwrap();

    let (u_key_vg_dot_same, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_dot_same
        .set_value("", &live_vol_dot_manifest)
        .unwrap();
    let (p_key_vg_dot_same, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_dot_same
        .set_value("", &dot_manifest_verbatim.to_string_lossy().into_owned())
        .unwrap();
    let res_vg_dot_same = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg verbatim Data. Volume GUID with matching peer");
    assert!(
        !res_vg_dot_same.manifest_removed,
        "trailing-dot directory Volume GUID candidate must match verbatim peer and preserve manifest"
    );
    assert!(dot_manifest_verbatim.is_file());

    let (u_key_vg_dot_diff, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_vg_dot_diff
        .set_value("", &live_vol_dot_manifest)
        .unwrap();
    let (p_key_vg_dot_diff, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_vg_dot_diff
        .set_value("", &vol_other.to_string_lossy().into_owned())
        .unwrap();
    let res_vg_dot_diff = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg verbatim Data. Volume GUID with unrelated peer");
    assert!(
        res_vg_dot_diff.manifest_removed,
        "trailing-dot directory Volume GUID candidate must be deleted when peer references unrelated file"
    );
    assert!(!dot_manifest_verbatim.exists());
    let _ = fs::remove_dir(&dot_dir_verbatim);

    // Non-verbatim Win32 path with trailing dot through a reparse point (junction) must normalize
    // per Win32 rules before reparse rewriting so it matches the underlying shared manifest (BUG_0001).
    let trail_manifest = real_dir.join("com.localedr.bridge.dottrail.json");
    write_manifest_atomic(&trail_manifest, &manifest).unwrap();
    let trail_junction = temp.path().join("trail_junc");
    let mk_trail = Command::new("cmd.exe")
        .args([
            "/C",
            "mklink",
            "/J",
            &trail_junction.to_string_lossy(),
            &real_dir.to_string_lossy(),
        ])
        .output()
        .expect("run mklink /J trail_junc");
    assert!(mk_trail.status.success());
    let non_verbatim_trailing_dot = format!(
        r"{}\com.localedr.bridge.dottrail.json.",
        trail_junction.display()
    );
    let (u_key_td, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_td
        .set_value("", &trail_manifest.to_string_lossy().into_owned())
        .unwrap();
    let (p_key_td, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_td
        .set_value("", &non_verbatim_trailing_dot)
        .unwrap();
    let res_td = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg with trailing-dot non-verbatim junction peer");
    assert!(
        !res_td.manifest_removed,
        "non-verbatim trailing-dot path through reparse point must still match shared manifest"
    );
    assert!(trail_manifest.is_file());
    let _ = fs::remove_file(&trail_manifest);
    fs::remove_dir(&trail_junction).expect("remove trail_junc");

    // Distinct `Data` and `Data..` directories: Win32 `GetFullPathNameW` preserves `Data..`
    // (does not over-strip multiple dots to `Data`), so a non-verbatim peer referencing `Data..\...`
    // must match a verbatim Volume GUID candidate pointing to the exact same `Data..\...` file.
    let plain_data_dir = real_dir.join("Data");
    let dot2_dir_verbatim = PathBuf::from(format!(r"\\?\{}\Data..", real_dir.display()));
    let dot2_manifest_verbatim = dot2_dir_verbatim.join("com.localedr.bridge.dot2.json");
    let dot2_non_verbatim = format!(r"{}\Data..\com.localedr.bridge.dot2.json", real_dir.display());
    let live_vol_dot2 = format!(
        "{live_vol_root}{}\\Data..\\com.localedr.bridge.dot2.json",
        &real_dir.to_string_lossy()[3..]
    );
    fs::create_dir(&plain_data_dir).expect("create plain Data dir");
    fs::create_dir(&dot2_dir_verbatim).expect("create verbatim Data.. dir");
    write_manifest_atomic(&dot2_manifest_verbatim, &manifest).unwrap();

    let (u_key_d2, _) = hkcu
        .create_subkey_with_flags(user_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    u_key_d2.set_value("", &live_vol_dot2).unwrap();
    let (p_key_d2, _) = hkcu
        .create_subkey_with_flags(peer_target.browser_subkey(BrowserKind::Chrome), KEY_WRITE)
        .unwrap();
    p_key_d2.set_value("", &dot2_non_verbatim).unwrap();
    let res_d2 = run_unregister_with(&unreg_peer, &user_target, Some(&peer_target))
        .expect("unreg Volume GUID Data.. candidate with non-verbatim Data.. peer");
    assert!(
        !res_d2.manifest_removed,
        "non-verbatim Data.. peer must not over-strip to Data and must preserve shared Data.. manifest"
    );
    assert!(dot2_manifest_verbatim.is_file());
    let _ = fs::remove_file(&dot2_manifest_verbatim);
    let _ = fs::remove_dir(&dot2_dir_verbatim);
    let _ = fs::remove_dir(&plain_data_dir);
    let _ = fs::remove_file(&vol_other);

    // 6. Boundary checks for Layer 1 path parsing, Layer 2 DOS device / drive types, and Layer 3 reparse targets.
    use crate::setup::{
        classify_dos_device_target, dos_device_targets_match_volume, extract_local_drive_letter,
        is_local_drive_type, parse_reparse_data_buffer, parse_volume_guid_path,
        resolve_local_reparse_target, DosDeviceTarget, ParsedReparseBuffer,
        ReparseTargetResolution, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
        IO_REPARSE_TAG_DFS, IO_REPARSE_TAG_DFSR, IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_NFS,
        IO_REPARSE_TAG_SYMLINK, SYMLINK_FLAG_RELATIVE,
    };

    assert!(dos_device_targets_match_volume(
        r"\Device\HarddiskVolume3",
        r"\device\harddiskvolume3"
    ));
    assert!(!dos_device_targets_match_volume(
        r"\Device\HarddiskVolume3",
        r"\Device\HarddiskVolume4"
    ));
    assert!(!dos_device_targets_match_volume(
        r"\Device\HarddiskVolume3",
        r"\??\D:\override"
    ));
    assert!(!dos_device_targets_match_volume(
        r"\Device\LanmanRedirector\srv\sh",
        r"\Device\LanmanRedirector\srv\sh"
    ));

    assert_eq!(
        extract_local_drive_letter(Path::new(r"C:\ProgramData\LocalEDR\com.localedr.bridge.json")),
        Some('C')
    );
    assert_eq!(
        extract_local_drive_letter(Path::new("d:/LocalEDR/com.localedr.bridge.json")),
        Some('D')
    );
    assert_eq!(
        extract_local_drive_letter(Path::new(r"\\?\c:\LocalEDR\com.localedr.bridge.json")),
        Some('C')
    );
    for rejected in [
        r"\\server\share\com.localedr.bridge.json",
        "//server/share/com.localedr.bridge.json",
        r"\\?\UNC\server\share\com.localedr.bridge.json",
        r"\\.\C:\com.localedr.bridge.json",
        r"\\.\pipe\localedr-ipc",
        r"\??\C:\com.localedr.bridge.json",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\com.localedr.bridge.json",
        r"C:relative.json",
        r"\root-relative\com.localedr.bridge.json",
        r"relative\com.localedr.bridge.json",
        r"\\?\C:\dir\..\com.localedr.bridge.json",
        r"\\?\C:/slash/com.localedr.bridge.json",
        r"\\?\C:\dir/sub\com.localedr.bridge.json",
        "",
    ] {
        assert_eq!(
            extract_local_drive_letter(Path::new(rejected)),
            None,
            "path must be rejected as non-local: '{rejected}'"
        );
    }

    assert!(is_local_drive_type(DRIVE_REMOVABLE));
    assert!(is_local_drive_type(DRIVE_FIXED));
    assert!(is_local_drive_type(DRIVE_RAMDISK));
    assert!(!is_local_drive_type(0)); // DRIVE_UNKNOWN
    assert!(!is_local_drive_type(1)); // DRIVE_NO_ROOT_DIR
    assert!(!is_local_drive_type(DRIVE_REMOTE));
    assert!(!is_local_drive_type(5)); // DRIVE_CDROM

    assert_eq!(
        classify_dos_device_target(r"\Device\HarddiskVolume3"),
        DosDeviceTarget::VolumeDevice
    );
    assert_eq!(
        classify_dos_device_target(r"\??\C:\Users\alice\links"),
        DosDeviceTarget::Subst(PathBuf::from(r"C:\Users\alice\links"))
    );
    assert_eq!(
        classify_dos_device_target(r"\GLOBAL??\D:\LocalEDR"),
        DosDeviceTarget::Subst(PathBuf::from(r"D:\LocalEDR"))
    );
    assert_eq!(
        classify_dos_device_target(r"\DosDevices\c:"),
        DosDeviceTarget::Subst(PathBuf::from(r"C:\"))
    );
    for non_local_dos in [
        r"\??\UNC\attacker.invalid\share",
        r"\GLOBAL??\UNC\attacker.invalid\share",
        r"\DosDevices\UNC\attacker.invalid\share",
        r"\Device\LanmanRedirector\;Z:0000000000012345\attacker.invalid\share",
        r"\Device\Mup\;LanmanRedirector\attacker.invalid\share",
        r"\Device\Mup",
        r"\Device\WebDavRedirector\attacker.invalid@SSL\DavWWWRoot",
        r"\Device\RdpDr\;Z:0000000000012345\tsclient\share",
        r"\Device\HGFS\shared",
        r"\Device\VBoxMiniRdr\shared",
        r"\\attacker.invalid\share",
        "",
    ] {
        assert_eq!(
            classify_dos_device_target(non_local_dos),
            DosDeviceTarget::NonLocal,
            "DOS device target must be rejected as non-local: '{non_local_dos}'"
        );
    }

    let build_reparse_buf = |tag: u32, sub_name: &str, flags: Option<u32>| -> Vec<u8> {
        let wide_bytes: Vec<u8> = sub_name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let sub_len = u16::try_from(wide_bytes.len()).unwrap();
        let header_extra = if flags.is_some() { 12usize } else { 8usize };
        let data_len = u16::try_from(header_extra + wide_bytes.len()).unwrap();
        let mut buf = Vec::with_capacity(8 + usize::from(data_len));
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        buf.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buf.extend_from_slice(&sub_len.to_le_bytes()); // SubstituteNameLength
        buf.extend_from_slice(&0u16.to_le_bytes()); // PrintNameOffset
        buf.extend_from_slice(&0u16.to_le_bytes()); // PrintNameLength
        if let Some(f) = flags {
            buf.extend_from_slice(&f.to_le_bytes());
        }
        buf.extend_from_slice(&wide_bytes);
        buf
    };

    assert_eq!(
        parse_volume_guid_path(
            r"\\?\Volume{01234567-89AB-cdef-0123-456789abcdef}\LEDR\com.localedr.bridge.json"
        ),
        Some((
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_string(),
            vec!["LEDR".to_string(), "com.localedr.bridge.json".to_string()],
        ))
    );
    assert_eq!(
        parse_volume_guid_path(r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\"),
        Some((
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_string(),
            Vec::new(),
        ))
    );
    assert_eq!(
        parse_volume_guid_path(r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\..\evil"),
        None
    );
    assert_eq!(parse_volume_guid_path(r"\\?\Volume{not-a-guid}\a"), None);

    let link_path = Path::new(r"C:\Temp\links\alias");
    let mp_local = build_reparse_buf(IO_REPARSE_TAG_MOUNT_POINT, r"\??\C:\Temp\real", None);
    let ParsedReparseBuffer::Target(parsed_mp) = parse_reparse_data_buffer(&mp_local) else {
        panic!("parse local mount point");
    };
    assert_eq!(parsed_mp.tag, IO_REPARSE_TAG_MOUNT_POINT);
    assert!(!parsed_mp.is_relative);
    assert_eq!(
        resolve_local_reparse_target(&parsed_mp.substitute_name, parsed_mp.is_relative, link_path),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\Temp\real"))
    );
    // Volume mount point targeting `\??\Volume{guid}\` must be classified as `VolumeGuid`, not `Remote`.
    let mp_vol = build_reparse_buf(
        IO_REPARSE_TAG_MOUNT_POINT,
        r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\",
        None,
    );
    let ParsedReparseBuffer::Target(parsed_mp_vol) = parse_reparse_data_buffer(&mp_vol) else {
        panic!("parse volume mount point");
    };
    assert_eq!(
        resolve_local_reparse_target(
            &parsed_mp_vol.substitute_name,
            parsed_mp_vol.is_relative,
            link_path
        ),
        ReparseTargetResolution::VolumeGuid {
            volume_root: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_string(),
            segments: Vec::new(),
        }
    );
    assert_eq!(
        resolve_local_reparse_target(
            r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\a",
            false,
            link_path
        ),
        ReparseTargetResolution::VolumeGuid {
            volume_root: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_string(),
            segments: vec!["a".to_string()],
        }
    );
    // Verbatim `\\?\X:\...` absolute reparse target must resolve locally while rejecting `\\?\X:\..\...`.
    assert_eq!(
        resolve_local_reparse_target(r"\\?\C:\Temp\real", false, link_path),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\Temp\real"))
    );
    assert_eq!(
        resolve_local_reparse_target(r"\\?\C:", false, link_path),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\"))
    );
    assert_eq!(
        resolve_local_reparse_target(r"\\?\C:\Temp\..\real", false, link_path),
        ReparseTargetResolution::Remote
    );

    let sym_rel = build_reparse_buf(
        IO_REPARSE_TAG_SYMLINK,
        r"..\real\com.localedr.bridge.json",
        Some(SYMLINK_FLAG_RELATIVE),
    );
    let ParsedReparseBuffer::Target(parsed_rel) = parse_reparse_data_buffer(&sym_rel) else {
        panic!("parse relative symlink");
    };
    assert!(parsed_rel.is_relative);
    assert_eq!(
        resolve_local_reparse_target(
            &parsed_rel.substitute_name,
            parsed_rel.is_relative,
            Path::new(r"C:\Temp\links\alias.json")
        ),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\Temp\real\com.localedr.bridge.json"))
    );
    // Relative symlink under a `\\?\` verbatim (or >=248-byte) `link_path` must also resolve cleanly.
    assert_eq!(
        resolve_local_reparse_target(
            r"..\real\com.localedr.bridge.json",
            true,
            Path::new(r"\\?\C:\Temp\links\alias.json")
        ),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\Temp\real\com.localedr.bridge.json"))
    );
    assert_eq!(
        resolve_local_reparse_target(
            "../real/com.localedr.bridge.json",
            true,
            Path::new(r"\\?\C:\Temp\links\alias.json")
        ),
        ReparseTargetResolution::LocalDrive(PathBuf::from(r"C:\Temp\real\com.localedr.bridge.json"))
    );
    assert_eq!(
        resolve_local_reparse_target(r"..\real\a.json", true, Path::new(r"C:\")),
        ReparseTargetResolution::Remote
    );

    for (tag, target, flags) in [
        (IO_REPARSE_TAG_SYMLINK, r"\??\UNC\evil.invalid\share\a.json", Some(0)),
        (IO_REPARSE_TAG_SYMLINK, r"\\evil.invalid\share\a.json", Some(0)),
        (IO_REPARSE_TAG_SYMLINK, r"\Device\Mup\evil.invalid\share", Some(0)),
        (IO_REPARSE_TAG_SYMLINK, r"Device\Mup\evil.invalid\share", Some(0)),
        (IO_REPARSE_TAG_SYMLINK, r"\Device\LanmanRedirector\evil.invalid\share", Some(0)),
        (IO_REPARSE_TAG_SYMLINK, r"Device\LanmanRedirector\evil.invalid\share", Some(0)),
        (
            IO_REPARSE_TAG_SYMLINK,
            r"\\evil.invalid\share\a.json",
            Some(SYMLINK_FLAG_RELATIVE),
        ),
        (IO_REPARSE_TAG_MOUNT_POINT, r"\??\UNC\evil.invalid\share", None),
        (IO_REPARSE_TAG_MOUNT_POINT, r"\Device\Mup\evil.invalid\share", None),
    ] {
        let buf = build_reparse_buf(tag, target, flags);
        let ParsedReparseBuffer::Target(parsed) = parse_reparse_data_buffer(&buf) else {
            panic!("parse remote reparse buffer for '{target}'");
        };
        assert_eq!(
            resolve_local_reparse_target(&parsed.substitute_name, parsed.is_relative, link_path),
            ReparseTargetResolution::Remote,
            "remote/non-local reparse substitute target must be rejected: '{target}'"
        );
    }

    // Known network reparse tags (DFS/DFSR/NFS) must classify as `RemoteTag` (skipped as NonLocal),
    // while unknown local filter tags (e.g. WOF 0x8000_0017) classify as `Unsupported` (conservatively Indeterminate).
    for remote_tag in [IO_REPARSE_TAG_DFS, IO_REPARSE_TAG_DFSR, IO_REPARSE_TAG_NFS] {
        let rbuf = build_reparse_buf(remote_tag, r"\??\C:\Temp\real", None);
        assert_eq!(
            parse_reparse_data_buffer(&rbuf),
            ParsedReparseBuffer::RemoteTag(remote_tag)
        );
    }
    let wof_buf = build_reparse_buf(0x8000_0017, r"\??\C:\Temp\real", None);
    assert_eq!(
        parse_reparse_data_buffer(&wof_buf),
        ParsedReparseBuffer::Unsupported
    );
}

#[cfg(windows)]
#[test]
fn bridge_16_known_folder_roots_ignore_poisoned_env_vars() {
    use crate::pipe_client::{
        is_authorized_browser_parent_exe, standard_browser_install_roots,
        standard_system_cmd_exe_paths, win_pipe_auth,
    };
    use std::process::Command;

    let assert_known_folders_clean = || {
        // 1. All 5 machine-wide Known Folders resolve with hToken = NULL and ignore poisoned env vars.
        for (label, folder_id) in [
            ("ProgramFiles", &win_pipe_auth::FOLDERID_PROGRAM_FILES),
            ("ProgramFilesX64", &win_pipe_auth::FOLDERID_PROGRAM_FILES_X64),
            ("ProgramFilesX86", &win_pipe_auth::FOLDERID_PROGRAM_FILES_X86),
            ("System", &win_pipe_auth::FOLDERID_SYSTEM),
            ("SystemX86", &win_pipe_auth::FOLDERID_SYSTEM_X86),
        ] {
            let resolved = win_pipe_auth::resolve_machine_known_folder_path(folder_id)
                .unwrap_or_else(|| panic!("FOLDERID_{label} must resolve with hToken = NULL"));
            assert!(
                resolved.is_absolute(),
                "FOLDERID_{label} must be absolute: {resolved:?}"
            );
            assert!(
                !resolved
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("evilspoof"),
                "FOLDERID_{label} must ignore poisoned env vars: {resolved:?}"
            );
        }

        // 2. Per-user FOLDERID_LocalAppData resolves cleanly (via SHGetKnownFolderPath with
        // TOKEN_QUERY | TOKEN_IMPERSONATE when permitted, or GetUserProfileDirectoryW fallback
        // under restricted tokens) and ignores poisoned env vars.
        let local_app_data = win_pipe_auth::resolve_user_local_app_data_path()
            .expect("FOLDERID_LocalAppData must resolve even with poisoned env vars");
        let local_lower = local_app_data.to_string_lossy().to_ascii_lowercase();
        assert!(
            local_lower.ends_with(r"\appdata\local"),
            "unexpected LocalAppData path: {local_app_data:?}"
        );
        assert!(
            !local_lower.contains("evilspoof"),
            "FOLDERID_LocalAppData must ignore poisoned USERPROFILE/LOCALAPPDATA: {local_app_data:?}"
        );
        if let Some(primary_local_app_data) =
            win_pipe_auth::resolve_user_local_app_data_via_known_folder()
        {
            assert_eq!(
                primary_local_app_data.to_string_lossy().to_ascii_lowercase(),
                local_lower,
                "primary SHGetKnownFolderPath(LocalAppData) must agree with resolve_user_local_app_data_path"
            );
        }

        // 3. GetUserProfileDirectoryW (TOKEN_QUERY-only) fallback resolves cleanly without env vars
        // and is dispatched automatically when the primary Known Folder lookup fails.
        let fallback_local_app_data =
            win_pipe_auth::resolve_user_local_app_data_path_with(|| None)
                .expect("GetUserProfileDirectoryW fallback must trigger when primary fails");
        let fallback_direct = win_pipe_auth::resolve_local_app_data_via_user_profile_dir()
            .expect("GetUserProfileDirectoryW direct call must resolve without env vars");
        assert_eq!(fallback_local_app_data, fallback_direct);
        let fallback_lower = fallback_local_app_data
            .to_string_lossy()
            .to_ascii_lowercase();
        assert!(
            fallback_lower.ends_with(r"\appdata\local"),
            "unexpected GetUserProfileDirectoryW LocalAppData path: {fallback_local_app_data:?}"
        );
        assert!(
            !fallback_lower.contains("evilspoof"),
            "GetUserProfileDirectoryW fallback must ignore poisoned env vars: {fallback_local_app_data:?}"
        );
        assert_eq!(
            fallback_lower, local_lower,
            "GetUserProfileDirectoryW fallback must agree with SHGetKnownFolderPath(LocalAppData)"
        );

        let roots = standard_browser_install_roots();
        assert!(!roots.is_empty(), "SHGetKnownFolderPath must resolve browser install roots");
        assert!(
            roots.iter().all(|p| p.is_absolute()),
            "all Known Folder roots must be absolute: {roots:?}"
        );
        assert!(
            !roots
                .iter()
                .any(|p| p.to_string_lossy().to_ascii_lowercase().contains("evilspoof")),
            "Known Folder roots must ignore poisoned env vars: {roots:?}"
        );

        let cmd_paths = standard_system_cmd_exe_paths();
        assert!(!cmd_paths.is_empty(), "SHGetKnownFolderPath must resolve System cmd.exe paths");
        assert!(
            cmd_paths
                .iter()
                .all(|p| p.to_string_lossy().to_ascii_lowercase().ends_with(r"\cmd.exe")),
            "system cmd paths must end with cmd.exe: {cmd_paths:?}"
        );
        assert!(
            cmd_paths.iter().any(|p| p.is_file()),
            "at least one resolved system cmd.exe must exist on disk: {cmd_paths:?}"
        );
        assert!(
            !cmd_paths
                .iter()
                .any(|p| p.to_string_lossy().to_ascii_lowercase().contains("evilspoof")),
            "system cmd paths must ignore poisoned env vars: {cmd_paths:?}"
        );

        let spoofed_chrome = Path::new(r"C:\EvilSpoof\Google\Chrome\Application\chrome.exe");
        assert!(!is_authorized_browser_parent_exe(spoofed_chrome));
        let valid_chrome = roots[0].join(r"Google\Chrome\Application\chrome.exe");
        assert!(is_authorized_browser_parent_exe(&valid_chrome));

        let cmd_refs: Vec<&Path> = cmd_paths.iter().map(PathBuf::as_path).collect();
        assert!(!is_authorized_cmd_exe_with(Path::new(r"C:\EvilSpoof\cmd.exe"), &cmd_refs));
        assert!(is_authorized_cmd_exe_with(&cmd_paths[0], &cmd_refs));

        // Unknown GUID must return None without crashing or leaking.
        let invalid_guid = win_pipe_auth::Guid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        };
        assert!(win_pipe_auth::resolve_machine_known_folder_path(&invalid_guid).is_none());
    };

    if std::env::var_os("LEDR_TEST_BRIDGE16_CHILD").is_some() {
        assert_known_folders_clean();
        return;
    }

    assert_known_folders_clean();

    // Verify in an isolated child process with poisoned env vars (without mutating parent env).
    let output = Command::new(std::env::current_exe().expect("current test binary"))
        .args([
            "--exact",
            "tests::bridge_16_known_folder_roots_ignore_poisoned_env_vars",
            "--nocapture",
        ])
        .env("LEDR_TEST_BRIDGE16_CHILD", "1")
        .env("ProgramFiles", r"C:\EvilSpoof")
        .env("ProgramW6432", r"C:\EvilSpoof")
        .env("ProgramFiles(x86)", r"C:\EvilSpoof")
        .env("LOCALAPPDATA", r"C:\EvilSpoof")
        .env("USERPROFILE", r"C:\EvilSpoof")
        .env("SystemRoot", r"C:\EvilSpoof")
        .env("WINDIR", r"C:\EvilSpoof")
        .env("ComSpec", r"C:\EvilSpoof\cmd.exe")
        .output()
        .expect("spawn poisoned-env child test");
    assert!(
        output.status.success(),
        "poisoned-env child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn bridge_17_caller_chain_direct_cmd_mediated_rejections_and_status_policy() {
    let browser_roots = [
        Path::new(r"C:\Program Files"),
        Path::new(r"C:\Program Files (x86)"),
        Path::new(r"C:\Users\Alice\AppData\Local"),
    ];
    let cmd_paths = [
        Path::new(r"C:\Windows\System32\cmd.exe"),
        Path::new(r"C:\Windows\SysWOW64\cmd.exe"),
    ];
    let chrome_exe = PathBuf::from(r"C:\Program Files\Google\Chrome\Application\chrome.exe");
    let edge_exe = PathBuf::from(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe");
    let sys32_cmd = PathBuf::from(r"C:\Windows\System32\cmd.exe");
    let syswow_cmd = PathBuf::from(r"C:\Windows\SysWOW64\cmd.exe");

    // 1. Direct authorized browser parent passes.
    let direct_ok = BrowserCallerChain {
        self_create_time_100ns: 300,
        parent: ProcessSnapshot {
            pid: 1000,
            create_time_100ns: 200,
            exe_path: chrome_exe.clone(),
        },
        grandparent: None,
        stdin_transport: StdHandleTransport::NonPipe,
        stdout_transport: StdHandleTransport::NonPipe,
    };
    assert!(evaluate_browser_caller_chain(&direct_ok, &browser_roots, &cmd_paths).is_ok());

    // 2. Direct parent with reversed timestamp (PID reuse) is rejected.
    let direct_reversed = BrowserCallerChain {
        self_create_time_100ns: 150,
        ..direct_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&direct_reversed, &browser_roots, &cmd_paths).is_err());

    // 3. cmd.exe mediated with authorized browser grandparent + pipe stdio matching grandparent PID passes.
    let mediated_ok = BrowserCallerChain {
        self_create_time_100ns: 300,
        parent: ProcessSnapshot {
            pid: 2000,
            create_time_100ns: 200,
            exe_path: sys32_cmd.clone(),
        },
        grandparent: Some(ProcessSnapshot {
            pid: 1000,
            create_time_100ns: 100,
            exe_path: chrome_exe.clone(),
        }),
        stdin_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(1000),
        },
        stdout_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(1000),
        },
    };
    assert!(evaluate_browser_caller_chain(&mediated_ok, &browser_roots, &cmd_paths).is_ok());

    // 4. SysWOW64 cmd.exe with Edge grandparent and pipe handles where GetNamedPipeServerProcessId returns None passes.
    let mediated_wow64_ok = BrowserCallerChain {
        parent: ProcessSnapshot {
            pid: 2001,
            create_time_100ns: 200,
            exe_path: syswow_cmd,
        },
        grandparent: Some(ProcessSnapshot {
            pid: 1001,
            create_time_100ns: 100,
            exe_path: edge_exe,
        }),
        stdin_transport: StdHandleTransport::Pipe {
            pipe_server_pid: None,
        },
        stdout_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(1001),
        },
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&mediated_wow64_ok, &browser_roots, &cmd_paths).is_ok());

    // 5. Standalone cmd.exe (missing grandparent or untrusted grandparent) is rejected.
    let cmd_no_gp = BrowserCallerChain {
        grandparent: None,
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&cmd_no_gp, &browser_roots, &cmd_paths).is_err());

    let cmd_bad_gp = BrowserCallerChain {
        grandparent: Some(ProcessSnapshot {
            pid: 1000,
            create_time_100ns: 100,
            exe_path: PathBuf::from(r"C:\Windows\explorer.exe"),
        }),
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&cmd_bad_gp, &browser_roots, &cmd_paths).is_err());

    // 6. Fake cmd.exe outside System/SystemX86 is rejected even with valid grandparent & pipes.
    let fake_cmd = BrowserCallerChain {
        parent: ProcessSnapshot {
            pid: 2000,
            create_time_100ns: 200,
            exe_path: PathBuf::from(r"C:\Temp\cmd.exe"),
        },
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&fake_cmd, &browser_roots, &cmd_paths).is_err());

    // 7. Non-pipe (console/file) stdin or stdout is rejected under cmd.exe mediation.
    let non_pipe_in = BrowserCallerChain {
        stdin_transport: StdHandleTransport::NonPipe,
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&non_pipe_in, &browser_roots, &cmd_paths).is_err());

    let non_pipe_out = BrowserCallerChain {
        stdout_transport: StdHandleTransport::NonPipe,
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&non_pipe_out, &browser_roots, &cmd_paths).is_err());

    // 8. Pipe server PID mismatch (e.g. cmd.exe PID or attacker PID or 0) is rejected.
    let bad_stdin_pid = BrowserCallerChain {
        stdin_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(2000),
        },
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&bad_stdin_pid, &browser_roots, &cmd_paths).is_err());

    let bad_stdout_pid = BrowserCallerChain {
        stdout_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(9999),
        },
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&bad_stdout_pid, &browser_roots, &cmd_paths).is_err());

    let zero_pipe_pid = BrowserCallerChain {
        stdin_transport: StdHandleTransport::Pipe {
            pipe_server_pid: Some(0),
        },
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&zero_pipe_pid, &browser_roots, &cmd_paths).is_err());

    // 9. Timestamp reversal between grandparent, cmd.exe, and self is rejected.
    let gp_after_cmd = BrowserCallerChain {
        grandparent: Some(ProcessSnapshot {
            pid: 1000,
            create_time_100ns: 250,
            exe_path: chrome_exe,
        }),
        ..mediated_ok.clone()
    };
    assert!(evaluate_browser_caller_chain(&gp_after_cmd, &browser_roots, &cmd_paths).is_err());

    let cmd_after_self = BrowserCallerChain {
        self_create_time_100ns: 150,
        ..mediated_ok
    };
    assert!(evaluate_browser_caller_chain(&cmd_after_self, &browser_roots, &cmd_paths).is_err());

    // 10. Status reports NativeHostsExecutablesLaunchDirectly policy only when present.
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
        use winreg::RegKey;

        let (_reg_guard, prefix) = RegTestGuard::new("bridge-nm-b17-policy");
        let temp = TempDirGuard::new("ledr-bridge-nm-b17");
        let target = RegistryTarget {
            scope: Scope::User,
            key_prefix: Some(prefix),
        };
        let status_args = StatusArgs {
            scope: StatusScope::User,
            extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
            ping: false,
            pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
            json: false,
        };

        // Absent policy keys: omitted from both text and JSON.
        let report_absent =
            run_status_with(&status_args, std::slice::from_ref(&target), Some(temp.path()))
                .expect("status without policy");
        assert!(report_absent.scopes[0]
            .browsers
            .iter()
            .all(|b| b.native_hosts_launch_directly.is_none()));
        let text_absent = format_status_text(&report_absent);
        assert!(!text_absent.contains(NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE));
        let json_absent = serde_json::to_string(&report_absent).unwrap();
        assert!(!json_absent.contains("native_hosts_launch_directly"));

        // Present policy keys: Chrome=0 (cmd.exe mediated), Edge=1 (direct), Brave=None.
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let chrome_pol_key = target.browser_policy_subkey(BrowserKind::Chrome).unwrap();
        let edge_pol_key = target.browser_policy_subkey(BrowserKind::Edge).unwrap();
        let (ck, _) = hkcu.create_subkey_with_flags(&chrome_pol_key, KEY_WRITE).unwrap();
        ck.set_value(NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE, &0u32).unwrap();
        let (ek, _) = hkcu.create_subkey_with_flags(&edge_pol_key, KEY_WRITE).unwrap();
        ek.set_value(NATIVE_HOSTS_LAUNCH_DIRECTLY_VALUE, &1u32).unwrap();

        let report_present =
            run_status_with(&status_args, std::slice::from_ref(&target), Some(temp.path()))
                .expect("status with policy");
        let browsers = &report_present.scopes[0].browsers;
        assert_eq!(browsers[0].native_hosts_launch_directly, Some(false));
        assert_eq!(browsers[1].native_hosts_launch_directly, Some(true));
        assert_eq!(browsers[2].native_hosts_launch_directly, None);
        let text_present = format_status_text(&report_present);
        assert!(text_present.contains("NativeHostsExecutablesLaunchDirectly=0 (cmd.exe mediated)"));
        assert!(text_present.contains("NativeHostsExecutablesLaunchDirectly=1 (direct)"));
    }
}

#[cfg(windows)]
#[test]
fn bridge_18_cmd_mediated_pipe_inheritance_real_kernel() {
    use crate::pipe_client::{standard_system_cmd_exe_paths, win_pipe_auth, StdHandleTransport};
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::Read;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    if let Ok(gp_pid_str) = std::env::var("LEDR_TEST_BRIDGE18_GRANDPARENT_PID") {
        let expected_gp_pid: u32 = gp_pid_str
            .parse()
            .expect("LEDR_TEST_BRIDGE18_GRANDPARENT_PID must be u32");
        let stdin_transport =
            win_pipe_auth::inspect_std_handle_transport(win_pipe_auth::STD_INPUT_HANDLE);
        let stdout_transport =
            win_pipe_auth::inspect_std_handle_transport(win_pipe_auth::STD_OUTPUT_HANDLE);

        assert_eq!(
            stdin_transport,
            StdHandleTransport::Pipe {
                pipe_server_pid: Some(expected_gp_pid),
            },
            "inherited STD_INPUT_HANDLE must be a pipe owned by grandparent PID {expected_gp_pid}"
        );
        assert_eq!(
            stdout_transport,
            StdHandleTransport::Pipe {
                pipe_server_pid: Some(expected_gp_pid),
            },
            "inherited STD_OUTPUT_HANDLE must be a pipe owned by grandparent PID {expected_gp_pid}"
        );

        // Grandparent is the test binary (not Chrome/Edge/Brave), so production caller verification
        // must successfully traverse self -> System cmd.exe -> grandparent and fail closed specifically
        // at the grandparent browser allowlist check.
        let verify_err = win_pipe_auth::verify_browser_parent_process()
            .expect_err("cmd.exe mediated launch from non-browser grandparent must still be rejected");
        let verify_err_msg = verify_err.to_string();
        assert!(
            verify_err_msg.contains("via cmd.exe PID ")
                && verify_err_msg.contains(&format!("from untrusted grandparent PID {expected_gp_pid}")),
            "expected cmd.exe -> grandparent rejection for PID {expected_gp_pid}, got: {verify_err_msg}"
        );

        println!(
            "BRIDGE18_OK gp_pid={expected_gp_pid} stdin={stdin_transport:?} stdout={stdout_transport:?}"
        );
        return;
    }

    let cmd_exe = standard_system_cmd_exe_paths()
        .into_iter()
        .find(|p| p.is_file())
        .expect("system cmd.exe must exist");
    let test_exe = std::env::current_exe().expect("current test binary");
    let gp_pid = std::process::id();

    let create_inheritable_pipe = || -> (*mut c_void, *mut c_void) {
        let sa = win_pipe_test_helpers::SecurityAttributes {
            n_length: u32::try_from(std::mem::size_of::<win_pipe_test_helpers::SecurityAttributes>())
                .unwrap(),
            lp_security_descriptor: std::ptr::null_mut(),
            b_inherit_handle: 1,
        };
        let mut read_h: *mut c_void = std::ptr::null_mut();
        let mut write_h: *mut c_void = std::ptr::null_mut();
        // SAFETY: `read_h`, `write_h`, and `sa` are valid stack locals.
        let ok = unsafe { win_pipe_test_helpers::CreatePipe(&mut read_h, &mut write_h, &sa, 0) };
        assert_ne!(
            ok,
            0,
            "CreatePipe failed: {}",
            std::io::Error::last_os_error()
        );
        (read_h, write_h)
    };

    // Stdin pipe: child inherits read end; grandparent retains non-inheritable write end.
    let (stdin_read_h, stdin_write_h) = create_inheritable_pipe();
    // SAFETY: Both handles were freshly created by `CreatePipe`.
    let stdin_child = unsafe { Stdio::from_raw_handle(stdin_read_h) };
    // SAFETY: Owned handle retained by grandparent until child exits.
    let stdin_parent_write = unsafe { File::from_raw_handle(stdin_write_h) };
    // SAFETY: Clearing HANDLE_FLAG_INHERIT on a valid owned pipe handle.
    let clear_in_ok = unsafe {
        win_pipe_test_helpers::SetHandleInformation(
            stdin_parent_write.as_raw_handle(),
            win_pipe_test_helpers::HANDLE_FLAG_INHERIT,
            0,
        )
    };
    assert_ne!(clear_in_ok, 0, "SetHandleInformation(stdin_write) failed");

    // Stdout pipe: child inherits write end; grandparent retains non-inheritable read end.
    let (stdout_read_h, stdout_write_h) = create_inheritable_pipe();
    // SAFETY: Both handles were freshly created by `CreatePipe`.
    let mut stdout_parent_read = unsafe { File::from_raw_handle(stdout_read_h) };
    // SAFETY: Owned handle transferred to `Stdio` for child inheritance.
    let stdout_child = unsafe { Stdio::from_raw_handle(stdout_write_h) };
    // SAFETY: Clearing HANDLE_FLAG_INHERIT on a valid owned pipe handle.
    let clear_out_ok = unsafe {
        win_pipe_test_helpers::SetHandleInformation(
            stdout_parent_read.as_raw_handle(),
            win_pipe_test_helpers::HANDLE_FLAG_INHERIT,
            0,
        )
    };
    assert_ne!(clear_out_ok, 0, "SetHandleInformation(stdout_read) failed");

    let raw_cmd = format!(
        "/D /C \"\"{}\" --exact tests::bridge_18_cmd_mediated_pipe_inheritance_real_kernel --nocapture\"",
        test_exe.display()
    );
    let mut child = Command::new(&cmd_exe)
        .raw_arg(&raw_cmd)
        .env("LEDR_TEST_BRIDGE18_GRANDPARENT_PID", gp_pid.to_string())
        .stdin(stdin_child)
        .stdout(stdout_child)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cmd.exe /D /C grandchild");

    let mut stderr_pipe = child.stderr.take().expect("captured stderr");
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let mut stdout_buf = Vec::new();
    stdout_parent_read
        .read_to_end(&mut stdout_buf)
        .expect("read grandchild stdout pipe");
    // Keep grandparent's stdin write handle open until grandchild completes and closes stdout.
    drop(stdin_parent_write);

    let status = child.wait().expect("wait cmd.exe child");
    let stderr_text = stderr_thread.join().expect("join stderr reader");
    let stdout_text = String::from_utf8_lossy(&stdout_buf);

    assert!(
        status.success(),
        "cmd.exe mediated grandchild failed (status={status}):\nstdout: {stdout_text}\nstderr: {stderr_text}"
    );
    assert!(
        stdout_text.contains("BRIDGE18_OK"),
        "missing BRIDGE18_OK marker in grandchild stdout:\nstdout: {stdout_text}\nstderr: {stderr_text}"
    );
    println!("{stdout_text}");
}

#[test]
fn bridge_19_select_effective_hklm_probe_exhaustive_matrix() {
    use NativeHostRegProbe::{
        Absent, AccessError, EmptyString, InvalidType, Present, UnresolvableExpandSz,
    };

    let p32 = Present(r"C:\ProgramData\LocalEDR\native-messaging\m32.json".to_string());
    let p64 = Present(r"C:\ProgramData\LocalEDR\native-messaging\m64.json".to_string());
    let unres32 = UnresolvableExpandSz {
        raw: r"%LEDR_MISSING_32%\m32.json".to_string(),
        error: "unresolved-32".to_string(),
    };
    let unres64 = UnresolvableExpandSz {
        raw: r"%LEDR_MISSING_64%\m64.json".to_string(),
        error: "unresolved-64".to_string(),
    };
    let err32 = AccessError("denied-32".to_string());
    let err64 = AccessError("denied-64".to_string());

    let variants_32 = [
        p32.clone(),
        EmptyString,
        unres32.clone(),
        Absent,
        InvalidType,
        err32.clone(),
    ];
    let variants_64 = [
        p64.clone(),
        EmptyString,
        unres64.clone(),
        Absent,
        InvalidType,
        err64.clone(),
    ];

    // Verify all 36 combinations of (view32, view64) follow Chromium's HKLM WOW64 precedence:
    // - 32-bit Present, EmptyString, and UnresolvableExpandSz stop fallback and win over any 64-bit state.
    // - Only 32-bit Absent / InvalidType / AccessError falls back to 64-bit Present / EmptyString / UnresolvableExpandSz.
    for v32 in &variants_32 {
        for v64 in &variants_64 {
            let expected = match (v32, v64) {
                (Present(_) | EmptyString | UnresolvableExpandSz { .. }, _) => {
                    (v32.clone(), Some(RegWow64View::Wow6432))
                }
                (_, Present(_) | EmptyString | UnresolvableExpandSz { .. }) => {
                    (v64.clone(), Some(RegWow64View::Wow6464))
                }
                (Absent, Absent) => (Absent, None),
                (Absent, _) => (v64.clone(), Some(RegWow64View::Wow6464)),
                (_, Absent) => (v32.clone(), Some(RegWow64View::Wow6432)),
                _ => (v32.clone(), Some(RegWow64View::Wow6432)),
            };
            assert_eq!(
                select_effective_hklm_probe(v32.clone(), v64.clone()),
                expected,
                "mismatch for view32={v32:?}, view64={v64:?}"
            );
        }
    }

    // Explicit spot checks for critical invariants
    assert_eq!(
        select_effective_hklm_probe(EmptyString, p64.clone()),
        (EmptyString, Some(RegWow64View::Wow6432))
    );
    assert_eq!(
        select_effective_hklm_probe(unres32.clone(), p64.clone()),
        (unres32, Some(RegWow64View::Wow6432))
    );
    assert_eq!(
        select_effective_hklm_probe(p32.clone(), p64.clone()),
        (p32, Some(RegWow64View::Wow6432))
    );
    assert_eq!(
        select_effective_hklm_probe(Absent, unres64.clone()),
        (unres64.clone(), Some(RegWow64View::Wow6464))
    );
    assert_eq!(
        select_effective_hklm_probe(InvalidType, unres64.clone()),
        (unres64.clone(), Some(RegWow64View::Wow6464))
    );
    assert_eq!(
        select_effective_hklm_probe(err32.clone(), unres64.clone()),
        (unres64, Some(RegWow64View::Wow6464))
    );
    assert_eq!(
        select_effective_hklm_probe(InvalidType, p64.clone()),
        (p64.clone(), Some(RegWow64View::Wow6464))
    );
    assert_eq!(
        select_effective_hklm_probe(err32, p64.clone()),
        (p64, Some(RegWow64View::Wow6464))
    );
    assert_eq!(
        select_effective_hklm_probe(Absent, err64.clone()),
        (err64, Some(RegWow64View::Wow6464))
    );
}

type MockNmhMap = std::collections::HashMap<(Scope, String, Option<RegWow64View>), NativeHostRegProbe>;

#[derive(Default)]
struct MockRegistryViewOps {
    nmh_entries: std::sync::Mutex<MockNmhMap>,
    uri_cmds: std::sync::Mutex<std::collections::HashMap<Scope, String>>,
    aumids: std::sync::Mutex<std::collections::HashMap<Scope, String>>,
    probe_calls: std::sync::Mutex<Vec<(Scope, String, Option<RegWow64View>)>>,
}

impl MockRegistryViewOps {
    fn set_entry(
        &self,
        scope: Scope,
        subkey: &str,
        view: Option<RegWow64View>,
        probe: NativeHostRegProbe,
    ) {
        self.nmh_entries
            .lock()
            .unwrap()
            .insert((scope, subkey.to_string(), view), probe);
    }

    fn get_entry(
        &self,
        scope: Scope,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> NativeHostRegProbe {
        self.nmh_entries
            .lock()
            .unwrap()
            .get(&(scope, subkey.to_string(), view))
            .cloned()
            .unwrap_or(NativeHostRegProbe::Absent)
    }

    fn take_probe_calls(&self) -> Vec<(Scope, String, Option<RegWow64View>)> {
        std::mem::take(&mut *self.probe_calls.lock().unwrap())
    }
}

impl RegistryViewOps for MockRegistryViewOps {
    fn ensure_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
        expected: &str,
    ) -> anyhow::Result<bool> {
        match target.scope {
            Scope::Machine => assert!(
                view.is_some(),
                "Scope::Machine NMH writes must specify an explicit WOW64 view"
            ),
            Scope::User => assert!(
                view.is_none(),
                "Scope::User NMH writes must stay on default view"
            ),
        }
        let mut map = self.nmh_entries.lock().unwrap();
        let key = (target.scope, subkey.to_string(), view);
        if matches!(map.get(&key), Some(NativeHostRegProbe::Present(cur)) if cur == expected) {
            return Ok(false);
        }
        map.insert(key, NativeHostRegProbe::Present(expected.to_string()));
        Ok(true)
    }

    fn probe_default_sz(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> NativeHostRegProbe {
        match target.scope {
            Scope::Machine => assert!(
                view.is_some(),
                "Scope::Machine NMH probes must specify an explicit WOW64 view"
            ),
            Scope::User => assert!(
                view.is_none(),
                "Scope::User NMH probes must stay on default view"
            ),
        }
        self.probe_calls
            .lock()
            .unwrap()
            .push((target.scope, subkey.to_string(), view));
        self.get_entry(target.scope, subkey, view)
    }

    fn delete_subkey_tree_idempotent(
        &self,
        target: &RegistryTarget,
        subkey: &str,
        view: Option<RegWow64View>,
    ) -> anyhow::Result<bool> {
        if subkey == target.uri_subkey() {
            assert!(view.is_none(), "URI deletion must stay on default view");
            return Ok(self.uri_cmds.lock().unwrap().remove(&target.scope).is_some());
        }
        if subkey == target.aumid_subkey() {
            assert!(view.is_none(), "AUMID deletion must stay on default view");
            return Ok(self.aumids.lock().unwrap().remove(&target.scope).is_some());
        }
        let mut map = self.nmh_entries.lock().unwrap();
        Ok(map.remove(&(target.scope, subkey.to_string(), view)).is_some())
    }

    fn ensure_uri_registered(&self, target: &RegistryTarget, ui_exe: &Path) -> anyhow::Result<bool> {
        let cmd = crate::setup::format_ledr_uri_command(ui_exe);
        let mut map = self.uri_cmds.lock().unwrap();
        if map.get(&target.scope).is_some_and(|cur| cur == &cmd) {
            return Ok(false);
        }
        map.insert(target.scope, cmd);
        Ok(true)
    }

    fn ensure_aumid_registered(&self, target: &RegistryTarget) -> anyhow::Result<bool> {
        let mut map = self.aumids.lock().unwrap();
        if map
            .get(&target.scope)
            .is_some_and(|cur| cur == crate::setup::LEDR_AUMID_DISPLAY_NAME)
        {
            return Ok(false);
        }
        map.insert(
            target.scope,
            crate::setup::LEDR_AUMID_DISPLAY_NAME.to_string(),
        );
        Ok(true)
    }

    fn read_uri_status(&self, target: &RegistryTarget) -> (bool, Option<String>) {
        let val = self.uri_cmds.lock().unwrap().get(&target.scope).cloned();
        (val.is_some(), val)
    }

    fn read_aumid_status(&self, target: &RegistryTarget) -> (bool, Option<String>) {
        let val = self.aumids.lock().unwrap().get(&target.scope).cloned();
        (val.is_some(), val)
    }

    fn read_native_hosts_launch_directly_policy(
        &self,
        _target: &RegistryTarget,
        _browser: BrowserKind,
    ) -> Option<bool> {
        None
    }

    fn verify_local_manifest_for_removal(&self, _path: &Path) -> bool {
        true
    }
}

#[test]
fn bridge_20_mock_registry_machine_wow64_setup_status_unregister() {
    let temp = TempDirGuard::new("ledr-bridge-nm-b20");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    let fake_ui = temp.path().join("ledr-ui.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    fs::write(&fake_ui, b"MZ-test-ui").unwrap();
    let manifest_dir = temp.path().join("nm-machine");

    let machine_target = RegistryTarget::for_scope(Scope::Machine);
    let user_target = RegistryTarget::for_scope(Scope::User);
    let status_machine = StatusArgs {
        scope: StatusScope::Machine,
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        ping: false,
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        json: true,
    };

    // (a) Stale / empty 32-bit shadow in HKLM is exposed as invalid (not masked by 64-bit),
    //     then repaired by `setup --scope machine` (Option A1) and validated by `status`.
    let ops = MockRegistryViewOps::default();
    let chrome_subkey = machine_target.browser_subkey(BrowserKind::Chrome);
    let edge_subkey = machine_target.browser_subkey(BrowserKind::Edge);
    let brave_subkey = machine_target.browser_subkey(BrowserKind::Brave);

    let chrome_manifest_path = manifest_dir.join(manifest_filename_for(Scope::Machine, BrowserKind::Chrome));
    let edge_manifest_path = manifest_dir.join(manifest_filename_for(Scope::Machine, BrowserKind::Edge));
    let m = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();
    write_manifest_atomic(&chrome_manifest_path, &m).unwrap();
    write_manifest_atomic(&edge_manifest_path, &m).unwrap();
    let chrome_display = crate::manifest::normalize_display_path(&chrome_manifest_path);
    let edge_display = crate::manifest::normalize_display_path(&edge_manifest_path);

    ops.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::EmptyString,
    );
    ops.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(chrome_display.clone()),
    );
    ops.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(r"C:\Stale\old.json".to_string()),
    );
    ops.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(edge_display.clone()),
    );

    let pre_report = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops,
    )
    .expect("status before repair");
    let pre_chrome = &pre_report.scopes[0].browsers[0];
    assert!(pre_chrome.registered);
    assert_eq!(pre_chrome.registry_view.as_deref(), Some("wow64-32"));
    assert_eq!(pre_chrome.manifest_path, None);
    let pre_chrome_manifest = pre_chrome.manifest.as_ref().expect("synthetic invalid manifest");
    assert!(!pre_chrome_manifest.valid);
    assert!(pre_chrome_manifest
        .error
        .as_deref()
        .is_some_and(|e| e.contains("empty REG_SZ")));
    let pre_json = serde_json::to_string(&pre_report).unwrap();
    assert!(pre_json.contains(r#""registry_view":"wow64-32""#));

    let pre_brave = &pre_report.scopes[0].browsers[2];
    assert!(!pre_brave.registered);
    assert_eq!(pre_brave.registry_view, None);

    let setup_args = SetupArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Chrome, BrowserKind::Edge],
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        bridge_exe: Some(fake_bridge.clone()),
        ui_exe: Some(fake_ui),
        manifest_dir: Some(manifest_dir.clone()),
        skip_uri: false,
        json: false,
    };
    let setup_first = run_setup_with_ops(&setup_args, &machine_target, &ops).expect("first setup");
    assert!(setup_first.browsers.iter().all(|b| b.updated));
    assert_eq!(
        ops.get_entry(Scope::Machine, &chrome_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Present(chrome_display.clone())
    );
    assert_eq!(
        ops.get_entry(Scope::Machine, &chrome_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Present(chrome_display)
    );
    assert_eq!(
        ops.get_entry(Scope::Machine, &edge_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Present(edge_display.clone())
    );
    assert_eq!(
        ops.get_entry(Scope::Machine, &edge_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Present(edge_display)
    );

    let setup_second =
        run_setup_with_ops(&setup_args, &machine_target, &ops).expect("idempotent second setup");
    assert!(setup_second.browsers.iter().all(|b| !b.updated));
    assert!(!setup_second.uri_updated);
    assert!(!setup_second.aumid_updated);

    let post_report = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops,
    )
    .expect("status after repair");
    for entry in post_report.scopes[0].browsers.iter().take(2) {
        assert!(entry.registered);
        assert_eq!(entry.registry_view.as_deref(), Some("wow64-32"));
        assert!(entry.manifest.as_ref().is_some_and(|v| v.valid));
    }

    // (b) 32-bit-only legacy registration is detected by `status` and removed by `unregister`.
    let ops_b = MockRegistryViewOps::default();
    let legacy_32_manifest = manifest_dir.join("com.localedr.bridge.legacy32.json");
    write_manifest_atomic(&legacy_32_manifest, &m).unwrap();
    let legacy_32_display = crate::manifest::normalize_display_path(&legacy_32_manifest);
    ops_b.set_entry(
        Scope::Machine,
        &brave_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(legacy_32_display.clone()),
    );

    let legacy_status = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops_b,
    )
    .expect("status legacy 32-bit");
    let brave_status = &legacy_status.scopes[0].browsers[2];
    assert!(brave_status.registered);
    assert_eq!(brave_status.registry_view.as_deref(), Some("wow64-32"));
    assert_eq!(
        brave_status.manifest_path.as_deref(),
        Some(legacy_32_display.as_str())
    );
    assert!(brave_status.manifest.as_ref().is_some_and(|v| v.valid));

    let unreg_brave = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Brave],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let unreg_res =
        run_unregister_with_ops(&unreg_brave, &machine_target, Some(&user_target), &ops_b)
            .expect("unregister legacy 32-bit");
    assert!(unreg_res.browsers[0].removed);
    assert!(unreg_res.manifest_removed);
    assert!(!legacy_32_manifest.exists());
    assert_eq!(
        ops_b.get_entry(Scope::Machine, &brave_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Absent
    );

    let unreg_repeat =
        run_unregister_with_ops(&unreg_brave, &machine_target, Some(&user_target), &ops_b)
            .expect("repeat unregister idempotent");
    assert!(!unreg_repeat.browsers[0].removed);
    assert!(!unreg_repeat.manifest_removed);

    let post_unreg_status = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops_b,
    )
    .expect("status after unregister");
    assert!(!post_unreg_status.scopes[0].browsers[2].registered);
    assert_eq!(post_unreg_status.scopes[0].browsers[2].registry_view, None);

    // (c) Cross-browser 32-bit reference prevents deleting shared manifest file.
    let ops_c = MockRegistryViewOps::default();
    let manifest_dir_c = temp.path().join("nm-machine-shared");
    let shared_manifest = manifest_dir_c.join(MANIFEST_FILENAME);
    write_manifest_atomic(&shared_manifest, &m).unwrap();
    let shared_display = crate::manifest::normalize_display_path(&shared_manifest);
    ops_c.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(shared_display.clone()),
    );
    ops_c.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(shared_display),
    );

    let unreg_chrome_only = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir_c.clone()),
        keep_uri: true,
        json: false,
    };
    let res_chrome_only = run_unregister_with_ops(
        &unreg_chrome_only,
        &machine_target,
        Some(&user_target),
        &ops_c,
    )
    .expect("unreg chrome while edge 32-bit still references shared manifest");
    assert!(res_chrome_only.browsers[0].removed);
    assert!(
        !res_chrome_only.manifest_removed,
        "Edge HKLM 32-bit reference must preserve shared manifest"
    );
    assert!(shared_manifest.is_file());

    let unreg_edge_last = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Edge],
        manifest_dir: Some(manifest_dir_c),
        keep_uri: true,
        json: false,
    };
    let res_edge_last = run_unregister_with_ops(
        &unreg_edge_last,
        &machine_target,
        Some(&user_target),
        &ops_c,
    )
    .expect("unreg edge removes final 32-bit reference");
    assert!(res_edge_last.browsers[0].removed);
    assert!(res_edge_last.manifest_removed);
    assert!(!shared_manifest.exists());
}

#[cfg(windows)]
#[test]
fn bridge_21_real_win32_ffi_explicit_wow64_view_roundtrip() {
    use crate::setup::win_reg_ops;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
    use winreg::RegKey;

    assert_eq!(win_reg_ops::KEY_WOW64_64KEY, 0x0100);
    assert_eq!(win_reg_ops::KEY_WOW64_32KEY, 0x0200);

    // `HKCU\Software\Classes\CLSID` is WOW64-redirected on 64-bit Windows without elevation
    // (32-bit view maps to `Software\Classes\Wow6432Node\CLSID` while 64-bit stays under
    // `Software\Classes\CLSID`).
    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let clsid_subkey = format!(
        r"Software\Classes\CLSID\{{LocalEDR-Test-Bridge-NM-{}-{seq}}}",
        std::process::id()
    );
    let nested_subkey = format!(r"{clsid_subkey}\LocalServer32");
    let target = RegistryTarget {
        scope: Scope::User,
        key_prefix: None,
    };

    struct ViewCleanup {
        target: RegistryTarget,
        subkey: String,
    }
    impl Drop for ViewCleanup {
        fn drop(&mut self) {
            let _ = win_reg_ops::delete_subkey_tree_idempotent(
                &self.target,
                &self.subkey,
                Some(RegWow64View::Wow6432),
            );
            let _ = win_reg_ops::delete_subkey_tree_idempotent(
                &self.target,
                &self.subkey,
                Some(RegWow64View::Wow6464),
            );
        }
    }
    let _cleanup = ViewCleanup {
        target: target.clone(),
        subkey: clsid_subkey.clone(),
    };

    // Clean start + idempotent delete when absent
    assert!(!win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
    )
    .expect("absent 32-bit delete"));
    assert!(!win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6464),
    )
    .expect("absent 64-bit delete"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Absent
    );
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Absent
    );

    let val32 = r"C:\ProgramData\LocalEDR\native-messaging\win32-test-32.json";
    let val64 = r"C:\ProgramData\LocalEDR\native-messaging\win32-test-64.json";

    // Write 32-bit view (including a child subkey to exercise RegDeleteTreeW + RegDeleteKeyExW).
    assert!(win_reg_ops::ensure_default_sz(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
        val32,
    )
    .expect("create 32-bit key"));
    assert!(win_reg_ops::ensure_default_sz(
        &target,
        &nested_subkey,
        Some(RegWow64View::Wow6432),
        "nested-32",
    )
    .expect("create nested 32-bit key"));
    assert!(!win_reg_ops::ensure_default_sz(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
        val32,
    )
    .expect("idempotent repeat 32-bit ensure"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Present(val32.to_string())
    );
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Absent
    );

    // Write 64-bit view independently and verify view isolation.
    assert!(win_reg_ops::ensure_default_sz(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6464),
        val64,
    )
    .expect("create 64-bit key"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Present(val64.to_string())
    );
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Present(val32.to_string())
    );

    // Empty REG_SZ and non-REG_SZ probes in 32-bit view.
    assert!(win_reg_ops::ensure_default_sz(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
        "",
    )
    .expect("overwrite 32-bit with empty REG_SZ"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::EmptyString
    );
    assert_eq!(
        select_effective_hklm_probe(
            win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
            win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        ),
        (NativeHostRegProbe::EmptyString, Some(RegWow64View::Wow6432))
    );

    // REG_DWORD in 32-bit view -> InvalidType, falling back to 64-bit Present.
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (k32, _) = hkcu
        .create_subkey_with_flags(&clsid_subkey, KEY_WRITE | win_reg_ops::KEY_WOW64_32KEY)
        .unwrap();
    k32.set_value("", &1u32).unwrap();
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::InvalidType
    );
    assert_eq!(
        select_effective_hklm_probe(
            win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
            win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        ),
        (
            NativeHostRegProbe::Present(val64.to_string()),
            Some(RegWow64View::Wow6464)
        )
    );

    // Deleting 32-bit view via explicit FFI deletes tree without affecting 64-bit view, and is idempotent.
    assert!(win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
    )
    .expect("delete 32-bit tree"));
    assert!(!win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6432),
    )
    .expect("idempotent repeat 32-bit delete"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::Absent
    );
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Present(val64.to_string())
    );

    // Deleting 64-bit view via explicit FFI leaves both views Absent and repeats idempotently.
    assert!(win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6464),
    )
    .expect("delete 64-bit tree"));
    assert!(!win_reg_ops::delete_subkey_tree_idempotent(
        &target,
        &clsid_subkey,
        Some(RegWow64View::Wow6464),
    )
    .expect("idempotent repeat 64-bit delete"));
    assert_eq!(
        win_reg_ops::probe_default_sz(&target, &clsid_subkey, Some(RegWow64View::Wow6464)),
        NativeHostRegProbe::Absent
    );
}

#[test]
fn bridge_22_status_machine_short_circuits_wow64_64_probe() {
    let temp = TempDirGuard::new("ledr-bridge-nm-b22");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    let manifest_dir = temp.path().join("nm-machine");
    let m = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();
    let m32_path = manifest_dir.join(manifest_filename_for(Scope::Machine, BrowserKind::Chrome));
    let m64_path = manifest_dir.join("com.localedr.bridge.m64.json");
    write_manifest_atomic(&m32_path, &m).unwrap();
    write_manifest_atomic(&m64_path, &m).unwrap();
    let m32_display = crate::manifest::normalize_display_path(&m32_path);
    let m64_display = crate::manifest::normalize_display_path(&m64_path);

    let machine_target = RegistryTarget::for_scope(Scope::Machine);
    let chrome_subkey = machine_target.browser_subkey(BrowserKind::Chrome);
    let edge_subkey = machine_target.browser_subkey(BrowserKind::Edge);
    let brave_subkey = machine_target.browser_subkey(BrowserKind::Brave);
    let status_machine = StatusArgs {
        scope: StatusScope::Machine,
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        ping: false,
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        json: false,
    };

    // (a) When Wow6432 returns Present, EmptyString, or UnresolvableExpandSz,
    //     run_status_with_ops MUST short-circuit and perform ZERO Wow6464 probes.
    let ops = MockRegistryViewOps::default();
    let unres_raw = r"%LEDR_NONEXISTENT_B22%\com.localedr.bridge.json".to_string();
    let unres_err = "unresolved env token %LEDR_NONEXISTENT_B22%".to_string();

    ops.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(m32_display.clone()),
    );
    ops.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );
    ops.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::EmptyString,
    );
    ops.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );
    ops.set_entry(
        Scope::Machine,
        &brave_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::UnresolvableExpandSz {
            raw: unres_raw.clone(),
            error: unres_err.clone(),
        },
    );
    ops.set_entry(
        Scope::Machine,
        &brave_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );

    let report = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops,
    )
    .expect("status with 32-bit stopping probes");
    let calls = ops.take_probe_calls();
    assert_eq!(
        calls,
        vec![
            (Scope::Machine, chrome_subkey.clone(), Some(RegWow64View::Wow6432)),
            (Scope::Machine, edge_subkey.clone(), Some(RegWow64View::Wow6432)),
            (Scope::Machine, brave_subkey.clone(), Some(RegWow64View::Wow6432)),
        ],
        "Wow6464 must not be probed when Wow6432 stops fallback"
    );

    let brave = &report.scopes[0].browsers[2];
    assert!(brave.registered);
    assert_eq!(brave.registry_view.as_deref(), Some("wow64-32"));
    assert_eq!(brave.manifest_path.as_deref(), Some(unres_raw.as_str()));
    let brave_manifest = brave
        .manifest
        .as_ref()
        .expect("synthetic invalid manifest for UnresolvableExpandSz");
    assert!(!brave_manifest.valid);
    assert_eq!(brave_manifest.path, unres_raw);
    assert_eq!(brave_manifest.error.as_deref(), Some(unres_err.as_str()));
    let text = format_status_text(&report);
    assert!(text.contains(&unres_raw));
    assert!(text.contains(&unres_err));

    // (b) When Wow6432 returns Absent, InvalidType, or AccessError,
    //     run_status_with_ops MUST probe Wow6464 as fallback.
    let ops_fallback = MockRegistryViewOps::default();
    ops_fallback.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Absent,
    );
    ops_fallback.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );
    ops_fallback.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::InvalidType,
    );
    ops_fallback.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );
    ops_fallback.set_entry(
        Scope::Machine,
        &brave_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::AccessError("denied-32".to_string()),
    );
    ops_fallback.set_entry(
        Scope::Machine,
        &brave_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(m64_display.clone()),
    );

    let fallback_report = run_status_with_ops(
        &status_machine,
        std::slice::from_ref(&machine_target),
        Some(&manifest_dir),
        &ops_fallback,
    )
    .expect("status with 64-bit fallback");
    let fallback_calls = ops_fallback.take_probe_calls();
    assert_eq!(
        fallback_calls,
        vec![
            (Scope::Machine, chrome_subkey, Some(RegWow64View::Wow6432)),
            (Scope::Machine, machine_target.browser_subkey(BrowserKind::Chrome), Some(RegWow64View::Wow6464)),
            (Scope::Machine, edge_subkey, Some(RegWow64View::Wow6432)),
            (Scope::Machine, machine_target.browser_subkey(BrowserKind::Edge), Some(RegWow64View::Wow6464)),
            (Scope::Machine, brave_subkey, Some(RegWow64View::Wow6432)),
            (Scope::Machine, machine_target.browser_subkey(BrowserKind::Brave), Some(RegWow64View::Wow6464)),
        ]
    );
    for b in &fallback_report.scopes[0].browsers {
        assert!(b.registered);
        assert_eq!(b.registry_view.as_deref(), Some("wow64-64"));
        assert_eq!(b.manifest_path.as_deref(), Some(m64_display.as_str()));
        assert!(b.manifest.as_ref().is_some_and(|v| v.valid));
    }
}

#[test]
fn bridge_23_unregister_unresolvable_expand_sz_and_dual_view_manifest_removed() {
    let temp = TempDirGuard::new("ledr-bridge-nm-b23");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    let m = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();

    let machine_target = RegistryTarget::for_scope(Scope::Machine);
    let user_target = RegistryTarget::for_scope(Scope::User);
    let chrome_subkey = machine_target.browser_subkey(BrowserKind::Chrome);
    let edge_subkey = machine_target.browser_subkey(BrowserKind::Edge);

    // (a) Remaining browser with UnresolvableExpandSz fails closed and blocks shared manifest deletion.
    let ops_a = MockRegistryViewOps::default();
    let manifest_dir_a = temp.path().join("dir-a");
    let shared_manifest = manifest_dir_a.join(manifest_filename_for(Scope::Machine, BrowserKind::Chrome));
    write_manifest_atomic(&shared_manifest, &m).unwrap();
    let shared_display = crate::manifest::normalize_display_path(&shared_manifest);
    let unres_raw = r"%LEDR_NONEXISTENT_SHARED%\com.localedr.bridge.json".to_string();

    ops_a.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(shared_display),
    );
    ops_a.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::UnresolvableExpandSz {
            raw: unres_raw.clone(),
            error: "unresolved env token".to_string(),
        },
    );

    let unreg_chrome_a = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir_a.clone()),
        keep_uri: true,
        json: false,
    };
    let res_a = run_unregister_with_ops(
        &unreg_chrome_a,
        &machine_target,
        Some(&user_target),
        &ops_a,
    )
    .expect("unregister chrome while edge has UnresolvableExpandSz");
    assert!(res_a.browsers[0].removed);
    assert!(
        !res_a.manifest_removed,
        "remaining UnresolvableExpandSz must fail-closed and preserve manifest"
    );
    assert!(res_a.manifest_paths_removed.is_empty());
    assert!(shared_manifest.is_file());

    // Unregistering Edge with UnresolvableExpandSz (and no Present path) preserves raw as manifest_path
    // fallback and never adds UnresolvableExpandSz raw value to candidate_paths for deletion.
    let unreg_edge_a = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Edge],
        manifest_dir: Some(temp.path().join("other-empty-dir")),
        keep_uri: true,
        json: false,
    };
    let res_edge_a = run_unregister_with_ops(
        &unreg_edge_a,
        &machine_target,
        Some(&user_target),
        &ops_a,
    )
    .expect("unregister edge with UnresolvableExpandSz");
    assert!(res_edge_a.browsers[0].removed);
    assert_eq!(res_edge_a.browsers[0].manifest_path.as_deref(), Some(unres_raw.as_str()));
    assert!(!res_edge_a.manifest_removed);

    // (b) Dual-view different custom paths on Chrome:
    //     32-bit points to path A (still referenced by Edge -> kept on disk);
    //     64-bit points to path B (unreferenced -> deleted from disk).
    //     `manifest_paths_removed` must contain B, path A must remain on disk,
    //     and Chrome's `BrowserUnregisterOutcome.manifest_removed` must be `true`.
    let ops_b = MockRegistryViewOps::default();
    let custom_dir = temp.path().join("custom-dual");
    let path_a = custom_dir.join("com.localedr.bridge.custom-a.json");
    let path_b = custom_dir.join("com.localedr.bridge.custom-b.json");
    write_manifest_atomic(&path_a, &m).unwrap();
    write_manifest_atomic(&path_b, &m).unwrap();
    let path_a_display = crate::manifest::normalize_display_path(&path_a);
    let path_b_display = crate::manifest::normalize_display_path(&path_b);
    let path_b_extended = format!(r"\\?\{path_b_display}");

    ops_b.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(path_a_display.clone()),
    );
    ops_b.set_entry(
        Scope::Machine,
        &chrome_subkey,
        Some(RegWow64View::Wow6464),
        NativeHostRegProbe::Present(path_b_extended),
    );
    ops_b.set_entry(
        Scope::Machine,
        &edge_subkey,
        Some(RegWow64View::Wow6432),
        NativeHostRegProbe::Present(path_a_display.clone()),
    );

    let unreg_chrome_b = UnregisterArgs {
        scope: Scope::Machine,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(temp.path().join("unrelated-default-dir")),
        keep_uri: true,
        json: false,
    };
    let res_b = run_unregister_with_ops(
        &unreg_chrome_b,
        &machine_target,
        Some(&user_target),
        &ops_b,
    )
    .expect("unregister chrome with dual-view custom paths");
    assert!(res_b.browsers[0].removed);
    assert_eq!(
        res_b.browsers[0].manifest_path.as_deref(),
        Some(path_a_display.as_str()),
        "primary manifest_path keeps 32-bit view value for backward compatibility"
    );
    assert_eq!(res_b.manifest_paths_removed, vec![path_b_display]);
    assert!(res_b.manifest_removed);
    assert!(
        res_b.browsers[0].manifest_removed,
        "Chrome manifest_removed must be true when its 64-bit view path B was removed"
    );
    assert!(path_a.is_file(), "path A referenced by Edge must remain on disk");
    assert!(!path_b.exists(), "unreferenced path B must be deleted from disk");
}

#[cfg(windows)]
#[test]
fn bridge_24_real_win32_reg_expand_sz_probe_status_and_unregister() {
    use crate::setup::win_reg_ops;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE, REG_EXPAND_SZ};
    use winreg::{RegKey, RegValue};

    // (a) Pure unit checks for has_unresolved_env_token
    assert!(!has_unresolved_env_token(
        r"%SystemRoot%\System32\notepad.exe",
        r"C:\Windows\System32\notepad.exe"
    ));
    assert!(has_unresolved_env_token(
        r"%LEDR_MISSING%\m.json",
        r"%LEDR_MISSING%\m.json"
    ));
    assert!(has_unresolved_env_token(
        r"%ledr_missing%\m.json",
        r"%LEDR_MISSING%\m.json"
    ));
    assert!(has_unresolved_env_token(
        r"C:\100%done\%LEDR_MISSING%\m.json",
        r"C:\100%done\%LEDR_MISSING%\m.json"
    ));
    assert!(!has_unresolved_env_token(
        r"C:\100%done\m.json",
        r"C:\100%done\m.json"
    ));
    assert!(!has_unresolved_env_token(
        r"C:\a%%b\a:b%c/d%e\m.json",
        r"C:\a%%b\a:b%c/d%e\m.json"
    ));

    fn encode_reg_expand_sz(s: &str) -> RegValue<'static> {
        let bytes: Vec<u8> = s
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect();
        RegValue {
            bytes: bytes.into(),
            vtype: REG_EXPAND_SZ,
        }
    }

    fn encode_path_with_env_var(path: &Path) -> Option<String> {
        for var in ["TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA"] {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    if let Ok(rel) = path.strip_prefix(Path::new(&val)) {
                        return Some(format!("%{var}%\\{}", rel.display()));
                    }
                }
            }
        }
        if let Ok(drive) = std::env::var("SystemDrive") {
            let path_str = path.to_string_lossy();
            if path_str.len() > drive.len()
                && path_str[..drive.len()].eq_ignore_ascii_case(&drive)
            {
                return Some(format!("%SystemDrive%{}", &path_str[drive.len()..]));
            }
        }
        None
    }

    let temp = TempDirGuard::new("ledr-bridge-nm-b24");
    let fake_bridge = temp.path().join("ledr-bridge-nm.exe");
    fs::write(&fake_bridge, b"MZ-test").unwrap();
    let m = build_manifest(&fake_bridge, DEFAULT_CHROME_EXTENSION_ID).unwrap();

    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let prefix = format!(r"Software\LocalEDR-Test\Bridge24-{}-{seq}", std::process::id());
    let clsid_subkey = format!(
        r"Software\Classes\CLSID\{{LocalEDR-Test-Bridge24-{}-{seq}}}",
        std::process::id()
    );

    struct RegCleanup {
        prefix: String,
        clsid_subkey: String,
    }
    impl Drop for RegCleanup {
        fn drop(&mut self) {
            let user = RegistryTarget {
                scope: Scope::User,
                key_prefix: None,
            };
            let _ = win_reg_ops::delete_subkey_tree_idempotent(&user, &self.prefix, None);
            let _ = win_reg_ops::delete_subkey_tree_idempotent(
                &user,
                &self.clsid_subkey,
                Some(RegWow64View::Wow6432),
            );
            let _ = win_reg_ops::delete_subkey_tree_idempotent(
                &user,
                &self.clsid_subkey,
                Some(RegWow64View::Wow6464),
            );
        }
    }
    let _cleanup = RegCleanup {
        prefix: prefix.clone(),
        clsid_subkey: clsid_subkey.clone(),
    };

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let user_plain = RegistryTarget {
        scope: Scope::User,
        key_prefix: None,
    };

    // (b) Real Win32 REG_EXPAND_SZ probe variants under CLSID WOW64 views:
    //     32-bit REG_EXPAND_SZ takes precedence over 64-bit REG_SZ.
    let (k64, _) = hkcu
        .create_subkey_with_flags(&clsid_subkey, KEY_WRITE | win_reg_ops::KEY_WOW64_64KEY)
        .unwrap();
    let val64 = r"C:\ProgramData\LocalEDR\native-messaging\win32-expand-64.json";
    k64.set_value("", &val64).unwrap();

    let (k32, _) = hkcu
        .create_subkey_with_flags(&clsid_subkey, KEY_WRITE | win_reg_ops::KEY_WOW64_32KEY)
        .unwrap();

    // Resolved %SystemRoot% REG_EXPAND_SZ in 32-bit view wins over 64-bit REG_SZ
    let sys_root = std::env::var("SystemRoot").expect("SystemRoot must be set on Windows");
    let raw_resolved = r"%SystemRoot%\System32\notepad.exe";
    let expected_resolved = format!(r"{sys_root}\System32\notepad.exe");
    k32.set_raw_value("", &encode_reg_expand_sz(raw_resolved))
        .unwrap();
    let probe32_resolved =
        win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6432));
    assert_eq!(
        probe32_resolved,
        NativeHostRegProbe::Present(expected_resolved.clone())
    );
    assert_eq!(
        select_effective_hklm_probe(
            probe32_resolved,
            win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6464)),
        ),
        (
            NativeHostRegProbe::Present(expected_resolved),
            Some(RegWow64View::Wow6432)
        )
    );

    // Unresolved %LEDR_NONEXISTENT_VAR_8F4B2C% REG_EXPAND_SZ in 32-bit view stops fallback over 64-bit
    let raw_unresolved = format!(r"%LEDR_NONEXISTENT_VAR_{}_{seq}%\com.localedr.bridge.json", std::process::id());
    k32.set_raw_value("", &encode_reg_expand_sz(&raw_unresolved))
        .unwrap();
    let probe32_unres =
        win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6432));
    match &probe32_unres {
        NativeHostRegProbe::UnresolvableExpandSz { raw, error } => {
            assert_eq!(raw, &raw_unresolved);
            assert!(error.contains("unresolved"), "unexpected error: {error}");
        }
        other => panic!("expected UnresolvableExpandSz, got {other:?}"),
    }
    assert_eq!(
        select_effective_hklm_probe(
            probe32_unres.clone(),
            win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6464)),
        ),
        (probe32_unres, Some(RegWow64View::Wow6432))
    );

    // Whitespace-only REG_EXPAND_SZ -> EmptyString; odd-byte-length REG_EXPAND_SZ -> InvalidType
    k32.set_raw_value("", &encode_reg_expand_sz("   ")).unwrap();
    assert_eq!(
        win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::EmptyString
    );
    k32.set_raw_value(
        "",
        &RegValue {
            bytes: vec![b'a', 0, b'b'].into(),
            vtype: REG_EXPAND_SZ,
        },
    )
    .unwrap();
    assert_eq!(
        win_reg_ops::probe_default_sz(&user_plain, &clsid_subkey, Some(RegWow64View::Wow6432)),
        NativeHostRegProbe::InvalidType
    );

    // (c) Isolated HKCU end-to-end: remaining browser with real REG_EXPAND_SZ (both resolved
    //     shared path and unresolved fail-closed) prevents deletion of shared manifest during unregister.
    let isolated_user = RegistryTarget {
        scope: Scope::User,
        key_prefix: Some(prefix),
    };
    let manifest_dir = temp.path().join("nm-user");
    let shared_manifest = manifest_dir.join(manifest_filename_for(Scope::User, BrowserKind::Chrome));
    write_manifest_atomic(&shared_manifest, &m).unwrap();
    let shared_display = crate::manifest::normalize_display_path(&shared_manifest);
    let edge_expand_shared = encode_path_with_env_var(&shared_manifest)
        .expect("temp path must be expressible via standard Windows env var");

    let chrome_key = isolated_user.browser_subkey(BrowserKind::Chrome);
    let edge_key = isolated_user.browser_subkey(BrowserKind::Edge);
    win_reg_ops::ensure_default_sz(&isolated_user, &chrome_key, None, &shared_display).unwrap();
    let (edge_reg, _) = hkcu.create_subkey_with_flags(&edge_key, KEY_WRITE).unwrap();
    edge_reg
        .set_raw_value("", &encode_reg_expand_sz(&edge_expand_shared))
        .unwrap();

    let status_args = StatusArgs {
        scope: StatusScope::User,
        extension_id: DEFAULT_CHROME_EXTENSION_ID.to_string(),
        ping: false,
        pipe_name: ledr_proto::IPC_PIPE_NAME.to_string(),
        json: false,
    };
    let status_resolved = run_status_with(
        &status_args,
        std::slice::from_ref(&isolated_user),
        Some(&manifest_dir),
    )
    .expect("status with real REG_EXPAND_SZ");
    let edge_status = &status_resolved.scopes[0].browsers[1];
    assert!(edge_status.registered);
    assert_eq!(
        edge_status.manifest_path.as_deref(),
        Some(shared_display.as_str())
    );
    assert!(edge_status.manifest.as_ref().is_some_and(|v| v.valid));

    let unreg_chrome = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let res_resolved = run_unregister_with(&unreg_chrome, &isolated_user, None)
        .expect("unregister chrome while edge has resolved REG_EXPAND_SZ");
    assert!(res_resolved.browsers[0].removed);
    assert!(
        !res_resolved.manifest_removed,
        "resolved REG_EXPAND_SZ on Edge must prevent deleting shared manifest"
    );
    assert!(shared_manifest.is_file());

    // Now re-register Chrome and replace Edge's REG_EXPAND_SZ with an unresolvable variable
    win_reg_ops::ensure_default_sz(&isolated_user, &chrome_key, None, &shared_display).unwrap();
    edge_reg
        .set_raw_value("", &encode_reg_expand_sz(&raw_unresolved))
        .unwrap();

    let status_unres = run_status_with(
        &status_args,
        std::slice::from_ref(&isolated_user),
        Some(&manifest_dir),
    )
    .expect("status with unresolvable REG_EXPAND_SZ");
    let edge_unres = &status_unres.scopes[0].browsers[1];
    assert!(edge_unres.registered);
    assert_eq!(edge_unres.manifest_path.as_deref(), Some(raw_unresolved.as_str()));
    assert!(!edge_unres.manifest.as_ref().unwrap().valid);

    let res_unres = run_unregister_with(&unreg_chrome, &isolated_user, None)
        .expect("unregister chrome while edge has unresolved REG_EXPAND_SZ");
    assert!(res_unres.browsers[0].removed);
    assert!(
        !res_unres.manifest_removed,
        "unresolved REG_EXPAND_SZ on Edge must fail-closed and preserve manifest"
    );
    assert!(shared_manifest.is_file());
}
