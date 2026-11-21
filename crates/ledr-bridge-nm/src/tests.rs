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
    format_status_text, resolve_bridge_exe_with, resolve_manifest_dir, resolve_ui_exe_with,
    run_setup_with, run_status_with, run_unregister_with, RegistryTarget,
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

    // 6. Boundary checks for Layer 1 path parsing, Layer 2 drive types, and Layer 3 reparse targets.
    use crate::setup::{
        extract_local_drive_letter, is_local_drive_type, parse_reparse_data_buffer,
        resolve_local_reparse_target, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
        IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK, SYMLINK_FLAG_RELATIVE,
    };

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

    let link_path = Path::new(r"C:\Temp\links\alias");
    let mp_local = build_reparse_buf(IO_REPARSE_TAG_MOUNT_POINT, r"\??\C:\Temp\real", None);
    let parsed_mp = parse_reparse_data_buffer(&mp_local).expect("parse local mount point");
    assert_eq!(parsed_mp.tag, IO_REPARSE_TAG_MOUNT_POINT);
    assert!(!parsed_mp.is_relative);
    assert_eq!(
        resolve_local_reparse_target(&parsed_mp.substitute_name, parsed_mp.is_relative, link_path),
        Some(PathBuf::from(r"C:\Temp\real"))
    );

    let sym_rel = build_reparse_buf(
        IO_REPARSE_TAG_SYMLINK,
        r"..\real\com.localedr.bridge.json",
        Some(SYMLINK_FLAG_RELATIVE),
    );
    let parsed_rel = parse_reparse_data_buffer(&sym_rel).expect("parse relative symlink");
    assert!(parsed_rel.is_relative);
    assert_eq!(
        resolve_local_reparse_target(
            &parsed_rel.substitute_name,
            parsed_rel.is_relative,
            Path::new(r"C:\Temp\links\alias.json")
        ),
        Some(PathBuf::from(r"C:\Temp\real\com.localedr.bridge.json"))
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
            r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\a",
            Some(0),
        ),
        (
            IO_REPARSE_TAG_SYMLINK,
            r"\\evil.invalid\share\a.json",
            Some(SYMLINK_FLAG_RELATIVE),
        ),
        (IO_REPARSE_TAG_MOUNT_POINT, r"\??\UNC\evil.invalid\share", None),
        (IO_REPARSE_TAG_MOUNT_POINT, r"\Device\Mup\evil.invalid\share", None),
    ] {
        let buf = build_reparse_buf(tag, target, flags);
        let parsed = parse_reparse_data_buffer(&buf).expect("parse remote reparse buffer");
        assert_eq!(
            resolve_local_reparse_target(&parsed.substitute_name, parsed.is_relative, link_path),
            None,
            "remote/non-local reparse substitute target must be rejected: '{target}'"
        );
    }

    // Unsupported/network reparse tag (e.g. IO_REPARSE_TAG_DFS = 0x8000_000A) must be rejected.
    let dfs_buf = build_reparse_buf(0x8000_000A, r"\??\C:\Temp\real", None);
    assert!(parse_reparse_data_buffer(&dfs_buf).is_none());
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

        // 2. Per-user FOLDERID_LocalAppData resolves with TOKEN_QUERY | TOKEN_IMPERSONATE.
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

        // 3. GetUserProfileDirectoryW (TOKEN_QUERY-only) fallback resolves cleanly without env vars.
        let fallback_local_app_data =
            win_pipe_auth::resolve_local_app_data_via_user_profile_dir()
                .expect("GetUserProfileDirectoryW fallback must resolve without env vars");
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

        match stdin_transport {
            StdHandleTransport::Pipe { pipe_server_pid } => {
                if let Some(server_pid) = pipe_server_pid {
                    assert_eq!(
                        server_pid, expected_gp_pid,
                        "stdin pipe server PID must match grandparent PID"
                    );
                }
            }
            StdHandleTransport::NonPipe => {
                panic!("expected inherited STD_INPUT_HANDLE to be StdHandleTransport::Pipe");
            }
        }

        match stdout_transport {
            StdHandleTransport::Pipe { pipe_server_pid } => {
                if let Some(server_pid) = pipe_server_pid {
                    assert_eq!(
                        server_pid, expected_gp_pid,
                        "stdout pipe server PID must match grandparent PID"
                    );
                }
            }
            StdHandleTransport::NonPipe => {
                panic!("expected inherited STD_OUTPUT_HANDLE to be StdHandleTransport::Pipe");
            }
        }

        // Grandparent is the test binary (not Chrome/Edge/Brave), so production caller verification must fail closed.
        assert!(
            win_pipe_auth::verify_browser_parent_process().is_err(),
            "cmd.exe mediated launch from non-browser grandparent must still be rejected"
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
