//! Specification-driven unit and Named Pipe tests for `ledr-bridge-nm` (`BRIDGE-01`..`BRIDGE-10`).

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ledr_proto::{decode_ipc_frame, encode_ipc_frame, IpcRequest, IpcResponse, IPC_MAX_FRAME_BYTES};

use crate::cli::{parse_args_from, BrowserKind, Command, Scope, SetupArgs, StatusArgs, StatusScope, UnregisterArgs};
use crate::extension_id::{
    chrome_extension_origin, decode_base64, derive_extension_id_from_base64_key,
    derive_extension_id_from_der, is_valid_extension_id, sha256, DEFAULT_CHROME_EXTENSION_ID,
};
use crate::manifest::{
    build_manifest, validate_manifest_file, write_manifest_atomic, MANIFEST_FILENAME,
};
use crate::pipe_client::{
    is_authorized_pipe_server_exe_with, is_default_ipc_pipe, BridgeTransportError, PipeClient,
};
use crate::relay::{read_raw_frame, run_relay_loop, write_raw_frame, FrameExchange, RawFrameError};
use crate::setup::{run_setup_with, run_status_with, run_unregister_with, RegistryTarget};

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
#[test]
fn bridge_08_setup_status_unregister_idempotent_roundtrip() {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;

    struct RegTestGuard {
        root_subkey: String,
    }
    impl Drop for RegTestGuard {
        fn drop(&mut self) {
            let hkcu = RegKey::predef(HKEY_CURRENT_USER);
            let _ = hkcu.delete_subkey_all(&self.root_subkey);
        }
    }

    let seq = UNIQUE_SEQ.fetch_add(1, Ordering::Relaxed);
    let prefix = format!(r"Software\LocalEDR-Test\bridge-nm-{}-{seq}", std::process::id());
    let _reg_guard = RegTestGuard {
        root_subkey: prefix.clone(),
    };
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

    // 1. First setup writes manifest + 3 browser keys + ledr:// URI + AUMID
    let first = run_setup_with(&setup_args, &target).expect("first setup");
    assert!(first.manifest_written);
    assert!(first.uri_registered);
    assert!(first.uri_updated);
    assert!(first.aumid_updated);
    assert!(first.browsers.iter().all(|b| b.updated));
    assert!(manifest_dir.join(MANIFEST_FILENAME).is_file());

    // 2. Second setup is strictly idempotent
    let second = run_setup_with(&setup_args, &target).expect("second setup");
    assert!(!second.manifest_written);
    assert!(!second.uri_updated);
    assert!(!second.aumid_updated);
    assert!(second.browsers.iter().all(|b| !b.updated));

    // 3. Status reads all 3 browsers + valid manifest + URI + AUMID
    let status_args = StatusArgs {
        scope: StatusScope::User,
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

    // 4. Unregistering only Chrome preserves shared manifest while Edge & Brave remain
    let unreg_chrome = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Chrome],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: true,
        json: false,
    };
    let res_chrome = run_unregister_with(&unreg_chrome, &target).expect("unreg chrome");
    assert!(!res_chrome.manifest_removed);
    assert!(manifest_dir.join(MANIFEST_FILENAME).is_file());

    // 5. Unregistering remaining browsers without --keep-uri deletes manifest + URI + AUMID
    let unreg_all = UnregisterArgs {
        scope: Scope::User,
        browsers: vec![BrowserKind::Edge, BrowserKind::Brave],
        manifest_dir: Some(manifest_dir.clone()),
        keep_uri: false,
        json: false,
    };
    let res_all = run_unregister_with(&unreg_all, &target).expect("unreg all");
    assert!(res_all.manifest_removed);
    assert!(res_all.uri_removed);
    assert!(res_all.aumid_removed);
    assert!(!manifest_dir.join(MANIFEST_FILENAME).exists());

    // 6. Repeat unregister is cleanly idempotent
    let res_repeat = run_unregister_with(&unreg_all, &target).expect("repeat unreg");
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
    assert!(valid.error.is_none());
}
