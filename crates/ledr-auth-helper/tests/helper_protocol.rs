use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ledr_auth_helper::{
    inspect_authenticode, read_framed_json, write_framed_json, AuthVerifyRequest,
    AuthVerifyResponse, DEFAULT_IDLE_TIMEOUT_MS,
};

#[test]
fn auth_helper_bin_verifies_signed_unsigned_and_self_exits_on_idle() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT_MS, 15_000);

    let bin = env!("CARGO_BIN_EXE_ledr-auth-helper");
    let mut child = Command::new(bin)
        .arg("--idle-timeout-ms")
        .arg("200")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ledr-auth-helper");

    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = child.stdout.take().expect("child stdout");

    // 1. Signed OS binary (`cmd.exe`) matches direct `inspect_authenticode`.
    let cmd_exe = r"C:\Windows\System32\cmd.exe";
    let expected_cmd = inspect_authenticode(Path::new(cmd_exe));
    assert!(expected_cmd.is_some(), "cmd.exe should be signed");
    write_framed_json(
        &mut stdin,
        &AuthVerifyRequest {
            id: 1,
            exe_path: cmd_exe.to_string(),
        },
    )
    .expect("write cmd.exe request");
    let resp1: AuthVerifyResponse = read_framed_json(&mut stdout).expect("read cmd.exe response");
    assert_eq!(resp1.id, 1);
    assert_eq!(resp1.authenticode, expected_cmd);

    // 2. Unsigned temp file returns `None`.
    let tmp_dir = std::env::temp_dir().join(format!("ledr-auth-helper-it-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let unsigned = tmp_dir.join("unsigned.exe");
    std::fs::write(&unsigned, b"MZ-unsigned").expect("write unsigned");
    write_framed_json(
        &mut stdin,
        &AuthVerifyRequest {
            id: 2,
            exe_path: unsigned.to_string_lossy().into_owned(),
        },
    )
    .expect("write unsigned request");
    let resp2: AuthVerifyResponse = read_framed_json(&mut stdout).expect("read unsigned response");
    assert_eq!(resp2.id, 2);
    assert_eq!(resp2.authenticode, None);
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // 3. Idle timeout causes self-exit with exit code 0 even while stdin stays open.
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            panic!("ledr-auth-helper did not self-exit on idle timeout within 3s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "expected clean exit 0, got {status}");
}

#[test]
fn auth_helper_bin_rejects_oversized_frame_without_stdout_corruption() {
    let bin = env!("CARGO_BIN_EXE_ledr-auth-helper");
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ledr-auth-helper");

    {
        let mut stdin = child.stdin.take().expect("stdin");
        let oversized_len: u32 = (64 * 1024) + 1;
        let _ = stdin.write_all(&oversized_len.to_le_bytes());
        let _ = stdin.flush();
    }
    let output = child.wait_with_output().expect("wait_with_output");
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "helper must never emit unframed stdout output"
    );
}
