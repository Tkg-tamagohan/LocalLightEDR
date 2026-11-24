use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ledr_auth_helper::{
    inspect_authenticode, read_framed_json, write_framed_json, AuthVerifyRequest,
    AuthVerifyResponse, DEFAULT_IDLE_TIMEOUT_MS,
};

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ledr-auth-helper-it-{}-{tag}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child not yet consumed")
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let status = self.child_mut().try_wait()?;
        if status.is_some() {
            self.0 = None;
        }
        Ok(status)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for_exit(
    child: &mut ChildGuard,
    timeout: Duration,
    reason: &str,
) -> std::process::ExitStatus {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        assert!(
            start.elapsed() <= timeout,
            "ledr-auth-helper did not exit for {reason} within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// AUTH-IT-01: Verifies signed and unsigned executable requests and clean EOF shutdown.
#[test]
fn auth_helper_bin_verifies_signed_and_unsigned_requests() {
    assert_eq!(DEFAULT_IDLE_TIMEOUT_MS, 15_000);

    // Pre-compute Authenticode baseline and temp file before spawning the child process
    // so slow host/AV I/O cannot race with the helper's idle timer.
    let cmd_exe = r"C:\Windows\System32\cmd.exe";
    let expected_cmd = inspect_authenticode(Path::new(cmd_exe));
    assert!(expected_cmd.is_some(), "cmd.exe should be signed");

    let tmp_dir = TempDirGuard::new("signed-unsigned");
    let tmp_path = tmp_dir.path().to_path_buf();
    let unsigned = tmp_path.join("unsigned.exe");
    std::fs::write(&unsigned, b"MZ-unsigned").expect("write unsigned");

    let bin = env!("CARGO_BIN_EXE_ledr-auth-helper");
    let mut child = ChildGuard::new(
        Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ledr-auth-helper"),
    );

    let mut stdin = child.child_mut().stdin.take().expect("child stdin");
    let mut stdout = child.child_mut().stdout.take().expect("child stdout");

    // 1. Signed OS binary (`cmd.exe`) matches direct `inspect_authenticode`.
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

    drop(stdin);
    const EOF_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
    assert!(EOF_EXIT_TIMEOUT < Duration::from_millis(DEFAULT_IDLE_TIMEOUT_MS));
    let status = wait_for_exit(&mut child, EOF_EXIT_TIMEOUT, "EOF shutdown");
    assert_eq!(status.code(), Some(0), "expected clean exit 0, got {status}");

    drop(tmp_dir);
    assert!(!tmp_path.exists(), "temp dir should be removed on drop");
}

/// AUTH-IT-02: Verifies self-exit with exit code 0 on idle timeout while stdin remains open.
#[test]
fn auth_helper_bin_self_exits_on_idle_timeout() {
    let bin = env!("CARGO_BIN_EXE_ledr-auth-helper");
    let mut child = ChildGuard::new(
        Command::new(bin)
            .arg("--idle-timeout-ms")
            .arg("250")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ledr-auth-helper"),
    );

    let stdin = child.child_mut().stdin.take().expect("child stdin");

    let status = wait_for_exit(&mut child, Duration::from_secs(5), "idle timeout");

    drop(stdin);
    assert_eq!(status.code(), Some(0), "expected clean exit 0, got {status}");
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
