//! Harmless canary, honeypot, and `--prepare-dir` filesystem scenario implementations.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use ledr_proto::HONEYPOT_DEFAULT_FILENAME;

use super::types::{CookiesOpenOutcome, HoneypotWriteOutcome, PrepareDirOutcome};

const DUMMY_COOKIE_PAYLOAD: &[u8] = b"SQLite format 3\0LocalEDR-Sim-Dummy-Cookies";
const INITIAL_HONEYPOT_BYTES: &[u8] = b"LocalEDR-Sim-Honeypot-Decoy\n";
static TEMP_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

pub(crate) struct TempSimDir(PathBuf);

impl TempSimDir {
    pub(crate) fn new(prefix: &str) -> Result<Self> {
        let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ledr-sim-{prefix}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create temp simulation dir {}", dir.display()))?;
        Ok(Self(dir))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempSimDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Option<std::process::Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) fn dummy_cookie_path(base_dir: &Path) -> PathBuf {
    base_dir
        .join("Google")
        .join("Chrome")
        .join("User Data")
        .join("Default")
        .join("Cookies")
}

pub(crate) fn dummy_honeypot_path(base_dir: &Path) -> PathBuf {
    base_dir.join(HONEYPOT_DEFAULT_FILENAME)
}

/// Pre-creates dummy `Google\Chrome\User Data\Default\Cookies` and
/// `!00_LocalEDR_Canary_DoNotEdit.docx` inside `base_dir` before telemetry monitoring starts.
///
/// Files created by this call are tracked and removed again when the overall preparation
/// fails, so a retry after resolving the reported conflict is not blocked by leftovers.
pub fn prepare_sim_dir(base_dir: &Path) -> Result<PrepareDirOutcome> {
    let cookie_path = dummy_cookie_path(base_dir);
    if let Some(parent) = cookie_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("failed to create dummy Chrome profile dir {}", parent.display())
        })?;
    }

    let mut created_paths: Vec<PathBuf> = Vec::new();
    let outcome = (|| -> Result<()> {
        {
            // `create_new` fails when the file already exists instead of truncating it
            // (BUG_0003 — `--prepare-dir` must never clobber a real Cookies DB or honeypot).
            let mut writer = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&cookie_path)
                .with_context(|| {
                    format!("failed to create dummy Cookies {}", cookie_path.display())
                })?;
            created_paths.push(cookie_path.clone());
            writer.write_all(DUMMY_COOKIE_PAYLOAD)?;
            writer.flush()?;
        }

        let honeypot_path = dummy_honeypot_path(base_dir);
        {
            let mut writer = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&honeypot_path)
                .with_context(|| {
                    format!("failed to create honeypot {}", honeypot_path.display())
                })?;
            created_paths.push(honeypot_path);
            writer.write_all(INITIAL_HONEYPOT_BYTES)?;
            writer.flush()?;
        }
        Ok(())
    })();
    if let Err(err) = outcome {
        for path in &created_paths {
            let _ = std::fs::remove_file(path);
        }
        return Err(err);
    }

    Ok(PrepareDirOutcome {
        base_dir: base_dir.display().to_string(),
        cookies_path: cookie_path.display().to_string(),
        honeypot_path: dummy_honeypot_path(base_dir).display().to_string(),
    })
}

/// Creates a harmless dummy `Google\Chrome\User Data\Default\Cookies` file in a temporary
/// directory, opens and reads it cleanly, and returns [`CookiesOpenOutcome`].
pub async fn run_cookies_open_scenario() -> Result<CookiesOpenOutcome> {
    run_cookies_open_scenario_with_hold(0).await
}

/// Like [`run_cookies_open_scenario`], holding the process alive for `hold_ms` milliseconds
/// after opening `Cookies` so real-time ETW + `NtSuspendProcess` E2E tests can observe suspension.
pub async fn run_cookies_open_scenario_with_hold(hold_ms: u64) -> Result<CookiesOpenOutcome> {
    run_cookies_open_scenario_with_options(None, hold_ms).await
}

/// Like [`run_cookies_open_scenario_with_hold`], optionally running inside an existing `base_dir`
/// without deleting it afterwards.
pub async fn run_cookies_open_scenario_with_options(
    base_dir: Option<PathBuf>,
    hold_ms: u64,
) -> Result<CookiesOpenOutcome> {
    tokio::task::spawn_blocking(move || {
        let _temp_guard = match base_dir.as_ref() {
            Some(_) => None,
            None => Some(TempSimDir::new("cookies")?),
        };
        let target_dir = match (&base_dir, &_temp_guard) {
            (Some(dir), _) => dir.as_path(),
            (None, Some(temp)) => temp.path(),
            (None, None) => unreachable!(),
        };
        let outcome = run_cookies_open_scenario_in(target_dir)?;
        if hold_ms > 0 {
            std::thread::sleep(Duration::from_millis(hold_ms));
        }
        Ok(outcome)
    })
    .await
    .context("cookies-open simulation task panicked")?
}

/// Runs the dummy `Cookies` open/read simulation under `base_dir` without removing `base_dir`.
///
/// When the target `Cookies` file already exists (e.g., pre-created via `--prepare-dir`), only a
/// read-only `File::open` is issued without calling `File::create`.
pub fn run_cookies_open_scenario_in(base_dir: &Path) -> Result<CookiesOpenOutcome> {
    let cookie_path = dummy_cookie_path(base_dir);
    if !cookie_path.is_file() {
        if let Some(parent) = cookie_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create dummy Chrome profile dir {}", parent.display())
            })?;
        }
        let mut writer = File::create(&cookie_path)
            .with_context(|| format!("failed to create dummy Cookies {}", cookie_path.display()))?;
        writer.write_all(DUMMY_COOKIE_PAYLOAD)?;
        writer.flush()?;
    }

    let mut reader = File::open(&cookie_path)
        .with_context(|| format!("failed to open dummy Cookies {}", cookie_path.display()))?;
    let mut buf = Vec::new();
    let bytes_read = reader
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read dummy Cookies {}", cookie_path.display()))?;

    Ok(CookiesOpenOutcome {
        target_path: cookie_path.display().to_string(),
        bytes_read,
        opened: true,
    })
}

/// Creates a harmless temp `!00_LocalEDR_Canary_DoNotEdit.docx` file, appends 1 byte, and
/// returns [`HoneypotWriteOutcome`].
pub async fn run_honeypot_write_scenario() -> Result<HoneypotWriteOutcome> {
    run_honeypot_write_scenario_with_hold(0).await
}

/// Like [`run_honeypot_write_scenario`], spawning a harmless child process and holding for
/// `hold_ms` milliseconds after modifying the decoy file so tree-level `NtSuspendProcess` E2E
/// tests can verify parent + child suspension (`L-07`).
pub async fn run_honeypot_write_scenario_with_hold(hold_ms: u64) -> Result<HoneypotWriteOutcome> {
    run_honeypot_write_scenario_with_options(None, hold_ms).await
}

/// Like [`run_honeypot_write_scenario_with_hold`], optionally running inside an existing
/// `base_dir` without deleting it afterwards.
pub async fn run_honeypot_write_scenario_with_options(
    base_dir: Option<PathBuf>,
    hold_ms: u64,
) -> Result<HoneypotWriteOutcome> {
    tokio::task::spawn_blocking(move || {
        let _temp_guard = match base_dir.as_ref() {
            Some(_) => None,
            None => Some(TempSimDir::new("honeypot")?),
        };
        let target_dir = match (&base_dir, &_temp_guard) {
            (Some(dir), _) => dir.as_path(),
            (None, Some(temp)) => temp.path(),
            (None, None) => unreachable!(),
        };
        let _child_guard = if hold_ms > 0 {
            let ping_count = (hold_ms / 1000).saturating_add(2).clamp(2, 120);
            let cmd = format!("ping -n {ping_count} 127.0.0.1 >nul");
            let child = std::process::Command::new("cmd.exe")
                .args(["/c", &cmd])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok();
            ChildGuard(child)
        } else {
            ChildGuard(None)
        };

        let outcome = run_honeypot_write_scenario_in(target_dir)?;
        if hold_ms > 0 {
            std::thread::sleep(Duration::from_millis(hold_ms));
        }
        Ok(outcome)
    })
    .await
    .context("honeypot-write simulation task panicked")?
}

/// Runs the dummy honeypot 1-byte append simulation under `base_dir` without removing `base_dir`.
///
/// When the target honeypot file already exists (e.g., pre-created via `--prepare-dir`), only
/// `OpenOptions` append/write is issued without calling `File::create`.
pub fn run_honeypot_write_scenario_in(base_dir: &Path) -> Result<HoneypotWriteOutcome> {
    const APPEND_ONE_BYTE: &[u8] = b"!";

    let honeypot_path = dummy_honeypot_path(base_dir);
    let initial_bytes = if honeypot_path.is_file() {
        std::fs::metadata(&honeypot_path)
            .with_context(|| format!("failed to stat honeypot {}", honeypot_path.display()))?
            .len() as usize
    } else {
        std::fs::create_dir_all(base_dir)
            .with_context(|| format!("failed to create honeypot dir {}", base_dir.display()))?;
        {
            let mut creator = File::create(&honeypot_path)
                .with_context(|| format!("failed to create honeypot {}", honeypot_path.display()))?;
            creator.write_all(INITIAL_HONEYPOT_BYTES)?;
            creator.flush()?;
        }
        INITIAL_HONEYPOT_BYTES.len()
    };

    {
        let mut appender = OpenOptions::new()
            .append(true)
            .open(&honeypot_path)
            .with_context(|| format!("failed to open honeypot {} for append", honeypot_path.display()))?;
        appender.write_all(APPEND_ONE_BYTE)?;
        appender.flush()?;
    }

    let final_bytes = std::fs::metadata(&honeypot_path)
        .with_context(|| format!("failed to stat honeypot {}", honeypot_path.display()))?
        .len() as usize;

    Ok(HoneypotWriteOutcome {
        target_path: honeypot_path.display().to_string(),
        initial_bytes,
        appended_bytes: APPEND_ONE_BYTE.len(),
        final_bytes,
    })
}
