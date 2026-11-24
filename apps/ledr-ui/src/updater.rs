//! Application self-updater, staging, UAC elevation, and elevated verification (`L-26`+).
//!
//! Non-elevated `ledr-ui` checks signed release manifests via `ledr-updater`, stages and
//! pre-verifies installers into `%LOCALAPPDATA%\LocalEDR\updates\staging\<uuid>\`, and
//! launches `C:\Program Files\LocalEDR\ledr-ui.exe --apply-verified-update ...` via
//! `ShellExecuteExW("runas")`. The elevated process copies payloads into an Admin-only ACL
//! directory under `C:\ProgramData\LocalEDR\updates\verified\<uuid>\`, re-verifies Ed25519
//! signature + SemVer + SHA-256, runs NSIS `/S /UPDATE`, deletes `verified\<uuid>\`, and
//! relaunches `ledr-ui.exe` at Medium IL using `explorer.exe`'s token.

use crate::cli::{ApplyVerifiedUpdateArgs, LaunchMode};
use crate::ipc::normalize_windows_exe_path;
use ledr_proto::AUTHORIZED_UI_EXE_PATH;
use ledr_updater::{
    AUTO_CHECK_COOLDOWN_SECS, CancelToken, DownloadProgress, HttpClientConfig, MAX_INSTALLER_BYTES,
    MAX_MANIFEST_BYTES, MAX_SIG_BYTES, PublicKeyRing, STAGING_RETENTION_SECS, UpdateManifest,
    UpdateVerificationOutcome, UpdaterError, UpdaterHttpClient, atomic_write_file,
    cleanup_stale_staging_dirs, create_exclusive_file, create_staging_session_dir,
    ensure_no_reparse_points, validate_initial_release_url, validate_single_segment_filename,
    verify_and_evaluate_manifest, verify_installer_file,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter};

pub(crate) const UPDATER_STATUS_EVENT: &str = "updater://status-changed";
pub(crate) const UPDATE_STATE_FILENAME: &str = "update-state.json";
pub(crate) const STAGED_MANIFEST_FILENAME: &str = "update-manifest.json";
pub(crate) const STAGED_SIG_FILENAME: &str = "update-manifest.json.sig";
pub(crate) const UPDATE_STATE_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_UPDATE_STATE_BYTES: u64 = 256 * 1024;
pub(crate) const CLOSE_CANCEL_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(100);
const INSTALL_DIR_WINDOWS: &str = r"C:\Program Files\LocalEDR";

#[cfg(any(windows, test))]
pub(crate) const ADMIN_ONLY_DIR_SDDL: &str = "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";
#[cfg(any(windows, test))]
pub(crate) const PROGRAM_DATA_ROOT_SDDL: &str =
    "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)(A;OICI;0x1200a9;;;BU)";

/// Installation mode derived from the normalized running executable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    StandardInstalled,
    PortableOrDev,
}

/// State machine phase for the UI updater (`UpdaterStatusView::phase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdaterPhase {
    Idle,
    Checking,
    UpToDate,
    UpdateAvailable,
    ManualUpdateRequired,
    Downloading,
    Verifying,
    LaunchingUpdater,
    Error,
}

/// Serialized status snapshot exposed to the Tauri frontend via commands and events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterStatusView {
    pub phase: UpdaterPhase,
    pub app_version: String,
    pub install_kind: InstallKind,
    pub can_auto_apply: bool,
    pub last_checked_at_ms: Option<u64>,
    pub latest_version: Option<String>,
    pub min_updater_version: Option<String>,
    pub release_notes_url: Option<String>,
    pub manifest: Option<UpdateManifest>,
    pub bytes_downloaded: u64,
    pub total_bytes: Option<u64>,
    pub error_message: Option<String>,
    pub notice_message: Option<String>,
}

/// Persisted cooldown and verified-release cache state stored in `%LOCALAPPDATA%\LocalEDR\update-state.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedUpdateState {
    #[serde(default = "default_state_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub last_checked_at_ms: Option<u64>,
    #[serde(default)]
    pub last_known_latest_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_manifest_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_sig_json: Option<String>,
}

fn default_state_schema_version() -> u32 {
    UPDATE_STATE_SCHEMA_VERSION
}

impl Default for PersistedUpdateState {
    fn default() -> Self {
        Self {
            schema_version: UPDATE_STATE_SCHEMA_VERSION,
            last_checked_at_ms: None,
            last_known_latest_version: None,
            cached_manifest_json: None,
            cached_sig_json: None,
        }
    }
}

/// Classifies `exe_path` against [`AUTHORIZED_UI_EXE_PATH`] after Windows path normalization.
pub fn classify_install_kind_from_path(exe_path: Option<&Path>) -> InstallKind {
    let Some(path) = exe_path else {
        return InstallKind::PortableOrDev;
    };
    let raw = path.to_string_lossy();
    let normalized = normalize_windows_exe_path(&raw);
    let authorized = normalize_windows_exe_path(AUTHORIZED_UI_EXE_PATH);
    if !normalized.is_empty() && normalized == authorized {
        InstallKind::StandardInstalled
    } else {
        InstallKind::PortableOrDev
    }
}

/// Detects [`InstallKind`] for the current process, resolving final path on Windows to defeat
/// junctions or short-name aliases.
pub fn detect_install_kind() -> InstallKind {
    let Ok(exe) = std::env::current_exe() else {
        return InstallKind::PortableOrDev;
    };
    #[cfg(windows)]
    {
        if ensure_no_reparse_points(&exe).is_err() {
            return InstallKind::PortableOrDev;
        }
        if let Some(resolved) = win_updater::resolve_final_path_if_exists(&exe) {
            return classify_install_kind_from_path(Some(&resolved));
        }
    }
    classify_install_kind_from_path(Some(&exe))
}

/// Resolves `%LOCALAPPDATA%\LocalEDR` without using unverified fallback paths.
pub fn resolve_local_edr_data_dir() -> Result<PathBuf, String> {
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "LOCALAPPDATA environment variable is not set".to_string())?;
    Ok(PathBuf::from(local_app_data).join("LocalEDR"))
}

pub fn update_state_path_from_data_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(UPDATE_STATE_FILENAME)
}

pub fn staging_root_from_data_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("updates").join("staging")
}

#[cfg(test)]
pub(crate) fn verified_root_from_program_data_dir(program_data_dir: &Path) -> PathBuf {
    program_data_dir.join("updates").join("verified")
}

/// Returns current Unix epoch time in milliseconds.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Returns `true` iff `mode` is [`LaunchMode::Normal`] and the 6-hour auto-check cooldown has elapsed.
pub fn is_auto_check_due(
    mode: &LaunchMode,
    persisted: &PersistedUpdateState,
    now_ms: u64,
) -> bool {
    if !matches!(mode, LaunchMode::Normal) {
        return false;
    }
    let cooldown_ms = AUTO_CHECK_COOLDOWN_SECS.saturating_mul(1000);
    match persisted.last_checked_at_ms {
        None => true,
        Some(last_ms) => now_ms.saturating_sub(last_ms) >= cooldown_ms,
    }
}

/// Loads `update-state.json` safely, resetting to `Default` if missing, oversized, corrupt,
/// unknown `schema_version`, or containing reparse points.
pub fn load_persisted_state(path: &Path) -> PersistedUpdateState {
    if let Err(err) = ensure_no_reparse_points(path) {
        eprintln!("updater: ignoring unsafe update-state path {}: {err}", path.display());
        return PersistedUpdateState::default();
    }

    let file = match open_verified_read_file_bounded(path, MAX_UPDATE_STATE_BYTES) {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return PersistedUpdateState::default();
        }
        Err(err) => {
            eprintln!("updater: failed to read update-state {}: {err}", path.display());
            return PersistedUpdateState::default();
        }
    };

    let mut bytes = Vec::new();
    let limit = usize::try_from(MAX_UPDATE_STATE_BYTES).unwrap_or(256 * 1024);
    if let Err(err) = file.take((limit + 1) as u64).read_to_end(&mut bytes) {
        eprintln!("updater: failed reading update-state {}: {err}", path.display());
        return PersistedUpdateState::default();
    }
    if bytes.len() > limit {
        eprintln!("updater: update-state {} exceeded size limit; resetting", path.display());
        return PersistedUpdateState::default();
    }

    match serde_json::from_slice::<PersistedUpdateState>(&bytes) {
        Ok(state) if state.schema_version == UPDATE_STATE_SCHEMA_VERSION => state,
        Ok(other) => {
            eprintln!(
                "updater: unsupported update-state schema_version {}; resetting",
                other.schema_version
            );
            PersistedUpdateState::default()
        }
        Err(err) => {
            eprintln!("updater: corrupt update-state JSON ({}): {err}; resetting", path.display());
            PersistedUpdateState::default()
        }
    }
}

/// Atomically persists `update-state.json` via `ledr_updater::atomic_write_file`.
pub fn save_persisted_state(path: &Path, state: &PersistedUpdateState) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("failed to serialize update-state: {err}"))?;
    atomic_write_file(path, &bytes).map_err(|err| format!("failed to save update-state: {err}"))
}

/// Cleans up orphaned staging directories older than 24 hours.
pub fn run_startup_staging_gc(staging_root: &Path) -> Result<usize, String> {
    cleanup_stale_staging_dirs(staging_root, Duration::from_secs(STAGING_RETENTION_SECS))
        .map_err(|err| format!("staging GC failed: {err}"))
}

/// Validates staged installer filename: single-segment, `.exe`, and no collision with
/// `update-manifest.json` or `update-manifest.json.sig`.
pub(crate) fn validate_staged_installer_filename(filename: &str) -> Result<(), String> {
    validate_single_segment_filename(filename).map_err(|err| err.to_string())?;
    if filename.eq_ignore_ascii_case(STAGED_MANIFEST_FILENAME)
        || filename.eq_ignore_ascii_case(STAGED_SIG_FILENAME)
    {
        return Err(format!(
            "manifest filename '{filename}' collides with reserved staging metadata filename"
        ));
    }
    if !filename.to_ascii_lowercase().ends_with(".exe") {
        return Err(format!(
            "manifest filename '{filename}' must have a .exe extension"
        ));
    }
    Ok(())
}

/// Validates and opens a release notes URL in the OS browser without invoking a shell.
pub(crate) fn open_release_notes_url_validated(url: &str) -> Result<(), String> {
    validate_initial_release_url(url, false).map_err(|err| err.to_string())?;
    #[cfg(windows)]
    {
        win_updater::shell_open_url(url)
    }
    #[cfg(not(windows))]
    {
        Err("release notes browser launch is only supported on Windows".to_string())
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ElevationLaunchResult {
    Launched,
    UserCancelled,
    Failed(String),
}

pub(crate) trait ElevationLauncher: Send + Sync {
    fn launch_elevated_apply(
        &self,
        manifest_path: &Path,
        sig_path: &Path,
        installer_path: &Path,
    ) -> ElevationLaunchResult;
}

#[derive(Debug, Default)]
struct Win32ElevationLauncher;

impl ElevationLauncher for Win32ElevationLauncher {
    fn launch_elevated_apply(
        &self,
        manifest_path: &Path,
        sig_path: &Path,
        installer_path: &Path,
    ) -> ElevationLaunchResult {
        #[cfg(windows)]
        {
            win_updater::launch_elevated_apply_uac(
                Path::new(AUTHORIZED_UI_EXE_PATH),
                manifest_path,
                sig_path,
                installer_path,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (manifest_path, sig_path, installer_path);
            ElevationLaunchResult::Failed("UAC elevation is only supported on Windows".to_string())
        }
    }
}

#[derive(Clone)]
pub(crate) struct UpdaterConfig {
    pub(crate) app_version: String,
    pub(crate) install_kind: InstallKind,
    pub(crate) data_dir: Option<PathBuf>,
    pub(crate) manifest_url: String,
    pub(crate) sig_url: String,
    pub(crate) http_config: HttpClientConfig,
    pub(crate) key_ring_override: Option<PublicKeyRing>,
    #[cfg(test)]
    pub(crate) installer_url_override: Option<String>,
    pub(crate) elevation_launcher: Arc<dyn ElevationLauncher>,
    pub(crate) on_launch_exit: Arc<dyn Fn() + Send + Sync>,
    pub(crate) now_ms_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl UpdaterConfig {
    pub(crate) fn production(app_handle: AppHandle) -> Self {
        Self {
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            install_kind: detect_install_kind(),
            data_dir: resolve_local_edr_data_dir().ok(),
            manifest_url: ledr_updater::LATEST_MANIFEST_URL.to_string(),
            sig_url: ledr_updater::LATEST_SIG_URL.to_string(),
            http_config: HttpClientConfig::default(),
            key_ring_override: None,
            #[cfg(test)]
            installer_url_override: None,
            elevation_launcher: Arc::new(Win32ElevationLauncher),
            on_launch_exit: Arc::new(move || {
                app_handle.exit(0);
            }),
            now_ms_fn: Arc::new(now_unix_ms),
        }
    }
}

#[derive(Clone)]
struct CachedVerifiedRelease {
    manifest: UpdateManifest,
    manifest_bytes: Vec<u8>,
    sig_bytes: Vec<u8>,
}

enum VerifyStageResult {
    Verified,
    Cancelled,
    Failed(String),
}

struct ManagerInner {
    phase: UpdaterPhase,
    in_flight: bool,
    auto_check_started: bool,
    closing: bool,
    cancel_token: Option<CancelToken>,
    active_staging_dir: Option<PathBuf>,
    cached_verified: Option<CachedVerifiedRelease>,
    persisted: PersistedUpdateState,
    latest_version: Option<String>,
    min_updater_version: Option<String>,
    release_notes_url: Option<String>,
    bytes_downloaded: u64,
    total_bytes: Option<u64>,
    error_message: Option<String>,
    notice_message: Option<String>,
}

impl ManagerInner {
    fn to_status_view(&self, config: &UpdaterConfig) -> UpdaterStatusView {
        UpdaterStatusView {
            phase: self.phase,
            app_version: config.app_version.clone(),
            install_kind: config.install_kind,
            can_auto_apply: config.install_kind == InstallKind::StandardInstalled,
            last_checked_at_ms: self.persisted.last_checked_at_ms,
            latest_version: self
                .latest_version
                .clone()
                .or_else(|| self.persisted.last_known_latest_version.clone()),
            min_updater_version: self.min_updater_version.clone(),
            release_notes_url: self.release_notes_url.clone(),
            manifest: self.cached_verified.as_ref().map(|c| c.manifest.clone()),
            bytes_downloaded: self.bytes_downloaded,
            total_bytes: self.total_bytes,
            error_message: self.error_message.clone(),
            notice_message: self.notice_message.clone(),
        }
    }

    fn is_busy(&self) -> bool {
        self.in_flight
            || matches!(
                self.phase,
                UpdaterPhase::Checking
                    | UpdaterPhase::Downloading
                    | UpdaterPhase::Verifying
                    | UpdaterPhase::LaunchingUpdater
            )
    }
}

/// Shared state manager coordinating update checks, downloads, staging, and UAC elevation.
#[derive(Clone)]
pub(crate) struct AppUpdateManager {
    config: UpdaterConfig,
    inner: Arc<Mutex<ManagerInner>>,
    done_signal: Arc<(Mutex<bool>, Condvar)>,
}

struct OperationGuard {
    inner: Arc<Mutex<ManagerInner>>,
    done_signal: Arc<(Mutex<bool>, Condvar)>,
    completed_cleanly: AtomicBool,
}

impl OperationGuard {
    fn new(
        inner: Arc<Mutex<ManagerInner>>,
        done_signal: Arc<(Mutex<bool>, Condvar)>,
    ) -> Self {
        Self {
            inner,
            done_signal,
            completed_cleanly: AtomicBool::new(false),
        }
    }

    fn mark_finished(&self) {
        self.completed_cleanly.store(true, Ordering::Release);
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut staging_to_clean: Option<PathBuf> = None;
        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.in_flight = false;
            guard.cancel_token = None;
            if !self.completed_cleanly.load(Ordering::Acquire) {
                staging_to_clean = guard.active_staging_dir.take();
                if matches!(
                    guard.phase,
                    UpdaterPhase::Checking
                        | UpdaterPhase::Downloading
                        | UpdaterPhase::Verifying
                        | UpdaterPhase::LaunchingUpdater
                ) {
                    guard.phase = UpdaterPhase::Error;
                    if guard.error_message.is_none() {
                        guard.error_message =
                            Some("更新処理が予期せず中断されました。".to_string());
                    }
                }
            }
        }
        if let Some(dir) = staging_to_clean {
            let _ = remove_dir_all_no_reparse(&dir);
        }
        let (done_lock, done_cv) = &*self.done_signal;
        let mut done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
        *done = true;
        done_cv.notify_all();
    }
}

struct RestoredStartupState {
    phase: UpdaterPhase,
    persisted: PersistedUpdateState,
    cached_verified: Option<CachedVerifiedRelease>,
    latest_version: Option<String>,
    min_updater_version: Option<String>,
    release_notes_url: Option<String>,
}

fn clear_cached_manifest_fields(persisted: &mut PersistedUpdateState, clear_latest: bool) {
    persisted.cached_manifest_json = None;
    persisted.cached_sig_json = None;
    if clear_latest {
        persisted.last_known_latest_version = None;
    }
}

fn persist_cleaned_state_best_effort(
    state_path: Option<&Path>,
    persisted: &PersistedUpdateState,
) {
    if let Some(path) = state_path {
        if let Err(err) = save_persisted_state(path, persisted) {
            eprintln!("updater: failed to persist cleaned update-state: {err}");
        }
    }
}

fn restore_persisted_state_on_startup(config: &UpdaterConfig) -> RestoredStartupState {
    let state_path = config
        .data_dir
        .as_deref()
        .map(update_state_path_from_data_dir);
    let mut persisted = state_path
        .as_deref()
        .map(load_persisted_state)
        .unwrap_or_default();

    let cached_manifest = persisted.cached_manifest_json.take();
    let cached_sig = persisted.cached_sig_json.take();

    match (cached_manifest, cached_sig) {
        (None, None) => {
            let latest_version = persisted.last_known_latest_version.clone();
            RestoredStartupState {
                phase: UpdaterPhase::Idle,
                persisted,
                cached_verified: None,
                latest_version,
                min_updater_version: None,
                release_notes_url: None,
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            eprintln!("updater: incomplete cached manifest/signature in update-state; clearing");
            clear_cached_manifest_fields(&mut persisted, true);
            persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
            RestoredStartupState {
                phase: UpdaterPhase::Idle,
                persisted,
                cached_verified: None,
                latest_version: None,
                min_updater_version: None,
                release_notes_url: None,
            }
        }
        (Some(manifest_json), Some(sig_json)) => {
            if manifest_json.len() > MAX_MANIFEST_BYTES || sig_json.len() > MAX_SIG_BYTES {
                eprintln!("updater: cached manifest/signature exceeded bounds; clearing");
                clear_cached_manifest_fields(&mut persisted, true);
                persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
                return RestoredStartupState {
                    phase: UpdaterPhase::Idle,
                    persisted,
                    cached_verified: None,
                    latest_version: None,
                    min_updater_version: None,
                    release_notes_url: None,
                };
            }

            let key_ring = match &config.key_ring_override {
                Some(kr) => Ok(kr.clone()),
                None => PublicKeyRing::from_embedded(),
            };
            let key_ring = match key_ring {
                Ok(kr) => kr,
                Err(err) => {
                    eprintln!(
                        "updater: public key ring unavailable during startup cache verification; clearing cached state: {err}"
                    );
                    clear_cached_manifest_fields(&mut persisted, true);
                    persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
                    return RestoredStartupState {
                        phase: UpdaterPhase::Idle,
                        persisted,
                        cached_verified: None,
                        latest_version: None,
                        min_updater_version: None,
                        release_notes_url: None,
                    };
                }
            };

            match verify_and_evaluate_manifest(
                manifest_json.as_bytes(),
                sig_json.as_bytes(),
                &key_ring,
                &config.app_version,
            ) {
                Ok(UpdateVerificationOutcome::UpdateAvailable { manifest, .. }) => {
                    let manifest_val = *manifest;
                    if let Err(err) = validate_staged_installer_filename(&manifest_val.filename) {
                        eprintln!(
                            "updater: cached manifest filename rejected; clearing cached state: {err}"
                        );
                        clear_cached_manifest_fields(&mut persisted, true);
                        persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
                        return RestoredStartupState {
                            phase: UpdaterPhase::Idle,
                            persisted,
                            cached_verified: None,
                            latest_version: None,
                            min_updater_version: None,
                            release_notes_url: None,
                        };
                    }
                    let latest = manifest_val.version.clone();
                    let min_ver = manifest_val.min_updater_version.clone();
                    let notes_url = manifest_val.release_notes_url.clone();
                    persisted.last_known_latest_version = Some(latest.clone());
                    persisted.cached_manifest_json = Some(manifest_json.clone());
                    persisted.cached_sig_json = Some(sig_json.clone());
                    RestoredStartupState {
                        phase: UpdaterPhase::UpdateAvailable,
                        persisted,
                        cached_verified: Some(CachedVerifiedRelease {
                            manifest: manifest_val,
                            manifest_bytes: manifest_json.into_bytes(),
                            sig_bytes: sig_json.into_bytes(),
                        }),
                        latest_version: Some(latest),
                        min_updater_version: Some(min_ver),
                        release_notes_url: Some(notes_url),
                    }
                }
                Ok(UpdateVerificationOutcome::ManualUpdateRequired {
                    min_updater_version,
                    latest_version,
                    release_notes_url,
                    ..
                }) => {
                    persisted.last_known_latest_version = Some(latest_version.clone());
                    persisted.cached_manifest_json = Some(manifest_json);
                    persisted.cached_sig_json = Some(sig_json);
                    RestoredStartupState {
                        phase: UpdaterPhase::ManualUpdateRequired,
                        persisted,
                        cached_verified: None,
                        latest_version: Some(latest_version),
                        min_updater_version: Some(min_updater_version),
                        release_notes_url: Some(release_notes_url),
                    }
                }
                Ok(UpdateVerificationOutcome::UpToDate { latest_version, .. }) => {
                    clear_cached_manifest_fields(&mut persisted, false);
                    persisted.last_known_latest_version = Some(latest_version.clone());
                    persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
                    RestoredStartupState {
                        phase: UpdaterPhase::UpToDate,
                        persisted,
                        cached_verified: None,
                        latest_version: Some(latest_version),
                        min_updater_version: None,
                        release_notes_url: None,
                    }
                }
                Err(err) => {
                    eprintln!(
                        "updater: cached manifest verification failed closed; clearing cached state: {err}"
                    );
                    clear_cached_manifest_fields(&mut persisted, true);
                    persist_cleaned_state_best_effort(state_path.as_deref(), &persisted);
                    RestoredStartupState {
                        phase: UpdaterPhase::Idle,
                        persisted,
                        cached_verified: None,
                        latest_version: None,
                        min_updater_version: None,
                        release_notes_url: None,
                    }
                }
            }
        }
    }
}

impl AppUpdateManager {
    pub(crate) fn new(config: UpdaterConfig) -> Self {
        let restored = restore_persisted_state_on_startup(&config);

        Self {
            config,
            inner: Arc::new(Mutex::new(ManagerInner {
                phase: restored.phase,
                in_flight: false,
                auto_check_started: false,
                closing: false,
                cancel_token: None,
                active_staging_dir: None,
                cached_verified: restored.cached_verified,
                persisted: restored.persisted,
                latest_version: restored.latest_version,
                min_updater_version: restored.min_updater_version,
                release_notes_url: restored.release_notes_url,
                bytes_downloaded: 0,
                total_bytes: None,
                error_message: None,
                notice_message: None,
            })),
            done_signal: Arc::new((Mutex::new(true), Condvar::new())),
        }
    }

    pub(crate) fn status(&self) -> UpdaterStatusView {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.to_status_view(&self.config)
    }

    pub(crate) fn run_startup_gc_sync(&self) -> Result<usize, String> {
        let Some(data_dir) = &self.config.data_dir else {
            return Ok(0);
        };
        let staging_root = staging_root_from_data_dir(data_dir);
        run_startup_staging_gc(&staging_root)
    }

    fn emit_status<F: Fn(&UpdaterStatusView)>(&self, emitter: &F, view: &UpdaterStatusView) {
        emitter(view);
    }

    /// Checks whether a background startup auto-check should run (only in `LaunchMode::Normal`,
    /// once per process lifetime, gated by the 6-hour cooldown).
    pub(crate) fn should_trigger_startup_auto_check(&self, mode: &LaunchMode) -> bool {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closing || guard.auto_check_started || guard.is_busy() {
            return false;
        }
        let now_ms = (self.config.now_ms_fn)();
        if !is_auto_check_due(mode, &guard.persisted, now_ms) {
            return false;
        }
        guard.auto_check_started = true;
        true
    }

    pub(crate) fn check_for_updates_blocking_with<F>(
        &self,
        emit: F,
    ) -> Result<UpdaterStatusView, String>
    where
        F: Fn(&UpdaterStatusView),
    {
        let (cancel_token, prev_snapshot, checking_view) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.closing {
                return Err("アプリケーション終了中のため更新確認を開始できません。".to_string());
            }
            if guard.is_busy() {
                return Err(
                    "UPDATE_IN_PROGRESS: 更新確認または適用が進行中です。".to_string()
                );
            }
            let prev_snapshot = (
                guard.phase,
                guard.latest_version.clone(),
                guard.min_updater_version.clone(),
                guard.release_notes_url.clone(),
                guard.cached_verified.clone(),
            );
            let token = CancelToken::new();
            guard.in_flight = true;
            guard.cancel_token = Some(token.clone());
            guard.phase = UpdaterPhase::Checking;
            guard.bytes_downloaded = 0;
            guard.total_bytes = None;
            guard.error_message = None;
            guard.notice_message = None;
            let (done_lock, _) = &*self.done_signal;
            *done_lock.lock().unwrap_or_else(|e| e.into_inner()) = false;
            (token, prev_snapshot, guard.to_status_view(&self.config))
        };

        let op_guard = OperationGuard::new(Arc::clone(&self.inner), Arc::clone(&self.done_signal));
        self.emit_status(&emit, &checking_view);

        let key_ring = match &self.config.key_ring_override {
            Some(kr) => kr.clone(),
            None => match PublicKeyRing::from_embedded() {
                Ok(kr) => kr,
                Err(err) => {
                    let msg = err.to_string();
                    let view = self.set_error_state(msg.clone());
                    op_guard.mark_finished();
                    self.emit_status(&emit, &view);
                    return Err(msg);
                }
            },
        };

        let client = UpdaterHttpClient::new(self.config.http_config.clone());
        let manifest_bytes = match client.fetch_manifest(&self.config.manifest_url, &cancel_token) {
            Ok(bytes) => bytes,
            Err(UpdaterError::Cancelled) => {
                let view = self.restore_after_check_cancel(prev_snapshot);
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            Err(err) => {
                let msg = err.to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        let sig_bytes = match client.fetch_signature(&self.config.sig_url, &cancel_token) {
            Ok(bytes) => bytes,
            Err(UpdaterError::Cancelled) => {
                let view = self.restore_after_check_cancel(prev_snapshot);
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            Err(err) => {
                let msg = err.to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        let outcome = match verify_and_evaluate_manifest(
            &manifest_bytes,
            &sig_bytes,
            &key_ring,
            &self.config.app_version,
        ) {
            Ok(out) => out,
            Err(err) => {
                let msg = err.to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        if let UpdateVerificationOutcome::UpdateAvailable { ref manifest, .. } = outcome {
            if let Err(msg) = validate_staged_installer_filename(&manifest.filename) {
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        }

        let manifest_json = match String::from_utf8(manifest_bytes.clone()) {
            Ok(s) => s,
            Err(err) => {
                let msg = format!("manifest is not valid UTF-8: {err}");
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };
        let sig_json = match String::from_utf8(sig_bytes.clone()) {
            Ok(s) => s,
            Err(err) => {
                let msg = format!("signature envelope is not valid UTF-8: {err}");
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        let checked_at_ms = (self.config.now_ms_fn)();
        let (next_persisted, view) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.bytes_downloaded = 0;
            guard.total_bytes = None;
            guard.error_message = None;
            guard.notice_message = None;

            match outcome {
                UpdateVerificationOutcome::UpToDate { latest_version, .. } => {
                    guard.phase = UpdaterPhase::UpToDate;
                    guard.latest_version = Some(latest_version.clone());
                    guard.min_updater_version = None;
                    guard.release_notes_url = None;
                    guard.cached_verified = None;
                    guard.persisted.last_checked_at_ms = Some(checked_at_ms);
                    guard.persisted.last_known_latest_version = Some(latest_version);
                    clear_cached_manifest_fields(&mut guard.persisted, false);
                }
                UpdateVerificationOutcome::UpdateAvailable { manifest, .. } => {
                    let manifest_val = *manifest;
                    guard.phase = UpdaterPhase::UpdateAvailable;
                    guard.latest_version = Some(manifest_val.version.clone());
                    guard.min_updater_version = Some(manifest_val.min_updater_version.clone());
                    guard.release_notes_url = Some(manifest_val.release_notes_url.clone());
                    guard.persisted.last_checked_at_ms = Some(checked_at_ms);
                    guard.persisted.last_known_latest_version = Some(manifest_val.version.clone());
                    guard.persisted.cached_manifest_json = Some(manifest_json);
                    guard.persisted.cached_sig_json = Some(sig_json);
                    guard.cached_verified = Some(CachedVerifiedRelease {
                        manifest: manifest_val,
                        manifest_bytes,
                        sig_bytes,
                    });
                }
                UpdateVerificationOutcome::ManualUpdateRequired {
                    min_updater_version,
                    latest_version,
                    release_notes_url,
                    ..
                } => {
                    guard.phase = UpdaterPhase::ManualUpdateRequired;
                    guard.latest_version = Some(latest_version.clone());
                    guard.min_updater_version = Some(min_updater_version);
                    guard.release_notes_url = Some(release_notes_url);
                    guard.cached_verified = None;
                    guard.persisted.last_checked_at_ms = Some(checked_at_ms);
                    guard.persisted.last_known_latest_version = Some(latest_version);
                    guard.persisted.cached_manifest_json = Some(manifest_json);
                    guard.persisted.cached_sig_json = Some(sig_json);
                }
            }
            (guard.persisted.clone(), guard.to_status_view(&self.config))
        };

        if let Some(data_dir) = &self.config.data_dir {
            let state_path = update_state_path_from_data_dir(data_dir);
            if let Err(err) = save_persisted_state(&state_path, &next_persisted) {
                eprintln!("updater: failed to persist update-state: {err}");
            }
        }

        op_guard.mark_finished();
        self.emit_status(&emit, &view);
        Ok(view)
    }

    fn set_error_state(&self, msg: String) -> UpdaterStatusView {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.phase = UpdaterPhase::Error;
        guard.bytes_downloaded = 0;
        guard.total_bytes = None;
        guard.error_message = Some(msg);
        guard.notice_message = None;
        guard.to_status_view(&self.config)
    }

    #[allow(clippy::type_complexity)]
    fn restore_after_check_cancel(
        &self,
        prev: (
            UpdaterPhase,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<CachedVerifiedRelease>,
        ),
    ) -> UpdaterStatusView {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.phase = prev.0;
        guard.latest_version = prev.1;
        guard.min_updater_version = prev.2;
        guard.release_notes_url = prev.3;
        guard.cached_verified = prev.4;
        guard.bytes_downloaded = 0;
        guard.total_bytes = None;
        guard.error_message = None;
        guard.notice_message = Some("更新確認をキャンセルしました".to_string());
        guard.to_status_view(&self.config)
    }

    pub(crate) fn apply_update_blocking_with<F, B>(
        &self,
        emit: F,
        on_download_started: Option<B>,
    ) -> Result<UpdaterStatusView, String>
    where
        F: Fn(&UpdaterStatusView),
        B: FnOnce(),
    {
        self.apply_update_blocking_with_hooks(emit, on_download_started, None::<fn()>)
    }

    pub(crate) fn apply_update_blocking_with_hooks<F, B, V>(
        &self,
        emit: F,
        on_download_started: Option<B>,
        on_verifying_started: Option<V>,
    ) -> Result<UpdaterStatusView, String>
    where
        F: Fn(&UpdaterStatusView),
        B: FnOnce(),
        V: FnOnce(),
    {
        let (cancel_token, cached, downloading_view) = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if guard.closing {
                return Err("アプリケーション終了中のため更新を適用できません。".to_string());
            }
            if guard.is_busy() {
                return Err(
                    "UPDATE_IN_PROGRESS: 更新確認または適用が進行中です。".to_string()
                );
            }
            if self.config.install_kind != InstallKind::StandardInstalled {
                return Err(
                    "PORTABLE_OR_DEV_MANUAL_UPDATE_ONLY: Portable / Dev 環境では自動適用できません。".to_string(),
                );
            }
            if guard.phase != UpdaterPhase::UpdateAvailable {
                return Err("NO_UPDATE_AVAILABLE: 適用可能な更新がありません。".to_string());
            }
            let Some(cached) = guard.cached_verified.clone() else {
                return Err("NO_UPDATE_AVAILABLE: 検証済みマニフェストがキャッシュされていません。".to_string());
            };
            validate_staged_installer_filename(&cached.manifest.filename)?;

            let token = CancelToken::new();
            guard.in_flight = true;
            guard.cancel_token = Some(token.clone());
            guard.phase = UpdaterPhase::Downloading;
            guard.bytes_downloaded = 0;
            guard.total_bytes = Some(cached.manifest.size_bytes);
            guard.error_message = None;
            guard.notice_message = None;
            let (done_lock, _) = &*self.done_signal;
            *done_lock.lock().unwrap_or_else(|e| e.into_inner()) = false;
            (token, cached, guard.to_status_view(&self.config))
        };

        let op_guard = OperationGuard::new(Arc::clone(&self.inner), Arc::clone(&self.done_signal));
        self.emit_status(&emit, &downloading_view);

        let data_dir = match &self.config.data_dir {
            Some(dir) => dir.clone(),
            None => {
                let msg = "LOCALAPPDATA が取得できないためステージングを作成できません。".to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        let staging_root = staging_root_from_data_dir(&data_dir);
        let (_session_id, staging_dir) = match create_staging_session_dir(&staging_root) {
            Ok(pair) => pair,
            Err(err) => {
                let msg = err.to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        };

        {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.active_staging_dir = Some(staging_dir.clone());
        }

        let manifest_path = staging_dir.join(STAGED_MANIFEST_FILENAME);
        let sig_path = staging_dir.join(STAGED_SIG_FILENAME);
        let installer_path = staging_dir.join(&cached.manifest.filename);

        if let Err(err) = write_exclusive_synced(&manifest_path, &cached.manifest_bytes)
            .and_then(|()| write_exclusive_synced(&sig_path, &cached.sig_bytes))
        {
            self.cleanup_active_staging(&staging_dir);
            let msg = format!("ステージングファイル書き込みに失敗しました: {err}");
            let view = self.set_error_state(msg.clone());
            op_guard.mark_finished();
            self.emit_status(&emit, &view);
            return Err(msg);
        }

        #[cfg(test)]
        let download_url = self
            .config
            .installer_url_override
            .as_deref()
            .unwrap_or(&cached.manifest.download_url);
        #[cfg(not(test))]
        let download_url = cached.manifest.download_url.as_str();

        if let Some(hook) = on_download_started {
            hook();
        }

        let client = UpdaterHttpClient::new(self.config.http_config.clone());
        let mut last_emit = Instant::now() - PROGRESS_EMIT_INTERVAL;
        let mut progress_cb = |progress: DownloadProgress| {
            let should_emit = last_emit.elapsed() >= PROGRESS_EMIT_INTERVAL
                || progress
                    .total_bytes
                    .is_some_and(|total| progress.bytes_downloaded >= total);
            if should_emit {
                last_emit = Instant::now();
                let view = {
                    let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.bytes_downloaded = progress.bytes_downloaded;
                    if progress.total_bytes.is_some() {
                        guard.total_bytes = progress.total_bytes;
                    }
                    guard.to_status_view(&self.config)
                };
                self.emit_status(&emit, &view);
            }
        };

        let dl_result = client.download_installer_to_file(
            download_url,
            Some(cached.manifest.size_bytes),
            &installer_path,
            &cancel_token,
            &mut progress_cb,
        );

        match dl_result {
            Ok(_) => {}
            Err(UpdaterError::Cancelled) => {
                // `download_installer_to_file` has returned and dropped `BufWriter<File>`.
                self.cleanup_active_staging(&staging_dir);
                let view = self.revert_to_update_available(
                    Some("ダウンロードをキャンセルしました".to_string()),
                );
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            Err(err) => {
                self.cleanup_active_staging(&staging_dir);
                let msg = err.to_string();
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(msg);
            }
        }

        let verifying_view = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if cancel_token.is_cancelled() || guard.closing {
                drop(guard);
                self.cleanup_active_staging(&staging_dir);
                let view = self.revert_to_update_available(Some(
                    "更新の適用をキャンセルしました".to_string(),
                ));
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            guard.phase = UpdaterPhase::Verifying;
            guard.bytes_downloaded = cached.manifest.size_bytes;
            guard.total_bytes = Some(cached.manifest.size_bytes);
            guard.to_status_view(&self.config)
        };
        self.emit_status(&emit, &verifying_view);

        if let Some(hook) = on_verifying_started {
            hook();
        }

        match self.verify_staged_artifacts(
            &manifest_path,
            &sig_path,
            &installer_path,
            &cached.manifest,
            &cancel_token,
        ) {
            VerifyStageResult::Verified => {}
            VerifyStageResult::Cancelled => {
                self.cleanup_active_staging(&staging_dir);
                let view = self.revert_to_update_available(Some(
                    "更新の適用をキャンセルしました".to_string(),
                ));
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            VerifyStageResult::Failed(err) => {
                self.cleanup_active_staging(&staging_dir);
                let view = self.set_error_state(err.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Err(err);
            }
        }

        let launching_view = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if cancel_token.is_cancelled() || guard.closing {
                drop(guard);
                self.cleanup_active_staging(&staging_dir);
                let view = self.revert_to_update_available(Some(
                    "更新の適用をキャンセルしました".to_string(),
                ));
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                return Ok(view);
            }
            guard.phase = UpdaterPhase::LaunchingUpdater;
            guard.to_status_view(&self.config)
        };
        self.emit_status(&emit, &launching_view);

        match self.config.elevation_launcher.launch_elevated_apply(
            &manifest_path,
            &sig_path,
            &installer_path,
        ) {
            ElevationLaunchResult::Launched => {
                // Elevated child will consume and clean up `staging_dir`.
                {
                    let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    guard.active_staging_dir = None;
                }
                let final_view = self.status();
                op_guard.mark_finished();
                (self.config.on_launch_exit)();
                Ok(final_view)
            }
            ElevationLaunchResult::UserCancelled => {
                self.cleanup_active_staging(&staging_dir);
                let view = self.revert_to_update_available(
                    Some("UAC 昇格がキャンセルされました".to_string()),
                );
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                Ok(view)
            }
            ElevationLaunchResult::Failed(msg) => {
                self.cleanup_active_staging(&staging_dir);
                let view = self.set_error_state(msg.clone());
                op_guard.mark_finished();
                self.emit_status(&emit, &view);
                Err(msg)
            }
        }
    }

    fn is_closing(&self) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.closing
    }

    fn verify_staged_artifacts(
        &self,
        manifest_path: &Path,
        sig_path: &Path,
        installer_path: &Path,
        expected_manifest: &UpdateManifest,
        cancel_token: &CancelToken,
    ) -> VerifyStageResult {
        if cancel_token.is_cancelled() || self.is_closing() {
            return VerifyStageResult::Cancelled;
        }
        let m_bytes = match read_verified_bounded_bytes(manifest_path, MAX_MANIFEST_BYTES as u64) {
            Ok(b) => b,
            Err(e) => {
                if cancel_token.is_cancelled() || self.is_closing() {
                    return VerifyStageResult::Cancelled;
                }
                return VerifyStageResult::Failed(format!(
                    "ステージ済みマニフェスト読み取りに失敗しました: {e}"
                ));
            }
        };
        let s_bytes = match read_verified_bounded_bytes(sig_path, MAX_SIG_BYTES as u64) {
            Ok(b) => b,
            Err(e) => {
                if cancel_token.is_cancelled() || self.is_closing() {
                    return VerifyStageResult::Cancelled;
                }
                return VerifyStageResult::Failed(format!(
                    "ステージ済み署名読み取りに失敗しました: {e}"
                ));
            }
        };
        let key_ring = match &self.config.key_ring_override {
            Some(kr) => kr.clone(),
            None => match PublicKeyRing::from_embedded() {
                Ok(kr) => kr,
                Err(e) => return VerifyStageResult::Failed(e.to_string()),
            },
        };
        let outcome = match verify_and_evaluate_manifest(
            &m_bytes,
            &s_bytes,
            &key_ring,
            &self.config.app_version,
        ) {
            Ok(out) => out,
            Err(e) => return VerifyStageResult::Failed(e.to_string()),
        };
        match outcome {
            UpdateVerificationOutcome::UpdateAvailable { manifest, .. } => {
                if *manifest != *expected_manifest {
                    return VerifyStageResult::Failed(
                        "ステージ済みマニフェストが検証済み内容と一致しません。".to_string(),
                    );
                }
            }
            _ => {
                return VerifyStageResult::Failed(
                    "ステージ済みマニフェストのバージョン状態が不正です。".to_string(),
                );
            }
        }
        if cancel_token.is_cancelled() || self.is_closing() {
            return VerifyStageResult::Cancelled;
        }
        if let Err(e) = verify_installer_file(installer_path, expected_manifest) {
            if cancel_token.is_cancelled() || self.is_closing() {
                return VerifyStageResult::Cancelled;
            }
            return VerifyStageResult::Failed(e.to_string());
        }
        if cancel_token.is_cancelled() || self.is_closing() {
            return VerifyStageResult::Cancelled;
        }
        VerifyStageResult::Verified
    }

    fn revert_to_update_available(&self, notice: Option<String>) -> UpdaterStatusView {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.phase = UpdaterPhase::UpdateAvailable;
        guard.bytes_downloaded = 0;
        guard.total_bytes = None;
        guard.error_message = None;
        guard.notice_message = notice;
        guard.to_status_view(&self.config)
    }

    fn cleanup_active_staging(&self, staging_dir: &Path) {
        let _ = remove_dir_all_no_reparse(staging_dir);
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.active_staging_dir.as_deref() == Some(staging_dir) {
            guard.active_staging_dir = None;
        }
    }

    /// Cancels an active download/check and waits boundedly for cleanup before returning status.
    pub(crate) fn cancel_active_operation(&self) -> UpdaterStatusView {
        let token = {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.cancel_token.clone()
        };
        if let Some(tok) = token {
            tok.cancel();
            let (done_lock, done_cv) = &*self.done_signal;
            let done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = done_cv.wait_timeout_while(done, CLOSE_CANCEL_WAIT_TIMEOUT, |d| !*d);
        }
        self.status()
    }

    /// Called on `WindowEvent::CloseRequested`: cancels in-flight downloads, waits boundedly
    /// (`<= 500ms`) for open handles to drop, and removes incomplete staging directories (`L-08`).
    pub(crate) fn cancel_and_cleanup_on_close(&self) {
        let token = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.closing = true;
            guard.cancel_token.clone()
        };
        if let Some(tok) = token {
            tok.cancel();
        }
        let (done_lock, done_cv) = &*self.done_signal;
        let done = done_lock.lock().unwrap_or_else(|e| e.into_inner());
        let _ = done_cv.wait_timeout_while(done, CLOSE_CANCEL_WAIT_TIMEOUT, |d| !*d);

        let leftover = {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            guard.active_staging_dir.take()
        };
        if let Some(dir) = leftover {
            let _ = remove_dir_all_no_reparse(&dir);
        }
    }
}

pub(crate) fn emit_updater_status(app: &AppHandle, view: &UpdaterStatusView) {
    let _ = app.emit(UPDATER_STATUS_EVENT, view);
}

fn write_exclusive_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = create_exclusive_file(path).map_err(updater_err_to_io)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_verified_bounded_bytes(path: &Path, max_bytes: u64) -> io::Result<Vec<u8>> {
    let file = open_verified_read_file_bounded(path, max_bytes)?;
    let limit = usize::try_from(max_bytes).unwrap_or(64 * 1024);
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file {} exceeded {limit} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

fn updater_err_to_io(err: UpdaterError) -> io::Error {
    match err {
        UpdaterError::Io(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Opens an existing regular file for read-only access after reparse-point, disk-type,
/// hardlink (`nNumberOfLinks == 1`), final-path containment, and `ReOpenFile` identity verification.
pub fn open_verified_read_file_bounded(path: &Path, max_bytes: u64) -> io::Result<File> {
    #[cfg(windows)]
    {
        win_updater::open_verified_read_file_bounded(path, max_bytes)
    }
    #[cfg(not(windows))]
    {
        let _ = (path, max_bytes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "verified Windows read is only supported on Windows",
        ))
    }
}

/// Recursively deletes `dir` without following reparse points, junctions, or symlinks.
pub fn remove_dir_all_no_reparse(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        win_updater::remove_dir_all_no_reparse(dir)
    }
    #[cfg(not(windows))]
    {
        let _ = dir;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "reparse-safe cleanup is only supported on Windows",
        ))
    }
}

#[cfg(any(windows, test))]
pub(crate) fn is_allowed_admin_owner_sid(sid: &str) -> bool {
    sid.eq_ignore_ascii_case("S-1-5-18") || sid.eq_ignore_ascii_case("S-1-5-32-544")
}

/// Elevated `--apply-verified-update` entrypoint dispatched before Tauri/IPC startup.
pub(crate) fn dispatch_apply_verified_update(args: &ApplyVerifiedUpdateArgs) -> i32 {
    #[cfg(windows)]
    {
        let install_kind = detect_install_kind();
        let is_elevated = match win_updater::is_current_process_elevated() {
            Ok(val) => val,
            Err(err) => {
                log_apply_diagnostic(&format!(
                    "elevated updater failed to query process elevation token: {err}"
                ));
                return 1;
            }
        };
        let key_ring = match PublicKeyRing::from_embedded() {
            Ok(kr) => kr,
            Err(err) => {
                log_apply_diagnostic(&format!(
                    "elevated updater failed closed on public key ring: {err}"
                ));
                return 1;
            }
        };
        let program_data_dir = PathBuf::from(ledr_proto::PROGRAM_DATA_DIR);
        let installed_exe = PathBuf::from(AUTHORIZED_UI_EXE_PATH);

        match apply_verified_update_with(
            args,
            install_kind,
            is_elevated,
            &key_ring,
            env!("CARGO_PKG_VERSION"),
            &program_data_dir,
            &installed_exe,
            true,
            win_updater::run_nsis_silent_update,
            win_updater::relaunch_non_elevated_via_explorer,
        ) {
            Ok(()) => 0,
            Err(err) => {
                log_apply_diagnostic(&format!("elevated updater aborted: {err}"));
                1
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        eprintln!("--apply-verified-update is only supported on Windows");
        1
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_verified_update_with<N, R>(
    args: &ApplyVerifiedUpdateArgs,
    install_kind: InstallKind,
    is_elevated: bool,
    key_ring: &PublicKeyRing,
    current_version: &str,
    program_data_dir: &Path,
    installed_ui_exe: &Path,
    enforce_admin_owner: bool,
    run_nsis: N,
    relaunch_non_elevated: R,
) -> Result<(), String>
where
    N: FnOnce(&Path) -> Result<(), String>,
    R: FnOnce(&Path) -> Result<(), String>,
{
    if install_kind != InstallKind::StandardInstalled {
        return Err(
            "refusing --apply-verified-update: executable is not installed under C:\\Program Files\\LocalEDR\\ledr-ui.exe".to_string(),
        );
    }
    if !is_elevated {
        return Err("refusing --apply-verified-update: process token is not elevated".to_string());
    }

    validate_distinct_local_inputs(&args.manifest, &args.sig, &args.installer)?;

    ensure_no_reparse_points(&args.manifest).map_err(|e| e.to_string())?;
    ensure_no_reparse_points(&args.sig).map_err(|e| e.to_string())?;
    ensure_no_reparse_points(&args.installer).map_err(|e| e.to_string())?;

    #[cfg(windows)]
    {
        let verified_dir = win_updater::prepare_admin_verified_session_dir(
            program_data_dir,
            enforce_admin_owner,
        )?;
        let verified_guard = VerifiedDirGuard::new(verified_dir.clone());

        let staged_manifest_bytes = read_verified_bounded_bytes(&args.manifest, MAX_MANIFEST_BYTES as u64)
            .map_err(|e| format!("failed reading staged manifest: {e}"))?;
        let staged_sig_bytes = read_verified_bounded_bytes(&args.sig, MAX_SIG_BYTES as u64)
            .map_err(|e| format!("failed reading staged signature: {e}"))?;

        let copied_manifest_path = verified_dir.join(STAGED_MANIFEST_FILENAME);
        let copied_sig_path = verified_dir.join(STAGED_SIG_FILENAME);
        write_exclusive_synced(&copied_manifest_path, &staged_manifest_bytes)
            .map_err(|e| format!("failed copying manifest to verified dir: {e}"))?;
        write_exclusive_synced(&copied_sig_path, &staged_sig_bytes)
            .map_err(|e| format!("failed copying signature to verified dir: {e}"))?;

        let re_manifest_bytes =
            read_verified_bounded_bytes(&copied_manifest_path, MAX_MANIFEST_BYTES as u64)
                .map_err(|e| format!("failed re-reading verified manifest: {e}"))?;
        let re_sig_bytes = read_verified_bounded_bytes(&copied_sig_path, MAX_SIG_BYTES as u64)
            .map_err(|e| format!("failed re-reading verified signature: {e}"))?;

        let outcome = verify_and_evaluate_manifest(
            &re_manifest_bytes,
            &re_sig_bytes,
            key_ring,
            current_version,
        )
        .map_err(|e| format!("verified manifest check failed: {e}"))?;

        let manifest = match outcome {
            UpdateVerificationOutcome::UpdateAvailable { manifest, .. } => *manifest,
            UpdateVerificationOutcome::UpToDate { .. } => {
                return Err("update aborted: target version is already up to date".to_string());
            }
            UpdateVerificationOutcome::ManualUpdateRequired { .. } => {
                return Err("update aborted: manifest requires manual update".to_string());
            }
        };
        validate_staged_installer_filename(&manifest.filename)?;

        let copied_installer_path = verified_dir.join(&manifest.filename);
        copy_verified_installer_bounded(&args.installer, &copied_installer_path, manifest.size_bytes)?;
        verify_installer_file(&copied_installer_path, &manifest)
            .map_err(|e| format!("installer verification inside verified dir failed: {e}"))?;

        best_effort_cleanup_staged_parent(&args.manifest, &args.sig, &args.installer);

        run_nsis(&copied_installer_path)?;

        // Unconditionally delete `verified\<uuid>\` before relaunching the UI.
        verified_guard.cleanup_now()?;

        if let Err(err) = relaunch_non_elevated(installed_ui_exe) {
            // Never fall back to launching an elevated UI! Log and exit cleanly.
            log_apply_diagnostic(&format!(
                "update succeeded, but non-elevated UI relaunch was skipped/failed (will NOT relaunch elevated): {err}"
            ));
        }

        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (
            key_ring,
            current_version,
            program_data_dir,
            installed_ui_exe,
            enforce_admin_owner,
            run_nsis,
            relaunch_non_elevated,
        );
        Err("elevated update apply is only supported on Windows".to_string())
    }
}

pub(crate) fn validate_distinct_local_inputs(
    manifest: &Path,
    sig: &Path,
    installer: &Path,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        for p in [manifest, sig, installer] {
            if !win_updater::is_strict_local_drive_path(p) {
                return Err(format!(
                    "input path '{}' is not a strict local drive path",
                    p.display()
                ));
            }
        }
    }
    let m = normalize_windows_exe_path(&manifest.to_string_lossy());
    let s = normalize_windows_exe_path(&sig.to_string_lossy());
    let i = normalize_windows_exe_path(&installer.to_string_lossy());
    if m == s || m == i || s == i {
        return Err("--manifest, --sig, and --installer must refer to 3 distinct files".to_string());
    }
    Ok(())
}

#[cfg(windows)]
fn copy_verified_installer_bounded(
    src_path: &Path,
    dst_path: &Path,
    expected_size: u64,
) -> Result<(), String> {
    if expected_size == 0 || expected_size > MAX_INSTALLER_BYTES {
        return Err(format!(
            "manifest size_bytes ({expected_size}) outside permitted bounds (1..={MAX_INSTALLER_BYTES})"
        ));
    }
    let mut src = open_verified_read_file_bounded(src_path, MAX_INSTALLER_BYTES)
        .map_err(|e| format!("failed opening staged installer safely: {e}"))?;
    let mut dst = create_exclusive_file(dst_path)
        .map_err(|e| format!("failed creating verified installer file: {e}"))?;

    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = src
            .read(&mut buf)
            .map_err(|e| format!("failed reading staged installer: {e}"))?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > expected_size || total > MAX_INSTALLER_BYTES {
            return Err(format!(
                "staged installer exceeded expected size ({total} > {expected_size})"
            ));
        }
        dst.write_all(&buf[..n])
            .map_err(|e| format!("failed writing verified installer: {e}"))?;
    }
    if total != expected_size {
        return Err(format!(
            "staged installer size mismatch during copy: expected {expected_size}, copied {total}"
        ));
    }
    dst.sync_all()
        .map_err(|e| format!("failed syncing verified installer: {e}"))?;
    Ok(())
}

#[cfg(any(windows, test))]
pub(crate) fn is_valid_uuid_dirname(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, &b) in bytes.iter().enumerate() {
        if matches!(idx, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(all(windows, test))]
pub(crate) fn best_effort_cleanup_staged_parent_for_test(
    manifest: &Path,
    sig: &Path,
    installer: &Path,
) {
    best_effort_cleanup_staged_parent(manifest, sig, installer);
}

#[cfg(windows)]
fn best_effort_cleanup_staged_parent(manifest: &Path, sig: &Path, installer: &Path) {
    let (Some(pm), Some(ps), Some(pi)) = (manifest.parent(), sig.parent(), installer.parent()) else {
        return;
    };
    let pm_n = normalize_windows_exe_path(&pm.to_string_lossy());
    let ps_n = normalize_windows_exe_path(&ps.to_string_lossy());
    let pi_n = normalize_windows_exe_path(&pi.to_string_lossy());
    if pm_n != ps_n || pm_n != pi_n {
        return;
    }
    if !pm
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_valid_uuid_dirname)
    {
        return;
    }
    let Some(grandparent) = pm.parent() else {
        return;
    };
    if grandparent
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("staging"))
        && ensure_no_reparse_points(pm).is_ok()
    {
        let _ = remove_dir_all_no_reparse(pm);
    }
}

#[cfg(windows)]
struct VerifiedDirGuard {
    dir: Option<PathBuf>,
}

#[cfg(windows)]
impl VerifiedDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self { dir: Some(dir) }
    }

    fn cleanup_now(mut self) -> Result<(), String> {
        if let Some(dir) = self.dir.take() {
            remove_dir_all_no_reparse(&dir)
                .map_err(|e| format!("failed removing verified session dir {}: {e}", dir.display()))?;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for VerifiedDirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = remove_dir_all_no_reparse(&dir);
        }
    }
}

#[cfg(windows)]
fn log_apply_diagnostic(message: &str) {
    eprintln!("ledr-ui updater: {message}");
    let log_dir = PathBuf::from(ledr_proto::PROGRAM_DATA_DIR).join("logs");
    if ensure_no_reparse_points(&log_dir).is_err() {
        return;
    }
    let log_path = log_dir.join("updater-apply.log");
    if ensure_no_reparse_points(&log_path).is_err() {
        return;
    }
    if std::fs::create_dir_all(&log_dir).is_ok() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
        {
            let _ = writeln!(f, "[{}] {message}", now_unix_ms());
        }
    }
}

#[cfg(windows)]
pub(crate) mod win_updater {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::ptr;
    use windows::Win32::System::Com::{
        COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
    };

    const INVALID_HANDLE_VALUE: isize = -1;
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;

    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_TYPE_DISK: u32 = 0x0001;
    const VOLUME_NAME_DOS: u32 = 0x0;

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ALREADY_EXISTS: u32 = 183;
    const ERROR_CANCELLED: u32 = 1223;

    const SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
    const SEE_MASK_NOASYNC: u32 = 0x0000_0100;
    const SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
    const SW_SHOWNORMAL: i32 = 1;

    const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
    const TOKEN_DUPLICATE: u32 = 0x0002;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
    const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
    const TOKEN_ELEVATION_INFO_CLASS: u32 = 20;
    const SECURITY_IMPERSONATION_LEVEL: i32 = 2;
    const TOKEN_TYPE_PRIMARY: i32 = 1;

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: FileTime,
        ft_last_access_time: FileTime,
        ft_last_write_time: FileTime,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[repr(C)]
    pub(crate) struct SecurityAttributes {
        pub(crate) n_length: u32,
        pub(crate) lp_security_descriptor: *mut c_void,
        pub(crate) b_inherit_handle: i32,
    }

    #[repr(C)]
    pub(crate) struct ShellExecuteInfoW {
        pub(crate) cb_size: u32,
        pub(crate) f_mask: u32,
        pub(crate) hwnd: *mut c_void,
        pub(crate) lp_verb: *const u16,
        pub(crate) lp_file: *const u16,
        pub(crate) lp_parameters: *const u16,
        pub(crate) lp_directory: *const u16,
        pub(crate) n_show: i32,
        pub(crate) h_inst_app: *mut c_void,
        pub(crate) lp_id_list: *mut c_void,
        pub(crate) lp_class: *const u16,
        pub(crate) hkey_class: *mut c_void,
        pub(crate) dw_hot_key: u32,
        pub(crate) h_icon_or_monitor: *mut c_void,
        pub(crate) h_process: *mut c_void,
    }

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[link(name = "kernel32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn GetLastError() -> u32;
        fn CloseHandle(h_object: *mut c_void) -> i32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn GetLongPathNameW(
            lpsz_short_path: *const u16,
            lpsz_long_path: *mut u16,
            cch_buffer: u32,
        ) -> u32;
        fn CreateDirectoryW(
            lp_path_name: *const u16,
            lp_security_attributes: *const SecurityAttributes,
        ) -> i32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *const c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: *mut c_void,
        ) -> *mut c_void;
        fn ReOpenFile(
            h_original_file: *mut c_void,
            dw_desired_access: u32,
            dw_share_mode: u32,
            dw_flags_and_attributes: u32,
        ) -> *mut c_void;
        fn GetFileType(h_file: *mut c_void) -> u32;
        fn GetFileInformationByHandle(
            h_file: *mut c_void,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            h_file: *mut c_void,
            lpsz_file_path: *mut u16,
            cch_file_path: u32,
            dw_flags: u32,
        ) -> u32;
        fn GetCurrentProcess() -> *mut c_void;
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(dw_process_id: u32, p_session_id: *mut u32) -> i32;
        fn OpenProcess(
            dw_desired_access: u32,
            b_inherit_handle: i32,
            dw_process_id: u32,
        ) -> *mut c_void;
    }

    #[link(name = "shell32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> i32;
    }

    #[link(name = "user32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn GetShellWindow() -> *mut c_void;
        fn GetWindowThreadProcessId(h_wnd: *mut c_void, lpdw_process_id: *mut u32) -> u32;
    }

    #[link(name = "advapi32.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: *mut c_void,
            desired_access: u32,
            token_handle: *mut *mut c_void,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: *mut c_void,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn DuplicateTokenEx(
            h_existing_token: *mut c_void,
            dw_desired_access: u32,
            lp_token_attributes: *const c_void,
            impersonation_level: i32,
            token_type: i32,
            ph_new_token: *mut *mut c_void,
        ) -> i32;
        fn CreateProcessWithTokenW(
            h_token: *mut c_void,
            dw_logon_flags: u32,
            lp_application_name: *const u16,
            lp_command_line: *mut u16,
            dw_creation_flags: u32,
            lp_environment: *const c_void,
            lp_current_directory: *const u16,
            lp_startup_info: *const StartupInfoW,
            lp_process_information: *mut ProcessInformation,
        ) -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            security_descriptor: *const c_void,
            requested_string_sd_revision: u32,
            security_information: u32,
            string_security_descriptor: *mut *mut u16,
            string_security_descriptor_len: *mut u32,
        ) -> i32;
        fn ConvertSidToStringSidW(sid: *const c_void, string_sid: *mut *mut u16) -> i32;
        fn GetSecurityDescriptorDacl(
            p_security_descriptor: *const c_void,
            lpb_dacl_present: *mut i32,
            p_dacl: *mut *mut c_void,
            lpb_dacl_defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityInfo(
            handle: *mut c_void,
            object_type: u32,
            security_info: u32,
            ppsid_owner: *mut *mut c_void,
            ppsid_group: *mut *mut c_void,
            pp_dacl: *mut *mut c_void,
            pp_sacl: *mut *mut c_void,
            pp_security_descriptor: *mut *mut c_void,
        ) -> u32;
        fn SetSecurityInfo(
            handle: *mut c_void,
            object_type: u32,
            security_info: u32,
            psid_owner: *mut c_void,
            psid_group: *mut c_void,
            p_dacl: *mut c_void,
            p_sacl: *mut c_void,
        ) -> u32;
    }

    #[link(name = "userenv.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn CreateEnvironmentBlock(
            lp_environment: *mut *mut c_void,
            h_token: *mut c_void,
            b_inherit: i32,
        ) -> i32;
        fn DestroyEnvironmentBlock(lp_environment: *mut c_void) -> i32;
    }

    #[link(name = "bcrypt.dll", kind = "raw-dylib", modifiers = "+verbatim")]
    extern "system" {
        fn BCryptGenRandom(
            h_algorithm: *mut c_void,
            pb_buffer: *mut u8,
            cb_buffer: u32,
            dw_flags: u32,
        ) -> i32;
    }

    struct OwnedHandle(*mut c_void);

    impl OwnedHandle {
        fn from_raw(raw: *mut c_void) -> Option<Self> {
            if raw.is_null() || raw as isize == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(Self(raw))
            }
        }

        fn into_raw(mut self) -> *mut c_void {
            let raw = self.0;
            self.0 = ptr::null_mut();
            raw
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != INVALID_HANDLE_VALUE {
                // SAFETY: `self.0` is an owned Win32 HANDLE.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct LocalMemGuard(*mut c_void);

    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by a Win32 API requiring `LocalFree`.
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    struct EnvBlockGuard(*mut c_void);

    impl EnvBlockGuard {
        fn for_token(token: *mut c_void) -> Result<Self, String> {
            let mut env: *mut c_void = ptr::null_mut();
            // SAFETY: `token` is a valid primary token and `env` receives the allocated block.
            let ok = unsafe { CreateEnvironmentBlock(&mut env, token, 0) };
            if ok != 0 && !env.is_null() {
                Ok(Self(env))
            } else {
                Err(format!(
                    "CreateEnvironmentBlock failed: {}",
                    io::Error::last_os_error()
                ))
            }
        }

        fn as_ptr(&self) -> *const c_void {
            self.0 as *const c_void
        }
    }

    impl Drop for EnvBlockGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was returned by `CreateEnvironmentBlock`.
                unsafe {
                    let _ = DestroyEnvironmentBlock(self.0);
                }
            }
        }
    }

    struct ComApartmentGuard {
        should_uninit: bool,
    }

    impl ComApartmentGuard {
        fn init_sta() -> Self {
            // SAFETY: Valid COM initialization on calling thread.
            let hr = unsafe {
                CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)
            };
            Self {
                should_uninit: hr.is_ok(),
            }
        }
    }

    impl Drop for ComApartmentGuard {
        fn drop(&mut self) {
            if self.should_uninit {
                // SAFETY: Paired with successful `CoInitializeEx`.
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    pub(crate) struct OwnedSecurityDescriptor {
        sd: *mut c_void,
    }

    impl OwnedSecurityDescriptor {
        pub(crate) fn from_sddl(sddl: &str) -> Result<Self, String> {
            let sddl_w = encode_wide_str_nul(sddl);
            let mut sd: *mut c_void = ptr::null_mut();
            let mut sd_len: u32 = 0;
            // SAFETY: `sddl_w` is NUL-terminated UTF-16; `sd` is owned and freed by `LocalFree`.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    &mut sd_len,
                )
            };
            if ok == 0 || sd.is_null() {
                return Err(format!(
                    "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
                    io::Error::last_os_error()
                ));
            }
            Ok(Self { sd })
        }

        pub(crate) fn security_attributes(&self) -> SecurityAttributes {
            SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: self.sd,
                b_inherit_handle: 0,
            }
        }

        pub(crate) fn dacl(&self) -> Result<*mut c_void, String> {
            let mut present: i32 = 0;
            let mut dacl: *mut c_void = ptr::null_mut();
            let mut defaulted: i32 = 0;
            // SAFETY: `self.sd` is a valid security descriptor owned by `self`.
            let ok = unsafe {
                GetSecurityDescriptorDacl(self.sd, &mut present, &mut dacl, &mut defaulted)
            };
            if ok == 0 || present == 0 || dacl.is_null() {
                return Err("failed to extract DACL from admin security descriptor".to_string());
            }
            Ok(dacl)
        }

        #[cfg(test)]
        pub(crate) fn to_dacl_sddl_string(&self) -> Result<String, String> {
            sd_ptr_to_sddl(self.sd, DACL_SECURITY_INFORMATION)
        }
    }

    impl Drop for OwnedSecurityDescriptor {
        fn drop(&mut self) {
            if !self.sd.is_null() {
                // SAFETY: `self.sd` was allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
                unsafe {
                    let _ = LocalFree(self.sd);
                }
                self.sd = ptr::null_mut();
            }
        }
    }

    fn sd_ptr_to_sddl(sd: *const c_void, info: u32) -> Result<String, String> {
        let mut sddl_ptr: *mut u16 = ptr::null_mut();
        let mut sddl_len: u32 = 0;
        // SAFETY: `sd` is valid and `sddl_ptr` is freed via `LocalMemGuard`.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                info,
                &mut sddl_ptr,
                &mut sddl_len,
            )
        };
        if ok == 0 || sddl_ptr.is_null() {
            return Err(format!(
                "ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {}",
                io::Error::last_os_error()
            ));
        }
        let _guard = LocalMemGuard(sddl_ptr as *mut c_void);
        // SAFETY: `sddl_ptr` contains `sddl_len` UTF-16 code units.
        let slice = unsafe { std::slice::from_raw_parts(sddl_ptr, sddl_len as usize) };
        let nul_trimmed = slice.split(|&c| c == 0).next().unwrap_or(slice);
        Ok(String::from_utf16_lossy(nul_trimmed))
    }

    fn sid_ptr_to_string(sid: *const c_void) -> Result<String, String> {
        let mut str_ptr: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` is a valid SID pointer; `str_ptr` is freed via `LocalMemGuard`.
        let ok = unsafe { ConvertSidToStringSidW(sid, &mut str_ptr) };
        if ok == 0 || str_ptr.is_null() {
            return Err(format!(
                "ConvertSidToStringSidW failed: {}",
                io::Error::last_os_error()
            ));
        }
        let _guard = LocalMemGuard(str_ptr as *mut c_void);
        let mut len = 0usize;
        // SAFETY: `ConvertSidToStringSidW` guarantees NUL termination.
        unsafe {
            while *str_ptr.add(len) != 0 && len < 256 {
                len += 1;
            }
            let slice = std::slice::from_raw_parts(str_ptr, len);
            Ok(String::from_utf16_lossy(slice))
        }
    }

    fn encode_wide_str_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn encode_wide_path_nul(path: &Path) -> io::Result<Vec<u16>> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid empty or NUL path",
            ));
        }
        wide.push(0);
        Ok(wide)
    }

    pub(crate) fn is_strict_local_drive_path(path: &Path) -> bool {
        parse_strict_local_drive_path(path).is_some()
    }

    pub(crate) fn parse_strict_local_drive_path(path: &Path) -> Option<(char, Vec<String>)> {
        let raw = path.to_str()?;
        if raw.is_empty() || raw.contains('\0') {
            return None;
        }

        let rest = if let Some(verbatim) = raw.strip_prefix(r"\\?\") {
            let bytes = verbatim.as_bytes();
            if bytes.len() < 3
                || !bytes[0].is_ascii_alphabetic()
                || bytes[1] != b':'
                || bytes[2] != b'\\'
            {
                return None;
            }
            verbatim
        } else if raw.starts_with(r"\\") || raw.starts_with("//") {
            return None;
        } else {
            raw
        };

        let bytes = rest.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || (bytes[2] != b'\\' && bytes[2] != b'/')
        {
            return None;
        }
        let drive = (bytes[0] as char).to_ascii_uppercase();
        let tail = &rest[3..];
        let mut segments = Vec::new();
        for seg in tail.split(['\\', '/']) {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." {
                return None;
            }
            if seg.contains(':') || seg.ends_with('.') || seg.ends_with(' ') {
                return None;
            }
            segments.push(seg.to_string());
        }
        Some((drive, segments))
    }

    fn build_verbatim_drive_path(drive: char, segments: &[String]) -> PathBuf {
        let mut s = format!(r"\\?\{}:\", drive.to_ascii_uppercase());
        for (i, seg) in segments.iter().enumerate() {
            if i > 0 {
                s.push('\\');
            }
            s.push_str(seg);
        }
        PathBuf::from(s)
    }

    fn query_long_path(verbatim: &Path) -> Option<PathBuf> {
        let wide = encode_wide_path_nul(verbatim).ok()?;
        let mut cap = 512usize;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `wide` is NUL-terminated UTF-16 and `buf` has `cap` writable elements.
            let ret = unsafe {
                GetLongPathNameW(
                    wide.as_ptr(),
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                )
            };
            if ret == 0 {
                return None;
            }
            let len = ret as usize;
            if len < buf.len() {
                return String::from_utf16(&buf[..len]).ok().map(PathBuf::from);
            }
            if len < 32_768 {
                cap = len.saturating_add(1);
                continue;
            }
            return None;
        }
        None
    }

    fn query_final_path_dos(handle: *mut c_void) -> Option<PathBuf> {
        let mut cap = 512usize;
        for _ in 0..4 {
            let mut buf = vec![0u16; cap];
            // SAFETY: `handle` is an open Win32 handle and `buf` has `cap` writable elements.
            let ret = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buf.as_mut_ptr(),
                    u32::try_from(buf.len()).unwrap_or(u32::MAX),
                    VOLUME_NAME_DOS,
                )
            };
            if ret == 0 {
                return None;
            }
            let len = ret as usize;
            if len < buf.len() {
                return String::from_utf16(&buf[..len]).ok().map(PathBuf::from);
            }
            if len < 32_768 {
                cap = len.saturating_add(1);
                continue;
            }
            return None;
        }
        None
    }

    pub(crate) fn resolve_final_path_if_exists(path: &Path) -> Option<PathBuf> {
        let wide = encode_wide_path_nul(path).ok()?;
        // SAFETY: `wide` is NUL-terminated UTF-16; opens existing file for attributes query only.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        let handle = OwnedHandle::from_raw(raw)?;
        query_final_path_dos(handle.0)
    }

    fn segment_eq_case_insensitive(a: &str, b: &str) -> bool {
        if a.is_ascii() && b.is_ascii() {
            a.eq_ignore_ascii_case(b)
        } else {
            a.to_lowercase() == b.to_lowercase()
        }
    }

    fn paths_equal_case_insensitive(a: (char, &[String]), b: (char, &[String])) -> bool {
        a.0.eq_ignore_ascii_case(&b.0)
            && a.1.len() == b.1.len()
            && a.1
                .iter()
                .zip(b.1.iter())
                .all(|(x, y)| segment_eq_case_insensitive(x, y))
    }

    fn expand_long_segments(drive: char, segments: &[String]) -> (char, Vec<String>) {
        let verbatim = build_verbatim_drive_path(drive, segments);
        if let Some(long_path) = query_long_path(&verbatim) {
            if let Some((ld, lsegs)) = parse_strict_local_drive_path(&long_path) {
                if !lsegs.is_empty() {
                    return (ld, lsegs);
                }
            }
        }
        (drive, segments.to_vec())
    }

    fn open_attribute_handle(verbatim_path: &Path, is_dir: bool) -> io::Result<Option<OwnedHandle>> {
        let wide = encode_wide_path_nul(verbatim_path)?;
        let flags = FILE_FLAG_OPEN_REPARSE_POINT
            | if is_dir {
                FILE_FLAG_BACKUP_SEMANTICS
            } else {
                0
            };
        // SAFETY: `wide` is NUL-terminated UTF-16.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                flags,
                ptr::null_mut(),
            )
        };
        if raw as isize == INVALID_HANDLE_VALUE {
            let err = io::Error::last_os_error();
            let code = err.raw_os_error().unwrap_or(0) as u32;
            if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
                return Ok(None);
            }
            return Err(err);
        }
        Ok(OwnedHandle::from_raw(raw))
    }

    fn get_file_info(handle: *mut c_void) -> io::Result<ByHandleFileInformation> {
        let mut info = ByHandleFileInformation {
            dw_file_attributes: 0,
            ft_creation_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            ft_last_access_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            ft_last_write_time: FileTime {
                dw_low_date_time: 0,
                dw_high_date_time: 0,
            },
            dw_volume_serial_number: 0,
            n_file_size_high: 0,
            n_file_size_low: 0,
            n_number_of_links: 0,
            n_file_index_high: 0,
            n_file_index_low: 0,
        };
        // SAFETY: `handle` is an open Win32 handle and `info` is valid out-memory.
        if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    fn is_reparse_entry(verbatim_path: &Path) -> io::Result<bool> {
        let wide = encode_wide_path_nul(verbatim_path)?;
        // SAFETY: `wide` is NUL-terminated UTF-16.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let code = unsafe { GetLastError() };
            if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
                return Ok(false);
            }
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
    }

    pub(crate) fn open_verified_read_file_bounded(
        path: &Path,
        max_bytes: u64,
    ) -> io::Result<File> {
        if let Some(raw) = path.to_str() {
            if raw.ends_with('\\') || raw.ends_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file path ends with directory separator",
                ));
            }
        }
        let leaf = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing filename"))?;
        validate_single_segment_filename(leaf).map_err(updater_err_to_io)?;
        ensure_no_reparse_points(path).map_err(updater_err_to_io)?;

        let (drive, segments) = parse_strict_local_drive_path(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path '{}' is not a strict local drive path", path.display()),
            )
        })?;
        let leaf_verbatim = build_verbatim_drive_path(drive, &segments);

        let attr_handle = open_attribute_handle(&leaf_verbatim, false)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        // SAFETY: `attr_handle.0` is an open Win32 handle.
        if unsafe { GetFileType(attr_handle.0) } != FILE_TYPE_DISK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "target is not a regular disk file",
            ));
        }

        let info1 = get_file_info(attr_handle.0)?;
        if (info1.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info1.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || info1.n_number_of_links != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file failed reparse/regular/link-count check",
            ));
        }

        let file_size = ((info1.n_file_size_high as u64) << 32) | (info1.n_file_size_low as u64);
        if file_size > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("file size {file_size} exceeded limit {max_bytes}"),
            ));
        }

        let final_dos_raw = query_final_path_dos(attr_handle.0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "failed to resolve final path")
        })?;
        let final_dos = parse_strict_local_drive_path(&final_dos_raw).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "final path was not local drive")
        })?;
        let expected_long = expand_long_segments(drive, &segments);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file final path resolved outside expected location",
            ));
        }

        // Upgrade handle via `ReOpenFile` holding `FILE_SHARE_READ` to block concurrent writers.
        // SAFETY: `attr_handle.0` is an open verified disk file handle.
        let read_raw = unsafe {
            ReOpenFile(
                attr_handle.0,
                FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ,
                0,
            )
        };
        if read_raw as isize == INVALID_HANDLE_VALUE || read_raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let read_handle = OwnedHandle::from_raw(read_raw)
            .ok_or_else(|| io::Error::other("invalid handle from ReOpenFile"))?;
        let info2 = get_file_info(read_handle.0)?;
        if (info2.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info2.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0
            || info2.n_number_of_links != 1
            || info2.dw_volume_serial_number != info1.dw_volume_serial_number
            || info2.n_file_index_high != info1.n_file_index_high
            || info2.n_file_index_low != info1.n_file_index_low
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file changed identity during handle upgrade",
            ));
        }

        // SAFETY: `read_handle` transfers ownership of a valid Win32 file handle.
        Ok(unsafe { File::from_raw_handle(read_handle.into_raw() as _) })
    }

    pub(crate) fn remove_dir_all_no_reparse(dir: &Path) -> io::Result<()> {
        let (drive, segments) = parse_strict_local_drive_path(dir).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cleanup path '{}' is not a strict local drive path", dir.display()),
            )
        })?;
        if segments.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to remove bare drive root '{}'", dir.display()),
            ));
        }
        ensure_no_reparse_points(dir).map_err(updater_err_to_io)?;
        let dir_verbatim = build_verbatim_drive_path(drive, &segments);
        if let Some(handle) = open_attribute_handle(&dir_verbatim, true)? {
            let final_dos_raw = query_final_path_dos(handle.0).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "failed resolving cleanup dir final path")
            })?;
            let final_dos = parse_strict_local_drive_path(&final_dos_raw).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "cleanup dir final path was not local drive")
            })?;
            let expected_long = expand_long_segments(drive, &segments);
            if !paths_equal_case_insensitive(
                (final_dos.0, &final_dos.1),
                (expected_long.0, &expected_long.1),
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cleanup dir '{}' resolved outside expected location", dir.display()),
                ));
            }
        }
        remove_dir_all_verbatim_no_reparse(&dir_verbatim)
    }

    fn remove_dir_all_verbatim_no_reparse(dir_verbatim: &Path) -> io::Result<()> {
        if is_reparse_entry(dir_verbatim)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("refusing to remove reparse directory {}", dir_verbatim.display()),
            ));
        }
        let Some(handle) = open_attribute_handle(dir_verbatim, true)? else {
            return Ok(());
        };
        let info = get_file_info(handle.0)?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("refusing to recurse into non-regular directory {}", dir_verbatim.display()),
            ));
        }
        drop(handle);

        for entry_res in std::fs::read_dir(dir_verbatim)? {
            let entry = entry_res?;
            let child_path = entry.path();
            let ft = entry.file_type()?;
            if ft.is_symlink() || is_reparse_entry(&child_path)? {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("reparse child {} encountered during cleanup", child_path.display()),
                ));
            }
            if ft.is_dir() {
                remove_dir_all_verbatim_no_reparse(&child_path)?;
            } else {
                std::fs::remove_file(&child_path)?;
            }
        }
        std::fs::remove_dir(dir_verbatim)?;
        Ok(())
    }

    fn is_token_elevated(token_handle: *mut c_void) -> Result<bool, String> {
        let mut elevation = TokenElevation {
            token_is_elevated: 0,
        };
        let mut ret_len: u32 = 0;
        // SAFETY: `elevation` is properly sized `TokenElevation` output buffer.
        let ok = unsafe {
            GetTokenInformation(
                token_handle,
                TOKEN_ELEVATION_INFO_CLASS,
                (&mut elevation as *mut TokenElevation).cast::<c_void>(),
                std::mem::size_of::<TokenElevation>() as u32,
                &mut ret_len,
            )
        };
        if ok == 0 {
            return Err(format!(
                "GetTokenInformation(TokenElevation) failed: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(elevation.token_is_elevated != 0)
    }

    pub(crate) fn is_current_process_elevated() -> Result<bool, String> {
        let mut raw_token: *mut c_void = ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns pseudo-handle; `raw_token` is closed by `OwnedHandle`.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if ok == 0 {
            return Err(format!("OpenProcessToken failed: {}", io::Error::last_os_error()));
        }
        let token = OwnedHandle::from_raw(raw_token)
            .ok_or_else(|| "OpenProcessToken returned null handle".to_string())?;
        is_token_elevated(token.0)
    }

    pub(crate) fn generate_uuid_v4_string() -> Result<String, String> {
        let mut bytes = [0u8; 16];
        // SAFETY: `bytes` is a 16-byte writable buffer; system preferred RNG requires null alg handle.
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(format!("BCryptGenRandom failed with NTSTATUS 0x{status:08x}"));
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    pub(crate) fn create_and_verify_admin_dir(
        dir_path: &Path,
        sddl: &str,
        must_be_new: bool,
        enforce_admin_owner: bool,
    ) -> Result<(), String> {
        let (drive, segments) = parse_strict_local_drive_path(dir_path).ok_or_else(|| {
            format!("directory '{}' is not a strict local drive path", dir_path.display())
        })?;
        if segments.is_empty() {
            return Err(format!(
                "refusing to use bare drive root '{}' as admin directory",
                dir_path.display()
            ));
        }
        ensure_no_reparse_points(dir_path).map_err(|e| e.to_string())?;
        let verbatim = build_verbatim_drive_path(drive, &segments);
        let wide = encode_wide_path_nul(&verbatim).map_err(|e| e.to_string())?;

        let sd = OwnedSecurityDescriptor::from_sddl(sddl)?;
        let sa = sd.security_attributes();

        // SAFETY: `wide` is NUL-terminated UTF-16 and `sa` points to valid `OwnedSecurityDescriptor`.
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
        if created == 0 {
            let err_code = unsafe { GetLastError() };
            if err_code != ERROR_ALREADY_EXISTS || must_be_new {
                return Err(format!(
                    "CreateDirectoryW({}) failed: {}",
                    dir_path.display(),
                    io::Error::from_raw_os_error(err_code as i32)
                ));
            }
        }

        // Open handle without following reparse points and enforce protected DACL.
        // SAFETY: `wide` is NUL-terminated UTF-16.
        let raw_handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        let handle = OwnedHandle::from_raw(raw_handle).ok_or_else(|| {
            format!(
                "failed opening directory handle {}: {}",
                dir_path.display(),
                io::Error::last_os_error()
            )
        })?;

        let info = get_file_info(handle.0).map_err(|e| e.to_string())?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        {
            return Err(format!(
                "directory '{}' failed reparse/directory verification",
                dir_path.display()
            ));
        }

        let final_dos_raw = query_final_path_dos(handle.0)
            .ok_or_else(|| format!("GetFinalPathNameByHandleW failed for {}", dir_path.display()))?;
        let final_dos = parse_strict_local_drive_path(&final_dos_raw)
            .ok_or_else(|| "verified dir final path is not strict local drive".to_string())?;
        let expected_long = expand_long_segments(drive, &segments);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(format!(
                "directory '{}' resolved outside expected location",
                dir_path.display()
            ));
        }

        let mut owner_sid: *mut c_void = ptr::null_mut();
        let mut existing_dacl: *mut c_void = ptr::null_mut();
        let mut queried_sd: *mut c_void = ptr::null_mut();
        // SAFETY: `handle.0` is an open handle with `READ_CONTROL`; `queried_sd` is freed via `LocalMemGuard`.
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                ptr::null_mut(),
                &mut existing_dacl,
                ptr::null_mut(),
                &mut queried_sd,
            )
        };
        if status != 0 || queried_sd.is_null() {
            return Err(format!(
                "GetSecurityInfo failed on {}: {}",
                dir_path.display(),
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        let _sd_guard = LocalMemGuard(queried_sd);

        if enforce_admin_owner {
            if owner_sid.is_null() {
                return Err(format!("directory '{}' has null owner SID", dir_path.display()));
            }
            let sid_str = sid_ptr_to_string(owner_sid)?;
            if !is_allowed_admin_owner_sid(&sid_str) {
                return Err(format!(
                    "directory '{}' has non-admin owner SID {sid_str}",
                    dir_path.display()
                ));
            }
        }

        let target_dacl = sd.dacl()?;
        // Enforce protected admin-only DACL on the open handle so pre-existing dirs cannot leak non-admin ACEs.
        // SAFETY: `handle.0` has `WRITE_DAC` and `target_dacl` is valid for the lifetime of `sd`.
        let set_status = unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                target_dacl,
                ptr::null_mut(),
            )
        };
        if set_status != 0 {
            return Err(format!(
                "SetSecurityInfo failed on {}: {}",
                dir_path.display(),
                io::Error::from_raw_os_error(set_status as i32)
            ));
        }

        // Re-query DACL to confirm protected admin-only SDDL took effect.
        verify_handle_dacl_sddl(handle.0, sddl, dir_path)?;

        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn query_dir_dacl_sddl(dir_path: &Path) -> Result<String, String> {
        let wide = encode_wide_path_nul(dir_path).map_err(|e| e.to_string())?;
        // SAFETY: `wide` is NUL-terminated UTF-16.
        let raw_handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        let handle = OwnedHandle::from_raw(raw_handle).ok_or_else(|| {
            format!(
                "failed opening {} for DACL read: {}",
                dir_path.display(),
                io::Error::last_os_error()
            )
        })?;
        let mut queried_sd: *mut c_void = ptr::null_mut();
        let mut dacl: *mut c_void = ptr::null_mut();
        // SAFETY: `handle.0` has `READ_CONTROL`; `queried_sd` is freed via `LocalMemGuard`.
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut queried_sd,
            )
        };
        if status != 0 || queried_sd.is_null() {
            return Err(format!(
                "GetSecurityInfo failed on {}: {}",
                dir_path.display(),
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        let _guard = LocalMemGuard(queried_sd);
        sd_ptr_to_sddl(queried_sd, DACL_SECURITY_INFORMATION)
    }

    fn verify_handle_dacl_sddl(
        handle: *mut c_void,
        _expected_sddl: &str,
        dir_path: &Path,
    ) -> Result<(), String> {
        let mut queried_sd: *mut c_void = ptr::null_mut();
        let mut dacl: *mut c_void = ptr::null_mut();
        // SAFETY: `handle` has `READ_CONTROL`; `queried_sd` is freed via `LocalMemGuard`.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut queried_sd,
            )
        };
        if status != 0 || queried_sd.is_null() {
            return Err(format!(
                "GetSecurityInfo verify failed on {}: {}",
                dir_path.display(),
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        let _guard = LocalMemGuard(queried_sd);
        let actual = sd_ptr_to_sddl(queried_sd, DACL_SECURITY_INFORMATION)?;
        verify_admin_only_dacl_sddl(&actual).map_err(|reason| {
            format!(
                "directory '{}' failed admin-only DACL verification ({reason}): got '{actual}'",
                dir_path.display()
            )
        })
    }

    fn parse_ace_flags(ace_flags: &str, ace: &str, allow_inherited: bool) -> Result<bool, String> {
        if !ace_flags.len().is_multiple_of(2) {
            return Err(format!("malformed ACE flags '{ace_flags}' in ({ace})"));
        }
        let mut has_io = false;
        let mut has_oi = false;
        let mut has_ci = false;
        let (chunks, _) = ace_flags.as_bytes().as_chunks::<2>();
        for chunk in chunks {
            match chunk {
                b"OI" => has_oi = true,
                b"CI" => has_ci = true,
                b"NP" => {}
                b"IO" => has_io = true,
                b"ID" => {
                    if !allow_inherited {
                        return Err(format!("inherited ACE flag 'ID' not allowed in ({ace})"));
                    }
                }
                other => {
                    let s = std::str::from_utf8(other).unwrap_or("??");
                    return Err(format!("unexpected ACE flag '{s}' in ({ace})"));
                }
            }
        }
        if has_io && !has_oi && !has_ci {
            return Err(format!("standalone inherit-only ACE flag '{ace_flags}' in ({ace})"));
        }
        Ok(has_io)
    }

    fn is_read_execute_only_sddl_rights(rights: &str) -> bool {
        // Permitted read/execute/sync bits only:
        // FILE_READ_DATA (0x1) | FILE_READ_EA (0x8) | FILE_EXECUTE (0x20) | FILE_READ_ATTRIBUTES (0x80)
        // | READ_CONTROL (0x20000) | SYNCHRONIZE (0x100000) | GENERIC_EXECUTE (0x20000000) | GENERIC_READ (0x80000000)
        const SAFE_RX_MASK: u32 = 0xA012_00A9;

        if let Some(hex) = rights.strip_prefix("0x").or_else(|| rights.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16)
                .is_ok_and(|mask| mask != 0 && (mask & !SAFE_RX_MASK) == 0);
        }
        if rights.is_empty() || !rights.len().is_multiple_of(2) {
            return false;
        }
        let (chunks, _) = rights.as_bytes().as_chunks::<2>();
        chunks
            .iter()
            .all(|chunk| matches!(chunk, b"GR" | b"GX" | b"FR" | b"FX" | b"RC"))
    }

    pub(crate) fn verify_admin_only_dacl_sddl(sddl: &str) -> Result<(), String> {
        let Some(after_d) = sddl.strip_prefix("D:") else {
            return Err("missing DACL section".to_string());
        };
        let dacl_part = after_d.split("S:").next().unwrap_or(after_d);
        let first_ace_idx = dacl_part
            .find('(')
            .ok_or_else(|| "DACL contains no ACE entries".to_string())?;
        let flags = &dacl_part[..first_ace_idx];
        if !flags.contains('P') {
            return Err("DACL is not protected against parent inheritance (missing 'P')".to_string());
        }
        let aces_str = &dacl_part[first_ace_idx..];
        let mut rest = aces_str;
        let mut has_direct_sy = false;
        let mut has_direct_ba = false;
        while !rest.is_empty() {
            let Some(after_open) = rest.strip_prefix('(') else {
                return Err(format!("unexpected trailing DACL tokens: {rest}"));
            };
            let Some(close_idx) = after_open.find(')') else {
                return Err("unclosed ACE parenthesis in DACL".to_string());
            };
            let ace = &after_open[..close_idx];
            rest = &after_open[close_idx + 1..];
            let fields: Vec<&str> = ace.split(';').collect();
            if fields.len() != 6 {
                return Err(format!("unexpected ACE field count in ({ace})"));
            }
            let (ace_type, ace_flags, rights, _obj, _inh_obj, sid) = (
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
            );
            if ace_type != "A" {
                return Err(format!("non-allow ACE ({ace}) in admin-only DACL"));
            }
            let is_io = parse_ace_flags(ace_flags, ace, false)?;
            if rights != "GA" && rights != "FA" {
                return Err(format!("unexpected access rights '{rights}' in ({ace})"));
            }
            if sid == "SY" || sid.eq_ignore_ascii_case("S-1-5-18") {
                if !is_io {
                    has_direct_sy = true;
                }
            } else if sid == "BA" || sid.eq_ignore_ascii_case("S-1-5-32-544") {
                if !is_io {
                    has_direct_ba = true;
                }
            } else {
                return Err(format!("unauthorized trustee SID '{sid}' in ({ace})"));
            }
        }
        if !has_direct_sy || !has_direct_ba {
            return Err(
                "admin-only DACL must grant direct non-IO full access to both SY and BA"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub(crate) fn verify_program_data_dacl_sddl(sddl: &str) -> Result<(), String> {
        let Some(after_d) = sddl.strip_prefix("D:") else {
            return Err("missing DACL section".to_string());
        };
        let dacl_part = after_d.split("S:").next().unwrap_or(after_d);
        let first_ace_idx = dacl_part
            .find('(')
            .ok_or_else(|| "DACL contains no ACE entries".to_string())?;
        let aces_str = &dacl_part[first_ace_idx..];
        let mut rest = aces_str;
        let mut has_direct_sy = false;
        let mut has_direct_ba = false;
        while !rest.is_empty() {
            let Some(after_open) = rest.strip_prefix('(') else {
                return Err(format!("unexpected trailing DACL tokens: {rest}"));
            };
            let Some(close_idx) = after_open.find(')') else {
                return Err("unclosed ACE parenthesis in DACL".to_string());
            };
            let ace = &after_open[..close_idx];
            rest = &after_open[close_idx + 1..];
            let fields: Vec<&str> = ace.split(';').collect();
            if fields.len() != 6 {
                return Err(format!("unexpected ACE field count in ({ace})"));
            }
            let (ace_type, ace_flags, rights, _obj, _inh_obj, sid) = (
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5],
            );
            if ace_type != "A" {
                return Err(format!("non-allow ACE ({ace}) in ProgramData DACL"));
            }
            let is_io = parse_ace_flags(ace_flags, ace, true)?;
            if sid == "SY" || sid.eq_ignore_ascii_case("S-1-5-18") {
                if rights != "GA" && rights != "FA" {
                    return Err(format!("unexpected SY access rights '{rights}' in ({ace})"));
                }
                if !is_io {
                    has_direct_sy = true;
                }
            } else if sid == "BA" || sid.eq_ignore_ascii_case("S-1-5-32-544") {
                if rights != "GA" && rights != "FA" {
                    return Err(format!("unexpected BA access rights '{rights}' in ({ace})"));
                }
                if !is_io {
                    has_direct_ba = true;
                }
            } else if sid == "BU" || sid.eq_ignore_ascii_case("S-1-5-32-545") {
                if !is_read_execute_only_sddl_rights(rights) {
                    return Err(format!(
                        "non-admin trustee '{sid}' has excessive access rights '{rights}' in ({ace})"
                    ));
                }
            } else {
                return Err(format!(
                    "unauthorized trustee SID '{sid}' in ProgramData DACL ({ace})"
                ));
            }
        }
        if !has_direct_sy || !has_direct_ba {
            return Err(
                "ProgramData DACL must grant direct non-IO full access to both SY and BA"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn ensure_and_verify_program_data_root(
        dir_path: &Path,
        enforce_admin_owner: bool,
    ) -> Result<(), String> {
        let (drive, segments) = parse_strict_local_drive_path(dir_path).ok_or_else(|| {
            format!("directory '{}' is not a strict local drive path", dir_path.display())
        })?;
        if segments.is_empty() {
            return Err(format!(
                "refusing to use bare drive root '{}' as ProgramData dir",
                dir_path.display()
            ));
        }
        ensure_no_reparse_points(dir_path).map_err(|e| e.to_string())?;
        let verbatim = build_verbatim_drive_path(drive, &segments);
        let wide = encode_wide_path_nul(&verbatim).map_err(|e| e.to_string())?;

        // Create only if missing (granting SY:F, BA:F, BU:RX); never overwrite an existing root DACL.
        let sd = OwnedSecurityDescriptor::from_sddl(PROGRAM_DATA_ROOT_SDDL)?;
        let sa = sd.security_attributes();
        // SAFETY: `wide` is NUL-terminated UTF-16 and `sa` points to valid `OwnedSecurityDescriptor`.
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
        if created == 0 {
            let err_code = unsafe { GetLastError() };
            if err_code != ERROR_ALREADY_EXISTS {
                return Err(format!(
                    "CreateDirectoryW({}) failed: {}",
                    dir_path.display(),
                    io::Error::from_raw_os_error(err_code as i32)
                ));
            }
        }

        // Open handle without following reparse points and inspect owner + DACL read-only.
        // SAFETY: `wide` is NUL-terminated UTF-16.
        let raw_handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        };
        let handle = OwnedHandle::from_raw(raw_handle).ok_or_else(|| {
            format!(
                "failed opening directory handle {}: {}",
                dir_path.display(),
                io::Error::last_os_error()
            )
        })?;

        let info = get_file_info(handle.0).map_err(|e| e.to_string())?;
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
            || (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0
        {
            return Err(format!(
                "directory '{}' failed reparse/directory verification",
                dir_path.display()
            ));
        }

        let final_dos_raw = query_final_path_dos(handle.0)
            .ok_or_else(|| format!("GetFinalPathNameByHandleW failed for {}", dir_path.display()))?;
        let final_dos = parse_strict_local_drive_path(&final_dos_raw)
            .ok_or_else(|| "ProgramData dir final path is not strict local drive".to_string())?;
        let expected_long = expand_long_segments(drive, &segments);
        if !paths_equal_case_insensitive(
            (final_dos.0, &final_dos.1),
            (expected_long.0, &expected_long.1),
        ) {
            return Err(format!(
                "directory '{}' resolved outside expected location",
                dir_path.display()
            ));
        }

        let mut owner_sid: *mut c_void = ptr::null_mut();
        let mut existing_dacl: *mut c_void = ptr::null_mut();
        let mut queried_sd: *mut c_void = ptr::null_mut();
        // SAFETY: `handle.0` is an open handle with `READ_CONTROL`; `queried_sd` is freed via `LocalMemGuard`.
        let status = unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                ptr::null_mut(),
                &mut existing_dacl,
                ptr::null_mut(),
                &mut queried_sd,
            )
        };
        if status != 0 || queried_sd.is_null() {
            return Err(format!(
                "GetSecurityInfo failed on {}: {}",
                dir_path.display(),
                io::Error::from_raw_os_error(status as i32)
            ));
        }
        let _sd_guard = LocalMemGuard(queried_sd);

        if enforce_admin_owner {
            if owner_sid.is_null() {
                return Err(format!("directory '{}' has null owner SID", dir_path.display()));
            }
            let sid_str = sid_ptr_to_string(owner_sid)?;
            if !is_allowed_admin_owner_sid(&sid_str) {
                return Err(format!(
                    "directory '{}' has non-admin owner SID {sid_str}",
                    dir_path.display()
                ));
            }
        }

        let actual_sddl = sd_ptr_to_sddl(queried_sd, DACL_SECURITY_INFORMATION)?;
        verify_program_data_dacl_sddl(&actual_sddl).map_err(|reason| {
            format!(
                "directory '{}' failed ProgramData DACL verification ({reason}): got '{actual_sddl}'",
                dir_path.display()
            )
        })?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn create_dir_with_sddl(dir_path: &Path, sddl: &str) -> Result<(), String> {
        let (drive, segments) = parse_strict_local_drive_path(dir_path).ok_or_else(|| {
            format!("directory '{}' is not a strict local drive path", dir_path.display())
        })?;
        let verbatim = build_verbatim_drive_path(drive, &segments);
        let wide = encode_wide_path_nul(&verbatim).map_err(|e| e.to_string())?;
        let sd = OwnedSecurityDescriptor::from_sddl(sddl)?;
        let sa = sd.security_attributes();
        // SAFETY: `wide` is NUL-terminated UTF-16 and `sa` points to valid `OwnedSecurityDescriptor`.
        let created = unsafe { CreateDirectoryW(wide.as_ptr(), &sa) };
        if created == 0 {
            return Err(format!(
                "CreateDirectoryW({}) failed: {}",
                dir_path.display(),
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_admin_verified_session_dir(
        program_data_dir: &Path,
        enforce_admin_owner: bool,
    ) -> Result<PathBuf, String> {
        ensure_and_verify_program_data_root(program_data_dir, enforce_admin_owner)?;
        let updates_dir = program_data_dir.join("updates");
        create_and_verify_admin_dir(
            &updates_dir,
            ADMIN_ONLY_DIR_SDDL,
            false,
            enforce_admin_owner,
        )?;
        let verified_root = updates_dir.join("verified");
        create_and_verify_admin_dir(
            &verified_root,
            ADMIN_ONLY_DIR_SDDL,
            false,
            enforce_admin_owner,
        )?;
        let session_uuid = generate_uuid_v4_string()?;
        let session_dir = verified_root.join(session_uuid);
        create_and_verify_admin_dir(
            &session_dir,
            ADMIN_ONLY_DIR_SDDL,
            true,
            enforce_admin_owner,
        )?;
        Ok(session_dir)
    }

    pub(crate) fn run_nsis_silent_update(verified_installer: &Path) -> Result<(), String> {
        ensure_no_reparse_points(verified_installer).map_err(|e| e.to_string())?;
        let status = Command::new(verified_installer)
            .args(["/S", "/UPDATE"])
            .current_dir(INSTALL_DIR_WINDOWS)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map_err(|e| format!("failed spawning NSIS installer: {e}"))?;
        if !status.success() {
            return Err(format!(
                "NSIS silent update exited with status {:?}",
                status.code()
            ));
        }
        Ok(())
    }

    fn format_quoted_cli_arg(path: &Path) -> Result<String, String> {
        if !is_strict_local_drive_path(path) {
            return Err(format!(
                "path '{}' is not a strict local drive path",
                path.display()
            ));
        }
        let s = path.to_string_lossy();
        if s.contains('"') || s.ends_with('\\') {
            return Err(format!(
                "path '{}' contains forbidden quote or trailing backslash",
                path.display()
            ));
        }
        Ok(format!("\"{s}\""))
    }

    pub(crate) fn launch_elevated_apply_uac(
        authorized_exe: &Path,
        manifest_path: &Path,
        sig_path: &Path,
        installer_path: &Path,
    ) -> ElevationLaunchResult {
        if let Err(err) = ensure_no_reparse_points(authorized_exe) {
            return ElevationLaunchResult::Failed(format!(
                "authorized UI executable failed reparse check: {err}"
            ));
        }
        if !authorized_exe.is_file() {
            return ElevationLaunchResult::Failed(format!(
                "authorized UI executable not found at {}",
                authorized_exe.display()
            ));
        }

        let (m_q, s_q, i_q) = match (
            format_quoted_cli_arg(manifest_path),
            format_quoted_cli_arg(sig_path),
            format_quoted_cli_arg(installer_path),
        ) {
            (Ok(m), Ok(s), Ok(i)) => (m, s, i),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                return ElevationLaunchResult::Failed(e);
            }
        };

        let params =
            format!("--apply-verified-update --manifest {m_q} --sig {s_q} --installer {i_q}");
        let verb_w = encode_wide_str_nul("runas");
        let file_w = match encode_wide_path_nul(authorized_exe) {
            Ok(w) => w,
            Err(e) => return ElevationLaunchResult::Failed(e.to_string()),
        };
        let params_w = encode_wide_str_nul(&params);
        let dir_w = encode_wide_str_nul(INSTALL_DIR_WINDOWS);

        let _com = ComApartmentGuard::init_sta();
        let mut sei = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
            hwnd: ptr::null_mut(),
            lp_verb: verb_w.as_ptr(),
            lp_file: file_w.as_ptr(),
            lp_parameters: params_w.as_ptr(),
            lp_directory: dir_w.as_ptr(),
            n_show: SW_SHOWNORMAL,
            h_inst_app: ptr::null_mut(),
            lp_id_list: ptr::null_mut(),
            lp_class: ptr::null(),
            hkey_class: ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: ptr::null_mut(),
            h_process: ptr::null_mut(),
        };

        // SAFETY: All wide strings and `sei` remain valid for the duration of `ShellExecuteExW`.
        let ok = unsafe { ShellExecuteExW(&mut sei) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_CANCELLED {
                return ElevationLaunchResult::UserCancelled;
            }
            return ElevationLaunchResult::Failed(format!(
                "ShellExecuteExW(runas) failed (error {code}): {}",
                io::Error::from_raw_os_error(code as i32)
            ));
        }

        let _proc = OwnedHandle::from_raw(sei.h_process);
        ElevationLaunchResult::Launched
    }

    pub(crate) fn shell_open_url(url: &str) -> Result<(), String> {
        let verb_w = encode_wide_str_nul("open");
        let url_w = encode_wide_str_nul(url);
        let _com = ComApartmentGuard::init_sta();
        let mut sei = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
            hwnd: ptr::null_mut(),
            lp_verb: verb_w.as_ptr(),
            lp_file: url_w.as_ptr(),
            lp_parameters: ptr::null(),
            lp_directory: ptr::null(),
            n_show: SW_SHOWNORMAL,
            h_inst_app: ptr::null_mut(),
            lp_id_list: ptr::null_mut(),
            lp_class: ptr::null(),
            hkey_class: ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: ptr::null_mut(),
            h_process: ptr::null_mut(),
        };
        // SAFETY: `verb_w`, `url_w`, and `sei` stay valid across `ShellExecuteExW`.
        let ok = unsafe { ShellExecuteExW(&mut sei) };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!(
                "failed to open release notes URL (error {code}): {}",
                io::Error::from_raw_os_error(code as i32)
            ));
        }
        Ok(())
    }

    pub(crate) fn relaunch_non_elevated_via_explorer(ui_exe: &Path) -> Result<(), String> {
        ensure_no_reparse_points(ui_exe).map_err(|e| e.to_string())?;
        if !ui_exe.is_file() {
            return Err(format!(
                "installed UI executable missing at {}",
                ui_exe.display()
            ));
        }

        // SAFETY: Queries shell window handle for current desktop session.
        let shell_hwnd = unsafe { GetShellWindow() };
        if shell_hwnd.is_null() {
            return Err("GetShellWindow returned NULL (no explorer.exe shell)".to_string());
        }

        let mut explorer_pid: u32 = 0;
        // SAFETY: `shell_hwnd` is non-null.
        unsafe {
            let _ = GetWindowThreadProcessId(shell_hwnd, &mut explorer_pid);
        }
        if explorer_pid == 0 {
            return Err("GetWindowThreadProcessId returned PID 0".to_string());
        }

        let mut current_session: u32 = 0;
        let mut explorer_session: u32 = 0;
        // SAFETY: Valid `u32` out-pointers for session IDs.
        let ok_cur = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) };
        let ok_exp = unsafe { ProcessIdToSessionId(explorer_pid, &mut explorer_session) };
        if ok_cur == 0 || ok_exp == 0 {
            return Err(format!(
                "ProcessIdToSessionId failed: {}",
                io::Error::last_os_error()
            ));
        }
        if current_session != explorer_session {
            return Err(format!(
                "explorer.exe session mismatch (current={current_session}, explorer={explorer_session})"
            ));
        }

        // SAFETY: Opens `explorer.exe` process for token query/duplication.
        let raw_proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, explorer_pid) };
        let explorer_proc = OwnedHandle::from_raw(raw_proc).ok_or_else(|| {
            format!(
                "OpenProcess(explorer PID={explorer_pid}) failed: {}",
                io::Error::last_os_error()
            )
        })?;

        let mut raw_token: *mut c_void = ptr::null_mut();
        // SAFETY: `explorer_proc.0` is an open process handle.
        if unsafe { OpenProcessToken(explorer_proc.0, TOKEN_DUPLICATE | TOKEN_QUERY, &mut raw_token) }
            == 0
        {
            return Err(format!(
                "OpenProcessToken(explorer) failed: {}",
                io::Error::last_os_error()
            ));
        }
        let explorer_token = OwnedHandle::from_raw(raw_token)
            .ok_or_else(|| "OpenProcessToken(explorer) returned null".to_string())?;

        if is_token_elevated(explorer_token.0)? {
            return Err(
                "refusing non-elevated relaunch: explorer.exe token is elevated".to_string(),
            );
        }

        let mut raw_primary: *mut c_void = ptr::null_mut();
        let access = TOKEN_ASSIGN_PRIMARY
            | TOKEN_DUPLICATE
            | TOKEN_QUERY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_SESSIONID;
        // SAFETY: Duplicates `explorer.exe`'s Medium IL token into a primary token.
        if unsafe {
            DuplicateTokenEx(
                explorer_token.0,
                access,
                ptr::null(),
                SECURITY_IMPERSONATION_LEVEL,
                TOKEN_TYPE_PRIMARY,
                &mut raw_primary,
            )
        } == 0
        {
            return Err(format!(
                "DuplicateTokenEx(explorer) failed: {}",
                io::Error::last_os_error()
            ));
        }
        let primary_token = OwnedHandle::from_raw(raw_primary)
            .ok_or_else(|| "DuplicateTokenEx returned null".to_string())?;

        let env_guard = EnvBlockGuard::for_token(primary_token.0)?;
        let mut desktop_w = encode_wide_str_nul(r"winsta0\default");
        let app_w = encode_wide_path_nul(ui_exe).map_err(|e| e.to_string())?;
        let cmd_str = format!("\"{}\"", ui_exe.display());
        let mut cmd_w = encode_wide_str_nul(&cmd_str);
        let dir_w = encode_wide_str_nul(INSTALL_DIR_WINDOWS);

        let startup_info = StartupInfoW {
            cb: std::mem::size_of::<StartupInfoW>() as u32,
            lp_reserved: ptr::null_mut(),
            lp_desktop: desktop_w.as_mut_ptr(),
            lp_title: ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: ptr::null_mut(),
            h_std_input: ptr::null_mut(),
            h_std_output: ptr::null_mut(),
            h_std_error: ptr::null_mut(),
        };
        let mut proc_info = ProcessInformation {
            h_process: ptr::null_mut(),
            h_thread: ptr::null_mut(),
            dw_process_id: 0,
            dw_thread_id: 0,
        };

        let flags = CREATE_UNICODE_ENVIRONMENT;
        let env_ptr = env_guard.as_ptr();

        // SAFETY: `primary_token.0` is a valid Medium-IL primary token; all buffers outlive the call.
        let ok = unsafe {
            CreateProcessWithTokenW(
                primary_token.0,
                0,
                app_w.as_ptr(),
                cmd_w.as_mut_ptr(),
                flags,
                env_ptr,
                dir_w.as_ptr(),
                &startup_info,
                &mut proc_info,
            )
        };
        if ok == 0 {
            return Err(format!(
                "CreateProcessWithTokenW failed: {}",
                io::Error::last_os_error()
            ));
        }

        let _proc = OwnedHandle::from_raw(proc_info.h_process);
        let _thread = OwnedHandle::from_raw(proc_info.h_thread);
        Ok(())
    }
}
