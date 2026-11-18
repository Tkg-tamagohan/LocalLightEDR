//! Active defense actuators (`NtSuspendProcess`, `NtResumeProcess`, `TerminateProcess`,
//! Never-Suspend / `CreationTime` safety guards, descendant tree containment, and
//! honeypot decoy file lifecycle management) (`AUTO-02`, `AUTO-03`, `L-06`, `L-07`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ledr_proto::{
    ActiveDefenseController, HONEYPOT_DEFAULT_FILENAME, ProcessIdentity, is_never_suspend_process,
};
use windows::core::PWSTR;
use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE,
    QueryFullProcessImageNameW, TerminateProcess,
};

use crate::{OwnedHandle, SensorError};

const HONEYPOT_DECOY_CONTENT: &[u8] = b"LocalEDR Canary Decoy File - Do Not Modify or Delete.\r\n";

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    fn NtResumeProcess(process_handle: HANDLE) -> i32;
}

/// Manages deployment and removal of lexicographically-first honeypot decoy files (`L-06`).
#[derive(Debug, Clone)]
pub struct HoneypotManager {
    roots: Vec<PathBuf>,
    create_missing_roots: bool,
    deployed_paths: Vec<PathBuf>,
}

impl Default for HoneypotManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HoneypotManager {
    /// Creates a [`HoneypotManager`] targeting the default user profile folders:
    /// `%USERPROFILE%\Documents`, `%USERPROFILE%\Desktop`, and `%USERPROFILE%\Pictures`.
    pub fn new() -> Self {
        let roots = default_honeypot_roots();
        Self {
            roots,
            create_missing_roots: false,
            deployed_paths: Vec::new(),
        }
    }

    /// Creates a [`HoneypotManager`] targeting an explicit list of root directories (for tests or
    /// custom policies).
    pub fn with_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            create_missing_roots: true,
            deployed_paths: Vec::new(),
        }
    }

    /// Returns the configured directory roots.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// Returns the paths currently tracked as deployed honeypots.
    pub fn deployed_paths(&self) -> &[PathBuf] {
        &self.deployed_paths
    }

    /// Deploys `!00_LocalEDR_Canary_DoNotEdit.docx` into configured roots and tracks created paths.
    pub fn deploy_honeypots(&mut self) -> Result<Vec<PathBuf>, SensorError> {
        let mut created = Vec::new();
        for root in &self.roots {
            if self.create_missing_roots {
                std::fs::create_dir_all(root)?;
            } else if !root.is_dir() {
                continue;
            }

            let target = root.join(HONEYPOT_DEFAULT_FILENAME);
            if !target.exists() {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                file.write_all(HONEYPOT_DECOY_CONTENT)?;
                file.flush()?;
            }

            if !self.deployed_paths.contains(&target) {
                self.deployed_paths.push(target.clone());
            }
            created.push(target);
        }
        Ok(created)
    }

    /// Deletes all tracked honeypot files cleanly, returning the number of files removed.
    pub fn remove_honeypots(&mut self) -> Result<usize, SensorError> {
        let tracked = std::mem::take(&mut self.deployed_paths);
        let mut removed = 0usize;
        let mut remaining = Vec::new();

        for (idx, path) in tracked.iter().enumerate() {
            match std::fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    remaining.extend_from_slice(&tracked[idx..]);
                    self.deployed_paths = remaining;
                    return Err(SensorError::Io(err));
                }
            }
        }

        Ok(removed)
    }
}

fn default_honeypot_roots() -> Vec<PathBuf> {
    let Some(profile) = std::env::var_os("USERPROFILE") else {
        return Vec::new();
    };
    let base = PathBuf::from(profile);
    vec![
        base.join("Documents"),
        base.join("Desktop"),
        base.join("Pictures"),
    ]
}

#[derive(Debug, Clone)]
pub(crate) struct ValidatedTarget {
    pub(crate) identity: ProcessIdentity,
    pub(crate) exe_path: String,
}

/// Validates that `target` is safe to suspend, resume, or terminate (`AUTO-02`, `AUTO-03`):
///
/// 1. Rejects `pid == 0`, `pid == 4`, and `pid == std::process::id()`.
/// 2. Resolves the image path (`QueryFullProcessImageNameW` with Toolhelp32 fallback) and rejects
///    any [`ledr_proto::is_never_suspend_process`] match.
/// 3. Verifies `GetProcessTimes` `CreationTime` matches `target.create_time_100ns` when non-zero
///    to prevent PID reuse errors.
pub fn validate_target_process(target: &ProcessIdentity) -> Result<(), String> {
    validate_and_inspect_target(target).map(|_| ())
}

fn validate_and_inspect_target(target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
    validate_pid_basics(target.pid, std::process::id())?;

    let handle = match open_process_checked(target.pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(h) => h,
        Err(open_err) => {
            if let Some(fallback_exe) = find_process_exe_toolhelp32(target.pid) {
                if is_never_suspend_process(&fallback_exe) {
                    return Err(format!(
                        "refusing to act on protected process `{fallback_exe}` (PID {})",
                        target.pid
                    ));
                }
            }
            return Err(open_err);
        }
    };

    validate_open_handle(handle.as_raw(), target)
}

fn validate_pid_basics(pid: u32, self_pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("refusing to act on Idle process (PID 0)".to_string());
    }
    if pid == 4 {
        return Err("refusing to act on System process (PID 4)".to_string());
    }
    if pid == self_pid {
        return Err(format!("refusing to act on self process (PID {pid})"));
    }
    Ok(())
}

fn validate_open_handle(handle: HANDLE, target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
    let exe_path = query_full_image_name(handle)
        .or_else(|| find_process_exe_toolhelp32(target.pid))
        .ok_or_else(|| {
            format!(
                "unable to resolve image name for PID {}; refusing action fail-closed",
                target.pid
            )
        })?;

    let actual_create_time = query_process_creation_time(handle);
    validate_process_metadata(
        target.pid,
        std::process::id(),
        Some(&exe_path),
        target.create_time_100ns,
        actual_create_time,
    )?;

    let resolved_create_time = actual_create_time.unwrap_or(target.create_time_100ns);
    Ok(ValidatedTarget {
        identity: ProcessIdentity::new(target.pid, resolved_create_time),
        exe_path,
    })
}

fn validate_process_metadata(
    pid: u32,
    self_pid: u32,
    exe_path: Option<&str>,
    expected_create_time_100ns: u64,
    actual_create_time_100ns: Option<u64>,
) -> Result<(), String> {
    validate_pid_basics(pid, self_pid)?;

    let exe = exe_path.ok_or_else(|| format!("missing image path for PID {pid}"))?;
    if is_never_suspend_process(exe) {
        return Err(format!(
            "refusing to act on protected process `{exe}` (PID {pid})"
        ));
    }

    if expected_create_time_100ns != 0 {
        let actual = actual_create_time_100ns.ok_or_else(|| {
            format!("unable to query CreationTime for PID {pid} to verify ProcessIdentity")
        })?;
        if actual != expected_create_time_100ns {
            return Err(format!(
                "CreationTime mismatch for PID {pid} (expected {expected_create_time_100ns}, actual {actual}): possible PID reuse"
            ));
        }
    }

    Ok(())
}

/// Windows active-defense actuator implementing [`ActiveDefenseController`] via `ntdll`
/// `NtSuspendProcess`/`NtResumeProcess` and Win32 `TerminateProcess` (`AUTO-02`, `AUTO-03`, `L-07`).
#[derive(Debug, Default)]
pub struct WindowsDefenseController {
    suspended_processes: Mutex<HashSet<ProcessIdentity>>,
    suspended_children: Mutex<HashMap<ProcessIdentity, Vec<ProcessIdentity>>>,
}

impl WindowsDefenseController {
    /// Creates a new [`WindowsDefenseController`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a snapshot of currently tracked suspended descendants for `target` (useful for
    /// diagnostics and tests).
    pub fn tracked_suspended_children(&self, target: &ProcessIdentity) -> Vec<ProcessIdentity> {
        self.suspended_children
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(target)
            .cloned()
            .unwrap_or_default()
    }

    fn suspend_single_validated(&self, target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
        let pre = validate_and_inspect_target(target)?;
        {
            let tracked = self
                .suspended_processes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if tracked.contains(&pre.identity) {
                tracing::debug!(
                    pid = pre.identity.pid,
                    exe = %pre.exe_path,
                    "process already suspended by LocalEDR; skipping duplicate NtSuspendProcess"
                );
                return Ok(pre);
            }
        }

        let handle = open_process_checked(
            target.pid,
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
        )?;
        let verified = validate_open_handle(handle.as_raw(), &pre.identity)?;

        // SAFETY: `handle` is an open valid process handle validated against Never-Suspend and CreationTime.
        let status = unsafe { NtSuspendProcess(handle.as_raw()) };
        if status < 0 {
            return Err(format!(
                "NtSuspendProcess failed for PID {} (`{}`): NTSTATUS 0x{:08X}",
                verified.identity.pid, verified.exe_path, status as u32
            ));
        }
        self.suspended_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(verified.identity);
        tracing::info!(
            pid = verified.identity.pid,
            exe = %verified.exe_path,
            "suspended process via NtSuspendProcess"
        );
        Ok(verified)
    }

    fn resume_single_validated(&self, target: &ProcessIdentity) -> Result<ValidatedTarget, String> {
        let pre = validate_and_inspect_target(target)?;
        let handle = open_process_checked(
            target.pid,
            PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION,
        )?;
        let verified = validate_open_handle(handle.as_raw(), &pre.identity)?;

        // SAFETY: `handle` is an open valid process handle validated against Never-Suspend and CreationTime.
        let status = unsafe { NtResumeProcess(handle.as_raw()) };
        if status < 0 {
            return Err(format!(
                "NtResumeProcess failed for PID {} (`{}`): NTSTATUS 0x{:08X}",
                verified.identity.pid, verified.exe_path, status as u32
            ));
        }
        self.suspended_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&verified.identity);
        tracing::info!(
            pid = verified.identity.pid,
            exe = %verified.exe_path,
            "resumed process via NtResumeProcess"
        );
        Ok(verified)
    }

    fn terminate_single_validated(&self, target: &ProcessIdentity) -> Result<(), String> {
        let pre = validate_and_inspect_target(target)?;
        let handle = open_process_checked(
            target.pid,
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
        )?;
        let verified = validate_open_handle(handle.as_raw(), &pre.identity)?;

        // SAFETY: `handle` has `PROCESS_TERMINATE` and passed Never-Suspend and CreationTime checks.
        unsafe { TerminateProcess(handle.as_raw(), 1) }.map_err(|err| {
            format!(
                "TerminateProcess failed for PID {} (`{}`): {err}",
                verified.identity.pid, verified.exe_path
            )
        })?;
        self.suspended_processes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&verified.identity);
        tracing::info!(
            pid = verified.identity.pid,
            exe = %verified.exe_path,
            "terminated process via TerminateProcess"
        );
        Ok(())
    }
}

impl ActiveDefenseController for WindowsDefenseController {
    fn suspend_process(&self, target: &ProcessIdentity, include_children: bool) -> Result<(), String> {
        let root = self.suspend_single_validated(target)?;
        if !include_children {
            return Ok(());
        }

        let descendants = collect_validated_descendants(&root.identity);
        let mut suspended_kids = Vec::with_capacity(descendants.len());
        for child in descendants {
            match self.suspend_single_validated(&child) {
                Ok(verified_child) => suspended_kids.push(verified_child.identity),
                Err(err) => {
                    tracing::debug!(
                        root_pid = root.identity.pid,
                        child_pid = child.pid,
                        error = %err,
                        "skipping descendant during tree suspend"
                    );
                }
            }
        }

        if !suspended_kids.is_empty() {
            let mut map = self
                .suspended_children
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let entry = map.entry(root.identity).or_default();
            for kid in suspended_kids {
                if !entry.contains(&kid) {
                    entry.push(kid);
                }
            }
        }

        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        let root = validate_and_inspect_target(target)?;
        let recorded_children = {
            let mut map = self
                .suspended_children
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut kids = map.remove(&root.identity).unwrap_or_default();
            if kids.is_empty() && target != &root.identity {
                kids = map.remove(target).unwrap_or_default();
            }
            kids
        };

        for child in recorded_children {
            if let Err(err) = self.resume_single_validated(&child) {
                tracing::debug!(
                    root_pid = root.identity.pid,
                    child_pid = child.pid,
                    error = %err,
                    "skipping descendant during tree resume"
                );
            }
        }

        self.resume_single_validated(&root.identity).map(|_| ())
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        let root = validate_and_inspect_target(target)?;
        let recorded_children = {
            let mut map = self
                .suspended_children
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut kids = map.remove(&root.identity).unwrap_or_default();
            if kids.is_empty() && target != &root.identity {
                kids = map.remove(target).unwrap_or_default();
            }
            kids
        };

        let mut descendants_to_kill = Vec::new();
        if include_children {
            let mut seen_pids = HashSet::new();
            for child in collect_validated_descendants(&root.identity) {
                if seen_pids.insert(child.pid) {
                    descendants_to_kill.push(child);
                }
            }
            for child in recorded_children {
                if seen_pids.insert(child.pid) {
                    descendants_to_kill.push(child);
                }
            }
        }

        // Terminate the root first so it cannot respawn children or exit on child death before
        // `TerminateProcess` runs on it, then terminate every collected descendant.
        self.terminate_single_validated(&root.identity)?;

        for child in descendants_to_kill.into_iter().rev() {
            if let Err(err) = self.terminate_single_validated(&child) {
                tracing::debug!(
                    root_pid = root.identity.pid,
                    child_pid = child.pid,
                    error = %err,
                    "skipping descendant during tree terminate"
                );
            }
        }

        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        _exe_path: &Path,
        _remote_ip: Option<IpAddr>,
        _allow: bool,
    ) -> Result<u64, String> {
        Err("WFP dynamic firewall rules are not enabled until Phase 3".to_string())
    }

    fn remove_wfp_rule(&self, _filter_id: u64) -> Result<(), String> {
        Err("WFP dynamic firewall rules are not enabled until Phase 3".to_string())
    }
}

#[derive(Debug, Clone)]
struct SnapshotEntry {
    pid: u32,
    ppid: u32,
    exe_name: String,
}

fn snapshot_process_entries() -> Result<Vec<SnapshotEntry>, String> {
    // SAFETY: `TH32CS_SNAPPROCESS` with PID 0 enumerates all processes on the host.
    let raw_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|err| format!("CreateToolhelp32Snapshot failed: {err}"))?;
    let snapshot = OwnedHandle::new(raw_snap)
        .ok_or_else(|| "CreateToolhelp32Snapshot returned an invalid handle".to_string())?;

    let mut out = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // SAFETY: `snapshot` is valid and `entry.dwSize` is initialized.
    if let Err(err) = unsafe { Process32FirstW(snapshot.as_raw(), &mut entry) } {
        return Err(format!("Process32FirstW failed: {err}"));
    }

    let no_more_files = ERROR_NO_MORE_FILES.to_hresult();
    loop {
        out.push(SnapshotEntry {
            pid: entry.th32ProcessID,
            ppid: entry.th32ParentProcessID,
            exe_name: utf16_z_to_string(&entry.szExeFile),
        });

        // SAFETY: `snapshot` and `entry` remain valid across iteration.
        if let Err(err) = unsafe { Process32NextW(snapshot.as_raw(), &mut entry) } {
            if err.code() == no_more_files {
                break;
            }
            return Err(format!("Process32NextW failed: {err}"));
        }
    }

    Ok(out)
}

fn collect_validated_descendants(root: &ProcessIdentity) -> Vec<ProcessIdentity> {
    let Ok(entries) = snapshot_process_entries() else {
        return Vec::new();
    };

    let mut by_ppid: HashMap<u32, Vec<SnapshotEntry>> = HashMap::new();
    for entry in entries {
        if entry.pid == 0 || entry.pid == 4 {
            continue;
        }
        by_ppid.entry(entry.ppid).or_default().push(entry);
    }

    let mut visited = HashSet::new();
    visited.insert(0);
    visited.insert(4);
    visited.insert(std::process::id());
    visited.insert(root.pid);

    let mut descendants = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(*root);

    while let Some(parent) = queue.pop_front() {
        let Some(children) = by_ppid.get(&parent.pid) else {
            continue;
        };
        for child_entry in children {
            if !visited.insert(child_entry.pid) {
                continue;
            }
            if is_never_suspend_process(&child_entry.exe_name) {
                tracing::warn!(
                    parent_pid = parent.pid,
                    child_pid = child_entry.pid,
                    exe = %child_entry.exe_name,
                    "skipping protected descendant process during tree traversal"
                );
                continue;
            }

            let Ok(child_handle) =
                open_process_checked(child_entry.pid, PROCESS_QUERY_LIMITED_INFORMATION)
            else {
                continue;
            };
            let Some(child_create_time) = query_process_creation_time(child_handle.as_raw()) else {
                continue;
            };

            // Guard against recycled parent PIDs: a true descendant must be created at or after
            // its parent's creation timestamp.
            if !is_valid_descendant_timestamp(parent.create_time_100ns, child_create_time) {
                continue;
            }

            let candidate = ProcessIdentity::new(child_entry.pid, child_create_time);
            match validate_open_handle(child_handle.as_raw(), &candidate) {
                Ok(validated) => {
                    descendants.push(validated.identity);
                    queue.push_back(validated.identity);
                }
                Err(err) => {
                    tracing::debug!(
                        child_pid = child_entry.pid,
                        error = %err,
                        "descendant rejected by safety guard"
                    );
                }
            }
        }
    }

    descendants
}

fn is_valid_descendant_timestamp(parent_create_time_100ns: u64, child_create_time_100ns: u64) -> bool {
    parent_create_time_100ns == 0 || child_create_time_100ns >= parent_create_time_100ns
}

fn open_process_checked(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<OwnedHandle, String> {
    // SAFETY: `OpenProcess` takes plain integer flags and PID; result handle is RAII-wrapped.
    let raw = unsafe { OpenProcess(access, false, pid) }
        .map_err(|err| format!("OpenProcess(PID {pid}) failed: {err}"))?;
    OwnedHandle::new(raw).ok_or_else(|| format!("OpenProcess(PID {pid}) returned invalid handle"))
}

fn query_full_image_name(handle: HANDLE) -> Option<String> {
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `handle` is an open process handle and `buf` is valid writable storage.
    unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) }
        .ok()?;
    if len == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(
        &buf[..(len as usize).min(buf.len())],
    ))
}

fn query_process_creation_time(handle: HANDLE) -> Option<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is an open process handle and all four `FILETIME` structs are valid.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.ok()?;
    Some(((creation.dwHighDateTime as u64) << 32) | (creation.dwLowDateTime as u64))
}

fn find_process_exe_toolhelp32(pid: u32) -> Option<String> {
    let entries = snapshot_process_entries().ok()?;
    entries
        .into_iter()
        .find(|e| e.pid == pid)
        .map(|e| e.exe_name)
}

fn utf16_z_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempTestDir(PathBuf);

    impl TempTestDir {
        fn new(prefix: &str) -> Self {
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "ledr-sensor-test-{prefix}-{}-{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create temp test dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sens_p2_04_never_suspend_guard_rejects_system_self_and_explorer() {
        let controller = WindowsDefenseController::new();

        // PID 0, PID 4, and self PID must be rejected by both validator and controller.
        for forbidden_pid in [0u32, 4u32, std::process::id()] {
            let ident = ProcessIdentity::new(forbidden_pid, 0);
            assert!(
                validate_target_process(&ident).is_err(),
                "expected validate_target_process to reject PID {forbidden_pid}"
            );
            assert!(
                controller.suspend_process(&ident, false).is_err(),
                "expected suspend_process to reject PID {forbidden_pid}"
            );
            assert!(
                controller.terminate_process(&ident, false).is_err(),
                "expected terminate_process to reject PID {forbidden_pid}"
            );
        }

        // Verify metadata guard rejects all NEVER_SUSPEND_PROCESS_NAMES entries.
        for protected in ledr_proto::NEVER_SUSPEND_PROCESS_NAMES {
            let path = format!(r"C:\Windows\System32\{protected}");
            assert!(
                validate_process_metadata(9999, std::process::id(), Some(&path), 100, Some(100))
                    .is_err(),
                "expected Never-Suspend rejection for `{path}`"
            );
        }

        // If `explorer.exe` is running in this session, verify live validation rejects it too.
        if let Ok(entries) = snapshot_process_entries() {
            if let Some(explorer) = entries
                .into_iter()
                .find(|e| e.exe_name.eq_ignore_ascii_case("explorer.exe"))
            {
                let ident = ProcessIdentity::new(explorer.pid, 0);
                let err = validate_target_process(&ident)
                    .expect_err("live explorer.exe MUST be rejected by Never-Suspend guard");
                assert!(
                    err.contains("protected process"),
                    "unexpected explorer.exe error message: {err}"
                );
                assert!(controller.suspend_process(&ident, true).is_err());
            }
        }
    }

    #[test]
    fn sens_p2_05_creation_time_mismatch_and_tree_containment() {
        let controller = WindowsDefenseController::new();

        // Spawn a harmless two-level process tree (`cmd.exe` -> `findstr.exe`) blocked on stdin.
        let mut child = Command::new("cmd.exe")
            .args(["/c", "echo ready & findstr .*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn harmless cmd.exe child for defense tests");
        let _stdin_keepalive = child.stdin.take();

        let child_pid = child.id();
        let handle = open_process_checked(child_pid, PROCESS_QUERY_LIMITED_INFORMATION)
            .expect("open spawned test child");
        let real_create_time = query_process_creation_time(handle.as_raw())
            .expect("query spawned child CreationTime");
        drop(handle);

        // Give cmd.exe a moment to spawn its grandchild `findstr.exe` when testing tree containment.
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(
            child.try_wait().expect("poll child status").is_none(),
            "test child must still be running before suspend/terminate checks"
        );

        // 1. CreationTime mismatch MUST be rejected (PID reuse guard, AUTO-03).
        let stale_ident = ProcessIdentity::new(child_pid, real_create_time.saturating_add(1));
        let mismatch_err = validate_target_process(&stale_ident)
            .expect_err("CreationTime mismatch must reject target");
        assert!(
            mismatch_err.contains("CreationTime mismatch"),
            "unexpected mismatch error: {mismatch_err}"
        );
        assert!(controller.suspend_process(&stale_ident, false).is_err());
        assert!(controller.terminate_process(&stale_ident, false).is_err());

        // 2. Exact CreationTime passes validation and supports suspend -> resume -> terminate.
        let valid_ident = ProcessIdentity::new(child_pid, real_create_time);
        assert_eq!(validate_target_process(&valid_ident), Ok(()));
        assert!(!is_valid_descendant_timestamp(real_create_time, real_create_time.saturating_sub(1)));
        assert!(is_valid_descendant_timestamp(real_create_time, real_create_time));

        let had_live_grandchild = snapshot_process_entries()
            .unwrap_or_default()
            .iter()
            .any(|e| e.ppid == child_pid);

        controller
            .suspend_process(&valid_ident, true)
            .expect("suspend harmless child tree");
        if had_live_grandchild {
            assert!(
                !controller.tracked_suspended_children(&valid_ident).is_empty(),
                "expected descendant process to be tracked while tree is suspended"
            );
        }
        controller
            .resume_process(&valid_ident)
            .expect("resume harmless child tree");
        assert!(
            controller.tracked_suspended_children(&valid_ident).is_empty(),
            "expected tracked suspended children to clear after resume"
        );
        controller
            .terminate_process(&valid_ident, true)
            .expect("terminate harmless child tree");

        let status = child.wait().expect("wait terminated child");
        assert!(!status.success());

        // Phase 3 WFP methods cleanly report Phase 3 status.
        assert!(
            controller
                .add_wfp_app_rule(Path::new(r"C:\Temp\a.exe"), None, false)
                .is_err()
        );
        assert!(controller.remove_wfp_rule(1).is_err());
    }

    #[test]
    fn sens_p2_06_honeypot_manager_deploy_and_remove_lifecycle() {
        let temp = TempTestDir::new("honeypot");
        let docs = temp.path().join("Documents");
        let desktop = temp.path().join("Desktop");
        let pics = temp.path().join("Pictures");

        let mut manager =
            HoneypotManager::with_roots(vec![docs.clone(), desktop.clone(), pics.clone()]);
        let deployed = manager.deploy_honeypots().expect("deploy honeypots");
        assert_eq!(deployed.len(), 3);
        assert_eq!(manager.deployed_paths().len(), 3);

        for path in &deployed {
            assert!(path.is_file(), "expected honeypot file at {}", path.display());
            assert_eq!(
                path.file_name().and_then(|n| n.to_str()),
                Some(HONEYPOT_DEFAULT_FILENAME)
            );
            let bytes = std::fs::read(path).expect("read deployed honeypot");
            assert!(!bytes.is_empty());
        }

        // Re-deploying should not duplicate tracked entries.
        let redeployed = manager.deploy_honeypots().expect("idempotent redeploy");
        assert_eq!(redeployed.len(), 3);
        assert_eq!(manager.deployed_paths().len(), 3);

        // Removing deletes all tracked decoy files and resets tracked state.
        let removed = manager.remove_honeypots().expect("remove honeypots");
        assert_eq!(removed, 3);
        assert!(manager.deployed_paths().is_empty());
        for path in &deployed {
            assert!(
                !path.exists(),
                "expected honeypot {} to be removed",
                path.display()
            );
        }

        // Second removal is a clean no-op returning 0.
        assert_eq!(manager.remove_honeypots().expect("idempotent remove"), 0);

        // Default constructor uses %USERPROFILE%\Documents, Desktop, Pictures when present.
        let default_mgr = HoneypotManager::new();
        if std::env::var_os("USERPROFILE").is_some() {
            assert_eq!(default_mgr.roots().len(), 3);
        }
    }

    #[test]
    fn sens_p2_07_idempotent_double_suspend_single_resume() {
        let controller = WindowsDefenseController::new();
        let mut child = Command::new("cmd.exe")
            .args(["/c", "findstr .*"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn harmless cmd.exe child for idempotent suspend test");
        let stdin_pipe = child.stdin.take();

        let child_pid = child.id();
        let handle = open_process_checked(child_pid, PROCESS_QUERY_LIMITED_INFORMATION)
            .expect("open child for CreationTime");
        let real_create_time =
            query_process_creation_time(handle.as_raw()).expect("query child CreationTime");
        drop(handle);

        let ident = ProcessIdentity::new(child_pid, real_create_time);
        controller
            .suspend_process(&ident, false)
            .expect("first suspend");
        controller
            .suspend_process(&ident, false)
            .expect("idempotent second suspend");

        // Drop stdin EOF while suspended: process must stay paused until a single resume_process.
        drop(stdin_pipe);
        std::thread::sleep(std::time::Duration::from_millis(120));
        assert!(
            child.try_wait().expect("poll suspended child").is_none(),
            "child must remain suspended despite stdin EOF"
        );

        controller
            .resume_process(&ident)
            .expect("single resume must clear suspension completely");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Some(_status) = child.try_wait().expect("poll resumed child") {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child remained frozen after single resume_process (double suspend leaked suspend count)");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}
