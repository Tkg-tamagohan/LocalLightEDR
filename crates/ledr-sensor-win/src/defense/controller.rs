//! Active defense controller implementing suspend, resume, terminate, and WFP delegation.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use ledr_proto::{ActiveDefenseController, ProcessIdentity, is_never_suspend_process};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess,
};

use crate::wfp::{
    WfpDropSinkFn, WfpDynamicEngine, validate_wfp_package_sid, validate_wfp_rule_request,
};

use super::guard::{
    TargetValidationError, ValidatedTarget, validate_and_inspect_target,
    validate_and_inspect_target_detailed, validate_open_handle,
};
use super::process_probe::{
    PROCESS_EXIT_WAIT_MS, is_process_handle_exited, open_process_checked,
    open_process_checked_detailed, query_full_image_name, query_process_creation_time,
};
use super::tree::collect_validated_descendants;

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    fn NtResumeProcess(process_handle: HANDLE) -> i32;
}

/// Windows active-defense actuator implementing [`ActiveDefenseController`] via `ntdll`
/// `NtSuspendProcess`/`NtResumeProcess`, Win32 `TerminateProcess`, and the dynamic WFP
/// firewall engine (`AUTO-02`, `AUTO-03`, `AUTO-04`, `L-03`, `L-07`).
#[derive(Default)]
pub struct WindowsDefenseController {
    suspended_processes: Mutex<HashSet<ProcessIdentity>>,
    suspended_children: Mutex<HashMap<ProcessIdentity, Vec<ProcessIdentity>>>,
    wfp_engine: Mutex<Option<WfpDynamicEngine>>,
    pub(super) wfp_drop_sink: Mutex<Option<WfpDropSinkFn>>,
}

impl std::fmt::Debug for WindowsDefenseController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let has_wfp = self.wfp_engine.lock().is_ok_and(|g| g.is_some());
        let has_drop_sink = self.wfp_drop_sink.lock().is_ok_and(|g| g.is_some());
        f.debug_struct("WindowsDefenseController")
            .field("has_wfp_engine", &has_wfp)
            .field("has_wfp_drop_sink", &has_drop_sink)
            .finish()
    }
}

fn ensure_wfp_engine_locked<'a>(
    slot: &'a mut Option<WfpDynamicEngine>,
    pending_sink: &Mutex<Option<WfpDropSinkFn>>,
) -> Result<&'a WfpDynamicEngine, String> {
    if slot.is_none() {
        let engine = WfpDynamicEngine::open_dynamic()?;
        let sink_opt = pending_sink.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(sink) = sink_opt {
            if let Err(err) = engine.set_drop_sink(sink) {
                tracing::warn!(
                    error = %err,
                    "failed attaching pending WFP drop sink during lazy session initialization"
                );
            }
        }
        *slot = Some(engine);
    }
    slot.as_ref()
        .ok_or_else(|| "WFP dynamic session failed to initialize".to_string())
}

impl WindowsDefenseController {
    /// Creates a new [`WindowsDefenseController`] with lazy dynamic WFP session initialization.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`WindowsDefenseController`] pre-configured with an explicit [`WfpDynamicEngine`].
    pub fn with_wfp_engine(wfp_engine: WfpDynamicEngine) -> Self {
        Self {
            suspended_processes: Mutex::new(HashSet::new()),
            suspended_children: Mutex::new(HashMap::new()),
            wfp_engine: Mutex::new(Some(wfp_engine)),
            wfp_drop_sink: Mutex::new(None),
        }
    }

    /// Eagerly initializes the dynamic WFP session (`FWPM_SESSION_FLAG_DYNAMIC`) and custom
    /// SubLayer (`AUTO-04`). Safe to call repeatedly (no-op once initialized).
    pub fn init_wfp_session(&self) -> Result<(), String> {
        let mut slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _ = ensure_wfp_engine_locked(&mut slot, &self.wfp_drop_sink)?;
        Ok(())
    }

    /// Registers a callback sink receiving WFP net-event drops for LocalEDR block filters
    /// (`BUG_0001`). Works both before and after lazy WFP session creation.
    pub fn set_wfp_drop_sink(&self, sink: WfpDropSinkFn) -> Result<(), String> {
        let slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(engine) = slot.as_ref() {
            engine.set_drop_sink(Arc::clone(&sink))?;
        }
        let mut sink_slot = self
            .wfp_drop_sink
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *sink_slot = Some(sink);
        Ok(())
    }

    /// Unregisters any active WFP net-event drop sink and clears any pending lazy registration.
    pub fn clear_wfp_drop_sink(&self) {
        let slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        {
            let mut sink_slot = self
                .wfp_drop_sink
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            *sink_slot = None;
        }
        if let Some(engine) = slot.as_ref() {
            if let Err(err) = engine.clear_drop_sink() {
                tracing::warn!(error = %err, "failed clearing WFP drop sink");
            }
        }
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
        let (handle, has_synchronize) = match open_process_checked(
            target.pid,
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
        ) {
            Ok(h) => (h, true),
            Err(_) => match open_process_checked(
                target.pid,
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            ) {
                Ok(h) => (h, false),
                Err(open_err) => {
                    if confirm_validated_identity_exited(&pre.identity) {
                        self.suspended_processes
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .remove(&pre.identity);
                        tracing::info!(
                            pid = pre.identity.pid,
                            exe = %pre.exe_path,
                            "target process already exited before TerminateProcess handle open"
                        );
                        return Ok(());
                    }
                    return Err(open_err);
                }
            },
        };
        let verified = validate_open_handle(handle.as_raw(), &pre.identity)?;

        if is_process_handle_exited(handle.as_raw(), has_synchronize, 0) {
            self.suspended_processes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&verified.identity);
            tracing::info!(
                pid = verified.identity.pid,
                exe = %verified.exe_path,
                "target process already exited (kernel rundown zombie); skipping TerminateProcess"
            );
            return Ok(());
        }

        // SAFETY: `handle` has `PROCESS_TERMINATE` and passed Never-Suspend and CreationTime checks.
        if let Err(err) = unsafe { TerminateProcess(handle.as_raw(), 1) } {
            if is_process_handle_exited(handle.as_raw(), has_synchronize, PROCESS_EXIT_WAIT_MS) {
                self.suspended_processes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&verified.identity);
                tracing::info!(
                    pid = verified.identity.pid,
                    exe = %verified.exe_path,
                    error = %err,
                    "TerminateProcess returned error after process already exited during rundown"
                );
                return Ok(());
            }
            return Err(format!(
                "TerminateProcess failed for PID {} (`{}`): {err}",
                verified.identity.pid, verified.exe_path
            ));
        }

        // Give Windows asynchronous kernel rundown a brief bounded window to finish signaling the
        // process object before callers inspect liveness or reap children.
        let _ = is_process_handle_exited(handle.as_raw(), has_synchronize, PROCESS_EXIT_WAIT_MS);
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

    fn take_recorded_children(
        &self,
        target: &ProcessIdentity,
        validated_identity: Option<&ProcessIdentity>,
    ) -> Vec<ProcessIdentity> {
        let mut map = self
            .suspended_children
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut kids = if let Some(valid) = validated_identity {
            let mut drained = map.remove(valid).unwrap_or_default();
            if target != valid {
                let extra = map.remove(target).unwrap_or_default();
                for kid in extra {
                    if !drained.contains(&kid) {
                        drained.push(kid);
                    }
                }
            }
            drained
        } else {
            map.remove(target).unwrap_or_default()
        };
        kids.retain(|k| k.create_time_100ns != 0);
        kids
    }

    fn resume_descendants(&self, root_pid: u32, descendants: Vec<ProcessIdentity>) {
        for child in descendants.into_iter().rev() {
            if let Err(err) = self.resume_single_validated(&child) {
                tracing::debug!(
                    root_pid,
                    child_pid = child.pid,
                    error = %err,
                    "skipping descendant during tree resume"
                );
            }
        }
    }

    fn terminate_descendants(&self, root_pid: u32, descendants: Vec<ProcessIdentity>) {
        for child in descendants.into_iter().rev() {
            if let Err(err) = self.terminate_single_validated(&child) {
                tracing::debug!(
                    root_pid,
                    child_pid = child.pid,
                    error = %err,
                    "skipping descendant during tree terminate"
                );
            }
        }
    }
}

fn confirm_validated_identity_exited(identity: &ProcessIdentity) -> bool {
    if identity.create_time_100ns == 0 {
        return false;
    }
    let (probe, has_synchronize) = match open_process_checked_detailed(
        identity.pid,
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    ) {
        Ok(h) => (h, true),
        Err(_) => match open_process_checked_detailed(
            identity.pid,
            PROCESS_QUERY_LIMITED_INFORMATION,
        ) {
            Ok(h) => (h, false),
            Err(_) => return false,
        },
    };
    if query_process_creation_time(probe.as_raw()) != Some(identity.create_time_100ns) {
        return false;
    }
    if query_full_image_name(probe.as_raw()).is_some_and(|exe| is_never_suspend_process(&exe)) {
        return false;
    }
    is_process_handle_exited(probe.as_raw(), has_synchronize, PROCESS_EXIT_WAIT_MS)
}

fn collect_deduplicated_descendants(
    root_identity: Option<&ProcessIdentity>,
    target: &ProcessIdentity,
    include_live: bool,
    recorded_children: Vec<ProcessIdentity>,
) -> Vec<ProcessIdentity> {
    let mut merged = Vec::new();
    let mut seen = HashSet::new();
    if include_live {
        let live_root = root_identity.unwrap_or(target);
        for child in collect_validated_descendants(live_root) {
            if seen.insert(child) {
                merged.push(child);
            }
        }
    }
    for child in recorded_children {
        if seen.insert(child) {
            merged.push(child);
        }
    }
    merged
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
        match validate_and_inspect_target_detailed(target) {
            Ok(root) => {
                let recorded_children = self.take_recorded_children(target, Some(&root.identity));
                let descendants = collect_deduplicated_descendants(
                    Some(&root.identity),
                    target,
                    true,
                    recorded_children,
                );
                self.resume_descendants(root.identity.pid, descendants);
                self.resume_single_validated(&root.identity).map(|_| ())
            }
            Err(TargetValidationError::PolicyRejected(err)) => Err(err),
            Err(TargetValidationError::IdentityMismatch(err)) => {
                let recorded_children = self.take_recorded_children(target, None);
                self.resume_descendants(target.pid, recorded_children);
                Err(err)
            }
            Err(TargetValidationError::Unavailable(err)) => {
                let recorded_children = self.take_recorded_children(target, None);
                let descendants =
                    collect_deduplicated_descendants(None, target, true, recorded_children);
                self.resume_descendants(target.pid, descendants);
                Err(err)
            }
        }
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        match validate_and_inspect_target_detailed(target) {
            Ok(root) => {
                let recorded_children = self.take_recorded_children(target, Some(&root.identity));
                let descendants = if include_children {
                    collect_deduplicated_descendants(
                        Some(&root.identity),
                        target,
                        true,
                        recorded_children,
                    )
                } else {
                    Vec::new()
                };

                // Terminate the root first so it cannot respawn children or exit on child death
                // before `TerminateProcess` runs on it, then terminate every collected descendant.
                let root_term_res = self.terminate_single_validated(&root.identity);
                if include_children {
                    self.terminate_descendants(root.identity.pid, descendants);
                }
                root_term_res
            }
            Err(TargetValidationError::PolicyRejected(err)) => Err(err),
            Err(TargetValidationError::IdentityMismatch(err)) => {
                if include_children {
                    let recorded_children = self.take_recorded_children(target, None);
                    self.terminate_descendants(target.pid, recorded_children);
                }
                Err(err)
            }
            Err(TargetValidationError::Unavailable(err)) => {
                if include_children {
                    let recorded_children = self.take_recorded_children(target, None);
                    let descendants =
                        collect_deduplicated_descendants(None, target, true, recorded_children);
                    self.terminate_descendants(target.pid, descendants);
                }
                Err(err)
            }
        }
    }

    fn add_wfp_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        validate_wfp_rule_request(exe_path, allow)?;
        let mut slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let engine = ensure_wfp_engine_locked(&mut slot, &self.wfp_drop_sink)?;
        engine.add_app_rule(exe_path, remote_ip, allow)
    }

    fn add_wfp_scoped_app_rule(
        &self,
        exe_path: &Path,
        package_sid: Option<&str>,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        let Some(sid) = package_sid else {
            return self.add_wfp_app_rule(exe_path, remote_ip, allow);
        };
        validate_wfp_rule_request(exe_path, allow)?;
        let validated_sid = validate_wfp_package_sid(sid)?;
        let mut slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let engine = ensure_wfp_engine_locked(&mut slot, &self.wfp_drop_sink)?;
        engine.add_scoped_app_rule(exe_path, Some(&validated_sid), remote_ip, allow)
    }

    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
        let slot = self
            .wfp_engine
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let engine = slot
            .as_ref()
            .ok_or_else(|| "WFP dynamic session is not initialized".to_string())?;
        engine.remove_rule(filter_id)
    }
}
