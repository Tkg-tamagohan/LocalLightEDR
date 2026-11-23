//! Validated descendant process-tree discovery and PID-reuse timestamp guards (`L-07`).

use std::collections::{HashMap, HashSet, VecDeque};

use ledr_proto::{ProcessIdentity, is_never_suspend_process};
use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use super::guard::{TargetValidationError, validate_open_handle_detailed};
use super::process_probe::{
    OpenProcessError, SnapshotEntry, find_process_exe_toolhelp32,
    open_process_checked_detailed, query_full_image_name, query_process_creation_time,
    snapshot_process_entries,
};

/// Collects all currently live, validated descendant identities of `target`.
///
/// Returns an empty vector when `target.create_time_100ns == 0` (unverified identity) or when
/// `target` refers to a forbidden/protected root process.
pub fn collect_live_descendants(target: &ProcessIdentity) -> Vec<ProcessIdentity> {
    if target.create_time_100ns == 0 {
        return Vec::new();
    }
    collect_validated_descendants(target)
}

pub(super) fn collect_validated_descendants(root: &ProcessIdentity) -> Vec<ProcessIdentity> {
    let self_pid = std::process::id();
    let canonical_root = root.pid & !3;
    if root.create_time_100ns == 0
        || canonical_root == 0
        || canonical_root == 4
        || canonical_root == (self_pid & !3)
    {
        return Vec::new();
    }

    let mut recycled_cutoff_100ns = None;
    match open_process_checked_detailed(root.pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(root_handle) => {
            let actual_ct = query_process_creation_time(root_handle.as_raw());
            if actual_ct == Some(root.create_time_100ns) {
                if let Some(exe) = query_full_image_name(root_handle.as_raw())
                    .or_else(|| find_process_exe_toolhelp32(root.pid))
                {
                    if is_never_suspend_process(&exe) {
                        return Vec::new();
                    }
                }
            } else if let Some(ct) = actual_ct {
                // `root.pid` currently belongs to a different process instance; skip any child created
                // at or after its creation timestamp.
                recycled_cutoff_100ns = Some(ct);
            }
        }
        Err(OpenProcessError::PidZero | OpenProcessError::PidMismatch { .. }) => {
            return Vec::new();
        }
        Err(OpenProcessError::Failed(_)) => {
            let fallback_exe = find_process_exe_toolhelp32(root.pid).or_else(|| {
                (root.pid & 3 != 0)
                    .then(|| find_process_exe_toolhelp32(canonical_root))
                    .flatten()
            });
            if let Some(exe) = fallback_exe {
                if is_never_suspend_process(&exe) {
                    return Vec::new();
                }
            }
        }
    }

    let Ok(entries) = snapshot_process_entries() else {
        return Vec::new();
    };

    collect_validated_descendants_from_snapshot(root, recycled_cutoff_100ns, entries)
}

pub(super) fn resolve_recycled_cutoff_from_entries(
    root: &ProcessIdentity,
    initial_cutoff_100ns: Option<u64>,
    entries: &[SnapshotEntry],
) -> Option<u64> {
    if initial_cutoff_100ns.is_some() {
        return initial_cutoff_100ns;
    }
    entries
        .iter()
        .find(|e| e.pid == root.pid)
        .and_then(|root_entry| root_entry.create_time_100ns)
        .filter(|&snap_ct| snap_ct > root.create_time_100ns)
}

pub(super) fn collect_validated_descendants_from_snapshot(
    root: &ProcessIdentity,
    initial_cutoff_100ns: Option<u64>,
    entries: Vec<SnapshotEntry>,
) -> Vec<ProcessIdentity> {
    let resolved_cutoff = resolve_recycled_cutoff_from_entries(root, initial_cutoff_100ns, &entries);
    collect_validated_descendants_from_entries(root, resolved_cutoff, entries)
}

pub(super) fn collect_validated_descendants_from_entries(
    root: &ProcessIdentity,
    recycled_cutoff_100ns: Option<u64>,
    entries: Vec<SnapshotEntry>,
) -> Vec<ProcessIdentity> {
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

            let child_handle = match open_process_checked_detailed(
                child_entry.pid,
                PROCESS_QUERY_LIMITED_INFORMATION,
            ) {
                Ok(handle) => handle,
                Err(OpenProcessError::PidZero | OpenProcessError::PidMismatch { .. }) => {
                    continue;
                }
                Err(OpenProcessError::Failed(open_err)) => {
                    if is_never_suspend_process(&child_entry.exe_name) {
                        tracing::warn!(
                            parent_pid = parent.pid,
                            child_pid = child_entry.pid,
                            exe = %child_entry.exe_name,
                            error = %open_err,
                            "skipping protected descendant process after OpenProcess failure"
                        );
                        continue;
                    }
                    if is_error_invalid_parameter(&open_err) {
                        let Some(child_ct) = child_entry.create_time_100ns else {
                            tracing::warn!(
                                parent_pid = parent.pid,
                                child_pid = child_entry.pid,
                                exe = %child_entry.exe_name,
                                "intermediate child exited before handle open without verified snapshot creation time; refusing traversal fail-closed"
                            );
                            continue;
                        };
                        if parent.pid == root.pid {
                            if let Some(cutoff) = recycled_cutoff_100ns {
                                if child_ct >= cutoff {
                                    tracing::debug!(
                                        parent_pid = parent.pid,
                                        child_pid = child_entry.pid,
                                        child_create_time_100ns = child_ct,
                                        recycled_cutoff_100ns = cutoff,
                                        "skipping exited intermediate child created at or after recycled root cutoff"
                                    );
                                    continue;
                                }
                            }
                        }
                        if !is_valid_descendant_timestamp(parent.create_time_100ns, child_ct) {
                            tracing::debug!(
                                parent_pid = parent.pid,
                                parent_create_time_100ns = parent.create_time_100ns,
                                child_pid = child_entry.pid,
                                child_create_time_100ns = child_ct,
                                "skipping exited intermediate child created before parent (PID reuse guard)"
                            );
                            continue;
                        }
                        tracing::debug!(
                            parent_pid = parent.pid,
                            child_pid = child_entry.pid,
                            child_create_time_100ns = child_ct,
                            exe = %child_entry.exe_name,
                            "intermediate child exited before handle open; continuing grandchild traversal with verified snapshot creation time"
                        );
                        queue.push_back(ProcessIdentity::new(child_entry.pid, child_ct));
                    } else {
                        tracing::warn!(
                            parent_pid = parent.pid,
                            child_pid = child_entry.pid,
                            exe = %child_entry.exe_name,
                            error = %open_err,
                            "skipping descendant process after OpenProcess failure"
                        );
                    }
                    continue;
                }
            };

            let Some(child_create_time) = query_process_creation_time(child_handle.as_raw()) else {
                continue;
            };
            if let Some(snap_ct) = child_entry.create_time_100ns {
                if snap_ct != child_create_time {
                    tracing::debug!(
                        parent_pid = parent.pid,
                        child_pid = child_entry.pid,
                        snapshot_create_time_100ns = snap_ct,
                        handle_create_time_100ns = child_create_time,
                        "skipping descendant whose PID was recycled between snapshot and OpenProcess"
                    );
                    continue;
                }
            }

            if parent.pid == root.pid {
                if let Some(cutoff) = recycled_cutoff_100ns {
                    if child_create_time >= cutoff {
                        continue;
                    }
                }
            }

            // Guard against recycled parent PIDs: a true descendant must be created at or after
            // its parent's creation timestamp.
            if !is_valid_descendant_timestamp(parent.create_time_100ns, child_create_time) {
                continue;
            }

            let candidate = ProcessIdentity::new(child_entry.pid, child_create_time);
            match validate_open_handle_detailed(child_handle.as_raw(), &candidate) {
                Ok(validated) => {
                    descendants.push(validated.identity);
                    queue.push_back(validated.identity);
                }
                Err(TargetValidationError::PolicyRejected(err)) => {
                    tracing::warn!(
                        parent_pid = parent.pid,
                        child_pid = child_entry.pid,
                        exe = %child_entry.exe_name,
                        error = %err,
                        "skipping policy-rejected descendant process"
                    );
                }
                Err(TargetValidationError::Unavailable(err)) => {
                    tracing::warn!(
                        parent_pid = parent.pid,
                        child_pid = child_entry.pid,
                        exe = %child_entry.exe_name,
                        error = %err,
                        "skipping descendant process fail-closed: full image path unavailable"
                    );
                }
                Err(TargetValidationError::IdentityMismatch(err)) => {
                    tracing::debug!(
                        parent_pid = parent.pid,
                        child_pid = child_entry.pid,
                        error = %err,
                        "descendant rejected due to identity mismatch"
                    );
                }
            }
        }
    }

    descendants
}

fn is_error_invalid_parameter(open_err: &str) -> bool {
    let invalid_param_hex = format!("0x{:08x}", ERROR_INVALID_PARAMETER.to_hresult().0 as u32);
    open_err.to_ascii_lowercase().contains(&invalid_param_hex)
}

pub(super) fn is_valid_descendant_timestamp(parent_create_time_100ns: u64, child_create_time_100ns: u64) -> bool {
    parent_create_time_100ns != 0
        && child_create_time_100ns != 0
        && child_create_time_100ns >= parent_create_time_100ns
}
