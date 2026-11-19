//! Validated descendant process-tree discovery and PID-reuse timestamp guards (`L-07`).

use std::collections::{HashMap, HashSet, VecDeque};

use ledr_proto::{ProcessIdentity, is_never_suspend_process};
use windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

use super::guard::validate_open_handle;
use super::process_probe::{
    SnapshotEntry, find_process_exe_toolhelp32, open_process_checked, query_full_image_name,
    query_process_creation_time, snapshot_process_entries,
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
    if root.create_time_100ns == 0
        || root.pid == 0
        || root.pid == 4
        || root.pid == std::process::id()
    {
        return Vec::new();
    }

    let mut recycled_cutoff_100ns = None;
    if let Ok(root_handle) = open_process_checked(root.pid, PROCESS_QUERY_LIMITED_INFORMATION) {
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
    } else if let Some(exe) = find_process_exe_toolhelp32(root.pid) {
        if is_never_suspend_process(&exe) {
            return Vec::new();
        }
    }

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

pub(super) fn is_valid_descendant_timestamp(parent_create_time_100ns: u64, child_create_time_100ns: u64) -> bool {
    parent_create_time_100ns != 0
        && child_create_time_100ns != 0
        && child_create_time_100ns >= parent_create_time_100ns
}
