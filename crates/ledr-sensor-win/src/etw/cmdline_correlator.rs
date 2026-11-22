//! Bounded bidirectional correlator between `SystemTrace` (`Process_V4_TypeGroup1`)
//! kernel command lines and `Microsoft-Windows-Kernel-Process` Event 1 (`ProcessStart`).

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

pub(super) const MAX_CACHED_SYSTEM_CMDLINES: usize = 2048;
pub(super) const MAX_CACHED_SYSTEM_CMDLINE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_PENDING_KERNEL_STARTS: usize = 1024;
pub(super) const MAX_ENTRIES_PER_PID: usize = 16;
pub(super) const MAX_CMDLINE_UTF8_BYTES: usize = 32_768;
pub(super) const ENTRY_TTL_MS: u64 = 15_000;
pub(super) const MATCH_MAX_BEFORE_100NS: u64 = 500 * 10_000;
pub(super) const MATCH_MAX_AFTER_100NS: u64 = 5_000 * 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SystemProcessCommandLine {
    pub pid: u32,
    pub parent_pid: u32,
    pub event_ts_100ns: u64,
    pub image_short_name: String,
    pub command_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingKernelStart {
    pub pid: u32,
    pub create_time_100ns: u64,
    pub parent_pid: u32,
    pub exe_path: String,
    pub user_sid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MatchedCommandLine {
    pub command_line: String,
    pub delta_100ns: i128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TakeOrRegisterOutcome {
    Matched {
        pending: PendingKernelStart,
        matched: MatchedCommandLine,
    },
    Registered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedPendingStart {
    pub pending: PendingKernelStart,
    pub command_line: String,
    pub delta_100ns: i128,
}

#[derive(Debug, Clone)]
struct CachedSysEntry {
    seq: u64,
    inserted_at_ms: u64,
    pid: u32,
    parent_pid: u32,
    event_ts_100ns: u64,
    image_short_name_lower: String,
    command_line: String,
}

#[derive(Debug, Clone)]
struct PendingStartEntry {
    seq: u64,
    inserted_at_ms: u64,
    pending: PendingKernelStart,
    exe_basename_lower: String,
}

/// Bounded in-memory bidirectional correlator pairing `Process_V4_TypeGroup1` kernel
/// command-line events with `Microsoft-Windows-Kernel-Process` `ProcessStart` events.
#[derive(Debug)]
pub(super) struct ProcessCommandLineCorrelator {
    origin: Instant,
    next_seq: u64,
    sys_by_pid: HashMap<u32, VecDeque<CachedSysEntry>>,
    sys_fifo: VecDeque<(u64, u32)>,
    sys_active_count: usize,
    sys_active_bytes: usize,
    pending_by_pid: HashMap<u32, VecDeque<PendingStartEntry>>,
    pending_fifo: VecDeque<(u64, u32)>,
    pending_active_count: usize,
}

impl Default for ProcessCommandLineCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCommandLineCorrelator {
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
            next_seq: 1,
            sys_by_pid: HashMap::new(),
            sys_fifo: VecDeque::new(),
            sys_active_count: 0,
            sys_active_bytes: 0,
            pending_by_pid: HashMap::new(),
            pending_fifo: VecDeque::new(),
            pending_active_count: 0,
        }
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    #[cfg(test)]
    pub(super) fn cached_sys_len(&self) -> usize {
        self.sys_active_count
    }

    #[cfg(test)]
    pub(super) fn cached_sys_bytes(&self) -> usize {
        self.sys_active_bytes
    }

    #[cfg(test)]
    pub(super) fn pending_starts_len(&self) -> usize {
        self.pending_active_count
    }

    #[cfg(test)]
    pub(super) fn sys_fifo_len(&self) -> usize {
        self.sys_fifo.len()
    }

    #[cfg(test)]
    pub(super) fn pending_fifo_len(&self) -> usize {
        self.pending_fifo.len()
    }

    /// Queries cached `SystemTrace` entries for a matching command line and consumes it on hit.
    pub(super) fn take_matching_command_line(
        &mut self,
        pid: u32,
        parent_pid: u32,
        create_time_100ns: u64,
        exe_path: &str,
    ) -> Option<MatchedCommandLine> {
        let now_ms = self.now_ms();
        self.take_matching_command_line_at(pid, parent_pid, create_time_100ns, exe_path, now_ms)
    }

    pub(super) fn take_matching_command_line_at(
        &mut self,
        pid: u32,
        parent_pid: u32,
        create_time_100ns: u64,
        exe_path: &str,
        now_ms: u64,
    ) -> Option<MatchedCommandLine> {
        self.prune_expired_at(now_ms);
        if pid == 0 || create_time_100ns == 0 {
            return None;
        }
        let kp_basename_lower = extract_exe_basename_lower(exe_path);
        let bucket = self.sys_by_pid.get_mut(&pid)?;

        let mut best: Option<(usize, u64)> = None;
        for (idx, entry) in bucket.iter().enumerate() {
            if let Some(abs_diff) = matches_incarnation(
                entry.pid,
                entry.parent_pid,
                entry.event_ts_100ns,
                &entry.image_short_name_lower,
                pid,
                parent_pid,
                create_time_100ns,
                &kp_basename_lower,
            ) {
                let replace = match best {
                    None => true,
                    Some((_, best_diff)) => abs_diff < best_diff,
                };
                if replace {
                    best = Some((idx, abs_diff));
                }
            }
        }

        let (best_idx, _) = best?;
        let removed = bucket.remove(best_idx)?;
        if bucket.is_empty() {
            self.sys_by_pid.remove(&pid);
        }
        self.sys_active_count = self.sys_active_count.saturating_sub(1);
        self.sys_active_bytes = self.sys_active_bytes.saturating_sub(removed.command_line.len());

        let delta_100ns = removed.event_ts_100ns as i128 - create_time_100ns as i128;
        Some(MatchedCommandLine {
            command_line: removed.command_line,
            delta_100ns,
        })
    }

    /// Atomically checks `SystemTrace` cache first; only registers `PendingKernelStart` on miss.
    pub(super) fn take_or_register_pending_start(
        &mut self,
        pending: PendingKernelStart,
    ) -> TakeOrRegisterOutcome {
        let now_ms = self.now_ms();
        self.take_or_register_pending_start_at(pending, now_ms)
    }

    pub(super) fn take_or_register_pending_start_at(
        &mut self,
        pending: PendingKernelStart,
        now_ms: u64,
    ) -> TakeOrRegisterOutcome {
        if let Some(matched) = self.take_matching_command_line_at(
            pending.pid,
            pending.parent_pid,
            pending.create_time_100ns,
            &pending.exe_path,
            now_ms,
        ) {
            return TakeOrRegisterOutcome::Matched { pending, matched };
        }

        if pending.pid == 0 || pending.create_time_100ns == 0 {
            return TakeOrRegisterOutcome::Registered;
        }

        self.insert_pending_start_at(pending, now_ms);
        TakeOrRegisterOutcome::Registered
    }

    /// Records an incoming `SystemTrace` command line or resolves a waiting `PendingKernelStart`.
    pub(super) fn on_system_process_start(
        &mut self,
        sys: SystemProcessCommandLine,
    ) -> Option<ResolvedPendingStart> {
        let now_ms = self.now_ms();
        self.on_system_process_start_at(sys, now_ms)
    }

    pub(super) fn on_system_process_start_at(
        &mut self,
        sys: SystemProcessCommandLine,
        now_ms: u64,
    ) -> Option<ResolvedPendingStart> {
        self.prune_expired_at(now_ms);
        if sys.pid == 0 || sys.event_ts_100ns == 0 {
            return None;
        }
        let command_line = sanitize_and_truncate_cmdline(&sys.command_line)?;
        let sys_short_lower = extract_exe_basename_lower(&sys.image_short_name);

        if let Some(bucket) = self.pending_by_pid.get_mut(&sys.pid) {
            let mut best: Option<(usize, u64)> = None;
            for (idx, entry) in bucket.iter().enumerate() {
                if let Some(abs_diff) = matches_incarnation(
                    sys.pid,
                    sys.parent_pid,
                    sys.event_ts_100ns,
                    &sys_short_lower,
                    entry.pending.pid,
                    entry.pending.parent_pid,
                    entry.pending.create_time_100ns,
                    &entry.exe_basename_lower,
                ) {
                    let replace = match best {
                        None => true,
                        Some((_, best_diff)) => abs_diff < best_diff,
                    };
                    if replace {
                        best = Some((idx, abs_diff));
                    }
                }
            }

            if let Some((best_idx, _)) = best {
                let removed = bucket.remove(best_idx)?;
                if bucket.is_empty() {
                    self.pending_by_pid.remove(&sys.pid);
                }
                self.pending_active_count = self.pending_active_count.saturating_sub(1);
                let delta_100ns =
                    sys.event_ts_100ns as i128 - removed.pending.create_time_100ns as i128;
                return Some(ResolvedPendingStart {
                    pending: removed.pending,
                    command_line,
                    delta_100ns,
                });
            }
        }

        self.insert_sys_cmdline_at(
            sys.pid,
            sys.parent_pid,
            sys.event_ts_100ns,
            sys_short_lower,
            command_line,
            now_ms,
        );
        None
    }

    fn insert_sys_cmdline_at(
        &mut self,
        pid: u32,
        parent_pid: u32,
        event_ts_100ns: u64,
        image_short_name_lower: String,
        command_line: String,
        now_ms: u64,
    ) {
        let new_bytes = command_line.len();
        if new_bytes > MAX_CACHED_SYSTEM_CMDLINE_BYTES {
            return;
        }

        if let Some(bucket) = self.sys_by_pid.get_mut(&pid) {
            while bucket.len() >= MAX_ENTRIES_PER_PID {
                if let Some(evicted) = bucket.pop_front() {
                    self.sys_active_count = self.sys_active_count.saturating_sub(1);
                    self.sys_active_bytes =
                        self.sys_active_bytes.saturating_sub(evicted.command_line.len());
                } else {
                    break;
                }
            }
        }

        while self.sys_active_count >= MAX_CACHED_SYSTEM_CMDLINES
            || self.sys_active_bytes.saturating_add(new_bytes) > MAX_CACHED_SYSTEM_CMDLINE_BYTES
        {
            if !self.evict_oldest_sys() {
                break;
            }
        }

        let seq = self.alloc_seq();
        self.sys_by_pid.entry(pid).or_default().push_back(CachedSysEntry {
            seq,
            inserted_at_ms: now_ms,
            pid,
            parent_pid,
            event_ts_100ns,
            image_short_name_lower,
            command_line,
        });
        self.sys_fifo.push_back((seq, pid));
        self.sys_active_count += 1;
        self.sys_active_bytes += new_bytes;

        if self.sys_fifo.len() > MAX_CACHED_SYSTEM_CMDLINES.saturating_mul(4) {
            let by_pid = &self.sys_by_pid;
            self.sys_fifo.retain(|(s, p)| {
                by_pid
                    .get(p)
                    .is_some_and(|deque| deque.iter().any(|e| e.seq == *s))
            });
        }
    }

    fn insert_pending_start_at(&mut self, pending: PendingKernelStart, now_ms: u64) {
        let pid = pending.pid;
        let exe_basename_lower = extract_exe_basename_lower(&pending.exe_path);

        if let Some(bucket) = self.pending_by_pid.get_mut(&pid) {
            while bucket.len() >= MAX_ENTRIES_PER_PID {
                if bucket.pop_front().is_some() {
                    self.pending_active_count = self.pending_active_count.saturating_sub(1);
                } else {
                    break;
                }
            }
        }

        while self.pending_active_count >= MAX_PENDING_KERNEL_STARTS {
            if !self.evict_oldest_pending() {
                break;
            }
        }

        let seq = self.alloc_seq();
        self.pending_by_pid
            .entry(pid)
            .or_default()
            .push_back(PendingStartEntry {
                seq,
                inserted_at_ms: now_ms,
                pending,
                exe_basename_lower,
            });
        self.pending_fifo.push_back((seq, pid));
        self.pending_active_count += 1;

        if self.pending_fifo.len() > MAX_PENDING_KERNEL_STARTS.saturating_mul(4) {
            let by_pid = &self.pending_by_pid;
            self.pending_fifo.retain(|(s, p)| {
                by_pid
                    .get(p)
                    .is_some_and(|deque| deque.iter().any(|e| e.seq == *s))
            });
        }
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        seq
    }

    fn evict_oldest_sys(&mut self) -> bool {
        while let Some((seq, pid)) = self.sys_fifo.pop_front() {
            let mut empty = false;
            if let Some(bucket) = self.sys_by_pid.get_mut(&pid) {
                if let Some(pos) = bucket.iter().position(|e| e.seq == seq) {
                    if let Some(removed) = bucket.remove(pos) {
                        self.sys_active_count = self.sys_active_count.saturating_sub(1);
                        self.sys_active_bytes =
                            self.sys_active_bytes.saturating_sub(removed.command_line.len());
                    }
                    empty = bucket.is_empty();
                    if empty {
                        self.sys_by_pid.remove(&pid);
                    }
                    return true;
                }
                empty = bucket.is_empty();
            }
            if empty {
                self.sys_by_pid.remove(&pid);
            }
        }
        false
    }

    fn evict_oldest_pending(&mut self) -> bool {
        while let Some((seq, pid)) = self.pending_fifo.pop_front() {
            let mut empty = false;
            if let Some(bucket) = self.pending_by_pid.get_mut(&pid) {
                if let Some(pos) = bucket.iter().position(|e| e.seq == seq) {
                    let _ = bucket.remove(pos);
                    self.pending_active_count = self.pending_active_count.saturating_sub(1);
                    empty = bucket.is_empty();
                    if empty {
                        self.pending_by_pid.remove(&pid);
                    }
                    return true;
                }
                empty = bucket.is_empty();
            }
            if empty {
                self.pending_by_pid.remove(&pid);
            }
        }
        false
    }

    fn prune_expired_at(&mut self, now_ms: u64) {
        while let Some(&(seq, pid)) = self.sys_fifo.front() {
            let status = match self.sys_by_pid.get(&pid) {
                None => FrontStatus::Tombstone,
                Some(bucket) => match bucket.iter().position(|e| e.seq == seq) {
                    None => FrontStatus::Tombstone,
                    Some(pos) => {
                        if now_ms.saturating_sub(bucket[pos].inserted_at_ms) > ENTRY_TTL_MS {
                            FrontStatus::Expired(pos)
                        } else {
                            FrontStatus::Live
                        }
                    }
                },
            };
            match status {
                FrontStatus::Tombstone => {
                    self.sys_fifo.pop_front();
                }
                FrontStatus::Expired(pos) => {
                    self.sys_fifo.pop_front();
                    if let Some(bucket) = self.sys_by_pid.get_mut(&pid) {
                        if let Some(removed) = bucket.remove(pos) {
                            self.sys_active_count = self.sys_active_count.saturating_sub(1);
                            self.sys_active_bytes =
                                self.sys_active_bytes.saturating_sub(removed.command_line.len());
                        }
                        if bucket.is_empty() {
                            self.sys_by_pid.remove(&pid);
                        }
                    }
                }
                FrontStatus::Live => break,
            }
        }

        while let Some(&(seq, pid)) = self.pending_fifo.front() {
            let status = match self.pending_by_pid.get(&pid) {
                None => FrontStatus::Tombstone,
                Some(bucket) => match bucket.iter().position(|e| e.seq == seq) {
                    None => FrontStatus::Tombstone,
                    Some(pos) => {
                        if now_ms.saturating_sub(bucket[pos].inserted_at_ms) > ENTRY_TTL_MS {
                            FrontStatus::Expired(pos)
                        } else {
                            FrontStatus::Live
                        }
                    }
                },
            };
            match status {
                FrontStatus::Tombstone => {
                    self.pending_fifo.pop_front();
                }
                FrontStatus::Expired(pos) => {
                    self.pending_fifo.pop_front();
                    if let Some(bucket) = self.pending_by_pid.get_mut(&pid) {
                        let _ = bucket.remove(pos);
                        self.pending_active_count = self.pending_active_count.saturating_sub(1);
                        if bucket.is_empty() {
                            self.pending_by_pid.remove(&pid);
                        }
                    }
                }
                FrontStatus::Live => break,
            }
        }
    }
}

enum FrontStatus {
    Tombstone,
    Expired(usize),
    Live,
}

pub(super) fn sanitize_and_truncate_cmdline(raw: &str) -> Option<String> {
    if raw.trim().is_empty() {
        return None;
    }
    if raw.len() <= MAX_CMDLINE_UTF8_BYTES {
        return Some(raw.to_owned());
    }
    let mut end = MAX_CMDLINE_UTF8_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    let truncated = &raw[..end];
    if truncated.trim().is_empty() {
        None
    } else {
        Some(truncated.to_owned())
    }
}

pub(super) fn extract_exe_basename_lower(exe_path: &str) -> String {
    exe_path
        .rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or("")
        .to_ascii_lowercase()
}

#[allow(clippy::too_many_arguments)]
fn matches_incarnation(
    sys_pid: u32,
    sys_parent_pid: u32,
    sys_event_ts_100ns: u64,
    sys_short_lower: &str,
    kp_pid: u32,
    kp_parent_pid: u32,
    kp_create_time_100ns: u64,
    kp_basename_lower: &str,
) -> Option<u64> {
    if sys_pid == 0 || sys_pid != kp_pid {
        return None;
    }
    if kp_create_time_100ns == 0 || sys_event_ts_100ns == 0 {
        return None;
    }
    let min_ts = kp_create_time_100ns.saturating_sub(MATCH_MAX_BEFORE_100NS);
    let max_ts = kp_create_time_100ns.saturating_add(MATCH_MAX_AFTER_100NS);
    if sys_event_ts_100ns < min_ts || sys_event_ts_100ns > max_ts {
        return None;
    }
    if sys_parent_pid != 0 && kp_parent_pid != 0 && sys_parent_pid != kp_parent_pid {
        return None;
    }
    let parent_pid_known_match =
        sys_parent_pid != 0 && kp_parent_pid != 0 && sys_parent_pid == kp_parent_pid;
    if !image_names_compatible(sys_short_lower, kp_basename_lower, parent_pid_known_match) {
        return None;
    }
    Some(sys_event_ts_100ns.abs_diff(kp_create_time_100ns))
}

fn image_names_compatible(
    sys_short_lower: &str,
    kp_basename_lower: &str,
    parent_pid_known_match: bool,
) -> bool {
    if sys_short_lower.is_empty() || kp_basename_lower.is_empty() {
        return parent_pid_known_match;
    }
    if !kp_basename_lower.is_ascii() {
        return true;
    }
    if sys_short_lower.len() >= 14 {
        kp_basename_lower.starts_with(sys_short_lower)
    } else {
        kp_basename_lower == sys_short_lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys_cmd(
        pid: u32,
        ppid: u32,
        ts: u64,
        img: &str,
        cmd: &str,
    ) -> SystemProcessCommandLine {
        SystemProcessCommandLine {
            pid,
            parent_pid: ppid,
            event_ts_100ns: ts,
            image_short_name: img.to_string(),
            command_line: cmd.to_string(),
        }
    }

    fn kp_pending(pid: u32, ppid: u32, create_ts: u64, exe: &str) -> PendingKernelStart {
        PendingKernelStart {
            pid,
            create_time_100ns: create_ts,
            parent_pid: ppid,
            exe_path: exe.to_string(),
            user_sid: None,
        }
    }

    /// `ETW-P4-CMD-04`: PID reuse rejection — mismatched parent_pid, outside closed interval
    /// `[-500ms, +5000ms]`, `< 14`-byte prefix mismatch (`cmd` vs `cmd_tool.exe`), empty
    /// filename with `parent_pid == 0`, and minimum `abs_diff` selection among multiple hits.
    #[test]
    fn etw_p4_cmd_04_pid_reuse_rejection_and_best_timestamp_selection() {
        let mut corr = ProcessCommandLineCorrelator::new();
        let base_ts: u64 = 133_800_000_000_000_000;

        // Mismatched parent_pid must reject.
        assert!(corr
            .on_system_process_start_at(sys_cmd(4242, 9999, base_ts, "cmd.exe", "cmd.exe /c a"), 0)
            .is_none());
        assert!(corr
            .take_matching_command_line_at(4242, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 0)
            .is_none());

        // Outside [-500ms, +5000ms] rejected; boundaries -500ms and +5000ms accepted.
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(
                    4242,
                    1200,
                    base_ts - MATCH_MAX_BEFORE_100NS - 1,
                    "cmd.exe",
                    "too-early"
                ),
                0
            )
            .is_none());
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(
                    4242,
                    1200,
                    base_ts + MATCH_MAX_AFTER_100NS + 1,
                    "cmd.exe",
                    "too-late"
                ),
                0
            )
            .is_none());
        assert!(corr
            .take_matching_command_line_at(4242, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 0)
            .is_none());

        assert!(corr
            .on_system_process_start_at(
                sys_cmd(4243, 1200, base_ts - MATCH_MAX_BEFORE_100NS, "cmd.exe", "exact-before"),
                0
            )
            .is_none());
        let before_hit = corr
            .take_matching_command_line_at(4243, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 0)
            .expect("-500ms closed boundary must match");
        assert_eq!(before_hit.command_line, "exact-before");

        assert!(corr
            .on_system_process_start_at(
                sys_cmd(4244, 1200, base_ts + MATCH_MAX_AFTER_100NS, "cmd.exe", "exact-after"),
                0
            )
            .is_none());
        let after_hit = corr
            .take_matching_command_line_at(4244, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 0)
            .expect("+5000ms closed boundary must match");
        assert_eq!(after_hit.command_line, "exact-after");

        // < 14 byte prefix mismatch (`cmd` vs `cmd_tool.exe`) must reject.
        assert!(corr
            .on_system_process_start_at(sys_cmd(5000, 1200, base_ts, "cmd", "cmd --short"), 0)
            .is_none());
        assert!(corr
            .take_matching_command_line_at(
                5000,
                1200,
                base_ts,
                r"C:\Tools\cmd_tool.exe",
                0
            )
            .is_none());

        // Empty image name with parent_pid == 0 must reject (cannot fail-open).
        assert!(corr
            .on_system_process_start_at(sys_cmd(5001, 0, base_ts, "", "empty-name"), 0)
            .is_none());
        assert!(corr
            .take_matching_command_line_at(5001, 0, base_ts, r"C:\Tools\app.exe", 0)
            .is_none());

        // Multiple candidates for same PID: selects minimum abs_diff and consumes only that entry.
        corr.on_system_process_start_at(
            sys_cmd(6000, 1200, base_ts + 2_000 * 10_000, "cmd.exe", "far-entry"),
            10,
        );
        corr.on_system_process_start_at(
            sys_cmd(6000, 1200, base_ts + 15 * 10_000, "cmd.exe", "closest-entry"),
            20,
        );
        let picked = corr
            .take_matching_command_line_at(6000, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 30)
            .expect("closest timestamp candidate matches");
        assert_eq!(picked.command_line, "closest-entry");
        let remaining = corr
            .take_matching_command_line_at(6000, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 31)
            .expect("second candidate remains unconsumed");
        assert_eq!(remaining.command_line, "far-entry");

        // `?`-containing OEM lossy SystemTrace name must NOT match pure-ASCII `cmd.exe`.
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(6001, 1200, base_ts + 10_000, "?????.exe", "non-ascii-cmdline"),
                32
            )
            .is_none());
        assert!(corr
            .take_matching_command_line_at(6001, 1200, base_ts, r"C:\Windows\System32\cmd.exe", 33)
            .is_none());

        // Path B (Kernel-Process first, SystemTrace second): rejects mismatch & picks min abs_diff.
        assert_eq!(
            corr.take_or_register_pending_start_at(
                kp_pending(6002, 1200, base_ts, r"C:\Windows\System32\cmd.exe"),
                40
            ),
            TakeOrRegisterOutcome::Registered
        );
        assert_eq!(
            corr.take_or_register_pending_start_at(
                kp_pending(
                    6002,
                    1200,
                    base_ts + 2_000 * 10_000,
                    r"C:\Windows\System32\cmd.exe"
                ),
                41
            ),
            TakeOrRegisterOutcome::Registered
        );
        // Wrong parent_pid rejected on Path B.
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(6002, 9999, base_ts + 1_900 * 10_000, "cmd.exe", "wrong-ppid"),
                42
            )
            .is_none());
        // Closest pending KernelStart (base_ts + 2000ms) selected and consumed.
        let resolved = corr
            .on_system_process_start_at(
                sys_cmd(6002, 1200, base_ts + 1_900 * 10_000, "cmd.exe", "matched-b"),
                43
            )
            .expect("Path B resolves closest PendingKernelStart");
        assert_eq!(resolved.pending.create_time_100ns, base_ts + 2_000 * 10_000);
        assert_eq!(resolved.command_line, "matched-b");
    }

    /// `ETW-P4-CMD-05`: 14–15 byte truncated `EPROCESS.ImageFileName` matches full executable
    /// basename case-insensitively, and non-ASCII basenames fall back to PID/parent/timestamp.
    #[test]
    fn etw_p4_cmd_05_truncated_15_byte_and_non_ascii_image_names() {
        let mut corr = ProcessCommandLineCorrelator::new();
        let base_ts: u64 = 133_800_000_000_000_000;

        // 14-char truncated ImageFileName (`verylongproces`) vs `VeryLongProcessName.exe`
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(7001, 100, base_ts + 50_000, "verylongproces", "verylong --arg"),
                0
            )
            .is_none());
        let long_hit = corr
            .take_matching_command_line_at(
                7001,
                100,
                base_ts,
                r"C:\Tools\VeryLongProcessName.exe",
                0,
            )
            .expect("14-byte truncated ImageFileName must prefix-match");
        assert_eq!(long_hit.command_line, "verylong --arg");

        // 15-char truncated ImageFileName (`ledr_very_long_`) vs `ledr_very_long_probe_binary_name.exe`
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(
                    7002,
                    100,
                    base_ts + 50_000,
                    "ledr_very_long_",
                    "\"C:\\Temp\\ledr_very_long_probe_binary_name.exe\" --ok"
                ),
                0
            )
            .is_none());
        let long_15_hit = corr
            .take_matching_command_line_at(
                7002,
                100,
                base_ts,
                r"C:\Temp\ledr_very_long_probe_binary_name.exe",
                0,
            )
            .expect("15-byte truncated ImageFileName must prefix-match");
        assert!(long_15_hit.command_line.contains("--ok"));

        // Non-ASCII exe basename with OEM `?` lossy conversion in `ImageFileName`
        assert!(corr
            .on_system_process_start_at(
                sys_cmd(7003, 100, base_ts + 10_000, "?????.exe", "テスト実行.exe --run"),
                0
            )
            .is_none());
        let non_ascii_hit = corr
            .take_matching_command_line_at(7003, 100, base_ts, r"C:\Tools\テスト実行.exe", 0)
            .expect("non-ASCII basename should fall back to PID + parent + timestamp");
        assert_eq!(non_ascii_hit.command_line, "テスト実行.exe --run");
    }

    /// `ETW-P4-CMD-06`: Bounded count caps (2048/1024), 4 MiB total byte budget, per-PID cap (16),
    /// 15 s monotonic TTL expiration, tombstone compaction, whitespace discard, and 32 KiB UTF-8
    /// char-boundary truncation.
    #[test]
    fn etw_p4_cmd_06_bounded_caps_ttl_tombstone_compaction_and_utf8_truncation() {
        let mut corr = ProcessCommandLineCorrelator::new();
        let base_ts: u64 = 133_800_000_000_000_000;

        // Whitespace-only command line is ignored.
        assert!(corr
            .on_system_process_start_at(sys_cmd(10, 1, base_ts, "cmd.exe", "   \t\r\n  "), 0)
            .is_none());
        assert_eq!(corr.cached_sys_len(), 0);

        // 32,768-byte UTF-8 char-boundary truncation with multi-byte Japanese characters.
        let mut oversized = "a".repeat(MAX_CMDLINE_UTF8_BYTES - 1);
        oversized.push('あ'); // 3 bytes; crosses 32,768 boundary
        oversized.push_str("tail");
        corr.on_system_process_start_at(sys_cmd(11, 1, base_ts, "cmd.exe", &oversized), 0);
        let trunc_hit = corr
            .take_matching_command_line_at(11, 1, base_ts, r"C:\Windows\System32\cmd.exe", 0)
            .expect("oversized command line should be stored truncated");
        assert_eq!(trunc_hit.command_line.len(), MAX_CMDLINE_UTF8_BYTES - 1);
        assert!(trunc_hit.command_line.chars().all(|c| c == 'a'));

        // Per-PID cap = 16.
        for i in 0..24u32 {
            corr.on_system_process_start_at(
                sys_cmd(100, 1, base_ts + u64::from(i) * 10_000, "cmd.exe", &format!("cmd-{i}")),
                u64::from(i),
            );
        }
        assert_eq!(corr.cached_sys_len(), MAX_ENTRIES_PER_PID);

        // Total byte budget (4 MiB): pushing 160 * 32 KiB (= 5 MiB) across distinct PIDs stays <= 4 MiB.
        let mut corr_bytes = ProcessCommandLineCorrelator::new();
        let big_cmd = "x".repeat(MAX_CMDLINE_UTF8_BYTES);
        for i in 0..160u32 {
            corr_bytes.on_system_process_start_at(
                sys_cmd(1000 + i, 1, base_ts, "cmd.exe", &big_cmd),
                u64::from(i),
            );
        }
        assert_eq!(
            corr_bytes.cached_sys_bytes(),
            MAX_CACHED_SYSTEM_CMDLINE_BYTES
        );
        assert_eq!(
            corr_bytes.cached_sys_len(),
            MAX_CACHED_SYSTEM_CMDLINE_BYTES / MAX_CMDLINE_UTF8_BYTES
        );

        // Count cap (2048) + tombstone compaction.
        let mut corr_count = ProcessCommandLineCorrelator::new();
        for i in 0..(MAX_CACHED_SYSTEM_CMDLINES as u32 + 250) {
            corr_count.on_system_process_start_at(
                sys_cmd(10_000 + i, 1, base_ts, "cmd.exe", "c"),
                1,
            );
        }
        assert_eq!(corr_count.cached_sys_len(), MAX_CACHED_SYSTEM_CMDLINES);

        // Pending count cap (1024).
        for i in 0..(MAX_PENDING_KERNEL_STARTS as u32 + 100) {
            assert_eq!(
                corr_count.take_or_register_pending_start_at(
                    kp_pending(20_000 + i, 1, base_ts, r"C:\Windows\System32\cmd.exe"),
                    1
                ),
                TakeOrRegisterOutcome::Registered
            );
        }
        assert_eq!(corr_count.pending_starts_len(), MAX_PENDING_KERNEL_STARTS);

        // Repeated match-and-consume triggers fifo tombstone compaction on BOTH sys_fifo and pending_fifo.
        for i in 0..(MAX_CACHED_SYSTEM_CMDLINES as u32 * 5) {
            let pid = 50_000 + i;
            corr_count.on_system_process_start_at(sys_cmd(pid, 1, base_ts, "cmd.exe", "k"), 2);
            assert!(corr_count
                .take_matching_command_line_at(pid, 1, base_ts, r"C:\Windows\System32\cmd.exe", 2)
                .is_some());
        }
        for i in 0..(MAX_PENDING_KERNEL_STARTS as u32 * 5) {
            let pid = 80_000 + i;
            assert_eq!(
                corr_count.take_or_register_pending_start_at(
                    kp_pending(pid, 1, base_ts, r"C:\Windows\System32\cmd.exe"),
                    3
                ),
                TakeOrRegisterOutcome::Registered
            );
            assert!(corr_count
                .on_system_process_start_at(sys_cmd(pid, 1, base_ts, "cmd.exe", "k"), 3)
                .is_some());
        }
        assert!(corr_count.sys_fifo_len() <= MAX_CACHED_SYSTEM_CMDLINES * 4);
        assert!(corr_count.pending_fifo_len() <= MAX_PENDING_KERNEL_STARTS * 4);

        // 15 s monotonic TTL expiry.
        let mut corr_ttl = ProcessCommandLineCorrelator::new();
        corr_ttl.on_system_process_start_at(sys_cmd(777, 1, base_ts, "cmd.exe", "ttl-sys"), 100);
        assert_eq!(
            corr_ttl.take_or_register_pending_start_at(
                kp_pending(778, 1, base_ts, r"C:\Windows\System32\cmd.exe"),
                100
            ),
            TakeOrRegisterOutcome::Registered
        );
        assert!(corr_ttl
            .take_matching_command_line_at(
                777,
                1,
                base_ts,
                r"C:\Windows\System32\cmd.exe",
                100 + ENTRY_TTL_MS + 1
            )
            .is_none());
        assert_eq!(corr_ttl.cached_sys_len(), 0);
        assert_eq!(corr_ttl.pending_starts_len(), 0);
    }
}
