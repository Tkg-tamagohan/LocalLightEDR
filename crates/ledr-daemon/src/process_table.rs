//! Bounded O(1) in-memory active process table for parent-child correlation (`決定記録 L-12`).

use std::collections::{HashMap, HashSet, VecDeque};

use ledr_proto::{is_never_suspend_process, ProcessIdentity, ACTIVE_PROCESS_TABLE_CAPACITY};

/// Process metadata cached in memory for O(1) parent context lookup during rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProcessEntry {
    pub identity: ProcessIdentity,
    pub instance_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub parent_instance_id: Option<String>,
    pub exe_path: String,
    pub command_line: String,
    pub user_sid: Option<String>,
    pub created_at_ms: i64,
    pub exited_at_ms: Option<i64>,
    pub sigma_evaluated: bool,
    pub emitted_rule_ids: HashSet<String>,
}

/// Resolution result returned when recording a new `ProcessStart` into [`ActiveProcessTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartResolution {
    pub instance_id: String,
    pub parent_instance_id: Option<String>,
    pub parent_exe_path: Option<String>,
    pub parent_command_line: Option<String>,
    pub should_evaluate_sigma: bool,
    /// Inferred exit time set when this `ProcessStart` describes an older incarnation already
    /// superseded in memory; the engine propagates it to the store row.
    pub exited_at_ms: Option<i64>,
}

/// Bounded in-memory process table (`ACTIVE_PROCESS_TABLE_CAPACITY` = 4,096) supporting
/// O(1) lookup by `pid` or `instance_id` and evicting oldest exited entries when over capacity.
#[derive(Debug)]
pub struct ActiveProcessTable {
    capacity: usize,
    pid_to_identity: HashMap<u32, ProcessIdentity>,
    entries: HashMap<String, ActiveProcessEntry>,
    exited_fifo: VecDeque<String>,
    insertion_fifo: VecDeque<String>,
    active_count: usize,
}

impl Default for ActiveProcessTable {
    fn default() -> Self {
        Self::new(ACTIVE_PROCESS_TABLE_CAPACITY)
    }
}

impl ActiveProcessTable {
    /// Creates an [`ActiveProcessTable`] bounded at `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            pid_to_identity: HashMap::with_capacity(cap.min(1024)),
            entries: HashMap::with_capacity(cap.min(1024)),
            exited_fifo: VecDeque::new(),
            insertion_fifo: VecDeque::new(),
            active_count: 0,
        }
    }

    /// Records a newly started (or initially snapshotted) process and resolves its parent lineage in O(1).
    pub fn on_process_start(
        &mut self,
        identity: ProcessIdentity,
        parent_pid: u32,
        exe_path: String,
        command_line: String,
        user_sid: Option<String>,
        created_at_ms: i64,
    ) -> ProcessStartResolution {
        let instance_id = identity.instance_id();

        let (mut parent_instance_id, mut parent_exe_path, mut parent_command_line) =
            if parent_pid != 0 && parent_pid != identity.pid {
                let parent_opt = self
                    .lookup_by_pid_at(parent_pid, created_at_ms)
                    .or_else(|| {
                        self.lookup_by_pid(parent_pid)
                            .filter(|entry| entry.identity.create_time_100ns == 0)
                    });
                if let Some(parent_entry) = parent_opt {
                    (
                        Some(parent_entry.instance_id.clone()),
                        Some(parent_entry.exe_path.clone()),
                        (!parent_entry.command_line.is_empty())
                            .then(|| parent_entry.command_line.clone()),
                    )
                } else {
                    (None, None, None)
                }
            } else {
                (None, None, None)
            };

        if self.entries.contains_key(&instance_id) {
            // Before mutating `existing`, populate parent metadata from `existing.parent_instance_id`
            // if `parent_pid` lookup returned `None`.
            if parent_instance_id.is_none() {
                let existing_parent_id = self
                    .entries
                    .get(&instance_id)
                    .and_then(|e| e.parent_instance_id.clone());
                if let Some(ref existing_pid) = existing_parent_id {
                    if let Some(parent_entry) = self.entries.get(existing_pid) {
                        parent_instance_id = Some(parent_entry.instance_id.clone());
                        parent_exe_path = Some(parent_entry.exe_path.clone());
                        parent_command_line = (!parent_entry.command_line.is_empty())
                            .then(|| parent_entry.command_line.clone());
                    }
                }
            }

            let existing = self
                .entries
                .get_mut(&instance_id)
                .expect("entry presence verified");
            let upgraded_parent =
                existing.parent_instance_id.is_none() && parent_instance_id.is_some();
            let upgraded_cmd = existing.command_line.is_empty() && !command_line.is_empty();
            let upgraded_exe = existing.exe_path.is_empty() && !exe_path.is_empty();
            let should_evaluate_sigma =
                !existing.sigma_evaluated || upgraded_parent || upgraded_cmd || upgraded_exe;
            existing.sigma_evaluated = true;

            if existing.parent_instance_id.is_none() {
                existing.parent_instance_id = parent_instance_id.clone();
            }
            if !exe_path.is_empty() {
                existing.exe_path = exe_path;
            }
            if !command_line.is_empty() {
                existing.command_line = command_line;
            }
            if existing.user_sid.is_none() {
                existing.user_sid = user_sid;
            }
            let is_active = existing.exited_at_ms.is_none();
            let resolved_parent_id = existing.parent_instance_id.clone();
            if is_active {
                self.pid_to_identity.insert(identity.pid, identity);
            }
            return ProcessStartResolution {
                instance_id,
                parent_instance_id: resolved_parent_id,
                parent_exe_path,
                parent_command_line,
                should_evaluate_sigma,
                exited_at_ms: None,
            };
        }

        if let Some(prev_id) = self
            .pid_to_identity
            .get(&identity.pid)
            .copied()
            .filter(|prev| *prev != identity)
            .map(|prev| prev.instance_id())
        {
            if let Some(prev_entry) = self.entries.get(&prev_id) {
                if (prev_entry.created_at_ms, prev_entry.identity.create_time_100ns)
                    > (created_at_ms, identity.create_time_100ns)
                {
                    // Arriving ProcessStart is older than the already-registered process for this PID:
                    // preserve the newer active mapping and record this older incarnation as exited.
                    let inferred_exit_ms = prev_entry.created_at_ms;
                    self.entries.insert(
                        instance_id.clone(),
                        ActiveProcessEntry {
                            identity,
                            instance_id: instance_id.clone(),
                            pid: identity.pid,
                            ppid: parent_pid,
                            parent_instance_id: parent_instance_id.clone(),
                            exe_path,
                            command_line,
                            user_sid,
                            created_at_ms,
                            exited_at_ms: Some(inferred_exit_ms),
                            sigma_evaluated: true,
                            emitted_rule_ids: HashSet::new(),
                        },
                    );
                    self.exited_fifo.push_back(instance_id.clone());
                    self.insertion_fifo.push_back(instance_id.clone());
                    self.evict_if_over_capacity(&instance_id);
                    return ProcessStartResolution {
                        instance_id,
                        parent_instance_id,
                        parent_exe_path,
                        parent_command_line,
                        should_evaluate_sigma: true,
                        exited_at_ms: Some(inferred_exit_ms),
                    };
                }
            }

            // If a previous process with the same PID is still marked active (missed stop), mark it exited.
            if let Some(prev_entry) = self
                .entries
                .get_mut(&prev_id)
                .filter(|entry| entry.exited_at_ms.is_none())
            {
                prev_entry.exited_at_ms = Some(created_at_ms);
                self.active_count = self.active_count.saturating_sub(1);
                self.exited_fifo.push_back(prev_id);
            }
        }

        self.pid_to_identity.insert(identity.pid, identity);
        self.entries.insert(
            instance_id.clone(),
            ActiveProcessEntry {
                identity,
                instance_id: instance_id.clone(),
                pid: identity.pid,
                ppid: parent_pid,
                parent_instance_id: parent_instance_id.clone(),
                exe_path,
                command_line,
                user_sid,
                created_at_ms,
                exited_at_ms: None,
                sigma_evaluated: true,
                emitted_rule_ids: HashSet::new(),
            },
        );
        self.active_count += 1;
        self.insertion_fifo.push_back(instance_id.clone());

        self.evict_if_over_capacity(&instance_id);

        ProcessStartResolution {
            instance_id,
            parent_instance_id,
            parent_exe_path,
            parent_command_line,
            should_evaluate_sigma: true,
            exited_at_ms: None,
        }
    }

    /// Marks the active process for `pid` as exited while keeping it cached until capacity eviction
    /// so in-flight telemetry events and immediate child spawns can still resolve its metadata.
    pub fn on_process_stop(&mut self, pid: u32, exited_at_ms: i64) -> Option<String> {
        let candidate_id = if let Some(ident) = self.pid_to_identity.get(&pid).copied() {
            let id = ident.instance_id();
            match self.entries.get(&id) {
                Some(entry) if entry.created_at_ms <= exited_at_ms => Some(id),
                _ => None,
            }
        } else {
            None
        };

        let target_id = candidate_id.or_else(|| {
            self.entries
                .values()
                .filter(|e| {
                    e.identity.pid == pid
                        && e.exited_at_ms.is_none()
                        && e.created_at_ms <= exited_at_ms
                })
                .max_by_key(|e| (e.created_at_ms, e.identity.create_time_100ns))
                .map(|e| e.instance_id.clone())
        })?;

        let entry = self.entries.get_mut(&target_id)?;
        if entry.exited_at_ms.is_none() {
            entry.exited_at_ms = Some(exited_at_ms);
            self.active_count = self.active_count.saturating_sub(1);
            self.exited_fifo.push_back(target_id.clone());
        }
        Some(target_id)
    }

    /// O(1) lookup by PID (matches active or recently exited un-evicted entry).
    pub fn lookup_by_pid(&self, pid: u32) -> Option<&ActiveProcessEntry> {
        let ident = self.pid_to_identity.get(&pid)?;
        self.entries.get(&ident.instance_id())
    }

    /// Time-window lookup by PID (`BUG_0002`), checking the O(1) current mapping first and
    /// falling back to cached exited incarnations alive at `event_ts_ms` (`created_at_ms <= event_ts_ms <= exited_at_ms`).
    pub fn lookup_by_pid_at(&self, pid: u32, event_ts_ms: i64) -> Option<&ActiveProcessEntry> {
        if let Some(entry) = self.lookup_by_pid(pid) {
            if entry.created_at_ms <= event_ts_ms
                && entry.exited_at_ms.is_none_or(|exit_ts| event_ts_ms <= exit_ts)
            {
                return Some(entry);
            }
        }
        self.entries
            .values()
            .filter(|e| {
                e.identity.pid == pid
                    && e.created_at_ms <= event_ts_ms
                    && e.exited_at_ms.is_none_or(|exit_ts| event_ts_ms <= exit_ts)
            })
            .max_by_key(|e| (e.created_at_ms, e.identity.create_time_100ns))
    }

    /// Returns `instance_id`s for all currently unexited processes in the table.
    pub fn active_instance_ids(&self) -> Vec<String> {
        self.entries
            .values()
            .filter(|e| e.exited_at_ms.is_none())
            .map(|e| e.instance_id.clone())
            .collect()
    }

    /// Returns deduplicated executable paths for all currently unexited processes in the table.
    pub fn active_exe_paths(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for entry in self.entries.values() {
            if entry.exited_at_ms.is_none() && !entry.exe_path.trim().is_empty() {
                let key = entry.exe_path.to_ascii_lowercase();
                if seen.insert(key) {
                    out.push(entry.exe_path.clone());
                }
            }
        }
        out
    }

    /// Zero-allocation check returning `true` if any currently unexited process matches
    /// `target_exe_key` (as normalized by `WfpRuleManager::exe_key`).
    pub fn has_active_exe_key(&self, target_exe_key: &str) -> bool {
        self.entries.values().any(|entry| {
            entry.exited_at_ms.is_none()
                && !entry.exe_path.trim().is_empty()
                && normalized_exe_key_eq(&entry.exe_path, target_exe_key)
        })
    }

    /// Returns candidate entries matching `target_exe_key` (as normalized by
    /// `WfpRuleManager::exe_key`), ordered active processes first (newest `created_at_ms`
    /// first), followed by recently exited entries (most recently exited/created first).
    pub fn candidates_by_exe_key(&self, target_exe_key: &str) -> Vec<&ActiveProcessEntry> {
        let mut matches: Vec<&ActiveProcessEntry> = self
            .entries
            .values()
            .filter(|entry| {
                !entry.exe_path.trim().is_empty()
                    && normalized_exe_key_eq(&entry.exe_path, target_exe_key)
            })
            .collect();
        matches.sort_by(|a, b| {
            let a_exited = a.exited_at_ms.is_some();
            let b_exited = b.exited_at_ms.is_some();
            a_exited
                .cmp(&b_exited)
                .then_with(|| b.exited_at_ms.cmp(&a.exited_at_ms))
                .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
                .then_with(|| b.identity.create_time_100ns.cmp(&a.identity.create_time_100ns))
        });
        matches
    }

    /// O(1) lookup by composite `instance_id` (`"{pid}:{create_time_100ns}"`).
    pub fn get_by_instance_id(&self, instance_id: &str) -> Option<&ActiveProcessEntry> {
        self.entries.get(instance_id)
    }

    /// Marks `rule_id` as having emitted an alert for `instance_id`, returning `true` only on
    /// the first alert for that `(instance_id, rule_id)` pair (or when `instance_id` is uncached).
    pub fn mark_rule_alert_emitted(&mut self, instance_id: &str, rule_id: &str) -> bool {
        match self.entries.get_mut(instance_id) {
            Some(entry) => entry.emitted_rule_ids.insert(rule_id.to_string()),
            None => true,
        }
    }

    /// Clears a previously emitted `(instance_id, rule_id)` alert deduplication mark so
    /// subsequent matches for that rule/canary target can re-evaluate (`BUG_0006` / `BUG_0004`).
    pub fn clear_rule_alert_emitted(&mut self, instance_id: &str, rule_id: &str) -> bool {
        match self.entries.get_mut(instance_id) {
            Some(entry) => entry.emitted_rule_ids.remove(rule_id),
            None => false,
        }
    }

    /// Returns `true` when `rule_id` was already marked emitted for `instance_id`
    /// (`ANALYSIS_0002` — read-only dedup check that does not consume the first-emit slot).
    pub fn has_rule_alert_emitted(&self, instance_id: &str, rule_id: &str) -> bool {
        self.entries
            .get(instance_id)
            .is_some_and(|entry| entry.emitted_rule_ids.contains(rule_id))
    }

    /// Collects unexited, non-protected descendant [`ProcessIdentity`] values of `root`
    /// currently tracked in memory (`BUG_0005`), in BFS parent-before-child order.
    pub fn collect_unexited_descendants(&self, root: &ProcessIdentity) -> Vec<ProcessIdentity> {
        if root.create_time_100ns == 0 {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        visited.insert(*root);
        let mut queue = VecDeque::new();
        queue.push_back(*root);
        let mut descendants = Vec::new();

        while let Some(parent) = queue.pop_front() {
            let parent_id = parent.instance_id();
            let mut children: Vec<&ActiveProcessEntry> = self
                .entries
                .values()
                .filter(|e| {
                    e.exited_at_ms.is_none()
                        && e.identity.create_time_100ns != 0
                        && !visited.contains(&e.identity)
                        && !is_never_suspend_process(&e.exe_path)
                        && (e.parent_instance_id.as_deref() == Some(parent_id.as_str())
                            || (e.parent_instance_id.is_none()
                                && e.ppid == parent.pid
                                && e.identity.create_time_100ns >= parent.create_time_100ns))
                })
                .collect();
            children.sort_by_key(|e| (e.identity.create_time_100ns, e.pid));
            for child in children {
                if visited.insert(child.identity) {
                    descendants.push(child.identity);
                    queue.push_back(child.identity);
                }
            }
        }

        descendants
    }

    /// Returns the number of non-exited processes currently tracked.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Returns total cached entries (active + recently exited, always `<= capacity`).
    pub fn total_len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the configured maximum entry capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn evict_if_over_capacity(&mut self, protect_id: &str) {
        while self.entries.len() > self.capacity {
            let mut evicted = false;

            while let Some(candidate_id) = self.exited_fifo.pop_front() {
                if candidate_id == protect_id {
                    continue;
                }
                if self
                    .entries
                    .get(&candidate_id)
                    .is_some_and(|e| e.exited_at_ms.is_some())
                {
                    self.remove_entry(&candidate_id);
                    evicted = true;
                    break;
                }
            }

            if !evicted {
                while let Some(candidate_id) = self.insertion_fifo.pop_front() {
                    if candidate_id == protect_id {
                        continue;
                    }
                    if self.entries.contains_key(&candidate_id) {
                        self.remove_entry(&candidate_id);
                        evicted = true;
                        break;
                    }
                }
            }

            if !evicted {
                break;
            }
        }

        if self.insertion_fifo.len() > self.capacity.saturating_mul(2) {
            let entries = &self.entries;
            self.insertion_fifo.retain(|id| entries.contains_key(id));
        }
    }

    fn remove_entry(&mut self, instance_id: &str) {
        if let Some(removed) = self.entries.remove(instance_id) {
            if removed.exited_at_ms.is_none() {
                self.active_count = self.active_count.saturating_sub(1);
            }
            if self.pid_to_identity.get(&removed.pid) == Some(&removed.identity) {
                self.pid_to_identity.remove(&removed.pid);
            }
        }
    }
}

fn normalized_exe_key_eq(raw_exe: &str, canonical_lower_key: &str) -> bool {
    let trimmed = raw_exe.trim();
    let (prefix_slash_prefix, rest) = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\") || p.eq_ignore_ascii_case("//?/UNC/"))
    {
        (r"\\", &trimmed[8..])
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\") || p.eq_ignore_ascii_case("//?/"))
    {
        ("", &trimmed[4..])
    } else {
        ("", trimmed)
    };

    let mut key_bytes = canonical_lower_key.bytes();
    for b in prefix_slash_prefix.bytes().chain(rest.bytes()) {
        let norm = if b == b'/' {
            b'\\'
        } else {
            b.to_ascii_lowercase()
        };
        if key_bytes.next() != Some(norm) {
            return false;
        }
    }
    key_bytes.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_table_tracks_parent_and_evicts_oldest_exited() {
        let mut table = ActiveProcessTable::new(3);
        let parent = ProcessIdentity::new(100, 1000);
        let child = ProcessIdentity::new(200, 2000);

        let p_res = table.on_process_start(
            parent,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            "cmd.exe".to_string(),
            None,
            10,
        );
        assert_eq!(p_res.parent_instance_id, None);

        let c_res = table.on_process_start(
            child,
            100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -enc AA==".to_string(),
            None,
            20,
        );
        assert_eq!(c_res.parent_instance_id.as_deref(), Some("100:1000"));
        assert_eq!(
            c_res.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(table.active_count(), 2);

        table.on_process_stop(100, 30);
        assert_eq!(table.active_count(), 1);
        assert_eq!(table.total_len(), 2);

        // Adding 2 more active processes forces eviction of the exited parent (oldest exited).
        table.on_process_start(
            ProcessIdentity::new(300, 3000),
            200,
            "a.exe".to_string(),
            String::new(),
            None,
            40,
        );
        table.on_process_start(
            ProcessIdentity::new(400, 4000),
            200,
            "b.exe".to_string(),
            String::new(),
            None,
            50,
        );
        assert_eq!(table.total_len(), 3);
        assert!(table.get_by_instance_id("100:1000").is_none());
        assert!(table.get_by_instance_id("200:2000").is_some());
    }

    #[test]
    fn process_table_pid_reuse_time_window_and_snapshot_race_preservation() {
        let mut table = ActiveProcessTable::new(16);
        let a = ProcessIdentity::new(500, 1000);
        let b = ProcessIdentity::new(500, 3000);

        table.on_process_start(a, 4, "a.exe".to_string(), String::new(), None, 100);
        assert_eq!(table.on_process_stop(500, 200), Some(a.instance_id()));
        table.on_process_start(b, 4, "b.exe".to_string(), String::new(), None, 300);

        // Time-window lookup resolves A within [100, 200] and B at >= 300.
        assert_eq!(
            table.lookup_by_pid_at(500, 150).map(|e| e.identity),
            Some(a)
        );
        assert_eq!(
            table.lookup_by_pid_at(500, 350).map(|e| e.identity),
            Some(b)
        );
        assert!(table.lookup_by_pid_at(500, 250).is_none());

        // Snapshot arriving after ProcessStop must preserve exited_at_ms and not clobber B.
        table.on_process_start(a, 4, "a_full.exe".to_string(), "a.exe --arg".to_string(), None, 100);
        let a_entry = table.get_by_instance_id(&a.instance_id()).expect("A retained");
        assert_eq!(a_entry.exited_at_ms, Some(200));
        assert_eq!(a_entry.exe_path, "a_full.exe");
        assert_eq!(table.lookup_by_pid(500).map(|e| e.identity), Some(b));

        // Out-of-order stop for an older incarnation must not mark newer B as exited.
        assert_eq!(table.on_process_stop(500, 250), None);
        assert_eq!(
            table
                .get_by_instance_id(&b.instance_id())
                .and_then(|e| e.exited_at_ms),
            None
        );
    }

    #[test]
    fn process_table_deduplicates_sigma_evaluation_unless_cmdline_enriched() {
        let mut table = ActiveProcessTable::new(16);
        let p1 = ProcessIdentity::new(901, 10_000);
        let first = table.on_process_start(
            p1,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -enc AA==".to_string(),
            None,
            100,
        );
        assert!(first.should_evaluate_sigma);

        // Duplicate start (e.g., ETW + seed_processes) with non-empty command line does not re-evaluate.
        let dup = table.on_process_start(
            p1,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -enc AA==".to_string(),
            None,
            100,
        );
        assert!(!dup.should_evaluate_sigma);

        // Process initially observed without command line re-evaluates once enriched.
        let p2 = ProcessIdentity::new(902, 20_000);
        let empty_cmd = table.on_process_start(
            p2,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            String::new(),
            None,
            200,
        );
        assert!(empty_cmd.should_evaluate_sigma);

        let enriched = table.on_process_start(
            p2,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -Command iex 'x'".to_string(),
            None,
            200,
        );
        assert!(enriched.should_evaluate_sigma);

        let post_enrich_dup = table.on_process_start(
            p2,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -Command iex 'x'".to_string(),
            None,
            200,
        );
        assert!(!post_enrich_dup.should_evaluate_sigma);
    }

    #[test]
    fn process_table_parent_enrichment_dedup_and_older_snapshot_preservation() {
        let mut table = ActiveProcessTable::new(16);
        let parent = ProcessIdentity::new(1100, 10_000);
        let child = ProcessIdentity::new(1200, 20_000);

        // Child arrives before parent, with empty exe_path initially.
        let initial_child = table.on_process_start(
            child,
            1100,
            String::new(),
            "powershell.exe -enc AA==".to_string(),
            None,
            200,
        );
        assert!(initial_child.should_evaluate_sigma);
        assert_eq!(initial_child.parent_instance_id, None);
        assert!(table.mark_rule_alert_emitted(&child.instance_id(), "LEDR-LOTL-002"));
        assert!(!table.mark_rule_alert_emitted(&child.instance_id(), "LEDR-LOTL-002"));
        assert!(table.mark_rule_alert_emitted("9999:1", "LEDR-LOTL-001"));

        // Parent arrives, then child is re-observed -> upgrades parent and exe_path.
        table.on_process_start(
            parent,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            "cmd.exe".to_string(),
            None,
            100,
        );
        let enriched_child = table.on_process_start(
            child,
            1100,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -enc AA==".to_string(),
            None,
            200,
        );
        assert!(enriched_child.should_evaluate_sigma);
        assert_eq!(
            enriched_child.parent_instance_id.as_deref(),
            Some("1100:10000")
        );
        assert_eq!(
            enriched_child.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert!(table.mark_rule_alert_emitted(&child.instance_id(), "LEDR-LOTL-001"));
        assert!(!table.mark_rule_alert_emitted(&child.instance_id(), "LEDR-LOTL-002"));

        // Re-observing child with parent_pid=0 still resolves parent metadata from existing.parent_instance_id
        // without triggering re-evaluation.
        let fallback_parent = table.on_process_start(
            child,
            0,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -enc AA==".to_string(),
            None,
            200,
        );
        assert!(!fallback_parent.should_evaluate_sigma);
        assert_eq!(
            fallback_parent.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );

        // Older snapshot for PID 42 arriving after newer ETW start preserves newer active entry.
        let newer_42 = ProcessIdentity::new(42, 2000);
        let older_42 = ProcessIdentity::new(42, 1000);
        table.on_process_start(newer_42, 4, "new42.exe".to_string(), String::new(), None, 2000);
        let active_before = table.active_count();
        let older_res =
            table.on_process_start(older_42, 4, "old42.exe".to_string(), String::new(), None, 1000);
        assert!(older_res.should_evaluate_sigma);
        assert_eq!(table.active_count(), active_before);
        assert_eq!(table.lookup_by_pid(42).map(|e| e.identity), Some(newer_42));
        assert_eq!(
            table.lookup_by_pid_at(42, 2500).map(|e| e.identity),
            Some(newer_42)
        );
        assert_eq!(
            table
                .get_by_instance_id(&newer_42.instance_id())
                .and_then(|e| e.exited_at_ms),
            None
        );
        assert_eq!(
            table
                .get_by_instance_id(&older_42.instance_id())
                .and_then(|e| e.exited_at_ms),
            Some(2000)
        );
    }

    #[test]
    fn process_table_candidates_by_exe_key_prefers_active_then_recent_exited() {
        let mut table = ActiveProcessTable::new(16);
        let exe = r"\\?\C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let exe_key = r"c:\windows\system32\windowspowershell\v1.0\powershell.exe";

        let exited_old = ProcessIdentity::new(7001, 1000);
        let exited_recent = ProcessIdentity::new(7002, 2000);
        let active_one = ProcessIdentity::new(7003, 3000);

        table.on_process_start(exited_old, 4, exe.to_string(), String::new(), None, 100);
        table.on_process_stop(7001, 150);
        table.on_process_start(exited_recent, 4, exe.to_string(), String::new(), None, 200);
        table.on_process_stop(7002, 250);
        table.on_process_start(active_one, 4, exe.to_string(), String::new(), None, 300);

        let candidates = table.candidates_by_exe_key(exe_key);
        let pids: Vec<u32> = candidates.iter().map(|e| e.pid).collect();
        assert_eq!(pids, vec![7003, 7002, 7001]);
    }
}
