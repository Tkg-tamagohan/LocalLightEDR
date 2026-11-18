//! Bounded O(1) in-memory active process table for parent-child correlation (`決定記録 L-12`).

use std::collections::{HashMap, VecDeque};

use ledr_proto::{ProcessIdentity, ACTIVE_PROCESS_TABLE_CAPACITY};

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
}

/// Resolution result returned when recording a new `ProcessStart` into [`ActiveProcessTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartResolution {
    pub instance_id: String,
    pub parent_instance_id: Option<String>,
    pub parent_exe_path: Option<String>,
    pub parent_command_line: Option<String>,
    pub should_evaluate_sigma: bool,
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

        let (parent_instance_id, parent_exe_path, parent_command_line) =
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

        if let Some(existing) = self.entries.get_mut(&instance_id) {
            let upgrade_cmd = existing.command_line.is_empty() && !command_line.is_empty();
            let should_evaluate = !existing.sigma_evaluated || upgrade_cmd;
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
                should_evaluate_sigma: should_evaluate,
            };
        }

        // If a previous process with the same PID is still marked active (missed stop), mark it exited.
        if let Some(prev_id) = self
            .pid_to_identity
            .get(&identity.pid)
            .copied()
            .filter(|prev| *prev != identity)
            .map(|prev| prev.instance_id())
        {
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

    /// O(1) lookup by composite `instance_id` (`"{pid}:{create_time_100ns}"`).
    pub fn get_by_instance_id(&self, instance_id: &str) -> Option<&ActiveProcessEntry> {
        self.entries.get(instance_id)
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
}
