//! Bounded O(1) in-memory active process table for parent-child correlation (`決定記録 L-12`).

use std::collections::{HashMap, HashSet, VecDeque};

use ledr_proto::{is_never_suspend_process, ProcessIdentity, ACTIVE_PROCESS_TABLE_CAPACITY};

const MAX_EVICTED_EXITED_HISTORY: usize = 1024;
const MAX_EVICTED_CMDLINE_BYTES: usize = 4096;
const MAX_EVICTED_LIVE_HISTORY: usize = ACTIVE_PROCESS_TABLE_CAPACITY;
const MAX_OVERFLOWED_EVICTED_LIVE_EXES: usize = ACTIVE_PROCESS_TABLE_CAPACITY;

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
    pub launch_guards_applied: bool,
    pub emitted_rule_ids: HashSet<String>,
    pub origin_url: Option<String>,
    pub motw_referrer: Option<String>,
    pub motw_frame_url: Option<String>,
    pub motw_source: Option<String>,
    pub motw_zone_id: Option<u32>,
}

/// Resolution result returned when recording a new `ProcessStart` into [`ActiveProcessTable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessStartResolution {
    /// Effective [`ProcessIdentity`] resolved in memory (equals the already-running verified
    /// identity when a `create_time_100ns == 0` snapshot is absorbed into it).
    pub resolved_identity: ProcessIdentity,
    pub instance_id: String,
    pub parent_instance_id: Option<String>,
    pub parent_exe_path: Option<String>,
    pub parent_command_line: Option<String>,
    pub should_evaluate_sigma: bool,
    /// Inferred exit time set when this `ProcessStart` describes an older incarnation already
    /// superseded in memory; the engine propagates it to the store row.
    pub exited_at_ms: Option<i64>,
    /// Previous `(process_instance_id, exit_ms)` marked exited in memory when this `ProcessStart`
    /// supersedes an earlier active entry for the same PID (such as a `pid:0` snapshot
    /// placeholder); the engine propagates it to the store in the same transaction.
    pub superseded_exit: Option<(String, i64)>,
    /// `true` when an unverified `create_time_100ns == 0` snapshot was absorbed into an already
    /// running verified process without enriching any missing metadata, so persisting a synthetic
    /// `pid:0` row into SQLite must be skipped.
    pub skip_store_ingest: bool,
    /// `true` when launch-time MOTW and preemptive WFP guards must not run on this `ProcessStart`
    /// (for example, an already-exited/evicted process, or an active process whose launch guards
    /// have already been applied and whose `exe_path` did not newly upgrade from empty).
    pub skip_launch_guards: bool,
    /// `process_instance_id` values evicted from memory to stay within `capacity`.
    pub evicted_instance_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EvictedCommandLine {
    Empty,
    /// Full command line retained only when its UTF-8 byte length fits within
    /// `MAX_EVICTED_CMDLINE_BYTES` so Sigma `endswith`/exact rules never see a truncated prefix.
    Complete(String),
    /// Original command line exceeded `MAX_EVICTED_CMDLINE_BYTES`; omitted from Sigma evaluation
    /// and never overwritten by subsequent delayed events.
    Oversized,
}

impl EvictedCommandLine {
    fn from_owned(cmd: String) -> Self {
        if cmd.is_empty() {
            Self::Empty
        } else if cmd.len() <= MAX_EVICTED_CMDLINE_BYTES {
            Self::Complete(cmd)
        } else {
            Self::Oversized
        }
    }

    fn as_complete(&self) -> Option<&str> {
        match self {
            Self::Complete(cmd) => Some(cmd.as_str()),
            Self::Empty | Self::Oversized => None,
        }
    }
}

#[derive(Debug, Clone)]
struct EvictedExitedRecord {
    identity: ProcessIdentity,
    created_at_ms: i64,
    exited_at_ms: i64,
    parent_instance_id: Option<String>,
    exe_path: String,
    command_line: EvictedCommandLine,
    emitted_rule_ids: HashSet<String>,
}

/// Compact record retained when a still-running (`exited_at_ms == None`) entry is evicted from
/// `ActiveProcessTable::entries` under capacity pressure so live instances are never mistaken for
/// exited processes during preemptive WFP cleanup (`PRRT_kwDOVyjVyM66ksZW`).
#[derive(Debug, Clone)]
struct EvictedLiveRecord {
    identity: ProcessIdentity,
    created_at_ms: i64,
    exe_path: String,
    exe_key: String,
    has_motw: bool,
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
    evicted_exited: HashMap<String, EvictedExitedRecord>,
    evicted_exited_fifo: VecDeque<String>,
    evicted_live: HashMap<String, EvictedLiveRecord>,
    evicted_live_fifo: VecDeque<String>,
    evicted_live_capacity: usize,
    evicted_live_exe_counts: HashMap<String, usize>,
    evicted_live_motw_exe_counts: HashMap<String, usize>,
    overflowed_evicted_live_exes: HashSet<String>,
    overflowed_evicted_live_motw_exes: HashSet<String>,
    evicted_live_overflow_any: bool,
    evicted_live_motw_overflow_any: bool,
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
            evicted_exited: HashMap::new(),
            evicted_exited_fifo: VecDeque::new(),
            evicted_live: HashMap::new(),
            evicted_live_fifo: VecDeque::new(),
            evicted_live_capacity: MAX_EVICTED_LIVE_HISTORY,
            evicted_live_exe_counts: HashMap::new(),
            evicted_live_motw_exe_counts: HashMap::new(),
            overflowed_evicted_live_exes: HashSet::new(),
            overflowed_evicted_live_motw_exes: HashSet::new(),
            evicted_live_overflow_any: false,
            evicted_live_motw_overflow_any: false,
            active_count: 0,
        }
    }

    /// Overrides the bounded capacity of the secondary evicted-live tracker in unit/integration
    /// tests so overflow fail-closed protection can be exercised deterministically.
    #[cfg(test)]
    pub fn with_evicted_live_capacity(mut self, capacity: usize) -> Self {
        self.evicted_live_capacity = capacity;
        self
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

        if identity.create_time_100ns == 0 {
            if let Some(active_verified_id) = self
                .pid_to_identity
                .get(&identity.pid)
                .copied()
                .filter(|prev| prev.create_time_100ns != 0)
                .map(|prev| prev.instance_id())
            {
                if let Some((
                    prev_identity,
                    prev_created_at_ms,
                    prev_ppid,
                    prev_parent_id,
                    prev_sigma_evaluated,
                )) = self
                    .entries
                    .get(&active_verified_id)
                    .filter(|e| e.exited_at_ms.is_none())
                    .map(|e| {
                        (
                            e.identity,
                            e.created_at_ms,
                            e.ppid,
                            e.parent_instance_id.clone(),
                            e.sigma_evaluated,
                        )
                    })
                {
                    if prev_ppid != 0 && parent_pid != 0 && prev_ppid != parent_pid {
                        let (
                            existing_parent_id,
                            existing_parent_exe,
                            existing_parent_cmd,
                        ) = prev_parent_id
                            .as_deref()
                            .map_or((None, None, None), |id| self.parent_metadata_by_id(id));
                        return ProcessStartResolution {
                            resolved_identity: prev_identity,
                            instance_id: prev_identity.instance_id(),
                            parent_instance_id: existing_parent_id,
                            parent_exe_path: existing_parent_exe,
                            parent_command_line: existing_parent_cmd,
                            should_evaluate_sigma: !prev_sigma_evaluated,
                            exited_at_ms: None,
                            superseded_exit: None,
                            skip_store_ingest: true,
                            skip_launch_guards: true,
                            evicted_instance_ids: Vec::new(),
                        };
                    }

                    let (parent_instance_id, parent_exe_path, parent_command_line) =
                        if let Some(ref existing_pid) = prev_parent_id {
                            self.parent_metadata_by_id(existing_pid)
                        } else {
                            let effective_parent_pid =
                                if prev_ppid != 0 { prev_ppid } else { parent_pid };
                            self.lookup_parent_for(
                                effective_parent_pid,
                                prev_identity,
                                prev_created_at_ms,
                                false,
                            )
                        };

                    let prev_entry = self
                        .entries
                        .get_mut(&active_verified_id)
                        .expect("verified active entry presence verified");
                    let upgraded_parent =
                        prev_entry.parent_instance_id.is_none() && parent_instance_id.is_some();
                    let upgraded_ppid = prev_entry.ppid == 0
                        && parent_pid != 0
                        && parent_pid != prev_entry.pid;
                    let upgraded_exe = prev_entry.exe_path.is_empty() && !exe_path.is_empty();
                    let upgraded_cmd =
                        prev_entry.command_line.is_empty() && !command_line.is_empty();
                    let upgraded_sid = prev_entry.user_sid.is_none() && user_sid.is_some();

                    if upgraded_parent {
                        prev_entry.parent_instance_id = parent_instance_id.clone();
                    }
                    if upgraded_ppid {
                        prev_entry.ppid = parent_pid;
                    }
                    if upgraded_exe {
                        prev_entry.exe_path = exe_path;
                    }
                    if upgraded_cmd {
                        prev_entry.command_line = command_line;
                    }
                    if upgraded_sid {
                        prev_entry.user_sid = user_sid;
                    }

                    let enriched = upgraded_parent
                        || upgraded_ppid
                        || upgraded_exe
                        || upgraded_cmd
                        || upgraded_sid;
                    let should_evaluate_sigma =
                        !prev_entry.sigma_evaluated || upgraded_parent || upgraded_cmd || upgraded_exe;
                    prev_entry.sigma_evaluated = true;

                    return ProcessStartResolution {
                        resolved_identity: prev_entry.identity,
                        instance_id: prev_entry.instance_id.clone(),
                        parent_instance_id: prev_entry.parent_instance_id.clone(),
                        parent_exe_path,
                        parent_command_line,
                        should_evaluate_sigma,
                        exited_at_ms: None,
                        superseded_exit: None,
                        skip_store_ingest: !enriched,
                        skip_launch_guards: prev_entry.launch_guards_applied && !upgraded_exe,
                        evicted_instance_ids: Vec::new(),
                    };
                }
            }
            if !self.evicted_live.is_empty() {
                if let Some(ev_identity) = self
                    .evicted_live
                    .values()
                    .filter(|ev| ev.identity.pid == identity.pid && ev.identity.create_time_100ns != 0)
                    .max_by_key(|ev| (ev.created_at_ms, ev.identity.create_time_100ns))
                    .map(|ev| ev.identity)
                {
                    return ProcessStartResolution {
                        resolved_identity: ev_identity,
                        instance_id: ev_identity.instance_id(),
                        parent_instance_id: None,
                        parent_exe_path: None,
                        parent_command_line: None,
                        should_evaluate_sigma: false,
                        exited_at_ms: None,
                        superseded_exit: None,
                        skip_store_ingest: true,
                        skip_launch_guards: true,
                        evicted_instance_ids: Vec::new(),
                    };
                }
            }
        }

        if let Some((
            existing_identity,
            existing_created_at_ms,
            existing_ppid,
            existing_parent_id,
        )) = self.entries.get(&instance_id).map(|e| {
            (
                e.identity,
                e.created_at_ms,
                e.ppid,
                e.parent_instance_id.clone(),
            )
        }) {
            let (parent_instance_id, parent_exe_path, parent_command_line) =
                if let Some(ref existing_pid) = existing_parent_id {
                    self.parent_metadata_by_id(existing_pid)
                } else {
                    let effective_parent_pid =
                        if existing_ppid != 0 { existing_ppid } else { parent_pid };
                    self.lookup_parent_for(
                        effective_parent_pid,
                        existing_identity,
                        existing_created_at_ms,
                        true,
                    )
                };

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
            if existing.ppid == 0 && parent_pid != 0 && parent_pid != existing.pid {
                existing.ppid = parent_pid;
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
            let existing_exited_at_ms = existing.exited_at_ms;
            let resolved_parent_id = existing.parent_instance_id.clone();
            let skip_launch_guards =
                !is_active || (existing.launch_guards_applied && !upgraded_exe);
            if is_active {
                self.pid_to_identity.insert(identity.pid, identity);
            }
            return ProcessStartResolution {
                resolved_identity: identity,
                instance_id,
                parent_instance_id: resolved_parent_id,
                parent_exe_path,
                parent_command_line,
                should_evaluate_sigma,
                exited_at_ms: existing_exited_at_ms,
                superseded_exit: None,
                skip_store_ingest: false,
                skip_launch_guards,
                evicted_instance_ids: Vec::new(),
            };
        }

        if identity.create_time_100ns != 0 {
            if let Some((evicted_exit_ms, saved_parent_id)) = self
                .evicted_exited
                .get(&instance_id)
                .map(|ev| (ev.exited_at_ms, ev.parent_instance_id.clone()))
            {
                let (parent_instance_id, parent_exe_path, parent_command_line) =
                    if let Some(ref existing_parent_id) = saved_parent_id {
                        self.parent_metadata_by_id(existing_parent_id)
                    } else {
                        self.lookup_parent_for(parent_pid, identity, created_at_ms, true)
                    };
                if let Some(evicted) = self.evicted_exited.get_mut(&instance_id) {
                    if evicted.parent_instance_id.is_none() {
                        evicted.parent_instance_id = parent_instance_id.clone();
                    }
                    if evicted.exe_path.is_empty() && !exe_path.is_empty() {
                        evicted.exe_path = exe_path;
                    }
                    if matches!(evicted.command_line, EvictedCommandLine::Empty)
                        && !command_line.is_empty()
                    {
                        evicted.command_line = EvictedCommandLine::from_owned(command_line);
                    }
                }
                return ProcessStartResolution {
                    resolved_identity: identity,
                    instance_id,
                    parent_instance_id,
                    parent_exe_path,
                    parent_command_line,
                    should_evaluate_sigma: true,
                    exited_at_ms: Some(evicted_exit_ms),
                    superseded_exit: None,
                    skip_store_ingest: false,
                    skip_launch_guards: true,
                    evicted_instance_ids: Vec::new(),
                };
            }
        }

        let (parent_instance_id, parent_exe_path, parent_command_line) =
            self.lookup_parent_for(parent_pid, identity, created_at_ms, true);

        let mut superseded_exit: Option<(String, i64)> = None;
        if let Some(prev_id) = self
            .pid_to_identity
            .get(&identity.pid)
            .copied()
            .filter(|prev| *prev != identity)
            .map(|prev| prev.instance_id())
        {
            if let Some(prev_entry) = self.entries.get(&prev_id) {
                if prev_entry.identity.create_time_100ns != 0
                    && (prev_entry.created_at_ms, prev_entry.identity.create_time_100ns)
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
                            launch_guards_applied: false,
                            emitted_rule_ids: HashSet::new(),
                            origin_url: None,
                            motw_referrer: None,
                            motw_frame_url: None,
                            motw_source: None,
                            motw_zone_id: None,
                        },
                    );
                    self.exited_fifo.push_back(instance_id.clone());
                    self.insertion_fifo.push_back(instance_id.clone());
                    let evicted_instance_ids = self.evict_if_over_capacity(&instance_id);
                    return ProcessStartResolution {
                        resolved_identity: identity,
                        instance_id,
                        parent_instance_id,
                        parent_exe_path,
                        parent_command_line,
                        should_evaluate_sigma: true,
                        exited_at_ms: Some(inferred_exit_ms),
                        superseded_exit: None,
                        skip_store_ingest: false,
                        skip_launch_guards: true,
                        evicted_instance_ids,
                    };
                }
            }

            // If a previous process with the same PID is still marked active (missed stop or
            // `pid:0` snapshot placeholder), mark it exited without inverting its timestamp.
            if let Some(prev_entry) = self
                .entries
                .get_mut(&prev_id)
                .filter(|entry| entry.exited_at_ms.is_none())
            {
                let exit_ms = created_at_ms.max(prev_entry.created_at_ms);
                prev_entry.exited_at_ms = Some(exit_ms);
                self.active_count = self.active_count.saturating_sub(1);
                self.exited_fifo.push_back(prev_id.clone());
                superseded_exit = Some((prev_id, exit_ms));
            }
        }

        if !self.evicted_live.is_empty() {
            // Re-inserting an evicted live instance removes its duplicate evicted-live record so
            // per-exe counts remain exact.
            self.remove_evicted_live_by_id(&instance_id);

            let newer_evicted_created = self
                .evicted_live
                .values()
                .filter(|ev| {
                    ev.identity.pid == identity.pid
                        && ev.identity != identity
                        && ev.identity.create_time_100ns != 0
                        && (ev.created_at_ms, ev.identity.create_time_100ns)
                            > (created_at_ms, identity.create_time_100ns)
                })
                .map(|ev| ev.created_at_ms)
                .max();
            if let Some(inferred_exit_ms) = newer_evicted_created {
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
                        launch_guards_applied: false,
                        emitted_rule_ids: HashSet::new(),
                        origin_url: None,
                        motw_referrer: None,
                        motw_frame_url: None,
                        motw_source: None,
                        motw_zone_id: None,
                    },
                );
                self.exited_fifo.push_back(instance_id.clone());
                self.insertion_fifo.push_back(instance_id.clone());
                let evicted_instance_ids = self.evict_if_over_capacity(&instance_id);
                return ProcessStartResolution {
                    resolved_identity: identity,
                    instance_id,
                    parent_instance_id,
                    parent_exe_path,
                    parent_command_line,
                    should_evaluate_sigma: true,
                    exited_at_ms: Some(inferred_exit_ms),
                    superseded_exit: None,
                    skip_store_ingest: false,
                    skip_launch_guards: true,
                    evicted_instance_ids,
                };
            }

            let older_evicted: Vec<(String, i64, u64)> = self
                .evicted_live
                .iter()
                .filter(|(_, ev)| ev.identity.pid == identity.pid && ev.identity != identity)
                .map(|(id, ev)| (id.clone(), ev.created_at_ms, ev.identity.create_time_100ns))
                .collect();
            if let Some((latest_id, latest_created, _)) = older_evicted
                .iter()
                .max_by_key(|(_, c, ct)| (*c, *ct))
                .cloned()
            {
                for (ev_id, _, _) in older_evicted {
                    self.remove_evicted_live_by_id(&ev_id);
                }
                if superseded_exit.is_none() {
                    superseded_exit = Some((latest_id, created_at_ms.max(latest_created)));
                }
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
                launch_guards_applied: false,
                emitted_rule_ids: HashSet::new(),
                origin_url: None,
                motw_referrer: None,
                motw_frame_url: None,
                motw_source: None,
                motw_zone_id: None,
            },
        );
        self.active_count += 1;
        self.insertion_fifo.push_back(instance_id.clone());

        let evicted_instance_ids = self.evict_if_over_capacity(&instance_id);

        ProcessStartResolution {
            resolved_identity: identity,
            instance_id,
            parent_instance_id,
            parent_exe_path,
            parent_command_line,
            should_evaluate_sigma: true,
            exited_at_ms: None,
            superseded_exit,
            skip_store_ingest: false,
            skip_launch_guards: false,
            evicted_instance_ids,
        }
    }

    /// Marks the active process for `pid` as exited while keeping it cached until capacity eviction
    /// so in-flight telemetry events and immediate child spawns can still resolve its metadata.
    pub fn on_process_stop(&mut self, pid: u32, exited_at_ms: i64) -> Option<String> {
        self.on_process_stop_with_exe(pid, exited_at_ms)
            .map(|(id, _)| id)
    }

    /// Variant of [`Self::on_process_stop`] that also returns the stopped process's executable
    /// path, covering both primary `entries` and still-running processes previously displaced into
    /// `evicted_live` under capacity pressure (`PRRT_kwDOVyjVyM66ksZW`).
    pub fn on_process_stop_with_exe(
        &mut self,
        pid: u32,
        exited_at_ms: i64,
    ) -> Option<(String, String)> {
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
        });

        if let Some(target_id) = target_id {
            let entry = self.entries.get_mut(&target_id)?;
            if entry.exited_at_ms.is_none() {
                entry.exited_at_ms = Some(exited_at_ms);
                self.active_count = self.active_count.saturating_sub(1);
                self.exited_fifo.push_back(target_id.clone());
            }
            let exe_path = entry.exe_path.clone();
            return Some((target_id, exe_path));
        }

        if !self.evicted_live.is_empty() {
            let evicted_id = self
                .evicted_live
                .iter()
                .filter(|(_, ev)| ev.identity.pid == pid && ev.created_at_ms <= exited_at_ms)
                .max_by_key(|(_, ev)| (ev.created_at_ms, ev.identity.create_time_100ns))
                .map(|(id, _)| id.clone());
            if let Some(ev_id) = evicted_id {
                if let Some(ev) = self.remove_evicted_live_by_id(&ev_id) {
                    return Some((ev_id, ev.exe_path));
                }
            }
        }

        None
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

    /// Returns `instance_id`s for all currently unexited processes in the table (including live
    /// entries displaced into `evicted_live` under capacity pressure).
    pub fn active_instance_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .entries
            .values()
            .filter(|e| e.exited_at_ms.is_none())
            .map(|e| e.instance_id.clone())
            .collect();
        if !self.evicted_live.is_empty() {
            ids.extend(self.evicted_live.keys().cloned());
        }
        ids
    }

    /// Returns deduplicated executable paths for all currently unexited processes in the table
    /// (including live entries displaced into `evicted_live` under capacity pressure).
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
        for ev in self.evicted_live.values() {
            if !ev.exe_path.trim().is_empty() {
                let key = ev.exe_path.to_ascii_lowercase();
                if seen.insert(key) {
                    out.push(ev.exe_path.clone());
                }
            }
        }
        out
    }

    /// Zero-allocation check returning `true` if any currently unexited process matches
    /// `target_exe_key` (as normalized by `WfpRuleManager::exe_key`), including live processes
    /// displaced from `entries` under capacity pressure (`PRRT_kwDOVyjVyM66ksZW`).
    pub fn has_active_exe_key(&self, target_exe_key: &str) -> bool {
        if self.evicted_live_overflow_any
            || self.evicted_live_exe_counts.contains_key(target_exe_key)
            || self.overflowed_evicted_live_exes.contains(target_exe_key)
        {
            return true;
        }
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

    /// Time-windowed variant of [`Self::candidates_by_exe_key`] returning only instances whose
    /// lifetime overlaps `event_ts_ms` (allowing minor `+- 1,000 ms` sensor timestamp skew).
    pub fn candidates_by_exe_key_at(
        &self,
        target_exe_key: &str,
        event_ts_ms: i64,
    ) -> Vec<&ActiveProcessEntry> {
        let mut matches: Vec<&ActiveProcessEntry> = self
            .entries
            .values()
            .filter(|entry| {
                !entry.exe_path.trim().is_empty()
                    && normalized_exe_key_eq(&entry.exe_path, target_exe_key)
                    && entry.created_at_ms <= event_ts_ms.saturating_add(1_000)
                    && entry
                        .exited_at_ms
                        .is_none_or(|ex| event_ts_ms <= ex.saturating_add(1_000))
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

    /// Marks launch-time outbound/WFP guards as applied for `instance_id`.
    pub fn mark_launch_guards_applied(&mut self, instance_id: &str) -> bool {
        let Some(entry) = self.entries.get_mut(instance_id) else {
            return false;
        };
        entry.launch_guards_applied = true;
        true
    }

    /// Attaches resolved MOTW origin metadata to an existing entry in the process table.
    pub fn set_motw_metadata(
        &mut self,
        instance_id: &str,
        origin_url: String,
        motw_source: String,
        motw_referrer: Option<String>,
        motw_frame_url: Option<String>,
        motw_zone_id: Option<u32>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(instance_id) else {
            return false;
        };
        entry.origin_url = Some(origin_url);
        entry.motw_source = Some(motw_source);
        entry.motw_referrer = motw_referrer;
        entry.motw_frame_url = motw_frame_url;
        entry.motw_zone_id = motw_zone_id;
        true
    }

    /// Attaches resolved MOTW origin metadata only if `instance_id` is still active (unexited)
    /// and does not already carry `origin_url`, returning `(exe_path, pid)` when applied.
    pub fn set_motw_metadata_if_active(
        &mut self,
        instance_id: &str,
        origin_url: String,
        motw_source: String,
        motw_referrer: Option<String>,
        motw_frame_url: Option<String>,
        motw_zone_id: Option<u32>,
    ) -> Option<(String, u32)> {
        if let Some(entry) = self.entries.get_mut(instance_id) {
            if entry.exited_at_ms.is_some() || entry.origin_url.is_some() {
                return None;
            }
            entry.origin_url = Some(origin_url);
            entry.motw_source = Some(motw_source);
            entry.motw_referrer = motw_referrer;
            entry.motw_frame_url = motw_frame_url;
            entry.motw_zone_id = motw_zone_id;
            return Some((entry.exe_path.clone(), entry.pid));
        }
        if let Some(ev) = self.evicted_live.get_mut(instance_id) {
            if ev.has_motw {
                return None;
            }
            ev.has_motw = true;
            let exe_key = ev.exe_key.clone();
            let exe_path = ev.exe_path.clone();
            let pid = ev.identity.pid;
            if !exe_key.is_empty() {
                *self.evicted_live_motw_exe_counts.entry(exe_key).or_insert(0) += 1;
            }
            return Some((exe_path, pid));
        }
        None
    }

    /// Returns `true` if any currently unexited process matching `target_exe_key` carries MOTW
    /// origin metadata (`L-18`), including live processes displaced under capacity pressure.
    pub fn has_active_motw_for_exe_key(&self, target_exe_key: &str) -> bool {
        if self.evicted_live_motw_overflow_any
            || self.evicted_live_motw_exe_counts.contains_key(target_exe_key)
            || self.overflowed_evicted_live_motw_exes.contains(target_exe_key)
        {
            return true;
        }
        self.entries.values().any(|entry| {
            entry.exited_at_ms.is_none()
                && entry.origin_url.is_some()
                && !entry.exe_path.trim().is_empty()
                && normalized_exe_key_eq(&entry.exe_path, target_exe_key)
        })
    }

    /// Marks `rule_id` as having emitted an alert for `instance_id`, returning `true` only on
    /// the first alert for that `(instance_id, rule_id)` pair (or when `instance_id` is uncached).
    pub fn mark_rule_alert_emitted(&mut self, instance_id: &str, rule_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(instance_id) {
            return entry.emitted_rule_ids.insert(rule_id.to_string());
        }
        if let Some(evicted) = self.evicted_exited.get_mut(instance_id) {
            return evicted.emitted_rule_ids.insert(rule_id.to_string());
        }
        true
    }

    /// Clears a previously emitted `(instance_id, rule_id)` alert deduplication mark so
    /// subsequent matches for that rule/canary target can re-evaluate (`BUG_0006` / `BUG_0004`).
    pub fn clear_rule_alert_emitted(&mut self, instance_id: &str, rule_id: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(instance_id) {
            return entry.emitted_rule_ids.remove(rule_id);
        }
        if let Some(evicted) = self.evicted_exited.get_mut(instance_id) {
            return evicted.emitted_rule_ids.remove(rule_id);
        }
        false
    }

    /// Returns `true` when `rule_id` was already marked emitted for `instance_id`
    /// (`ANALYSIS_0002` — read-only dedup check that does not consume the first-emit slot).
    pub fn has_rule_alert_emitted(&self, instance_id: &str, rule_id: &str) -> bool {
        self.entries
            .get(instance_id)
            .is_some_and(|entry| entry.emitted_rule_ids.contains(rule_id))
            || self
                .evicted_exited
                .get(instance_id)
                .is_some_and(|evicted| evicted.emitted_rule_ids.contains(rule_id))
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
                        && e.identity.create_time_100ns >= parent.create_time_100ns
                        && !visited.contains(&e.identity)
                        && !is_never_suspend_process(&e.exe_path)
                        && (e.parent_instance_id.as_deref() == Some(parent_id.as_str())
                            || (e.parent_instance_id.is_none() && e.ppid == parent.pid))
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

    fn parent_metadata_from_entry(
        entry: &ActiveProcessEntry,
    ) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(entry.instance_id.clone()),
            Some(entry.exe_path.clone()),
            (!entry.command_line.is_empty()).then(|| entry.command_line.clone()),
        )
    }

    fn parent_metadata_from_evicted(
        evicted: &EvictedExitedRecord,
    ) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(evicted.identity.instance_id()),
            (!evicted.exe_path.is_empty()).then(|| evicted.exe_path.clone()),
            evicted.command_line.as_complete().map(str::to_string),
        )
    }

    /// Looks up `(parent_instance_id, parent_exe_path, parent_command_line)` by `parent_id`,
    /// checking active/cached entries first and falling back to bounded evicted-exited history.
    pub fn parent_metadata_by_id(
        &self,
        parent_id: &str,
    ) -> (Option<String>, Option<String>, Option<String>) {
        if let Some(parent_entry) = self.entries.get(parent_id) {
            Self::parent_metadata_from_entry(parent_entry)
        } else if let Some(evicted_parent) = self.evicted_exited.get(parent_id) {
            Self::parent_metadata_from_evicted(evicted_parent)
        } else {
            (Some(parent_id.to_string()), None, None)
        }
    }

    fn lookup_parent_for(
        &self,
        parent_pid: u32,
        child_identity: ProcessIdentity,
        child_created_at_ms: i64,
        allow_unverified_parent: bool,
    ) -> (Option<String>, Option<String>, Option<String>) {
        if parent_pid == 0 || parent_pid == child_identity.pid {
            return (None, None, None);
        }

        let matches_verified_parent = |entry: &&ActiveProcessEntry| -> bool {
            entry.identity.pid == parent_pid
                && entry.identity.create_time_100ns != 0
                && entry.created_at_ms <= child_created_at_ms
                && entry
                    .exited_at_ms
                    .is_none_or(|exit_ts| child_created_at_ms <= exit_ts)
                && (child_identity.create_time_100ns == 0
                    || entry.identity.create_time_100ns <= child_identity.create_time_100ns)
        };

        let verified_parent = self
            .lookup_by_pid(parent_pid)
            .filter(matches_verified_parent)
            .or_else(|| {
                self.entries
                    .values()
                    .filter(matches_verified_parent)
                    .max_by_key(|e| (e.created_at_ms, e.identity.create_time_100ns))
            });

        if let Some(entry) = verified_parent {
            return Self::parent_metadata_from_entry(entry);
        }

        let evicted_parent = self
            .evicted_exited
            .values()
            .filter(|ev| {
                ev.identity.pid == parent_pid
                    && ev.identity.create_time_100ns != 0
                    && ev.created_at_ms <= child_created_at_ms
                    && child_created_at_ms <= ev.exited_at_ms
                    && (child_identity.create_time_100ns == 0
                        || ev.identity.create_time_100ns <= child_identity.create_time_100ns)
            })
            .max_by_key(|ev| (ev.created_at_ms, ev.identity.create_time_100ns));

        if let Some(ev) = evicted_parent {
            return Self::parent_metadata_from_evicted(ev);
        }

        let unverified_parent = allow_unverified_parent
            .then(|| {
                self.lookup_by_pid(parent_pid).filter(|entry| {
                    entry.identity.create_time_100ns == 0
                        && entry
                            .exited_at_ms
                            .is_none_or(|exit_ts| child_created_at_ms <= exit_ts)
                })
            })
            .flatten();

        unverified_parent.map_or((None, None, None), Self::parent_metadata_from_entry)
    }

    fn evict_if_over_capacity(&mut self, protect_id: &str) -> Vec<String> {
        let mut evicted_ids = Vec::new();
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
                    evicted_ids.push(candidate_id);
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
                        evicted_ids.push(candidate_id);
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
        evicted_ids
    }

    fn remove_entry(&mut self, instance_id: &str) {
        if let Some(removed) = self.entries.remove(instance_id) {
            if let Some(exit_ms) = removed.exited_at_ms {
                if removed.identity.create_time_100ns != 0 {
                    let record = EvictedExitedRecord {
                        identity: removed.identity,
                        created_at_ms: removed.created_at_ms,
                        exited_at_ms: exit_ms,
                        parent_instance_id: removed.parent_instance_id,
                        exe_path: removed.exe_path,
                        command_line: EvictedCommandLine::from_owned(removed.command_line),
                        emitted_rule_ids: removed.emitted_rule_ids,
                    };
                    if self
                        .evicted_exited
                        .insert(removed.instance_id.clone(), record)
                        .is_none()
                    {
                        self.evicted_exited_fifo.push_back(removed.instance_id);
                        while self.evicted_exited.len() > MAX_EVICTED_EXITED_HISTORY {
                            let Some(oldest_id) = self.evicted_exited_fifo.pop_front() else {
                                break;
                            };
                            self.evicted_exited.remove(&oldest_id);
                        }
                    }
                }
            } else {
                self.active_count = self.active_count.saturating_sub(1);
                self.record_evicted_live(removed.instance_id, removed.identity, removed.created_at_ms, removed.exe_path, removed.origin_url.is_some());
            }
            if self.pid_to_identity.get(&removed.pid) == Some(&removed.identity) {
                self.pid_to_identity.remove(&removed.pid);
            }
        }
    }

    fn record_evicted_live(
        &mut self,
        instance_id: String,
        identity: ProcessIdentity,
        created_at_ms: i64,
        exe_path: String,
        has_motw: bool,
    ) {
        let exe_key = normalize_exe_key(&exe_path);
        if self.evicted_live_capacity == 0 {
            self.record_overflowed_evicted_live_exe(&exe_key, has_motw);
            return;
        }
        if self.evicted_live.contains_key(&instance_id) {
            self.remove_evicted_live_by_id(&instance_id);
        }
        if !exe_key.is_empty() {
            *self.evicted_live_exe_counts.entry(exe_key.clone()).or_insert(0) += 1;
            if has_motw {
                *self
                    .evicted_live_motw_exe_counts
                    .entry(exe_key.clone())
                    .or_insert(0) += 1;
            }
        }
        self.evicted_live.insert(
            instance_id.clone(),
            EvictedLiveRecord {
                identity,
                created_at_ms,
                exe_path,
                exe_key,
                has_motw,
            },
        );
        self.evicted_live_fifo.push_back(instance_id);
        while self.evicted_live.len() > self.evicted_live_capacity {
            let Some(oldest_id) = self.evicted_live_fifo.pop_front() else {
                break;
            };
            if let Some(old) = self.remove_evicted_live_by_id(&oldest_id) {
                self.record_overflowed_evicted_live_exe(&old.exe_key, old.has_motw);
            }
        }
    }

    fn record_overflowed_evicted_live_exe(&mut self, exe_key: &str, has_motw: bool) {
        if exe_key.is_empty() {
            return;
        }
        if !self.evicted_live_overflow_any {
            if self.overflowed_evicted_live_exes.len() < MAX_OVERFLOWED_EVICTED_LIVE_EXES {
                self.overflowed_evicted_live_exes.insert(exe_key.to_string());
            } else if !self.overflowed_evicted_live_exes.contains(exe_key) {
                self.evicted_live_overflow_any = true;
            }
        }
        if has_motw && !self.evicted_live_motw_overflow_any {
            if self.overflowed_evicted_live_motw_exes.len() < MAX_OVERFLOWED_EVICTED_LIVE_EXES {
                self.overflowed_evicted_live_motw_exes
                    .insert(exe_key.to_string());
            } else if !self.overflowed_evicted_live_motw_exes.contains(exe_key) {
                self.evicted_live_motw_overflow_any = true;
            }
        }
    }

    fn remove_evicted_live_by_id(&mut self, instance_id: &str) -> Option<EvictedLiveRecord> {
        let removed = self.evicted_live.remove(instance_id)?;
        if !removed.exe_key.is_empty() {
            if let Some(cnt) = self.evicted_live_exe_counts.get_mut(&removed.exe_key) {
                if *cnt <= 1 {
                    self.evicted_live_exe_counts.remove(&removed.exe_key);
                } else {
                    *cnt -= 1;
                }
            }
            if removed.has_motw {
                if let Some(cnt) = self.evicted_live_motw_exe_counts.get_mut(&removed.exe_key) {
                    if *cnt <= 1 {
                        self.evicted_live_motw_exe_counts.remove(&removed.exe_key);
                    } else {
                        *cnt -= 1;
                    }
                }
            }
        }
        if self.evicted_live_fifo.len() > self.evicted_live_capacity.saturating_mul(2).max(16) {
            let live = &self.evicted_live;
            self.evicted_live_fifo.retain(|id| live.contains_key(id));
        }
        Some(removed)
    }
}

fn normalize_exe_key(raw_exe: &str) -> String {
    let trimmed = raw_exe.trim().replace('/', "\\");
    let stripped = if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &trimmed[8..])
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case(r"\\?\"))
    {
        trimmed[4..].to_string()
    } else {
        trimmed
    };
    stripped.to_ascii_lowercase()
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

        // Time-windowed query excludes long-exited or future-spawned instances.
        let at_2200 = table.candidates_by_exe_key_at(exe_key, 250);
        let at_250_pids: Vec<u32> = at_2200.iter().map(|e| e.pid).collect();
        assert_eq!(at_250_pids, vec![7003, 7002, 7001]);

        let future_ts = table.candidates_by_exe_key_at(exe_key, 10_000);
        let future_pids: Vec<u32> = future_ts.iter().map(|e| e.pid).collect();
        assert_eq!(future_pids, vec![7003]);

        // Instance started well after event_ts_ms (> +1000 ms skew) is excluded.
        let past_ts = table.candidates_by_exe_key_at(exe_key, 50);
        assert!(past_ts.iter().all(|e| e.created_at_ms <= 1_050));
        let early_pid = ProcessIdentity::new(7004, 4000);
        table.on_process_start(early_pid, 4, exe.to_string(), String::new(), None, 5_000);
        let before_spawn = table.candidates_by_exe_key_at(exe_key, 2_000);
        assert!(!before_spawn.iter().any(|e| e.pid == 7004));
    }

    /// `PR23-R26-T1-01`: Integrating a zero-timestamp snapshot into an existing verified child
    /// must search for its parent using the child's own creation timestamp/100ns order, reject
    /// conflicting `parent_pid`, and `collect_unexited_descendants` must enforce creation order
    /// even when `parent_instance_id` matches.
    #[test]
    fn process_table_zero_ts_snapshot_rejects_reused_parent_pid_and_conflicting_ppid() {
        let mut table = ActiveProcessTable::new(32);

        // Case 1: Child B (verified) started at ms=200 with parent_pid=800 (parent A missing),
        // then unrelated C acquires reused PID 800 at ms=300. Zero-ts snapshot for B at ms=400
        // must NOT link B to C.
        let child_b = ProcessIdentity::new(900, 200_000);
        let res_b = table.on_process_start(
            child_b,
            800,
            r"C:\Tools\child_b.exe".to_string(),
            "child_b.exe".to_string(),
            None,
            200,
        );
        assert_eq!(res_b.parent_instance_id, None);

        let unrelated_c = ProcessIdentity::new(800, 300_000);
        table.on_process_start(
            unrelated_c,
            4,
            r"C:\Tools\unrelated_c.exe".to_string(),
            "unrelated_c.exe".to_string(),
            None,
            300,
        );

        let snap_b = table.on_process_start(
            ProcessIdentity::new(900, 0),
            800,
            r"C:\Tools\child_b.exe".to_string(),
            "child_b.exe".to_string(),
            None,
            400,
        );
        assert_eq!(snap_b.resolved_identity, child_b);
        assert_eq!(snap_b.parent_instance_id, None);
        assert!(snap_b.skip_store_ingest);
        assert_eq!(
            table
                .get_by_instance_id(&child_b.instance_id())
                .and_then(|e| e.parent_instance_id.as_deref()),
            None
        );
        assert!(table.collect_unexited_descendants(&unrelated_c).is_empty());

        // Case 2: Same millisecond, C2 started later in 100ns ticks than B2 must also be rejected.
        let child_b2 = ProcessIdentity::new(904, 200_005_000);
        table.on_process_start(
            child_b2,
            804,
            r"C:\Tools\child_b2.exe".to_string(),
            "child_b2.exe".to_string(),
            None,
            200,
        );
        let unrelated_c2 = ProcessIdentity::new(804, 200_009_000);
        table.on_process_start(
            unrelated_c2,
            4,
            r"C:\Tools\unrelated_c2.exe".to_string(),
            "unrelated_c2.exe".to_string(),
            None,
            200,
        );
        let snap_b2 = table.on_process_start(
            ProcessIdentity::new(904, 0),
            804,
            r"C:\Tools\child_b2.exe".to_string(),
            "child_b2.exe".to_string(),
            None,
            400,
        );
        assert_eq!(snap_b2.parent_instance_id, None);
        assert!(table.collect_unexited_descendants(&unrelated_c2).is_empty());

        // Case 3: Conflicting parent_pid (999 != known ppid 800) on zero-ts snapshot must be
        // rejected completely without mutating B or linking PID 999.
        let other_999 = ProcessIdentity::new(999, 50_000);
        table.on_process_start(
            other_999,
            4,
            r"C:\Tools\other_999.exe".to_string(),
            "other_999.exe".to_string(),
            None,
            50,
        );
        let conflict_res = table.on_process_start(
            ProcessIdentity::new(900, 0),
            999,
            r"C:\Tools\spoofed.exe".to_string(),
            "spoofed.exe --evil".to_string(),
            Some("S-1-5-18".to_string()),
            450,
        );
        assert!(conflict_res.skip_store_ingest);
        assert_eq!(conflict_res.parent_instance_id, None);
        let b_after = table
            .get_by_instance_id(&child_b.instance_id())
            .expect("child_b remains");
        assert_eq!(b_after.ppid, 800);
        assert_eq!(b_after.parent_instance_id, None);
        assert_eq!(b_after.exe_path, r"C:\Tools\child_b.exe");
        assert_eq!(b_after.command_line, "child_b.exe");
        assert_eq!(b_after.user_sid, None);

        // Case 4: Verified parent A started BEFORE child B3 (initially ppid=0) IS legitimately
        // linked when B3 receives a zero-ts snapshot carrying parent_pid=808.
        let real_parent_a = ProcessIdentity::new(808, 100_000);
        table.on_process_start(
            real_parent_a,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            "cmd.exe".to_string(),
            None,
            100,
        );
        let child_b3 = ProcessIdentity::new(908, 200_000);
        let init_b3 = table.on_process_start(
            child_b3,
            0,
            r"C:\Tools\child_b3.exe".to_string(),
            "child_b3.exe".to_string(),
            None,
            200,
        );
        assert_eq!(init_b3.parent_instance_id, None);

        let snap_b3 = table.on_process_start(
            ProcessIdentity::new(908, 0),
            808,
            String::new(),
            String::new(),
            None,
            400,
        );
        assert!(!snap_b3.skip_store_ingest);
        assert_eq!(
            snap_b3.parent_instance_id.as_deref(),
            Some(real_parent_a.instance_id().as_str())
        );
        assert_eq!(
            snap_b3.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            table.collect_unexited_descendants(&real_parent_a),
            vec![child_b3]
        );

        // Case 5: Defense-in-depth — even if an entry's `parent_instance_id` points to a
        // newer process with `create_time_100ns > child.create_time_100ns`, descendant collection
        // excludes it.
        if let Some(entry) = table.entries.get_mut(&child_b.instance_id()) {
            entry.parent_instance_id = Some(unrelated_c.instance_id());
        }
        assert!(table.collect_unexited_descendants(&unrelated_c).is_empty());
    }

    #[test]
    fn launch_guards_applied_controls_skip_launch_guards_on_reentry_and_snapshot_absorption() {
        let mut table = ActiveProcessTable::new(16);
        let ident = ProcessIdentity::new(500, 1_000_000);
        let exe = r"C:\Users\Public\Downloads\probe.exe".to_string();

        // 1. Initial registration starts with `launch_guards_applied == false`.
        let first = table.on_process_start(ident, 4, exe.clone(), String::new(), None, 100);
        assert!(!first.skip_launch_guards);
        assert!(!table
            .get_by_instance_id(&first.instance_id)
            .expect("entry present")
            .launch_guards_applied);

        // 2. Re-entry BEFORE launch guards are marked applied must NOT skip launch guards.
        let before_mark = table.on_process_start(
            ident,
            4,
            exe.clone(),
            "probe.exe --arg".to_string(),
            None,
            100,
        );
        assert!(!before_mark.skip_launch_guards);

        // 3. `pid:0` snapshot absorption BEFORE launch guards are marked applied must NOT skip,
        //    both when enriching metadata (`skip_store_ingest == false`) and when non-enriching
        //    (`skip_store_ingest == true`).
        let snap_before = table.on_process_start(
            ProcessIdentity::new(500, 0),
            4,
            exe.clone(),
            String::new(),
            Some("S-1-5-21-1".to_string()),
            150,
        );
        assert!(!snap_before.skip_store_ingest);
        assert!(!snap_before.skip_launch_guards);

        let snap_non_enriching_before = table.on_process_start(
            ProcessIdentity::new(500, 0),
            4,
            exe.clone(),
            String::new(),
            None,
            160,
        );
        assert!(snap_non_enriching_before.skip_store_ingest);
        assert!(!snap_non_enriching_before.skip_launch_guards);

        // 4. Once marked applied, both same-instance re-entry and `pid:0` absorption skip guards
        //    when `exe_path` did not newly upgrade from empty.
        assert!(table.mark_launch_guards_applied(&first.instance_id));
        let after_mark = table.on_process_start(
            ident,
            4,
            exe.clone(),
            "probe.exe --arg2".to_string(),
            None,
            100,
        );
        assert!(after_mark.skip_launch_guards);

        let snap_after = table.on_process_start(
            ProcessIdentity::new(500, 0),
            4,
            exe,
            String::new(),
            None,
            200,
        );
        assert!(snap_after.skip_launch_guards);
    }

    #[test]
    fn evicted_parent_and_child_preserve_within_budget_and_omit_oversized_cmdline() {
        let mut table = ActiveProcessTable::new(2);

        // 1. Within-budget command_line (<= MAX_EVICTED_CMDLINE_BYTES) is preserved completely.
        let parent_ok = ProcessIdentity::new(600, 1_000_000);
        let child_ok = ProcessIdentity::new(604, 1_100_000);
        let ok_cmd = "cmd.exe /c echo あいうえお --encoded".to_string();
        assert!(ok_cmd.len() <= MAX_EVICTED_CMDLINE_BYTES);
        table.on_process_start(
            parent_ok,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            ok_cmd.clone(),
            None,
            100,
        );
        let initial_child_ok = table.on_process_start(
            child_ok,
            600,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            String::new(),
            None,
            150,
        );
        assert_eq!(
            initial_child_ok.parent_instance_id.as_deref(),
            Some(parent_ok.instance_id().as_str())
        );
        assert_eq!(table.on_process_stop(600, 200), Some(parent_ok.instance_id()));
        assert_eq!(table.on_process_stop(604, 210), Some(child_ok.instance_id()));

        // 2. Oversized command_line (> MAX_EVICTED_CMDLINE_BYTES) whose 4096-byte prefix ends with
        //    " --encoded" followed by " --profile normal" MUST be omitted (`None`) on eviction
        //    so Sigma `endswith` rules never false-positive on an artificial truncation boundary.
        let parent_big = ProcessIdentity::new(608, 1_200_000);
        let child_big = ProcessIdentity::new(612, 1_300_000);
        let suffix_at_boundary = " --encoded";
        let pad_len = MAX_EVICTED_CMDLINE_BYTES - suffix_at_boundary.len();
        let oversized_cmd = format!(
            "{}{} --profile normal",
            "a".repeat(pad_len),
            suffix_at_boundary
        );
        assert!(oversized_cmd.len() > MAX_EVICTED_CMDLINE_BYTES);
        assert!(oversized_cmd[..MAX_EVICTED_CMDLINE_BYTES].ends_with(suffix_at_boundary));

        table.on_process_start(
            parent_big,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            oversized_cmd.clone(),
            None,
            300,
        );
        table.on_process_start(
            child_big,
            608,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            String::new(),
            None,
            350,
        );
        assert!(table.get_by_instance_id(&parent_ok.instance_id()).is_none());
        assert!(table.get_by_instance_id(&child_ok.instance_id()).is_none());
        assert_eq!(table.on_process_stop(608, 400), Some(parent_big.instance_id()));
        assert_eq!(table.on_process_stop(612, 410), Some(child_big.instance_id()));

        // 3. Evicted parent initially missing command_line, then receiving an oversized delayed
        //    ProcessStart, must ALSO omit `parent_command_line` rather than storing a prefix.
        let parent_late = ProcessIdentity::new(616, 1_400_000);
        let child_late = ProcessIdentity::new(620, 1_500_000);
        table.on_process_start(
            parent_late,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            String::new(),
            None,
            500,
        );
        table.on_process_start(
            child_late,
            616,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            String::new(),
            None,
            550,
        );
        assert!(table.get_by_instance_id(&parent_big.instance_id()).is_none());
        assert!(table.get_by_instance_id(&child_big.instance_id()).is_none());
        assert_eq!(
            table.on_process_stop(616, 600),
            Some(parent_late.instance_id())
        );
        assert_eq!(
            table.on_process_stop(620, 610),
            Some(child_late.instance_id())
        );

        // Evict parent_late and child_late too.
        table.on_process_start(
            ProcessIdentity::new(624, 1_600_000),
            4,
            "f1.exe".to_string(),
            String::new(),
            None,
            700,
        );
        table.on_process_start(
            ProcessIdentity::new(628, 1_700_000),
            4,
            "f2.exe".to_string(),
            String::new(),
            None,
            710,
        );
        assert!(table.get_by_instance_id(&parent_late.instance_id()).is_none());
        assert!(table.get_by_instance_id(&child_late.instance_id()).is_none());

        // Verify Case 1 (within-budget): complete parent cmdline recovered verbatim.
        let delayed_ok = table.on_process_start(
            child_ok,
            600,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -EncodedCommand SQBFAFgA".to_string(),
            None,
            150,
        );
        assert_eq!(delayed_ok.exited_at_ms, Some(210));
        assert!(delayed_ok.skip_launch_guards);
        assert_eq!(
            delayed_ok.parent_instance_id.as_deref(),
            Some(parent_ok.instance_id().as_str())
        );
        assert_eq!(
            delayed_ok.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(delayed_ok.parent_command_line.as_deref(), Some(ok_cmd.as_str()));

        // Verify Case 2 (oversized on eviction): parent_exe_path preserved, parent_command_line omitted.
        let delayed_big = table.on_process_start(
            child_big,
            608,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -EncodedCommand SQBFAFgA".to_string(),
            None,
            350,
        );
        assert_eq!(
            delayed_big.parent_instance_id.as_deref(),
            Some(parent_big.instance_id().as_str())
        );
        assert_eq!(
            delayed_big.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(delayed_big.parent_command_line, None);

        // Oversized state must remain immutable even if a shorter delayed event arrives for parent_big.
        let _ = table.on_process_start(
            parent_big,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            "cmd.exe --encoded".to_string(),
            None,
            300,
        );
        let (_, _, after_retry_cmd) = table.parent_metadata_by_id(&parent_big.instance_id());
        assert_eq!(after_retry_cmd, None);

        // Verify Case 3 (oversized on delayed enrichment of evicted parent): omitted (`None`).
        let _ = table.on_process_start(
            parent_late,
            4,
            r"C:\Windows\System32\cmd.exe".to_string(),
            oversized_cmd,
            None,
            500,
        );
        let delayed_late = table.on_process_start(
            child_late,
            616,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string(),
            "powershell.exe -NoProfile".to_string(),
            None,
            550,
        );
        assert_eq!(
            delayed_late.parent_instance_id.as_deref(),
            Some(parent_late.instance_id().as_str())
        );
        assert_eq!(
            delayed_late.parent_exe_path.as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(delayed_late.parent_command_line, None);
    }

    /// Regression test `PROCESS-EVICT-LIVE-01` (`PRRT_kwDOVyjVyM66ksZW`):
    /// verifies that evicting a still-running (`exited_at_ms == None`) entry under capacity
    /// pressure retains its liveness in `evicted_live` (and fails closed on secondary overflow),
    /// resolves `on_process_stop_with_exe` with its concrete `exe_path`, handles PID reuse
    /// supersession, and updates MOTW tracking on evicted live instances.
    #[test]
    fn process_table_evicted_live_preserves_liveness_handles_stop_pid_reuse_and_overflow() {
        let mut table = ActiveProcessTable::new(2);
        let live1 = ProcessIdentity::new(7101, 1_000_000);
        let live2 = ProcessIdentity::new(7102, 1_100_000);
        let pad1 = ProcessIdentity::new(7103, 1_200_000);
        let exe_a = r"C:\Users\Alice\Downloads\evicted_live_a.exe";
        let exe_a_key = normalize_exe_key(exe_a);

        table.on_process_start(live1, 4, exe_a.to_string(), "a.exe".to_string(), None, 100);
        table.on_process_start(
            live2,
            4,
            r"C:\Program Files\Pad\p2.exe".to_string(),
            "p2.exe".to_string(),
            None,
            110,
        );
        // Third active process evicts still-running `live1` from primary `entries`.
        let res = table.on_process_start(
            pad1,
            4,
            r"C:\Program Files\Pad\p1.exe".to_string(),
            "p1.exe".to_string(),
            None,
            120,
        );
        assert_eq!(res.evicted_instance_ids, vec![live1.instance_id()]);
        assert_eq!(table.total_len(), 2);
        assert!(table.get_by_instance_id(&live1.instance_id()).is_none());
        assert!(
            table.has_active_exe_key(&exe_a_key),
            "evicted live instance must remain active in has_active_exe_key"
        );
        assert!(
            table
                .active_instance_ids()
                .iter()
                .any(|id| id == &live1.instance_id()),
            "active_instance_ids must include evicted live instance"
        );
        assert!(
            table
                .active_exe_paths()
                .iter()
                .any(|p| p.eq_ignore_ascii_case(exe_a)),
            "active_exe_paths must include evicted live executable"
        );

        // Delayed MOTW backfill on an evicted live process updates MOTW liveness.
        assert!(!table.has_active_motw_for_exe_key(&exe_a_key));
        assert_eq!(
            table.set_motw_metadata_if_active(
                &live1.instance_id(),
                "https://dl.example.com/a.exe".to_string(),
                "ADS_ZONE_IDENTIFIER".to_string(),
                None,
                None,
                Some(3),
            ),
            Some((exe_a.to_string(), live1.pid))
        );
        assert!(table.has_active_motw_for_exe_key(&exe_a_key));

        // Explicit ProcessStop for the evicted live process resolves both instance_id and exe_path
        // and clears liveness cleanly.
        assert_eq!(
            table.on_process_stop_with_exe(live1.pid, 200),
            Some((live1.instance_id(), exe_a.to_string()))
        );
        assert!(!table.has_active_exe_key(&exe_a_key));
        assert!(!table.has_active_motw_for_exe_key(&exe_a_key));

        // PID reuse supersedes an evicted live entry whose ProcessStop was missed.
        let reused_old = ProcessIdentity::new(7200, 2_000_000);
        let reused_exe = r"C:\Users\Alice\Downloads\reused_evicted.exe";
        let reused_key = normalize_exe_key(reused_exe);
        table.on_process_start(
            reused_old,
            4,
            reused_exe.to_string(),
            "old.exe".to_string(),
            None,
            300,
        );
        table.on_process_start(
            ProcessIdentity::new(7201, 2_100_000),
            4,
            r"C:\Program Files\Pad\q1.exe".to_string(),
            "q1.exe".to_string(),
            None,
            310,
        );
        table.on_process_start(
            ProcessIdentity::new(7202, 2_200_000),
            4,
            r"C:\Program Files\Pad\q2.exe".to_string(),
            "q2.exe".to_string(),
            None,
            320,
        );
        assert!(table.get_by_instance_id(&reused_old.instance_id()).is_none());
        assert!(table.has_active_exe_key(&reused_key));

        let reused_new = ProcessIdentity::new(7200, 2_500_000);
        let reuse_res = table.on_process_start(
            reused_new,
            4,
            r"C:\Program Files\Benign\new.exe".to_string(),
            "new.exe".to_string(),
            None,
            400,
        );
        assert_eq!(
            reuse_res.superseded_exit,
            Some((reused_old.instance_id(), 400))
        );
        assert!(
            !table.has_active_exe_key(&reused_key),
            "PID reuse must clear superseded evicted live executable"
        );

        // Secondary overflow (`evicted_live_capacity = 1`) must fail closed on `has_active_exe_key`.
        let mut small = ActiveProcessTable::new(1).with_evicted_live_capacity(1);
        let ov_exe = r"C:\Users\Alice\Downloads\overflow_live.exe";
        let ov_key = normalize_exe_key(ov_exe);
        small.on_process_start(
            ProcessIdentity::new(7301, 3_000_000),
            4,
            ov_exe.to_string(),
            "ov.exe".to_string(),
            None,
            500,
        );
        small.on_process_start(
            ProcessIdentity::new(7302, 3_100_000),
            4,
            r"C:\Program Files\Pad\ov_p1.exe".to_string(),
            "ov_p1.exe".to_string(),
            None,
            510,
        );
        small.on_process_start(
            ProcessIdentity::new(7303, 3_200_000),
            4,
            r"C:\Program Files\Pad\ov_p2.exe".to_string(),
            "ov_p2.exe".to_string(),
            None,
            520,
        );
        assert!(
            small.has_active_exe_key(&ov_key),
            "evicted_live secondary overflow must stay fail-closed for the overflowed executable"
        );
    }
}
