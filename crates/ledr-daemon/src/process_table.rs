//! Bounded O(1) in-memory active process table for parent-child correlation (`決定記録 L-12`).

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::sync::{Arc, Mutex, Weak};

use ledr_proto::{is_never_suspend_process, ProcessIdentity, ACTIVE_PROCESS_TABLE_CAPACITY};

const MAX_EVICTED_EXITED_HISTORY: usize = 1024;
const MAX_EVICTED_CMDLINE_BYTES: usize = 4096;
const MAX_EVICTED_LIVE_HISTORY: usize = ACTIVE_PROCESS_TABLE_CAPACITY;
const MAX_OVERFLOWED_EVICTED_LIVE_EXES: usize = ACTIVE_PROCESS_TABLE_CAPACITY;
pub(crate) const PATH_INTERNER_MAX_ENTRIES: usize = 8_192;

/// Bounded weak-reference string interner for deduplicating repeated `exe_path`, `exe_key`, and
/// `domain` allocations (`FU-E2E-03` Track 1c).
///
/// Lock-order invariant: `PathInterner` MUST remain a strict **leaf lock** (`firewall ->
/// process_table -> path_interner`). It must NEVER acquire `process_table` or `firewall`.
#[derive(Debug)]
pub(crate) struct PathInterner {
    max_entries: usize,
    hasher: RandomState,
    empty: Arc<str>,
    entries: HashMap<u64, Weak<str>>,
}

impl Default for PathInterner {
    fn default() -> Self {
        Self::new(PATH_INTERNER_MAX_ENTRIES)
    }
}

impl PathInterner {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            hasher: RandomState::new(),
            empty: Arc::from(""),
            entries: HashMap::new(),
        }
    }

    fn hash_str(&self, value: &str) -> u64 {
        self.hasher.hash_one(value)
    }

    pub(crate) fn intern(&mut self, value: &str) -> Arc<str> {
        if value.is_empty() {
            return Arc::clone(&self.empty);
        }
        let hash = self.hash_str(value);
        if let Some(slot) = self.entries.get_mut(&hash) {
            if let Some(existing) = slot.upgrade() {
                if existing.as_ref() == value {
                    return existing;
                }
                return Arc::from(value);
            }
            let arc: Arc<str> = Arc::from(value);
            *slot = Arc::downgrade(&arc);
            return arc;
        }
        if self.entries.len() >= self.max_entries {
            self.sweep_dead();
            if self.entries.len() >= self.max_entries {
                return Arc::from(value);
            }
        }
        let arc: Arc<str> = Arc::from(value);
        self.entries.insert(hash, Arc::downgrade(&arc));
        arc
    }

    pub(crate) fn intern_shared(interner: &Arc<Mutex<Self>>, value: &str) -> Arc<str> {
        if value.is_empty() {
            return Arc::from("");
        }
        interner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .intern(value)
    }

    pub(crate) fn sweep_dead(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, weak| weak.strong_count() > 0);
        let shrink_target = self.entries.len().saturating_mul(2).max(64);
        if self.entries.capacity() > shrink_target {
            self.entries.shrink_to(shrink_target);
        }
        before.saturating_sub(self.entries.len())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn live_len(&self) -> usize {
        self.entries.values().filter(|w| w.strong_count() > 0).count()
    }

    #[cfg(test)]
    pub(crate) fn max_entries(&self) -> usize {
        self.max_entries
    }
}

/// Process metadata cached in memory for O(1) parent context lookup during rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveProcessEntry {
    pub identity: ProcessIdentity,
    pub instance_id: String,
    pub pid: u32,
    pub ppid: u32,
    pub parent_instance_id: Option<String>,
    pub exe_path: Arc<str>,
    pub command_line: String,
    pub user_sid: Option<String>,
    pub package_family_name: Option<String>,
    pub package_sid: Option<String>,
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
    /// All active or evicted-live `(process_instance_id, exe_path)` instances superseded by PID
    /// reuse during this `ProcessStart` so the engine can release per-instance firewall/DNS state
    /// and re-check unused non-startup `Preemptive` WFP blocks using the same path as
    /// `ProcessStop` (`PRRT_kwDOVyjVyM66k6ks`).
    pub superseded_exited_processes: Vec<(String, String)>,
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
    exe_path: Arc<str>,
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
    exe_path: Arc<str>,
    exe_key: Arc<str>,
    has_motw: bool,
    package_family_name: Option<String>,
    package_sid: Option<String>,
    generation: u64,
}

/// Compact WFP drop attribution snapshot avoiding cloning `emitted_rule_ids` and omitting
/// global overflow flags (`FU-E2E-05`).
#[derive(Debug)]
pub struct WfpProcessCandidates<'a> {
    pub entries: Vec<&'a ActiveProcessEntry>,
    pub evicted_live_identities: Vec<ProcessIdentity>,
    pub evicted_exited_identities: Vec<ProcessIdentity>,
    pub exe_evicted_live_overflowed: bool,
}

#[derive(Debug, Clone, Copy)]
struct QueuedParent {
    identity: ProcessIdentity,
    exited_at_ms: Option<i64>,
}

/// Bounded in-memory process table (`ACTIVE_PROCESS_TABLE_CAPACITY` = 4,096) supporting
/// O(1) lookup by `pid` or `instance_id` and evicting oldest exited entries when over capacity.
#[derive(Debug)]
pub struct ActiveProcessTable {
    capacity: usize,
    path_interner: Arc<Mutex<PathInterner>>,
    pid_to_identity: HashMap<u32, ProcessIdentity>,
    entries: HashMap<String, ActiveProcessEntry>,
    exited_fifo: VecDeque<String>,
    insertion_fifo: VecDeque<String>,
    evicted_exited: HashMap<String, EvictedExitedRecord>,
    evicted_exited_fifo: VecDeque<String>,
    evicted_live: HashMap<String, EvictedLiveRecord>,
    evicted_live_by_pid: HashMap<u32, Vec<String>>,
    evicted_live_fifo: VecDeque<(String, u64)>,
    evicted_live_seq: u64,
    evicted_live_capacity: usize,
    evicted_live_exe_counts: HashMap<Arc<str>, usize>,
    evicted_live_motw_exe_counts: HashMap<Arc<str>, usize>,
    overflowed_evicted_live_exes: HashSet<Arc<str>>,
    overflowed_evicted_live_motw_exes: HashSet<Arc<str>>,
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
            path_interner: Arc::new(Mutex::new(PathInterner::new(PATH_INTERNER_MAX_ENTRIES))),
            pid_to_identity: HashMap::with_capacity(cap.min(1024)),
            entries: HashMap::with_capacity(cap.min(1024)),
            exited_fifo: VecDeque::new(),
            insertion_fifo: VecDeque::new(),
            evicted_exited: HashMap::new(),
            evicted_exited_fifo: VecDeque::new(),
            evicted_live: HashMap::new(),
            evicted_live_by_pid: HashMap::new(),
            evicted_live_fifo: VecDeque::new(),
            evicted_live_seq: 0,
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

    pub(crate) fn path_interner(&self) -> Arc<Mutex<PathInterner>> {
        Arc::clone(&self.path_interner)
    }

    /// Frees non-lineage metadata (`motw_referrer`, `motw_frame_url`, `motw_source`,
    /// `motw_zone_id`, `user_sid`) on exited entries whose `exited_at_ms <= cutoff_ms`
    /// (`FU-E2E-03` Track 1c).
    ///
    /// Keeps entries in `entries` (no blanket 60s eviction into `evicted_exited`) and preserves
    /// `parent_instance_id`, `exe_path`, `command_line`, `emitted_rule_ids`, and `origin_url`.
    pub fn compact_exited_older_than(&mut self, cutoff_ms: i64) -> usize {
        let mut compacted = 0usize;
        for entry in self.entries.values_mut() {
            if entry
                .exited_at_ms
                .is_some_and(|exited_ms| exited_ms <= cutoff_ms)
            {
                let had_non_lineage = entry.user_sid.is_some()
                    || entry.motw_referrer.is_some()
                    || entry.motw_frame_url.is_some()
                    || entry.motw_source.is_some()
                    || entry.motw_zone_id.is_some();
                if had_non_lineage {
                    entry.user_sid = None;
                    entry.motw_referrer = None;
                    entry.motw_frame_url = None;
                    entry.motw_source = None;
                    entry.motw_zone_id = None;
                    compacted += 1;
                }
            }
        }
        compacted
    }

    /// Overrides the bounded capacity of the secondary evicted-live tracker in unit/integration
    /// tests so overflow fail-closed protection can be exercised deterministically.
    #[cfg(test)]
    pub fn with_evicted_live_capacity(mut self, capacity: usize) -> Self {
        self.evicted_live_capacity = capacity;
        self
    }

    #[cfg(test)]
    pub fn force_evicted_live_overflow_any_for_test(&mut self) {
        self.evicted_live_overflow_any = true;
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
        self.on_process_start_with_package(
            identity,
            parent_pid,
            exe_path,
            command_line,
            user_sid,
            None,
            None,
            created_at_ms,
        )
    }

    /// Variant of [`Self::on_process_start`] that also records independently gathered
    /// `package_family_name` and `package_sid` without synthesizing one from the other (`FU-P4-03`).
    #[allow(clippy::too_many_arguments)]
    pub fn on_process_start_with_package(
        &mut self,
        identity: ProcessIdentity,
        parent_pid: u32,
        exe_path: String,
        command_line: String,
        user_sid: Option<String>,
        package_family_name: Option<String>,
        package_sid: Option<String>,
        created_at_ms: i64,
    ) -> ProcessStartResolution {
        let package_family_name = normalize_optional_pkg_attr(package_family_name);
        let package_sid = normalize_optional_pkg_attr(package_sid);
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
                            superseded_exited_processes: Vec::new(),
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
                    let upgraded_pkg_pfn =
                        prev_entry.package_family_name.is_none() && package_family_name.is_some();
                    let upgraded_pkg_sid =
                        prev_entry.package_sid.is_none() && package_sid.is_some();

                    if upgraded_parent {
                        prev_entry.parent_instance_id = parent_instance_id.clone();
                    }
                    if upgraded_ppid {
                        prev_entry.ppid = parent_pid;
                    }
                    if upgraded_exe {
                        prev_entry.exe_path =
                            PathInterner::intern_shared(&self.path_interner, &exe_path);
                    }
                    if upgraded_cmd {
                        prev_entry.command_line = command_line;
                    }
                    if upgraded_sid {
                        prev_entry.user_sid = user_sid;
                    }
                    if upgraded_pkg_pfn {
                        prev_entry.package_family_name = package_family_name;
                    }
                    if upgraded_pkg_sid {
                        prev_entry.package_sid = package_sid;
                    }

                    let enriched = upgraded_parent
                        || upgraded_ppid
                        || upgraded_exe
                        || upgraded_cmd
                        || upgraded_sid
                        || upgraded_pkg_pfn
                        || upgraded_pkg_sid;
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
                        superseded_exited_processes: Vec::new(),
                        skip_store_ingest: !enriched,
                        skip_launch_guards: prev_entry.launch_guards_applied && !upgraded_exe,
                        evicted_instance_ids: Vec::new(),
                    };
                }
            }
            if let Some(ev_identity) = self.evicted_live_by_pid.get(&identity.pid).and_then(|ids| {
                ids.iter()
                    .filter_map(|id| self.evicted_live.get(id))
                    .filter(|ev| ev.identity.create_time_100ns != 0)
                    .max_by_key(|ev| (ev.created_at_ms, ev.identity.create_time_100ns))
                    .map(|ev| ev.identity)
            }) {
                return ProcessStartResolution {
                    resolved_identity: ev_identity,
                    instance_id: ev_identity.instance_id(),
                    parent_instance_id: None,
                    parent_exe_path: None,
                    parent_command_line: None,
                    should_evaluate_sigma: false,
                    exited_at_ms: None,
                    superseded_exit: None,
                    superseded_exited_processes: Vec::new(),
                    skip_store_ingest: true,
                    skip_launch_guards: true,
                    evicted_instance_ids: Vec::new(),
                };
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
                existing.exe_path = PathInterner::intern_shared(&self.path_interner, &exe_path);
            }
            if !command_line.is_empty() {
                existing.command_line = command_line;
            }
            if existing.user_sid.is_none() {
                existing.user_sid = user_sid;
            }
            if existing.package_family_name.is_none() {
                existing.package_family_name = package_family_name;
            }
            if existing.package_sid.is_none() {
                existing.package_sid = package_sid;
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
                superseded_exited_processes: Vec::new(),
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
                let interned_exe = (!exe_path.is_empty())
                    .then(|| PathInterner::intern_shared(&self.path_interner, &exe_path));
                if let Some(evicted) = self.evicted_exited.get_mut(&instance_id) {
                    if evicted.parent_instance_id.is_none() {
                        evicted.parent_instance_id = parent_instance_id.clone();
                    }
                    if evicted.exe_path.is_empty() {
                        if let Some(interned) = interned_exe {
                            evicted.exe_path = interned;
                        }
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
                    superseded_exited_processes: Vec::new(),
                    skip_store_ingest: false,
                    skip_launch_guards: true,
                    evicted_instance_ids: Vec::new(),
                };
            }
        }

        let (parent_instance_id, parent_exe_path, parent_command_line) =
            self.lookup_parent_for(parent_pid, identity, created_at_ms, true);

        let prev_pid_id = self
            .pid_to_identity
            .get(&identity.pid)
            .copied()
            .filter(|prev| *prev != identity)
            .map(|prev| prev.instance_id());
        if let Some(ref prev_id) = prev_pid_id {
            if let Some(prev_entry) = self.entries.get(prev_id) {
                if prev_entry.identity.create_time_100ns != 0
                    && (prev_entry.created_at_ms, prev_entry.identity.create_time_100ns)
                        > (created_at_ms, identity.create_time_100ns)
                {
                    // Arriving ProcessStart is older than the already-registered process for this PID:
                    // preserve the newer active mapping and record this older incarnation as exited.
                    let inferred_exit_ms = prev_entry.created_at_ms;
                    let interned_exe = PathInterner::intern_shared(&self.path_interner, &exe_path);
                    self.entries.insert(
                        instance_id.clone(),
                        ActiveProcessEntry {
                            identity,
                            instance_id: instance_id.clone(),
                            pid: identity.pid,
                            ppid: parent_pid,
                            parent_instance_id: parent_instance_id.clone(),
                            exe_path: interned_exe,
                            command_line,
                            user_sid,
                            package_family_name,
                            package_sid,
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
                        superseded_exited_processes: Vec::new(),
                        skip_store_ingest: false,
                        skip_launch_guards: true,
                        evicted_instance_ids,
                    };
                }
            }
        }

        // O(1) PID-indexed check against evicted live processes (`PRRT_kwDOVyjVyM66k6mA`).
        if let Some(inferred_exit_ms) = self.evicted_live_by_pid.get(&identity.pid).and_then(|ids| {
            ids.iter()
                .filter_map(|id| self.evicted_live.get(id))
                .filter(|ev| {
                    ev.identity != identity
                        && ev.identity.create_time_100ns != 0
                        && (ev.created_at_ms, ev.identity.create_time_100ns)
                            > (created_at_ms, identity.create_time_100ns)
                })
                .map(|ev| ev.created_at_ms)
                .max()
        }) {
            self.remove_evicted_live_by_id(&instance_id);
            let interned_exe = PathInterner::intern_shared(&self.path_interner, &exe_path);
            self.entries.insert(
                instance_id.clone(),
                ActiveProcessEntry {
                    identity,
                    instance_id: instance_id.clone(),
                    pid: identity.pid,
                    ppid: parent_pid,
                    parent_instance_id: parent_instance_id.clone(),
                    exe_path: interned_exe,
                    command_line,
                    user_sid,
                    package_family_name,
                    package_sid,
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
                superseded_exited_processes: Vec::new(),
                skip_store_ingest: false,
                skip_launch_guards: true,
                evicted_instance_ids,
            };
        }

        let mut superseded_exit: Option<(String, i64)> = None;
        let mut superseded_exited_processes: Vec<(String, String)> = Vec::new();
        if let Some(prev_id) = prev_pid_id {
            // If a previous process with the same PID is still marked active (missed stop or
            // `pid:0` snapshot placeholder), mark it exited without inverting its timestamp.
            if let Some(prev_entry) = self
                .entries
                .get_mut(&prev_id)
                .filter(|entry| entry.exited_at_ms.is_none())
            {
                let exit_ms = created_at_ms.max(prev_entry.created_at_ms);
                prev_entry.exited_at_ms = Some(exit_ms);
                let prev_exe_path = prev_entry.exe_path.to_string();
                self.active_count = self.active_count.saturating_sub(1);
                self.exited_fifo.push_back(prev_id.clone());
                superseded_exit = Some((prev_id.clone(), exit_ms));
                superseded_exited_processes.push((prev_id, prev_exe_path));
            }
        }

        // Re-inserting an evicted live instance removes its duplicate evicted-live record so
        // per-exe counts remain exact (O(1) hash lookup).
        self.remove_evicted_live_by_id(&instance_id);
        if let Some(older_evicted_ids) = self.evicted_live_by_pid.get(&identity.pid).map(|ids| {
            ids.iter()
                .filter(|id| id.as_str() != instance_id.as_str())
                .cloned()
                .collect::<Vec<_>>()
        }) {
            let mut latest_evicted: Option<(String, i64, u64)> = None;
            for ev_id in older_evicted_ids {
                if let Some(ev) = self.remove_evicted_live_by_id(&ev_id) {
                    let key = (ev.created_at_ms, ev.identity.create_time_100ns);
                    if latest_evicted
                        .as_ref()
                        .is_none_or(|(_, c, ct)| key > (*c, *ct))
                    {
                        latest_evicted =
                            Some((ev_id.clone(), ev.created_at_ms, ev.identity.create_time_100ns));
                    }
                    superseded_exited_processes.push((ev_id, ev.exe_path.to_string()));
                }
            }
            if let Some((latest_id, latest_created, _)) = latest_evicted {
                if superseded_exit.is_none() {
                    superseded_exit = Some((latest_id, created_at_ms.max(latest_created)));
                }
            }
        }

        let interned_exe = PathInterner::intern_shared(&self.path_interner, &exe_path);
        self.pid_to_identity.insert(identity.pid, identity);
        self.entries.insert(
            instance_id.clone(),
            ActiveProcessEntry {
                identity,
                instance_id: instance_id.clone(),
                pid: identity.pid,
                ppid: parent_pid,
                parent_instance_id: parent_instance_id.clone(),
                exe_path: interned_exe,
                command_line,
                user_sid,
                package_family_name,
                package_sid,
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
            superseded_exited_processes,
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
        self.on_process_stop_with_package(pid, exited_at_ms)
            .map(|(id, exe, _, _)| (id, exe))
    }

    /// Variant of [`Self::on_process_stop_with_exe`] that also returns collected
    /// `(package_family_name, package_sid)` from either primary `entries` or `evicted_live`.
    pub fn on_process_stop_with_package(
        &mut self,
        pid: u32,
        exited_at_ms: i64,
    ) -> Option<(String, String, Option<String>, Option<String>)> {
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
            let exe_path = entry.exe_path.to_string();
            let pfn = entry.package_family_name.clone();
            let sid = entry.package_sid.clone();
            return Some((target_id, exe_path, pfn, sid));
        }

        if let Some(ev_id) = self.evicted_live_by_pid.get(&pid).and_then(|ids| {
            ids.iter()
                .filter_map(|id| self.evicted_live.get(id).map(|ev| (id, ev)))
                .filter(|(_, ev)| ev.created_at_ms <= exited_at_ms)
                .max_by_key(|(_, ev)| (ev.created_at_ms, ev.identity.create_time_100ns))
                .map(|(id, _)| id.clone())
        }) {
            if let Some(ev) = self.remove_evicted_live_by_id(&ev_id) {
                return Some((
                    ev_id,
                    ev.exe_path.to_string(),
                    ev.package_family_name,
                    ev.package_sid,
                ));
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
                    out.push(entry.exe_path.to_string());
                }
            }
        }
        for ev in self.evicted_live.values() {
            if !ev.exe_path.trim().is_empty() {
                let key = ev.exe_path.to_ascii_lowercase();
                if seen.insert(key) {
                    out.push(ev.exe_path.to_string());
                }
            }
        }
        out
    }

    /// Returns `(active_exe_paths, evicted_live_overflow_any, overflowed_evicted_live_exes)`
    /// atomically under the caller's single lock acquisition so reconciliation can fail closed
    /// against deferred preemptive block removal whenever capacity overflow hid live keys.
    pub fn active_exe_liveness_snapshot(&self) -> (Vec<String>, bool, HashSet<String>) {
        (
            self.active_exe_paths(),
            self.evicted_live_overflow_any,
            self.overflowed_evicted_live_exes
                .iter()
                .map(|s| s.to_string())
                .collect(),
        )
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

    /// Time-windowed WFP drop candidate lookup including live/recently-exited `entries`,
    /// `evicted_live`, `evicted_exited`, and per-executable `overflowed_evicted_live_exes`
    /// (excluding global `evicted_live_overflow_any` to prevent cross-executable freeze bypasses).
    pub fn candidates_by_exe_key_for_wfp(
        &self,
        target_exe_key: &str,
        event_ts_ms: i64,
        recent_exit_window_ms: i64,
        max_post_event_create_skew_ms: i64,
    ) -> WfpProcessCandidates<'_> {
        let exit_window = recent_exit_window_ms.max(0);
        let max_created = event_ts_ms.saturating_add(max_post_event_create_skew_ms.max(0));
        let mut matches: Vec<&ActiveProcessEntry> = self
            .entries
            .values()
            .filter(|entry| {
                !entry.exe_path.trim().is_empty()
                    && normalized_exe_key_eq(&entry.exe_path, target_exe_key)
                    && entry.created_at_ms <= max_created
                    && entry
                        .exited_at_ms
                        .is_none_or(|ex| event_ts_ms <= ex.saturating_add(exit_window))
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

        let norm_target = normalize_exe_key(target_exe_key);
        let evicted_live_identities: Vec<ProcessIdentity> = self
            .evicted_live
            .values()
            .filter(|ev| {
                ev.exe_key.as_ref() == norm_target && ev.created_at_ms <= max_created
            })
            .map(|ev| ev.identity)
            .collect();

        let evicted_exited_identities: Vec<ProcessIdentity> = self
            .evicted_exited
            .values()
            .filter(|ev| {
                !ev.exe_path.trim().is_empty()
                    && normalized_exe_key_eq(&ev.exe_path, &norm_target)
                    && ev.created_at_ms <= max_created
                    && event_ts_ms <= ev.exited_at_ms.saturating_add(exit_window)
            })
            .map(|ev| ev.identity)
            .collect();

        let exe_evicted_live_overflowed = self
            .overflowed_evicted_live_exes
            .contains(norm_target.as_str());

        WfpProcessCandidates {
            entries: matches,
            evicted_live_identities,
            evicted_exited_identities,
            exe_evicted_live_overflowed,
        }
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
            return Some((entry.exe_path.to_string(), entry.pid));
        }
        if let Some(ev) = self.evicted_live.get_mut(instance_id) {
            if ev.has_motw {
                return None;
            }
            ev.has_motw = true;
            let exe_key = ev.exe_key.clone();
            let exe_path = ev.exe_path.to_string();
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

    fn next_incarnation_from_index(
        create_times_by_pid: &HashMap<u32, Vec<u64>>,
        parent: ProcessIdentity,
    ) -> Option<u64> {
        if parent.pid == 0 {
            return None;
        }
        let times = create_times_by_pid.get(&parent.pid)?;
        let idx = times.partition_point(|&t| t <= parent.create_time_100ns);
        times.get(idx).copied()
    }

    /// Collects unexited, non-protected descendant [`ProcessIdentity`] values of `root`
    /// currently tracked in memory (`BUG_0005`), traversing verified and bounded `ppid`-fallback
    /// exited intermediates in deterministic BFS parent-before-child order.
    pub fn collect_unexited_descendants(&self, root: &ProcessIdentity) -> Vec<ProcessIdentity> {
        if root.create_time_100ns == 0 {
            return Vec::new();
        }
        let root_id = root.instance_id();
        let root_exe_path = self
            .entries
            .get(&root_id)
            .map(|e| e.exe_path.as_ref())
            .or_else(|| self.evicted_exited.get(&root_id).map(|ev| ev.exe_path.as_ref()));
        if root_exe_path.is_some_and(is_never_suspend_process) {
            return Vec::new();
        }

        let mut by_parent_id: HashMap<&str, Vec<&ActiveProcessEntry>> = HashMap::new();
        let mut by_ppid: HashMap<u32, Vec<&ActiveProcessEntry>> = HashMap::new();
        let mut create_times_by_pid: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut record_create_time = |ident: ProcessIdentity| {
            if ident.pid != 0 && ident.create_time_100ns != 0 {
                create_times_by_pid
                    .entry(ident.pid)
                    .or_default()
                    .push(ident.create_time_100ns);
            }
        };

        for entry in self.entries.values() {
            record_create_time(entry.identity);
            if let Some(parent_id) = entry.parent_instance_id.as_deref() {
                by_parent_id.entry(parent_id).or_default().push(entry);
            } else {
                by_ppid.entry(entry.ppid).or_default().push(entry);
            }
        }
        for ev in self.evicted_exited.values() {
            record_create_time(ev.identity);
        }
        for (&pid, ids) in &self.evicted_live_by_pid {
            if pid == 0 {
                continue;
            }
            for id in ids {
                if let Some(ev) = self.evicted_live.get(id) {
                    record_create_time(ev.identity);
                }
            }
        }
        for times in create_times_by_pid.values_mut() {
            if times.len() > 1 {
                times.sort_unstable();
            }
        }

        let mut visited = HashSet::from([*root]);
        let root_exited_at_ms = self
            .entries
            .get(&root_id)
            .and_then(|e| e.exited_at_ms)
            .or_else(|| self.evicted_exited.get(&root_id).map(|ev| ev.exited_at_ms));
        let mut queue = VecDeque::new();
        queue.push_back(QueuedParent {
            identity: *root,
            exited_at_ms: root_exited_at_ms,
        });
        let mut descendants = Vec::new();

        while let Some(parent) = queue.pop_front() {
            let parent_id = parent.identity.instance_id();
            let verified_candidates = by_parent_id.get(parent_id.as_str());
            let unverified_candidates = (parent.identity.pid != 0)
                .then(|| by_ppid.get(&parent.identity.pid))
                .flatten();
            let next_cutoff = if parent.identity.pid != 0
                && (verified_candidates.is_some() || unverified_candidates.is_some())
            {
                Self::next_incarnation_from_index(&create_times_by_pid, parent.identity)
            } else {
                None
            };

            let is_common_candidate = |e: &ActiveProcessEntry| -> bool {
                e.identity.create_time_100ns != 0
                    && e.identity.create_time_100ns >= parent.identity.create_time_100ns
                    && next_cutoff.is_none_or(|c| e.identity.create_time_100ns < c)
                    && !visited.contains(&e.identity)
                    && !is_never_suspend_process(&e.exe_path)
            };

            let mut children: Vec<&ActiveProcessEntry> = Vec::new();
            if let Some(verified) = verified_candidates {
                children.extend(verified.iter().copied().filter(|e| is_common_candidate(e)));
            }

            if let Some(unverified) = unverified_candidates {
                for &e in unverified {
                    if e.pid != parent.identity.pid
                        && is_common_candidate(e)
                        && parent
                            .exited_at_ms
                            .is_none_or(|exit_ms| e.created_at_ms <= exit_ms)
                    {
                        children.push(e);
                    }
                }
            }

            children.sort_by_key(|e| (e.identity.create_time_100ns, e.pid));
            for child in children {
                if visited.insert(child.identity) {
                    if child.exited_at_ms.is_none() {
                        descendants.push(child.identity);
                    }
                    if !child.exe_path.trim().is_empty() {
                        queue.push_back(QueuedParent {
                            identity: child.identity,
                            exited_at_ms: child.exited_at_ms,
                        });
                    }
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
            Some(entry.exe_path.to_string()),
            (!entry.command_line.is_empty()).then(|| entry.command_line.clone()),
        )
    }

    fn parent_metadata_from_evicted(
        evicted: &EvictedExitedRecord,
    ) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(evicted.identity.instance_id()),
            (!evicted.exe_path.is_empty()).then(|| evicted.exe_path.to_string()),
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
                self.record_evicted_live(
                    removed.instance_id,
                    removed.identity,
                    removed.created_at_ms,
                    removed.exe_path,
                    removed.origin_url.is_some(),
                    removed.package_family_name,
                    removed.package_sid,
                );
            }
            if self.pid_to_identity.get(&removed.pid) == Some(&removed.identity) {
                self.pid_to_identity.remove(&removed.pid);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_evicted_live(
        &mut self,
        instance_id: String,
        identity: ProcessIdentity,
        created_at_ms: i64,
        exe_path: Arc<str>,
        has_motw: bool,
        package_family_name: Option<String>,
        package_sid: Option<String>,
    ) {
        let exe_key_str = normalize_exe_key(&exe_path);
        let exe_key = PathInterner::intern_shared(&self.path_interner, &exe_key_str);
        if self.evicted_live_capacity == 0 {
            self.record_overflowed_evicted_live_exe(&exe_key, has_motw);
            return;
        }
        if self.evicted_live.contains_key(&instance_id) {
            self.remove_evicted_live_by_id(&instance_id);
        }
        self.evicted_live_seq = self.evicted_live_seq.wrapping_add(1);
        let generation = self.evicted_live_seq;
        if !exe_key.is_empty() {
            *self
                .evicted_live_exe_counts
                .entry(Arc::clone(&exe_key))
                .or_insert(0) += 1;
            if has_motw {
                *self
                    .evicted_live_motw_exe_counts
                    .entry(Arc::clone(&exe_key))
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
                package_family_name,
                package_sid,
                generation,
            },
        );
        self.evicted_live_by_pid
            .entry(identity.pid)
            .or_default()
            .push(instance_id.clone());
        self.evicted_live_fifo.push_back((instance_id, generation));
        while self.evicted_live.len() > self.evicted_live_capacity {
            let Some((oldest_id, oldest_gen)) = self.evicted_live_fifo.pop_front() else {
                break;
            };
            if self
                .evicted_live
                .get(&oldest_id)
                .is_none_or(|rec| rec.generation != oldest_gen)
            {
                continue;
            }
            if let Some(old) = self.remove_evicted_live_by_id(&oldest_id) {
                self.record_overflowed_evicted_live_exe(&old.exe_key, old.has_motw);
            }
        }
    }

    fn record_overflowed_evicted_live_exe(&mut self, exe_key: &Arc<str>, has_motw: bool) {
        if exe_key.is_empty() {
            return;
        }
        if !self.evicted_live_overflow_any {
            if self.overflowed_evicted_live_exes.len() < MAX_OVERFLOWED_EVICTED_LIVE_EXES {
                self.overflowed_evicted_live_exes
                    .insert(Arc::clone(exe_key));
            } else if !self.overflowed_evicted_live_exes.contains(exe_key.as_ref()) {
                self.evicted_live_overflow_any = true;
            }
        }
        if has_motw && !self.evicted_live_motw_overflow_any {
            if self.overflowed_evicted_live_motw_exes.len() < MAX_OVERFLOWED_EVICTED_LIVE_EXES {
                self.overflowed_evicted_live_motw_exes
                    .insert(Arc::clone(exe_key));
            } else if !self
                .overflowed_evicted_live_motw_exes
                .contains(exe_key.as_ref())
            {
                self.evicted_live_motw_overflow_any = true;
            }
        }
    }

    fn remove_evicted_live_by_id(&mut self, instance_id: &str) -> Option<EvictedLiveRecord> {
        let removed = self.evicted_live.remove(instance_id)?;
        if let Some(ids) = self.evicted_live_by_pid.get_mut(&removed.identity.pid) {
            ids.retain(|id| id != instance_id);
            if ids.is_empty() {
                self.evicted_live_by_pid.remove(&removed.identity.pid);
            }
        }
        if !removed.exe_key.is_empty() {
            if let Some(cnt) = self
                .evicted_live_exe_counts
                .get_mut(removed.exe_key.as_ref())
            {
                if *cnt <= 1 {
                    self.evicted_live_exe_counts
                        .remove(removed.exe_key.as_ref());
                } else {
                    *cnt -= 1;
                }
            }
            if removed.has_motw {
                if let Some(cnt) = self
                    .evicted_live_motw_exe_counts
                    .get_mut(removed.exe_key.as_ref())
                {
                    if *cnt <= 1 {
                        self.evicted_live_motw_exe_counts
                            .remove(removed.exe_key.as_ref());
                    } else {
                        *cnt -= 1;
                    }
                }
            }
        }
        if self.evicted_live_fifo.len() > self.evicted_live_capacity.saturating_mul(2).max(16) {
            let live = &self.evicted_live;
            self.evicted_live_fifo
                .retain(|(id, gen)| live.get(id).is_some_and(|rec| rec.generation == *gen));
        }
        Some(removed)
    }
}

fn normalize_optional_pkg_attr(raw: Option<String>) -> Option<String> {
    raw.and_then(|s| {
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
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
        assert_eq!(a_entry.exe_path.as_ref(), "a_full.exe");
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
        assert_eq!(b_after.exe_path.as_ref(), r"C:\Tools\child_b.exe");
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

    fn start_test_proc(
        table: &mut ActiveProcessTable,
        pid: u32,
        create_time_100ns: u64,
        parent_pid: u32,
        exe_path: &str,
        created_at_ms: i64,
    ) -> ProcessIdentity {
        let ident = ProcessIdentity::new(pid, create_time_100ns);
        table.on_process_start(
            ident,
            parent_pid,
            exe_path.to_string(),
            String::new(),
            None,
            created_at_ms,
        );
        ident
    }

    /// `PROC-DESC-01`: Single-hop and multi-hop exited intermediate parents capture live
    /// grandchildren/great-grandchildren while excluding exited intermediates and exited leaves.
    #[test]
    fn proc_desc_01_exited_intermediates_capture_live_descendants_only() {
        let mut table = ActiveProcessTable::new(32);
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 10);

        let mid1 = start_test_proc(&mut table, 200, 2_000, 100, r"C:\Tools\launcher1.exe", 20);
        let leaf1 = start_test_proc(&mut table, 300, 3_000, 200, r"C:\Tools\payload1.exe", 25);
        assert_eq!(table.on_process_stop(200, 30), Some(mid1.instance_id()));

        let mid2a = start_test_proc(&mut table, 201, 4_000, 100, r"C:\Tools\launcher2a.exe", 40);
        let mid2b = start_test_proc(&mut table, 202, 5_000, 201, r"C:\Tools\launcher2b.exe", 45);
        let leaf2 = start_test_proc(&mut table, 301, 6_000, 202, r"C:\Tools\payload2.exe", 48);
        let leaf_exited =
            start_test_proc(&mut table, 302, 7_000, 202, r"C:\Tools\dead_child.exe", 49);
        assert_eq!(table.on_process_stop(201, 50), Some(mid2a.instance_id()));
        assert_eq!(
            table.on_process_stop(302, 52),
            Some(leaf_exited.instance_id())
        );
        assert_eq!(table.on_process_stop(202, 55), Some(mid2b.instance_id()));

        let unrelated =
            start_test_proc(&mut table, 400, 8_000, 4, r"C:\Tools\unrelated.exe", 60);

        let got = table.collect_unexited_descendants(&root);
        assert_eq!(got, vec![leaf1, leaf2]);
        for excluded in [root, mid1, mid2a, mid2b, leaf_exited, unrelated] {
            assert!(!got.contains(&excluded));
        }
    }

    /// `PROC-DESC-02`: Multiple exited intermediate parents preserve deterministic BFS order by
    /// `(create_time_100ns, pid)`.
    #[test]
    fn proc_desc_02_multiple_exited_intermediates_deterministic_bfs_order() {
        let mut table = ActiveProcessTable::new(32);
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 10);

        // Insert level-1 children out of sorted order, including equal `create_time_100ns` tie.
        let direct_live =
            start_test_proc(&mut table, 199, 18_000, 100, r"C:\Tools\direct.exe", 40);
        let mid_3 = start_test_proc(&mut table, 203, 15_000, 100, r"C:\Tools\mid3.exe", 30);
        let mid_2 = start_test_proc(&mut table, 201, 15_000, 100, r"C:\Tools\mid2.exe", 30);
        let mid_1 = start_test_proc(&mut table, 205, 10_000, 100, r"C:\Tools\mid1.exe", 20);

        // Insert grandchildren in reverse order of expected BFS expansion.
        let ggc_direct =
            start_test_proc(&mut table, 401, 40_000, 199, r"C:\Tools\ggc.exe", 45);
        let gc_3 = start_test_proc(&mut table, 303, 26_000, 203, r"C:\Tools\gc3.exe", 32);
        let gc_2 = start_test_proc(&mut table, 302, 25_000, 201, r"C:\Tools\gc2.exe", 32);
        let gc_1 = start_test_proc(&mut table, 301, 30_000, 205, r"C:\Tools\gc1.exe", 22);

        assert_eq!(table.on_process_stop(205, 25), Some(mid_1.instance_id()));
        assert_eq!(table.on_process_stop(201, 35), Some(mid_2.instance_id()));
        assert_eq!(table.on_process_stop(203, 35), Some(mid_3.instance_id()));

        let got = table.collect_unexited_descendants(&root);
        assert_eq!(got, vec![direct_live, gc_1, gc_2, gc_3, ggc_direct]);
    }

    /// `PROC-DESC-03`: Out-of-order child arrival (`parent_instance_id == None`) resolves via
    /// bounded `ppid` fallback across exited intermediates and exited roots.
    #[test]
    fn proc_desc_03_out_of_order_ppid_fallback_through_exited_parents() {
        let mut table = ActiveProcessTable::new(32);

        // Case A: grandchild arrives before exited intermediate `mid`.
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 10);
        let grandchild =
            start_test_proc(&mut table, 300, 15_000, 200, r"C:\Tools\grandchild.exe", 150);
        assert_eq!(
            table
                .get_by_instance_id(&grandchild.instance_id())
                .expect("grandchild present")
                .parent_instance_id,
            None
        );
        let mid = start_test_proc(&mut table, 200, 10_000, 100, r"C:\Tools\mid.exe", 100);
        assert_eq!(table.on_process_stop(200, 200), Some(mid.instance_id()));
        assert_eq!(table.collect_unexited_descendants(&root), vec![grandchild]);

        // Case B: direct child arrives before exited root.
        let late_child =
            start_test_proc(&mut table, 500, 25_000, 400, r"C:\Tools\late_child.exe", 120);
        assert_eq!(
            table
                .get_by_instance_id(&late_child.instance_id())
                .expect("late_child present")
                .parent_instance_id,
            None
        );
        let late_root =
            start_test_proc(&mut table, 400, 20_000, 4, r"C:\Tools\late_root.exe", 100);
        assert_eq!(
            table.on_process_stop(400, 150),
            Some(late_root.instance_id())
        );
        assert_eq!(
            table.collect_unexited_descendants(&late_root),
            vec![late_child]
        );
    }

    /// `PROC-DESC-04`: Exited parent `ppid` fallback allows `created_at_ms == exited_at_ms` and
    /// rejects `created_at_ms == exited_at_ms + 1`.
    #[test]
    fn proc_desc_04_exited_parent_ppid_fallback_ms_boundary() {
        let mut table = ActiveProcessTable::new(32);
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 50);

        let at_exit = start_test_proc(&mut table, 301, 12_000, 200, r"C:\Tools\at_exit.exe", 200);
        let after_exit =
            start_test_proc(&mut table, 302, 13_000, 200, r"C:\Tools\after_exit.exe", 201);
        assert_eq!(
            table
                .get_by_instance_id(&at_exit.instance_id())
                .expect("at_exit")
                .parent_instance_id,
            None
        );
        assert_eq!(
            table
                .get_by_instance_id(&after_exit.instance_id())
                .expect("after_exit")
                .parent_instance_id,
            None
        );

        let mid = start_test_proc(&mut table, 200, 10_000, 100, r"C:\Tools\mid.exe", 100);
        assert_eq!(table.on_process_stop(200, 200), Some(mid.instance_id()));

        assert_eq!(table.collect_unexited_descendants(&root), vec![at_exit]);
    }

    /// `PROC-DESC-05`: Live parent (`exited_at_ms == None`) enforces 100ns reuse cutoff:
    /// `cutoff - 1` allowed, `== cutoff` rejected.
    #[test]
    fn proc_desc_05_live_parent_100ns_cutoff_boundary() {
        let mut table = ActiveProcessTable::new(32);

        // Place newer incarnation `2_000` for PID 100 in `evicted_exited` so `parent` stays live.
        let newer_inc = start_test_proc(&mut table, 100, 2_000, 4, r"C:\Tools\inc2.exe", 50);
        assert_eq!(
            table.on_process_stop(100, 60),
            Some(newer_inc.instance_id())
        );
        table.remove_entry(&newer_inc.instance_id());
        assert!(table.evicted_exited.contains_key(&newer_inc.instance_id()));

        let before_cutoff =
            start_test_proc(&mut table, 301, 1_999, 100, r"C:\Tools\before.exe", 300);
        let at_cutoff = start_test_proc(&mut table, 302, 2_000, 100, r"C:\Tools\at.exe", 300);
        assert_eq!(
            table
                .get_by_instance_id(&before_cutoff.instance_id())
                .expect("before_cutoff")
                .parent_instance_id,
            None
        );
        assert_eq!(
            table
                .get_by_instance_id(&at_cutoff.instance_id())
                .expect("at_cutoff")
                .parent_instance_id,
            None
        );

        let parent = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\parent.exe", 100);
        assert_eq!(
            table
                .get_by_instance_id(&parent.instance_id())
                .expect("parent")
                .exited_at_ms,
            None
        );

        assert_eq!(
            table.collect_unexited_descendants(&parent),
            vec![before_cutoff]
        );
    }

    /// `PROC-DESC-06`: Same-millisecond PID reuse enforces 100ns cutoff across all 3 sources
    /// (`entries`, `evicted_live`, `evicted_exited`): `cutoff - 1` allowed, `==` and `>` rejected.
    #[test]
    fn proc_desc_06_same_ms_pid_reuse_100ns_cutoff_all_three_sources() {
        enum CutoffSource {
            Entries,
            EvictedLive,
            EvictedExited,
        }

        for source in [
            CutoffSource::Entries,
            CutoffSource::EvictedLive,
            CutoffSource::EvictedExited,
        ] {
            let mut table = ActiveProcessTable::new(32);
            let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 50);

            // Out-of-order children in the same ms (500) as `mid`'s exit and `reused_mid`'s start.
            let child_before =
                start_test_proc(&mut table, 301, 19_999, 200, r"C:\Tools\before.exe", 500);
            let child_at = start_test_proc(&mut table, 302, 20_000, 200, r"C:\Tools\at.exe", 500);
            let child_after =
                start_test_proc(&mut table, 303, 20_001, 200, r"C:\Tools\after.exe", 500);
            for child in [child_before, child_at, child_after] {
                assert_eq!(
                    table
                        .get_by_instance_id(&child.instance_id())
                        .expect("ppid-fallback child present")
                        .parent_instance_id,
                    None
                );
            }

            let mid = start_test_proc(&mut table, 200, 10_000, 100, r"C:\Tools\mid.exe", 100);
            assert_eq!(table.on_process_stop(200, 500), Some(mid.instance_id()));

            let reused_mid =
                start_test_proc(&mut table, 200, 20_000, 4, r"C:\Tools\reused.exe", 500);
            match source {
                CutoffSource::Entries => {
                    assert!(table.entries.contains_key(&reused_mid.instance_id()));
                    assert!(table.evicted_live.is_empty());
                    assert!(table.evicted_exited.is_empty());
                }
                CutoffSource::EvictedLive => {
                    table.remove_entry(&reused_mid.instance_id());
                    assert!(!table.entries.contains_key(&reused_mid.instance_id()));
                    assert!(table.evicted_live.contains_key(&reused_mid.instance_id()));
                    assert!(table.evicted_exited.is_empty());
                }
                CutoffSource::EvictedExited => {
                    assert_eq!(
                        table.on_process_stop(200, 550),
                        Some(reused_mid.instance_id())
                    );
                    table.remove_entry(&reused_mid.instance_id());
                    assert!(!table.entries.contains_key(&reused_mid.instance_id()));
                    assert!(table.evicted_live.is_empty());
                    assert!(table.evicted_exited.contains_key(&reused_mid.instance_id()));
                }
            }

            let got = table.collect_unexited_descendants(&root);
            assert_eq!(got, vec![child_before]);
            assert!(!got.contains(&child_at));
            assert!(!got.contains(&child_after));
        }

        // Minimum across multiple sources: `entries` (30_000) + `evicted_exited` (20_000) -> 20_000.
        let mut table = ActiveProcessTable::new(32);
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 50);
        let child_before =
            start_test_proc(&mut table, 301, 19_999, 200, r"C:\Tools\before.exe", 500);
        let child_between =
            start_test_proc(&mut table, 302, 25_000, 200, r"C:\Tools\between.exe", 500);
        for child in [child_before, child_between] {
            assert_eq!(
                table
                    .get_by_instance_id(&child.instance_id())
                    .expect("ppid-fallback child present")
                    .parent_instance_id,
                None
            );
        }

        let older_reused =
            start_test_proc(&mut table, 200, 20_000, 4, r"C:\Tools\reused_a.exe", 500);
        assert_eq!(
            table.on_process_stop(200, 520),
            Some(older_reused.instance_id())
        );
        table.remove_entry(&older_reused.instance_id());
        assert!(table.evicted_exited.contains_key(&older_reused.instance_id()));
        let _newer_reused =
            start_test_proc(&mut table, 200, 30_000, 4, r"C:\Tools\reused_b.exe", 550);

        let mid = start_test_proc(&mut table, 200, 10_000, 100, r"C:\Tools\mid.exe", 100);
        if let Some(mid_entry) = table.entries.get_mut(&mid.instance_id()) {
            mid_entry.exited_at_ms = Some(500);
        }
        let got = table.collect_unexited_descendants(&root);
        assert_eq!(got, vec![child_before]);
        assert!(!got.contains(&child_between));
    }

    /// `PROC-DESC-07`: Entry with `parent_instance_id == Some(other_parent)` and
    /// `ppid == parent.pid` must NOT be captured via `ppid` fallback.
    #[test]
    fn proc_desc_07_verified_other_parent_not_captured_by_ppid_fallback() {
        let mut table = ActiveProcessTable::new(32);
        let other_parent =
            start_test_proc(&mut table, 200, 5_000, 4, r"C:\Tools\other.exe", 50);
        let child = start_test_proc(&mut table, 300, 6_000, 200, r"C:\Tools\child.exe", 60);
        let parent = start_test_proc(&mut table, 200, 10_000, 4, r"C:\Tools\reused.exe", 100);

        // Also craft a child whose `create_time_100ns >= parent.create_time_100ns` and `ppid == 200`,
        // but whose `parent_instance_id` points to a distinct parent `999:1000`.
        let other_unrelated =
            start_test_proc(&mut table, 999, 1_000, 4, r"C:\Tools\unrelated_p.exe", 10);
        let child_later =
            start_test_proc(&mut table, 301, 15_000, 999, r"C:\Tools\child2.exe", 150);
        if let Some(entry) = table.entries.get_mut(&child_later.instance_id()) {
            entry.ppid = 200;
        }

        assert!(table.collect_unexited_descendants(&parent).is_empty());
        assert_eq!(
            table.collect_unexited_descendants(&other_parent),
            vec![child]
        );
        assert_eq!(
            table.collect_unexited_descendants(&other_unrelated),
            vec![child_later]
        );
    }

    /// `PROC-DESC-08`: Protected intermediates (`svchost.exe`, live and exited) and
    /// empty/whitespace `exe_path` (`""`, `"  \t "`, live and exited) do not expand descendants,
    /// while live direct children with blank `exe_path` are still returned in `descendants`.
    #[test]
    fn proc_desc_08_protected_and_blank_exe_intermediates_do_not_expand() {
        assert!(is_never_suspend_process(r"C:\Windows\System32\svchost.exe"));

        let mut table = ActiveProcessTable::new(32);
        let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 10);

        let _prot_live = start_test_proc(
            &mut table,
            201,
            2_000,
            100,
            r"C:\Windows\System32\svchost.exe",
            20,
        );
        let _gc_prot_live =
            start_test_proc(&mut table, 301, 2_100, 201, r"C:\Tools\evil1.exe", 25);

        let prot_exited = start_test_proc(
            &mut table,
            202,
            3_000,
            100,
            r"C:\Windows\System32\svchost.exe",
            30,
        );
        let _gc_prot_exited =
            start_test_proc(&mut table, 302, 3_100, 202, r"C:\Tools\evil2.exe", 32);
        assert_eq!(
            table.on_process_stop(202, 35),
            Some(prot_exited.instance_id())
        );

        let empty_exited = start_test_proc(&mut table, 203, 4_000, 100, "", 40);
        let _gc_empty_exited =
            start_test_proc(&mut table, 303, 4_100, 203, r"C:\Tools\evil3.exe", 42);
        assert_eq!(
            table.on_process_stop(203, 45),
            Some(empty_exited.instance_id())
        );

        let ws_exited = start_test_proc(&mut table, 204, 5_000, 100, "  \t ", 50);
        let _gc_ws_exited =
            start_test_proc(&mut table, 304, 5_100, 204, r"C:\Tools\evil4.exe", 52);
        assert_eq!(
            table.on_process_stop(204, 55),
            Some(ws_exited.instance_id())
        );

        let empty_live = start_test_proc(&mut table, 205, 6_000, 100, "", 60);
        let _gc_empty_live =
            start_test_proc(&mut table, 305, 6_100, 205, r"C:\Tools\evil5.exe", 62);

        let ws_live = start_test_proc(&mut table, 206, 7_000, 100, "  \t ", 70);
        let _gc_ws_live =
            start_test_proc(&mut table, 306, 7_100, 206, r"C:\Tools\evil6.exe", 72);

        assert_eq!(
            table.collect_unexited_descendants(&root),
            vec![empty_live, ws_live]
        );
    }

    /// `PROC-DESC-09`: `root` boundary conditions: `create_time_100ns == 0`, protected `root` in
    /// `entries` and `evicted_exited`, exited `root` in `entries`, evicted `root` in
    /// `evicted_exited`, and `root` absent from table.
    ///
    /// Note: Cases 4 and 5 exercise the direct `ActiveProcessTable::collect_unexited_descendants`
    /// unit API contract for an already-exited `root`. By contrast, the current production decoy
    /// freeze path (`engine/events.rs`) invokes descendant collection only after suspending a live
    /// triggering root process, so real-machine E2E validates live-root -> exited-intermediate ->
    /// live-descendant freezing separately from this unit boundary contract.
    #[test]
    fn proc_desc_09_root_entry_guards_and_exit_time_sources() {
        // 1. `root.create_time_100ns == 0` -> empty.
        let mut table = ActiveProcessTable::new(32);
        let _c0 = start_test_proc(&mut table, 200, 1_000, 100, r"C:\Tools\child.exe", 10);
        assert!(table
            .collect_unexited_descendants(&ProcessIdentity::new(100, 0))
            .is_empty());

        // 2. Protected `root` in `entries` -> empty.
        let mut table = ActiveProcessTable::new(32);
        let prot_root = start_test_proc(
            &mut table,
            100,
            1_000,
            4,
            r"C:\Windows\System32\svchost.exe",
            10,
        );
        let _child_under_prot =
            start_test_proc(&mut table, 200, 2_000, 100, r"C:\Tools\child.exe", 20);
        assert!(table.collect_unexited_descendants(&prot_root).is_empty());

        // 3. Protected `root` in `evicted_exited` -> empty.
        assert_eq!(
            table.on_process_stop(100, 30),
            Some(prot_root.instance_id())
        );
        table.remove_entry(&prot_root.instance_id());
        assert!(table.evicted_exited.contains_key(&prot_root.instance_id()));
        assert!(table.collect_unexited_descendants(&prot_root).is_empty());

        // 4. Non-protected exited `root` in `entries` (`exited_at_ms = 200`) enforces exit window on
        //    `ppid` fallback while still following verified `parent_instance_id`.
        let mut table = ActiveProcessTable::new(32);
        let fb_at_exit =
            start_test_proc(&mut table, 201, 2_000, 100, r"C:\Tools\fb_ok.exe", 200);
        let _fb_after_exit =
            start_test_proc(&mut table, 202, 2_100, 100, r"C:\Tools\fb_late.exe", 201);
        let exited_root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 100);
        assert_eq!(
            table.on_process_stop(100, 200),
            Some(exited_root.instance_id())
        );
        let verified_child =
            start_test_proc(&mut table, 203, 2_200, 100, r"C:\Tools\verified.exe", 250);
        if let Some(entry) = table.entries.get_mut(&verified_child.instance_id()) {
            entry.parent_instance_id = Some(exited_root.instance_id());
        }
        assert_eq!(
            table.collect_unexited_descendants(&exited_root),
            vec![fb_at_exit, verified_child]
        );

        // 5. Evicted non-protected `root` in `evicted_exited` (`exited_at_ms = 200`) preserves its
        //    `exited_at_ms` bound for `ppid` fallback.
        table.remove_entry(&exited_root.instance_id());
        assert!(table.evicted_exited.contains_key(&exited_root.instance_id()));
        assert_eq!(
            table.collect_unexited_descendants(&exited_root),
            vec![fb_at_exit, verified_child]
        );

        // 6. `root` absent from table -> traverses matching children while enforcing 100ns order.
        let mut table = ActiveProcessTable::new(32);
        let absent_root = ProcessIdentity::new(777, 10_000);
        let _too_old =
            start_test_proc(&mut table, 801, 9_999, 777, r"C:\Tools\old.exe", 50);
        let valid_child =
            start_test_proc(&mut table, 802, 10_500, 777, r"C:\Tools\valid.exe", 60);
        assert_eq!(
            table.collect_unexited_descendants(&absent_root),
            vec![valid_child]
        );
    }

    /// `PROC-DESC-11`: Same-millisecond PID reuse enforces the 100ns cutoff on verified
    /// `by_parent_id` links as well when out-of-order children arrive after `mid` exits and before
    /// successor `C` is registered (`entries`, `evicted_live`, and `evicted_exited`).
    #[test]
    fn proc_desc_11_verified_parent_link_enforces_100ns_cutoff_across_all_three_sources() {
        enum CutoffSource {
            Entries,
            EvictedLive,
            EvictedExited,
        }

        for source in [
            CutoffSource::Entries,
            CutoffSource::EvictedLive,
            CutoffSource::EvictedExited,
        ] {
            let mut table = ActiveProcessTable::new(32);
            let root = start_test_proc(&mut table, 100, 1_000, 4, r"C:\Tools\root.exe", 50);
            let mid = start_test_proc(&mut table, 200, 10_000, 100, r"C:\Tools\mid.exe", 100);
            assert_eq!(table.on_process_stop(200, 500), Some(mid.instance_id()));

            // Children start at the same ms (500) AFTER `mid` exits and BEFORE successor `C` starts,
            // so `lookup_parent_for` binds `parent_instance_id = Some(mid.instance_id())` on all 3.
            let d_before =
                start_test_proc(&mut table, 301, 19_999, 200, r"C:\Tools\d_before.exe", 500);
            let d_at = start_test_proc(&mut table, 302, 20_000, 200, r"C:\Tools\d_at.exe", 500);
            let d_after =
                start_test_proc(&mut table, 303, 25_000, 200, r"C:\Tools\d_after.exe", 500);
            for child in [d_before, d_at, d_after] {
                assert_eq!(
                    table
                        .get_by_instance_id(&child.instance_id())
                        .expect("verified child present")
                        .parent_instance_id
                        .as_deref(),
                    Some(mid.instance_id().as_str())
                );
            }

            let successor_c =
                start_test_proc(&mut table, 200, 20_000, 4, r"C:\Tools\successor_c.exe", 500);
            match source {
                CutoffSource::Entries => {
                    assert!(table.entries.contains_key(&successor_c.instance_id()));
                    assert!(table.evicted_live.is_empty());
                    assert!(table.evicted_exited.is_empty());
                }
                CutoffSource::EvictedLive => {
                    table.remove_entry(&successor_c.instance_id());
                    assert!(!table.entries.contains_key(&successor_c.instance_id()));
                    assert!(table.evicted_live.contains_key(&successor_c.instance_id()));
                    assert!(table.evicted_exited.is_empty());
                }
                CutoffSource::EvictedExited => {
                    assert_eq!(
                        table.on_process_stop(200, 550),
                        Some(successor_c.instance_id())
                    );
                    table.remove_entry(&successor_c.instance_id());
                    assert!(!table.entries.contains_key(&successor_c.instance_id()));
                    assert!(table.evicted_live.is_empty());
                    assert!(table.evicted_exited.contains_key(&successor_c.instance_id()));
                }
            }
            assert!(table.entries.contains_key(&mid.instance_id()));

            let got = table.collect_unexited_descendants(&root);
            assert_eq!(got, vec![d_before]);
            assert!(!got.contains(&d_at));
            assert!(!got.contains(&d_after));
        }
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
        assert_eq!(
            reuse_res.superseded_exited_processes,
            vec![(reused_old.instance_id(), reused_exe.to_string())],
            "PID reuse must return superseded evicted-live executable path for firewall cleanup"
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

    /// Regression test `PT-EVICT-01` (`PRRT_kwDOVyjVyM66k6lW`, `PRRT_kwDOVyjVyM66k6mA`,
    /// `PRRT_kwDOVyjVyM66k6ks`, `PRRT_kwDOVyjVyM66lPbl`):
    /// verifies that:
    /// 1. Re-registering and re-evicting a process does not let stale `evicted_live_fifo` entries
    ///    prematurely evict the newer generation into `overflowed_evicted_live_exes`, so normal
    ///    `ProcessStop` still resolves the process and clears `has_active_exe_key`.
    /// 2. `remove_evicted_live_by_id` FIFO compaction (`retain`) checks generation equality while
    ///    the target process remains live-evicted, pruning stale generations of A and keeping
    ///    only A's current generation when another evicted process (C2) is removed.
    /// 3. `evicted_live_by_pid` stays synchronized across eviction, re-registration, `pid:0`
    ///    snapshot absorption, out-of-order older start, PID reuse supersede, and explicit stop.
    #[test]
    fn process_table_evicted_live_generation_fifo_and_pid_index_stay_exact() {
        let mut table = ActiveProcessTable::new(1).with_evicted_live_capacity(2);
        let exe_a = r"C:\Users\Alice\Downloads\gen_a.exe";
        let exe_b = r"C:\Users\Alice\Downloads\gen_b.exe";
        let exe_c = r"C:\Users\Alice\Downloads\gen_c.exe";
        let key_a = normalize_exe_key(exe_a);
        let key_b = normalize_exe_key(exe_b);
        let key_c = normalize_exe_key(exe_c);

        let id_a = ProcessIdentity::new(8101, 10_000_000);
        let id_b = ProcessIdentity::new(8102, 10_100_000);
        let id_c = ProcessIdentity::new(8103, 10_200_000);
        let id_d = ProcessIdentity::new(8104, 10_300_000);

        // 1. Start A, then B (evicts A -> fifo [(A, 1)]), then C (evicts B -> fifo [(A, 1), (B, 2)]).
        table.on_process_start(id_a, 4, exe_a.to_string(), "a.exe".to_string(), None, 100);
        table.on_process_start(id_b, 4, exe_b.to_string(), "b.exe".to_string(), None, 110);
        table.on_process_start(id_c, 4, exe_c.to_string(), "c.exe".to_string(), None, 120);
        assert!(table.evicted_live.contains_key(&id_a.instance_id()));
        assert!(table.evicted_live.contains_key(&id_b.instance_id()));
        assert_eq!(table.evicted_live_by_pid.len(), 2);

        // 2. Re-register A (e.g. canary backfill) -> removes A from evicted_live while stale (A, 1)
        //    remains in evicted_live_fifo; evicts C -> evicted_live = {B, C}.
        //    First stop C so re-registering A doesn't evict C into evicted_live and overflow B early.
        assert_eq!(
            table.on_process_stop_with_exe(id_c.pid, 125),
            Some((id_c.instance_id(), exe_c.to_string()))
        );
        table.on_process_start(id_a, 4, exe_a.to_string(), "a.exe".to_string(), None, 100);
        assert!(!table.evicted_live.contains_key(&id_a.instance_id()));
        assert!(!table.evicted_live_by_pid.contains_key(&id_a.pid));
        assert!(table.evicted_live.contains_key(&id_b.instance_id()));

        // 3. Re-evict A by starting a new process C2 -> evicted_live = {B (gen 2), A (gen 3)},
        //    evicted_live_fifo = [(A, 1), (B, 2), (A, 3)].
        let id_c2 = ProcessIdentity::new(8105, 10_400_000);
        table.on_process_start(id_c2, 4, exe_c.to_string(), "c2.exe".to_string(), None, 130);
        assert!(table.evicted_live.contains_key(&id_a.instance_id()));
        assert!(table.evicted_live.contains_key(&id_b.instance_id()));
        assert!(!table.overflowed_evicted_live_exes.contains(key_a.as_str()));

        // 4. Start D -> evicts C2 into evicted_live (size 3 > capacity 2).
        //    Stale (A, 1) sits at the head of FIFO ahead of (B, 2) and MUST be ignored so B (gen 2)
        //    overflows instead of newer A (gen 3).
        table.on_process_start(
            id_d,
            4,
            r"C:\Program Files\Pad\gen_d.exe".to_string(),
            "d.exe".to_string(),
            None,
            140,
        );
        assert!(
            table.evicted_live.contains_key(&id_a.instance_id()),
            "newer generation of re-evicted A must NOT be evicted by stale FIFO entry"
        );
        assert!(
            !table.overflowed_evicted_live_exes.contains(key_a.as_str()),
            "A must remain individually tracked rather than fail-closed overflowed"
        );
        assert!(
            !table.evicted_live.contains_key(&id_b.instance_id()),
            "oldest live generation B must be evicted to overflow"
        );
        assert!(
            table.overflowed_evicted_live_exes.contains(key_b.as_str()),
            "B must move to overflowed_evicted_live_exes (fail-closed)"
        );
        assert!(table.has_active_exe_key(&key_b));
        assert!(table.has_active_exe_key(&key_c));

        // 5. Verify PID-indexed `create_time_100ns == 0` snapshot absorption matches evicted A.
        let snap_res = table.on_process_start(
            ProcessIdentity::new(id_a.pid, 0),
            4,
            exe_a.to_string(),
            String::new(),
            None,
            145,
        );
        assert_eq!(snap_res.resolved_identity, id_a);
        assert!(snap_res.skip_store_ingest);

        // 6. Verify PID-indexed older out-of-order start against evicted A is marked exited.
        //    Stop D first so inserting the already-exited older record evicts exited D instead of
        //    pushing a live D into `evicted_live` and rotating A out.
        assert_eq!(
            table.on_process_stop_with_exe(id_d.pid, 146).map(|(id, _)| id),
            Some(id_d.instance_id())
        );
        let older_a = ProcessIdentity::new(id_a.pid, 9_000_000);
        let older_res = table.on_process_start(
            older_a,
            4,
            r"C:\Program Files\Old\older_a.exe".to_string(),
            "older_a.exe".to_string(),
            None,
            50,
        );
        assert_eq!(older_res.exited_at_ms, Some(100));
        assert!(older_res.superseded_exited_processes.is_empty());

        // 7. Re-register and re-evict A until `evicted_live_fifo.len() > 16` while A remains in
        //    `evicted_live` alongside C2, then trigger `remove_evicted_live_by_id` compaction by
        //    stopping C2 (NOT A) so `retain` must distinguish A's stale generations from A's
        //    current live generation (`PRRT_kwDOVyjVyM66lPbl`).
        assert!(table.evicted_live.contains_key(&id_a.instance_id()));
        assert!(table.evicted_live.contains_key(&id_c2.instance_id()));
        let mut cycle: u32 = 0;
        while table.evicted_live_fifo.len() <= 16 {
            assert!(
                cycle < 32,
                "evicted_live_fifo must cross the compaction threshold within 32 cycles"
            );
            table.on_process_start(id_a, 4, exe_a.to_string(), "a.exe".to_string(), None, 100);
            assert!(!table.evicted_live.contains_key(&id_a.instance_id()));
            let pad_id = ProcessIdentity::new(8200 + cycle, 10_500_000 + u64::from(cycle) * 10_000);
            let pad_ts = 150 + i64::from(cycle) * 2;
            table.on_process_start(
                pad_id,
                4,
                r"C:\Program Files\Pad\compact_pad.exe".to_string(),
                format!("compact_pad_{cycle}.exe"),
                None,
                pad_ts,
            );
            assert!(table.evicted_live.contains_key(&id_a.instance_id()));
            assert_eq!(
                table.on_process_stop_with_exe(pad_id.pid, pad_ts + 1).map(|(id, _)| id),
                Some(pad_id.instance_id())
            );
            cycle += 1;
        }
        let current_a_gen = table
            .evicted_live
            .get(&id_a.instance_id())
            .expect("A must remain in evicted_live before compaction")
            .generation;
        let a_fifo_entries_before = table
            .evicted_live_fifo
            .iter()
            .filter(|(id, _)| id == &id_a.instance_id())
            .count();
        assert!(
            table.evicted_live_fifo.len() > 16,
            "evicted_live_fifo must exceed compaction threshold before stopping C2 (len={})",
            table.evicted_live_fifo.len()
        );
        assert!(
            a_fifo_entries_before > 1,
            "A must have both stale and current generations in evicted_live_fifo before compaction (count={a_fifo_entries_before})"
        );

        // Stop C2 while A stays in `evicted_live` -> triggers `remove_evicted_live_by_id`
        // compaction; only A's current generation may survive in `evicted_live_fifo`.
        assert_eq!(
            table.on_process_stop_with_exe(id_c2.pid, 250),
            Some((id_c2.instance_id(), exe_c.to_string()))
        );
        assert!(!table.evicted_live.contains_key(&id_c2.instance_id()));
        assert!(!table.evicted_live_by_pid.contains_key(&id_c2.pid));
        assert!(!table.has_active_exe_key(&key_c));
        assert_eq!(
            table.evicted_live.get(&id_a.instance_id()).map(|rec| rec.generation),
            Some(current_a_gen),
            "A must remain in evicted_live at its current generation after C2 stop compaction"
        );
        assert!(table.evicted_live_by_pid.contains_key(&id_a.pid));
        assert_eq!(
            table.evicted_live_fifo.iter().cloned().collect::<Vec<_>>(),
            vec![(id_a.instance_id(), current_a_gen)],
            "generation-aware FIFO compaction must prune all stale generations of A and retain only A's current generation"
        );

        // 8. Stop A normally -> resolves from evicted_live via PID index and clears liveness!
        assert_eq!(
            table.on_process_stop_with_exe(id_a.pid, 300),
            Some((id_a.instance_id(), exe_a.to_string()))
        );
        assert!(
            !table.has_active_exe_key(&key_a),
            "stopping re-evicted A must clear has_active_exe_key cleanly"
        );
        assert!(!table.evicted_live_by_pid.contains_key(&id_a.pid));

        // 9. Verify PID-indexed `evicted_live_by_pid` stays exact in size with `evicted_live`.
        let indexed_total: usize = table.evicted_live_by_pid.values().map(Vec::len).sum();
        assert_eq!(indexed_total, table.evicted_live.len());
        assert!(table.evicted_live_by_pid.values().all(|v| !v.is_empty()));
    }

    /// `PROC-MEM-01`: Verifies that post-60s compaction frees ONLY the 5 non-lineage fields
    /// (`motw_referrer`, `motw_frame_url`, `motw_source`, `motw_zone_id`, `user_sid`) without
    /// blanket 60s eviction into `evicted_exited`, `PathInterner` deduplicates `Arc<str>` paths and
    /// stays bounded `<= 8,192` with `sweep_dead()`, and parent lineage, `evicted_live`,
    /// `EvictedCommandLine::Oversized`, and lock-order invariants (`try_lock`) hold.
    #[test]
    fn proc_mem_01_post_60s_compaction_interning_and_invariants() {
        let mut table = ActiveProcessTable::new(8).with_evicted_live_capacity(8);

        let parent_id = ProcessIdentity::new(100, 10_000);
        let shared_exe = r"C:\Program Files\SharedApp\app.exe".to_string();
        table.on_process_start(
            parent_id,
            4,
            shared_exe.clone(),
            "app.exe --parent".to_string(),
            Some("S-1-5-21-100".to_string()),
            1_000,
        );
        table.set_motw_metadata(
            &parent_id.instance_id(),
            "https://parent.example/app.zip".to_string(),
            "Zone.Identifier".to_string(),
            Some("https://ref.example/".to_string()),
            Some("https://frame.example/".to_string()),
            Some(3),
        );

        let old_child_id = ProcessIdentity::new(101, 20_000);
        let oversized_cmd = format!("child.exe {}", "x".repeat(MAX_EVICTED_CMDLINE_BYTES + 128));
        table.on_process_start(
            old_child_id,
            100,
            shared_exe.clone(),
            oversized_cmd.clone(),
            Some("S-1-5-21-101".to_string()),
            2_000,
        );
        table.set_motw_metadata(
            &old_child_id.instance_id(),
            "https://child.example/dl.exe".to_string(),
            "Zone.Identifier".to_string(),
            Some("https://ref.example/child".to_string()),
            Some("https://frame.example/child".to_string()),
            Some(3),
        );
        assert!(table.mark_rule_alert_emitted(&old_child_id.instance_id(), "SIGMA-001"));
        assert_eq!(
            table.on_process_stop(old_child_id.pid, 100_000),
            Some(old_child_id.instance_id())
        );

        let recent_child_id = ProcessIdentity::new(102, 30_000);
        table.on_process_start(
            recent_child_id,
            100,
            r"C:\Tools\recent.exe".to_string(),
            "recent.exe --keep".to_string(),
            Some("S-1-5-21-102".to_string()),
            130_000,
        );
        table.set_motw_metadata(
            &recent_child_id.instance_id(),
            "https://recent.example/bin.exe".to_string(),
            "Zone.Identifier".to_string(),
            Some("https://ref.example/recent".to_string()),
            Some("https://frame.example/recent".to_string()),
            Some(3),
        );
        assert_eq!(
            table.on_process_stop(recent_child_id.pid, 140_000),
            Some(recent_child_id.instance_id())
        );

        // 1. Arc<str> pointer sharing across entries with the same exe_path.
        let parent_arc = Arc::clone(
            &table
                .get_by_instance_id(&parent_id.instance_id())
                .expect("parent active")
                .exe_path,
        );
        let child_arc = Arc::clone(
            &table
                .get_by_instance_id(&old_child_id.instance_id())
                .expect("old child retained")
                .exe_path,
        );
        assert!(
            Arc::ptr_eq(&parent_arc, &child_arc),
            "repeated exe_path must share the exact same Arc<str> allocation"
        );
        drop(parent_arc);
        drop(child_arc);

        // 2. Post-60s compaction at now_ms = 160_000 (cutoff = 100_000):
        //    only old_child_id (exited_at_ms = 100_000 <= 100_000) is compacted;
        //    NO blanket eviction into evicted_exited occurs.
        let compacted = table.compact_exited_older_than(100_000);
        assert_eq!(compacted, 1);
        assert_eq!(
            table.compact_exited_older_than(100_000),
            0,
            "second compaction pass must be idempotent"
        );
        assert!(table.evicted_exited.is_empty());

        let old_entry = table
            .get_by_instance_id(&old_child_id.instance_id())
            .expect("old exited entry stays in entries (no blanket 60s eviction)");
        assert_eq!(old_entry.user_sid, None);
        assert_eq!(old_entry.motw_referrer, None);
        assert_eq!(old_entry.motw_frame_url, None);
        assert_eq!(old_entry.motw_source, None);
        assert_eq!(old_entry.motw_zone_id, None);
        // Preserved lineage / dedup / L-18 MOTW / oversized command_line fields:
        assert_eq!(
            old_entry.parent_instance_id.as_deref(),
            Some(parent_id.instance_id().as_str())
        );
        assert_eq!(old_entry.exe_path.as_ref(), shared_exe);
        assert_eq!(old_entry.command_line, oversized_cmd);
        assert!(table.has_rule_alert_emitted(&old_child_id.instance_id(), "SIGMA-001"));
        assert_eq!(
            old_entry.origin_url.as_deref(),
            Some("https://child.example/dl.exe")
        );

        // Recently exited and still-live entries keep all 5 non-lineage fields intact.
        let recent_entry = table
            .get_by_instance_id(&recent_child_id.instance_id())
            .expect("recent exited entry");
        assert_eq!(recent_entry.user_sid.as_deref(), Some("S-1-5-21-102"));
        assert_eq!(recent_entry.motw_zone_id, Some(3));
        assert!(recent_entry.motw_referrer.is_some());
        assert!(recent_entry.motw_frame_url.is_some());
        assert!(recent_entry.motw_source.is_some());

        let live_parent = table
            .get_by_instance_id(&parent_id.instance_id())
            .expect("live parent");
        assert_eq!(live_parent.user_sid.as_deref(), Some("S-1-5-21-100"));
        assert_eq!(live_parent.motw_zone_id, Some(3));

        // 3. Evicting old_child_id via capacity pressure preserves parent lineage, MOTW,
        //    emitted_rule_ids, and EvictedCommandLine::Oversized (`> 4096` bytes), while
        //    evicting live parent into `evicted_live` preserves live + MOTW tracking.
        for i in 0..8u32 {
            let filler_id = ProcessIdentity::new(500 + i, 50_000 + u64::from(i));
            table.on_process_start(
                filler_id,
                4,
                format!(r"C:\Temp\filler_{i}.exe"),
                format!("filler_{i}.exe"),
                None,
                150_000 + i64::from(i),
            );
        }
        assert!(table.get_by_instance_id(&old_child_id.instance_id()).is_none());
        let evicted_old = table
            .evicted_exited
            .get(&old_child_id.instance_id())
            .expect("old child moved to evicted_exited on capacity eviction");
        assert!(matches!(evicted_old.command_line, EvictedCommandLine::Oversized));
        assert_eq!(
            evicted_old.parent_instance_id.as_deref(),
            Some(parent_id.instance_id().as_str())
        );
        assert!(table.has_rule_alert_emitted(&old_child_id.instance_id(), "SIGMA-001"));
        assert_eq!(
            table.parent_metadata_by_id(&old_child_id.instance_id()),
            (
                Some(old_child_id.instance_id()),
                Some(shared_exe.clone()),
                None
            )
        );
        // Live parent evicted into evicted_live keeps liveness + MOTW queries true.
        let parent_exe_key = normalize_exe_key(&shared_exe);
        assert!(table.has_active_exe_key(&parent_exe_key));
        assert!(table.has_active_motw_for_exe_key(&parent_exe_key));

        // 4. Lock-order invariant: `path_interner` is a leaf lock accessible via `try_lock()`
        //    while `process_table` is held, and `sweep_dead()` cleans dropped entries.
        let interner_arc = table.path_interner();
        {
            let mut guard = interner_arc
                .try_lock()
                .expect("leaf lock path_interner must be acquirable without deadlock");
            let swept = guard.sweep_dead();
            let _ = swept;
            assert!(guard.len() <= PATH_INTERNER_MAX_ENTRIES);
        }

        // 5. PathInterner bounded capacity <= 8,192 and sweep_dead() reclamation.
        let mut bounded = PathInterner::new(PATH_INTERNER_MAX_ENTRIES);
        let mut kept: Vec<Arc<str>> = Vec::with_capacity(9_000);
        for i in 0..9_000usize {
            kept.push(bounded.intern(&format!(r"C:\Apps\bin_{i}.exe")));
        }
        assert_eq!(bounded.max_entries(), PATH_INTERNER_MAX_ENTRIES);
        assert!(
            bounded.len() <= PATH_INTERNER_MAX_ENTRIES,
            "interner len {} exceeded max {}",
            bounded.len(),
            PATH_INTERNER_MAX_ENTRIES
        );
        assert_eq!(bounded.live_len(), PATH_INTERNER_MAX_ENTRIES);
        kept.clear();
        assert_eq!(bounded.live_len(), 0);
        let removed = bounded.sweep_dead();
        assert_eq!(removed, PATH_INTERNER_MAX_ENTRIES);
        assert_eq!(bounded.len(), 0);
    }

    #[test]
    fn proc_fu_p4_03_package_attributes_preserved_and_non_clobbering_across_upserts() {
        let mut table = ActiveProcessTable::new(16);
        let ident = ProcessIdentity::new(7100, 133_800_000_000_000_100);
        let res = table.on_process_start_with_package(
            ident,
            4,
            r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
            "backgroundTaskHost.exe -ServerName:App".to_string(),
            None,
            Some("  Contoso.App_12345  ".to_string()),
            Some("".to_string()),
            1_000,
        );
        assert!(!res.skip_store_ingest);
        let entry = table
            .get_by_instance_id(&res.instance_id)
            .expect("entry present");
        assert_eq!(entry.package_family_name.as_deref(), Some("Contoso.App_12345"));
        assert_eq!(entry.package_sid, None);

        // pid:0 absorption backfills missing package_sid without overwriting existing package_family_name.
        let abs_res = table.on_process_start_with_package(
            ProcessIdentity::new(7100, 0),
            4,
            r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
            String::new(),
            None,
            Some("Other.App_999".to_string()),
            Some("S-1-15-2-1-2-3".to_string()),
            1_010,
        );
        assert!(
            !abs_res.skip_store_ingest,
            "pid:0 backfill gaining package_sid must persist"
        );
        let entry = table
            .get_by_instance_id(&res.instance_id)
            .expect("entry still present");
        assert_eq!(entry.package_family_name.as_deref(), Some("Contoso.App_12345"));
        assert_eq!(entry.package_sid.as_deref(), Some("S-1-15-2-1-2-3"));

        // Duplicate start with None must NOT clobber existing fields.
        table.on_process_start_with_package(
            ident,
            4,
            r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
            String::new(),
            None,
            None,
            None,
            1_020,
        );
        let entry = table
            .get_by_instance_id(&res.instance_id)
            .expect("entry keeps package attrs");
        assert_eq!(entry.package_family_name.as_deref(), Some("Contoso.App_12345"));
        assert_eq!(entry.package_sid.as_deref(), Some("S-1-15-2-1-2-3"));
    }

    #[test]
    fn proc_fu_p4_03_evicted_live_process_stop_preserves_package_attrs() {
        let mut table = ActiveProcessTable::new(1);
        let evicted_id = ProcessIdentity::new(7201, 133_800_000_000_000_100);
        let evicting_id = ProcessIdentity::new(7202, 133_800_000_000_000_200);
        let bth_exe = r"C:\Windows\System32\backgroundTaskHost.exe";

        table.on_process_start_with_package(
            evicted_id,
            4,
            bth_exe.to_string(),
            "backgroundTaskHost.exe -ServerName:EvictedPkg".to_string(),
            None,
            Some("Contoso.Evicted_1".to_string()),
            Some("S-1-15-2-7201".to_string()),
            1_000,
        );
        table.on_process_start_with_package(
            evicting_id,
            4,
            r"C:\Windows\System32\notepad.exe".to_string(),
            "notepad.exe".to_string(),
            None,
            None,
            None,
            1_100,
        );

        assert!(
            table.get_by_instance_id(&evicted_id.instance_id()).is_none(),
            "first process should be displaced out of primary entries"
        );
        let stopped = table.on_process_stop_with_package(evicted_id.pid, 1_200);
        assert_eq!(
            stopped,
            Some((
                evicted_id.instance_id(),
                bth_exe.to_string(),
                Some("Contoso.Evicted_1".to_string()),
                Some("S-1-15-2-7201".to_string()),
            ))
        );
    }
}
