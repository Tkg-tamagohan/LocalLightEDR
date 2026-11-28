use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[cfg(doc)]
use ledr_proto::SensorEvent;
use ledr_proto::{
    is_never_suspend_process, AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord,
    ProcessIdentity,
};
use ledr_rules::{
    canonical_ip, classify_outbound_risk, evaluate_outbound_policy, is_external_ip,
    matches_network_target, parse_cidr_target, BinaryIdentity, OutboundDecision, OutboundRiskClass,
};
use ledr_sensor_win::etw::LiveSiblingCheck;
#[cfg(doc)]
use ledr_sensor_win::WfpDynamicEngine;
use ledr_sensor_win::{WfpDropEvent, WfpDropSinkFn};
use uuid::Uuid;

use crate::firewall::{parse_literal_target_ip, WfpRuleManager};
#[cfg(doc)]
use crate::process_table::ActiveProcessTable;

use super::domain_policy::{
    collect_domain_specific_blocked_hints, extend_authorizing_hints_from_existing_permit,
    has_domain_allow_rule_for_exe, outbound_alert_title, partition_permit_hints,
    select_outbound_decision_for_domains,
};
use super::events::ResolvedProcessContext;
use super::{
    current_unix_ms, DaemonEngine, InspectOutcome, OutboundEnforcementMode,
    AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
};

const MAX_PENDING_WFP_DROPS: usize = 512;
const WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS: i64 = 250;

/// Queued WFP net-event drop metadata passed from BFE callbacks into [`DaemonEngine::run_pipeline`]
/// over a bounded channel so correlation happens off the BFE callback thread in order behind
/// already-queued `ProcessStart` / `DnsQuery` / `NetworkConnect` events (`Thread 9`, `Thread 13`).
#[derive(Debug, Clone)]
pub(super) struct QueuedWfpDrop {
    pub(super) exe_path: String,
    pub(super) exe_key: String,
    pub(super) dst_ip: IpAddr,
    pub(super) dst_port: u16,
    pub(super) protocol: u8,
    pub(super) timestamp_ms: i64,
    pub(super) os_filter_id: u64,
    pub(super) package_sid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingWfpDropReason {
    DnsGrace,
    AttributionGrace,
    DnsAndAttribution,
}

impl PendingWfpDropReason {
    pub(super) fn includes_attribution_grace(self) -> bool {
        matches!(self, Self::AttributionGrace | Self::DnsAndAttribution)
    }

    fn includes_dns_grace(self) -> bool {
        matches!(self, Self::DnsGrace | Self::DnsAndAttribution)
    }
}

#[derive(Debug, Clone)]
pub(super) struct PendingWfpDrop {
    pub(super) item: QueuedWfpDrop,
    pub(super) deadline: tokio::time::Instant,
    pub(super) dns_deadline: Option<tokio::time::Instant>,
    pub(super) reason: PendingWfpDropReason,
    pub(super) parked_single_instance_id: Option<String>,
    pub(super) confirmed_ambiguous: bool,
}

pub(super) struct WfpCandidateResolution {
    candidates: Vec<WfpCandidate>,
    ambiguous: bool,
    candidate_gone: bool,
    candidates_complete: bool,
}

#[derive(Debug, Clone)]
struct WfpCandidate {
    identity: ProcessIdentity,
    instance_id: String,
    exe_path: String,
    command_line: Option<String>,
    parent_exe_path: Option<String>,
    parent_command_line: Option<String>,
    origin_url: Option<String>,
    motw_source: Option<String>,
    motw_referrer: Option<String>,
    motw_frame_url: Option<String>,
    motw_zone_id: Option<u32>,
    package_family_name: Option<String>,
    package_sid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverflowPushOutcome {
    Queued,
    Deduplicated,
    CoalescedNewExe,
    CoalescedOverwritten,
}

fn normalize_package_sid_key(package_sid: Option<&str>) -> Option<String> {
    package_sid
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Bounded overflow fallback queue for [`QueuedWfpDrop`] events when `wfp_drop_tx` is temporarily
/// full inside a non-blocking BFE net-event callback (`L-10`, `BUG_0006` overflow guarantee).
/// Deduplicates identical `(exe_key, package_sid, dst_ip)` tuples and coalesces per
/// `(exe_key, package_sid)` if even the secondary queue reaches `capacity` so blocked apps/packages
/// still reach operator triage without cross-package suppression.
#[derive(Debug, Default)]
pub(super) struct WfpDropOverflowQueue {
    queue: VecDeque<QueuedWfpDrop>,
    active_keys: HashSet<(String, Option<String>, IpAddr)>,
    coalesced_by_exe: HashMap<(String, Option<String>), QueuedWfpDrop>,
    coalesced_order: VecDeque<(String, Option<String>)>,
    coalesced_exe_counts: HashMap<String, usize>,
    last_coalesced: Option<(String, IpAddr)>,
    capacity: usize,
}

impl WfpDropOverflowQueue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            active_keys: HashSet::new(),
            coalesced_by_exe: HashMap::new(),
            coalesced_order: VecDeque::new(),
            coalesced_exe_counts: HashMap::new(),
            last_coalesced: None,
            capacity: capacity.max(1),
        }
    }

    fn remove_coalesced_entry(
        &mut self,
        key: &(String, Option<String>),
    ) -> Option<QueuedWfpDrop> {
        let removed = self.coalesced_by_exe.remove(key)?;
        if let Some(count) = self.coalesced_exe_counts.get_mut(&key.0) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.coalesced_exe_counts.remove(&key.0);
            }
        }
        Some(removed)
    }

    fn evict_coalesced_fair(&mut self, incoming_exe: &str) -> Option<(String, Option<String>)> {
        // Tier 1: Reclaim an extra slot from any executable holding >1 package slot so shared
        // host executables cannot starve unrelated single-slot executables.
        // Tier 2: Reclaim the incoming executable's own existing slot if it already has >=1 slot.
        // Tier 3: Fall back to oldest FIFO across single-slot executables.
        let target_idx = self
            .coalesced_order
            .iter()
            .position(|(exe, _)| self.coalesced_exe_counts.get(exe).copied().unwrap_or(0) > 1)
            .or_else(|| {
                (self
                    .coalesced_exe_counts
                    .get(incoming_exe)
                    .copied()
                    .unwrap_or(0)
                    >= 1)
                    .then(|| {
                        self.coalesced_order
                            .iter()
                            .position(|(exe, _)| exe == incoming_exe)
                    })
                    .flatten()
            })
            .or_else(|| (!self.coalesced_order.is_empty()).then_some(0));
        let idx = target_idx?;
        let key = self.coalesced_order.remove(idx)?;
        self.remove_coalesced_entry(&key);
        Some(key)
    }

    pub(super) fn push(&mut self, item: QueuedWfpDrop) -> OverflowPushOutcome {
        let canon_dst = canonical_ip(item.dst_ip);
        let sid_key = normalize_package_sid_key(item.package_sid.as_deref());
        let dedup_key = (item.exe_key.clone(), sid_key.clone(), canon_dst);
        if self.active_keys.contains(&dedup_key) {
            return OverflowPushOutcome::Deduplicated;
        }
        let coalesce_key = (item.exe_key.clone(), sid_key);
        if let Some(existing) = self.coalesced_by_exe.get_mut(&coalesce_key) {
            if canonical_ip(existing.dst_ip) == canon_dst {
                *existing = item;
                return OverflowPushOutcome::Deduplicated;
            }
        }
        if self.queue.len() < self.capacity {
            self.active_keys.insert(dedup_key);
            self.queue.push_back(item);
            return OverflowPushOutcome::Queued;
        }
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.coalesced_by_exe.entry(coalesce_key.clone())
        {
            self.last_coalesced = Some((item.exe_path.clone(), canon_dst));
            entry.insert(item);
            return OverflowPushOutcome::CoalescedOverwritten;
        }
        let mut evicted_same_exe = false;
        while self.coalesced_by_exe.len() >= self.capacity {
            let Some((ev_exe, _)) = self.evict_coalesced_fair(&coalesce_key.0) else {
                self.coalesced_by_exe.clear();
                self.coalesced_exe_counts.clear();
                self.coalesced_order.clear();
                break;
            };
            if ev_exe == coalesce_key.0 {
                evicted_same_exe = true;
                self.last_coalesced = Some((item.exe_path.clone(), canon_dst));
            }
        }
        self.coalesced_order.push_back(coalesce_key.clone());
        *self
            .coalesced_exe_counts
            .entry(coalesce_key.0.clone())
            .or_insert(0) += 1;
        self.coalesced_by_exe.insert(coalesce_key, item);
        if evicted_same_exe {
            OverflowPushOutcome::CoalescedOverwritten
        } else {
            OverflowPushOutcome::CoalescedNewExe
        }
    }

    pub(super) fn take_last_coalesced(&mut self) -> Option<(String, IpAddr)> {
        self.last_coalesced.take()
    }

    pub(super) fn pop(&mut self) -> Option<QueuedWfpDrop> {
        if let Some(item) = self.queue.pop_front() {
            let dedup_key = (
                item.exe_key.clone(),
                normalize_package_sid_key(item.package_sid.as_deref()),
                canonical_ip(item.dst_ip),
            );
            self.active_keys.remove(&dedup_key);
            return Some(item);
        }
        while let Some(coalesce_key) = self.coalesced_order.pop_front() {
            if let Some(item) = self.remove_coalesced_entry(&coalesce_key) {
                return Some(item);
            }
        }
        None
    }
}

/// Bounded deduplication set for unresolved app-level ambiguous WFP drop alerts keyed by
/// `(exe_key, package_sid, canonical_dst_ip)` (`Thread 9`).
#[derive(Debug, Default)]
pub(super) struct AppWfpAlertDedup {
    keys: HashSet<(String, Option<String>, IpAddr)>,
    order: VecDeque<(String, Option<String>, IpAddr)>,
    capacity: usize,
}

impl AppWfpAlertDedup {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            keys: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn mark_if_new(&mut self, exe_key: &str, package_sid: Option<&str>, dst_ip: IpAddr) -> bool {
        let key = (
            exe_key.to_string(),
            normalize_package_sid_key(package_sid),
            canonical_ip(dst_ip),
        );
        if self.keys.contains(&key) {
            return false;
        }
        while self.keys.len() >= self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.keys.remove(&evicted);
            } else {
                self.keys.clear();
                break;
            }
        }
        self.keys.insert(key.clone());
        self.order.push_back(key);
        true
    }

    pub(super) fn clear_key(
        &mut self,
        exe_key: &str,
        package_sid: Option<&str>,
        dst_ip: IpAddr,
    ) {
        let key = (
            exe_key.to_string(),
            normalize_package_sid_key(package_sid),
            canonical_ip(dst_ip),
        );
        self.keys.remove(&key);
    }
}

impl DaemonEngine {
    /// Returns a [`WfpDropSinkFn`] callback capturing ONLY a [`std::sync::Weak`] reference to
    /// this engine (preventing reference cycles) that translates WFP block drop events into
    /// high-priority [`SensorEvent::NetworkConnect`] triage events (`#1`).
    pub fn wfp_drop_sink(self: &Arc<Self>) -> WfpDropSinkFn {
        let weak = Arc::downgrade(self);
        Arc::new(move |drop_ev| {
            if let Some(engine) = weak.upgrade() {
                let _ = engine.ingest_wfp_drop_event(drop_ev);
            }
        })
    }

    /// Correlates a [`WfpDropEvent`] against [`ActiveProcessTable`] (active processes first,
    /// then recently exited) and per-instance DNS history, deduplicates rapid connection retries
    /// within 250 ms per `(exe_key, dst_ip, dst_port)`, and enqueues a synthetic
    /// Accepts an asynchronous [`WfpDropEvent`] from [`WfpDynamicEngine`]'s BFE callback and
    /// enqueues it onto the dedicated bounded `wfp_drop_tx` channel for in-order pipeline
    /// attribution behind already-queued `ProcessStart` / `DnsQuery` / `NetworkConnect` events.
    ///
    /// Returns `true` when the drop event was queued.
    pub fn ingest_wfp_drop_event(&self, drop_ev: WfpDropEvent) -> bool {
        if !self.config.outbound_firewall_enabled {
            return false;
        }
        let canon_ip = canonical_ip(drop_ev.dst_ip);
        if !is_external_ip(canon_ip) {
            return false;
        }
        let trimmed_exe = drop_ev.exe_path.trim();
        if trimmed_exe.is_empty()
            || classify_outbound_risk(trimmed_exe) == OutboundRiskClass::ProtectedOs
        {
            return false;
        }
        let exe_key = WfpRuleManager::exe_key(trimmed_exe);
        let effective_ts = if drop_ev.timestamp_ms > 0 {
            drop_ev.timestamp_ms
        } else {
            current_unix_ms()
        };

        let package_sid = drop_ev
            .package_sid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        {
            let mut dedup = self
                .wfp_drop_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.should_emit(
                &exe_key,
                package_sid.as_deref(),
                canon_ip,
                drop_ev.dst_port,
                effective_ts,
            ) {
                return false;
            }
        }

        let queued = QueuedWfpDrop {
            exe_path: trimmed_exe.to_string(),
            exe_key,
            dst_ip: canon_ip,
            dst_port: drop_ev.dst_port,
            protocol: drop_ev.protocol,
            timestamp_ms: effective_ts,
            os_filter_id: drop_ev.os_filter_id,
            package_sid,
        };
        match self.wfp_drop_tx.try_send(queued) {
            Ok(()) => true,
            Err(tokio::sync::mpsc::error::TrySendError::Full(queued)) => {
                let outcome = self
                    .wfp_drop_overflow
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(queued);
                match outcome {
                    OverflowPushOutcome::Queued | OverflowPushOutcome::CoalescedNewExe => {
                        self.wfp_drop_overflow_pushed.fetch_add(1, Ordering::Relaxed);
                    }
                    OverflowPushOutcome::CoalescedOverwritten => {
                        self.wfp_drop_overflow_coalesced
                            .fetch_add(1, Ordering::Release);
                    }
                    OverflowPushOutcome::Deduplicated => {}
                }
                self.wfp_drop_overflow_notify.notify_one();
                true
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub(super) fn pop_wfp_drop_overflow(&self) -> Option<QueuedWfpDrop> {
        self.wfp_drop_overflow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
    }

    /// Emits a power-of-two rate-limited warning from the asynchronous pipeline worker task
    /// whenever BFE callbacks incremented `wfp_drop_overflow_coalesced` since the last check
    /// (`#9` — keeps `ingest_wfp_drop_event` completely free of synchronous logging).
    ///
    /// Returns `true` when a warning was emitted.
    pub(super) fn maybe_log_wfp_drop_overflow_coalesced(&self, last_warned_coalesced: &mut u64) -> bool {
        let current = self.wfp_drop_overflow_coalesced();
        if current <= *last_warned_coalesced {
            return false;
        }
        let next_threshold = if *last_warned_coalesced == 0 {
            1
        } else {
            last_warned_coalesced.saturating_mul(2)
        };
        if current < next_threshold {
            return false;
        }
        let reached_threshold = if current >= (1u64 << 63) {
            current
        } else {
            1u64 << (63 - current.leading_zeros())
        };
        *last_warned_coalesced = reached_threshold;
        let last_meta = self
            .wfp_drop_overflow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take_last_coalesced();
        match last_meta {
            Some((exe_path, dst_ip)) => {
                tracing::warn!(
                    exe_path = %exe_path,
                    dst_ip = %dst_ip,
                    coalesced_count = current,
                    "WFP drop overflow queue full; coalesced earlier destination for same executable into latest drop"
                );
            }
            None => {
                tracing::warn!(
                    coalesced_count = current,
                    "WFP drop overflow queue full; coalesced earlier destination for same executable into latest drop"
                );
            }
        }
        true
    }

    /// Number of WFP drop events routed through the bounded overflow fallback (`L-10`).
    pub fn wfp_drop_overflow_pushed(&self) -> u64 {
        self.wfp_drop_overflow_pushed.load(Ordering::Relaxed)
    }

    /// Number of WFP drop events overwritten in `coalesced_by_exe` when the same executable
    /// overflowed both `wfp_drop_tx` and `wfp_drop_overflow.queue` with distinct destinations (`L-10`).
    pub fn wfp_drop_overflow_coalesced(&self) -> u64 {
        self.wfp_drop_overflow_coalesced.load(Ordering::Acquire)
    }

    fn resolve_wfp_candidates(
        &self,
        item: &QueuedWfpDrop,
        check_live_os_siblings: bool,
    ) -> WfpCandidateResolution {
        let (mut candidates, mut extra_identities, exe_overflowed) = {
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let raw = table.candidates_by_exe_key_for_wfp(
                &item.exe_key,
                item.timestamp_ms,
                self.config.wfp_drop_recent_exit_window_ms as i64,
                WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS,
            );
            let candidates: Vec<WfpCandidate> = raw
                .entries
                .into_iter()
                .map(|e| {
                    let (parent_exe_path, parent_command_line) = e
                        .parent_instance_id
                        .as_deref()
                        .and_then(|pid_id| table.get_by_instance_id(pid_id))
                        .map(|p| {
                            (
                                Some(p.exe_path.to_string()),
                                (!p.command_line.is_empty()).then(|| p.command_line.clone()),
                            )
                        })
                        .unwrap_or((None, None));
                    WfpCandidate {
                        identity: e.identity,
                        instance_id: e.instance_id.clone(),
                        exe_path: e.exe_path.to_string(),
                        command_line: (!e.command_line.is_empty()).then(|| e.command_line.clone()),
                        parent_exe_path,
                        parent_command_line,
                        origin_url: e.origin_url.clone(),
                        motw_source: e.motw_source.clone(),
                        motw_referrer: e.motw_referrer.clone(),
                        motw_frame_url: e.motw_frame_url.clone(),
                        motw_zone_id: e.motw_zone_id,
                        package_family_name: e.package_family_name.clone(),
                        package_sid: e.package_sid.clone(),
                    }
                })
                .collect();
            let mut extra_identities: Vec<ProcessIdentity> = Vec::new();
            for id in raw
                .evicted_live_identities
                .into_iter()
                .chain(raw.evicted_exited_identities)
            {
                if !candidates.iter().any(|c| c.identity == id) && !extra_identities.contains(&id) {
                    extra_identities.push(id);
                }
            }
            (candidates, extra_identities, raw.exe_evicted_live_overflowed)
        };

        let mut candidate_gone = false;

        let canonical_exe = candidates
            .first()
            .map(|c| c.exe_path.clone())
            .unwrap_or_else(|| item.exe_path.clone());
        for id in extra_identities.drain(..) {
            candidates.push(WfpCandidate {
                identity: id,
                instance_id: id.instance_id(),
                exe_path: canonical_exe.clone(),
                command_line: None,
                parent_exe_path: None,
                parent_command_line: None,
                origin_url: None,
                motw_source: None,
                motw_referrer: None,
                motw_frame_url: None,
                motw_zone_id: None,
                package_family_name: None,
                package_sid: None,
            });
        }
        let mut ambiguous = candidates.len() > 1;
        let mut candidates_complete = !exe_overflowed;

        if candidates.len() == 1 && !ambiguous {
            let single_inst_id = candidates[0].instance_id.clone();
            let single_identity = candidates[0].identity;
            let other_dns_window_ms = self.config.wfp_drop_other_instance_dns_window_ms as i64;
            let negative_dns_ambiguous = {
                let history = self
                    .process_dns_history
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                let own_has_dns = !history
                    .lookup_domains_for_process(&single_inst_id, item.dst_ip)
                    .is_empty();
                !own_has_dns
                    && other_dns_window_ms > 0
                    && history.has_fresh_ip_record_for_other_instance(
                        &item.exe_key,
                        &single_inst_id,
                        item.dst_ip,
                        item.timestamp_ms,
                        other_dns_window_ms,
                        item.timestamp_ms
                            .saturating_add(WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS),
                        WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS,
                    )
            };
            if negative_dns_ambiguous {
                ambiguous = true;
                candidates_complete = false;
            }

            if !ambiguous && check_live_os_siblings && self.config.wfp_drop_live_sibling_os_check {
                let max_created_ms = item
                    .timestamp_ms
                    .saturating_add(WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS);
                match self.live_process_inspector.check_live_siblings_for_exe(
                    &item.exe_key,
                    single_identity,
                    max_created_ms,
                ) {
                    LiveSiblingCheck::SiblingFound(extra_ids) => {
                        ambiguous = true;
                        for id in extra_ids {
                            if !candidates.iter().any(|c| c.identity == id) {
                                candidates.push(WfpCandidate {
                                    identity: id,
                                    instance_id: id.instance_id(),
                                    exe_path: canonical_exe.clone(),
                                    command_line: None,
                                    parent_exe_path: None,
                                    parent_command_line: None,
                                    origin_url: None,
                                    motw_source: None,
                                    motw_referrer: None,
                                    motw_frame_url: None,
                                    motw_zone_id: None,
                                    package_family_name: None,
                                    package_sid: None,
                                });
                            }
                        }
                    }
                    LiveSiblingCheck::CandidateGone => {
                        candidate_gone = true;
                        if exe_overflowed {
                            ambiguous = true;
                        }
                    }
                    LiveSiblingCheck::NoneFound => {}
                    LiveSiblingCheck::Indeterminate => {
                        if exe_overflowed {
                            ambiguous = true;
                        }
                    }
                }
            } else if !ambiguous && exe_overflowed && !self.config.wfp_drop_live_sibling_os_check {
                ambiguous = true;
            }
        }

        WfpCandidateResolution {
            candidates,
            ambiguous,
            candidate_gone,
            candidates_complete,
        }
    }

    pub(super) fn on_wfp_drop_dequeued(
        &self,
        item: QueuedWfpDrop,
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if self.is_shutdown_drain_cutoff() {
            return;
        }
        let res = self.resolve_wfp_candidates(&item, true);
        if res.candidates.is_empty()
            || (self.config.wfp_drop_dns_grace_ms == 0
                && self.config.wfp_drop_attribution_grace_ms == 0)
        {
            self.handle_wfp_drop_event_with_context(&item, Some(res), false, None);
            return;
        }

        let rules = self.store.list_network_rules().unwrap_or_default();
        let has_domain_allow = has_domain_allow_rule_for_exe(&item.exe_path, &rules);
        let is_ambig = res.ambiguous || res.candidates.len() > 1;
        let domain_candidates: Vec<(String, i64)> = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !is_ambig && res.candidates.len() == 1 {
                history.lookup_domains_for_process(&res.candidates[0].instance_id, item.dst_ip)
            } else {
                let mut combined = Vec::new();
                for c in &res.candidates {
                    combined.extend(history.lookup_fresh_domains_for_process(
                        &c.instance_id,
                        item.dst_ip,
                        item.timestamp_ms,
                        AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
                    ));
                }
                combined
            }
        };
        let may_need_dns = self.config.wfp_drop_dns_grace_ms > 0 && has_domain_allow;
        let may_need_attr = self.config.wfp_drop_attribution_grace_ms > 0
            && self.config.outbound_enforcement_mode != OutboundEnforcementMode::Audit
            && res.candidates.len() == 1
            && !is_ambig
            && !res.candidate_gone
            && domain_candidates.is_empty()
            && !is_never_suspend_process(&res.candidates[0].exe_path);

        // Neither grace applies (for example, repeated retries on a blocked no-allow exe,
        // or multi-candidate ambiguity with no domain allow rule): skip cold inspection here
        // and reuse the already-resolved candidates directly without repeating OS sibling scans.
        if !may_need_dns && !may_need_attr {
            self.handle_wfp_drop_event_with_context(&item, Some(res), false, None);
            return;
        }

        let InspectOutcome::Completed(bin_identity) =
            self.inspect_binary_for_pipeline(&item.exe_path)
        else {
            return;
        };
        let (decision, _) = select_outbound_decision_for_domains(
            &bin_identity,
            item.dst_ip,
            &domain_candidates,
            &rules,
        );
        let decision_restrict_or_unknown = matches!(
            decision,
            OutboundDecision::PreemptiveRestrict(_) | OutboundDecision::UnknownFirstConnect
        );
        if decision_restrict_or_unknown {
            let ambiguous_freshness =
                is_ambig.then_some((item.timestamp_ms, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS));
            if !self.has_valid_live_domain_policy_permit(
                &item.exe_path,
                &bin_identity,
                item.dst_ip,
                &domain_candidates,
                &rules,
                ambiguous_freshness,
            ) {
                let canon_dst = canonical_ip(item.dst_ip);
                let item_sid_key = normalize_package_sid_key(item.package_sid.as_deref());
                if pending.iter().any(|p| {
                    p.item.exe_key == item.exe_key
                        && normalize_package_sid_key(p.item.package_sid.as_deref()) == item_sid_key
                        && canonical_ip(p.item.dst_ip) == canon_dst
                        && p.item.dst_port == item.dst_port
                }) {
                    return;
                }
                while pending.len() >= MAX_PENDING_WFP_DROPS {
                    if let Some(oldest) = pending.pop_front() {
                        self.handle_wfp_drop_event_with_context(
                            &oldest.item,
                            None,
                            oldest.confirmed_ambiguous,
                            None,
                        );
                    }
                }
                let reason = match (may_need_dns, may_need_attr) {
                    (true, true) => PendingWfpDropReason::DnsAndAttribution,
                    (true, false) => PendingWfpDropReason::DnsGrace,
                    (false, true) => PendingWfpDropReason::AttributionGrace,
                    (false, false) => unreachable!(),
                };
                let now = tokio::time::Instant::now();
                let dns_deadline = may_need_dns
                    .then(|| now + Duration::from_millis(self.config.wfp_drop_dns_grace_ms));
                let grace_ms = match reason {
                    PendingWfpDropReason::DnsGrace => self.config.wfp_drop_dns_grace_ms,
                    PendingWfpDropReason::AttributionGrace => {
                        self.config.wfp_drop_attribution_grace_ms
                    }
                    PendingWfpDropReason::DnsAndAttribution => self
                        .config
                        .wfp_drop_dns_grace_ms
                        .max(self.config.wfp_drop_attribution_grace_ms),
                };
                let deadline = now + Duration::from_millis(grace_ms);
                pending.push_back(PendingWfpDrop {
                    item,
                    deadline,
                    dns_deadline,
                    reason,
                    parked_single_instance_id: (res.candidates.len() == 1 && !is_ambig)
                        .then(|| res.candidates[0].instance_id.clone()),
                    confirmed_ambiguous: false,
                });
                return;
            }
        }
        self.handle_wfp_drop_event_with_context(&item, Some(res), false, Some(bin_identity));
    }

    pub(super) fn flush_ready_pending_wfp_drops(
        &self,
        dns_inst_id: &str,
        dns_exe_key: &str,
        _query_name: &str,
        accepted_ips: &[IpAddr],
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if self.is_shutdown_drain_cutoff() || pending.is_empty() || accepted_ips.is_empty() {
            return;
        }
        let canon_accepted: Vec<IpAddr> = accepted_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let mut cached_rules: Option<Vec<AllowlistRuleRecord>> = None;
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut ready: Vec<(QueuedWfpDrop, bool)> = Vec::new();
        while let Some(mut entry) = pending.pop_front() {
            let canon_dst = canonical_ip(entry.item.dst_ip);
            if dns_exe_key != entry.item.exe_key || !canon_accepted.contains(&canon_dst) {
                remaining.push_back(entry);
                continue;
            }
            let res = self.resolve_wfp_candidates(&entry.item, false);
            let is_ambig = entry.confirmed_ambiguous || res.ambiguous || res.candidates.len() > 1;
            let dns_matches_candidate = res.candidates.iter().any(|c| c.instance_id == dns_inst_id);

            if entry.reason.includes_attribution_grace() {
                if is_ambig {
                    entry.confirmed_ambiguous = true;
                    if !entry.reason.includes_dns_grace() {
                        ready.push((entry.item, true));
                        continue;
                    }
                    // Sibling ambiguity discovered, but DnsGrace remains independent so a soon-to-
                    // arrive allowed DNS query can authorize before emitting an alert (`#5`).
                    entry.reason = PendingWfpDropReason::DnsGrace;
                    let dns_cap = entry
                        .dns_deadline
                        .unwrap_or_else(tokio::time::Instant::now);
                    entry.deadline = dns_cap;
                    if dns_cap <= tokio::time::Instant::now() && !dns_matches_candidate {
                        ready.push((entry.item, true));
                        continue;
                    }
                    // Fall through to multi-instance DNS evaluation if this query matched a candidate.
                } else if entry.parked_single_instance_id.as_deref() == Some(dns_inst_id) {
                    if !entry.reason.includes_dns_grace() {
                        ready.push((entry.item, entry.confirmed_ambiguous));
                        continue;
                    }
                    // Candidate's own DNS arrived while both AttributionGrace and DnsGrace were active.
                    // Check if the resolved domain now authorizes or explicitly blocks; otherwise
                    // clear AttributionGrace and keep the original `dns_deadline`.
                    let domains = {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        history.lookup_domains_for_process(dns_inst_id, canon_dst)
                    };
                    let rules = cached_rules
                        .get_or_insert_with(|| self.store.list_network_rules().unwrap_or_default());
                    let InspectOutcome::Completed(bin_identity) =
                        self.inspect_binary_for_pipeline(&entry.item.exe_path)
                    else {
                        return;
                    };
                    let (decision, _) = select_outbound_decision_for_domains(
                        &bin_identity,
                        entry.item.dst_ip,
                        &domains,
                        rules,
                    );
                    if matches!(
                        decision,
                        OutboundDecision::AllowedByRule { .. }
                            | OutboundDecision::BlockedByRule { .. }
                            | OutboundDecision::ProtectedOs
                    ) {
                        ready.push((entry.item, entry.confirmed_ambiguous));
                        continue;
                    }
                    entry.reason = PendingWfpDropReason::DnsGrace;
                    let dns_cap = entry
                        .dns_deadline
                        .unwrap_or_else(tokio::time::Instant::now);
                    if dns_cap < entry.deadline {
                        entry.deadline = dns_cap;
                    }
                    if entry.deadline <= tokio::time::Instant::now() {
                        ready.push((entry.item, entry.confirmed_ambiguous));
                    } else {
                        remaining.push_back(entry);
                    }
                    continue;
                }
            }

            if !dns_matches_candidate {
                remaining.push_back(entry);
                continue;
            }
            if !is_ambig && res.candidates.len() == 1 {
                let domains = {
                    let history = self
                        .process_dns_history
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    history.lookup_domains_for_process(dns_inst_id, canon_dst)
                };
                if domains.is_empty() {
                    remaining.push_back(entry);
                    continue;
                }
                let rules = cached_rules
                    .get_or_insert_with(|| self.store.list_network_rules().unwrap_or_default());
                if !has_domain_allow_rule_for_exe(&entry.item.exe_path, rules) {
                    ready.push((entry.item, entry.confirmed_ambiguous));
                    continue;
                }
                let InspectOutcome::Completed(bin_identity) =
                    self.inspect_binary_for_pipeline(&entry.item.exe_path)
                else {
                    return;
                };
                let (decision, _) = select_outbound_decision_for_domains(
                    &bin_identity,
                    entry.item.dst_ip,
                    &domains,
                    rules,
                );
                if matches!(
                    decision,
                    OutboundDecision::AllowedByRule { .. }
                        | OutboundDecision::BlockedByRule { .. }
                        | OutboundDecision::ProtectedOs
                ) {
                    ready.push((entry.item, entry.confirmed_ambiguous));
                } else {
                    remaining.push_back(entry);
                }
            } else {
                // Multi-instance case: only wake early if this candidate's fresh DNS history is
                // available and the combined fresh candidate set reaches AllowedByRule or
                // BlockedByRule so an unrelated or stale DNS does not cut another instance's grace
                // window short.
                let (own_fresh_non_empty, all_fresh_domains) = {
                    let history = self
                        .process_dns_history
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let own_fresh = history.lookup_fresh_domains_for_process(
                        dns_inst_id,
                        canon_dst,
                        entry.item.timestamp_ms,
                        AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
                    );
                    if own_fresh.is_empty() {
                        (false, Vec::new())
                    } else {
                        let mut combined = Vec::new();
                        for c in &res.candidates {
                            combined.extend(history.lookup_fresh_domains_for_process(
                                &c.instance_id,
                                canon_dst,
                                entry.item.timestamp_ms,
                                AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
                            ));
                        }
                        (true, combined)
                    }
                };
                if !own_fresh_non_empty {
                    if entry.deadline <= tokio::time::Instant::now() {
                        ready.push((entry.item, entry.confirmed_ambiguous));
                    } else {
                        remaining.push_back(entry);
                    }
                    continue;
                }
                let rules = cached_rules
                    .get_or_insert_with(|| self.store.list_network_rules().unwrap_or_default());
                if !has_domain_allow_rule_for_exe(&entry.item.exe_path, rules) {
                    ready.push((entry.item, entry.confirmed_ambiguous));
                    continue;
                }
                let InspectOutcome::Completed(bin_identity) =
                    self.inspect_binary_for_pipeline(&entry.item.exe_path)
                else {
                    return;
                };
                let (decision, _) = select_outbound_decision_for_domains(
                    &bin_identity,
                    entry.item.dst_ip,
                    &all_fresh_domains,
                    rules,
                );
                if matches!(
                    decision,
                    OutboundDecision::AllowedByRule { .. }
                        | OutboundDecision::BlockedByRule { .. }
                        | OutboundDecision::ProtectedOs
                ) || entry.deadline <= tokio::time::Instant::now()
                {
                    ready.push((entry.item, entry.confirmed_ambiguous));
                } else {
                    remaining.push_back(entry);
                }
            }
        }
        *pending = remaining;
        for (item, confirmed_ambig) in ready {
            self.handle_wfp_drop_event_with_context(&item, None, confirmed_ambig, None);
        }
    }

    pub(super) fn flush_ambiguous_pending_wfp_drops_for_process_start(
        &self,
        identity: ProcessIdentity,
        exe_path: &str,
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if pending.is_empty() || exe_path.trim().is_empty() {
            return;
        }
        let started_info = {
            let table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let entry = table
                .get_by_instance_id(&identity.instance_id())
                .or_else(|| table.lookup_by_pid(identity.pid));
            entry.and_then(|e| {
                let clean_exe = e.exe_path.trim();
                (!clean_exe.is_empty()).then(|| {
                    (
                        e.instance_id.clone(),
                        WfpRuleManager::exe_key(clean_exe),
                        e.created_at_ms,
                    )
                })
            })
        };
        let Some((new_inst_id, new_exe_key, new_created_at_ms)) = started_info else {
            return;
        };

        let now = tokio::time::Instant::now();
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut ready: Vec<(QueuedWfpDrop, bool)> = Vec::new();
        while let Some(mut entry) = pending.pop_front() {
            let sibling_in_window = entry.reason.includes_attribution_grace()
                && entry.item.exe_key == new_exe_key
                && entry
                    .parked_single_instance_id
                    .as_deref()
                    .is_some_and(|id| id != new_inst_id)
                && new_created_at_ms
                    <= entry
                        .item
                        .timestamp_ms
                        .saturating_add(WFP_DROP_LATE_SIBLING_CREATE_SKEW_MS);
            if sibling_in_window {
                entry.confirmed_ambiguous = true;
                if entry.reason == PendingWfpDropReason::DnsAndAttribution {
                    entry.reason = PendingWfpDropReason::DnsGrace;
                    let dns_cap = entry.dns_deadline.unwrap_or(now);
                    entry.deadline = dns_cap;
                    if dns_cap <= now {
                        ready.push((entry.item, true));
                    } else {
                        remaining.push_back(entry);
                    }
                } else {
                    ready.push((entry.item, true));
                }
            } else {
                remaining.push_back(entry);
            }
        }
        *pending = remaining;
        for (item, confirmed_ambig) in ready {
            self.handle_wfp_drop_event_with_context(&item, None, confirmed_ambig, None);
        }
    }

    pub(super) fn flush_expired_pending_wfp_drops(&self, pending: &mut VecDeque<PendingWfpDrop>) {
        if pending.is_empty() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut expired: Vec<(QueuedWfpDrop, bool)> = Vec::new();
        while let Some(entry) = pending.pop_front() {
            if entry.deadline <= now {
                expired.push((entry.item, entry.confirmed_ambiguous));
            } else {
                remaining.push_back(entry);
            }
        }
        *pending = remaining;
        for (item, confirmed_ambig) in expired {
            self.handle_wfp_drop_event_with_context(&item, None, confirmed_ambig, None);
        }
    }

    pub(super) fn handle_wfp_drop_event_now(&self, item: &QueuedWfpDrop) {
        self.handle_wfp_drop_event_with_context(item, None, false, None);
    }

    pub(super) fn handle_wfp_drop_event_with_context(
        &self,
        item: &QueuedWfpDrop,
        prefetched_res: Option<WfpCandidateResolution>,
        force_ambiguous: bool,
        prefetched_identity: Option<BinaryIdentity>,
    ) {
        if self.is_shutdown_drain_cutoff() {
            return;
        }
        let mut res = prefetched_res
            .unwrap_or_else(|| self.resolve_wfp_candidates(item, !force_ambiguous));
        if force_ambiguous {
            res.ambiguous = true;
            res.candidates_complete = false;
        }
        if res.candidates.is_empty() {
            tracing::debug!(
                exe_path = %item.exe_path,
                dst_ip = %item.dst_ip,
                dst_port = item.dst_port,
                "dropping WFP net event with no active/in-window candidate in ActiveProcessTable"
            );
            return;
        }

        if res.ambiguous || res.candidates.len() > 1 {
            // WfpDropEvent carries no PID or local socket tuple (`BUG_0004`); never guess an
            // individual instance across concurrent siblings — keep multi-candidate drops app-level.
            self.handle_ambiguous_wfp_drop(
                item,
                &res.candidates,
                res.candidates_complete && res.candidates.len() > 1,
                prefetched_identity,
            );
            return;
        }
        let cand = &res.candidates[0];

        let domain_candidates = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            history.lookup_domains_for_process(&cand.instance_id, item.dst_ip)
        };
        let event_sid = item
            .package_sid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let cand_sid = cand
            .package_sid
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let sid_mismatch = matches!(
            (event_sid, cand_sid),
            (Some(ev), Some(cd)) if !ev.eq_ignore_ascii_case(cd)
        );
        let proc_ctx = ResolvedProcessContext {
            proc_identity: Some(cand.identity),
            proc_instance_id: Some(cand.instance_id.clone()),
            proc_exe_path: Some(cand.exe_path.clone()),
            proc_command_line: cand.command_line.clone(),
            store_hint: Some(cand.instance_id.clone()),
            parent_exe_path: cand.parent_exe_path.clone(),
            parent_command_line: cand.parent_command_line.clone(),
            should_evaluate_sigma: true,
            exited_at_ms: None,
            superseded_exit: None,
            skip_store_ingest: false,
            skip_launch_guards: false,
            effective_process_start: None,
            origin_url: cand.origin_url.clone(),
            motw_source: cand.motw_source.clone(),
            motw_referrer: cand.motw_referrer.clone(),
            motw_frame_url: cand.motw_frame_url.clone(),
            motw_zone_id: cand.motw_zone_id,
            package_family_name: if sid_mismatch {
                None
            } else {
                cand.package_family_name.clone()
            },
            package_sid: event_sid
                .map(str::to_owned)
                .or_else(|| cand_sid.map(str::to_owned)),
            proc_sha256: None,
            proc_created_at_ms: None,
        };
        let (_action, emitted_alert) = self.evaluate_and_handle_outbound_connect(
            None,
            &proc_ctx,
            &cand.exe_path,
            cand.identity.pid,
            item.protocol,
            item.dst_ip,
            item.dst_port,
            &domain_candidates,
            item.timestamp_ms,
        );
        if emitted_alert {
            if let Some(Err(err)) = self.try_store_write(|s| s.flush_batch()) {
                tracing::warn!(error = %err, "failed flushing store after attributed WFP drop alert");
            }
        }
    }

    fn handle_ambiguous_wfp_drop(
        &self,
        item: &QueuedWfpDrop,
        candidates: &[WfpCandidate],
        candidates_complete: bool,
        prefetched_identity: Option<BinaryIdentity>,
    ) {
        if self.is_shutdown_drain_cutoff() {
            return;
        }
        let canonical_exe = candidates
            .first()
            .map(|c| c.exe_path.as_str())
            .unwrap_or(item.exe_path.as_str());
        let risk = classify_outbound_risk(canonical_exe);
        if risk == OutboundRiskClass::ProtectedOs {
            return;
        }
        let rules = self.store.list_network_rules().unwrap_or_default();
        let bin_identity = match prefetched_identity {
            Some(id) => id,
            None => match self.inspect_binary_for_pipeline(canonical_exe) {
                InspectOutcome::Completed(id) => id,
                InspectOutcome::Cancelled => return,
            },
        };
        let cand_domains: Vec<(String, i64)> = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut combined: Vec<(String, i64)> = Vec::new();
            for c in candidates {
                combined.extend(history.lookup_fresh_domains_for_process(
                    &c.instance_id,
                    item.dst_ip,
                    item.timestamp_ms,
                    AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS,
                ));
            }
            combined.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            combined
        };
        let mut decision = evaluate_outbound_policy(&bin_identity, item.dst_ip, None, &rules);
        let (cand_decision, cand_hint) = select_outbound_decision_for_domains(
            &bin_identity,
            item.dst_ip,
            &cand_domains,
            &rules,
        );
        let mut blocked_dom_from_cand: Option<String> = None;
        if matches!(decision, OutboundDecision::AllowedByRule { .. }) {
            if let OutboundDecision::BlockedByRule {
                rule_id: blk_rule_id,
            } = &cand_decision
            {
                blocked_dom_from_cand = cand_hint;
                decision = OutboundDecision::BlockedByRule {
                    rule_id: blk_rule_id.clone(),
                };
            }
        }
        let mut permit_failure: Option<(String, String)> = None;
        match &decision {
            OutboundDecision::ProtectedOs => return,
            OutboundDecision::AllowedByRule { rule_id } => {
                // App-scoped IP/CIDR/wildcard allow: materialize a concrete IP WFP Permit even
                // when PID is ambiguous, respecting existing IP blocks (`deny overrides allow`)
                // and preserving all known candidate domain hints (`SEC_0001`, `#2`).
                // Never swallow a BFE failure silently without alerting.
                let matched_target = rules
                    .iter()
                    .find(|r| &r.rule_id == rule_id)
                    .and_then(|r| r.allowed_target.as_deref())
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let cand_hint_strs: Vec<&str> = cand_domains
                    .iter()
                    .map(|(dom, _)| dom.as_str())
                    .collect();
                let (mut authorizing_hints, cohosted_hints) =
                    partition_permit_hints(&bin_identity, item.dst_ip, &cand_hint_strs, &rules);
                if authorizing_hints.is_empty() && cohosted_hints.is_empty() {
                    let fallback_domain = matched_target.filter(|t| {
                        parse_literal_target_ip(t).is_none()
                            && parse_cidr_target(t).is_err()
                            && !matches_network_target(t, item.dst_ip, None)
                    });
                    if let Some(dom) = fallback_domain {
                        authorizing_hints.push(dom.to_string());
                    }
                }
                let permit_res = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    if fw.active_app_block(canonical_exe).is_some() {
                        extend_authorizing_hints_from_existing_permit(
                            &fw,
                            canonical_exe,
                            item.dst_ip,
                            &bin_identity,
                            &rules,
                            &mut authorizing_hints,
                        );
                        fw.ensure_ip_permit_for_domain_hints_prioritized(
                            canonical_exe,
                            item.dst_ip,
                            &authorizing_hints,
                            &cohosted_hints,
                            &*self.defense,
                        )
                    } else {
                        Ok(None)
                    }
                };
                match permit_res {
                    Ok(_) => return,
                    Err(err) => {
                        tracing::warn!(
                            exe_path = %canonical_exe,
                            dst_ip = %item.dst_ip,
                            rule_id = %rule_id,
                            error = %err,
                            "failed installing IP-specific WFP permit for app-level allowed target"
                        );
                        permit_failure = Some((rule_id.clone(), err));
                    }
                }
            }
            OutboundDecision::PreemptiveRestrict(_) | OutboundDecision::UnknownFirstConnect => {
                // If an active candidate already resolved an allowed domain for `dst_ip` and
                // materialized a live IP Permit (with no overriding block), OR a live
                // `DomainPolicy` IP Permit still validates against the latest binary identity,
                // current rules, and active exe-wide DNS history (e.g., cached old IP after
                // domain migration), do not emit a false ambiguous drop alert (`AUD-P3-01`).
                if matches!(cand_decision, OutboundDecision::AllowedByRule { .. }) {
                    let has_live_ip_permit = {
                        let fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                        fw.has_active_filter(canonical_exe, Some(item.dst_ip), true)
                            && !fw.has_active_filter(canonical_exe, Some(item.dst_ip), false)
                    };
                    if has_live_ip_permit {
                        return;
                    }
                }
                if !matches!(cand_decision, OutboundDecision::BlockedByRule { .. })
                    && self.has_valid_live_domain_policy_permit(
                        canonical_exe,
                        &bin_identity,
                        item.dst_ip,
                        &cand_domains,
                        &rules,
                        Some((item.timestamp_ms, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS)),
                    )
                {
                    return;
                }
            }
            OutboundDecision::BlockedByRule { .. } => {}
        }

        let (effective_package_family_name, effective_package_sid) =
            resolve_ambiguous_package_context(
                item.package_sid.as_deref(),
                candidates,
                candidates_complete,
            );

        {
            let mut dedup = self
                .app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.mark_if_new(
                &item.exe_key,
                effective_package_sid.as_deref(),
                item.dst_ip,
            ) {
                return;
            }
        }

        let alert_id = Uuid::new_v4().to_string();
        let mut bound_existing = false;
        let mut wfp_permit_error: Option<String> = None;
        let (rule_id, severity, label, matched_rule_id, wfp_filter_id) =
            if let Some((rule_id, err_msg)) = permit_failure {
                let wfp_handle = {
                    let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                    bound_existing = fw.bind_alert_to_app_block(&alert_id, canonical_exe);
                    fw.active_app_block(canonical_exe)
                        .map(|(h, _)| h)
                        .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                };
                wfp_permit_error = Some(err_msg);
                (
                    "LEDR-NET-POLICY-PERMIT-FAILED",
                    AlertSeverity::High,
                    "Allowed Outbound WFP Permit Failed (App-Level)",
                    Some(rule_id),
                    wfp_handle,
                )
            } else {
                match decision {
                    OutboundDecision::BlockedByRule { rule_id } => {
                        let matched_target = rules
                            .iter()
                            .find(|r| r.rule_id == rule_id)
                            .and_then(|r| r.allowed_target.as_deref())
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        let domain_blocked_hints = if matched_target
                            .is_some_and(|target_pat| parse_literal_target_ip(target_pat).is_none())
                        {
                            collect_domain_specific_blocked_hints(
                                &bin_identity,
                                item.dst_ip,
                                &cand_domains,
                                &rules,
                            )
                        } else {
                            Vec::new()
                        };
                        let wfp_handle = {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            let active_app = fw.active_app_block(canonical_exe).map(|(h, _)| h);
                            let res = match matched_target {
                                None => fw.ensure_policy_block(canonical_exe, None, &*self.defense),
                                Some(target_pat) if parse_literal_target_ip(target_pat).is_some() => {
                                    fw.ensure_policy_block(
                                        canonical_exe,
                                        Some(item.dst_ip),
                                        &*self.defense,
                                    )
                                }
                                Some(_)
                                    if blocked_dom_from_cand.is_some()
                                        && active_app.is_some()
                                        && !fw.has_active_filter(
                                            canonical_exe,
                                            Some(item.dst_ip),
                                            true,
                                        ) =>
                                {
                                    // Ambiguous multi-instance DNS correlation must not pin a sticky
                                    // IP-level DomainPolicy Block when the app-wide block is already
                                    // active (and no conflicting IP Permit exists); otherwise future
                                    // permitted CIDR traffic to the same IP would stay blocked after
                                    // DNS expires or moves (`BUG_..._0003`).
                                    active_app.ok_or_else(String::new)
                                }
                                Some(target_pat)
                                    if parse_cidr_target(target_pat).is_ok()
                                        || matches_network_target(
                                            target_pat,
                                            item.dst_ip,
                                            None,
                                        ) =>
                                {
                                    fw.ensure_domain_policy_block_hints(
                                        canonical_exe,
                                        item.dst_ip,
                                        &domain_blocked_hints,
                                        &*self.defense,
                                    )
                                }
                                Some(target_pat) => {
                                    if !domain_blocked_hints.is_empty() {
                                        fw.ensure_domain_policy_block_hints(
                                            canonical_exe,
                                            item.dst_ip,
                                            &domain_blocked_hints,
                                            &*self.defense,
                                        )
                                    } else {
                                        fw.ensure_domain_policy_block(
                                            canonical_exe,
                                            item.dst_ip,
                                            blocked_dom_from_cand.as_deref().unwrap_or(target_pat),
                                            &*self.defense,
                                        )
                                    }
                                }
                            };
                            res.ok()
                                .or(active_app)
                                .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                        };
                        (
                            "LEDR-NET-POLICY-BLOCK",
                            AlertSeverity::High,
                            "Blocked Outbound Policy Match (App-Level)",
                            Some(rule_id),
                            wfp_handle,
                        )
                    }
                    OutboundDecision::PreemptiveRestrict(_)
                    | OutboundDecision::UnknownFirstConnect => {
                        let wfp_handle = {
                            let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                            bound_existing = fw.bind_alert_to_app_block(&alert_id, canonical_exe);
                            fw.active_app_block(canonical_exe)
                                .map(|(h, _)| h)
                                .or((item.os_filter_id != 0).then_some(item.os_filter_id))
                        };
                        let motw_cand = candidates.iter().find(|c| c.origin_url.is_some());
                        let effective_risk = if motw_cand.is_some()
                            && risk == OutboundRiskClass::GeneralUnknown
                        {
                            OutboundRiskClass::HighRiskPath
                        } else {
                            risk
                        };
                        let (rid, sev, lbl) = match effective_risk {
                            OutboundRiskClass::HighRiskPath => (
                                "LEDR-NET-HIGH-RISK-PATH",
                                AlertSeverity::High,
                                "High-Risk Path Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                            OutboundRiskClass::ScriptInterpreter => (
                                "LEDR-NET-SCRIPT-INTERPRETER",
                                AlertSeverity::High,
                                "Script Interpreter Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                            _ => (
                                "LEDR-NET-UNKNOWN-OUTBOUND",
                                AlertSeverity::Medium,
                                "Unknown Process Outbound Drop (Multi-Instance Ambiguous)",
                            ),
                        };
                        (rid, sev, lbl, None, wfp_handle)
                    }
                    OutboundDecision::ProtectedOs | OutboundDecision::AllowedByRule { .. } => {
                        unreachable!()
                    }
                }
            };

        let motw_cand = candidates.iter().find(|c| c.origin_url.is_some());
        let effective_risk = if motw_cand.is_some() && risk == OutboundRiskClass::GeneralUnknown {
            OutboundRiskClass::HighRiskPath
        } else {
            risk
        };
        let candidate_pids: Vec<u32> = candidates.iter().map(|c| c.identity.pid).collect();
        let candidate_instance_ids: Vec<&str> =
            candidates.iter().map(|c| c.instance_id.as_str()).collect();
        let context_json = serde_json::json!({
            "attribution": "app_level_ambiguous",
            "pid": serde_json::Value::Null,
            "candidate_pids": candidate_pids,
            "candidate_instance_ids": candidate_instance_ids,
            "exe_path": canonical_exe,
            "dst_ip": item.dst_ip.to_string(),
            "dst_port": item.dst_port,
            "protocol": item.protocol,
            "domain_hint": serde_json::Value::Null,
            "matched_rule_id": matched_rule_id,
            "wfp_permit_error": wfp_permit_error,
            "risk_class": format!("{effective_risk:?}"),
            "wfp_blocked": wfp_filter_id.is_some(),
            "wfp_filter_id": wfp_filter_id,
            "sha256": bin_identity.sha256,
            "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
            "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
            "origin_url": motw_cand.and_then(|c| c.origin_url.as_deref()),
            "motw_source": motw_cand.and_then(|c| c.motw_source.as_deref()),
            "motw_referrer": motw_cand.and_then(|c| c.motw_referrer.as_deref()),
            "motw_frame_url": motw_cand.and_then(|c| c.motw_frame_url.as_deref()),
            "motw_zone_id": motw_cand.and_then(|c| c.motw_zone_id),
            "package_family_name": effective_package_family_name,
            "package_sid": effective_package_sid,
        })
        .to_string();

        let alert = AlertRecord {
            alert_id: alert_id.clone(),
            timestamp_ms: item.timestamp_ms,
            severity,
            source_layer: "LAYER_3_NETWORK".to_string(),
            rule_id: rule_id.to_string(),
            title: outbound_alert_title(
                label,
                canonical_exe,
                item.dst_ip,
                item.dst_port,
                None,
            ),
            process_instance_id: None,
            process_suspended: false,
            status: AlertStatus::Pending,
            context_json,
            resolved_at_ms: None,
        };

        if let Err(err) = self.record_alert_checked(&alert) {
            tracing::warn!(
                error = %err,
                alert_id = %alert.alert_id,
                exe_path = %canonical_exe,
                "failed to record app-level ambiguous WFP drop alert"
            );
            if bound_existing {
                let mut fw = self.firewall.lock().unwrap_or_else(|e| e.into_inner());
                fw.unbind_alert(&alert_id);
                self.retry_deferred_preemptive_removal_locked(&mut fw, canonical_exe);
            }
            self.app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear_key(&item.exe_key, effective_package_sid.as_deref(), item.dst_ip);
            return;
        }

        self.alerts_emitted.fetch_add(1, Ordering::Relaxed);
        if let Err(err) = self.notifier.notify_alert(&alert) {
            tracing::warn!(
                alert_id = %alert.alert_id,
                error = %err,
                "failed to dispatch toast notification for app-level WFP drop alert"
            );
        }
        if let Some(Err(err)) = self.try_store_write(|s| s.flush_batch()) {
            tracing::warn!(error = %err, "failed flushing store after app-level WFP drop alert");
        }
    }
}

fn resolve_ambiguous_package_context(
    event_package_sid: Option<&str>,
    candidates: &[WfpCandidate],
    candidates_complete: bool,
) -> (Option<String>, Option<String>) {
    let effective_sid = event_package_sid
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            if !candidates_complete || candidates.is_empty() {
                return None;
            }
            let first = candidates
                .first()?
                .package_sid
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())?;
            candidates
                .iter()
                .all(|c| {
                    c.package_sid
                        .as_deref()
                        .map(str::trim)
                        .is_some_and(|s| s.eq_ignore_ascii_case(first))
                })
                .then(|| first.to_owned())
        });

    let effective_pfn = if let Some(ref sid) = effective_sid {
        let mut unique_pfns: HashMap<String, &str> = HashMap::new();
        for c in candidates {
            if c.package_sid
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| s.eq_ignore_ascii_case(sid))
            {
                if let Some(pfn) = c
                    .package_family_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    unique_pfns.entry(pfn.to_ascii_lowercase()).or_insert(pfn);
                }
            }
        }
        (unique_pfns.len() == 1).then(|| (*unique_pfns.values().next().unwrap()).to_owned())
    } else if !candidates_complete || candidates.is_empty() {
        None
    } else {
        candidates
            .first()
            .and_then(|c| c.package_family_name.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|first| {
                candidates
                    .iter()
                    .all(|c| {
                        c.package_family_name
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|p| p.eq_ignore_ascii_case(first))
                    })
                    .then(|| first.to_owned())
            })
    };

    (effective_pfn, effective_sid)
}

#[derive(Debug, Default)]
pub(super) struct WfpDropDedupCache {
    capacity: usize,
    window_ms: i64,
    last_seen: HashMap<(String, Option<String>, IpAddr, u16), i64>,
    insertion_order: VecDeque<(String, Option<String>, IpAddr, u16)>,
}

impl WfpDropDedupCache {
    pub(super) fn new(capacity: usize, window_ms: i64) -> Self {
        Self {
            capacity: capacity.max(1),
            window_ms: window_ms.max(1),
            last_seen: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn should_emit(
        &mut self,
        exe_key: &str,
        package_sid: Option<&str>,
        ip: IpAddr,
        port: u16,
        ts_ms: i64,
    ) -> bool {
        let norm_sid = normalize_package_sid_key(package_sid);
        let key = (exe_key.to_string(), norm_sid, canonical_ip(ip), port);
        if let Some(prev_ts) = self.last_seen.get_mut(&key) {
            if ts_ms >= *prev_ts && ts_ms.saturating_sub(*prev_ts) < self.window_ms {
                return false;
            }
            *prev_ts = ts_ms;
            return true;
        }
        while self.last_seen.len() >= self.capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.last_seen.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.last_seen.insert(key, ts_ms);
        true
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_drop_item(exe: &str, package_sid: Option<&str>, dst_ip: IpAddr) -> QueuedWfpDrop {
        QueuedWfpDrop {
            os_filter_id: 1,
            exe_key: exe.to_ascii_lowercase(),
            exe_path: exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: 1_760_000_000_000,
            package_sid: package_sid.map(str::to_string),
        }
    }

    fn make_candidate(pid: u32, pfn: Option<&str>, sid: Option<&str>) -> WfpCandidate {
        let identity = ProcessIdentity::new(pid, pid as u64);
        WfpCandidate {
            identity,
            instance_id: identity.instance_id(),
            exe_path: r"C:\Windows\System32\backgroundTaskHost.exe".to_string(),
            command_line: None,
            parent_exe_path: None,
            parent_command_line: None,
            origin_url: None,
            motw_source: None,
            motw_referrer: None,
            motw_frame_url: None,
            motw_zone_id: None,
            package_family_name: pfn.map(str::to_string),
            package_sid: sid.map(str::to_string),
        }
    }

    #[test]
    fn overflow_queue_dedup_isolates_distinct_package_sids() {
        let mut q = WfpDropOverflowQueue::new(4);
        let exe = r"C:\Windows\System32\backgroundTaskHost.exe";
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
        let dst2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 45));

        assert_eq!(
            q.push(make_drop_item(exe, Some("S-1-15-2-111"), dst)),
            OverflowPushOutcome::Queued
        );
        assert_eq!(
            q.push(make_drop_item(exe, Some(" S-1-15-2-111 "), dst)),
            OverflowPushOutcome::Deduplicated
        );
        assert_eq!(
            q.push(make_drop_item(exe, Some("S-1-15-2-222"), dst)),
            OverflowPushOutcome::Queued
        );
        assert_eq!(
            q.push(make_drop_item(exe, None, dst)),
            OverflowPushOutcome::Queued
        );

        let first = q.pop().expect("first");
        assert_eq!(first.package_sid.as_deref(), Some("S-1-15-2-111"));
        assert_eq!(
            q.pop().expect("second").package_sid.as_deref(),
            Some("S-1-15-2-222")
        );
        assert_eq!(q.pop().expect("third").package_sid, None);
        assert_eq!(
            q.push(make_drop_item(exe, Some("S-1-15-2-111"), dst)),
            OverflowPushOutcome::Queued
        );

        // Secondary coalescing map must also preserve distinct packages on the same exe/IP.
        let mut q_sec = WfpDropOverflowQueue::new(2);
        assert_eq!(
            q_sec.push(make_drop_item("other_a.exe", None, dst)),
            OverflowPushOutcome::Queued
        );
        assert_eq!(
            q_sec.push(make_drop_item("other_b.exe", None, dst)),
            OverflowPushOutcome::Queued
        );
        // Primary queue is full (2/2). Both packages on `backgroundTaskHost.exe` enter coalesced map.
        assert_eq!(
            q_sec.push(make_drop_item(exe, Some("S-1-15-2-111"), dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q_sec.push(make_drop_item(exe, Some(" s-1-15-2-111 "), dst)),
            OverflowPushOutcome::Deduplicated
        );
        assert_eq!(
            q_sec.push(make_drop_item(exe, Some("S-1-15-2-222"), dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        // Distinct destination for package 111 overwrites only package 111, leaving 222 intact.
        assert_eq!(
            q_sec.push(make_drop_item(exe, Some("S-1-15-2-111"), dst2)),
            OverflowPushOutcome::CoalescedOverwritten
        );
        let _ = q_sec.pop().expect("primary 1");
        let _ = q_sec.pop().expect("primary 2");
        let sec1 = q_sec.pop().expect("secondary pkg 111");
        let sec2 = q_sec.pop().expect("secondary pkg 222");
        assert!(q_sec.pop().is_none());
        assert_eq!(sec1.package_sid.as_deref(), Some("S-1-15-2-111"));
        assert_eq!(sec1.dst_ip, dst2);
        assert_eq!(sec2.package_sid.as_deref(), Some("S-1-15-2-222"));
        assert_eq!(sec2.dst_ip, dst);
    }

    #[test]
    fn overflow_queue_secondary_fair_eviction_protects_other_exe_sole_slot() {
        let bth = r"C:\Windows\System32\backgroundTaskHost.exe";
        let other = r"C:\Tools\other.exe";
        let third = r"C:\Tools\third.exe";
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));

        // Case A: cap = 2, primary full; secondary receives other.exe, bth+PkgA, then bth+PkgB.
        // bth+PkgB must reclaim bth+PkgA rather than evicting other.exe's sole slot.
        let mut q2 = WfpDropOverflowQueue::new(2);
        assert_eq!(
            q2.push(make_drop_item("p1.exe", None, dst)),
            OverflowPushOutcome::Queued
        );
        assert_eq!(
            q2.push(make_drop_item("p2.exe", None, dst)),
            OverflowPushOutcome::Queued
        );
        assert_eq!(
            q2.push(make_drop_item(other, None, dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q2.push(make_drop_item(bth, Some("S-1-15-2-111"), dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q2.push(make_drop_item(bth, Some("S-1-15-2-222"), dst)),
            OverflowPushOutcome::CoalescedOverwritten
        );
        let _ = q2.pop().expect("p1");
        let _ = q2.pop().expect("p2");
        let rem_a1 = q2.pop().expect("other survives");
        let rem_a2 = q2.pop().expect("bth 222 survives");
        assert!(q2.pop().is_none());
        assert_eq!(rem_a1.exe_path, other);
        assert_eq!(rem_a2.exe_path, bth);
        assert_eq!(rem_a2.package_sid.as_deref(), Some("S-1-15-2-222"));

        // Case B: cap = 3, primary full; secondary has [other, bth+111, bth+222].
        // Pushing brand-new third.exe reclaims multi-slot bth+111 before other's sole slot.
        let mut q3 = WfpDropOverflowQueue::new(3);
        for name in ["p1.exe", "p2.exe", "p3.exe"] {
            assert_eq!(
                q3.push(make_drop_item(name, None, dst)),
                OverflowPushOutcome::Queued
            );
        }
        assert_eq!(
            q3.push(make_drop_item(other, None, dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q3.push(make_drop_item(bth, Some("S-1-15-2-111"), dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q3.push(make_drop_item(bth, Some("S-1-15-2-222"), dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        assert_eq!(
            q3.push(make_drop_item(third, None, dst)),
            OverflowPushOutcome::CoalescedNewExe
        );
        for _ in 0..3 {
            let _ = q3.pop().expect("primary item");
        }
        let sec: Vec<(String, Option<String>)> = std::iter::from_fn(|| q3.pop())
            .map(|i| (i.exe_path, i.package_sid))
            .collect();
        assert_eq!(
            sec,
            vec![
                (other.to_string(), None),
                (bth.to_string(), Some("S-1-15-2-222".to_string())),
                (third.to_string(), None),
            ]
        );
    }

    #[test]
    fn app_wfp_alert_dedup_isolates_and_clears_by_package_sid() {
        let mut dedup = AppWfpAlertDedup::new(8);
        let exe_key = r"c:\windows\system32\backgroundtaskhost.exe";
        let dst = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));

        assert!(dedup.mark_if_new(exe_key, Some("S-1-15-2-111"), dst));
        assert!(!dedup.mark_if_new(exe_key, Some("s-1-15-2-111 "), dst));
        assert!(dedup.mark_if_new(exe_key, Some("S-1-15-2-222"), dst));
        assert!(dedup.mark_if_new(exe_key, None, dst));

        dedup.clear_key(exe_key, Some("S-1-15-2-111"), dst);
        assert!(dedup.mark_if_new(exe_key, Some("S-1-15-2-111"), dst));
        assert!(!dedup.mark_if_new(exe_key, Some("S-1-15-2-222"), dst));
        assert!(!dedup.mark_if_new(exe_key, None, dst));
    }

    #[test]
    fn incomplete_candidates_do_not_infer_unanimous_package_without_event_sid() {
        let cand = make_candidate(1001, Some("PkgA_111"), Some("S-1-15-2-111"));

        // Negative DNS / overflowed candidate set without event package_sid must return (None, None).
        assert_eq!(
            resolve_ambiguous_package_context(None, std::slice::from_ref(&cand), false),
            (None, None)
        );

        // Even with incomplete candidates, an explicit kernel package_sid matches known PFN safely.
        assert_eq!(
            resolve_ambiguous_package_context(Some("s-1-15-2-111"), &[cand], false),
            (Some("PkgA_111".to_string()), Some("s-1-15-2-111".to_string()))
        );
    }
}
