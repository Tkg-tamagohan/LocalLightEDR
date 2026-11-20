use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[cfg(doc)]
use ledr_proto::SensorEvent;
use ledr_proto::{
    AlertRecord, AlertSeverity, AlertStatus, AllowlistRuleRecord, ProcessIdentity,
};
use ledr_rules::{
    canonical_ip, classify_outbound_risk, evaluate_outbound_policy, is_external_ip,
    matches_network_target, parse_cidr_target, OutboundDecision, OutboundRiskClass,
};
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
use super::{current_unix_ms, DaemonEngine, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS};

const MAX_PENDING_WFP_DROPS: usize = 512;

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
}

#[derive(Debug, Clone)]
pub(super) struct PendingWfpDrop {
    pub(super) item: QueuedWfpDrop,
    pub(super) deadline: tokio::time::Instant,
}

#[derive(Debug, Clone)]
struct WfpCandidate {
    identity: ProcessIdentity,
    instance_id: String,
    exe_path: String,
    command_line: Option<String>,
    parent_exe_path: Option<String>,
    parent_command_line: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverflowPushOutcome {
    Queued,
    Deduplicated,
    CoalescedNewExe,
    CoalescedOverwritten,
}

/// Bounded overflow fallback queue for [`QueuedWfpDrop`] events when `wfp_drop_tx` is temporarily
/// full inside a non-blocking BFE net-event callback (`L-10`, `BUG_0006` overflow guarantee).
/// Deduplicates identical `(exe_key, dst_ip)` tuples and coalesces per `exe_key` if even the
/// secondary queue reaches `capacity` so blocked apps still reach operator triage.
#[derive(Debug, Default)]
pub(super) struct WfpDropOverflowQueue {
    queue: VecDeque<QueuedWfpDrop>,
    active_keys: HashSet<(String, IpAddr)>,
    coalesced_by_exe: HashMap<String, QueuedWfpDrop>,
    coalesced_order: VecDeque<String>,
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
            last_coalesced: None,
            capacity: capacity.max(1),
        }
    }

    pub(super) fn push(&mut self, item: QueuedWfpDrop) -> OverflowPushOutcome {
        let canon_dst = canonical_ip(item.dst_ip);
        let dedup_key = (item.exe_key.clone(), canon_dst);
        if self.active_keys.contains(&dedup_key) {
            return OverflowPushOutcome::Deduplicated;
        }
        if let Some(existing) = self.coalesced_by_exe.get_mut(&item.exe_key) {
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
        let exe_k = item.exe_key.clone();
        if let std::collections::hash_map::Entry::Occupied(mut entry) =
            self.coalesced_by_exe.entry(exe_k.clone())
        {
            self.last_coalesced = Some((item.exe_path.clone(), canon_dst));
            entry.insert(item);
            return OverflowPushOutcome::CoalescedOverwritten;
        }
        while self.coalesced_by_exe.len() >= self.capacity {
            let Some(evicted) = self.coalesced_order.pop_front() else {
                self.coalesced_by_exe.clear();
                break;
            };
            self.coalesced_by_exe.remove(&evicted);
        }
        self.coalesced_order.push_back(exe_k.clone());
        self.coalesced_by_exe.insert(exe_k, item);
        OverflowPushOutcome::CoalescedNewExe
    }

    pub(super) fn take_last_coalesced(&mut self) -> Option<(String, IpAddr)> {
        self.last_coalesced.take()
    }

    pub(super) fn pop(&mut self) -> Option<QueuedWfpDrop> {
        if let Some(item) = self.queue.pop_front() {
            let dedup_key = (item.exe_key.clone(), canonical_ip(item.dst_ip));
            self.active_keys.remove(&dedup_key);
            return Some(item);
        }
        while let Some(exe_k) = self.coalesced_order.pop_front() {
            if let Some(item) = self.coalesced_by_exe.remove(&exe_k) {
                return Some(item);
            }
        }
        None
    }
}

/// Bounded deduplication set for unresolved app-level ambiguous WFP drop alerts keyed by
/// `(exe_key, canonical_dst_ip)` (`Thread 9`).
#[derive(Debug, Default)]
pub(super) struct AppWfpAlertDedup {
    keys: HashSet<(String, IpAddr)>,
    order: VecDeque<(String, IpAddr)>,
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

    fn mark_if_new(&mut self, exe_key: &str, dst_ip: IpAddr) -> bool {
        let key = (exe_key.to_string(), canonical_ip(dst_ip));
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

    pub(super) fn clear_key(&mut self, exe_key: &str, dst_ip: IpAddr) {
        let key = (exe_key.to_string(), canonical_ip(dst_ip));
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

        {
            let mut dedup = self
                .wfp_drop_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.should_emit(&exe_key, canon_ip, drop_ev.dst_port, effective_ts) {
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

    fn collect_wfp_candidates(&self, exe_key: &str, event_ts_ms: i64) -> Vec<WfpCandidate> {
        let table = self
            .process_table
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        table
            .candidates_by_exe_key_at(exe_key, event_ts_ms)
            .into_iter()
            .map(|e| {
                let (parent_exe_path, parent_command_line) = e
                    .parent_instance_id
                    .as_deref()
                    .and_then(|pid_id| table.get_by_instance_id(pid_id))
                    .map(|p| {
                        (
                            Some(p.exe_path.clone()),
                            (!p.command_line.is_empty()).then(|| p.command_line.clone()),
                        )
                    })
                    .unwrap_or((None, None));
                WfpCandidate {
                    identity: e.identity,
                    instance_id: e.instance_id.clone(),
                    exe_path: e.exe_path.clone(),
                    command_line: (!e.command_line.is_empty()).then(|| e.command_line.clone()),
                    parent_exe_path,
                    parent_command_line,
                }
            })
            .collect()
    }

    pub(super) fn on_wfp_drop_dequeued(
        &self,
        item: QueuedWfpDrop,
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if self.config.wfp_drop_dns_grace_ms > 0 {
            let rules = self.store.list_network_rules().unwrap_or_default();
            if has_domain_allow_rule_for_exe(&item.exe_path, &rules) {
                let candidates = self.collect_wfp_candidates(&item.exe_key, item.timestamp_ms);
                if !candidates.is_empty() {
                    let domain_candidates: Vec<(String, i64)> = {
                        let history = self
                            .process_dns_history
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if candidates.len() == 1 {
                            history.lookup_domains_for_process(&candidates[0].instance_id, item.dst_ip)
                        } else {
                            let mut combined = Vec::new();
                            for c in &candidates {
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
                    let bin_identity = self.inspector.inspect(&item.exe_path);
                    let (decision, _) = select_outbound_decision_for_domains(
                        &bin_identity,
                        item.dst_ip,
                        &domain_candidates,
                        &rules,
                    );
                    let ambiguous_freshness = (candidates.len() > 1)
                        .then_some((item.timestamp_ms, AMBIGUOUS_DNS_HISTORY_MAX_AGE_MS));
                    if matches!(
                        decision,
                        OutboundDecision::PreemptiveRestrict(_)
                            | OutboundDecision::UnknownFirstConnect
                    ) && !self.has_valid_live_domain_policy_permit(
                        &item.exe_path,
                        &bin_identity,
                        item.dst_ip,
                        &domain_candidates,
                        &rules,
                        ambiguous_freshness,
                    ) {
                        while pending.len() >= MAX_PENDING_WFP_DROPS {
                            if let Some(oldest) = pending.pop_front() {
                                self.handle_wfp_drop_event_now(&oldest.item);
                            }
                        }
                        let deadline = tokio::time::Instant::now()
                            + Duration::from_millis(self.config.wfp_drop_dns_grace_ms);
                        pending.push_back(PendingWfpDrop { item, deadline });
                        return;
                    }
                }
            }
        }
        self.handle_wfp_drop_event_now(&item);
    }

    pub(super) fn flush_ready_pending_wfp_drops(
        &self,
        dns_inst_id: &str,
        dns_exe_key: &str,
        _query_name: &str,
        accepted_ips: &[IpAddr],
        pending: &mut VecDeque<PendingWfpDrop>,
    ) {
        if pending.is_empty() || accepted_ips.is_empty() {
            return;
        }
        let canon_accepted: Vec<IpAddr> = accepted_ips.iter().map(|ip| canonical_ip(*ip)).collect();
        let mut cached_rules: Option<Vec<AllowlistRuleRecord>> = None;
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut ready = Vec::new();
        while let Some(entry) = pending.pop_front() {
            let canon_dst = canonical_ip(entry.item.dst_ip);
            if dns_exe_key != entry.item.exe_key || !canon_accepted.contains(&canon_dst) {
                remaining.push_back(entry);
                continue;
            }
            let candidates =
                self.collect_wfp_candidates(&entry.item.exe_key, entry.item.timestamp_ms);
            let dns_matches_candidate = candidates.iter().any(|c| c.instance_id == dns_inst_id);
            if !dns_matches_candidate {
                remaining.push_back(entry);
                continue;
            }
            if candidates.len() == 1 {
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
                    ready.push(entry.item);
                    continue;
                }
                let bin_identity = self.inspector.inspect(&entry.item.exe_path);
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
                    ready.push(entry.item);
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
                        for c in &candidates {
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
                    remaining.push_back(entry);
                    continue;
                }
                let rules = cached_rules
                    .get_or_insert_with(|| self.store.list_network_rules().unwrap_or_default());
                if !has_domain_allow_rule_for_exe(&entry.item.exe_path, rules) {
                    ready.push(entry.item);
                    continue;
                }
                let bin_identity = self.inspector.inspect(&entry.item.exe_path);
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
                ) {
                    ready.push(entry.item);
                } else {
                    remaining.push_back(entry);
                }
            }
        }
        *pending = remaining;
        for item in ready {
            self.handle_wfp_drop_event_now(&item);
        }
    }

    pub(super) fn flush_expired_pending_wfp_drops(&self, pending: &mut VecDeque<PendingWfpDrop>) {
        if pending.is_empty() {
            return;
        }
        let now = tokio::time::Instant::now();
        let mut remaining = VecDeque::with_capacity(pending.len());
        let mut expired = Vec::new();
        while let Some(entry) = pending.pop_front() {
            if entry.deadline <= now {
                expired.push(entry.item);
            } else {
                remaining.push_back(entry);
            }
        }
        *pending = remaining;
        for item in expired {
            self.handle_wfp_drop_event_now(&item);
        }
    }

    pub(super) fn handle_wfp_drop_event_now(&self, item: &QueuedWfpDrop) {
        let candidates = self.collect_wfp_candidates(&item.exe_key, item.timestamp_ms);
        if candidates.is_empty() {
            tracing::debug!(
                exe_path = %item.exe_path,
                dst_ip = %item.dst_ip,
                dst_port = item.dst_port,
                "dropping WFP net event with no active/in-window candidate in ActiveProcessTable"
            );
            return;
        }

        if candidates.len() > 1 {
            // WfpDropEvent carries no PID or local socket tuple (`BUG_0004`); never guess an
            // individual instance across concurrent siblings — keep multi-candidate drops app-level.
            self.handle_ambiguous_wfp_drop(item, &candidates);
            return;
        }
        let cand = &candidates[0];

        let domain_candidates = {
            let history = self
                .process_dns_history
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            history.lookup_domains_for_process(&cand.instance_id, item.dst_ip)
        };
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
            if let Err(err) = self.store.flush_batch() {
                tracing::warn!(error = %err, "failed flushing store after attributed WFP drop alert");
            }
        }
    }

    fn handle_ambiguous_wfp_drop(&self, item: &QueuedWfpDrop, candidates: &[WfpCandidate]) {
        let canonical_exe = candidates
            .first()
            .map(|c| c.exe_path.as_str())
            .unwrap_or(item.exe_path.as_str());
        let risk = classify_outbound_risk(canonical_exe);
        if risk == OutboundRiskClass::ProtectedOs {
            return;
        }
        let rules = self.store.list_network_rules().unwrap_or_default();
        let bin_identity = self.inspector.inspect(canonical_exe);
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

        {
            let mut dedup = self
                .app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !dedup.mark_if_new(&item.exe_key, item.dst_ip) {
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
                        let (rid, sev, lbl) = match risk {
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
            "risk_class": format!("{risk:?}"),
            "wfp_blocked": wfp_filter_id.is_some(),
            "wfp_filter_id": wfp_filter_id,
            "sha256": bin_identity.sha256,
            "signer_subject": bin_identity.authenticode.as_ref().map(|a| a.signer_subject.as_str()),
            "root_thumbprint": bin_identity.authenticode.as_ref().map(|a| a.root_thumbprint.as_str()),
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
                self.firewall
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .unbind_alert(&alert_id);
            }
            self.app_wfp_alert_dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clear_key(&item.exe_key, item.dst_ip);
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
        if let Err(err) = self.store.flush_batch() {
            tracing::warn!(error = %err, "failed flushing store after app-level WFP drop alert");
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct WfpDropDedupCache {
    capacity: usize,
    window_ms: i64,
    last_seen: HashMap<(String, IpAddr, u16), i64>,
    insertion_order: VecDeque<(String, IpAddr, u16)>,
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

    fn should_emit(&mut self, exe_key: &str, ip: IpAddr, port: u16, ts_ms: i64) -> bool {
        let key = (exe_key.to_string(), canonical_ip(ip), port);
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
