//! Bounded two-lane event ingestion channel (`決定記録 L-10`).
//!
//! - High-priority lane (`HIGH_PRIORITY_CHANNEL_CAPACITY` = 1,024): never drops events.
//! - Telemetry lane (`TELEMETRY_CHANNEL_CAPACITY` = 8,192): drop-oldest ring buffer (`VecDeque`)
//!   that counts evicted events in `telemetry_dropped`.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ledr_proto::{
    EventLane, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY, HIGH_PRIORITY_CHANNEL_CAPACITY,
    TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::is_external_ip;
use ledr_sensor_win::ProcessPackageInfo;
use tokio::sync::{mpsc, watch, Notify};

#[derive(Debug, Clone)]
struct HighPriorityItem {
    event: SensorEvent,
    package: ProcessPackageInfo,
}

/// Error returned when a high-priority event cannot be sent immediately or the channel is closed.
#[derive(Debug)]
pub enum HighPrioritySendError {
    Full(SensorEvent),
    Closed(SensorEvent),
}

impl fmt::Display for HighPrioritySendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(_) => {
                write!(
                    f,
                    "high-priority lane is full (capacity reached, event preserved to caller)"
                )
            }
            Self::Closed(_) => write!(f, "two-lane channel is closed"),
        }
    }
}

impl std::error::Error for HighPrioritySendError {}

/// Error returned when sending an event to a closed [`TwoLaneChannel`].
#[derive(Debug)]
pub struct ChannelClosedError(pub SensorEvent);

impl fmt::Display for ChannelClosedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "two-lane channel is closed")
    }
}

impl std::error::Error for ChannelClosedError {}

const TELEMETRY_IDLE_BASELINE_CAPACITY: usize = 1024;

#[derive(Debug)]
struct TelemetryState {
    queue: VecDeque<SensorEvent>,
    closed: bool,
    last_above_1024_at: Option<Instant>,
}

#[derive(Debug)]
struct TelemetryRing {
    capacity: usize,
    state: Mutex<TelemetryState>,
    dropped: AtomicU64,
    notify: Notify,
}

impl TelemetryRing {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(TelemetryState {
                queue: VecDeque::with_capacity(capacity.min(TELEMETRY_IDLE_BASELINE_CAPACITY)),
                closed: false,
                last_above_1024_at: None,
            }),
            dropped: AtomicU64::new(0),
            notify: Notify::new(),
        }
    }

    fn push(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.closed {
                return Err(ChannelClosedError(event));
            }
            if guard.queue.len() >= self.capacity {
                guard.queue.pop_front();
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            guard.queue.push_back(event);
            if guard.queue.len() > TELEMETRY_IDLE_BASELINE_CAPACITY {
                guard.last_above_1024_at = Some(Instant::now());
            }
        }
        self.notify.notify_one();
        Ok(())
    }

    fn try_pop(&self) -> Option<SensorEvent> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let event = guard.queue.pop_front();
        if guard.queue.len() > TELEMETRY_IDLE_BASELINE_CAPACITY {
            guard.last_above_1024_at = Some(Instant::now());
        }
        event
    }

    fn shrink_to_if_idle(&self, idle_threshold: Duration) -> bool {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.queue.is_empty() || guard.queue.capacity() <= TELEMETRY_IDLE_BASELINE_CAPACITY {
            return false;
        }
        let Some(last_above) = guard.last_above_1024_at else {
            return false;
        };
        if last_above.elapsed() < idle_threshold {
            return false;
        }
        guard.queue.shrink_to(TELEMETRY_IDLE_BASELINE_CAPACITY);
        guard.last_above_1024_at = None;
        true
    }

    #[cfg(test)]
    fn queue_capacity(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .queue
            .capacity()
    }

    #[cfg(test)]
    fn backdate_last_above_1024(&self, age: Duration) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.last_above_1024_at = Some(
            Instant::now()
                .checked_sub(age)
                .unwrap_or_else(Instant::now),
        );
    }

    fn len(&self) -> usize {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.queue.len()
    }

    fn close(&self) {
        {
            let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.closed = true;
        }
        self.notify.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.closed
    }
}

#[derive(Debug)]
struct SharedStats {
    high_capacity: usize,
    high_dropped: AtomicU64,
    closed: AtomicBool,
    in_flight_high: AtomicUsize,
    in_flight_notify: Notify,
}

struct InFlightHighGuard<'a> {
    stats: &'a SharedStats,
}

impl<'a> InFlightHighGuard<'a> {
    fn enter(stats: &'a SharedStats) -> Self {
        stats.in_flight_high.fetch_add(1, Ordering::SeqCst);
        Self { stats }
    }
}

impl Drop for InFlightHighGuard<'_> {
    fn drop(&mut self) {
        if self.stats.in_flight_high.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.stats.in_flight_notify.notify_waiters();
        }
    }
}

/// Cloneable producer handle for [`TwoLaneChannel`].
#[derive(Debug, Clone)]
pub struct TwoLaneSender {
    high_tx: mpsc::Sender<HighPriorityItem>,
    telemetry: Arc<TelemetryRing>,
    stats: Arc<SharedStats>,
    close_tx: Arc<watch::Sender<bool>>,
}

impl TwoLaneSender {
    /// Routes `event` to its [`SensorEvent::default_lane`], awaiting space if the
    /// high-priority lane is temporarily full (never dropping high-priority events).
    pub async fn send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.send_with_package(event, ProcessPackageInfo::default())
            .await
    }

    /// Routes `event` paired with [`ProcessPackageInfo`] to its [`SensorEvent::default_lane`].
    pub async fn send_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), ChannelClosedError> {
        match event.default_lane() {
            EventLane::HighPriority => self
                .send_high_priority_with_package(event, package)
                .await
                .map_err(|err| match err {
                    HighPrioritySendError::Full(ev) | HighPrioritySendError::Closed(ev) => {
                        ChannelClosedError(ev)
                    }
                }),
            EventLane::Telemetry => self.send_telemetry(event),
        }
    }

    /// Non-blocking send routing `event` by [`SensorEvent::default_lane`].
    pub fn try_send(&self, event: SensorEvent) -> Result<(), HighPrioritySendError> {
        match event.default_lane() {
            EventLane::HighPriority => self.try_send_high_priority(event),
            EventLane::Telemetry => self
                .send_telemetry(event)
                .map_err(|ChannelClosedError(ev)| HighPrioritySendError::Closed(ev)),
        }
    }

    /// Sends a high-priority event, waiting for capacity instead of dropping (`L-10`).
    pub async fn send_high_priority(&self, event: SensorEvent) -> Result<(), HighPrioritySendError> {
        self.send_high_priority_with_package(event, ProcessPackageInfo::default())
            .await
    }

    async fn send_high_priority_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), HighPrioritySendError> {
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(HighPrioritySendError::Closed(event));
        }
        self.high_tx
            .send(HighPriorityItem { event, package })
            .await
            .map_err(|mpsc::error::SendError(item)| HighPrioritySendError::Closed(item.event))
    }

    /// Attempts to enqueue a high-priority event without awaiting or dropping (`L-10`).
    pub fn try_send_high_priority(&self, event: SensorEvent) -> Result<(), HighPrioritySendError> {
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(HighPrioritySendError::Closed(event));
        }
        self.high_tx
            .try_send(HighPriorityItem {
                event,
                package: ProcessPackageInfo::default(),
            })
            .map_err(|err| match err {
                mpsc::error::TrySendError::Full(item) => HighPrioritySendError::Full(item.event),
                mpsc::error::TrySendError::Closed(item) => {
                    HighPrioritySendError::Closed(item.event)
                }
            })
    }

    /// Blocking send for synchronous producer threads (such as the ETW callback bridge).
    pub fn blocking_send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.blocking_send_with_package(event, ProcessPackageInfo::default())
    }

    /// Blocking send paired with [`ProcessPackageInfo`] for synchronous producers (`FU-P4-03`).
    pub fn blocking_send_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), ChannelClosedError> {
        match event.default_lane() {
            EventLane::HighPriority => self.blocking_send_high_priority_with_package(event, package),
            EventLane::Telemetry => self.send_telemetry(event),
        }
    }

    /// Blocking send directly into the non-dropping high-priority lane (`L-10`).
    pub fn blocking_send_high_priority(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.blocking_send_high_priority_with_package(event, ProcessPackageInfo::default())
    }

    fn blocking_send_high_priority_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), ChannelClosedError> {
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(ChannelClosedError(event));
        }
        self.high_tx
            .blocking_send(HighPriorityItem { event, package })
            .map_err(|mpsc::error::SendError(item)| ChannelClosedError(item.event))
    }

    /// Enqueues a telemetry event into the drop-oldest ring buffer (`L-10`).
    pub fn send_telemetry(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.telemetry.push(event)
    }

    /// Marks the channel closed so consumers drain all remaining queued events and terminate.
    pub fn close(&self) {
        self.stats.closed.store(true, Ordering::SeqCst);
        self.telemetry.close();
        let _ = self.close_tx.send(true);
        self.stats.in_flight_notify.notify_waiters();
    }

    /// Current queued depth in the high-priority lane.
    pub fn high_priority_depth(&self) -> usize {
        if self.high_tx.is_closed() {
            0
        } else {
            self.stats
                .high_capacity
                .saturating_sub(self.high_tx.capacity())
        }
    }

    /// Configured capacity of the high-priority lane.
    pub fn high_priority_capacity(&self) -> usize {
        self.stats.high_capacity
    }

    /// Total high-priority events dropped (always `0` per `決定記録 L-10`).
    pub fn high_priority_dropped(&self) -> u64 {
        self.stats.high_dropped.load(Ordering::Relaxed)
    }

    /// Current queued depth in the telemetry lane.
    pub fn telemetry_depth(&self) -> usize {
        self.telemetry.len()
    }

    /// Configured capacity of the telemetry lane.
    pub fn telemetry_capacity(&self) -> usize {
        self.telemetry.capacity
    }

    /// Total oldest telemetry events evicted because the telemetry ring buffer was full.
    pub fn telemetry_dropped(&self) -> u64 {
        self.telemetry.dropped.load(Ordering::Relaxed)
    }

    /// Shrinks the telemetry ring buffer back to 1,024 slots when empty and idle for at least
    /// `idle_threshold` since the queue last exceeded 1,024 entries (`FU-E2E-03` Track 1b).
    pub fn shrink_telemetry_if_idle(&self, idle_threshold: Duration) -> bool {
        self.telemetry.shrink_to_if_idle(idle_threshold)
    }

    #[cfg(test)]
    pub(crate) fn telemetry_queue_capacity(&self) -> usize {
        self.telemetry.queue_capacity()
    }

    #[cfg(test)]
    pub(crate) fn backdate_telemetry_last_above_1024_for_test(&self, age: Duration) {
        self.telemetry.backdate_last_above_1024(age);
    }
}

/// Consumer half of [`TwoLaneChannel`] draining high-priority events strictly before telemetry.
#[derive(Debug)]
pub struct TwoLaneReceiver {
    high_rx: mpsc::Receiver<HighPriorityItem>,
    telemetry: Arc<TelemetryRing>,
    stats: Arc<SharedStats>,
    close_rx: watch::Receiver<bool>,
}

impl TwoLaneReceiver {
    /// Receives the next event, strictly prioritizing the high-priority lane over telemetry.
    /// Returns `None` only after the channel is closed AND both lanes are completely drained.
    pub async fn recv(&mut self) -> Option<SensorEvent> {
        self.recv_with_lane().await.map(|(ev, _)| ev)
    }

    pub(crate) async fn recv_with_lane(&mut self) -> Option<(SensorEvent, EventLane)> {
        self.recv_with_lane_and_package()
            .await
            .map(|(ev, lane, _)| (ev, lane))
    }

    pub(crate) async fn recv_with_lane_and_package(
        &mut self,
    ) -> Option<(SensorEvent, EventLane, ProcessPackageInfo)> {
        loop {
            if let Ok(item) = self.high_rx.try_recv() {
                return Some((item.event, EventLane::HighPriority, item.package));
            }

            let notified = self.telemetry.notify.notified();
            tokio::pin!(notified);

            if let Some(ev) = self.telemetry.try_pop() {
                return Some((ev, EventLane::Telemetry, ProcessPackageInfo::default()));
            }

            if *self.close_rx.borrow() || self.telemetry.is_closed() {
                if self.stats.in_flight_high.load(Ordering::SeqCst) == 0 {
                    self.high_rx.close();
                    if let Some(item) = self.high_rx.recv().await {
                        return Some((item.event, EventLane::HighPriority, item.package));
                    }
                    if let Some(ev) = self.telemetry.try_pop() {
                        return Some((ev, EventLane::Telemetry, ProcessPackageInfo::default()));
                    }
                    return None;
                }

                let in_flight_notified = self.stats.in_flight_notify.notified();
                tokio::pin!(in_flight_notified);
                if self.stats.in_flight_high.load(Ordering::SeqCst) == 0 {
                    continue;
                }
                tokio::select! {
                    biased;
                    maybe_high = self.high_rx.recv() => {
                        if let Some(item) = maybe_high {
                            return Some((item.event, EventLane::HighPriority, item.package));
                        }
                    }
                    _ = &mut in_flight_notified => {}
                }
                continue;
            }

            tokio::select! {
                biased;
                maybe_high = self.high_rx.recv() => {
                    if let Some(item) = maybe_high {
                        return Some((item.event, EventLane::HighPriority, item.package));
                    }
                    // High-priority senders dropped; drain any remaining telemetry and exit on next pass.
                    self.telemetry.close();
                }
                _ = &mut notified => {}
                _ = self.close_rx.changed() => {}
            }
        }
    }

    pub(crate) fn try_recv_high_priority_with_package(
        &mut self,
    ) -> Option<(SensorEvent, ProcessPackageInfo)> {
        self.high_rx
            .try_recv()
            .ok()
            .map(|item| (item.event, item.package))
    }

    pub(crate) fn try_recv_telemetry(&mut self) -> Option<SensorEvent> {
        self.telemetry.try_pop()
    }

    /// Non-blocking drain of all currently buffered events (high-priority first, then telemetry).
    pub fn drain_ready(&mut self) -> Vec<SensorEvent> {
        self.drain_ready_with_lane()
            .into_iter()
            .map(|(ev, _)| ev)
            .collect()
    }

    pub(crate) fn drain_ready_with_lane(&mut self) -> Vec<(SensorEvent, EventLane)> {
        self.drain_ready_with_lane_and_package()
            .into_iter()
            .map(|(ev, lane, _)| (ev, lane))
            .collect()
    }

    pub(crate) fn drain_ready_with_lane_and_package(
        &mut self,
    ) -> Vec<(SensorEvent, EventLane, ProcessPackageInfo)> {
        if (*self.close_rx.borrow() || self.telemetry.is_closed())
            && self.stats.in_flight_high.load(Ordering::SeqCst) == 0
        {
            self.high_rx.close();
        }
        let mut out = Vec::new();
        while let Ok(item) = self.high_rx.try_recv() {
            out.push((item.event, EventLane::HighPriority, item.package));
        }
        while let Some(ev) = self.telemetry.try_pop() {
            out.push((ev, EventLane::Telemetry, ProcessPackageInfo::default()));
        }
        out
    }
}

/// Bounded per-PID steady-state tracker used by [`ClassifiedEventSender`] to promote
/// unverified external [`SensorEvent::NetworkConnect`] events onto the non-dropping
/// high-priority lane (`決定記録 L-10`) while routing steady/known traffic via telemetry.
#[derive(Debug)]
pub struct OutboundLaneClassifier {
    outbound_firewall_enabled: bool,
    has_domain_rules: AtomicBool,
    protected_pids: RwLock<HashSet<u32>>,
    steady_pids: RwLock<HashSet<u32>>,
}

impl OutboundLaneClassifier {
    /// Creates a new [`OutboundLaneClassifier`] bound to `outbound_firewall_enabled`.
    pub fn new(outbound_firewall_enabled: bool) -> Self {
        Self {
            outbound_firewall_enabled,
            has_domain_rules: AtomicBool::new(false),
            protected_pids: RwLock::new(HashSet::new()),
            steady_pids: RwLock::new(HashSet::new()),
        }
    }

    /// Returns `true` when outbound firewall lane promotion is enabled.
    pub fn outbound_firewall_enabled(&self) -> bool {
        self.outbound_firewall_enabled
    }

    /// Updates whether any persisted domain/wildcard network rule is active so [`ClassifiedEventSender`]
    /// promotes external [`SensorEvent::DnsQuery`] events onto `HighPriority` ahead of
    /// [`SensorEvent::NetworkConnect`] without losing domain correlation under telemetry pressure.
    pub fn set_has_domain_rules(&self, has_domain_rules: bool) {
        self.has_domain_rules
            .store(has_domain_rules, Ordering::Release);
    }

    /// Returns `true` when domain-scoped outbound policy rules require lossless DNS ingestion.
    pub fn has_domain_rules(&self) -> bool {
        self.has_domain_rules.load(Ordering::Acquire)
    }

    /// Returns `true` when `pid` is currently marked steady (protected OS, app-wide allowed,
    /// `AllowOnce`, or dedup-suppressed with no persisted network rules).
    pub fn is_steady_pid(&self, pid: u32) -> bool {
        self.steady_pids
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&pid)
    }

    /// Returns `true` when an external [`SensorEvent::NetworkConnect`] for `pid` must be
    /// promoted to the high-priority lane (`L-10`).
    pub fn should_promote_network_connect(&self, pid: u32, dst_ip: IpAddr) -> bool {
        self.outbound_firewall_enabled && is_external_ip(dst_ip) && !self.is_steady_pid(pid)
    }

    /// Returns `true` when an external [`SensorEvent::DnsQuery`] for `pid` must be promoted to the
    /// high-priority lane so domain-scoped network rules are never starved behind telemetry overflow.
    pub fn should_promote_dns_query(&self, pid: u32, resolved_ips: &[IpAddr]) -> bool {
        self.outbound_firewall_enabled
            && self.has_domain_rules()
            && !self.is_steady_pid(pid)
            && resolved_ips.iter().any(|ip| is_external_ip(*ip))
    }

    /// Marks `pid` as steady (bounded at `ACTIVE_PROCESS_TABLE_CAPACITY`).
    pub fn mark_steady(&self, pid: u32) {
        let protected = self
            .protected_pids
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut steady = self.steady_pids.write().unwrap_or_else(|e| e.into_inner());
        if !steady.contains(&pid) && steady.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
            steady.retain(|p| protected.contains(p));
            if steady.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
                steady.clear();
            }
        }
        steady.insert(pid);
    }

    /// Marks `pid` as a `ProtectedOs` process and retains it as steady across policy updates.
    pub fn mark_protected_os(&self, pid: u32) {
        let mut protected = self
            .protected_pids
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if !protected.contains(&pid) && protected.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
            protected.clear();
        }
        protected.insert(pid);
        let mut steady = self.steady_pids.write().unwrap_or_else(|e| e.into_inner());
        if !steady.contains(&pid) && steady.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
            steady.retain(|p| protected.contains(p));
            if steady.len() >= ACTIVE_PROCESS_TABLE_CAPACITY {
                steady.clear();
            }
        }
        steady.insert(pid);
    }

    /// Clears steady state for `pid` (e.g. on `ProcessStart` or `ProcessStop`).
    pub fn remove_pid(&self, pid: u32) {
        let mut protected = self
            .protected_pids
            .write()
            .unwrap_or_else(|e| e.into_inner());
        let mut steady = self.steady_pids.write().unwrap_or_else(|e| e.into_inner());
        protected.remove(&pid);
        steady.remove(&pid);
    }

    /// Clears all non-`ProtectedOs` steady PIDs (called on policy changes or permit revocation).
    pub fn clear_non_protected(&self) {
        let protected = self
            .protected_pids
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut steady = self.steady_pids.write().unwrap_or_else(|e| e.into_inner());
        steady.retain(|pid| protected.contains(pid));
    }

    /// Returns the number of PIDs currently tracked as steady.
    pub fn steady_pid_count(&self) -> usize {
        self.steady_pids
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

/// Cloneable producer handle wrapping [`TwoLaneSender`] + [`OutboundLaneClassifier`] (without
/// referencing [`crate::DaemonEngine`]) so unknown external `NetworkConnect` events promote onto
/// the non-dropping high-priority lane (`L-10`).
#[derive(Debug, Clone)]
pub struct ClassifiedEventSender {
    inner: TwoLaneSender,
    classifier: Arc<OutboundLaneClassifier>,
}

impl ClassifiedEventSender {
    /// Creates a new [`ClassifiedEventSender`].
    pub fn new(inner: TwoLaneSender, classifier: Arc<OutboundLaneClassifier>) -> Self {
        Self { inner, classifier }
    }

    /// Returns `true` when `event` will be promoted to the high-priority lane.
    pub fn should_promote(&self, event: &SensorEvent) -> bool {
        match event {
            SensorEvent::NetworkConnect { pid, dst_ip, .. } => {
                self.classifier.should_promote_network_connect(*pid, *dst_ip)
            }
            SensorEvent::DnsQuery {
                pid, resolved_ips, ..
            } => self.classifier.should_promote_dns_query(*pid, resolved_ips),
            _ => false,
        }
    }

    /// Sends `event`, promoting unverified external `NetworkConnect` events to high-priority.
    pub async fn send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.send_with_package(event, ProcessPackageInfo::default())
            .await
    }

    /// Sends `event` paired with [`ProcessPackageInfo`], promoting qualifying events to high-priority.
    pub async fn send_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), ChannelClosedError> {
        if self.should_promote(&event) {
            self.inner
                .send_high_priority_with_package(event, package)
                .await
                .map_err(|err| match err {
                    HighPrioritySendError::Full(ev) | HighPrioritySendError::Closed(ev) => {
                        ChannelClosedError(ev)
                    }
                })
        } else {
            self.inner.send_with_package(event, package).await
        }
    }

    /// Non-blocking send with high-priority promotion for unverified external `NetworkConnect`.
    pub fn try_send(&self, event: SensorEvent) -> Result<(), HighPrioritySendError> {
        if self.should_promote(&event) {
            self.inner.try_send_high_priority(event)
        } else {
            self.inner.try_send(event)
        }
    }

    /// Blocking send for synchronous producers (ETW callback bridge) with high-priority promotion.
    pub fn blocking_send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        self.blocking_send_with_package(event, ProcessPackageInfo::default())
    }

    /// Blocking send paired with [`ProcessPackageInfo`] for synchronous ETW callback bridges.
    pub fn blocking_send_with_package(
        &self,
        event: SensorEvent,
        package: ProcessPackageInfo,
    ) -> Result<(), ChannelClosedError> {
        if self.should_promote(&event) {
            self.inner
                .blocking_send_high_priority_with_package(event, package)
        } else {
            self.inner.blocking_send_with_package(event, package)
        }
    }

    /// Returns a reference to the underlying [`TwoLaneSender`].
    pub fn inner(&self) -> &TwoLaneSender {
        &self.inner
    }

    /// Returns a reference to the shared [`OutboundLaneClassifier`].
    pub fn classifier(&self) -> &OutboundLaneClassifier {
        &self.classifier
    }

    /// Current queued depth in the high-priority lane.
    pub fn high_priority_depth(&self) -> usize {
        self.inner.high_priority_depth()
    }

    /// Current queued depth in the telemetry lane.
    pub fn telemetry_depth(&self) -> usize {
        self.inner.telemetry_depth()
    }

    /// Total oldest telemetry events evicted because the telemetry ring buffer was full.
    pub fn telemetry_dropped(&self) -> u64 {
        self.inner.telemetry_dropped()
    }

    /// Total high-priority events dropped (always `0`).
    pub fn high_priority_dropped(&self) -> u64 {
        self.inner.high_priority_dropped()
    }

    /// Marks the underlying channel closed.
    pub fn close(&self) {
        self.inner.close();
    }
}

/// Bounded two-lane pipeline channel (`HIGH_PRIORITY_CHANNEL_CAPACITY` + `TELEMETRY_CHANNEL_CAPACITY`).
#[derive(Debug)]
pub struct TwoLaneChannel {
    sender: TwoLaneSender,
    receiver: TwoLaneReceiver,
}

impl Default for TwoLaneChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl TwoLaneChannel {
    /// Creates a new two-lane channel with default capacities (`1,024` and `8,192`, `L-10`).
    pub fn new() -> Self {
        Self::with_capacities(HIGH_PRIORITY_CHANNEL_CAPACITY, TELEMETRY_CHANNEL_CAPACITY)
    }

    /// Creates a new two-lane channel with explicit lane capacities.
    pub fn with_capacities(high_priority_capacity: usize, telemetry_capacity: usize) -> Self {
        let hp_cap = high_priority_capacity.max(1);
        let tel_cap = telemetry_capacity.max(1);
        let (high_tx, high_rx) = mpsc::channel(hp_cap);
        let telemetry = Arc::new(TelemetryRing::new(tel_cap));
        let (close_tx, close_rx) = watch::channel(false);

        let stats = Arc::new(SharedStats {
            high_capacity: hp_cap,
            high_dropped: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            in_flight_high: AtomicUsize::new(0),
            in_flight_notify: Notify::new(),
        });
        let sender = TwoLaneSender {
            high_tx,
            telemetry: Arc::clone(&telemetry),
            stats: Arc::clone(&stats),
            close_tx: Arc::new(close_tx),
        };
        let receiver = TwoLaneReceiver {
            high_rx,
            telemetry,
            stats,
            close_rx,
        };
        Self { sender, receiver }
    }

    /// Returns a cloneable producer handle without consuming the channel.
    pub fn sender(&self) -> TwoLaneSender {
        self.sender.clone()
    }

    /// Splits the channel into `(TwoLaneSender, TwoLaneReceiver)`.
    pub fn split(self) -> (TwoLaneSender, TwoLaneReceiver) {
        (self.sender, self.receiver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledr_proto::ProcessIdentity;
    use std::net::{IpAddr, Ipv4Addr};

    fn dns_query(
        pid: u32,
        query_name: impl Into<String>,
        ip: Ipv4Addr,
        timestamp_ms: i64,
    ) -> SensorEvent {
        SensorEvent::DnsQuery {
            pid,
            query_name: query_name.into(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(ip)],
            timestamp_ms,
        }
    }

    fn network_connect(
        pid: u32,
        dst_ip: Ipv4Addr,
        domain_hint: Option<&str>,
        timestamp_ms: i64,
    ) -> SensorEvent {
        SensorEvent::NetworkConnect {
            pid,
            protocol: 6,
            dst_ip: IpAddr::V4(dst_ip),
            dst_port: 443,
            domain_hint: domain_hint.map(str::to_string),
            timestamp_ms,
        }
    }

    #[tokio::test]
    async fn channel_prioritizes_high_priority_and_drops_oldest_telemetry() {
        let (tx, mut rx) = TwoLaneChannel::with_capacities(2, 3).split();
        assert_eq!(tx.high_priority_capacity(), 2);
        assert_eq!(tx.telemetry_capacity(), 3);

        for i in 0..5 {
            tx.send_telemetry(dns_query(1, format!("d{i}.test"), Ipv4Addr::new(1, 1, 1, 1), i))
                .expect("telemetry send");
        }
        assert_eq!(tx.telemetry_depth(), 3);
        assert_eq!(tx.telemetry_dropped(), 2);

        tx.try_send_high_priority(SensorEvent::ProcessStart {
            identity: ProcessIdentity::new(10, 100),
            parent_pid: 4,
            exe_path: "a.exe".to_string(),
            command_line: String::new(),
            user_sid: None,
        })
        .expect("hp 1");
        tx.try_send_high_priority(SensorEvent::ProcessStop {
            pid: 10,
            exit_time_100ns: 200,
            exit_code: 0,
        })
        .expect("hp 2");
        assert!(matches!(
            tx.try_send_high_priority(SensorEvent::ProcessStop {
                pid: 11,
                exit_time_100ns: 201,
                exit_code: 0,
            }),
            Err(HighPrioritySendError::Full(_))
        ));
        assert_eq!(tx.high_priority_dropped(), 0);

        tx.close();
        let mut drained = Vec::new();
        while let Some(ev) = rx.recv().await {
            drained.push(ev);
        }
        assert_eq!(drained.len(), 5);
        assert!(matches!(drained[0], SensorEvent::ProcessStart { .. }));
        assert!(matches!(drained[1], SensorEvent::ProcessStop { .. }));
        match &drained[2] {
            SensorEvent::DnsQuery { query_name, .. } => assert_eq!(query_name, "d2.test"),
            other => panic!("expected d2.test, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classified_sender_promotes_unknown_external_connect_over_saturated_telemetry() {
        let (tx, mut rx) = TwoLaneChannel::with_capacities(4, 3).split();
        let classifier = Arc::new(OutboundLaneClassifier::new(true));
        let classified = ClassifiedEventSender::new(tx.clone(), Arc::clone(&classifier));

        classifier.mark_protected_os(42);
        classifier.mark_steady(99);

        // Private IP is NOT promoted; steady/protected PID external IP is NOT promoted.
        let private_ev = network_connect(500, Ipv4Addr::new(192, 168, 1, 10), None, 1);
        let steady_ev = network_connect(99, Ipv4Addr::new(93, 184, 216, 34), None, 2);
        assert!(!classified.should_promote(&private_ev));
        assert!(!classified.should_promote(&steady_ev));

        // Unknown external NetworkConnect IS promoted via high-priority lane even when telemetry overflows.
        let unknown_ext =
            network_connect(500, Ipv4Addr::new(93, 184, 216, 34), Some("unknown.example"), 3);
        assert!(classified.should_promote(&unknown_ext));

        // Send promoted event synchronously from a non-runtime OS thread via `blocking_send`.
        let classified_bg = classified.clone();
        let promoted_clone = unknown_ext.clone();
        std::thread::spawn(move || {
            classified_bg
                .blocking_send(promoted_clone)
                .expect("blocking_send promoted");
        })
        .join()
        .expect("join producer");

        // Saturate telemetry AFTER sending unknown_ext so telemetry drops older entries.
        for i in 0..6 {
            classified
                .send(dns_query(
                    99,
                    format!("noise-{i}.example"),
                    Ipv4Addr::new(198, 51, 100, 1),
                    10 + i,
                ))
                .await
                .expect("noise dns");
        }
        assert_eq!(classified.telemetry_dropped(), 3);
        assert_eq!(classified.high_priority_depth(), 1);

        // Policy invalidation clears non-protected steady PID 99 while retaining protected PID 42.
        classifier.clear_non_protected();
        assert!(!classifier.is_steady_pid(99));
        assert!(classifier.is_steady_pid(42));

        classified.close();
        let drained = rx.drain_ready_with_lane();
        assert_eq!(drained[0], (unknown_ext, EventLane::HighPriority));
        assert_eq!(drained.len(), 4);

        // Disabled firewall mode never promotes NetworkConnect or DnsQuery.
        let disabled = OutboundLaneClassifier::new(false);
        assert!(!disabled.should_promote_network_connect(500, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        disabled.set_has_domain_rules(true);
        assert!(!disabled.should_promote_dns_query(500, &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]));
    }

    #[tokio::test]
    async fn classified_sender_promotes_dns_query_only_when_domain_rules_active() {
        let (tx, mut rx) = TwoLaneChannel::with_capacities(8, 2).split();
        let classifier = Arc::new(OutboundLaneClassifier::new(true));
        let classified = ClassifiedEventSender::new(tx, Arc::clone(&classifier));
        classifier.mark_steady(99);

        let ext_dns = dns_query(500, "api.allowed.example", Ipv4Addr::new(93, 184, 216, 34), 1);
        let steady_dns = dns_query(99, "steady.example", Ipv4Addr::new(93, 184, 216, 34), 2);
        let local_dns = dns_query(500, "intranet.local", Ipv4Addr::new(10, 0, 0, 5), 3);

        // Without domain rules, DnsQuery stays on Telemetry so telemetry backpressure can shed it.
        assert!(!classified.should_promote(&ext_dns));

        // Enabling domain rules promotes non-steady external DnsQuery onto HighPriority in order
        // before NetworkConnect, even while Telemetry drops older messages.
        classifier.set_has_domain_rules(true);
        assert!(classified.should_promote(&ext_dns));
        assert!(!classified.should_promote(&steady_dns));
        assert!(!classified.should_promote(&local_dns));

        let connect = network_connect(500, Ipv4Addr::new(93, 184, 216, 34), None, 4);
        classified.send(ext_dns.clone()).await.expect("dns");
        classified.send(connect.clone()).await.expect("connect");

        // Overflow Telemetry with steady noise; HighPriority DNS + Connect remain lossless & ordered.
        for i in 0..5 {
            classified
                .send(dns_query(
                    99,
                    format!("overflow-{i}.example"),
                    Ipv4Addr::new(1, 1, 1, 1),
                    10 + i,
                ))
                .await
                .expect("noise");
        }
        assert_eq!(classified.telemetry_dropped(), 3);
        classified.close();
        let drained = rx.drain_ready_with_lane();
        assert_eq!(drained[0], (ext_dns, EventLane::HighPriority));
        assert_eq!(drained[1], (connect, EventLane::HighPriority));
    }

    /// `CHAN-MEM-01`: `TelemetryRing` expands to absorb 8,192 events, refuses to shrink while
    /// non-empty or before the 30s idle threshold, shrinks back to `<= with_capacity(1024)` once
    /// drained and idle `>= 30s`, and cleanly accepts another 8,192-event burst (`L-10` non-regression).
    #[test]
    fn chan_mem_01_telemetry_ring_shrinks_after_idle_and_rebursts() {
        let (tx, mut rx) = TwoLaneChannel::new().split();
        assert_eq!(tx.high_priority_capacity(), HIGH_PRIORITY_CHANNEL_CAPACITY);
        assert_eq!(tx.telemetry_capacity(), TELEMETRY_CHANNEL_CAPACITY);

        let baseline_cap = VecDeque::<SensorEvent>::with_capacity(TELEMETRY_IDLE_BASELINE_CAPACITY).capacity();
        assert!(tx.telemetry_queue_capacity() <= baseline_cap);

        // Push full 8,192-event telemetry burst (plus 16 overflow to verify L-10 drop-oldest).
        for i in 0..(TELEMETRY_CHANNEL_CAPACITY + 16) {
            tx.send_telemetry(dns_query(
                100,
                format!("burst1-{i}.example"),
                Ipv4Addr::new(93, 184, 216, 34),
                i as i64,
            ))
            .expect("telemetry burst1");
        }
        assert_eq!(tx.telemetry_depth(), TELEMETRY_CHANNEL_CAPACITY);
        assert_eq!(tx.telemetry_dropped(), 16);
        assert!(tx.telemetry_queue_capacity() >= TELEMETRY_CHANNEL_CAPACITY);

        // Must NOT shrink while queue is non-empty, even if idle threshold were 0.
        assert!(!tx.shrink_telemetry_if_idle(Duration::ZERO));

        // Drain all 8,192 events.
        let drained = rx.drain_ready_with_lane();
        assert_eq!(drained.len(), TELEMETRY_CHANNEL_CAPACITY);
        assert_eq!(tx.telemetry_depth(), 0);

        // Must NOT shrink before 30s idle threshold elapses.
        let threshold = Duration::from_secs(30);
        assert!(!tx.shrink_telemetry_if_idle(threshold));
        assert!(tx.telemetry_queue_capacity() > TELEMETRY_IDLE_BASELINE_CAPACITY);

        // Simulate >= 30s idle since last >1024 activity -> shrinks cleanly.
        tx.backdate_telemetry_last_above_1024_for_test(Duration::from_secs(31));
        assert!(tx.shrink_telemetry_if_idle(threshold));
        let shrunk_cap = tx.telemetry_queue_capacity();
        assert!(
            shrunk_cap <= baseline_cap,
            "shrunk capacity {shrunk_cap} must be <= baseline {baseline_cap}"
        );

        // Repeated idle tick must be a no-op.
        assert!(!tx.shrink_telemetry_if_idle(threshold));

        // Re-burst another 8,192 events cleanly without drops up to capacity, and drop-oldest beyond.
        for i in 0..TELEMETRY_CHANNEL_CAPACITY {
            tx.send_telemetry(dns_query(
                200,
                format!("burst2-{i}.example"),
                Ipv4Addr::new(198, 51, 100, 1),
                i as i64,
            ))
            .expect("telemetry burst2");
        }
        assert_eq!(tx.telemetry_depth(), TELEMETRY_CHANNEL_CAPACITY);
        assert_eq!(tx.telemetry_dropped(), 16);
        tx.send_telemetry(dns_query(
            200,
            "burst2-overflow.example",
            Ipv4Addr::new(198, 51, 100, 1),
            99_999,
        ))
        .expect("telemetry burst2 overflow");
        assert_eq!(tx.telemetry_depth(), TELEMETRY_CHANNEL_CAPACITY);
        assert_eq!(tx.telemetry_dropped(), 17);
    }
}
