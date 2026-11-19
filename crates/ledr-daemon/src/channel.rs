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

use ledr_proto::{
    EventLane, SensorEvent, ACTIVE_PROCESS_TABLE_CAPACITY, HIGH_PRIORITY_CHANNEL_CAPACITY,
    TELEMETRY_CHANNEL_CAPACITY,
};
use ledr_rules::is_external_ip;
use tokio::sync::{mpsc, watch, Notify};

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

#[derive(Debug)]
struct TelemetryState {
    queue: VecDeque<SensorEvent>,
    closed: bool,
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
                queue: VecDeque::with_capacity(capacity.min(1024)),
                closed: false,
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
        }
        self.notify.notify_one();
        Ok(())
    }

    fn try_pop(&self) -> Option<SensorEvent> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        guard.queue.pop_front()
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
    high_tx: mpsc::Sender<SensorEvent>,
    telemetry: Arc<TelemetryRing>,
    stats: Arc<SharedStats>,
    close_tx: Arc<watch::Sender<bool>>,
}

impl TwoLaneSender {
    /// Routes `event` to its [`SensorEvent::default_lane`], awaiting space if the
    /// high-priority lane is temporarily full (never dropping high-priority events).
    pub async fn send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        match event.default_lane() {
            EventLane::HighPriority => self.send_high_priority(event).await.map_err(|err| match err {
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
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(HighPrioritySendError::Closed(event));
        }
        self.high_tx
            .send(event)
            .await
            .map_err(|mpsc::error::SendError(ev)| HighPrioritySendError::Closed(ev))
    }

    /// Attempts to enqueue a high-priority event without awaiting or dropping (`L-10`).
    pub fn try_send_high_priority(&self, event: SensorEvent) -> Result<(), HighPrioritySendError> {
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(HighPrioritySendError::Closed(event));
        }
        self.high_tx.try_send(event).map_err(|err| match err {
            mpsc::error::TrySendError::Full(ev) => HighPrioritySendError::Full(ev),
            mpsc::error::TrySendError::Closed(ev) => HighPrioritySendError::Closed(ev),
        })
    }

    /// Blocking send for synchronous producer threads (such as the ETW callback bridge).
    pub fn blocking_send(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        match event.default_lane() {
            EventLane::HighPriority => self.blocking_send_high_priority(event),
            EventLane::Telemetry => self.send_telemetry(event),
        }
    }

    /// Blocking send directly into the non-dropping high-priority lane (`L-10`).
    pub fn blocking_send_high_priority(&self, event: SensorEvent) -> Result<(), ChannelClosedError> {
        let _guard = InFlightHighGuard::enter(&self.stats);
        if self.stats.closed.load(Ordering::SeqCst) {
            return Err(ChannelClosedError(event));
        }
        self.high_tx
            .blocking_send(event)
            .map_err(|mpsc::error::SendError(ev)| ChannelClosedError(ev))
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
}

/// Consumer half of [`TwoLaneChannel`] draining high-priority events strictly before telemetry.
#[derive(Debug)]
pub struct TwoLaneReceiver {
    high_rx: mpsc::Receiver<SensorEvent>,
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
        loop {
            if let Ok(ev) = self.high_rx.try_recv() {
                return Some((ev, EventLane::HighPriority));
            }

            let notified = self.telemetry.notify.notified();
            tokio::pin!(notified);

            if let Some(ev) = self.telemetry.try_pop() {
                return Some((ev, EventLane::Telemetry));
            }

            if *self.close_rx.borrow() || self.telemetry.is_closed() {
                if self.stats.in_flight_high.load(Ordering::SeqCst) == 0 {
                    self.high_rx.close();
                    if let Some(ev) = self.high_rx.recv().await {
                        return Some((ev, EventLane::HighPriority));
                    }
                    if let Some(ev) = self.telemetry.try_pop() {
                        return Some((ev, EventLane::Telemetry));
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
                        if let Some(ev) = maybe_high {
                            return Some((ev, EventLane::HighPriority));
                        }
                    }
                    _ = &mut in_flight_notified => {}
                }
                continue;
            }

            tokio::select! {
                biased;
                maybe_high = self.high_rx.recv() => {
                    if let Some(ev) = maybe_high {
                        return Some((ev, EventLane::HighPriority));
                    }
                    // High-priority senders dropped; drain any remaining telemetry and exit on next pass.
                    self.telemetry.close();
                }
                _ = &mut notified => {}
                _ = self.close_rx.changed() => {}
            }
        }
    }

    /// Non-blocking drain of all currently buffered events (high-priority first, then telemetry).
    pub fn drain_ready(&mut self) -> Vec<SensorEvent> {
        self.drain_ready_with_lane()
            .into_iter()
            .map(|(ev, _)| ev)
            .collect()
    }

    pub(crate) fn drain_ready_with_lane(&mut self) -> Vec<(SensorEvent, EventLane)> {
        if (*self.close_rx.borrow() || self.telemetry.is_closed())
            && self.stats.in_flight_high.load(Ordering::SeqCst) == 0
        {
            self.high_rx.close();
        }
        let mut out = Vec::new();
        while let Ok(ev) = self.high_rx.try_recv() {
            out.push((ev, EventLane::HighPriority));
        }
        while let Some(ev) = self.telemetry.try_pop() {
            out.push((ev, EventLane::Telemetry));
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
        if self.should_promote(&event) {
            self.inner
                .send_high_priority(event)
                .await
                .map_err(|err| match err {
                    HighPrioritySendError::Full(ev) | HighPrioritySendError::Closed(ev) => {
                        ChannelClosedError(ev)
                    }
                })
        } else {
            self.inner.send(event).await
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
        if self.should_promote(&event) {
            self.inner.blocking_send_high_priority(event)
        } else {
            self.inner.blocking_send(event)
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

    #[tokio::test]
    async fn channel_prioritizes_high_priority_and_drops_oldest_telemetry() {
        let (tx, mut rx) = TwoLaneChannel::with_capacities(2, 3).split();
        assert_eq!(tx.high_priority_capacity(), 2);
        assert_eq!(tx.telemetry_capacity(), 3);

        for i in 0..5 {
            tx.send_telemetry(SensorEvent::DnsQuery {
                pid: 1,
                query_name: format!("d{i}.test"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                timestamp_ms: i,
            })
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
        let private_ev = SensorEvent::NetworkConnect {
            pid: 500,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: 1,
        };
        let steady_ev = SensorEvent::NetworkConnect {
            pid: 99,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: 2,
        };
        assert!(!classified.should_promote(&private_ev));
        assert!(!classified.should_promote(&steady_ev));

        // Unknown external NetworkConnect IS promoted via high-priority lane even when telemetry overflows.
        let unknown_ext = SensorEvent::NetworkConnect {
            pid: 500,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("unknown.example".to_string()),
            timestamp_ms: 3,
        };
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
                .send(SensorEvent::DnsQuery {
                    pid: 99,
                    query_name: format!("noise-{i}.example"),
                    query_type: 1,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                    timestamp_ms: 10 + i,
                })
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

        let ext_dns = SensorEvent::DnsQuery {
            pid: 500,
            query_name: "api.allowed.example".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 1,
        };
        let steady_dns = SensorEvent::DnsQuery {
            pid: 99,
            query_name: "steady.example".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: 2,
        };
        let local_dns = SensorEvent::DnsQuery {
            pid: 500,
            query_name: "intranet.local".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
            timestamp_ms: 3,
        };

        // Without domain rules, DnsQuery stays on Telemetry so telemetry backpressure can shed it.
        assert!(!classified.should_promote(&ext_dns));

        // Enabling domain rules promotes non-steady external DnsQuery onto HighPriority in order
        // before NetworkConnect, even while Telemetry drops older messages.
        classifier.set_has_domain_rules(true);
        assert!(classified.should_promote(&ext_dns));
        assert!(!classified.should_promote(&steady_dns));
        assert!(!classified.should_promote(&local_dns));

        let connect = SensorEvent::NetworkConnect {
            pid: 500,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: 4,
        };
        classified.send(ext_dns.clone()).await.expect("dns");
        classified.send(connect.clone()).await.expect("connect");

        // Overflow Telemetry with steady noise; HighPriority DNS + Connect remain lossless & ordered.
        for i in 0..5 {
            classified
                .send(SensorEvent::DnsQuery {
                    pid: 99,
                    query_name: format!("overflow-{i}.example"),
                    query_type: 1,
                    resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                    timestamp_ms: 10 + i,
                })
                .await
                .expect("noise");
        }
        assert_eq!(classified.telemetry_dropped(), 3);
        classified.close();
        let drained = rx.drain_ready_with_lane();
        assert_eq!(drained[0], (ext_dns, EventLane::HighPriority));
        assert_eq!(drained[1], (connect, EventLane::HighPriority));
    }
}
