//! Bounded two-lane event ingestion channel (`決定記録 L-10`).
//!
//! - High-priority lane (`HIGH_PRIORITY_CHANNEL_CAPACITY` = 1,024): never drops events.
//! - Telemetry lane (`TELEMETRY_CHANNEL_CAPACITY` = 8,192): drop-oldest ring buffer (`VecDeque`)
//!   that counts evicted events in `telemetry_dropped`.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ledr_proto::{
    EventLane, SensorEvent, HIGH_PRIORITY_CHANNEL_CAPACITY, TELEMETRY_CHANNEL_CAPACITY,
};
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
            EventLane::HighPriority => {
                let _guard = InFlightHighGuard::enter(&self.stats);
                if self.stats.closed.load(Ordering::SeqCst) {
                    return Err(ChannelClosedError(event));
                }
                self.high_tx
                    .blocking_send(event)
                    .map_err(|mpsc::error::SendError(ev)| ChannelClosedError(ev))
            }
            EventLane::Telemetry => self.send_telemetry(event),
        }
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
        loop {
            if let Ok(ev) = self.high_rx.try_recv() {
                return Some(ev);
            }

            let notified = self.telemetry.notify.notified();
            tokio::pin!(notified);

            if let Some(ev) = self.telemetry.try_pop() {
                return Some(ev);
            }

            if *self.close_rx.borrow() || self.telemetry.is_closed() {
                if self.stats.in_flight_high.load(Ordering::SeqCst) == 0 {
                    self.high_rx.close();
                    if let Some(ev) = self.high_rx.recv().await {
                        return Some(ev);
                    }
                    if let Some(ev) = self.telemetry.try_pop() {
                        return Some(ev);
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
                            return Some(ev);
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
                        return Some(ev);
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
        if (*self.close_rx.borrow() || self.telemetry.is_closed())
            && self.stats.in_flight_high.load(Ordering::SeqCst) == 0
        {
            self.high_rx.close();
        }
        let mut out = Vec::new();
        while let Ok(ev) = self.high_rx.try_recv() {
            out.push(ev);
        }
        while let Some(ev) = self.telemetry.try_pop() {
            out.push(ev);
        }
        out
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
}
