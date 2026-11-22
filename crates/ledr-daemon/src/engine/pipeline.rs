use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ledr_proto::{EventLane, SensorEvent};
use ledr_store::StoreError;
use tokio::task::JoinHandle;

use crate::channel::TwoLaneReceiver;

use super::motw::{refresh_download_origins_after_purge, LateMotwAttribution};
use super::nrd::{execute_nrd_refresh, NrdThreadHandle};
use super::wfp_drops::{PendingWfpDrop, QueuedWfpDrop};
use super::{current_unix_ms, DaemonEngine};

const HIGH_PRIORITY_MOTW_INTERLEAVE_STREAK: usize = 16;

impl DaemonEngine {
    pub(super) async fn run_pipeline(
        self: Arc<Self>,
        mut receiver: TwoLaneReceiver,
        mut wfp_drop_rx: tokio::sync::mpsc::Receiver<QueuedWfpDrop>,
        mut motw_result_rx: tokio::sync::mpsc::Receiver<LateMotwAttribution>,
    ) -> Result<(), StoreError> {
        let interval_ms = self.config.batch_flush_interval_ms.max(50);
        let mut flush_ticker = tokio::time::interval(Duration::from_millis(interval_ms));
        flush_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let purge_interval = Duration::from_millis(self.config.ttl_purge_interval_ms.max(50));
        let mut purge_ticker = tokio::time::interval(purge_interval);
        purge_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate t=0 tick so TTL purge runs periodically on interval ticks.
        purge_ticker.tick().await;
        let mut purge_in_flight: Option<JoinHandle<()>> = None;

        let expiry_interval_ms = (self.config.alert_timeout_ms / 4).clamp(50, 5_000);
        let mut expiry_ticker = tokio::time::interval(Duration::from_millis(expiry_interval_ms));
        expiry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        expiry_ticker.tick().await;

        let nrd_refresh_enabled = self.config.nrd_refresh_enabled;
        let nrd_tick_ms = (self.config.nrd_refresh_interval_ms / 4).clamp(100, 3_600_000);
        let mut nrd_ticker = tokio::time::interval(Duration::from_millis(nrd_tick_ms));
        nrd_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut pending_wfp_drops: VecDeque<PendingWfpDrop> = VecDeque::new();
        let mut wfp_drop_rx_closed = false;
        let mut motw_result_rx_closed = false;
        let mut high_priority_streak = 0usize;
        let mut sync_telemetry_streak = 0usize;
        let mut last_warned_coalesced: u64 = 0;

        loop {
            // Tier 1: Drain non-dropping high-priority lane (ProcessStart/Stop, DnsQuery, Canary,
            // Script, unknown NetworkConnect) BEFORE WFP drops so process lineage and DNS history
            // are always up to date for attribution (`L-10`). Interleave one Tier 1b MOTW result
            // drain every `HIGH_PRIORITY_MOTW_INTERLEAVE_STREAK` (16) consecutive events so
            // sustained high-priority bursts cannot starve `motw_result_rx` or seed backlog progress.
            if let Some(event) = receiver.try_recv_high_priority() {
                sync_telemetry_streak = 0;
                if let Some(dns_update) = self
                    .process_event_with_lane_async(&event, EventLane::HighPriority)
                    .await
                {
                    if let SensorEvent::DnsQuery { query_name, .. } = &event {
                        self.flush_ready_pending_wfp_drops(
                            &dns_update.instance_id,
                            &dns_update.exe_key,
                            query_name,
                            &dns_update.accepted_ips,
                            &mut pending_wfp_drops,
                        );
                    }
                }
                high_priority_streak += 1;
                if high_priority_streak >= HIGH_PRIORITY_MOTW_INTERLEAVE_STREAK {
                    high_priority_streak = 0;
                    if !motw_result_rx_closed {
                        match motw_result_rx.try_recv() {
                            Ok(late_motw) => {
                                self.apply_late_motw_attribution(late_motw);
                                self.motw_pool.notify_late_result_consumed();
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                                motw_result_rx_closed = true;
                            }
                            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                        }
                    }
                }
                continue;
            }
            high_priority_streak = 0;

            // Tier 1b: Drain completed asynchronous MOTW attributions promptly before Tier 2/3.
            if !motw_result_rx_closed {
                match motw_result_rx.try_recv() {
                    Ok(late_motw) => {
                        sync_telemetry_streak = 0;
                        self.apply_late_motw_attribution(late_motw);
                        self.motw_pool.notify_late_result_consumed();
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        motw_result_rx_closed = true;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                }
            }

            // Tier 2a: Flush any grace-window WFP drops whose deadline has already expired.
            let earliest_drop_deadline = pending_wfp_drops.iter().map(|p| p.deadline).min();
            if earliest_drop_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                sync_telemetry_streak = 0;
                self.flush_expired_pending_wfp_drops(&mut pending_wfp_drops);
                continue;
            }

            // Tier 2b: Drain WFP drop events (primary bounded channel + bounded overflow queue)
            // STRICTLY BEFORE steady telemetry so telemetry bursts never starve or drop alerts (`L-10`).
            if !wfp_drop_rx_closed {
                match wfp_drop_rx.try_recv() {
                    Ok(drop_item) => {
                        self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                        sync_telemetry_streak = 0;
                        self.on_wfp_drop_dequeued(drop_item, &mut pending_wfp_drops);
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        wfp_drop_rx_closed = true;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
                }
            }
            if let Some(overflow_item) = self.pop_wfp_drop_overflow() {
                self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                sync_telemetry_streak = 0;
                self.on_wfp_drop_dequeued(overflow_item, &mut pending_wfp_drops);
                continue;
            }

            // Tier 3: Steady telemetry lane, yielding periodically so single-threaded runtimes and
            // grace timers remain responsive during bursts.
            if let Some(event) = receiver.try_recv_telemetry() {
                if let Some(dns_update) = self
                    .process_event_with_lane_async(&event, EventLane::Telemetry)
                    .await
                {
                    if let SensorEvent::DnsQuery { query_name, .. } = &event {
                        self.flush_ready_pending_wfp_drops(
                            &dns_update.instance_id,
                            &dns_update.exe_key,
                            query_name,
                            &dns_update.accepted_ips,
                            &mut pending_wfp_drops,
                        );
                    }
                }
                sync_telemetry_streak += 1;
                if sync_telemetry_streak >= 32 {
                    sync_telemetry_streak = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }
            sync_telemetry_streak = 0;

            let next_drop_sleep = async move {
                match earliest_drop_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::pin!(next_drop_sleep);

            tokio::select! {
                biased;
                maybe_event = receiver.recv_with_lane() => {
                    match maybe_event {
                        Some((event, lane)) => {
                            if let Some(dns_update) = self.process_event_with_lane_async(&event, lane).await {
                                if let SensorEvent::DnsQuery { query_name, .. } = &event {
                                    self.flush_ready_pending_wfp_drops(
                                        &dns_update.instance_id,
                                        &dns_update.exe_key,
                                        query_name,
                                        &dns_update.accepted_ips,
                                        &mut pending_wfp_drops,
                                    );
                                }
                            }
                        }
                        None => break,
                    }
                }
                maybe_late = motw_result_rx.recv(), if !motw_result_rx_closed => {
                    match maybe_late {
                        Some(late_motw) => {
                            self.apply_late_motw_attribution(late_motw);
                            self.motw_pool.notify_late_result_consumed();
                        }
                        None => motw_result_rx_closed = true,
                    }
                }
                maybe_drop = wfp_drop_rx.recv(), if !wfp_drop_rx_closed => {
                    match maybe_drop {
                        Some(drop_item) => {
                            self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                            self.on_wfp_drop_dequeued(drop_item, &mut pending_wfp_drops);
                        }
                        None => wfp_drop_rx_closed = true,
                    }
                }
                _ = self.wfp_drop_overflow_notify.notified() => {
                    self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                    while let Some(overflow_item) = self.pop_wfp_drop_overflow() {
                        self.on_wfp_drop_dequeued(overflow_item, &mut pending_wfp_drops);
                    }
                    self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                }
                _ = &mut next_drop_sleep, if earliest_drop_deadline.is_some() => {
                    self.flush_expired_pending_wfp_drops(&mut pending_wfp_drops);
                }
                _ = flush_ticker.tick() => {
                    self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
                    if let Err(err) = self.store.flush_if_interval_elapsed() {
                        tracing::warn!(error = %err, "periodic SQLite batch flush failed");
                    }
                }
                _ = expiry_ticker.tick() => {
                    if let Err(err) = self.expire_overdue_alerts(current_unix_ms()) {
                        tracing::warn!(error = %err, "periodic alert expiry transition failed");
                    }
                    self.sweep_unused_preemptive_wfp_blocks();
                }
                _ = purge_ticker.tick() => {
                    let busy = purge_in_flight.as_ref().is_some_and(|h| !h.is_finished());
                    if !busy {
                        let store = self.store.clone();
                        let dl_state = Arc::clone(&self.download_origin_state);
                        let before_state = dl_state.load(Ordering::Acquire);
                        let retention_days = self.config.ttl_retention_days;
                        purge_in_flight = Some(tokio::task::spawn_blocking(move || {
                            let now_ms = current_unix_ms();
                            match store.purge_expired(now_ms, retention_days) {
                                Ok(stats) => {
                                    refresh_download_origins_after_purge(
                                        &dl_state,
                                        &store,
                                        before_state,
                                        stats.downloads_deleted,
                                    );
                                }
                                Err(err) => {
                                    tracing::warn!(error = %err, "periodic SQLite TTL purge failed");
                                }
                            }
                        }));
                    }
                }
                _ = nrd_ticker.tick(), if nrd_refresh_enabled => {
                    if !self.nrd_cancel.is_cancelled() && !self.nrd_in_flight.load(Ordering::Acquire) {
                        let stale = {
                            let guard = self.nrd_cache.read().unwrap_or_else(|e| e.into_inner());
                            guard.is_stale(current_unix_ms(), self.config.nrd_refresh_interval_ms)
                        };
                        if stale
                            && self.nrd_in_flight
                                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                                .is_ok()
                        {
                            if self.nrd_cancel.is_cancelled() {
                                self.nrd_in_flight.store(false, Ordering::Release);
                                continue;
                            }
                            let feed_urls = self.config.nrd_feed_urls.clone();
                            let cache_path = self.config.nrd_cache_path.clone();
                            let nrd_cache = Arc::clone(&self.nrd_cache);
                            let nrd_cancel = self.nrd_cancel.clone();
                            let in_flight = Arc::clone(&self.nrd_in_flight);
                            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
                            match std::thread::Builder::new()
                                .name("ledr-nrd-refresh".to_string())
                                .spawn(move || {
                                    struct InFlightGuard {
                                        in_flight: Arc<AtomicBool>,
                                        done_tx: Option<tokio::sync::oneshot::Sender<()>>,
                                    }
                                    impl Drop for InFlightGuard {
                                        fn drop(&mut self) {
                                            self.in_flight.store(false, Ordering::Release);
                                            if let Some(tx) = self.done_tx.take() {
                                                let _ = tx.send(());
                                            }
                                        }
                                    }
                                    // Declare `_guard` before rebinding all captured inputs so
                                    // every thread-owned value drops BEFORE `done_tx.send(())`
                                    // wakes `shutdown_and_flush` (`R-11`).
                                    let _guard = InFlightGuard {
                                        in_flight,
                                        done_tx: Some(done_tx),
                                    };
                                    let (feed_urls, cache_path, nrd_cache, nrd_cancel) =
                                        (feed_urls, cache_path, nrd_cache, nrd_cancel);
                                    match execute_nrd_refresh(
                                        &feed_urls,
                                        cache_path.as_deref(),
                                        &nrd_cache,
                                        &nrd_cancel,
                                    ) {
                                        Ok(stats) => tracing::info!(
                                            entries = stats.total_entries,
                                            feeds_succeeded = stats.feeds_succeeded,
                                            feeds_failed = stats.feeds_failed,
                                            truncated = stats.truncated,
                                            "refreshed daily NRD domain cache"
                                        ),
                                        Err(err) => tracing::warn!(
                                            error = %err,
                                            "daily NRD feed refresh failed; retaining existing cache"
                                        ),
                                    }
                                }) {
                                Ok(join_handle) => {
                                    let prev = {
                                        let mut guard = self
                                            .nrd_thread_handle
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        guard.replace(NrdThreadHandle {
                                            join_handle,
                                            done_rx,
                                        })
                                    };
                                    if let Some(old_nrd) = prev {
                                        if old_nrd.join_handle.is_finished() {
                                            let _ = old_nrd.join_handle.join();
                                        }
                                    }
                                }
                                Err(err) => {
                                    self.nrd_in_flight.store(false, Ordering::Release);
                                    tracing::warn!(error = %err, "failed spawning ledr-nrd-refresh thread");
                                }
                            }
                        }
                    }
                }
            }
        }

        // Cancel any in-flight NRD fetch immediately so slow upstream HTTP cannot delay
        // daemon shutdown or pin the 3-second WAL checkpoint budget (`AUTO-10`, `#5`).
        self.nrd_cancel.cancel();

        if let Some(handle) = purge_in_flight {
            if let Err(err) = handle.await {
                tracing::warn!(error = %err, "TTL purge task panicked during shutdown");
            }
        }

        for (remaining, lane) in receiver.drain_ready_with_lane() {
            let _ = self.process_event_with_lane_async(&remaining, lane).await;
        }
        while let Ok(late_motw) = motw_result_rx.try_recv() {
            self.apply_late_motw_attribution(late_motw);
        }
        drop(motw_result_rx);
        self.motw_pool.notify_late_result_consumed();
        while let Ok(drop_item) = wfp_drop_rx.try_recv() {
            self.handle_wfp_drop_event_now(&drop_item);
        }
        while let Some(overflow_item) = self.pop_wfp_drop_overflow() {
            self.handle_wfp_drop_event_now(&overflow_item);
        }
        self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
        while let Some(pending) = pending_wfp_drops.pop_front() {
            self.handle_wfp_drop_event_now(&pending.item);
        }

        match self.store.checkpoint_truncate() {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::warn!(error = %err, "worker shutdown checkpoint_truncate failed");
                Err(err)
            }
        }
    }
}
