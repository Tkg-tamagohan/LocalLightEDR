use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ledr_proto::{EventLane, SensorEvent};
use ledr_store::StoreError;
use tokio::task::JoinHandle;

use crate::channel::TwoLaneReceiver;

use super::events::DnsCorrelationUpdate;
use super::motw::{refresh_download_origins_after_purge, LateMotwAttribution};
use super::nrd::{execute_nrd_refresh, NrdThreadHandle};
use super::wfp_drops::{PendingWfpDrop, QueuedWfpDrop};
use super::{current_unix_ms, DaemonEngine, StoreWriteGate};

const HIGH_PRIORITY_MOTW_INTERLEAVE_STREAK: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkerExit {
    Completed,
    DrainTruncated,
}

impl DaemonEngine {
    fn maybe_wake_pending_wfp_drops(
        &self,
        event: &SensorEvent,
        dns_update: Option<DnsCorrelationUpdate>,
        pending_wfp_drops: &mut VecDeque<PendingWfpDrop>,
    ) {
        if let Some(dns_update) = dns_update {
            if let SensorEvent::DnsQuery { query_name, .. } = event {
                self.flush_ready_pending_wfp_drops(
                    &dns_update.instance_id,
                    &dns_update.exe_key,
                    query_name,
                    &dns_update.accepted_ips,
                    pending_wfp_drops,
                );
            }
        } else if !pending_wfp_drops.is_empty() {
            if let SensorEvent::ProcessStart {
                identity, exe_path, ..
            } = event
            {
                self.flush_ambiguous_pending_wfp_drops_for_process_start(
                    *identity,
                    exe_path,
                    pending_wfp_drops,
                );
            }
        }
    }
    pub(super) async fn run_pipeline(
        self: Arc<Self>,
        mut receiver: TwoLaneReceiver,
        mut wfp_drop_rx: tokio::sync::mpsc::Receiver<QueuedWfpDrop>,
        mut motw_result_rx: tokio::sync::mpsc::Receiver<LateMotwAttribution>,
    ) -> Result<WorkerExit, StoreError> {
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
        let expiry_interval = Duration::from_millis(expiry_interval_ms);
        let mut next_expiry_at = tokio::time::Instant::now() + expiry_interval;

        let nrd_refresh_enabled = self.config.nrd_refresh_enabled;
        let nrd_tick_ms = (self.config.nrd_refresh_interval_ms / 4).clamp(100, 3_600_000);
        let mut nrd_ticker = tokio::time::interval(Duration::from_millis(nrd_tick_ms));
        nrd_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut mem_maintenance_ticker = tokio::time::interval(Duration::from_secs(60));
        mem_maintenance_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume the immediate t=0 tick so memory maintenance runs on 60s periodic ticks.
        mem_maintenance_ticker.tick().await;

        let mut pending_wfp_drops: VecDeque<PendingWfpDrop> = VecDeque::new();
        let mut wfp_drop_rx_closed = false;
        let mut motw_result_rx_closed = false;
        let mut high_priority_streak = 0usize;
        let mut sync_telemetry_streak = 0usize;
        let mut last_warned_coalesced: u64 = 0;

        loop {
            if self.is_shutdown_drain_cutoff() {
                break;
            }
            // Tier 1: Drain non-dropping high-priority lane (ProcessStart/Stop, DnsQuery, Canary,
            // Script, unknown NetworkConnect) BEFORE WFP drops so process lineage and DNS history
            // are always up to date for attribution (`L-10`). Interleave one Tier 1b MOTW result
            // drain every `HIGH_PRIORITY_MOTW_INTERLEAVE_STREAK` (16) consecutive events so
            // sustained high-priority bursts cannot starve `motw_result_rx` or seed backlog progress.
            if let Some(event) = receiver.try_recv_high_priority() {
                sync_telemetry_streak = 0;
                let dns_update = self
                    .process_event_with_lane_async(&event, EventLane::HighPriority)
                    .await;
                self.maybe_wake_pending_wfp_drops(&event, dns_update, &mut pending_wfp_drops);
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

            // Tier 2c: Run overdue periodic alert expiry and retained unused-preemptive WFP
            // sweeps strictly AFTER high-priority / MOTW / WFP drop lanes (`L-10`) and BEFORE
            // Tier 3 steady telemetry so sustained telemetry bursts cannot starve either
            // `expire_overdue_alerts` or `sweep_unused_preemptive_wfp_blocks`
            // (`PRRT_kwDOVyjVyM66kWF3`). Skip once shutdown is initiated so periodic BFE retries
            // never consume the 3-second shutdown flush budget.
            if !self.nrd_cancel.is_cancelled()
                && !self.store.is_shutdown_requested()
                && tokio::time::Instant::now() >= next_expiry_at
            {
                sync_telemetry_streak = 0;
                let removed = self.run_periodic_expiry_and_sweep();
                #[cfg(test)]
                {
                    self.tier2c_periodic_sweeps.fetch_add(1, Ordering::Release);
                    if removed > 0 {
                        self.tier2c_periodic_sweep_removals
                            .fetch_add(removed as u64, Ordering::Release);
                    }
                }
                #[cfg(not(test))]
                let _ = removed;
                next_expiry_at = tokio::time::Instant::now() + expiry_interval;
                continue;
            }

            // Tier 3: Steady telemetry lane, yielding periodically so single-threaded runtimes and
            // grace timers remain responsive during bursts.
            if let Some(event) = receiver.try_recv_telemetry() {
                let dns_update = self
                    .process_event_with_lane_async(&event, EventLane::Telemetry)
                    .await;
                self.maybe_wake_pending_wfp_drops(&event, dns_update, &mut pending_wfp_drops);
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

            let next_expiry_sleep = tokio::time::sleep_until(next_expiry_at);
            tokio::pin!(next_expiry_sleep);

            tokio::select! {
                biased;
                maybe_event = receiver.recv_with_lane() => {
                    match maybe_event {
                        Some((event, lane)) => {
                            let dns_update = self.process_event_with_lane_async(&event, lane).await;
                            self.maybe_wake_pending_wfp_drops(&event, dns_update, &mut pending_wfp_drops);
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
                    if let Some(Err(err)) = self.try_store_write(|s| s.flush_if_interval_elapsed()) {
                        tracing::warn!(error = %err, "periodic SQLite batch flush failed");
                    }
                }
                _ = &mut next_expiry_sleep, if !self.nrd_cancel.is_cancelled() && !self.store.is_shutdown_requested() => {
                    let removed = self.run_periodic_expiry_and_sweep();
                    #[cfg(test)]
                    {
                        self.select_idle_periodic_sweeps
                            .fetch_add(1, Ordering::Release);
                        if removed > 0 {
                            self.select_idle_periodic_sweep_removals
                                .fetch_add(removed as u64, Ordering::Release);
                        }
                    }
                    #[cfg(not(test))]
                    let _ = removed;
                    next_expiry_at = tokio::time::Instant::now() + expiry_interval;
                }
                _ = purge_ticker.tick() => {
                    let busy = purge_in_flight.as_ref().is_some_and(|h| !h.is_finished());
                    if !busy {
                        let store = self.store.clone();
                        let dl_state = Arc::clone(&self.download_origin_state);
                        let before_state = dl_state.load(Ordering::Acquire);
                        let retention_days = self.config.ttl_retention_days;
                        let write_gate = Arc::clone(&self.store_write_gate);
                        purge_in_flight = Some(tokio::task::spawn_blocking(move || {
                            let now_ms = current_unix_ms();
                            match store.purge_expired_with_guard(now_ms, retention_days, || {
                                StoreWriteGate::enter_sql_write(&write_gate)
                            }) {
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
                _ = mem_maintenance_ticker.tick(), if !self.nrd_cancel.is_cancelled() && !self.store.is_shutdown_requested() && !self.is_shutdown_drain_cutoff() => {
                    self.run_periodic_memory_maintenance();
                }
            }
        }

        // Cancel any in-flight NRD fetch immediately so slow upstream HTTP cannot delay
        // daemon shutdown or pin the 3-second WAL checkpoint budget (`AUTO-10`, `#5`).
        self.nrd_cancel.cancel();

        if let Some(handle) = purge_in_flight {
            if self.is_shutdown_drain_cutoff() {
                return Ok(WorkerExit::DrainTruncated);
            }
            tokio::select! {
                biased;
                _ = self.shutdown_cutoff_notify.notified() => {
                    return Ok(WorkerExit::DrainTruncated);
                }
                res = handle => {
                    if let Err(err) = res {
                        tracing::warn!(error = %err, "TTL purge task panicked during shutdown");
                    }
                }
            }
        }

        let remaining_events = receiver.drain_ready_with_lane();
        let total_remaining = remaining_events.len();
        for (idx, (remaining, lane)) in remaining_events.into_iter().enumerate() {
            if self.is_shutdown_drain_cutoff() {
                tracing::warn!(
                    dropped_remaining = total_remaining.saturating_sub(idx),
                    "shutdown drain cutoff reached; stopping residual pipeline drain"
                );
                return Ok(WorkerExit::DrainTruncated);
            }
            let _ = self.process_event_with_lane_async(&remaining, lane).await;
            tokio::task::yield_now().await;
        }
        while let Ok(late_motw) = motw_result_rx.try_recv() {
            if self.is_shutdown_drain_cutoff() {
                return Ok(WorkerExit::DrainTruncated);
            }
            self.apply_late_motw_attribution(late_motw);
            tokio::task::yield_now().await;
        }
        drop(motw_result_rx);
        self.motw_pool.notify_late_result_consumed();
        while let Ok(drop_item) = wfp_drop_rx.try_recv() {
            if self.is_shutdown_drain_cutoff() {
                return Ok(WorkerExit::DrainTruncated);
            }
            self.handle_wfp_drop_event_now(&drop_item);
            tokio::task::yield_now().await;
        }
        while let Some(overflow_item) = self.pop_wfp_drop_overflow() {
            if self.is_shutdown_drain_cutoff() {
                return Ok(WorkerExit::DrainTruncated);
            }
            self.handle_wfp_drop_event_now(&overflow_item);
            tokio::task::yield_now().await;
        }
        self.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned_coalesced);
        while let Some(pending) = pending_wfp_drops.pop_front() {
            if self.is_shutdown_drain_cutoff() {
                return Ok(WorkerExit::DrainTruncated);
            }
            if pending.reason.includes_attribution_grace() && !pending.confirmed_ambiguous {
                // Never freeze a process on attribution-grace expiry during daemon shutdown.
                continue;
            }
            self.handle_wfp_drop_event_with_context(
                &pending.item,
                None,
                pending.confirmed_ambiguous,
                None,
            );
            tokio::task::yield_now().await;
        }

        match self.try_store_write(|s| s.checkpoint_truncate()) {
            Some(Ok(())) => Ok(WorkerExit::Completed),
            Some(Err(err)) => {
                tracing::warn!(error = %err, "worker shutdown checkpoint_truncate failed");
                Err(err)
            }
            None => Ok(WorkerExit::DrainTruncated),
        }
    }

    fn run_periodic_expiry_and_sweep(&self) -> usize {
        if let Err(err) = self.expire_overdue_alerts(current_unix_ms()) {
            tracing::warn!(error = %err, "periodic alert expiry transition failed");
        }
        self.sweep_unused_preemptive_wfp_blocks()
    }

    pub(super) fn run_periodic_memory_maintenance(&self) {
        if self.nrd_cancel.is_cancelled()
            || self.store.is_shutdown_requested()
            || self.is_shutdown_drain_cutoff()
        {
            return;
        }
        let _ = self
            .sender
            .shrink_telemetry_if_idle(Duration::from_secs(30));
        let now_ms = current_unix_ms();
        let interner = {
            let mut table = self
                .process_table
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let _ = table.compact_exited_older_than(now_ms.saturating_sub(60_000));
            table.path_interner()
        };
        let _ = interner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sweep_dead();
        let _ = self
            .process_dns_history
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sweep_interner_and_shrink();
        let _ = self
            .verified_app_wide_allows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sweep_interner();
        // PHASE3_STORE_HOOK: let _ = self.store.shrink_reader_memory_if_idle(Duration::from_secs(30));
    }
}
