use super::{tolerate_missing_target, DaemonConfig, DaemonEngine};
use ledr_rules::{EarlyPruner, SigmaEngine};
use ledr_sensor_win::defense::ProcessLiveness;
use ledr_sensor_win::WfpDropEvent;
use ledr_store::LedrStore;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

async fn wait_until_nrd_handle_taken<T>(
    engine: &DaemonEngine,
    shutdown_task: &tokio::task::JoinHandle<T>,
    take_msg: &str,
    parked_msg: &str,
) {
    let sync_deadline = Instant::now() + Duration::from_secs(2);
    while engine.nrd_thread_handle.lock().unwrap().is_some() {
        assert!(Instant::now() < sync_deadline, "{take_msg}");
        tokio::task::yield_now().await;
    }
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(!shutdown_task.is_finished(), "{parked_msg}");
}

fn make_wfp_drop_event(exe: &str, last_octet: u8, timestamp_ms: i64) -> WfpDropEvent {
    WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: exe.to_string(),
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet)),
        dst_port: 443,
        timestamp_ms,
    }
}

fn start_overflow_engine(store: LedrStore) -> Arc<DaemonEngine> {
    DaemonEngine::start(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            high_priority_capacity: 1,
            outbound_firewall_enabled: true,
            ..DaemonConfig::default()
        },
    )
}

/// `DAEMON-P2-28` (`BUG_0002`): a snapshot/enumeration failure (`Unknown`) must not
/// be treated as "gone" — only a positively absent PID or a proven PID reuse may
/// swallow a suspend/resume/terminate error.
#[test]
fn daemon_p2_28_bug_0002_unknown_liveness_is_not_tolerated() {
    let cases = [
        ("OpenProcess failed", ProcessLiveness::Gone, true),
        (
            "PID reused: CreationTime mismatch",
            ProcessLiveness::Running,
            true,
        ),
        ("OpenProcess failed", ProcessLiveness::Running, false),
        ("OpenProcess failed", ProcessLiveness::Unknown, false),
    ];
    for (err, liveness, expected) in cases {
        assert_eq!(
            tolerate_missing_target(err, liveness),
            expected,
            "tolerate_missing_target({err:?}, {liveness:?})"
        );
    }
}

/// `DAEMON-P3-44A` (`R-13`): `WfpDropOverflowQueue` reports `CoalescedOverwritten` when a
/// full secondary queue overwrites a distinct destination for the same executable, retains the
/// latest destination without disturbing other executables, evicts excess coalesced apps in
/// FIFO order, and exposes the counter via `DaemonEngine::wfp_drop_overflow_coalesced`.
#[test]
fn daemon_p3_44a_wfp_drop_overflow_queue_coalescing_and_fifo_eviction() {
    use super::{current_unix_ms, OverflowPushOutcome, QueuedWfpDrop, WfpDropOverflowQueue};

    let make_item = |exe_key: &str, ip: IpAddr, port: u16| QueuedWfpDrop {
        exe_path: exe_key.to_string(),
        exe_key: exe_key.to_string(),
        dst_ip: ip,
        dst_port: port,
        protocol: 6,
        timestamp_ms: 1_000,
        os_filter_id: 1,
    };

    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3));
    let ip4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4));
    let ip1_mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 1).to_ipv6_mapped());

    // Part A: Same-app distinct-destination overwrite retains latest destination and leaves
    // other executables untouched.
    let mut q = WfpDropOverflowQueue::new(2);
    assert_eq!(
        q.push(make_item("app_a", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    assert_eq!(
        q.push(make_item("app_a", ip1_mapped, 443)),
        OverflowPushOutcome::Deduplicated
    );
    assert_eq!(
        q.push(make_item("app_b", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    // Primary `queue` is now full (2/2). Subsequent events enter `coalesced_by_exe`.
    assert_eq!(
        q.push(make_item("app_a", ip2, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );
    assert_eq!(
        q.push(make_item("app_a", ip2, 8443)),
        OverflowPushOutcome::Deduplicated
    );
    assert_eq!(
        q.push(make_item("app_a", ip3, 443)),
        OverflowPushOutcome::CoalescedOverwritten
    );
    assert_eq!(
        q.push(make_item("app_b", ip4, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );

    let drained: Vec<(String, IpAddr)> =
        std::iter::from_fn(|| q.pop().map(|i| (i.exe_key, i.dst_ip))).collect();
    assert_eq!(
        drained,
        vec![
            ("app_a".to_string(), ip1),
            ("app_b".to_string(), ip1),
            ("app_a".to_string(), ip3),
            ("app_b".to_string(), ip4),
        ],
        "coalesced overwrite must keep latest destination (ip3) for app_a without affecting app_b"
    );

    // Part B: Exceeding `coalesced_by_exe` capacity evicts the oldest coalesced executable FIFO.
    let mut q_fifo = WfpDropOverflowQueue::new(2);
    assert_eq!(
        q_fifo.push(make_item("q1", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    assert_eq!(
        q_fifo.push(make_item("q2", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    assert_eq!(
        q_fifo.push(make_item("app_a", ip2, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );
    assert_eq!(
        q_fifo.push(make_item("app_a", ip3, 443)),
        OverflowPushOutcome::CoalescedOverwritten
    );
    assert_eq!(
        q_fifo.push(make_item("app_b", ip2, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );
    // `coalesced_by_exe` is now full (2/2: [app_a, app_b]); adding `app_c` evicts `app_a`.
    assert_eq!(
        q_fifo.push(make_item("app_c", ip4, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );
    let drained_fifo: Vec<(String, IpAddr)> =
        std::iter::from_fn(|| q_fifo.pop().map(|i| (i.exe_key, i.dst_ip))).collect();
    assert_eq!(
        drained_fifo,
        vec![
            ("q1".to_string(), ip1),
            ("q2".to_string(), ip1),
            ("app_b".to_string(), ip2),
            ("app_c".to_string(), ip4),
        ],
        "coalesced_by_exe overflow must evict oldest executable (app_a) in FIFO order"
    );

    // Part B2: Partial drain of `queue` while `coalesced_by_exe` is non-empty must still
    // deduplicate an identical `(exe_key, canonical_dst_ip)` instead of double-queuing it,
    // while allowing a distinct destination IP to use the freed `queue` slot without losing
    // the pending coalesced destination.
    let mut q_partial = WfpDropOverflowQueue::new(2);
    assert_eq!(
        q_partial.push(make_item("app_a", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    assert_eq!(
        q_partial.push(make_item("app_b", ip1, 443)),
        OverflowPushOutcome::Queued
    );
    assert_eq!(
        q_partial.push(make_item("app_a", ip2, 443)),
        OverflowPushOutcome::CoalescedNewExe
    );
    // Pop one item from `queue` (`queue.len() == 1 < capacity`), leaving `app_a -> ip2` in
    // `coalesced_by_exe`.
    let popped = q_partial.pop().expect("pop first queued item");
    assert_eq!((popped.exe_key.as_str(), popped.dst_ip), ("app_a", ip1));
    assert_eq!(
        q_partial.push(make_item("app_a", ip2, 8443)),
        OverflowPushOutcome::Deduplicated,
        "duplicate (exe_key, dst_ip) already in coalesced_by_exe must deduplicate even when queue has free space"
    );
    assert_eq!(
        q_partial.push(make_item("app_a", ip3, 443)),
        OverflowPushOutcome::Queued,
        "distinct dst_ip should use freed queue slot without overwriting coalesced ip2"
    );
    let drained_partial: Vec<(String, IpAddr, u16)> =
        std::iter::from_fn(|| q_partial.pop().map(|i| (i.exe_key, i.dst_ip, i.dst_port)))
            .collect();
    assert_eq!(
        drained_partial,
        vec![
            ("app_b".to_string(), ip1, 443),
            ("app_a".to_string(), ip3, 443),
            ("app_a".to_string(), ip2, 8443),
        ],
        "partial-drain dedup must emit ip2 exactly once (with updated port) and preserve ip3"
    );

    // Part C: Engine-level metric `wfp_drop_overflow_coalesced()` increments deterministically
    // when `wfp_drop_tx` and `wfp_drop_overflow.queue` are both saturated.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt");
    rt.block_on(async {
        let store = LedrStore::open_in_memory().expect("open store");
        let engine = start_overflow_engine(store);
        // Current-thread worker has not yielded yet, so `wfp_drop_tx` (cap 1) and
        // `wfp_drop_overflow.queue` (cap 1) saturate deterministically before any `.await`.
        let exe = r"C:\Tools\burst_app.exe";
        let ts = current_unix_ms();
        let mk = |ip: IpAddr, port: u16| WfpDropEvent {
            os_filter_id: 1,
            rule_handle: 1,
            exe_path: exe.to_string(),
            protocol: 6,
            dst_ip: ip,
            dst_port: port,
            timestamp_ms: ts,
        };
        assert!(engine.ingest_wfp_drop_event(mk(ip1, 443))); // fills wfp_drop_tx
        assert_eq!(engine.wfp_drop_overflow_pushed(), 0);
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 0);

        assert!(engine.ingest_wfp_drop_event(mk(ip2, 443))); // Queued in overflow.queue
        assert_eq!(engine.wfp_drop_overflow_pushed(), 1);
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 0);

        assert!(engine.ingest_wfp_drop_event(mk(ip3, 443))); // CoalescedNewExe
        assert_eq!(engine.wfp_drop_overflow_pushed(), 2);
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 0);

        assert!(engine.ingest_wfp_drop_event(mk(ip4, 443))); // CoalescedOverwritten (#1)
        assert_eq!(engine.wfp_drop_overflow_pushed(), 2);
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 1);

        // Same dst_ip with different port passes WfpDropDedupCache, hits Deduplicated in
        // coalesced_by_exe -> must NOT increment `wfp_drop_overflow_coalesced`.
        assert!(engine.ingest_wfp_drop_event(mk(ip4, 8443)));
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 1);

        // Another distinct IP -> CoalescedOverwritten (#2).
        let ip5 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
        assert!(engine.ingest_wfp_drop_event(mk(ip5, 443)));
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 2);

        engine.shutdown_and_flush().await.expect("shutdown");
    });
}

/// `DAEMON-P3-45A` (`R-11`): `shutdown_and_flush` runs `checkpoint_truncate` before waiting on
/// an in-flight NRD thread when `!worker_checkpointed`, wakes via `oneshot` on both normal
/// completion and panic without Lost Wakeup, and detaches a wedged NRD OS thread on budget
/// expiry so subsequent Tokio `Runtime::drop` never hangs.
#[test]
fn daemon_p3_45a_r11_shutdown_checkpoints_first_and_detaches_wedged_nrd_without_runtime_hang() {
    use super::{current_unix_ms, DaemonConfig, DaemonEngine, NrdThreadHandle};
    use ledr_proto::{ProcessIdentity, SensorEvent};
    use ledr_rules::{EarlyPruner, SigmaEngine};
    use ledr_store::LedrStore;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    // Part A: Wedged NRD thread exceeds budget -> checkpoint runs BEFORE NRD wait, shutdown
    // detaches cleanly, and `drop(rt)` returns immediately without hanging.
    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-r11-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let db_path = tmp_dir.join("ledr.db");
    let wal_path = tmp_dir.join("ledr.db-wal");

    let (release_tx, release_rx) = mpsc::channel::<()>();
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build rt");

        rt.block_on(async {
            let store = LedrStore::open(&db_path).expect("open file store");
            let engine = DaemonEngine::start(
                store.clone(),
                SigmaEngine::default(),
                EarlyPruner::default(),
                DaemonConfig {
                    shutdown_flush_timeout_ms: 300,
                    outbound_firewall_enabled: false,
                    ..DaemonConfig::default()
                },
            );
            // Take and stop the worker task so `worker_checkpointed == false` during shutdown.
            if let Some(h) = engine.worker_handle.lock().await.take() {
                h.abort();
                let _ = h.await;
            }

            // Write a committed batch into the WAL file without checkpointing yet.
            let now_ms = current_unix_ms();
            let proc_id =
                ProcessIdentity::new(9501, (now_ms as u64 + 11_644_473_600_000) * 10_000);
            store
                .ingest_event(
                    &SensorEvent::ProcessStart {
                        identity: proc_id,
                        parent_pid: 4,
                        exe_path: r"C:\Tools\wal_probe.exe".to_string(),
                        command_line: r"C:\Tools\wal_probe.exe".to_string(),
                        user_sid: None,
                    },
                    None,
                    false,
                    "OBSERVED",
                )
                .expect("ingest");
            store.flush_batch().expect("flush batch to WAL");
            let wal_len_before = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
            assert!(wal_len_before > 0, "WAL must be non-empty before shutdown");

            // Install a wedged NRD thread that will stay blocked past the 300ms shutdown budget.
            let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
            let join_handle = std::thread::Builder::new()
                .name("ledr-r11-wedged-nrd".to_string())
                .spawn(move || {
                    let _ = release_rx.recv();
                    let _ = done_tx.send(());
                })
                .expect("spawn wedged nrd thread");
            *engine.nrd_thread_handle.lock().unwrap() = Some(NrdThreadHandle {
                join_handle,
                done_rx,
            });

            let engine_c = std::sync::Arc::clone(&engine);
            let wal_check_path = wal_path.clone();
            let shutdown_task = tokio::spawn(async move { engine_c.shutdown_and_flush().await });

            // Deterministically wait until `shutdown_and_flush` has already executed
            // `checkpoint_truncate`, taken `nrd_thread_handle`, and parked in `Poll::Pending`
            // on `timeout(remaining, &mut nrd.done_rx)`.
            wait_until_nrd_handle_taken(
                &engine,
                &shutdown_task,
                "shutdown_and_flush did not take nrd_thread_handle in time",
                "shutdown_and_flush must be parked awaiting remaining NRD budget on done_rx",
            )
            .await;
            let wal_len_mid = std::fs::metadata(&wal_check_path)
                .map(|m| m.len())
                .unwrap_or(0);
            assert_eq!(
                wal_len_mid, 0,
                "checkpoint_truncate must complete BEFORE waiting on NRD thread"
            );

            let started = Instant::now();
            shutdown_task
                .await
                .expect("join shutdown task")
                .expect("shutdown_and_flush should succeed after detaching wedged NRD thread");
            assert!(
                started.elapsed() < Duration::from_millis(1_500),
                "shutdown_and_flush must return promptly when NRD budget expires"
            );
        });

        // Drop Tokio runtime while the OS thread is STILL blocked -> must NOT hang!
        let drop_started = Instant::now();
        drop(rt);
        assert!(
            drop_started.elapsed() < Duration::from_millis(300),
            "Tokio Runtime::drop must not block on detached NRD OS thread (took {:?})",
            drop_started.elapsed()
        );
    }
    // Release the detached OS thread so the test process exits cleanly.
    let _ = release_tx.send(());
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Part B: Normal completion (already done before shutdown) and panic completion (unwinds
    // during shutdown while parked in `Poll::Pending`) both wake `done_rx` cleanly.
    let rt2 = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt2");
    rt2.block_on(async {
        // B1: Finished before `shutdown_and_flush` (no Lost Wakeup).
        let store = LedrStore::open_in_memory().expect("open store");
        let engine = DaemonEngine::start(
            store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                shutdown_flush_timeout_ms: 2_000,
                outbound_firewall_enabled: false,
                ..DaemonConfig::default()
            },
        );
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        let join_handle = std::thread::spawn(move || {
            let _ = done_tx.send(());
        });
        // Ensure the thread finishes before shutdown starts.
        while !join_handle.is_finished() {
            std::thread::yield_now();
        }
        *engine.nrd_thread_handle.lock().unwrap() = Some(NrdThreadHandle {
            join_handle,
            done_rx,
        });
        let t0 = Instant::now();
        engine.shutdown_and_flush().await.expect("shutdown B1");
        assert!(t0.elapsed() < Duration::from_millis(500));

        // B2: Panicking NRD thread sends via Drop guard while shutdown is parked on `done_rx`.
        let store2 = LedrStore::open_in_memory().expect("open store2");
        let engine2 = DaemonEngine::start(
            store2,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                shutdown_flush_timeout_ms: 2_000,
                outbound_firewall_enabled: false,
                ..DaemonConfig::default()
            },
        );
        let (done_tx2, done_rx2) = tokio::sync::oneshot::channel::<()>();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let join_handle2 = std::thread::spawn(move || {
            struct DropNotify(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for DropNotify {
                fn drop(&mut self) {
                    if let Some(tx) = self.0.take() {
                        let _ = tx.send(());
                    }
                }
            }
            let _guard = DropNotify(Some(done_tx2));
            let _ = go_rx.recv();
            panic!("simulated NRD refresh panic");
        });
        *engine2.nrd_thread_handle.lock().unwrap() = Some(NrdThreadHandle {
            join_handle: join_handle2,
            done_rx: done_rx2,
        });
        let engine2_c = std::sync::Arc::clone(&engine2);
        let shutdown_b2 = tokio::spawn(async move { engine2_c.shutdown_and_flush().await });
        // Deterministically synchronize until `shutdown_and_flush` has taken `nrd_thread_handle`
        // and parked in `Poll::Pending` on `done_rx2` before triggering the panic.
        wait_until_nrd_handle_taken(
            &engine2,
            &shutdown_b2,
            "shutdown B2 did not take nrd_thread_handle in time",
            "shutdown B2 must be parked awaiting done_rx2 before panic trigger",
        )
        .await;
        let t1 = Instant::now();
        let _ = go_tx.send(());
        shutdown_b2
            .await
            .expect("join shutdown B2")
            .expect("shutdown B2 should tolerate NRD panic cleanly");
        assert!(
            t1.elapsed() < Duration::from_millis(500),
            "panicking NRD thread must wake shutdown immediately via Drop guard (took {:?})",
            t1.elapsed()
        );
    });
}

/// `DAEMON-P3-48A` (`#9` + `T1-4`): `ingest_wfp_drop_event` emits zero synchronous `tracing`
/// events across `CoalescedOverwritten` (including thresholds 1, 2, 4) and `Closed` paths;
/// asynchronous worker reporting emits power-of-two aggregated warnings via
/// `maybe_log_wfp_drop_overflow_coalesced`; and `DaemonEngine::nrd_cancel_token` shares state
/// with the engine's internal cancellation token.
#[test]
fn daemon_p3_48a_ingest_wfp_drop_emits_zero_sync_logs_and_worker_warns_aggregated() {
    use super::current_unix_ms;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSubscriber {
        total_events: Arc<AtomicUsize>,
        warn_events: Arc<AtomicUsize>,
        coalesced_warn_events: Arc<AtomicUsize>,
    }
    impl tracing::Subscriber for CountingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            self.total_events.fetch_add(1, Ordering::SeqCst);
            if *event.metadata().level() == tracing::Level::WARN {
                self.warn_events.fetch_add(1, Ordering::SeqCst);
                if event.metadata().fields().field("coalesced_count").is_some() {
                    self.coalesced_warn_events.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build rt");
    rt.block_on(async {
        let store = LedrStore::open_in_memory().expect("open store");
        let engine = start_overflow_engine(store);

        // T1-4 check: `nrd_cancel_token()` exposes a live clone of `self.nrd_cancel`.
        let ext_token = engine.nrd_cancel_token();
        assert!(!ext_token.is_cancelled());

        let total_events = Arc::new(AtomicUsize::new(0));
        let warn_events = Arc::new(AtomicUsize::new(0));
        let coalesced_warn_events = Arc::new(AtomicUsize::new(0));
        let make_sub = || CountingSubscriber {
            total_events: Arc::clone(&total_events),
            warn_events: Arc::clone(&warn_events),
            coalesced_warn_events: Arc::clone(&coalesced_warn_events),
        };

        let exe = r"C:\Tools\bfe_callback_no_log.exe";
        let ts = current_unix_ms();
        let mk = |last_octet: u8| make_wfp_drop_event(exe, last_octet, ts);

        // Worker has not yielded yet -> `wfp_drop_tx` (cap 1) + `overflow.queue` (cap 1)
        // fill deterministically and hit `CoalescedOverwritten` #1, #2, #3, #4 synchronously.
        tracing::subscriber::with_default(make_sub(), || {
            assert!(engine.ingest_wfp_drop_event(mk(1))); // wfp_drop_tx
            assert!(engine.ingest_wfp_drop_event(mk(2))); // overflow.queue
            assert!(engine.ingest_wfp_drop_event(mk(3))); // CoalescedNewExe
            assert!(engine.ingest_wfp_drop_event(mk(4))); // CoalescedOverwritten #1
            assert!(engine.ingest_wfp_drop_event(mk(5))); // CoalescedOverwritten #2
            assert!(engine.ingest_wfp_drop_event(mk(6))); // CoalescedOverwritten #3
            assert!(engine.ingest_wfp_drop_event(mk(7))); // CoalescedOverwritten #4
        });
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 4);
        assert_eq!(
            total_events.load(Ordering::SeqCst),
            0,
            "ingest_wfp_drop_event must emit zero tracing events on CoalescedOverwritten (1, 2, 4)"
        );

        // Worker-side aggregated warning emits once at threshold 4, skips 5..7, and emits
        // again upon reaching threshold 8.
        let mut last_warned = 0u64;
        tracing::subscriber::with_default(make_sub(), || {
            assert!(engine.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned));
            assert_eq!(last_warned, 4);
            assert!(!engine.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned));
        });
        assert_eq!(warn_events.load(Ordering::SeqCst), 1);
        assert_eq!(total_events.load(Ordering::SeqCst), 1);

        tracing::subscriber::with_default(make_sub(), || {
            assert!(engine.ingest_wfp_drop_event(mk(8))); // #5
            assert!(engine.ingest_wfp_drop_event(mk(9))); // #6
            assert!(engine.ingest_wfp_drop_event(mk(10))); // #7
        });
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 7);
        assert_eq!(
            total_events.load(Ordering::SeqCst),
            1,
            "ingest_wfp_drop_event must remain silent during #5..#7"
        );
        tracing::subscriber::with_default(make_sub(), || {
            assert!(!engine.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned));
            assert!(engine.ingest_wfp_drop_event(mk(11))); // #8
        });
        assert_eq!(engine.wfp_drop_overflow_coalesced(), 8);
        assert_eq!(
            total_events.load(Ordering::SeqCst),
            1,
            "ingest_wfp_drop_event must remain silent on #8"
        );
        tracing::subscriber::with_default(make_sub(), || {
            assert!(engine.maybe_log_wfp_drop_overflow_coalesced(&mut last_warned));
            assert_eq!(last_warned, 8);
        });
        assert_eq!(warn_events.load(Ordering::SeqCst), 2);

        // Exercise the `Closed` channel path after shutting down the worker task.
        engine.shutdown_and_flush().await.expect("shutdown");
        assert!(
            ext_token.is_cancelled(),
            "shutdown_and_flush must cancel the token exposed by nrd_cancel_token()"
        );
        let before_closed = total_events.load(Ordering::SeqCst);
        tracing::subscriber::with_default(make_sub(), || {
            assert!(
                !engine.ingest_wfp_drop_event(mk(99)),
                "closed wfp_drop_tx channel must return false"
            );
        });
        assert_eq!(
            total_events.load(Ordering::SeqCst),
            before_closed,
            "ingest_wfp_drop_event must emit zero tracing events on Closed path"
        );
    });

    // Live worker-task verification: wrap a `current_thread` runtime execution in our custom
    // `tracing::Subscriber`, trigger `CoalescedOverwritten` before yielding (asserting zero
    // synchronous logs), then let the live `run_pipeline` worker task run and assert it emits
    // the aggregated warning asynchronously without calling the helper directly.
    let live_total = Arc::new(AtomicUsize::new(0));
    let live_warns = Arc::new(AtomicUsize::new(0));
    let live_coalesced_warns = Arc::new(AtomicUsize::new(0));
    let live_sub = CountingSubscriber {
        total_events: Arc::clone(&live_total),
        warn_events: Arc::clone(&live_warns),
        coalesced_warn_events: Arc::clone(&live_coalesced_warns),
    };
    let rt_live = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build live rt");
    tracing::subscriber::with_default(live_sub, || {
        rt_live.block_on(async {
            let store = LedrStore::open_in_memory().expect("open live store");
            let live_engine = start_overflow_engine(store);
            let exe = r"C:\Tools\bfe_live_worker_warn.exe";
            let ts = current_unix_ms();
            let mk = |last_octet: u8| make_wfp_drop_event(exe, last_octet, ts);
            // Reset counts after startup so only ingest + worker events are counted.
            live_total.store(0, Ordering::SeqCst);
            live_warns.store(0, Ordering::SeqCst);
            live_coalesced_warns.store(0, Ordering::SeqCst);
            assert!(live_engine.ingest_wfp_drop_event(mk(1)));
            assert!(live_engine.ingest_wfp_drop_event(mk(2)));
            assert!(live_engine.ingest_wfp_drop_event(mk(3)));
            assert!(live_engine.ingest_wfp_drop_event(mk(4))); // CoalescedOverwritten #1
            assert!(live_engine.ingest_wfp_drop_event(mk(5))); // CoalescedOverwritten #2
            assert_eq!(
                live_total.load(Ordering::SeqCst),
                0,
                "synchronous ingest_wfp_drop_event must emit zero logs under live worker subscriber"
            );
            // Park briefly so Tokio's timer driver completes `run_pipeline`'s initial t=0
            // interval ticks and the live worker dequeues drops and emits the aggregated
            // `coalesced_count` WARN BEFORE shutdown.
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
            while live_coalesced_warns.load(Ordering::SeqCst) == 0
                && std::time::Instant::now() < deadline
            {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(
                live_coalesced_warns.load(Ordering::SeqCst) >= 1,
                "live run_pipeline worker task must emit aggregated coalesced_count WARN before shutdown"
            );
            live_engine.shutdown_and_flush().await.expect("live shutdown");
        });
    });
}
