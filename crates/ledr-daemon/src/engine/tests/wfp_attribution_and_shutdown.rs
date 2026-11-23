use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ledr_proto::{AlertStatus, ProcessIdentity, SensorEvent};
use ledr_rules::{EarlyPruner, SigmaEngine};
use ledr_sensor_win::etw::{LiveProcessInfo, LiveSiblingCheck};
use ledr_sensor_win::WfpDropEvent;
use ledr_store::LedrStore;

use super::helpers::{
    send_dns, send_process_start, send_process_stop, start_stopped_engine, FixedShaInspector,
    StubNotifier, TestDefense,
};
use super::{current_unix_ms, DaemonConfig, DaemonEngine, WfpRuleManager};
use crate::engine::binary_inspector::LiveProcessInspector;
use crate::engine::wfp_drops::QueuedWfpDrop;

struct MockLiveSiblingInspector {
    response: Mutex<LiveSiblingCheck>,
    calls: Mutex<Vec<(String, ProcessIdentity, i64)>>,
}

impl MockLiveSiblingInspector {
    fn new(response: LiveSiblingCheck) -> Self {
        Self {
            response: Mutex::new(response),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, ProcessIdentity, i64)> {
        self.calls.lock().unwrap().clone()
    }
}

impl LiveProcessInspector for MockLiveSiblingInspector {
    fn inspect_live_process(&self, _pid: u32) -> Option<LiveProcessInfo> {
        None
    }

    fn check_live_siblings_for_exe(
        &self,
        exe_key: &str,
        candidate: ProcessIdentity,
        max_created_at_ms: i64,
    ) -> LiveSiblingCheck {
        self.calls
            .lock()
            .unwrap()
            .push((exe_key.to_string(), candidate, max_created_at_ms));
        self.response.lock().unwrap().clone()
    }
}

struct BlockingLiveSiblingInspector {
    entered: Arc<AtomicBool>,
    release: Arc<AtomicBool>,
    result: LiveSiblingCheck,
}

impl LiveProcessInspector for BlockingLiveSiblingInspector {
    fn inspect_live_process(&self, _pid: u32) -> Option<LiveProcessInfo> {
        None
    }

    fn check_live_siblings_for_exe(
        &self,
        _exe_key: &str,
        _candidate: ProcessIdentity,
        _max_created_at_ms: i64,
    ) -> LiveSiblingCheck {
        self.entered.store(true, Ordering::Release);
        let wait = || {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while !self.release.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
        };
        if tokio::runtime::Handle::try_current()
            .is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
        {
            tokio::task::block_in_place(wait);
        } else {
            wait();
        }
        self.result.clone()
    }
}

async fn wait_until_unit<F: Fn() -> bool>(timeout_ms: u64, pred: F) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    pred()
}

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

fn unix_ms_to_ft(ts_ms: i64) -> u64 {
    (ts_ms.max(0) as u64) * 10_000 + WINDOWS_TO_UNIX_EPOCH_100NS
}

/// `DAEMON-P3-51` (`FU-E2E-05`):
/// - Part A: BFE `WfpDropEvent` arrives ahead of ETW `ProcessStart` for a concurrent short-lived
///   sibling while a long-lived `python.exe` is active -> `wfp_drop_attribution_grace_ms` catches
///   the delayed sibling `ProcessStart` and marks the drop `app_level_ambiguous` (0 suspends).
/// - Part B: Even with `wfp_drop_attribution_grace_ms = 0`, `wfp_drop_live_sibling_os_check = true`
///   detects the live sibling on OS snapshot (`LiveSiblingCheck::SiblingFound`) and avoids freeze.
/// - Part C: While `LiveProcessInspector::check_live_siblings_for_exe` blocks, neither
///   `process_table` nor `firewall` lock is held (verified via bounded `try_lock()` checks per
///   `daemon-wfp-process-invariants.md` L27).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_p3_51_bfe_race_os_live_sibling_and_lock_non_holding() {
    let python_exe = r"C:\Python311\python.exe";
    let dst_v6 = IpAddr::V6("2001:4860:4840:400::".parse::<Ipv6Addr>().unwrap());

    // Part A: Attribution grace catches delayed ETW ProcessStart for concurrent sibling.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = DaemonEngine::start_with_all_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_attribution_grace_ms: 400,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(StubNotifier),
            Arc::new(FixedShaInspector("a".repeat(64))),
            Arc::new(MockLiveSiblingInspector::new(LiveSiblingCheck::NoneFound)),
        );

        let base_ms = current_unix_ms();
        let long_lived = ProcessIdentity::new(17004, unix_ms_to_ft(base_ms - 5_000));
        let sibling = ProcessIdentity::new(28840, unix_ms_to_ft(base_ms - 126));

        let sender = engine.sender();
        sender
            .send(SensorEvent::ProcessStart {
                identity: long_lived,
                parent_pid: 4,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" local_server.py"),
                user_sid: None,
            })
            .await
            .expect("send long_lived start");
        assert!(wait_until_unit(1_000, || engine.metrics().high_priority_processed >= 1).await);

        let drop_ts = base_ms;
        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 3,
            rule_handle: 1,
            exe_path: python_exe.to_string(),
            protocol: 6,
            dst_ip: dst_v6,
            dst_port: 443,
            timestamp_ms: drop_ts,
        }));

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(defense.suspends(), 0, "drop must be parked in attribution grace");

        // Delayed ETW ProcessStart of concurrent sibling arrives within grace window.
        sender
            .send(SensorEvent::ProcessStart {
                identity: sibling,
                parent_pid: 4,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" helper.py"),
                user_sid: None,
            })
            .await
            .expect("send delayed sibling start");

        assert!(
            wait_until_unit(1_000, || {
                store
                    .list_alerts(Some(AlertStatus::Pending), 50)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .await,
            "delayed sibling ProcessStart must wake parked drop as app_level_ambiguous"
        );
        assert_eq!(
            defense.suspends(),
            0,
            "long-lived python.exe must NOT be suspended when sibling ProcessStart arrives in grace"
        );
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 50).expect("alerts");
        assert_eq!(alerts.len(), 1);
        assert!(!alerts[0].process_suspended);
        assert_eq!(alerts[0].process_instance_id, None);
        let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx");
        assert_eq!(ctx["attribution"], "app_level_ambiguous");
        engine.shutdown_and_flush().await.expect("shutdown A");
    }

    // Part B: OS live sibling check catches concurrent sibling even with attribution grace = 0.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let base_ms = current_unix_ms();
        let long_lived = ProcessIdentity::new(17004, unix_ms_to_ft(base_ms - 5_000));
        let os_sibling = ProcessIdentity::new(28840, unix_ms_to_ft(base_ms - 100));
        let mock_live = Arc::new(MockLiveSiblingInspector::new(LiveSiblingCheck::SiblingFound(
            vec![os_sibling],
        )));

        let engine = DaemonEngine::start_with_all_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_attribution_grace_ms: 0,
                wfp_drop_live_sibling_os_check: true,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(StubNotifier),
            Arc::new(FixedShaInspector("a".repeat(64))),
            Arc::clone(&mock_live) as Arc<dyn LiveProcessInspector>,
        );

        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: long_lived,
                parent_pid: 4,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" local_server.py"),
                user_sid: None,
            })
            .await
            .expect("send long_lived");
        assert!(wait_until_unit(1_000, || engine.metrics().high_priority_processed >= 1).await);

        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 3,
            rule_handle: 1,
            exe_path: python_exe.to_string(),
            protocol: 6,
            dst_ip: dst_v6,
            dst_port: 443,
            timestamp_ms: base_ms,
        }));

        assert!(
            wait_until_unit(1_000, || {
                store
                    .list_alerts(Some(AlertStatus::Pending), 50)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .await
        );
        assert_eq!(defense.suspends(), 0);
        let calls = mock_live.calls();
        assert!(!calls.is_empty());
        assert_eq!(calls[0].1, long_lived);
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 50).expect("alerts");
        let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx");
        assert_eq!(ctx["attribution"], "app_level_ambiguous");
        engine.shutdown_and_flush().await.expect("shutdown B");
    }

    // Part C: Neither `process_table` nor `firewall` lock is held while `check_live_siblings_for_exe` runs.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let entered = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let blocking_live = Arc::new(BlockingLiveSiblingInspector {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            result: LiveSiblingCheck::SiblingFound(Vec::new()),
        });

        let engine = DaemonEngine::start_with_all_dependencies(
            store,
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_attribution_grace_ms: 0,
                wfp_drop_live_sibling_os_check: true,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(StubNotifier),
            Arc::new(FixedShaInspector("a".repeat(64))),
            blocking_live,
        );

        let base_ms = current_unix_ms();
        let long_lived = ProcessIdentity::new(17004, unix_ms_to_ft(base_ms - 5_000));
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: long_lived,
                parent_pid: 4,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" local_server.py"),
                user_sid: None,
            })
            .await
            .expect("send start");
        assert!(wait_until_unit(1_000, || engine.metrics().high_priority_processed >= 1).await);

        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 3,
            rule_handle: 1,
            exe_path: python_exe.to_string(),
            protocol: 6,
            dst_ip: dst_v6,
            dst_port: 443,
            timestamp_ms: base_ms,
        }));

        assert!(
            wait_until_unit(1_000, || entered.load(Ordering::Acquire)).await,
            "worker must enter BlockingLiveSiblingInspector"
        );
        let lock_deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut table_unlocked = false;
        let mut fw_unlocked = false;
        while tokio::time::Instant::now() < lock_deadline {
            if let Ok(_g) = engine.process_table.try_lock() {
                table_unlocked = true;
            }
            if let Ok(_g) = engine.firewall.try_lock() {
                fw_unlocked = true;
            }
            if table_unlocked && fw_unlocked {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        release.store(true, Ordering::Release);
        assert!(
            table_unlocked,
            "process_table lock MUST NOT be held across check_live_siblings_for_exe"
        );
        assert!(
            fw_unlocked,
            "firewall lock MUST NOT be held across check_live_siblings_for_exe"
        );
        engine.shutdown_and_flush().await.expect("shutdown C");
    }
}

/// `DAEMON-P3-52` (`FU-E2E-05`):
/// Verifies exited/evicted sibling handling, non-DoS against global `evicted_live_overflow_any`,
/// negative same-exe other-instance DNS disambiguation after `ProcessStop` `remove_process`, and
/// rejection of post-drop decoy spawns (`created_at_ms > drop_ts + 250`).
#[tokio::test]
async fn daemon_p3_52_evicted_siblings_non_dos_negative_dns_and_decoy_rejection() {
    let python_exe = r"C:\Python311\python.exe";
    let dst_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
    let base_ms = current_unix_ms();

    // 1a. Exited sibling evicted into `evicted_exited` within 1,000 ms prevents freezing survivor.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = start_stopped_engine(
            store.clone(),
            DaemonConfig {
                active_process_capacity: 2,
                outbound_firewall_enabled: true,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(FixedShaInspector("a".repeat(64))),
        )
        .await;

        let p_evicted_exited = ProcessIdentity::new(5001, unix_ms_to_ft(base_ms - 4_000));
        let filler = ProcessIdentity::new(5002, unix_ms_to_ft(base_ms - 3_000));
        let p_surviving = ProcessIdentity::new(5003, unix_ms_to_ft(base_ms - 2_000));

        send_process_start(&engine, p_evicted_exited, python_exe);
        send_process_stop(&engine, p_evicted_exited.pid, unix_ms_to_ft(base_ms - 500));
        // Fill capacity (2) with unrelated process + surviving sibling -> evicts `p_evicted_exited`
        // to `evicted_exited`.
        send_process_start(&engine, filler, r"C:\Other\filler.exe");
        send_process_start(&engine, p_surviving, python_exe);

        engine.handle_wfp_drop_event_now(&QueuedWfpDrop {
            exe_path: python_exe.to_string(),
            exe_key: WfpRuleManager::exe_key(python_exe),
            dst_ip,
            dst_port: 443,
            protocol: 6,
            timestamp_ms: base_ms,
            os_filter_id: 9,
        });
        assert_eq!(defense.suspends(), 0);
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 20).expect("alerts");
        assert_eq!(alerts.len(), 1);
        let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx");
        assert_eq!(ctx["attribution"], "app_level_ambiguous");
    }

    // 1b. Live sibling displaced into `evicted_live` prevents freezing surviving sibling.
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = start_stopped_engine(
            store.clone(),
            DaemonConfig {
                active_process_capacity: 2,
                outbound_firewall_enabled: true,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(FixedShaInspector("a".repeat(64))),
        )
        .await;

        let p_evicted_live = ProcessIdentity::new(5101, unix_ms_to_ft(base_ms - 3_000));
        let filler = ProcessIdentity::new(5102, unix_ms_to_ft(base_ms - 2_500));
        let p_surviving = ProcessIdentity::new(5103, unix_ms_to_ft(base_ms - 2_000));

        send_process_start(&engine, p_evicted_live, python_exe);
        send_process_start(&engine, filler, r"C:\Other\filler.exe");
        send_process_start(&engine, p_surviving, python_exe);

        engine.handle_wfp_drop_event_now(&QueuedWfpDrop {
            exe_path: python_exe.to_string(),
            exe_key: WfpRuleManager::exe_key(python_exe),
            dst_ip,
            dst_port: 443,
            protocol: 6,
            timestamp_ms: base_ms,
            os_filter_id: 19,
        });
        assert_eq!(defense.suspends(), 0);
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 20).expect("alerts");
        assert_eq!(alerts.len(), 1);
        let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx");
        assert_eq!(ctx["attribution"], "app_level_ambiguous");
    }

    // 2. Global `evicted_live_overflow_any == true` caused by UNRELATED exe spam must NOT disable
    //    single-candidate suspension for an unrelated target executable!
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = start_stopped_engine(
            store.clone(),
            DaemonConfig {
                active_process_capacity: 2,
                outbound_firewall_enabled: true,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(FixedShaInspector("a".repeat(64))),
        )
        .await;
        {
            let mut table = engine.process_table.lock().unwrap();
            *table = crate::process_table::ActiveProcessTable::new(2).with_evicted_live_capacity(2);
            table.force_evicted_live_overflow_any_for_test();
        }

        // Spam 6 unrelated live processes so `evicted_live` (cap=2) also overflows on noise.exe.
        for idx in 0..6u32 {
            let pid = 6100 + idx;
            send_process_start(
                &engine,
                ProcessIdentity::new(pid, unix_ms_to_ft(base_ms - 5_000 + i64::from(idx))),
                r"C:\Spam\noise.exe",
            );
        }
        // Now start a single malicious python.exe (NO siblings, NO overflow on python_exe).
        let target = ProcessIdentity::new(6200, unix_ms_to_ft(base_ms - 500));
        send_process_start(&engine, target, python_exe);

        engine.handle_wfp_drop_event_now(&QueuedWfpDrop {
            exe_path: python_exe.to_string(),
            exe_key: WfpRuleManager::exe_key(python_exe),
            dst_ip,
            dst_port: 443,
            protocol: 6,
            timestamp_ms: base_ms,
            os_filter_id: 10,
        });
        assert_eq!(
            defense.suspends(),
            1,
            "global evicted_live overflow on unrelated noise.exe must NOT bypass target suspension"
        );
    }

    // 3. Negative same-exe other-instance DNS disambiguation: sibling exited 3,500 ms ago (>1,000 ms,
    //    <=10,000 ms), ProcessStop removed its per-instance DNS entry, yet `recent_exe_ip_resolvers`
    //    retains that another instance of python.exe resolved `dst_ip` -> non-freeze!
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = start_stopped_engine(
            store.clone(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_recent_exit_window_ms: 1_000,
                wfp_drop_other_instance_dns_window_ms: 10_000,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(FixedShaInspector("a".repeat(64))),
        )
        .await;

        let long_lived = ProcessIdentity::new(7001, unix_ms_to_ft(base_ms - 20_000));
        let exited_sib = ProcessIdentity::new(7002, unix_ms_to_ft(base_ms - 4_000));
        send_process_start(&engine, long_lived, python_exe);
        send_process_start(&engine, exited_sib, python_exe);
        send_dns(
            &engine,
            exited_sib.pid,
            "api.example.invalid",
            &[dst_ip],
            base_ms - 3_600,
        );
        send_process_stop(&engine, exited_sib.pid, unix_ms_to_ft(base_ms - 3_500));

        engine.handle_wfp_drop_event_now(&QueuedWfpDrop {
            exe_path: python_exe.to_string(),
            exe_key: WfpRuleManager::exe_key(python_exe),
            dst_ip,
            dst_port: 443,
            protocol: 6,
            timestamp_ms: base_ms,
            os_filter_id: 11,
        });
        assert_eq!(
            defense.suspends(),
            0,
            "recent same-exe sibling DNS resolution within 10s must prevent freezing survivor"
        );
        let alerts = store.list_alerts(Some(AlertStatus::Pending), 20).expect("alerts");
        assert_eq!(alerts.len(), 1);
        let ctx: serde_json::Value = serde_json::from_str(&alerts[0].context_json).expect("ctx");
        assert_eq!(ctx["attribution"], "app_level_ambiguous");
    }

    // 4. Post-drop decoy sibling (`created_at_ms = drop_ts + 500 > drop_ts + 250`) arriving during
    //    `wfp_drop_attribution_grace_ms` MUST NOT make the earlier drop ambiguous -> attacker still frozen!
    {
        let store = LedrStore::open_in_memory().expect("open store");
        let defense = Arc::new(TestDefense::new(1));
        let engine = DaemonEngine::start_with_dependencies(
            store.clone(),
            SigmaEngine::default(),
            EarlyPruner::default(),
            DaemonConfig {
                outbound_firewall_enabled: true,
                wfp_drop_attribution_grace_ms: 350,
                wfp_drop_live_sibling_os_check: false,
                ..DaemonConfig::default()
            },
            Arc::clone(&defense) as Arc<dyn ledr_proto::ActiveDefenseController>,
            Arc::new(StubNotifier),
            Arc::new(FixedShaInspector("a".repeat(64))),
        );

        let drop_ts = current_unix_ms();
        let attacker = ProcessIdentity::new(8001, unix_ms_to_ft(drop_ts - 200));
        let decoy = ProcessIdentity::new(8002, unix_ms_to_ft(drop_ts + 500));

        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: attacker,
                parent_pid: 4,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" attack.py"),
                user_sid: None,
            })
            .await
            .expect("send attacker start");
        assert!(wait_until_unit(1_000, || engine.metrics().high_priority_processed >= 1).await);

        assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
            os_filter_id: 12,
            rule_handle: 1,
            exe_path: python_exe.to_string(),
            protocol: 6,
            dst_ip,
            dst_port: 443,
            timestamp_ms: drop_ts,
        }));
        tokio::time::sleep(Duration::from_millis(40)).await;

        // Spawn post-drop decoy inside the 350ms grace window; its create time exceeds drop_ts + 250ms.
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: decoy,
                parent_pid: attacker.pid,
                exe_path: python_exe.to_string(),
                command_line: format!("\"{python_exe}\" -c pass"),
                user_sid: None,
            })
            .await
            .expect("send decoy start");

        assert!(
            wait_until_unit(1_500, || defense.suspends() == 1).await,
            "post-drop decoy spawned after drop_ts + 250ms must NOT evade attacker suspension"
        );
        engine.shutdown_and_flush().await.expect("shutdown decoy test");
    }
}
