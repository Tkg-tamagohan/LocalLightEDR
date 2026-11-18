//! Phase 2 integration tests for `ledr-daemon`: Canary containment (`L-02`, `L-06`, `L-07`),
//! 60s `EXPIRED_SUSPENDED` timeout, `ResolveAlert` 3 decisions (`L-04`, `L-07`), Session 0 toast
//! launcher fallback (`L-08`), and Named Pipe SDDL / caller verification (`L-09`)
//! (`DAEMON-P2-01`..`DAEMON-P2-06`).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    build_service_pipe_security_descriptor, start_ipc_server, verify_authorized_caller_binary,
    verify_caller_identity, BinaryInspector, DaemonConfig, DaemonEngine, NotificationDispatcher,
    Session0ToastLauncher, SERVICE_PIPE_SDDL,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, ActiveDefenseController, AlertDecision, AlertRecord,
    AlertSeverity, AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, CanaryCategory, IpcRequest,
    IpcResponse, ProcessIdentity, RuleScope, SensorEvent, AUTHORIZED_UI_EXE_PATH,
    DEFAULT_ALERT_TIMEOUT_SECS,
};
use ledr_rules::{
    compute_file_sha256_hex, AllowlistConfig, BinaryIdentity, EarlyPruner, SigmaEngine,
};
use ledr_store::LedrStore;

const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
const TICKS_PER_MS: u64 = 10_000;

static PIPE_SEQ: AtomicU32 = AtomicU32::new(1);

fn unique_test_pipe_name() -> String {
    let pid = std::process::id();
    let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\localedr-p2-test-{pid}-{seq}")
}

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    u64::try_from(unix_ms).expect("positive unix_ms") * TICKS_PER_MS + WINDOWS_TO_UNIX_EPOCH_100NS
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn open_pipe_with_retry(pipe_name: &str) -> std::fs::File {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match OpenOptions::new().read(true).write(true).open(pipe_name) {
            Ok(file) => return file,
            Err(err)
                if Instant::now() < deadline
                    && matches!(err.raw_os_error(), Some(231) | Some(2)) =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(err) => panic!("open Named Pipe `{pipe_name}` failed: {err}"),
        }
    }
}

fn send_pipe_request(pipe_name: &str, req: &IpcRequest) -> IpcResponse {
    let mut pipe = open_pipe_with_retry(pipe_name);
    write_ipc_frame(&mut pipe, req).expect("write IPC request");
    read_ipc_frame::<_, IpcResponse>(&mut pipe).expect("read IPC response")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SuspendCall {
    target: ProcessIdentity,
    include_children: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminateCall {
    target: ProcessIdentity,
    include_children: bool,
}

#[derive(Default)]
struct MockDefenseController {
    suspends: Mutex<Vec<SuspendCall>>,
    resumes: Mutex<Vec<ProcessIdentity>>,
    terminates: Mutex<Vec<TerminateCall>>,
    fail_suspend: Mutex<bool>,
    terminate_error: Mutex<Option<String>>,
}

impl MockDefenseController {
    fn suspends(&self) -> Vec<SuspendCall> {
        self.suspends.lock().expect("lock suspends").clone()
    }

    fn resumes(&self) -> Vec<ProcessIdentity> {
        self.resumes.lock().expect("lock resumes").clone()
    }

    fn terminates(&self) -> Vec<TerminateCall> {
        self.terminates.lock().expect("lock terminates").clone()
    }

    fn set_terminate_error(&self, err: Option<String>) {
        *self.terminate_error.lock().expect("lock terminate_error") = err;
    }
}

impl ActiveDefenseController for MockDefenseController {
    fn suspend_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        if *self.fail_suspend.lock().expect("lock fail_suspend") {
            return Err("mock suspend failure".to_string());
        }
        self.suspends.lock().expect("lock suspends").push(SuspendCall {
            target: *target,
            include_children,
        });
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        self.resumes.lock().expect("lock resumes").push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        if let Some(err) = self
            .terminate_error
            .lock()
            .expect("lock terminate_error")
            .clone()
        {
            return Err(err);
        }
        self.terminates
            .lock()
            .expect("lock terminates")
            .push(TerminateCall {
                target: *target,
                include_children,
            });
        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        _exe_path: &Path,
        _remote_ip: Option<IpAddr>,
        _allow: bool,
    ) -> Result<u64, String> {
        Ok(1)
    }

    fn remove_wfp_rule(&self, _filter_id: u64) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Default)]
struct MockNotifier {
    notified: Mutex<Vec<AlertRecord>>,
}

impl MockNotifier {
    fn alerts(&self) -> Vec<AlertRecord> {
        self.notified.lock().expect("lock notified").clone()
    }
}

impl NotificationDispatcher for MockNotifier {
    fn notify_alert(&self, alert: &AlertRecord) -> Result<(), String> {
        self.notified
            .lock()
            .expect("lock notified")
            .push(alert.clone());
        Ok(())
    }
}

#[derive(Default)]
struct MockBinaryInspector {
    entries: Mutex<HashMap<String, BinaryIdentity>>,
}

impl MockBinaryInspector {
    fn insert(&self, identity: BinaryIdentity) {
        self.entries
            .lock()
            .expect("lock inspector")
            .insert(identity.exe_path.to_ascii_lowercase(), identity);
    }
}

impl BinaryInspector for MockBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        self.entries
            .lock()
            .expect("lock inspector")
            .get(&exe_path.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: None,
                authenticode: None,
            })
    }
}

async fn wait_for_hp_processed(engine: &DaemonEngine, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while engine.metrics().high_priority_processed < expected {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for high_priority_processed >= {expected} (actual {})",
            engine.metrics().high_priority_processed
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn daemon_p2_01_honeypot_read_ignored_and_write_tree_suspends() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MockBinaryInspector::default());

    let parent_exe = r"C:\Windows\explorer.exe".to_string();
    let locker_exe = r"C:\Temp\ransom_sim.exe".to_string();
    let locker_sha = "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    inspector.insert(BinaryIdentity {
        exe_path: locker_exe.clone(),
        sha256: Some(locker_sha.clone()),
        authenticode: None,
    });

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        inspector,
    );

    let t_base = current_unix_ms() - 5_000;
    let parent_ident = ProcessIdentity::new(1100, unix_ms_to_filetime(t_base));
    let locker_ident = ProcessIdentity::new(1200, unix_ms_to_filetime(t_base + 500));

    let sender = engine.sender();
    sender
        .send(SensorEvent::ProcessStart {
            identity: parent_ident,
            parent_pid: 4,
            exe_path: parent_exe.clone(),
            command_line: "explorer.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send parent");
    sender
        .send(SensorEvent::ProcessStart {
            identity: locker_ident,
            parent_pid: parent_ident.pid,
            exe_path: locker_exe.clone(),
            command_line: format!("{locker_exe} --encrypt"),
            user_sid: None,
        })
        .await
        .expect("send locker");

    let honeypot_path = r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string();
    // 1. Read-only honeypot open MUST be ignored (L-06).
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: locker_ident.pid,
            target_path: honeypot_path.clone(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t_base + 1_000,
        })
        .await
        .expect("send read-only honeypot");
    wait_for_hp_processed(&engine, 3).await;

    assert!(defense.suspends().is_empty());
    assert!(notifier.alerts().is_empty());
    assert!(store
        .list_alerts(None, 20)
        .expect("list alerts")
        .is_empty());
    assert!(store
        .query_flight_recorder(20, None)
        .expect("query fr")
        .file_canary_events
        .is_empty());

    // 2. Write/delete honeypot event MUST suspend tree (`include_children: true`, L-07).
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: locker_ident.pid,
            target_path: honeypot_path.clone(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0012_0116,
            is_write_or_delete: true,
            timestamp_ms: t_base + 1_500,
        })
        .await
        .expect("send honeypot write");
    wait_for_hp_processed(&engine, 4).await;

    assert_eq!(
        defense.suspends(),
        vec![SuspendCall {
            target: locker_ident,
            include_children: true,
        }]
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert_eq!(alert.source_layer, "LAYER_1_CANARY");
    assert_eq!(alert.severity, AlertSeverity::Critical);
    assert!(alert.process_suspended);
    assert_eq!(alert.status, AlertStatus::Pending);
    assert_eq!(
        alert.process_instance_id.as_deref(),
        Some(locker_ident.instance_id().as_str())
    );

    let ctx: serde_json::Value = serde_json::from_str(&alert.context_json).expect("parse context");
    assert_eq!(ctx["target_path"], honeypot_path);
    assert_eq!(ctx["category"], "honeypot");
    assert_eq!(ctx["access_mask"], 0x0012_0116);
    assert_eq!(ctx["is_write_or_delete"], true);
    assert_eq!(ctx["exe_path"], locker_exe);
    assert_eq!(ctx["command_line"], format!("{locker_exe} --encrypt"));
    assert_eq!(ctx["parent_exe_path"], parent_exe);
    assert_eq!(ctx["parent_command_line"], "explorer.exe");
    assert_eq!(ctx["sha256"], locker_sha);
    assert_eq!(ctx["include_children"], true);

    assert_eq!(notifier.alerts().len(), 1);
    assert_eq!(notifier.alerts()[0].alert_id, alert.alert_id);

    let snap = store.query_flight_recorder(20, None).expect("query fr");
    assert_eq!(snap.file_canary_events.len(), 1);
    assert_eq!(snap.file_canary_events[0].action_taken, "SUSPENDED");
    assert_eq!(snap.file_canary_events[0].category, CanaryCategory::Honeypot);

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_02_cookie_single_suspend_never_suspend_and_allowlist_bypass() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MockBinaryInspector::default());

    let browser_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string();
    let browser_auth = AuthenticodeInfo {
        signer_subject: "CN=Google LLC, O=Google LLC, C=US".to_string(),
        root_thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD".to_string(),
    };
    inspector.insert(BinaryIdentity {
        exe_path: browser_exe.clone(),
        sha256: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        authenticode: Some(browser_auth.clone()),
    });

    let stealer_exe = r"C:\Temp\cookie_stealer.exe".to_string();
    inspector.insert(BinaryIdentity {
        exe_path: stealer_exe.clone(),
        sha256: Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string()),
        authenticode: None,
    });

    // Seed allowlist rule for legitimate signed Chrome.
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "ALLOW-CHROME-COOKIES".to_string(),
            scope: RuleScope::FileCanaryAllow,
            exe_path_pattern: browser_exe.clone(),
            sha256: None,
            signer_subject: Some("CN=Google LLC".to_string()),
            root_thumbprint: Some(browser_auth.root_thumbprint.clone()),
            allowed_target: Some(r"*\Google\Chrome\User Data\*\Cookies".to_string()),
            created_at_ms: 1_000,
            created_by: "default".to_string(),
        })
        .expect("seed chrome rule");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        inspector,
    );

    let t_base = current_unix_ms() - 5_000;
    let chrome_ident = ProcessIdentity::new(2100, unix_ms_to_filetime(t_base));
    let explorer_ident = ProcessIdentity::new(2200, unix_ms_to_filetime(t_base + 100));
    let stealer_ident = ProcessIdentity::new(2300, unix_ms_to_filetime(t_base + 200));

    let sender = engine.sender();
    for (ident, exe) in [
        (chrome_ident, browser_exe.as_str()),
        (explorer_ident, r"C:\Windows\explorer.exe"),
        (stealer_ident, stealer_exe.as_str()),
    ] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }

    let cookie_path = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies";
    // 1. Allowlisted signed Chrome -> ALLOWED, no suspend, no alert.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: chrome_ident.pid,
            target_path: cookie_path.to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t_base + 500,
        })
        .await
        .expect("send chrome cookie");

    // 2. Protected OS process `explorer.exe` -> NEVER suspended (`AUTO-02`), still recorded as ALERTED.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: explorer_ident.pid,
            target_path: cookie_path.to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t_base + 600,
        })
        .await
        .expect("send explorer cookie");

    // 3. Unallowed stealer -> single-process suspend (`include_children: false`, L-07).
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: stealer_ident.pid,
            target_path: cookie_path.to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t_base + 700,
        })
        .await
        .expect("send stealer cookie");

    wait_for_hp_processed(&engine, 6).await;

    assert_eq!(
        defense.suspends(),
        vec![SuspendCall {
            target: stealer_ident,
            include_children: false,
        }]
    );

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 2);
    let stealer_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(stealer_ident.instance_id().as_str()))
        .expect("stealer alert");
    assert!(stealer_alert.process_suspended);

    let explorer_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(explorer_ident.instance_id().as_str()))
        .expect("explorer alert");
    assert!(!explorer_alert.process_suspended);

    let snap = store.query_flight_recorder(20, None).expect("query fr");
    assert_eq!(snap.file_canary_events.len(), 3);
    assert!(snap
        .file_canary_events
        .iter()
        .any(|e| e.process_instance_id == chrome_ident.instance_id() && e.action_taken == "ALLOWED"));
    assert!(snap
        .file_canary_events
        .iter()
        .any(|e| e.process_instance_id == explorer_ident.instance_id()
            && e.action_taken == "ALERTED"));
    assert!(snap
        .file_canary_events
        .iter()
        .any(|e| e.process_instance_id == stealer_ident.instance_id()
            && e.action_taken == "SUSPENDED"));

    assert_eq!(notifier.alerts().len(), 2);
    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_03_alert_timeout_transitions_to_expired_suspended_without_resuming() {
    assert_eq!(
        DaemonConfig::default().alert_timeout_ms,
        DEFAULT_ALERT_TIMEOUT_SECS * 1000
    );

    // Part A: Explicit 60s cutoff verification via `expire_overdue_alerts`.
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let engine = DaemonEngine::start_with_controllers(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            alert_timeout_ms: 60_000,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
    );

    let base_ms = current_unix_ms();
    let overdue_alert = AlertRecord {
        alert_id: "alert-overdue".to_string(),
        timestamp_ms: base_ms - 65_000,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Overdue Alert".to_string(),
        process_instance_id: Some("3100:1000".to_string()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: "{}".to_string(),
        resolved_at_ms: None,
    };
    let fresh_alert = AlertRecord {
        alert_id: "alert-fresh".to_string(),
        timestamp_ms: base_ms - 10_000,
        ..overdue_alert.clone()
    };
    store.record_alert(&overdue_alert).expect("record overdue");
    store.record_alert(&fresh_alert).expect("record fresh");

    let transitioned = engine
        .expire_overdue_alerts(base_ms)
        .expect("expire overdue");
    assert_eq!(transitioned, 1);
    assert!(
        defense.resumes().is_empty(),
        "L-07: timeout must preserve suspended state and NEVER auto-resume"
    );

    let all = store.list_alerts(None, 20).expect("list alerts");
    let overdue_row = all
        .iter()
        .find(|a| a.alert_id == "alert-overdue")
        .expect("overdue row");
    assert_eq!(overdue_row.status, AlertStatus::ExpiredSuspended);
    assert_eq!(overdue_row.resolved_at_ms, None);
    assert!(overdue_row.process_suspended);

    let fresh_row = all
        .iter()
        .find(|a| a.alert_id == "alert-fresh")
        .expect("fresh row");
    assert_eq!(fresh_row.status, AlertStatus::Pending);

    engine.shutdown_and_flush().await.expect("shutdown part A");

    // Part B: Periodic `run_pipeline` background timer automatically expires overdue alerts.
    let store2 = LedrStore::open_in_memory().expect("open store 2");
    let defense2 = Arc::new(MockDefenseController::default());
    let notifier2 = Arc::new(MockNotifier::default());
    let engine2 = DaemonEngine::start_with_controllers(
        store2.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            alert_timeout_ms: 80,
            ..DaemonConfig::default()
        },
        defense2.clone(),
        notifier2,
    );

    let ident = ProcessIdentity::new(3200, unix_ms_to_filetime(current_unix_ms() - 500));
    engine2
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: r"C:\Temp\slow_stealer.exe".to_string(),
            command_line: "slow_stealer.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");
    engine2
        .sender()
        .send(SensorEvent::CanaryFileAccess {
            pid: ident.pid,
            target_path: r"C:\Users\alice\.ssh\id_ed25519".to_string(),
            category: CanaryCategory::SshKey,
            access_mask: 1,
            is_write_or_delete: false,
            timestamp_ms: current_unix_ms() - 500,
        })
        .await
        .expect("send ssh canary");

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let expired = store2
            .list_alerts(Some(AlertStatus::ExpiredSuspended), 10)
            .expect("list expired");
        if !expired.is_empty() {
            assert_eq!(expired.len(), 1);
            assert!(expired[0].process_suspended);
            assert_eq!(expired[0].resolved_at_ms, None);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for periodic expiry ticker"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    assert!(defense2.resumes().is_empty());

    engine2.shutdown_and_flush().await.expect("shutdown part B");
}

#[tokio::test]
async fn daemon_p2_04_resolve_alert_three_decisions_and_ipc_roundtrip() {
    let pipe_name = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MockBinaryInspector::default());

    let signed_exe = r"C:\Program Files\TrustedBackup\backup.exe";
    let signed_sha = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let signed_subj = "CN=Trusted Backup Inc, O=Trusted Backup Inc, C=US";
    let signed_tp = "AABBCCDDEEFF0011223344556677889900112233";
    inspector.insert(BinaryIdentity {
        exe_path: signed_exe.to_string(),
        sha256: Some(signed_sha.to_string()),
        authenticode: Some(AuthenticodeInfo {
            signer_subject: signed_subj.to_string(),
            root_thumbprint: signed_tp.to_string(),
        }),
    });

    let unsigned_exe = r"C:\Tools\unsigned_helper.exe";
    let unsigned_sha = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    inspector.insert(BinaryIdentity {
        exe_path: unsigned_exe.to_string(),
        sha256: Some(unsigned_sha.to_string()),
        authenticode: None,
    });

    let evil_exe = r"C:\Users\alice\Downloads\stealer.exe";
    let evil_sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    inspector.insert(BinaryIdentity {
        exe_path: evil_exe.to_string(),
        sha256: Some(evil_sha.to_string()),
        authenticode: None,
    });

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        inspector,
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("start IPC");

    let t0 = current_unix_ms() - 10_000;
    let id_once = ProcessIdentity::new(4001, unix_ms_to_filetime(t0));
    let id_signed = ProcessIdentity::new(4002, unix_ms_to_filetime(t0 + 10));
    let id_unsigned = ProcessIdentity::new(4003, unix_ms_to_filetime(t0 + 20));
    let id_evil = ProcessIdentity::new(4004, unix_ms_to_filetime(t0 + 30));
    let id_no_hash = ProcessIdentity::new(4005, unix_ms_to_filetime(t0 + 40));

    let sender = engine.sender();
    for (ident, exe, target) in [
        (id_once, unsigned_exe, r"E:\dev\.env"),
        (id_signed, signed_exe, r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
        (id_unsigned, unsigned_exe, r"E:\dev\.env.prod"),
        (id_evil, evil_exe, r"C:\Users\alice\.aws\credentials"),
        (id_no_hash, r"C:\NonExistent\no_hash.exe", r"C:\Users\alice\.ssh\id_rsa"),
    ] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
        sender
            .send(SensorEvent::CanaryFileAccess {
                pid: ident.pid,
                target_path: target.to_string(),
                category: if target.contains("Canary") {
                    CanaryCategory::Honeypot
                } else {
                    CanaryCategory::EnvFile
                },
                access_mask: 2,
                is_write_or_delete: true,
                timestamp_ms: t0 + 100,
            })
            .await
            .expect("send canary");
    }

    wait_for_hp_processed(&engine, 10).await;
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 5);

    let find_alert_id = |ident: ProcessIdentity| -> String {
        alerts
            .iter()
            .find(|a| a.process_instance_id.as_deref() == Some(ident.instance_id().as_str()))
            .expect("find alert")
            .alert_id
            .clone()
    };

    let alert_once_id = find_alert_id(id_once);
    let alert_signed_id = find_alert_id(id_signed);
    let alert_unsigned_id = find_alert_id(id_unsigned);
    let alert_evil_id = find_alert_id(id_evil);
    let alert_no_hash_id = find_alert_id(id_no_hash);

    // Transition signed alert to ExpiredSuspended to verify resolution works from ExpiredSuspended too.
    assert!(store
        .update_alert_status(&alert_signed_id, AlertStatus::ExpiredSuspended, None)
        .expect("mark expired"));

    let pipe_for_client = pipe_name.clone();
    let (r_once, r_dup, r_signed, r_unsigned, r_evil, r_no_hash) =
        tokio::task::spawn_blocking(move || {
            let r_once = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_once_id.clone(),
                    decision: AlertDecision::AllowOnce,
                },
            );
            let r_dup = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_once_id,
                    decision: AlertDecision::AllowOnce,
                },
            );
            let r_signed = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_signed_id,
                    decision: AlertDecision::AllowPermanent {
                        use_signer_if_available: true,
                        allow_dest: Some(r"C:\Users\alice\Documents\*".to_string()),
                    },
                },
            );
            let r_unsigned = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_unsigned_id,
                    decision: AlertDecision::AllowPermanent {
                        use_signer_if_available: true,
                        allow_dest: None,
                    },
                },
            );
            let r_evil = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_evil_id,
                    decision: AlertDecision::TerminateAndBlock {
                        add_block_rule: true,
                    },
                },
            );
            let r_no_hash = send_pipe_request(
                &pipe_for_client,
                &IpcRequest::ResolveAlert {
                    alert_id: alert_no_hash_id,
                    decision: AlertDecision::AllowPermanent {
                        use_signer_if_available: true,
                        allow_dest: None,
                    },
                },
            );
            (r_once, r_dup, r_signed, r_unsigned, r_evil, r_no_hash)
        })
        .await
        .expect("join IPC client");

    assert!(matches!(r_once, IpcResponse::Ack { .. }));
    assert!(matches!(
        r_dup,
        IpcResponse::Error { ref code, .. } if code == "ALREADY_RESOLVED"
    ));
    assert!(matches!(r_signed, IpcResponse::Ack { .. }));
    assert!(matches!(r_unsigned, IpcResponse::Ack { .. }));
    assert!(matches!(r_evil, IpcResponse::Ack { .. }));
    // Unsigned binary with no SHA-256 must NOT be allowed permanently (L-04).
    assert!(matches!(
        r_no_hash,
        IpcResponse::Error { ref code, .. } if code == "RESOLVE_ERROR"
    ));

    // Verify defense calls.
    assert_eq!(defense.resumes(), vec![id_once, id_signed, id_unsigned]);
    assert_eq!(
        defense.terminates(),
        vec![TerminateCall {
            target: id_evil,
            include_children: true,
        }]
    );

    // Verify persisted allow/block rules follow L-04 2-tier invariant.
    let allow_rules = store
        .list_rules(Some(RuleScope::FileCanaryAllow))
        .expect("list allow rules");
    assert_eq!(allow_rules.len(), 2);

    let signed_rule = allow_rules
        .iter()
        .find(|r| r.exe_path_pattern == signed_exe)
        .expect("signed rule");
    assert_eq!(signed_rule.signer_subject.as_deref(), Some(signed_subj));
    assert_eq!(signed_rule.root_thumbprint.as_deref(), Some(signed_tp));
    assert_eq!(signed_rule.sha256, None);
    assert_eq!(
        signed_rule.allowed_target.as_deref(),
        Some(r"C:\Users\alice\Documents\*")
    );

    let unsigned_rule = allow_rules
        .iter()
        .find(|r| r.exe_path_pattern == unsigned_exe)
        .expect("unsigned rule");
    assert_eq!(unsigned_rule.signer_subject, None);
    assert_eq!(unsigned_rule.root_thumbprint, None);
    assert_eq!(unsigned_rule.sha256.as_deref(), Some(unsigned_sha));

    let block_rules = store
        .list_rules(Some(RuleScope::NetworkBlock))
        .expect("list block rules");
    assert_eq!(block_rules.len(), 1);
    assert_eq!(block_rules[0].exe_path_pattern, evil_exe);
    assert_eq!(block_rules[0].sha256.as_deref(), Some(evil_sha));

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

#[test]
fn daemon_p2_05_session0_toast_launcher_fallback_and_validation() {
    let sample_alert = AlertRecord {
        alert_id: "toast-alert-001".to_string(),
        timestamp_ms: 1_750_000_000_000,
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Test Alert".to_string(),
        process_instance_id: Some("100:100".to_string()),
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json: "{}".to_string(),
        resolved_at_ms: None,
    };

    // 1. Missing binary logs warning and returns Ok(()) gracefully.
    let missing_launcher =
        Session0ToastLauncher::new(r"C:\NonExistent_LocalEDR_Test_Dir\ledr-ui.exe");
    assert!(missing_launcher.notify_alert(&sample_alert).is_ok());

    // 2. Empty/invalid alert_id is rejected cleanly.
    let bad_alert = AlertRecord {
        alert_id: "   ".to_string(),
        ..sample_alert.clone()
    };
    assert!(missing_launcher.notify_alert(&bad_alert).is_err());

    // 3. Existing binary spawns cleanly via foreground fallback with CREATE_NO_WINDOW.
    let harmless_exe = Path::new(r"C:\Windows\System32\hostname.exe");
    if harmless_exe.is_file() {
        let launcher = Session0ToastLauncher::new(harmless_exe);
        assert!(launcher.notify_alert(&sample_alert).is_ok());
    }
}

#[tokio::test]
async fn daemon_p2_06_named_pipe_sddl_and_caller_binary_verification() {
    assert_eq!(
        SERVICE_PIPE_SDDL,
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
    );

    // 1. SDDL security descriptor builds cleanly and exposes valid SECURITY_ATTRIBUTES.
    let sd = build_service_pipe_security_descriptor().expect("build SDDL security descriptor");
    assert!(sd.byte_len() > 0);
    let sa = sd.security_attributes();
    assert_eq!(
        sa.nLength as usize,
        std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>()
    );
    assert!(!sa.lpSecurityDescriptor.is_null());

    // 2. Start strict-DACL IPC server and verify round-trip + unauthorized rejection.
    let strict_pipe = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: strict_pipe.clone(),
            dev_mode_bypass_ui_auth: false,
            strict_pipe_dacl: true,
            ..DaemonConfig::default()
        },
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind strict SDDL Named Pipe");

    let pipe_client = strict_pipe.clone();
    let (ping_resp, unauth_resolve) = tokio::task::spawn_blocking(move || {
        let ping = send_pipe_request(&pipe_client, &IpcRequest::Ping);
        let unauth = send_pipe_request(
            &pipe_client,
            &IpcRequest::ResolveAlert {
                alert_id: "any-id".to_string(),
                decision: AlertDecision::AllowOnce,
            },
        );
        (ping, unauth)
    })
    .await
    .expect("join strict IPC client");

    assert!(matches!(ping_resp, IpcResponse::Pong { .. }));
    assert!(matches!(
        unauth_resolve,
        IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"
    ));

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");

    // 3. `verify_authorized_caller_binary` and `verify_caller_identity` checks (L-09).
    let tmp_dir = std::env::temp_dir().join(format!("ledr-caller-auth-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let fake_ui = tmp_dir.join("ledr-ui.exe");
    std::fs::write(&fake_ui, b"localedr-ui-test-payload").expect("write fake ui");
    let fake_ui_str = fake_ui.to_string_lossy().into_owned();
    let fake_ui_sha = compute_file_sha256_hex(&fake_ui).expect("hash fake ui");

    assert!(verify_authorized_caller_binary(
        Some(&fake_ui_str),
        &fake_ui_str,
        Some(&fake_ui_sha),
        None,
        None,
        false
    ));
    assert!(!verify_authorized_caller_binary(
        Some(&fake_ui_str),
        &fake_ui_str,
        Some(&"f".repeat(64)),
        None,
        None,
        false
    ));
    assert!(!verify_authorized_caller_binary(
        Some(r"C:\Temp\evil-ui.exe"),
        AUTHORIZED_UI_EXE_PATH,
        None,
        None,
        None,
        false
    ));
    assert!(verify_authorized_caller_binary(
        Some(r"C:\Temp\evil-ui.exe"),
        AUTHORIZED_UI_EXE_PATH,
        None,
        None,
        None,
        true
    ));

    let signed_caller = BinaryIdentity {
        exe_path: AUTHORIZED_UI_EXE_PATH.to_string(),
        sha256: Some(fake_ui_sha.clone()),
        authenticode: Some(AuthenticodeInfo {
            signer_subject: "CN=LocalEDR, O=LocalEDR Contributors".to_string(),
            root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
        }),
    };
    assert!(verify_caller_identity(
        Some(&signed_caller),
        &AUTHORIZED_UI_EXE_PATH.replace('\\', "/"),
        Some(&fake_ui_sha),
        Some("CN=LocalEDR"),
        Some("0123456789ABCDEF0123456789ABCDEF01234567"),
        false
    ));
    assert!(!verify_caller_identity(
        Some(&signed_caller),
        AUTHORIZED_UI_EXE_PATH,
        Some(&fake_ui_sha),
        Some("CN=LocalEDR"),
        Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        false
    ));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn daemon_p2_07_default_allowlist_does_not_bypass_canary_for_system32_lolbins() {
    let allowlist_json = include_str!("../../../rules/default_allowlist.json");
    let cfg = AllowlistConfig::from_json_str(allowlist_json).expect("parse default_allowlist.json");

    let store = LedrStore::open_in_memory().expect("open in-memory store");
    for rule in &cfg.allowlist_rules {
        store.upsert_rule(rule).expect("seed default rule");
    }

    let ms_auth = AuthenticodeInfo {
        signer_subject:
            "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
                .to_string(),
        root_thumbprint: "3B1EFD3A66EA28B16697394703A72CA340A05BD5".to_string(),
    };

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string();
    let search_exe = r"C:\Windows\System32\SearchIndexer.exe".to_string();

    let inspector = Arc::new(MockBinaryInspector::default());
    inspector.insert(BinaryIdentity {
        exe_path: ps_exe.clone(),
        sha256: Some("0000000000000000000000000000000000000000000000000000000000000001".to_string()),
        authenticode: Some(ms_auth.clone()),
    });
    inspector.insert(BinaryIdentity {
        exe_path: search_exe.clone(),
        sha256: Some("0000000000000000000000000000000000000000000000000000000000000002".to_string()),
        authenticode: Some(ms_auth),
    });

    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::new(cfg.early_pruner),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        inspector,
    );

    let t0 = current_unix_ms() - 5_000;
    let ps_ident = ProcessIdentity::new(5100, unix_ms_to_filetime(t0));
    let search_ident = ProcessIdentity::new(5200, unix_ms_to_filetime(t0 + 50));

    let sender = engine.sender();
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps_ident,
            parent_pid: 4,
            exe_path: ps_exe,
            command_line: "powershell.exe -c Get-Content Cookies".to_string(),
            user_sid: None,
        })
        .await
        .expect("send ps start");
    sender
        .send(SensorEvent::ProcessStart {
            identity: search_ident,
            parent_pid: 4,
            exe_path: search_exe,
            command_line: "SearchIndexer.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send search start");

    let cookie_path = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies";
    let honeypot_path = r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx";

    // SearchIndexer.exe has explicit `FileCanaryAllow` -> ALLOWED.
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: search_ident.pid,
            target_path: cookie_path.to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t0 + 200,
        })
        .await
        .expect("send search canary");

    // powershell.exe only matches `ALLOW-OS-WIN-SYS32` (`ProcessAllow`) -> MUST NOT bypass canary!
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: ps_ident.pid,
            target_path: cookie_path.to_string(),
            category: CanaryCategory::CookieDb,
            access_mask: 0x0012_0089,
            is_write_or_delete: false,
            timestamp_ms: t0 + 300,
        })
        .await
        .expect("send ps cookie");
    sender
        .send(SensorEvent::CanaryFileAccess {
            pid: ps_ident.pid,
            target_path: honeypot_path.to_string(),
            category: CanaryCategory::Honeypot,
            access_mask: 0x0012_0116,
            is_write_or_delete: true,
            timestamp_ms: t0 + 400,
        })
        .await
        .expect("send ps honeypot write");

    wait_for_hp_processed(&engine, 5).await;

    assert_eq!(
        defense.suspends(),
        vec![
            SuspendCall {
                target: ps_ident,
                include_children: false,
            },
            SuspendCall {
                target: ps_ident,
                include_children: true,
            },
        ]
    );
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 2);
    assert!(alerts
        .iter()
        .all(|a| a.process_instance_id.as_deref() == Some(ps_ident.instance_id().as_str())));
    assert_eq!(notifier.alerts().len(), 2);

    let snap = store.query_flight_recorder(20, None).expect("query fr");
    assert!(snap
        .file_canary_events
        .iter()
        .any(|e| e.process_instance_id == search_ident.instance_id() && e.action_taken == "ALLOWED"));
    assert_eq!(
        snap.file_canary_events
            .iter()
            .filter(|e| e.process_instance_id == ps_ident.instance_id()
                && e.action_taken == "SUSPENDED")
            .count(),
        2
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_08_terminate_and_block_exited_non_suspended_and_refusals() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let engine = DaemonEngine::start_with_controllers(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
    );

    let now_ms = current_unix_ms();
    // 1. Non-suspended alert whose short-lived process already exited (`OpenProcess` fails).
    let exited_alert = AlertRecord {
        alert_id: "alert-exited-lotl".to_string(),
        timestamp_ms: now_ms - 5_000,
        severity: AlertSeverity::High,
        source_layer: "LAYER_2_RULES".to_string(),
        rule_id: "LEDR-LOTL-001".to_string(),
        title: "Cmd Spawning Encoded PowerShell".to_string(),
        process_instance_id: Some("5500:133765432100000000".to_string()),
        process_suspended: false,
        status: AlertStatus::Pending,
        context_json: serde_json::json!({
            "exe_path": r"C:\Temp\short_lived.exe",
            "sha256": "abababababababababababababababababababababababababababababababab",
        })
        .to_string(),
        resolved_at_ms: None,
    };
    store.record_alert(&exited_alert).expect("record exited");

    defense.set_terminate_error(Some(
        "OpenProcess(PID 5500) failed: The parameter is incorrect.".to_string(),
    ));
    let resolved = engine
        .resolve_alert(
            &exited_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("non-suspended exited alert must still resolve and save block rule");
    assert_eq!(resolved.status, AlertStatus::TerminatedBlocked);
    assert!(resolved.resolved_at_ms.is_some());

    let block_rules = store
        .list_rules(Some(RuleScope::NetworkBlock))
        .expect("list block rules");
    assert_eq!(block_rules.len(), 1);
    assert_eq!(block_rules[0].exe_path_pattern, r"C:\Temp\short_lived.exe");

    // 2. Non-suspended alert where defense explicitly refuses a protected Never-Suspend process -> Err.
    let protected_alert = AlertRecord {
        alert_id: "alert-protected-non-susp".to_string(),
        process_instance_id: Some("5501:133765432100000001".to_string()),
        context_json: serde_json::json!({
            "exe_path": r"C:\Windows\explorer.exe",
        })
        .to_string(),
        ..exited_alert.clone()
    };
    store
        .record_alert(&protected_alert)
        .expect("record protected");
    defense.set_terminate_error(Some(
        r"refusing to act on protected process `C:\Windows\explorer.exe` (PID 5501)".to_string(),
    ));
    let refusal_err = engine
        .resolve_alert(
            &protected_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect_err("protected Never-Suspend refusal must remain an error");
    assert!(refusal_err.contains("refusing to act on protected process"));
    assert_eq!(
        store
            .get_alert(&protected_alert.alert_id)
            .expect("get alert")
            .expect("exists")
            .status,
        AlertStatus::Pending
    );

    // 3. Suspended alert where terminate_process fails -> still returns Err strictly.
    let suspended_alert = AlertRecord {
        alert_id: "alert-suspended-fail".to_string(),
        process_instance_id: Some("5502:133765432100000002".to_string()),
        process_suspended: true,
        ..exited_alert
    };
    store
        .record_alert(&suspended_alert)
        .expect("record suspended");
    defense.set_terminate_error(Some(
        "OpenProcess(PID 5502) failed: The parameter is incorrect.".to_string(),
    ));
    assert!(engine
        .resolve_alert(
            &suspended_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .is_err());

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_09_canary_burst_deduplicates_alerts_and_suspends() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MockBinaryInspector::default());

    let dropper_exe = r"C:\Temp\burst_locker.exe";
    inspector.insert(BinaryIdentity {
        exe_path: dropper_exe.to_string(),
        sha256: Some("fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe".to_string()),
        authenticode: None,
    });

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier.clone(),
        inspector,
    );

    let t0 = current_unix_ms() - 2_000;
    let ident = ProcessIdentity::new(6600, unix_ms_to_filetime(t0));
    let sender = engine.sender();

    sender
        .send(SensorEvent::ProcessStart {
            identity: ident,
            parent_pid: 4,
            exe_path: dropper_exe.to_string(),
            command_line: "burst_locker.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");

    // Simulate a Kernel-File burst (Create, CreateNewFile, Write) on the same honeypot path
    // with mixed slashes/casing.
    for (offset, path, mask) in [
        (
            10,
            r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
            0x0012_0116,
        ),
        (
            11,
            r"c:\users\alice\documents\!00_LocalEDR_Canary_DoNotEdit.docx",
            0x0012_0116,
        ),
        (
            12,
            "C:/Users/alice/Documents/!00_LocalEDR_Canary_DoNotEdit.docx",
            16,
        ),
    ] {
        sender
            .send(SensorEvent::CanaryFileAccess {
                pid: ident.pid,
                target_path: path.to_string(),
                category: CanaryCategory::Honeypot,
                access_mask: mask,
                is_write_or_delete: true,
                timestamp_ms: t0 + offset,
            })
            .await
            .expect("send burst canary");
    }

    wait_for_hp_processed(&engine, 4).await;

    assert_eq!(
        defense.suspends(),
        vec![SuspendCall {
            target: ident,
            include_children: true,
        }]
    );
    assert_eq!(store.list_alerts(None, 20).expect("list alerts").len(), 1);
    assert_eq!(notifier.alerts().len(), 1);

    let canary_rows = store
        .list_file_canary_events(Some(CanaryCategory::Honeypot), Some(&ident.instance_id()), 20)
        .expect("list canary events");
    assert_eq!(canary_rows.len(), 3);
    assert_eq!(
        canary_rows
            .iter()
            .filter(|r| r.action_taken == "SUSPENDED")
            .count(),
        1
    );
    assert_eq!(
        canary_rows
            .iter()
            .filter(|r| r.action_taken == "DEDUP_SUPPRESSED")
            .count(),
        2
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}
