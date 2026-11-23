//! Phase 2 integration tests for `ledr-daemon`: Canary containment (`L-02`, `L-06`, `L-07`),
//! 60s `EXPIRED_SUSPENDED` timeout, `ResolveAlert` 3 decisions (`L-04`, `L-07`), Session 0 toast
//! launcher fallback (`L-08`), and Named Pipe SDDL / caller verification (`L-09`)
//! (`DAEMON-P2-01`..`DAEMON-P2-30`; `DAEMON-P2-28` lives in unit tests).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    build_service_pipe_security_descriptor, canonical_sddl_trustee_for_sid,
    current_process_user_sid, read_kernel_object_dacl_sddl, start_ipc_server,
    verify_authorized_caller_binary, verify_caller_identity, BinaryInspector, DaemonConfig,
    DaemonEngine, NotificationDispatcher, Session0ToastLauncher, WindowsBinaryInspector,
    SERVICE_PIPE_SDDL,
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
        let mut opts = OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.access_mode(0x0012_019B);
        }
        match opts.open(pipe_name) {
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
    terminate_attempts: Mutex<Vec<TerminateCall>>,
    terminate_error: Mutex<Option<String>>,
    failing_suspend_pids: Mutex<Vec<u32>>,
    failing_terminate_pids: Mutex<Vec<u32>>,
    failing_resume_pids: Mutex<Vec<u32>>,
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

    fn terminate_attempts(&self) -> Vec<TerminateCall> {
        self.terminate_attempts
            .lock()
            .expect("lock terminate_attempts")
            .clone()
    }

    fn set_terminate_error(&self, err: Option<String>) {
        *self.terminate_error.lock().expect("lock terminate_error") = err;
    }

    fn add_failing_terminate_pid(&self, pid: u32) {
        self.failing_terminate_pids
            .lock()
            .expect("lock failing_terminate_pids")
            .push(pid);
    }

    fn add_failing_suspend_pid(&self, pid: u32) {
        self.failing_suspend_pids
            .lock()
            .expect("lock failing_suspend_pids")
            .push(pid);
    }

    fn add_failing_resume_pid(&self, pid: u32) {
        self.failing_resume_pids
            .lock()
            .expect("lock failing_resume_pids")
            .push(pid);
    }

    fn remove_failing_resume_pid(&self, pid: u32) {
        self.failing_resume_pids
            .lock()
            .expect("lock failing_resume_pids")
            .retain(|p| *p != pid);
    }
}

impl ActiveDefenseController for MockDefenseController {
    fn suspend_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        if self
            .failing_suspend_pids
            .lock()
            .expect("lock failing_suspend_pids")
            .contains(&target.pid)
        {
            return Err(format!(
                "OpenProcess(PID {}) failed: Access is denied.",
                target.pid
            ));
        }
        self.suspends.lock().expect("lock suspends").push(SuspendCall {
            target: *target,
            include_children,
        });
        Ok(())
    }

    fn resume_process(&self, target: &ProcessIdentity) -> Result<(), String> {
        if self
            .failing_resume_pids
            .lock()
            .expect("lock failing_resume_pids")
            .contains(&target.pid)
        {
            return Err(format!(
                "OpenProcess(PID {}) failed: The parameter is incorrect.",
                target.pid
            ));
        }
        self.resumes.lock().expect("lock resumes").push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        include_children: bool,
    ) -> Result<(), String> {
        self.terminate_attempts
            .lock()
            .expect("lock terminate_attempts")
            .push(TerminateCall {
                target: *target,
                include_children,
            });
        if let Some(err) = self
            .terminate_error
            .lock()
            .expect("lock terminate_error")
            .clone()
        {
            return Err(err);
        }
        if self
            .failing_terminate_pids
            .lock()
            .expect("lock failing_terminate_pids")
            .contains(&target.pid)
        {
            return Err(format!(
                "OpenProcess(PID {}) failed: The parameter is incorrect.",
                target.pid
            ));
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
    inspections: AtomicU64,
}

impl MockBinaryInspector {
    fn insert(&self, identity: BinaryIdentity) {
        self.entries
            .lock()
            .expect("lock inspector")
            .insert(identity.exe_path.to_ascii_lowercase(), identity);
    }

    fn inspections(&self) -> u64 {
        self.inspections.load(Ordering::Relaxed)
    }
}

impl BinaryInspector for MockBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        self.inspections.fetch_add(1, Ordering::Relaxed);
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

struct Phase2Harness {
    store: LedrStore,
    defense: Arc<MockDefenseController>,
    notifier: Arc<MockNotifier>,
    engine: Arc<DaemonEngine>,
}

fn default_test_config() -> DaemonConfig {
    DaemonConfig {
        pipe_name: unique_test_pipe_name(),
        ..DaemonConfig::default()
    }
}

fn start_harness() -> Phase2Harness {
    start_harness_with_config(default_test_config())
}

fn start_harness_with_config(config: DaemonConfig) -> Phase2Harness {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let engine = DaemonEngine::start_with_controllers(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        config,
        defense.clone(),
        notifier.clone(),
    );
    Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    }
}

fn start_harness_with_inspector(
    store: LedrStore,
    pruner: EarlyPruner,
    config: DaemonConfig,
    inspector: Arc<MockBinaryInspector>,
) -> Phase2Harness {
    let defense = Arc::new(MockDefenseController::default());
    let notifier = Arc::new(MockNotifier::default());
    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        pruner,
        config,
        defense.clone(),
        notifier.clone(),
        inspector,
    );
    Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    }
}

async fn send_process_start(
    engine: &DaemonEngine,
    identity: ProcessIdentity,
    parent_pid: u32,
    exe_path: &str,
    command_line: &str,
) {
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity,
            parent_pid,
            exe_path: exe_path.to_string(),
            command_line: command_line.to_string(),
            user_sid: None,
        })
        .await
        .expect("send ProcessStart");
}

async fn send_canary_access(
    engine: &DaemonEngine,
    pid: u32,
    target_path: &str,
    category: CanaryCategory,
    access_mask: u32,
    is_write_or_delete: bool,
    timestamp_ms: i64,
) {
    engine
        .sender()
        .send(SensorEvent::CanaryFileAccess {
            pid,
            target_path: target_path.to_string(),
            category,
            access_mask,
            is_write_or_delete,
            timestamp_ms,
        })
        .await
        .expect("send CanaryFileAccess");
}

fn make_alert_record(
    alert_id: &str,
    process_instance_id: Option<String>,
    context_json: String,
) -> AlertRecord {
    AlertRecord {
        alert_id: alert_id.to_string(),
        timestamp_ms: current_unix_ms(),
        severity: AlertSeverity::High,
        source_layer: "LAYER_1_CANARY".to_string(),
        rule_id: "LEDR-CANARY-SSH_KEY".to_string(),
        title: "canary".to_string(),
        process_instance_id,
        process_suspended: true,
        status: AlertStatus::Pending,
        context_json,
        resolved_at_ms: None,
    }
}

#[tokio::test]
async fn daemon_p2_01_honeypot_read_ignored_and_write_tree_suspends() {
    let inspector = Arc::new(MockBinaryInspector::default());

    let parent_exe = r"C:\Windows\explorer.exe".to_string();
    let locker_exe = r"C:\Temp\ransom_sim.exe".to_string();
    let locker_sha = "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    inspector.insert(BinaryIdentity {
        exe_path: locker_exe.clone(),
        sha256: Some(locker_sha.clone()),
        authenticode: None,
    });

    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness_with_inspector(
        LedrStore::open_in_memory().expect("open in-memory store"),
        EarlyPruner::default(),
        default_test_config(),
        inspector,
    );

    let t_base = current_unix_ms() - 5_000;
    let parent_ident = ProcessIdentity::new(1100, unix_ms_to_filetime(t_base));
    let locker_ident = ProcessIdentity::new(1200, unix_ms_to_filetime(t_base + 500));

    send_process_start(&engine, parent_ident, 4, &parent_exe, "explorer.exe").await;
    send_process_start(
        &engine,
        locker_ident,
        parent_ident.pid,
        &locker_exe,
        &format!("{locker_exe} --encrypt"),
    )
    .await;

    let honeypot_path = r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string();
    // 1. Read-only honeypot open MUST be ignored (L-06).
    send_canary_access(
        &engine,
        locker_ident.pid,
        &honeypot_path,
        CanaryCategory::Honeypot,
        0x0012_0089,
        false,
        t_base + 1_000,
    )
    .await;
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
    send_canary_access(
        &engine,
        locker_ident.pid,
        &honeypot_path,
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t_base + 1_500,
    )
    .await;
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

    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness_with_inspector(
        store,
        EarlyPruner::default(),
        default_test_config(),
        inspector,
    );

    let t_base = current_unix_ms() - 5_000;
    let chrome_ident = ProcessIdentity::new(2100, unix_ms_to_filetime(t_base));
    let explorer_ident = ProcessIdentity::new(2200, unix_ms_to_filetime(t_base + 100));
    let stealer_ident = ProcessIdentity::new(2300, unix_ms_to_filetime(t_base + 200));

    for (ident, exe) in [
        (chrome_ident, browser_exe.as_str()),
        (explorer_ident, r"C:\Windows\explorer.exe"),
        (stealer_ident, stealer_exe.as_str()),
    ] {
        send_process_start(&engine, ident, 4, exe, exe).await;
    }

    let cookie_path = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies";
    // 1. Allowlisted signed Chrome -> ALLOWED, no suspend, no alert.
    send_canary_access(
        &engine,
        chrome_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t_base + 500,
    )
    .await;

    // 2. Protected OS process `explorer.exe` -> NEVER suspended (`AUTO-02`), still recorded as ALERTED.
    send_canary_access(
        &engine,
        explorer_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t_base + 600,
    )
    .await;

    // 3. Unallowed stealer -> single-process suspend (`include_children: false`, L-07).
    send_canary_access(
        &engine,
        stealer_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t_base + 700,
    )
    .await;

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
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness_with_config(DaemonConfig {
        alert_timeout_ms: 60_000,
        ..default_test_config()
    });

    let base_ms = current_unix_ms();
    let overdue_alert = AlertRecord {
        timestamp_ms: base_ms - 65_000,
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Overdue Alert".to_string(),
        ..make_alert_record(
            "alert-overdue",
            Some("3100:1000".to_string()),
            "{}".to_string(),
        )
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
    let Phase2Harness {
        store: store2,
        defense: defense2,
        engine: engine2,
        ..
    } = start_harness_with_config(DaemonConfig {
        alert_timeout_ms: 80,
        ..default_test_config()
    });

    let ident = ProcessIdentity::new(3200, unix_ms_to_filetime(current_unix_ms() - 500));
    send_process_start(
        &engine2,
        ident,
        4,
        r"C:\Temp\slow_stealer.exe",
        "slow_stealer.exe",
    )
    .await;
    send_canary_access(
        &engine2,
        ident.pid,
        r"C:\Users\alice\.ssh\id_ed25519",
        CanaryCategory::SshKey,
        1,
        false,
        current_unix_ms() - 500,
    )
    .await;

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

    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness_with_inspector(
        LedrStore::open_in_memory().expect("open in-memory store"),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
        inspector,
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("start IPC");

    let t0 = current_unix_ms() - 10_000;
    let id_once = ProcessIdentity::new(4001, unix_ms_to_filetime(t0));
    let id_signed = ProcessIdentity::new(4002, unix_ms_to_filetime(t0 + 10));
    let id_unsigned = ProcessIdentity::new(4003, unix_ms_to_filetime(t0 + 20));
    let id_evil = ProcessIdentity::new(4004, unix_ms_to_filetime(t0 + 30));
    let id_no_hash = ProcessIdentity::new(4005, unix_ms_to_filetime(t0 + 40));

    for (ident, exe, target) in [
        (id_once, unsigned_exe, r"E:\dev\.env"),
        (id_signed, signed_exe, r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx"),
        (id_unsigned, unsigned_exe, r"E:\dev\.env.prod"),
        (id_evil, evil_exe, r"C:\Users\alice\.aws\credentials"),
        (id_no_hash, r"C:\NonExistent\no_hash.exe", r"C:\Users\alice\.ssh\id_rsa"),
    ] {
        send_process_start(&engine, ident, 4, exe, exe).await;
        send_canary_access(
            &engine,
            ident.pid,
            target,
            if target.contains("Canary") {
                CanaryCategory::Honeypot
            } else {
                CanaryCategory::EnvFile
            },
            2,
            true,
            t0 + 100,
        )
        .await;
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
        timestamp_ms: 1_750_000_000_000,
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Test Alert".to_string(),
        ..make_alert_record(
            "toast-alert-001",
            Some("100:100".to_string()),
            "{}".to_string(),
        )
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

    // 3. Existing binary spawns cleanly via foreground fallback with CREATE_NO_WINDOW when enabled outside Session 0.
    let harmless_exe = Path::new(r"C:\Windows\System32\hostname.exe");
    if harmless_exe.is_file() {
        let safe_default = Session0ToastLauncher::new(harmless_exe);
        assert!(!safe_default.allow_foreground_fallback());
        assert!(safe_default.notify_alert(&sample_alert).is_ok());

        let launcher = Session0ToastLauncher::with_foreground_fallback(harmless_exe, true);
        assert!(launcher.allow_foreground_fallback());
        assert!(launcher.notify_alert(&sample_alert).is_ok());
    }
}

#[tokio::test]
async fn daemon_p2_06_named_pipe_sddl_and_caller_binary_verification() {
    assert_eq!(
        SERVICE_PIPE_SDDL,
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019B;;;IU)"
    );

    // 1. SDDL security descriptor builds cleanly, converts back to SDDL, and omits FILE_CREATE_PIPE_INSTANCE (0x0004).
    let sd = build_service_pipe_security_descriptor().expect("build SDDL security descriptor");
    assert!(sd.byte_len() > 0);
    let sddl_roundtrip = sd.to_sddl_string().expect("convert SD back to SDDL");
    assert!(sddl_roundtrip.contains(";;;IU)"));
    assert!(!sddl_roundtrip.contains("GRGW"));
    assert!(!sddl_roundtrip.contains("FW"));
    let iu_ace = sddl_roundtrip
        .split('(')
        .find(|ace| ace.contains(";;;IU)"))
        .expect("IU ACE present in roundtrip SDDL");
    let iu_rights = iu_ace.split(';').nth(2).expect("IU ACE rights field");
    let hex_str = iu_rights
        .strip_prefix("0x")
        .or_else(|| iu_rights.strip_prefix("0X"))
        .unwrap_or_else(|| panic!("expected hex access mask in IU ACE, got {iu_ace}"));
    let mask = u32::from_str_radix(hex_str, 16).expect("parse IU hex access mask");
    assert_eq!(
        mask & 0x0004,
        0,
        "IU ACE must exclude FILE_CREATE_PIPE_INSTANCE (0x0004), got {iu_ace}"
    );
    assert_eq!(mask & 0x0012_019B, 0x0012_019B);
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
    let (
        ping_resp,
        unauth_resolve,
        metrics_resp,
        flight_resp,
        alerts_resp,
        rules_resp,
        risk_resp,
    ) = tokio::task::spawn_blocking(move || {
        let ping = send_pipe_request(&pipe_client, &IpcRequest::Ping);
        let unauth = send_pipe_request(
            &pipe_client,
            &IpcRequest::ResolveAlert {
                alert_id: "any-id".to_string(),
                decision: AlertDecision::AllowOnce,
            },
        );
        let metrics = send_pipe_request(&pipe_client, &IpcRequest::GetPipelineMetrics);
        let flight = send_pipe_request(
            &pipe_client,
            &IpcRequest::GetFlightRecorder {
                limit: 10,
                process_instance_id: None,
            },
        );
        let alerts = send_pipe_request(
            &pipe_client,
            &IpcRequest::GetAlerts {
                status: None,
                limit: 10,
            },
        );
        let rules = send_pipe_request(&pipe_client, &IpcRequest::ListRules { scope: None });
        let risk = send_pipe_request(
            &pipe_client,
            &IpcRequest::CheckDomainRisk {
                domain: "example.com".to_string(),
            },
        );
        (ping, unauth, metrics, flight, alerts, rules, risk)
    })
    .await
    .expect("join strict IPC client");

    assert!(matches!(ping_resp, IpcResponse::Pong { .. }));
    for (label, resp) in [
        ("ResolveAlert", unauth_resolve),
        ("GetPipelineMetrics", metrics_resp),
        ("GetFlightRecorder", flight_resp),
        ("GetAlerts", alerts_resp),
        ("ListRules", rules_resp),
        ("CheckDomainRisk", risk_resp),
    ] {
        assert!(
            matches!(resp, IpcResponse::Error { ref code, .. } if code == "UNAUTHORIZED"),
            "{label} must return UNAUTHORIZED when auth bypass is off, got {resp:?}"
        );
    }

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");

    // 3. `verify_authorized_caller_binary` and `verify_caller_identity` checks (L-09, SEC_0002, SEC_0006).
    let tmp_dir = std::env::temp_dir().join(format!("ledr-caller-auth-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let fake_ui = tmp_dir.join("ledr-ui.exe");
    std::fs::write(&fake_ui, b"localedr-ui-test-payload").expect("write fake ui");
    let fake_ui_str = fake_ui.to_string_lossy().into_owned();
    let fake_ui_sha = compute_file_sha256_hex(&fake_ui).expect("hash fake ui");

    let wrong_sha = "f".repeat(64);
    let signed_os_exe = Path::new(r"C:\Windows\System32\SearchIndexer.exe");
    let signed_os_str = signed_os_exe.to_string_lossy().into_owned();
    let binary_cases = vec![
        // SEC_0002: unpinned + unsigned binary MUST be rejected even on exact path match.
        (
            "unpinned unsigned exact path rejected",
            Some(fake_ui_str.as_str()),
            fake_ui_str.as_str(),
            None,
            false,
            false,
        ),
        // Pinned SHA-256 matches and succeeds.
        (
            "pinned sha256 matches",
            Some(fake_ui_str.as_str()),
            fake_ui_str.as_str(),
            Some(fake_ui_sha.as_str()),
            false,
            true,
        ),
        (
            "mismatched sha256 pin rejected",
            Some(fake_ui_str.as_str()),
            fake_ui_str.as_str(),
            Some(wrong_sha.as_str()),
            false,
            false,
        ),
        (
            "mismatched path rejected",
            Some(r"C:\Temp\evil-ui.exe"),
            AUTHORIZED_UI_EXE_PATH,
            None,
            false,
            false,
        ),
        (
            "dev bypass allows mismatched path",
            Some(r"C:\Temp\evil-ui.exe"),
            AUTHORIZED_UI_EXE_PATH,
            None,
            true,
            true,
        ),
    ];
    // Real Authenticode-signed Windows binary succeeds even without explicit hash/signer pins.
    if signed_os_exe.is_file() {
        let signed_os_identity = BinaryIdentity {
            exe_path: signed_os_str.clone(),
            sha256: compute_file_sha256_hex(signed_os_exe).ok(),
            authenticode: ledr_auth_helper::inspect_authenticode(signed_os_exe),
        };
        assert!(
            verify_caller_identity(
                Some(&signed_os_identity),
                &signed_os_str,
                None,
                None,
                None,
                false,
            ),
            "authenticode signed OS binary accepted without pins"
        );
    }
    for (case, caller, expected_path, sha_pin, dev_bypass, expected) in binary_cases {
        assert_eq!(
            verify_authorized_caller_binary(caller, expected_path, sha_pin, None, None, dev_bypass),
            expected,
            "{case}"
        );
    }

    let signed_caller = BinaryIdentity {
        exe_path: AUTHORIZED_UI_EXE_PATH.to_string(),
        sha256: Some(fake_ui_sha.clone()),
        authenticode: Some(AuthenticodeInfo {
            signer_subject: "CN=LocalEDR, O=LocalEDR Contributors".to_string(),
            root_thumbprint: "0123456789ABCDEF0123456789ABCDEF01234567".to_string(),
        }),
    };
    let forward_slash_path = AUTHORIZED_UI_EXE_PATH.replace('\\', "/");
    let identity_cases = [
        (
            "signed caller with matching pins and forward slashes",
            forward_slash_path.as_str(),
            Some(fake_ui_sha.as_str()),
            Some("CN=LocalEDR"),
            Some("0123456789ABCDEF0123456789ABCDEF01234567"),
            true,
        ),
        // Signed identity accepted without explicit pins (SEC_0002).
        (
            "signed identity accepted without explicit pins",
            AUTHORIZED_UI_EXE_PATH,
            None,
            None,
            None,
            true,
        ),
        // SEC_0006: all-zero or missing root thumbprint MUST be rejected when signer pin is used.
        (
            "all-zero root thumbprint rejected",
            AUTHORIZED_UI_EXE_PATH,
            Some(fake_ui_sha.as_str()),
            Some("CN=LocalEDR"),
            Some("0000000000000000000000000000000000000000"),
            false,
        ),
        (
            "missing root thumbprint with signer pin rejected",
            AUTHORIZED_UI_EXE_PATH,
            Some(fake_ui_sha.as_str()),
            Some("CN=LocalEDR"),
            None,
            false,
        ),
        (
            "mismatched root thumbprint rejected",
            AUTHORIZED_UI_EXE_PATH,
            Some(fake_ui_sha.as_str()),
            Some("CN=LocalEDR"),
            Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            false,
        ),
    ];
    for (case, expected_path, sha_pin, signer_pin, root_tp_pin, expected) in identity_cases {
        assert_eq!(
            verify_caller_identity(
                Some(&signed_caller),
                expected_path,
                sha_pin,
                signer_pin,
                root_tp_pin,
                false,
            ),
            expected,
            "{case}"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn ipc_dacl_01_dev_bypass_with_strict_pipe_dacl_allows_client_roundtrip() {
    let strict_pipe = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: strict_pipe.clone(),
            dev_mode_bypass_ui_auth: true,
            strict_pipe_dacl: true,
            ..DaemonConfig::default()
        },
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind strict SDDL Named Pipe");
    let current_sid = current_process_user_sid().expect("query current process user SID");

    let pipe_client = strict_pipe.clone();
    let (ping_resp, first_sddl, resolve_resp, second_sddl) = tokio::task::spawn_blocking(move || {
        use std::os::windows::io::AsHandle;

        // First connection inspects initial pipe instance DACL and sends Ping.
        let mut pipe1 = open_pipe_with_retry(&pipe_client);
        let dacl1 = read_kernel_object_dacl_sddl(pipe1.as_handle())
            .expect("read live DACL on initial dev-bypass pipe");
        write_ipc_frame(&mut pipe1, &IpcRequest::Ping).expect("write Ping");
        let ping = read_ipc_frame::<_, IpcResponse>(&mut pipe1).expect("read Pong");
        drop(pipe1);

        // Second connection exercises secondary instance / recreate_strict_pipe_with_retry
        // and verifies the recreated pipe retains the same dev-bypass DACL without IU.
        let mut pipe2 = open_pipe_with_retry(&pipe_client);
        let dacl2 = read_kernel_object_dacl_sddl(pipe2.as_handle())
            .expect("read live DACL on second dev-bypass pipe");
        write_ipc_frame(
            &mut pipe2,
            &IpcRequest::ResolveAlert {
                alert_id: "nonexistent-alert-id".to_string(),
                decision: AlertDecision::AllowOnce,
            },
        )
        .expect("write ResolveAlert");
        let resolve = read_ipc_frame::<_, IpcResponse>(&mut pipe2).expect("read ResolveAlert");
        (ping, dacl1, resolve, dacl2)
    })
    .await
    .expect("join strict IPC client under dev bypass");

    for (label, live_sddl) in [("initial", &first_sddl), ("second", &second_sddl)] {
        assert!(
            !live_sddl.contains(";;;IU)"),
            "{label} dev-bypass pipe DACL must omit Interactive Users (IU): {live_sddl}"
        );
        // On live Named Pipe kernel objects, Windows maps GENERIC_ALL (`GA`) to FILE_ALL_ACCESS (`FA`).
        let has_sy_full =
            live_sddl.contains("(A;;FA;;;SY)") || live_sddl.contains("(A;;GA;;;SY)");
        let has_ba_full =
            live_sddl.contains("(A;;FA;;;BA)") || live_sddl.contains("(A;;GA;;;BA)");
        assert!(
            has_sy_full && has_ba_full,
            "{label} dev-bypass pipe DACL must retain SY/BA full control: {live_sddl}"
        );
        if !current_sid.eq_ignore_ascii_case("S-1-5-18") {
            let expected_trustee = canonical_sddl_trustee_for_sid(&current_sid)
                .expect("canonicalize current process user SID");
            assert_ne!(
                expected_trustee, "IU",
                "{label} dev-bypass pipe DACL must never map current user to IU"
            );
            assert_eq!(
                live_sddl.matches('(').count(),
                3,
                "{label} dev-bypass pipe DACL must have exactly 3 ACEs (SY, BA, current user): {live_sddl}"
            );
            let expected_suffix = format!(";;;{expected_trustee})");
            let user_ace = live_sddl
                .split('(')
                .find(|ace| ace.contains(&expected_suffix))
                .unwrap_or_else(|| {
                    panic!(
                        "{label} dev-bypass pipe DACL missing current user trustee {expected_trustee} (SID {current_sid}): {live_sddl}"
                    )
                });
            let rights = user_ace.split(';').nth(2).expect("user ACE rights");
            let hex = rights
                .strip_prefix("0x")
                .or_else(|| rights.strip_prefix("0X"))
                .unwrap_or_else(|| panic!("expected hex rights mask in {user_ace}"));
            let mask = u32::from_str_radix(hex, 16).expect("parse hex rights mask");
            assert_eq!(mask & 0x0004, 0, "must exclude FILE_CREATE_PIPE_INSTANCE");
            assert_eq!(mask & 0x0012_019B, 0x0012_019B);
        }
    }

    assert!(matches!(ping_resp, IpcResponse::Pong { .. }));
    assert!(
        matches!(
            resolve_resp,
            IpcResponse::Error { ref code, .. } if code == "NOT_FOUND"
        ),
        "expected NOT_FOUND (not UNAUTHORIZED) when dev_mode_bypass_ui_auth=true & strict_pipe_dacl=true, got {resolve_resp:?}"
    );

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
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
    let chrome_auth = AuthenticodeInfo {
        signer_subject: "CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US"
            .to_string(),
        root_thumbprint: "DDFB16CD4931C973A2037D3FC83A4D7D775D05E4".to_string(),
    };

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".to_string();
    let search_exe = r"C:\Windows\System32\SearchIndexer.exe".to_string();
    let chrome_exe = r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string();

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
    inspector.insert(BinaryIdentity {
        exe_path: chrome_exe.clone(),
        sha256: Some("0000000000000000000000000000000000000000000000000000000000000003".to_string()),
        authenticode: Some(chrome_auth),
    });

    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness_with_inspector(
        store,
        EarlyPruner::new(cfg.early_pruner),
        default_test_config(),
        inspector,
    );

    let t0 = current_unix_ms() - 5_000;
    let ps_ident = ProcessIdentity::new(5100, unix_ms_to_filetime(t0));
    let search_ident = ProcessIdentity::new(5200, unix_ms_to_filetime(t0 + 50));
    let chrome_ident = ProcessIdentity::new(5300, unix_ms_to_filetime(t0 + 100));

    send_process_start(
        &engine,
        ps_ident,
        4,
        &ps_exe,
        "powershell.exe -c Get-Content Cookies",
    )
    .await;
    send_process_start(&engine, search_ident, 4, &search_exe, "SearchIndexer.exe").await;
    send_process_start(&engine, chrome_ident, 4, &chrome_exe, "chrome.exe").await;

    let cookie_path = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies";
    let honeypot_path = r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx";

    // Chrome accessing its own Cookies has explicit `ALLOW-BROWSER-CHROME` -> ALLOWED (BUG_0002).
    send_canary_access(
        &engine,
        chrome_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t0 + 150,
    )
    .await;

    // SearchIndexer.exe has explicit `FileCanaryAllow` -> ALLOWED.
    send_canary_access(
        &engine,
        search_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t0 + 200,
    )
    .await;

    // powershell.exe only matches `ALLOW-OS-WIN-SYS32` (`ProcessAllow`) -> MUST NOT bypass canary!
    send_canary_access(
        &engine,
        ps_ident.pid,
        cookie_path,
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t0 + 300,
    )
    .await;
    send_canary_access(
        &engine,
        ps_ident.pid,
        honeypot_path,
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t0 + 400,
    )
    .await;

    wait_for_hp_processed(&engine, 7).await;

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
        .any(|e| e.process_instance_id == chrome_ident.instance_id() && e.action_taken == "ALLOWED"));
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
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let now_ms = current_unix_ms();
    // 1. Non-suspended alert whose short-lived process already exited (`OpenProcess` fails).
    let exited_alert = AlertRecord {
        timestamp_ms: now_ms - 5_000,
        source_layer: "LAYER_2_RULES".to_string(),
        rule_id: "LEDR-LOTL-001".to_string(),
        title: "Cmd Spawning Encoded PowerShell".to_string(),
        process_suspended: false,
        ..make_alert_record(
            "alert-exited-lotl",
            Some("5500:133765432100000000".to_string()),
            serde_json::json!({
                "exe_path": r"C:\Temp\short_lived.exe",
                "sha256": "abababababababababababababababababababababababababababababababab",
            })
            .to_string(),
        )
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

    // 3. Suspended alert where terminate_process fails on a still-running process
    //    (this test binary) -> still returns Err strictly. A gone/replaced target is
    //    tolerated instead so a retry can re-save the block rule (`BUG_0001`).
    let live_ident = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(now_ms - 1_000),
    );
    let suspended_alert = AlertRecord {
        alert_id: "alert-suspended-fail".to_string(),
        process_instance_id: Some(live_ident.instance_id()),
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
    let inspector = Arc::new(MockBinaryInspector::default());

    let dropper_exe = r"C:\Temp\burst_locker.exe";
    inspector.insert(BinaryIdentity {
        exe_path: dropper_exe.to_string(),
        sha256: Some("fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe".to_string()),
        authenticode: None,
    });

    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness_with_inspector(
        LedrStore::open_in_memory().expect("open in-memory store"),
        EarlyPruner::default(),
        default_test_config(),
        inspector,
    );

    let t0 = current_unix_ms() - 2_000;
    let ident = ProcessIdentity::new(6600, unix_ms_to_filetime(t0));

    send_process_start(&engine, ident, 4, dropper_exe, "burst_locker.exe").await;

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
        send_canary_access(
            &engine,
            ident.pid,
            path,
            CanaryCategory::Honeypot,
            mask,
            true,
            t0 + offset,
        )
        .await;
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

#[tokio::test]
async fn daemon_p2_10_bug_0001_zero_or_missing_create_time_never_suspends() {
    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness();

    let now_ms = current_unix_ms();

    // 1. Unknown PID (not in ActiveProcessTable -> proc_identity = None): must alert without suspending.
    send_canary_access(
        &engine,
        7701,
        r"C:\Users\alice\.ssh\id_rsa",
        CanaryCategory::SshKey,
        1,
        false,
        now_ms - 200,
    )
    .await;

    // 2. Process with create_time_100ns == 0: must NEVER suspend (BUG_0001).
    let zero_ident = ProcessIdentity::new(7702, 0);
    send_process_start(&engine, zero_ident, 4, r"C:\Temp\zero_ts.exe", "zero_ts.exe").await;
    wait_for_hp_processed(&engine, 2).await;
    send_canary_access(
        &engine,
        zero_ident.pid,
        r"C:\Users\alice\.aws\credentials",
        CanaryCategory::CloudCredential,
        1,
        false,
        current_unix_ms() + 100,
    )
    .await;

    wait_for_hp_processed(&engine, 3).await;

    assert!(
        defense.suspends().is_empty(),
        "BUG_0001: processes without non-zero create_time_100ns must never be suspended"
    );
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().all(|a| !a.process_suspended));
    assert_eq!(notifier.alerts().len(), 2);

    let snap = store.query_flight_recorder(20, None).expect("query fr");
    assert_eq!(snap.file_canary_events.len(), 2);
    assert!(snap
        .file_canary_events
        .iter()
        .all(|e| e.action_taken == "ALERTED"));

    // Resolving a non-suspended alert with missing/zero identity succeeds without touching defense.
    let zero_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some("7702:0"))
        .expect("zero alert");
    let resolved = engine
        .resolve_alert(&zero_alert.alert_id, AlertDecision::AllowOnce)
        .expect("resolve non-suspended zero-ts alert");
    assert_eq!(resolved.status, AlertStatus::ApprovedOnce);
    assert!(defense.resumes().is_empty());

    // Manually forged suspended alert with pid:0 + context pid fallback must be rejected in resolve_alert.
    let forged_suspended = AlertRecord {
        timestamp_ms: now_ms,
        title: "Forged Zero Identity".to_string(),
        ..make_alert_record(
            "forged-zero-suspended",
            Some("7703:0".to_string()),
            serde_json::json!({ "pid": 7703 }).to_string(),
        )
    };
    store.record_alert(&forged_suspended).expect("record forged");
    assert!(engine
        .resolve_alert(
            &forged_suspended.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false
            }
        )
        .is_err());
    assert!(defense.terminates().is_empty());

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_11_bug_0003_sibling_alerts_keep_suspended_until_last_allowed_and_cascade_terminate()
{
    let inspector = Arc::new(MockBinaryInspector::default());

    let proc_a_exe = r"C:\Temp\multi_stealer_a.exe".to_string();
    let proc_b_exe = r"C:\Temp\multi_stealer_b.exe".to_string();
    for exe in [&proc_a_exe, &proc_b_exe] {
        inspector.insert(BinaryIdentity {
            exe_path: exe.clone(),
            sha256: Some("1212121212121212121212121212121212121212121212121212121212121212".to_string()),
            authenticode: None,
        });
    }

    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness_with_inspector(
        LedrStore::open_in_memory().expect("open in-memory store"),
        EarlyPruner::default(),
        default_test_config(),
        inspector,
    );

    let t0 = current_unix_ms() - 5_000;
    let ident_a = ProcessIdentity::new(7801, unix_ms_to_filetime(t0));
    let ident_b = ProcessIdentity::new(7802, unix_ms_to_filetime(t0 + 10));

    for (ident, exe) in [(ident_a, &proc_a_exe), (ident_b, &proc_b_exe)] {
        send_process_start(&engine, ident, 4, exe, exe).await;
        send_canary_access(
            &engine,
            ident.pid,
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
            CanaryCategory::CookieDb,
            1,
            false,
            t0 + 100,
        )
        .await;
        send_canary_access(
            &engine,
            ident.pid,
            r"C:\Users\alice\.ssh\id_rsa",
            CanaryCategory::SshKey,
            1,
            false,
            t0 + 110,
        )
        .await;
    }

    wait_for_hp_processed(&engine, 6).await;
    let all_alerts = store.list_alerts(None, 20).expect("list alerts");
    let a_alerts: Vec<_> = all_alerts
        .iter()
        .filter(|a| a.process_instance_id.as_deref() == Some(ident_a.instance_id().as_str()))
        .collect();
    let b_alerts: Vec<_> = all_alerts
        .iter()
        .filter(|a| a.process_instance_id.as_deref() == Some(ident_b.instance_id().as_str()))
        .collect();
    assert_eq!(a_alerts.len(), 2);
    assert_eq!(b_alerts.len(), 2);

    // Part A: Resolving first alert for proc A keeps it suspended while second alert is unresolved.
    let res_a1 = engine
        .resolve_alert(&a_alerts[0].alert_id, AlertDecision::AllowOnce)
        .expect("resolve first A alert");
    assert_eq!(res_a1.status, AlertStatus::ApprovedOnce);
    assert!(
        defense.resumes().is_empty(),
        "BUG_0003: process must stay suspended while sibling unresolved suspended alert exists"
    );

    // Resolving the last unresolved suspended alert for proc A resumes it.
    let res_a2 = engine
        .resolve_alert(
            &a_alerts[1].alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect("resolve second A alert");
    assert_eq!(res_a2.status, AlertStatus::ApprovedRule);
    assert_eq!(defense.resumes(), vec![ident_a]);

    // Part B: TerminateAndBlock on one alert for proc B cascades TerminatedBlocked to sibling alert.
    let res_b1 = engine
        .resolve_alert(
            &b_alerts[0].alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("terminate proc B");
    assert_eq!(res_b1.status, AlertStatus::TerminatedBlocked);
    let sibling_b2 = store
        .get_alert(&b_alerts[1].alert_id)
        .expect("get sibling alert")
        .expect("sibling exists");
    assert_eq!(sibling_b2.status, AlertStatus::TerminatedBlocked);
    assert!(sibling_b2.resolved_at_ms.is_some());

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_12_bug_0004_record_alert_error_compensates_suspension_dedup_and_skips_notify() {
    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let parent_ident = ProcessIdentity::new(7901, unix_ms_to_filetime(t0));
    let child_ident = ProcessIdentity::new(7902, unix_ms_to_filetime(t0 + 50));
    let honeypot_path = r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx".to_string();

    send_process_start(
        &engine,
        parent_ident,
        4,
        r"C:\Temp\comp_parent.exe",
        "comp_parent.exe",
    )
    .await;
    send_process_start(
        &engine,
        child_ident,
        parent_ident.pid,
        r"C:\Temp\comp_child.exe",
        "comp_child.exe",
    )
    .await;
    wait_for_hp_processed(&engine, 2).await;

    // Force record_alert to fail on the next canary alert.
    engine.set_fail_record_alert_for_test(true);
    send_canary_access(
        &engine,
        parent_ident.pid,
        &honeypot_path,
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t0 + 200,
    )
    .await;
    wait_for_hp_processed(&engine, 3).await;

    // Suspension was triggered then compensated (parent + child resumed), no toast sent, no alert persisted.
    // The child also gets a per-descendant suspend_process confirmation call (BUG_0002).
    assert_eq!(
        defense.suspends(),
        vec![
            SuspendCall {
                target: parent_ident,
                include_children: true,
            },
            SuspendCall {
                target: child_ident,
                include_children: false,
            }
        ]
    );
    assert_eq!(defense.resumes(), vec![parent_ident, child_ident]);
    assert!(notifier.alerts().is_empty());
    assert!(store.list_alerts(None, 20).expect("list alerts").is_empty());
    assert_eq!(engine.alerts_emitted(), 0);

    let snap = store.query_flight_recorder(20, None).expect("query fr");
    assert_eq!(snap.file_canary_events.len(), 1);
    assert_eq!(snap.file_canary_events[0].action_taken, "ALERTED");

    // Re-enabling alert recording must NOT be suppressed by stale dedup state.
    engine.set_fail_record_alert_for_test(false);
    send_canary_access(
        &engine,
        parent_ident.pid,
        &honeypot_path,
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t0 + 300,
    )
    .await;
    wait_for_hp_processed(&engine, 4).await;

    assert_eq!(defense.suspends().len(), 4);
    assert_eq!(store.list_alerts(None, 20).expect("list alerts").len(), 1);
    assert_eq!(notifier.alerts().len(), 1);

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_13_bug_0005_honeypot_tracks_suspended_children_and_resolves_tree() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let parent_ident = ProcessIdentity::new(8001, unix_ms_to_filetime(t0));
    let child_ident = ProcessIdentity::new(8002, unix_ms_to_filetime(t0 + 20));
    let grandchild_ident = ProcessIdentity::new(8003, unix_ms_to_filetime(t0 + 40));

    for (ident, ppid, exe) in [
        (parent_ident, 4, r"C:\Temp\tree_root.exe"),
        (child_ident, parent_ident.pid, r"C:\Temp\tree_child.exe"),
        (grandchild_ident, child_ident.pid, r"C:\Temp\tree_grand.exe"),
    ] {
        send_process_start(&engine, ident, ppid, exe, exe).await;
    }
    send_canary_access(
        &engine,
        parent_ident.pid,
        r"C:\Users\alice\Desktop\!00_LocalEDR_Canary_DoNotEdit.docx",
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t0 + 100,
    )
    .await;
    wait_for_hp_processed(&engine, 4).await;

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    let ctx: serde_json::Value =
        serde_json::from_str(&alerts[0].context_json).expect("parse alert context");
    let children_json = ctx["suspended_children"]
        .as_array()
        .expect("suspended_children array recorded");
    let expected_ids = vec![
        serde_json::Value::String(child_ident.instance_id()),
        serde_json::Value::String(grandchild_ident.instance_id()),
    ];
    assert_eq!(children_json, &expected_ids);

    // Mark grandchild as already exited during AllowOnce resume; parent + child resume and alert resolves cleanly.
    defense.add_failing_resume_pid(grandchild_ident.pid);
    let resumed = engine
        .resolve_alert(&alerts[0].alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce must succeed even if child already exited");
    assert_eq!(resumed.status, AlertStatus::ApprovedOnce);
    assert_eq!(defense.resumes(), vec![parent_ident, child_ident]);

    // Also test TerminateAndBlock terminating parent + tracked children while ignoring already-exited child.
    defense.add_failing_terminate_pid(child_ident.pid);
    let term_alert = AlertRecord {
        timestamp_ms: t0 + 200,
        severity: AlertSeverity::Critical,
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        title: "Honeypot Tree Terminate".to_string(),
        ..make_alert_record(
            "tree-terminate-alert",
            Some(parent_ident.instance_id()),
            serde_json::json!({
                "exe_path": r"C:\Temp\tree_root.exe",
                "suspended_children": [child_ident.instance_id(), grandchild_ident.instance_id(), "9999:0"],
            })
            .to_string(),
        )
    };
    store.record_alert(&term_alert).expect("record term alert");
    let terminated = engine
        .resolve_alert(
            &term_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("TerminateAndBlock must succeed when child already exited");
    assert_eq!(terminated.status, AlertStatus::TerminatedBlocked);
    assert_eq!(
        defense.terminates(),
        vec![
            TerminateCall {
                target: parent_ident,
                include_children: true,
            },
            TerminateCall {
                target: grandchild_ident,
                include_children: true,
            },
        ]
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_14_bug_0006_allow_once_clears_canary_dedup_for_reevaluation() {
    let Phase2Harness {
        store,
        defense,
        notifier,
        engine,
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let ident = ProcessIdentity::new(8101, unix_ms_to_filetime(t0));
    let target = r"C:\Users\alice\.ssh\id_ed25519";

    send_process_start(
        &engine,
        ident,
        4,
        r"C:\Temp\retry_stealer.exe",
        "retry_stealer.exe",
    )
    .await;

    // 1. First access triggers alert #1 + suspension; immediate duplicate is suppressed.
    for offset in [100i64, 110] {
        send_canary_access(
            &engine,
            ident.pid,
            target,
            CanaryCategory::SshKey,
            1,
            false,
            t0 + offset,
        )
        .await;
    }
    wait_for_hp_processed(&engine, 3).await;
    let initial_alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(initial_alerts.len(), 1);
    assert_eq!(defense.suspends().len(), 1);

    // 2. AllowOnce clears dedup key so subsequent access to the same target re-evaluates.
    engine
        .resolve_alert(&initial_alerts[0].alert_id, AlertDecision::AllowOnce)
        .expect("resolve AllowOnce");
    assert_eq!(defense.resumes(), vec![ident]);

    send_canary_access(
        &engine,
        ident.pid,
        target,
        CanaryCategory::SshKey,
        1,
        false,
        t0 + 500,
    )
    .await;
    wait_for_hp_processed(&engine, 4).await;

    let final_alerts = store.list_alerts(None, 20).expect("list final alerts");
    assert_eq!(final_alerts.len(), 2);
    assert_eq!(defense.suspends().len(), 2);
    assert_eq!(notifier.alerts().len(), 2);

    engine.shutdown_and_flush().await.expect("shutdown");
}

#[test]
fn daemon_p2_15_sec_0004_session0_blocks_foreground_fallback() {
    let tmp_dir = std::env::temp_dir().join(format!("ledr-sec0004-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    // A non-PE file on disk: if spawn_foreground_fallback runs, Command::spawn fails with Err;
    // when blocked by SEC_0004 guards, notify_alert_with_session returns Ok(()) without spawning.
    let invalid_pe = tmp_dir.join("not-a-pe-ledr-ui.exe");
    std::fs::write(&invalid_pe, b"not-a-valid-pe-executable").expect("write marker file");

    let alert = AlertRecord {
        timestamp_ms: 1_750_000_000_000,
        rule_id: "LEDR-CANARY-COOKIE_DB".to_string(),
        title: "Session 0 Guard Test".to_string(),
        ..make_alert_record(
            "sec-0004-toast",
            Some("100:100".to_string()),
            "{}".to_string(),
        )
    };

    // 1. When allow_foreground_fallback is false, Session 1 also skips fallback safely.
    let disabled_launcher = Session0ToastLauncher::with_foreground_fallback(&invalid_pe, false);
    assert!(disabled_launcher
        .notify_alert_with_session(&alert, Ok(1))
        .is_ok());

    // 2. Even when allow_foreground_fallback is true, Session 0 MUST NEVER spawn foreground fallback.
    let enabled_launcher = Session0ToastLauncher::with_foreground_fallback(&invalid_pe, true);
    assert!(enabled_launcher
        .notify_alert_with_session(&alert, Ok(0))
        .is_ok());

    // 3. Session query failure also fails closed without spawning fallback.
    assert!(enabled_launcher
        .notify_alert_with_session(&alert, Err("ProcessIdToSessionId failed".to_string()))
        .is_ok());

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn daemon_p2_16_sec_0005_binary_inspector_detects_same_size_and_mtime_replacement() {
    let tmp_dir = std::env::temp_dir().join(format!("ledr-sec0005-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    let target = tmp_dir.join("swapped_tool.exe");

    let payload_a = vec![0x41u8; 256];
    let payload_b = vec![0x42u8; 256];
    std::fs::write(&target, &payload_a).expect("write payload A");
    let orig_mtime = std::fs::metadata(&target)
        .expect("meta A")
        .modified()
        .expect("mtime A");

    let inspector = WindowsBinaryInspector::new();
    let target_str = target.to_string_lossy().into_owned();
    let first = inspector.inspect(&target_str);
    let expected_sha_a = compute_file_sha256_hex(&target).expect("hash A");
    assert_eq!(first.sha256.as_deref(), Some(expected_sha_a.as_str()));

    // Replace binary in-place with identical length AND restore exact original mtime.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&target)
            .expect("reopen for replace");
        std::io::Write::write_all(&mut f, &payload_b).expect("write payload B");
        f.set_modified(orig_mtime).expect("preserve mtime");
    }
    let meta_b = std::fs::metadata(&target).expect("meta B");
    assert_eq!(meta_b.len(), 256);
    assert_eq!(meta_b.modified().expect("mtime B"), orig_mtime);

    let second = inspector.inspect(&target_str);
    let expected_sha_b = compute_file_sha256_hex(&target).expect("hash B");
    assert_ne!(expected_sha_a, expected_sha_b);
    assert_eq!(second.sha256.as_deref(), Some(expected_sha_b.as_str()));

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[tokio::test]
async fn daemon_p2_17_sec_0003_strict_pipe_isolates_malformed_and_timed_out_clients() {
    use std::io::{Read, Write};

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
            ipc_frame_timeout_ms: 80,
            ..DaemonConfig::default()
        },
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind strict SDDL Named Pipe");

    let pipe_for_clients = strict_pipe.clone();
    let (empty_err_code, pong_after_empty, stalled_eof, pong_after_timeout) =
        tokio::task::spawn_blocking(move || {
            // 1. Client 1 sends EMPTY_FRAME (0x0000_0000) + trailing garbage bytes in the same write.
            let empty_err_code = {
                let mut c1 = open_pipe_with_retry(&pipe_for_clients);
                c1.write_all(&[0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF, b'b', b'a', b'd'])
                    .expect("write EMPTY_FRAME + trailing garbage");
                c1.flush().expect("flush EMPTY_FRAME");
                match read_ipc_frame::<_, IpcResponse>(&mut c1).expect("read EMPTY_FRAME error") {
                    IpcResponse::Error { code, .. } => code,
                    other => panic!("expected Error response, got {other:?}"),
                }
            };

            // 2. Client 2 connects after Client 1 drops and must receive a clean Pong (no byte leak).
            let pong_after_empty = send_pipe_request(&pipe_for_clients, &IpcRequest::Ping);

            // 3. Client 1b stalls mid-frame past ipc_frame_timeout_ms (80ms).
            let stalled_eof = {
                let mut c1b = open_pipe_with_retry(&pipe_for_clients);
                c1b.write_all(&[0x20, 0x00]).expect("write partial header");
                c1b.flush().expect("flush partial header");
                std::thread::sleep(Duration::from_millis(160));
                let mut probe = [0u8; 8];
                matches!(c1b.read(&mut probe), Ok(0) | Err(_))
            };

            // 4. Client 2b must still connect and receive a clean Pong (no ERROR_OPERATION_ABORTED).
            let pong_after_timeout = send_pipe_request(&pipe_for_clients, &IpcRequest::Ping);

            (empty_err_code, pong_after_empty, stalled_eof, pong_after_timeout)
        })
        .await
        .expect("join strict pipe isolation clients");

    assert_eq!(empty_err_code, "EMPTY_FRAME");
    assert!(matches!(pong_after_empty, IpcResponse::Pong { .. }));
    assert!(stalled_eof, "stalled client must be disconnected on timeout");
    assert!(matches!(pong_after_timeout, IpcResponse::Pong { .. }));

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

#[tokio::test]
async fn daemon_p2_18_bug_0003_bug_0005_honeypot_sibling_resumes_children_on_last_resolve() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let parent_ident = ProcessIdentity::new(8201, unix_ms_to_filetime(t0));
    let child_ident = ProcessIdentity::new(8202, unix_ms_to_filetime(t0 + 20));

    for (ident, ppid, exe) in [
        (parent_ident, 4, r"C:\Temp\combo_root.exe"),
        (child_ident, parent_ident.pid, r"C:\Temp\combo_child.exe"),
    ] {
        send_process_start(&engine, ident, ppid, exe, exe).await;
    }

    send_canary_access(
        &engine,
        parent_ident.pid,
        r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
        CanaryCategory::Honeypot,
        0x0012_0116,
        true,
        t0 + 100,
    )
    .await;
    send_canary_access(
        &engine,
        parent_ident.pid,
        r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Cookies",
        CanaryCategory::CookieDb,
        0x0012_0089,
        false,
        t0 + 110,
    )
    .await;

    wait_for_hp_processed(&engine, 4).await;
    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 2);

    let honeypot_alert = alerts
        .iter()
        .find(|a| a.rule_id == "LEDR-CANARY-HONEYPOT")
        .expect("honeypot alert");
    let cookie_alert = alerts
        .iter()
        .find(|a| a.rule_id == "LEDR-CANARY-COOKIE_DB")
        .expect("cookie alert");

    // Resolve Honeypot alert first: parent and child stay suspended because CookieDb sibling is pending.
    engine
        .resolve_alert(&honeypot_alert.alert_id, AlertDecision::AllowOnce)
        .expect("resolve honeypot first");
    assert!(defense.resumes().is_empty());

    // Resolve CookieDb sibling last: must resume BOTH parent AND the honeypot's child.
    engine
        .resolve_alert(&cookie_alert.alert_id, AlertDecision::AllowOnce)
        .expect("resolve cookie last");
    assert_eq!(defense.resumes(), vec![parent_ident, child_ident]);

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-19` (`ANALYSIS_0001`): `resolve_alert_with_outcome` must report whether the
/// requested NetworkBlock rule was actually persisted, so callers cannot claim a rule was
/// saved when `exe_path` was unresolved.
#[tokio::test]
async fn daemon_p2_19_analysis_0001_resolve_outcome_reports_block_rule_saved() {
    let store = LedrStore::open_in_memory().expect("open in-memory store");
    let engine = DaemonEngine::start(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
    );

    let make_pending = |alert_id: &str, ctx: serde_json::Value| AlertRecord {
        severity: AlertSeverity::Critical,
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        process_suspended: false,
        ..make_alert_record(alert_id, None, ctx.to_string())
    };

    // Case A: no resolvable exe_path -> alert resolves but no block rule is saved.
    let a = make_pending("no-exe-path", serde_json::json!({}));
    store.record_alert(&a).expect("record alert a");
    let outcome_a = engine
        .resolve_alert_with_outcome(
            &a.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("resolve alert a");
    assert_eq!(outcome_a.alert.status, AlertStatus::TerminatedBlocked);
    assert_eq!(
        outcome_a.saved_rule_id, None,
        "block rule must not be reported saved without an exe path"
    );

    // Case B: exe_path in context -> block rule saved and its id is reported.
    let b = make_pending(
        "with-exe-path",
        serde_json::json!({ "exe_path": r"C:\Temp\evil.exe" }),
    );
    store.record_alert(&b).expect("record alert b");
    let outcome_b = engine
        .resolve_alert_with_outcome(
            &b.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("resolve alert b");
    let rule_id = outcome_b
        .saved_rule_id
        .expect("block rule id must be reported");
    assert!(rule_id.starts_with("RULE-BLOCK-"));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-20` (`ANALYSIS_0002`): repeated canary events for the same
/// (process, category, target) must be dedup-suppressed BEFORE the binary inspection so
/// a burst does not re-read the executable on the high-priority lane.
#[tokio::test]
async fn daemon_p2_20_analysis_0002_dedup_suppresses_before_binary_inspection() {
    let inspector = Arc::new(MockBinaryInspector::default());

    let dropper_exe = r"C:\Temp\burst_dedup.exe";
    inspector.insert(BinaryIdentity {
        exe_path: dropper_exe.to_string(),
        sha256: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
        authenticode: None,
    });

    let Phase2Harness { store, engine, .. } = start_harness_with_inspector(
        LedrStore::open_in_memory().expect("open in-memory store"),
        EarlyPruner::default(),
        default_test_config(),
        inspector.clone(),
    );

    let t0 = current_unix_ms() - 2_000;
    let ident = ProcessIdentity::new(6700, unix_ms_to_filetime(t0));
    send_process_start(&engine, ident, 4, dropper_exe, "burst_dedup.exe").await;
    for offset in 0..3i64 {
        send_canary_access(
            &engine,
            ident.pid,
            r"C:\Users\alice\Documents\!00_LocalEDR_Canary_DoNotEdit.docx",
            CanaryCategory::Honeypot,
            0x0012_0116,
            true,
            t0 + 10 + offset,
        )
        .await;
    }

    wait_for_hp_processed(&engine, 4).await;
    assert_eq!(
        inspector.inspections(),
        1,
        "dedup-suppressed events must skip binary inspection"
    );
    assert_eq!(store.list_alerts(None, 20).expect("list alerts").len(), 1);
    let canary_rows = store
        .list_file_canary_events(Some(CanaryCategory::Honeypot), Some(&ident.instance_id()), 20)
        .expect("list canary events");
    assert_eq!(
        canary_rows
            .iter()
            .filter(|r| r.action_taken == "DEDUP_SUPPRESSED")
            .count(),
        2
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-21` (`BUG_0002`): concurrent resolves of sibling suspended alerts must be
/// serialized so exactly one of them sees "no other unresolved alert" and resumes the
/// process once — never both skipping resume and freezing it forever.
#[tokio::test]
async fn daemon_p2_21_bug_0002_concurrent_sibling_resolves_resume_exactly_once() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let ident = ProcessIdentity::new(8301, unix_ms_to_filetime(t0));
    send_process_start(&engine, ident, 4, r"C:\Temp\race_root.exe", "race_root.exe").await;
    for (idx, target) in [r"C:\t\a.env", r"C:\t\b.env"].iter().enumerate() {
        send_canary_access(
            &engine,
            ident.pid,
            target,
            CanaryCategory::EnvFile,
            0x0012_0089,
            false,
            t0 + 100 + idx as i64,
        )
        .await;
    }
    wait_for_hp_processed(&engine, 3).await;

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 2);
    assert!(alerts.iter().all(|a| a.process_suspended));
    let id_a = alerts[0].alert_id.clone();
    let id_b = alerts[1].alert_id.clone();

    // Release both resolves simultaneously; serialization must order them so the second
    // one observes the first as resolved and performs the resume.
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let (e1, e2) = (Arc::clone(&engine), Arc::clone(&engine));
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let h1 = std::thread::spawn(move || {
        b1.wait();
        e1.resolve_alert(&id_a, AlertDecision::AllowOnce)
    });
    let h2 = std::thread::spawn(move || {
        b2.wait();
        e2.resolve_alert(&id_b, AlertDecision::AllowOnce)
    });
    h1.join().expect("join resolve 1").expect("resolve 1 ok");
    h2.join().expect("join resolve 2").expect("resolve 2 ok");

    assert_eq!(
        defense.resumes(),
        vec![ident],
        "exactly one resume must happen across concurrent sibling resolves"
    );
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-22` (`BUG_0004`): a resume failure on a still-running process must keep the
/// alert unresolved (operator can retry); only a genuinely gone process may be swallowed.
#[tokio::test]
async fn daemon_p2_22_bug_0004_resume_failure_on_live_process_keeps_alert_unresolved() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let mk_alert = |alert_id: &str, ident: &ProcessIdentity| {
        make_alert_record(alert_id, Some(ident.instance_id()), "{}".to_string())
    };

    // Live process (this test binary) whose resume fails: alert must stay unresolved.
    let live_ident = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(current_unix_ms() - 1_000),
    );
    defense.add_failing_resume_pid(live_ident.pid);
    let live_alert = mk_alert("live-resume-fail", &live_ident);
    store.record_alert(&live_alert).expect("record live alert");
    assert!(
        engine
            .resolve_alert(&live_alert.alert_id, AlertDecision::AllowOnce)
            .is_err(),
        "resume failure on a live process must surface as an error"
    );
    let kept = store
        .get_alert(&live_alert.alert_id)
        .expect("get live alert")
        .expect("live alert exists");
    assert!(
        kept.status.is_unresolved(),
        "alert must stay unresolved so the operator can retry"
    );

    // Gone process (PID that cannot exist in a Toolhelp32 snapshot): resolution proceeds.
    let gone_ident =
        ProcessIdentity::new(0x7FFF_FFC0, unix_ms_to_filetime(current_unix_ms() - 1_000));
    defense.add_failing_resume_pid(gone_ident.pid);
    let gone_alert = mk_alert("gone-resume-fail", &gone_ident);
    store.record_alert(&gone_alert).expect("record gone alert");
    let resolved = engine
        .resolve_alert(&gone_alert.alert_id, AlertDecision::AllowOnce)
        .expect("resume failure on a gone process is swallowed");
    assert_eq!(resolved.status, AlertStatus::ApprovedOnce);

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-23` (`SEC_0001`): an IPC client session is force-closed once its lifetime
/// exceeds `ipc_session_timeout_ms`, so one client cannot pin the single strict-mode
/// pipe instance forever with periodic lightweight requests.
#[tokio::test]
async fn daemon_p2_23_sec_0001_ipc_session_lifetime_cap() {
    let pipe_name = unique_test_pipe_name();
    let store = LedrStore::open_in_memory().expect("open store");
    let engine = DaemonEngine::start(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            ipc_frame_timeout_ms: 5_000,
            ipc_session_timeout_ms: 1_000,
            ..DaemonConfig::default()
        },
    );
    let ipc_handle = start_ipc_server(Arc::clone(&engine)).expect("bind Named Pipe");

    let pipe_for_clients = pipe_name.clone();
    let (session_capped, fresh_pong) = tokio::task::spawn_blocking(move || {
        let mut c = open_pipe_with_retry(&pipe_for_clients);
        // Staying under the cap keeps the session alive: periodic Ping works.
        write_ipc_frame(&mut c, &IpcRequest::Ping).expect("write ping 1");
        assert!(matches!(
            read_ipc_frame::<_, IpcResponse>(&mut c).expect("read pong 1"),
            IpcResponse::Pong { .. }
        ));
        // Wait past the session cap (1s, the documented minimum); the server must close.
        std::thread::sleep(Duration::from_millis(1_300));
        // Bound the post-cap probe so a hung server read fails the test instead of
        // blocking it forever.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = (|| {
                if write_ipc_frame(&mut c, &IpcRequest::Ping).is_err() {
                    return true;
                }
                read_ipc_frame::<_, IpcResponse>(&mut c).is_err()
            })();
            let _ = tx.send(r);
        });
        let session_capped = rx.recv_timeout(Duration::from_secs(5)).expect(
            "post-cap probe must return a verdict within 5s; a timeout means the disconnect could not be confirmed",
        );
        // A fresh connection after the cap still works normally.
        let fresh_pong = matches!(
            send_pipe_request(&pipe_for_clients, &IpcRequest::Ping),
            IpcResponse::Pong { .. }
        );
        (session_capped, fresh_pong)
    })
    .await
    .expect("join session cap probe");
    assert!(session_capped, "session must be cut at ipc_session_timeout_ms");
    assert!(fresh_pong, "fresh connection must still receive Pong");

    ipc_handle.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-24` (`BUG_0001`): when the resume step of an `AllowPermanent` resolve
/// fails, the stored allowlist rule must be rolled back so a later "allow once" retry
/// does not silently keep permanent access, and a retried decision must not pile up
/// duplicate rules.
#[tokio::test]
async fn daemon_p2_24_bug_0001_permanent_rule_rolled_back_on_resume_failure() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    // Suspended alert on a live process (this test binary) whose resume keeps failing.
    let live_ident = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(current_unix_ms() - 1_000),
    );
    defense.add_failing_resume_pid(live_ident.pid);
    let alert = make_alert_record(
        "perm-rollback",
        Some(live_ident.instance_id()),
        serde_json::json!({
            "exe_path": r"C:\Temp\backup.exe",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        })
        .to_string(),
    );
    store.record_alert(&alert).expect("record alert");

    assert!(
        engine
            .resolve_alert(
                &alert.alert_id,
                AlertDecision::AllowPermanent {
                    use_signer_if_available: false,
                    allow_dest: None,
                },
            )
            .is_err(),
        "resume failure on a live process must surface as an error"
    );
    assert!(
        store
            .get_alert(&alert.alert_id)
            .expect("get alert")
            .expect("alert exists")
            .status
            .is_unresolved(),
        "alert must stay unresolved so the operator can retry"
    );
    assert!(
        store
            .list_rules(None)
            .expect("list rules")
            .is_empty(),
        "stored permanent rule must be rolled back when the resolve fails"
    );

    // Retrying the same permanent decision after the failure must not pile up
    // duplicate rules.
    defense.remove_failing_resume_pid(live_ident.pid);
    let resolved = engine
        .resolve_alert(
            &alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect("retry after clearing the failure");
    assert_eq!(resolved.status, AlertStatus::ApprovedRule);
    assert_eq!(
        store
            .list_rules(None)
            .expect("list rules")
            .len(),
        1,
        "exactly one allowlist rule must exist after a retried permanent allow"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-25` (`BUG_0002`): a descendant the actuator could not suspend must not be
/// recorded in `suspended_children`, so its resume failure cannot block resolution.
#[tokio::test]
async fn daemon_p2_25_bug_0002_unsuspendable_child_not_recorded_for_resume() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let root_ident = ProcessIdentity::new(0x7FFF_0101, unix_ms_to_filetime(t0));
    let stuck_child = ProcessIdentity::new(0x7FFF_0102, unix_ms_to_filetime(t0 + 50));
    let ok_child = ProcessIdentity::new(0x7FFF_0103, unix_ms_to_filetime(t0 + 60));
    for (ident, parent_pid, exe) in [
        (root_ident, 4u32, r"C:\Temp\root.exe"),
        (stuck_child, root_ident.pid, r"C:\Temp\stuck.exe"),
        (ok_child, root_ident.pid, r"C:\Temp\ok.exe"),
    ] {
        send_process_start(&engine, ident, parent_pid, exe, exe).await;
    }
    // The child the actuator cannot suspend would also fail resume; it must be
    // excluded from the recorded list so it cannot block resolution.
    defense.add_failing_suspend_pid(stuck_child.pid);
    defense.add_failing_resume_pid(stuck_child.pid);
    send_canary_access(
        &engine,
        root_ident.pid,
        r"C:\t\!00_LocalEDR_Canary_DoNotEdit.docx",
        CanaryCategory::Honeypot,
        0x0012_0089,
        true,
        t0 + 100,
    )
    .await;
    wait_for_hp_processed(&engine, 4).await;

    let alerts = store.list_alerts(None, 20).expect("list alerts");
    assert_eq!(alerts.len(), 1);
    let alert = &alerts[0];
    assert!(alert.process_suspended);
    let ctx: serde_json::Value =
        serde_json::from_str(&alert.context_json).expect("parse alert context");
    let recorded: Vec<String> = ctx
        .get("suspended_children")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(
        recorded,
        vec![ok_child.instance_id()],
        "only actuator-confirmed suspended children may be recorded"
    );

    // Resolution must succeed even though the non-suspended child would fail resume.
    let resolved = engine
        .resolve_alert(&alert.alert_id, AlertDecision::AllowOnce)
        .expect("allow once resolves");
    assert_eq!(resolved.status, AlertStatus::ApprovedOnce);
    assert!(
        !defense.resumes().contains(&stuck_child),
        "resume must not be attempted for a child that was never suspended"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-26` (`BUG_0002`): a recorded suspended child that is still running but
/// cannot be resumed must keep the alert unresolved so the operator can retry.
#[tokio::test]
async fn daemon_p2_26_bug_0002_suspended_child_resume_failure_keeps_unresolved() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let t0 = current_unix_ms() - 5_000;
    let root_ident = ProcessIdentity::new(0x7FFF_0110, unix_ms_to_filetime(t0));
    // A recorded suspended child on a live pid (this test binary) whose resume fails.
    let live_child = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(t0 + 50),
    );
    let alert = AlertRecord {
        severity: AlertSeverity::Critical,
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        ..make_alert_record(
            "child-resume-fail",
            Some(root_ident.instance_id()),
            serde_json::json!({
                "suspended_children": [live_child.instance_id()],
            })
            .to_string(),
        )
    };
    store.record_alert(&alert).expect("record alert");

    defense.add_failing_resume_pid(live_child.pid);
    assert!(
        engine
            .resolve_alert(&alert.alert_id, AlertDecision::AllowOnce)
            .is_err(),
        "resume failure on a live suspended child must surface as an error"
    );
    assert!(
        store
            .get_alert(&alert.alert_id)
            .expect("get alert")
            .expect("alert exists")
            .status
            .is_unresolved(),
        "alert must stay unresolved while a suspended child cannot be resumed"
    );

    defense.remove_failing_resume_pid(live_child.pid);
    let resolved = engine
        .resolve_alert(&alert.alert_id, AlertDecision::AllowOnce)
        .expect("retry after clearing the failure");
    assert_eq!(resolved.status, AlertStatus::ApprovedOnce);

    engine.shutdown_and_flush().await.expect("shutdown");
}


/// `DAEMON-P2-27` (`BUG_0001`): when `TerminateAndBlock` already killed the target but the
/// status update failed and rolled back the block rule, the retry hits a terminate error
/// on the now-gone process. The retry must still re-save the block rule and resolve the
/// alert; a failure on a still-running target stays fatal.
#[tokio::test]
async fn daemon_p2_27_bug_0001_terminate_retry_on_gone_suspended_target_saves_block_rule() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let mk_alert = |alert_id: &str, ident: &ProcessIdentity| {
        make_alert_record(
            alert_id,
            Some(ident.instance_id()),
            serde_json::json!({ "exe_path": r"C:\Temp\terminated_once.exe" }).to_string(),
        )
    };

    // First attempt: termination succeeded, then the alert status update failed and the
    // fresh block rule was rolled back. A transient store failure cannot be injected
    // through `LedrStore`, so its durable result is emulated here — a terminated target
    // (this actuator call), no persisted rule, and a still-unresolved alert — before
    // driving the retry below.
    let gone_ident =
        ProcessIdentity::new(0x7FFF_FFC0, unix_ms_to_filetime(current_unix_ms() - 1_000));
    defense
        .terminate_process(&gone_ident, true)
        .expect("first attempt termination");
    assert_eq!(defense.terminates().len(), 1);
    defense.add_failing_terminate_pid(gone_ident.pid);
    let gone_alert = mk_alert("gone-terminate-fail", &gone_ident);
    store.record_alert(&gone_alert).expect("record gone alert");
    let outcome = engine
        .resolve_alert_with_outcome(
            &gone_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("terminate failure on a gone target must not block rule persistence");
    assert_eq!(outcome.alert.status, AlertStatus::TerminatedBlocked);
    let rule_id = outcome.saved_rule_id.expect("block rule persisted");
    assert!(rule_id.starts_with("RULE-BLOCK-"));
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkBlock))
            .expect("list block rules")
            .iter()
            .any(|rule| rule.rule_id == rule_id),
        "block rule must remain stored after resolution"
    );

    // A terminate failure on a still-running target stays fatal and persists nothing.
    let live_ident = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(current_unix_ms() - 1_000),
    );
    defense.add_failing_terminate_pid(live_ident.pid);
    let live_alert = mk_alert("live-terminate-fail", &live_ident);
    store.record_alert(&live_alert).expect("record live alert");
    assert!(
        engine
            .resolve_alert(
                &live_alert.alert_id,
                AlertDecision::TerminateAndBlock {
                    add_block_rule: true,
                },
            )
            .is_err(),
        "terminate failure on a live process must surface as an error"
    );
    assert!(
        store
            .get_alert(&live_alert.alert_id)
            .expect("get live alert")
            .expect("live alert exists")
            .status
            .is_unresolved(),
        "alert must stay unresolved while the target cannot be terminated"
    );
    assert_eq!(
        store
            .list_rules(Some(RuleScope::NetworkBlock))
            .expect("list block rules")
            .len(),
        1,
        "failed attempt must not persist a second block rule"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-29` (`BUG_0001`): when the frozen parent is already gone but a recorded
/// suspended child is still running and cannot be terminated (e.g. access denied), the
/// alert must stay unresolved — resolving would strand a suspended child the alert can
/// no longer terminate or resume, and must not persist the block rule.
#[tokio::test]
async fn daemon_p2_29_bug_0001_live_suspended_child_terminate_failure_keeps_unresolved() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let now_ms = current_unix_ms();
    let gone_parent = ProcessIdentity::new(0x7FFF_FFC1, unix_ms_to_filetime(now_ms - 1_000));
    let live_child = ProcessIdentity::new(
        std::process::id(),
        unix_ms_to_filetime(now_ms - 1_000),
    );
    let extra_child = ProcessIdentity::new(0x7FFF_FFC2, unix_ms_to_filetime(now_ms - 1_000));

    let alert = AlertRecord {
        timestamp_ms: now_ms,
        severity: AlertSeverity::Critical,
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        title: "child terminate failure".to_string(),
        ..make_alert_record(
            "alert-child-terminate-fail",
            Some(gone_parent.instance_id()),
            serde_json::json!({
                "exe_path": r"C:\Temp\gone_parent.exe",
                "suspended_children": [live_child.instance_id(), extra_child.instance_id()],
            })
            .to_string(),
        )
    };
    store.record_alert(&alert).expect("record alert");

    // Parent terminate is tolerated (already gone); the live child's terminate fails.
    defense.add_failing_terminate_pid(gone_parent.pid);
    defense.add_failing_terminate_pid(live_child.pid);
    let err = engine
        .resolve_alert(
            &alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect_err("terminate failure on a live suspended child must surface as an error");
    assert!(
        err.contains(&format!("PID {})", live_child.pid)),
        "surfaced error must reference the child's PID, not the parent's: {err}"
    );
    // The deferred failure must not abandon remaining recorded descendants: the later
    // child still gets its terminate attempt (the parent's own call failed and was
    // tolerated, so it is not recorded by the mock).
    assert_eq!(
        defense.terminates(),
        vec![TerminateCall {
            target: extra_child,
            include_children: true,
        }],
        "remaining recorded descendants must still be terminated after an earlier child failure"
    );
    assert!(
        store
            .get_alert(&alert.alert_id)
            .expect("get alert")
            .expect("alert exists")
            .status
            .is_unresolved(),
        "alert must stay unresolved while a suspended child cannot be terminated"
    );
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkBlock))
            .expect("list block rules")
            .is_empty(),
        "no block rule must persist while a suspended child cannot be terminated"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P2-30` (Phase 2 invariant regression): when a frozen parent fails `terminate_process`
/// for a non-protected reason while still running and `suspended_children` is non-empty, the
/// daemon must still attempt every recorded suspended child and return the parent's terminate
/// error with precedence (regardless of individual child outcomes), leaving the alert unresolved
/// and persisting no block rule.
#[tokio::test]
async fn daemon_p2_30_frozen_parent_terminate_failure_attempts_all_children_and_returns_parent_err() {
    let Phase2Harness {
        store,
        defense,
        engine,
        ..
    } = start_harness();

    let now_ms = current_unix_ms();
    // Use the current test process PID as a confirmed-live frozen parent so
    // `is_process_gone_or_replaced` returns false and enters the parent-error branch.
    let live_parent = ProcessIdentity::new(std::process::id(), unix_ms_to_filetime(now_ms - 1_000));
    let failing_child = ProcessIdentity::new(0x7FFF_FFD1, unix_ms_to_filetime(now_ms - 1_000));
    let succeeding_child = ProcessIdentity::new(0x7FFF_FFD2, unix_ms_to_filetime(now_ms - 1_000));

    let alert = AlertRecord {
        timestamp_ms: now_ms,
        severity: AlertSeverity::Critical,
        rule_id: "LEDR-CANARY-HONEYPOT".to_string(),
        title: "frozen parent terminate failure".to_string(),
        ..make_alert_record(
            "alert-frozen-parent-terminate-fail",
            Some(live_parent.instance_id()),
            serde_json::json!({
                "exe_path": r"C:\Temp\live_parent.exe",
                "suspended_children": [failing_child.instance_id(), succeeding_child.instance_id()],
            })
            .to_string(),
        )
    };
    store.record_alert(&alert).expect("record alert");

    defense.add_failing_terminate_pid(live_parent.pid);
    defense.add_failing_terminate_pid(failing_child.pid);

    let err = engine
        .resolve_alert_with_outcome(
            &alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect_err("frozen parent terminate failure must return parent error");

    assert!(
        err.contains(&format!("PID {})", live_parent.pid)),
        "returned error must prioritize the parent PID over child errors: {err}"
    );
    assert!(
        !err.contains(&format!("PID {})", failing_child.pid)),
        "returned error must not be replaced by a child terminate error: {err}"
    );
    assert_eq!(
        defense.terminate_attempts(),
        vec![
            TerminateCall {
                target: live_parent,
                include_children: true,
            },
            TerminateCall {
                target: failing_child,
                include_children: true,
            },
            TerminateCall {
                target: succeeding_child,
                include_children: true,
            },
        ],
        "parent and every recorded suspended child must be attempted in order"
    );
    assert_eq!(
        defense.terminates(),
        vec![TerminateCall {
            target: succeeding_child,
            include_children: true,
        }],
        "succeeding child must complete termination even when parent and earlier child failed"
    );
    assert!(
        store
            .get_alert(&alert.alert_id)
            .expect("get alert")
            .expect("alert exists")
            .status
            .is_unresolved(),
        "alert must remain unresolved after parent terminate failure"
    );
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkBlock))
            .expect("list block rules")
            .is_empty(),
        "no block rule must be persisted after parent terminate failure"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}
