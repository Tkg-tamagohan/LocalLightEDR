//! Phase 3 integration tests for outbound firewall, coupled WFP + suspension containment,
//! deny-overrides-allow reconciliation, and live NRD domain cache (`L-03`, `L-04`, `L-07`,
//! `L-13`, `AUTO-02`, `AUTO-04`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    start_ipc_server, BinaryInspector, DaemonConfig, DaemonEngine, NotificationDispatcher,
    WindowsBinaryInspector,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, ActiveDefenseController, AlertDecision, AlertRecord,
    AlertSeverity, AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, IpcRequest, IpcResponse,
    ProcessIdentity, RuleScope, SensorEvent,
};
use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
use ledr_store::LedrStore;

static PIPE_COUNTER: AtomicU64 = AtomicU64::new(1);

fn unique_test_pipe_name() -> String {
    let seq = PIPE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\localedr-p3-test-{}-{}", std::process::id(), seq)
}

fn current_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn unix_ms_to_filetime(unix_ms: i64) -> u64 {
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    EPOCH_DIFF_100NS.saturating_add(unix_ms.max(0) as u64 * 10_000)
}

fn send_pipe_request(pipe_name: &str, req: &IpcRequest) -> IpcResponse {
    let mut last_err = None;
    for _ in 0..40 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_name)
        {
            Ok(mut pipe) => {
                write_ipc_frame(&mut pipe, req).expect("write IPC request");
                return read_ipc_frame::<_, IpcResponse>(&mut pipe).expect("read IPC response");
            }
            Err(err) => {
                last_err = Some(err);
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    panic!(
        "open Named Pipe `{pipe_name}` failed: {}",
        last_err.unwrap()
    );
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WfpCall {
    handle: u64,
    exe_path: String,
    remote_ip: Option<IpAddr>,
    allow: bool,
}

#[derive(Default)]
struct MockWfpDefense {
    next_handle: AtomicU64,
    suspends: Mutex<Vec<ProcessIdentity>>,
    resumes: Mutex<Vec<ProcessIdentity>>,
    terminates: Mutex<Vec<ProcessIdentity>>,
    added_wfp: Mutex<Vec<WfpCall>>,
    removed_wfp: Mutex<Vec<u64>>,
    active_wfp: Mutex<HashMap<u64, WfpCall>>,
    fail_wfp_add: Mutex<bool>,
    fail_suspend: Mutex<bool>,
    failing_resume_pids: Mutex<Vec<u32>>,
}

impl MockWfpDefense {
    fn new() -> Self {
        Self {
            next_handle: AtomicU64::new(100),
            ..Self::default()
        }
    }

    fn suspends(&self) -> Vec<ProcessIdentity> {
        self.suspends.lock().expect("lock suspends").clone()
    }

    fn resumes(&self) -> Vec<ProcessIdentity> {
        self.resumes.lock().expect("lock resumes").clone()
    }

    fn terminates(&self) -> Vec<ProcessIdentity> {
        self.terminates.lock().expect("lock terminates").clone()
    }

    fn added_wfp(&self) -> Vec<WfpCall> {
        self.added_wfp.lock().expect("lock added_wfp").clone()
    }

    fn removed_wfp(&self) -> Vec<u64> {
        self.removed_wfp.lock().expect("lock removed_wfp").clone()
    }

    fn active_wfp(&self) -> Vec<WfpCall> {
        self.active_wfp
            .lock()
            .expect("lock active_wfp")
            .values()
            .cloned()
            .collect()
    }

    fn set_fail_wfp_add(&self, fail: bool) {
        *self.fail_wfp_add.lock().expect("lock fail_wfp_add") = fail;
    }

    fn set_fail_suspend(&self, fail: bool) {
        *self.fail_suspend.lock().expect("lock fail_suspend") = fail;
    }

    fn add_failing_resume_pid(&self, pid: u32) {
        self.failing_resume_pids
            .lock()
            .expect("lock failing_resume_pids")
            .push(pid);
    }

    fn clear_failing_resume_pid(&self, pid: u32) {
        self.failing_resume_pids
            .lock()
            .expect("lock failing_resume_pids")
            .retain(|p| *p != pid);
    }
}

impl ActiveDefenseController for MockWfpDefense {
    fn suspend_process(
        &self,
        target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
        if *self.fail_suspend.lock().expect("lock fail_suspend") {
            return Err(format!("mock suspend failure for PID {}", target.pid));
        }
        self.suspends.lock().expect("lock suspends").push(*target);
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
                "OpenProcess(PID {}) failed: Access is denied.",
                target.pid
            ));
        }
        self.resumes.lock().expect("lock resumes").push(*target);
        Ok(())
    }

    fn terminate_process(
        &self,
        target: &ProcessIdentity,
        _include_children: bool,
    ) -> Result<(), String> {
        self.terminates
            .lock()
            .expect("lock terminates")
            .push(*target);
        Ok(())
    }

    fn add_wfp_app_rule(
        &self,
        exe_path: &Path,
        remote_ip: Option<IpAddr>,
        allow: bool,
    ) -> Result<u64, String> {
        if *self.fail_wfp_add.lock().expect("lock fail_wfp_add") {
            return Err(format!(
                "mock WFP add_wfp_app_rule failure for {}",
                exe_path.display()
            ));
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let call = WfpCall {
            handle,
            exe_path: exe_path.to_string_lossy().into_owned(),
            remote_ip,
            allow,
        };
        self.added_wfp
            .lock()
            .expect("lock added_wfp")
            .push(call.clone());
        self.active_wfp
            .lock()
            .expect("lock active_wfp")
            .insert(handle, call);
        Ok(handle)
    }

    fn remove_wfp_rule(&self, filter_id: u64) -> Result<(), String> {
        self.removed_wfp
            .lock()
            .expect("lock removed_wfp")
            .push(filter_id);
        let removed = self
            .active_wfp
            .lock()
            .expect("lock active_wfp")
            .remove(&filter_id);
        if removed.is_none() {
            return Err(format!("mock WFP filter handle {filter_id} not found"));
        }
        Ok(())
    }
}

#[derive(Default)]
struct MockNotifier {
    notified: Mutex<Vec<AlertRecord>>,
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
struct MapBinaryInspector {
    identities: Mutex<HashMap<String, BinaryIdentity>>,
}

impl MapBinaryInspector {
    fn register(&self, exe_path: &str, sha256: Option<&str>, auth: Option<(&str, &str)>) {
        let key = exe_path.replace('/', "\\").to_ascii_lowercase();
        self.identities.lock().expect("lock identities").insert(
            key,
            BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: sha256.map(ToString::to_string),
                authenticode: auth.map(|(signer, thumb)| AuthenticodeInfo {
                    signer_subject: signer.to_string(),
                    root_thumbprint: thumb.to_string(),
                }),
            },
        );
    }
}

impl BinaryInspector for MapBinaryInspector {
    fn inspect(&self, exe_path: &str) -> BinaryIdentity {
        let key = exe_path.replace('/', "\\").to_ascii_lowercase();
        self.identities
            .lock()
            .expect("lock identities")
            .get(&key)
            .cloned()
            .unwrap_or_else(|| BinaryIdentity {
                exe_path: exe_path.to_string(),
                sha256: Some(format!("deadbeef{:056x}", key.len())),
                authenticode: None,
            })
    }
}

async fn wait_until<F: Fn() -> bool>(timeout_ms: u64, pred: F) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    pred()
}

fn file_url_for_path(path: &Path) -> String {
    let canonical = path.to_string_lossy().replace('\\', "/");
    format!("file:///{canonical}")
}

/// `DAEMON-P3-01`: High-risk paths (`Downloads`/`Temp`) and script interpreters (`powershell`,
/// `node`, `python`) receive pre-emptive dynamic WFP blocks on `ProcessStart` and freeze on
/// external `NetworkConnect`; `ProtectedOs` (`svchost.exe`) and local/private IPs are never
/// blocked or suspended (`L-03`, `AUTO-02`).
#[tokio::test]
async fn daemon_p3_01_high_risk_and_script_interpreter_preemptive_wfp_and_guards() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let svchost = ProcessIdentity::new(5001, unix_ms_to_filetime(now_ms - 5_000));
    let dl_dropper = ProcessIdentity::new(5002, unix_ms_to_filetime(now_ms - 4_000));
    let node_proc = ProcessIdentity::new(5003, unix_ms_to_filetime(now_ms - 3_000));
    let local_app = ProcessIdentity::new(5004, unix_ms_to_filetime(now_ms - 2_000));

    for (ident, exe) in [
        (svchost, r"C:\Windows\System32\svchost.exe"),
        (dl_dropper, r"C:\Users\alice\Downloads\dropper.exe"),
        (node_proc, r"C:\Program Files\nodejs\node.exe"),
        (local_app, r"C:\Tools\local_only.exe"),
    ] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: ident,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: Some("S-1-5-21-1000".to_string()),
            })
            .await
            .expect("send ProcessStart");
    }

    assert!(
        wait_until(2_000, || defense.active_wfp().len() == 2).await,
        "Downloads executable and node.exe must receive pre-emptive WFP block on ProcessStart"
    );
    assert!(engine.has_active_wfp_filter(r"C:\Users\alice\Downloads\dropper.exe", None, false));
    assert!(engine.has_active_wfp_filter(r"C:\Program Files\nodejs\node.exe", None, false));
    assert!(!engine.has_active_wfp_filter(r"C:\Windows\System32\svchost.exe", None, false));
    assert!(!engine.has_active_wfp_filter(r"C:\Tools\local_only.exe", None, false));

    // Protected OS process connecting externally + general process connecting to private/loopback
    // must NOT alert or suspend.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: svchost.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("windowsupdate.microsoft.com".to_string()),
            timestamp_ms: now_ms,
        })
        .await
        .expect("send svchost connect");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: local_app.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)),
            dst_port: 8080,
            domain_hint: None,
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("send local_app private connect");

    // Pre-emptively restricted processes connecting externally must freeze and emit High alerts.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: dl_dropper.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            dst_port: 443,
            domain_hint: Some("drop.example".to_string()),
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("send dropper connect");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: node_proc.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)),
            dst_port: 443,
            domain_hint: Some("registry.example".to_string()),
            timestamp_ms: now_ms + 3,
        })
        .await
        .expect("send node connect");

    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 20)
        .expect("list alerts");
    assert_eq!(alerts.len(), 2);

    let dl_alert = alerts
        .iter()
        .find(|a| a.rule_id == "LEDR-NET-HIGH-RISK-PATH")
        .expect("high-risk path alert");
    assert_eq!(dl_alert.source_layer, "LAYER_3_NETWORK");
    assert_eq!(dl_alert.severity, AlertSeverity::High);
    assert!(dl_alert.process_suspended);

    let node_alert = alerts
        .iter()
        .find(|a| a.rule_id == "LEDR-NET-SCRIPT-INTERPRETER")
        .expect("script interpreter alert");
    assert_eq!(node_alert.source_layer, "LAYER_3_NETWORK");
    assert_eq!(node_alert.severity, AlertSeverity::High);
    assert!(node_alert.process_suspended);

    assert_eq!(defense.suspends(), vec![dl_dropper, node_proc]);
}

/// `DAEMON-P3-02`: General-path unknown process triggers coupled WFP dynamic block +
/// `NtSuspendProcess` on first external connect, and `AllowPermanent` (both unsigned SHA-256
/// and signed Authenticode / domain-scoped) lifts containment, installs Permit, resumes, and
/// allows subsequent connections (`L-03`, `L-04`).
#[tokio::test]
async fn daemon_p3_02_unknown_process_coupled_containment_and_allow_permanent_variants() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let unsigned_exe = r"C:\Tools\unsigned_client.exe";
    let signed_exe = r"C:\Tools\signed_updater.exe";
    inspector.register(
        unsigned_exe,
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        None,
    );
    inspector.register(
        signed_exe,
        Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        Some(("CN=Trusted Vendor Corp", "THUMBPRINT-ROOT-001")),
    );

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let unsigned_id = ProcessIdentity::new(5101, unix_ms_to_filetime(now_ms - 3_000));
    let signed_id = ProcessIdentity::new(5102, unix_ms_to_filetime(now_ms - 2_000));

    sender
        .send(SensorEvent::ProcessStart {
            identity: unsigned_id,
            parent_pid: 4,
            exe_path: unsigned_exe.to_string(),
            command_line: unsigned_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("send unsigned start");
    sender
        .send(SensorEvent::ProcessStart {
            identity: signed_id,
            parent_pid: 4,
            exe_path: signed_exe.to_string(),
            command_line: signed_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("send signed start");

    assert!(
        wait_until(1_000, || engine.active_process_table_len() == 2).await,
        "both processes seeded"
    );
    // General-path executables are NOT pre-emptively blocked on ProcessStart.
    assert_eq!(defense.active_wfp().len(), 0);

    // 1. Unsigned unknown process connects externally -> coupled WFP block + suspend.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: unsigned_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("api.unsigned.example".to_string()),
            timestamp_ms: now_ms,
        })
        .await
        .expect("send unsigned connect");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "unsigned outbound alert emitted"
    );
    assert!(engine.has_active_wfp_filter(unsigned_exe, None, false));
    assert_eq!(defense.suspends(), vec![unsigned_id]);

    let unsigned_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")[0]
        .clone();
    assert_eq!(unsigned_alert.rule_id, "LEDR-NET-UNKNOWN-OUTBOUND");
    assert_eq!(unsigned_alert.severity, AlertSeverity::Medium);
    assert!(unsigned_alert.process_suspended);

    let outcome = engine
        .resolve_alert_with_outcome(
            &unsigned_alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect("AllowPermanent unsigned");
    let saved_id = outcome.saved_rule_id.expect("saved NetworkAllow rule");
    let saved_rule = store
        .get_rule(&saved_id)
        .expect("get rule")
        .expect("rule exists");
    assert_eq!(saved_rule.scope, RuleScope::NetworkAllow);
    assert_eq!(
        saved_rule.sha256.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(saved_rule.signer_subject.is_none());
    assert!(!engine.has_active_wfp_filter(unsigned_exe, None, false));
    assert!(engine.has_active_wfp_filter(unsigned_exe, None, true));
    assert_eq!(defense.resumes(), vec![unsigned_id]);

    // Subsequent external connection from unsigned_id is ALLOWED without alert or suspend.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: unsigned_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)),
            dst_port: 443,
            domain_hint: Some("other.unsigned.example".to_string()),
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("send second unsigned connect");

    // 2. Signed unknown process connects -> AllowPermanent with signer + domain scope.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: signed_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dst_port: 443,
            domain_hint: Some("updates.vendor.example".to_string()),
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("send signed connect");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "signed outbound alert emitted"
    );
    let signed_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")[0]
        .clone();
    let signed_outcome = engine
        .resolve_alert_with_outcome(
            &signed_alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: Some("*.vendor.example".to_string()),
            },
        )
        .expect("AllowPermanent signed domain");
    let signed_rule = store
        .get_rule(&signed_outcome.saved_rule_id.expect("signed rule id"))
        .expect("get signed rule")
        .expect("signed rule exists");
    assert_eq!(signed_rule.scope, RuleScope::NetworkAllow);
    assert!(signed_rule.sha256.is_none());
    assert_eq!(
        signed_rule.signer_subject.as_deref(),
        Some("CN=Trusted Vendor Corp")
    );
    assert_eq!(
        signed_rule.root_thumbprint.as_deref(),
        Some("THUMBPRINT-ROOT-001")
    );
    assert_eq!(
        signed_rule.allowed_target.as_deref(),
        Some("*.vendor.example")
    );
    // Transient block lifted; no app-wide permit was installed for a domain-scoped rule.
    assert!(!engine.has_active_wfp_filter(signed_exe, None, false));
    assert!(!engine.has_active_wfp_filter(signed_exe, None, true));

    // Allowed domain passes; unrelated domain triggers fresh containment.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: signed_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            dst_port: 443,
            domain_hint: Some("cdn.vendor.example".to_string()),
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("send allowed vendor domain");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: signed_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)),
            dst_port: 443,
            domain_hint: Some("untrusted.other.example".to_string()),
            timestamp_ms: now_ms + 40,
        })
        .await
        .expect("send untrusted domain");

    engine.shutdown_and_flush().await.expect("shutdown");

    let pending = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list pending");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].process_instance_id.as_deref(),
        Some(signed_id.instance_id().as_str())
    );
    assert!(pending[0].context_json.contains("untrusted.other.example"));

    let snapshot = store
        .query_flight_recorder(50, Some(&unsigned_id.instance_id()))
        .expect("query unsigned telemetry");
    assert!(
        snapshot
            .network_events
            .iter()
            .any(|n| n.dst_ip == "198.51.100.99" && n.action == "ALLOWED"),
        "second connection after AllowPermanent must log ALLOWED"
    );
}

/// `DAEMON-P3-03`: Single-side failure compensation (`active-defense-guards.md` #5):
/// (a) WFP add failure skips suspend (0 suspended, 0 WFP),
/// (b) suspend failure immediately removes the newly added WFP filter (0 suspended, 0 active WFP),
/// (c) `record_alert` failure compensates BOTH `resume_process` AND `remove_wfp_rule` and clears
/// dedup so a retry succeeds cleanly.
#[tokio::test]
async fn daemon_p3_03_single_side_failure_compensation_leaves_no_orphaned_state() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let p_a = ProcessIdentity::new(5201, unix_ms_to_filetime(now_ms - 3_000));
    let p_b = ProcessIdentity::new(5202, unix_ms_to_filetime(now_ms - 2_000));
    let p_c = ProcessIdentity::new(5203, unix_ms_to_filetime(now_ms - 1_000));

    for (id, exe) in [
        (p_a, r"C:\Tools\case_a.exe"),
        (p_b, r"C:\Tools\case_b.exe"),
        (p_c, r"C:\Tools\case_c.exe"),
    ] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 3).await);

    // Case A: add_wfp_app_rule fails -> suspend_process must NOT be invoked.
    defense.set_fail_wfp_add(true);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_a.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send case A");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    assert!(defense.suspends().is_empty());
    assert!(defense.active_wfp().is_empty());
    let alert_a = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")[0]
        .clone();
    assert!(!alert_a.process_suspended);
    assert!(alert_a.context_json.contains("\"wfp_blocked\":false"));

    // Case B: add_wfp_app_rule succeeds, suspend_process fails -> remove_wfp_rule called immediately.
    defense.set_fail_wfp_add(false);
    defense.set_fail_suspend(true);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_b.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("send case B");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    assert!(defense.suspends().is_empty());
    assert_eq!(defense.added_wfp().len(), 1);
    assert_eq!(defense.removed_wfp(), vec![defense.added_wfp()[0].handle]);
    assert!(defense.active_wfp().is_empty());
    assert_eq!(engine.active_wfp_rule_count(), 0);

    // Case C: both succeed, then record_alert fails -> BOTH resume_process AND remove_wfp_rule
    // execute and dedup is cleared so retrying succeeds.
    defense.set_fail_suspend(false);
    engine.set_fail_record_alert_for_test(true);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_c.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("send case C failing");
    assert!(
        wait_until(2_000, || defense.resumes().contains(&p_c)).await,
        "record_alert failure must compensate by calling resume_process"
    );
    assert!(
        defense.active_wfp().is_empty(),
        "record_alert failure must compensate by removing transient WFP filter"
    );
    assert_eq!(engine.active_wfp_rule_count(), 0);
    assert_eq!(
        store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .expect("list")
            .len(),
        2
    );

    // Retry Case C with store healthy -> dedup was cleared, so full coupled containment succeeds.
    engine.set_fail_record_alert_for_test(false);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_c.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("send case C retry");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 3)
                .unwrap_or(false)
        })
        .await,
        "retry after record_alert rollback must emit alert"
    );
    assert!(engine.has_active_wfp_filter(r"C:\Tools\case_c.exe", None, false));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-04`: `AllowOnce` lifts transient WFP block, resumes process, allows subsequent
/// connections from the same instance, rolls back WFP on resume failure, and never bypasses a
/// persisted `NetworkBlock`. Also verifies `AllowPermanent` resume failure restores a
/// `Preemptive` block after rolling back the saved rule.
#[tokio::test]
async fn daemon_p3_04_allow_once_and_allow_permanent_rollback_invariants() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // 1. Happy path AllowOnce
    let p_once = ProcessIdentity::new(5301, unix_ms_to_filetime(now_ms - 3_000));
    let exe_once = r"C:\Tools\once_app.exe";
    sender
        .send(SensorEvent::ProcessStart {
            identity: p_once,
            parent_pid: 4,
            exe_path: exe_once.to_string(),
            command_line: exe_once.to_string(),
            user_sid: None,
        })
        .await
        .expect("start once_app");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_once.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("connect once_app");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let alert_once = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")[0]
        .clone();
    engine
        .resolve_alert(&alert_once.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce succeeds");
    assert!(!engine.has_active_wfp_filter(exe_once, None, false));
    assert!(defense.resumes().contains(&p_once));

    // Follow-up connect from same process_instance_id must be ALLOWED without new alert.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_once.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("second connect once_app");

    // 2. AllowOnce rollback when resume_process fails on a confirmed-live PID
    let live_pid = std::process::id();
    let p_live = ProcessIdentity::new(live_pid, unix_ms_to_filetime(now_ms - 2_000));
    let exe_live = r"C:\Users\alice\Downloads\live_fail_resume.exe";
    sender
        .send(SensorEvent::ProcessStart {
            identity: p_live,
            parent_pid: 4,
            exe_path: exe_live.to_string(),
            command_line: exe_live.to_string(),
            user_sid: None,
        })
        .await
        .expect("start live_fail_resume");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_live.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("connect live_fail_resume");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let live_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")[0]
        .clone();

    defense.add_failing_resume_pid(live_pid);
    // AllowOnce fails on resume -> must restore lifted Preemptive WFP block!
    let once_err = engine
        .resolve_alert(&live_alert.alert_id, AlertDecision::AllowOnce)
        .expect_err("AllowOnce must fail when live process resume fails");
    assert!(once_err.contains("still running") || once_err.contains("Access is denied"));
    assert!(
        engine.has_active_wfp_filter(exe_live, None, false),
        "WFP block must be restored after AllowOnce resume rollback"
    );

    // AllowPermanent also fails on resume -> must roll back saved NetworkAllow rule, remove
    // temporary Permit filter, AND restore Preemptive Block filter with zero leaked Permit!
    let perm_err = engine
        .resolve_alert(
            &live_alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect_err("AllowPermanent must fail when live process resume fails");
    assert!(perm_err.contains("still running") || perm_err.contains("Access is denied"));
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkAllow))
            .expect("list allow")
            .is_empty(),
        "saved NetworkAllow must be rolled back on resume failure"
    );
    assert!(
        !engine.has_active_wfp_filter(exe_live, None, true),
        "temporary Permit filter must be removed on resume failure"
    );
    assert!(
        engine.has_active_wfp_filter(exe_live, None, false),
        "Preemptive Block filter must be re-armed after AllowPermanent rollback"
    );
    assert_eq!(
        defense
            .active_wfp()
            .iter()
            .filter(|w| w.exe_path.eq_ignore_ascii_case(exe_live))
            .count(),
        1,
        "no leaked Permit WFP handle must remain after rollback"
    );

    // 3. Persisted NetworkBlock cannot be bypassed by AllowOnce (deny-overrides-allow).
    let p_blocked = ProcessIdentity::new(5309, unix_ms_to_filetime(now_ms - 1_000));
    let exe_blocked = r"C:\Tools\hard_blocked.exe";
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-HARD-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: exe_blocked.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "user_quarantine".to_string(),
        })
        .expect("upsert block");
    assert!(engine.has_active_wfp_filter(exe_blocked, None, false));

    sender
        .send(SensorEvent::ProcessStart {
            identity: p_blocked,
            parent_pid: 4,
            exe_path: exe_blocked.to_string(),
            command_line: exe_blocked.to_string(),
            user_sid: None,
        })
        .await
        .expect("start hard_blocked");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_blocked.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("connect hard_blocked");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.iter().any(|a| a.rule_id == "LEDR-NET-POLICY-BLOCK"))
                .unwrap_or(false)
        })
        .await
    );
    let block_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list")
        .into_iter()
        .find(|a| a.rule_id == "LEDR-NET-POLICY-BLOCK")
        .expect("policy block alert");
    engine
        .resolve_alert(&block_alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce resolves non-suspended alert");
    // Persisted NetworkBlock WFP filter MUST remain active!
    assert!(
        engine.has_active_wfp_filter(exe_blocked, None, false),
        "AllowOnce must never lift a persisted NetworkBlock WFP filter"
    );

    engine.shutdown_and_flush().await.expect("shutdown");

    let snap_once = store
        .query_flight_recorder(50, Some(&p_once.instance_id()))
        .expect("query once_app");
    assert!(snap_once
        .network_events
        .iter()
        .any(|n| n.dst_ip == "198.51.100.44" && n.action == "ALLOWED"));
}

/// `DAEMON-P3-05`: `TerminateAndBlock { add_block_rule: true }` promotes transient WFP block
/// in-place without a gap and overrides existing `NetworkAllow`; `add_block_rule: false` releases
/// transient WFP containment without saving a rule.
#[tokio::test]
async fn daemon_p3_05_terminate_and_block_promotion_and_release_without_block() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let p_promote = ProcessIdentity::new(5401, unix_ms_to_filetime(now_ms - 2_000));
    let exe_promote = r"C:\Tools\promote_me.exe";
    let p_release = ProcessIdentity::new(5402, unix_ms_to_filetime(now_ms - 1_000));
    let exe_release = r"C:\Tools\release_me.exe";

    for (id, exe) in [(p_promote, exe_promote), (p_release, exe_release)] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
        sender
            .send(SensorEvent::NetworkConnect {
                pid: id.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms,
            })
            .await
            .expect("send connect");
    }

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list");
    let a_promote = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p_promote.instance_id().as_str()))
        .expect("promote alert");
    let a_release = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p_release.instance_id().as_str()))
        .expect("release alert");

    let removed_before_promote = defense.removed_wfp().len();
    let promote_outcome = engine
        .resolve_alert_with_outcome(
            &a_promote.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("TerminateAndBlock with rule");
    assert!(promote_outcome.saved_rule_id.is_some());
    assert_eq!(
        defense.removed_wfp().len(),
        removed_before_promote,
        "transient WFP block must be promoted in-place with zero gap"
    );
    assert!(engine.has_active_wfp_filter(exe_promote, None, false));
    assert!(defense.terminates().contains(&p_promote));

    let release_outcome = engine
        .resolve_alert_with_outcome(
            &a_release.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("TerminateAndBlock without rule");
    assert!(release_outcome.saved_rule_id.is_none());
    assert!(
        !engine.has_active_wfp_filter(exe_release, None, false),
        "transient WFP block must be released when add_block_rule=false"
    );
    assert!(defense.terminates().contains(&p_release));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-06`: Startup redeployment (`deploy_persisted_network_rules`) and live IPC
/// `UpsertRule` / `DeleteRule` reconciliation enforce deny-overrides-allow and restore shadowed
/// Permits or Preemptive blocks on deletion (`L-03`, `L-04`).
#[tokio::test]
async fn daemon_p3_06_startup_redeployment_and_ipc_rule_reconciliation() {
    let store = LedrStore::open_in_memory().expect("open store");
    let now_ms = current_unix_ms();

    let conflict_exe = r"C:\Tools\conflict_app.exe";
    let allow_only_exe = r"C:\Tools\allow_only.exe";
    let sha_conflict = "1111111111111111111111111111111111111111111111111111111111111111";
    let sha_allow = "2222222222222222222222222222222222222222222222222222222222222222";

    // Pre-populate persisted rules before daemon start (simulating restart).
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-CONFLICT-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: conflict_exe.to_string(),
            sha256: Some(sha_conflict.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms - 1_000,
            created_by: "user_triage".to_string(),
        })
        .expect("seed allow");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-CONFLICT-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: conflict_exe.to_string(),
            sha256: Some(sha_conflict.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms - 500,
            created_by: "user_quarantine".to_string(),
        })
        .expect("seed block");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-ALLOW-ONLY".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: allow_only_exe.to_string(),
            sha256: Some(sha_allow.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("198.51.100.20".to_string()),
            created_at_ms: now_ms - 400,
            created_by: "user_triage".to_string(),
        })
        .expect("seed ip allow");

    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());
    inspector.register(conflict_exe, Some(sha_conflict), None);
    inspector.register(allow_only_exe, Some(sha_allow), None);

    let pipe_name = unique_test_pipe_name();
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
        notifier,
        inspector,
    );

    // Persisted firewall rules are redeployed automatically at engine startup.
    assert_eq!(defense.active_wfp().len(), 2);
    // Deny-overrides-allow: conflict_exe must have Block, NOT Permit.
    assert!(engine.has_active_wfp_filter(conflict_exe, None, false));
    assert!(!engine.has_active_wfp_filter(conflict_exe, None, true));
    // allow_only_exe gets IP-specific Permit.
    let target_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    assert!(engine.has_active_wfp_filter(allow_only_exe, Some(target_ip), true));
    // Re-running reconciliation is idempotent (zero churn).
    let report = engine.deploy_persisted_network_rules();
    assert_eq!(report.applied, 0);
    assert_eq!(report.removed, 0);
    assert_eq!(report.failed, 0);

    // Start Named Pipe IPC server and test live UpsertRule / DeleteRule reconciliation.
    let ipc = start_ipc_server(Arc::clone(&engine)).expect("start IPC");
    let pipe_client = pipe_name.clone();
    let (delete_resp, upsert_block_resp, list_resp) = tokio::task::spawn_blocking(move || {
        // Delete RULE-CONFLICT-BLOCK -> shadowed RULE-CONFLICT-ALLOW must immediately become active Permit!
        let del = send_pipe_request(
            &pipe_client,
            &IpcRequest::DeleteRule {
                rule_id: "RULE-CONFLICT-BLOCK".to_string(),
            },
        );
        // Upsert an IP-specific NetworkBlock overriding allow_only_exe's IP Permit.
        let ups = send_pipe_request(
            &pipe_client,
            &IpcRequest::UpsertRule {
                rule: AllowlistRuleRecord {
                    rule_id: "RULE-IP-OVERRIDE-BLOCK".to_string(),
                    scope: RuleScope::NetworkBlock,
                    exe_path_pattern: allow_only_exe.to_string(),
                    sha256: None,
                    signer_subject: None,
                    root_thumbprint: None,
                    allowed_target: Some("198.51.100.20".to_string()),
                    created_at_ms: now_ms,
                    created_by: "user_policy".to_string(),
                },
            },
        );
        let list = send_pipe_request(&pipe_client, &IpcRequest::ListRules { scope: None });
        (del, ups, list)
    })
    .await
    .expect("join IPC client");

    assert!(matches!(delete_resp, IpcResponse::Ack { .. }));
    assert!(matches!(upsert_block_resp, IpcResponse::Ack { .. }));
    match list_resp {
        IpcResponse::Rules(rules) => assert_eq!(rules.len(), 3),
        other => panic!("expected Rules response, got {other:?}"),
    }

    assert!(
        !engine.has_active_wfp_filter(conflict_exe, None, false)
            && engine.has_active_wfp_filter(conflict_exe, None, true),
        "deleting NetworkBlock must restore shadowed NetworkAllow Permit"
    );
    assert!(
        !engine.has_active_wfp_filter(allow_only_exe, Some(target_ip), true)
            && engine.has_active_wfp_filter(allow_only_exe, Some(target_ip), false),
        "upserting IP NetworkBlock must replace IP NetworkAllow Permit"
    );

    ipc.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-07`: Live NRD feed refresh via `file://`, periodic `run_pipeline` background update,
/// disk cache persistence & reload across daemon restart, `DnsQuery` `is_nrd` population in
/// SQLite, NRD severity escalation on `NetworkConnect`, and IPC `CheckDomainRisk` (`L-13`).
#[tokio::test]
async fn daemon_p3_07_live_nrd_cache_file_feed_dns_and_ipc_check_domain_risk() {
    let tmp_dir = std::env::temp_dir().join(format!(
        "ledr-p3-nrd-test-{}-{}",
        std::process::id(),
        PIPE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp_dir).expect("create temp nrd dir");
    let feed_path = tmp_dir.join("nrd7.txt");
    let cache_path = tmp_dir.join("nrd_cache.txt");
    std::fs::write(
        &feed_path,
        "# HaGeZi NRD mock feed\nfresh-c2-2026.example\n0.0.0.0 evil-drop.xyz\n",
    )
    .expect("write mock feed");

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let pipe_name = unique_test_pipe_name();

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            nrd_refresh_enabled: true,
            nrd_refresh_interval_ms: 400,
            nrd_cache_path: Some(cache_path.clone()),
            nrd_feed_urls: vec![file_url_for_path(&feed_path)],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        Arc::new(WindowsBinaryInspector::new()),
    );

    // Wait for run_pipeline's periodic NRD refresh task to load the file:// feed and save cache.
    assert!(
        wait_until(3_000, || engine.nrd_entry_count() == 2 && cache_path.exists()).await,
        "periodic NRD refresh must populate in-memory cache and persist disk cache"
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let proc_id = ProcessIdentity::new(5501, unix_ms_to_filetime(now_ms - 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: proc_id,
            parent_pid: 4,
            exe_path: r"C:\Tools\nrd_probe.exe".to_string(),
            command_line: r"C:\Tools\nrd_probe.exe".to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");
    sender
        .send(SensorEvent::DnsQuery {
            pid: proc_id.pid,
            query_name: "sub.fresh-c2-2026.example".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66))],
            timestamp_ms: now_ms,
        })
        .await
        .expect("send NRD dns");
    sender
        .send(SensorEvent::DnsQuery {
            pid: proc_id.pid,
            query_name: "example.com".to_string(),
            query_type: 1,
            resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("send clean dns");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: proc_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 66)),
            dst_port: 443,
            domain_hint: Some("sub.fresh-c2-2026.example".to_string()),
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("send NRD connect");

    // Verify IPC CheckDomainRisk queries the live NRD cache.
    let ipc = start_ipc_server(Arc::clone(&engine)).expect("start IPC");
    let pipe_client = pipe_name.clone();
    let (nrd_resp, clean_resp) = tokio::task::spawn_blocking(move || {
        let a = send_pipe_request(
            &pipe_client,
            &IpcRequest::CheckDomainRisk {
                domain: "api.fresh-c2-2026.example".to_string(),
            },
        );
        let b = send_pipe_request(
            &pipe_client,
            &IpcRequest::CheckDomainRisk {
                domain: "example.com".to_string(),
            },
        );
        (a, b)
    })
    .await
    .expect("join IPC client");

    match nrd_resp {
        IpcResponse::DomainRisk { is_nrd, .. } => assert!(is_nrd),
        other => panic!("expected DomainRisk, got {other:?}"),
    }
    match clean_resp {
        IpcResponse::DomainRisk {
            is_nrd,
            is_homograph,
            ..
        } => {
            assert!(!is_nrd);
            assert!(!is_homograph);
        }
        other => panic!("expected DomainRisk, got {other:?}"),
    }

    ipc.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");

    let snap = store
        .query_flight_recorder(50, Some(&proc_id.instance_id()))
        .expect("query flight recorder");
    let nrd_dns = snap
        .dns_queries
        .iter()
        .find(|d| d.query_name == "sub.fresh-c2-2026.example")
        .expect("NRD DNS row");
    assert!(nrd_dns.is_nrd, "NRD query must persist is_nrd=true");
    let clean_dns = snap
        .dns_queries
        .iter()
        .find(|d| d.query_name == "example.com")
        .expect("clean DNS row");
    assert!(!clean_dns.is_nrd, "clean query must persist is_nrd=false");

    let alerts = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .expect("list alerts");
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts[0].severity,
        AlertSeverity::High,
        "unknown process connecting to an NRD domain must escalate to High severity"
    );
    assert!(alerts[0].context_json.contains("\"is_nrd\":true"));

    // Restart with nrd_refresh_enabled: false and same cache_path -> reloads from disk cache!
    let store2 = LedrStore::open_in_memory().expect("open store2");
    let engine2 = DaemonEngine::start(
        store2,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            nrd_refresh_enabled: false,
            nrd_cache_path: Some(cache_path.clone()),
            ..DaemonConfig::default()
        },
    );
    assert_eq!(engine2.nrd_entry_count(), 2);
    assert!(engine2.assess_domain("evil-drop.xyz").is_nrd);
    engine2.shutdown_and_flush().await.expect("shutdown2");

    let _ = std::fs::remove_dir_all(&tmp_dir);
}

/// `DAEMON-P3-08`: Overdue suspended outbound network alert transitions to `EXPIRED_SUSPENDED`
/// WITHOUT resuming the process or lifting its WFP dynamic block filter (`L-07`).
#[tokio::test]
async fn daemon_p3_08_overdue_network_alert_expires_without_resuming_or_lifting_wfp() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            alert_timeout_ms: 1_000,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let old_ts = current_unix_ms() - 5_000;
    let proc_id = ProcessIdentity::new(5601, unix_ms_to_filetime(old_ts - 1_000));
    let exe_path = r"C:\Tools\stale_net_proc.exe";

    sender
        .send(SensorEvent::ProcessStart {
            identity: proc_id,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: exe_path.to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: proc_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: old_ts,
        })
        .await
        .expect("send connect");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );

    let expired = engine
        .expire_overdue_alerts(current_unix_ms())
        .expect("expire overdue");
    assert_eq!(expired, 1);

    let alerts = store
        .list_alerts(Some(AlertStatus::ExpiredSuspended), 10)
        .expect("list expired");
    assert_eq!(alerts.len(), 1);
    assert!(alerts[0].process_suspended);
    assert!(defense.resumes().is_empty(), "must never auto-resume on expiry");
    assert!(
        engine.has_active_wfp_filter(exe_path, None, false),
        "must never auto-lift WFP block filter on expiry"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-09`: Deleting an app-wide `NetworkAllow` rule for an actively running high-risk
/// executable removes the Permit filter and immediately re-arms the pre-emptive WFP Block filter.
#[tokio::test]
async fn daemon_p3_09_deleting_network_allow_rearms_preemptive_block_for_active_high_risk_process()
{
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe_path = r"C:\Users\alice\Downloads\allowed_tool.exe";
    let sha = "3333333333333333333333333333333333333333333333333333333333333333";
    inspector.register(exe_path, Some(sha), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-DL-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: exe_path.to_string(),
            sha256: Some(sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "user_triage".to_string(),
        })
        .expect("seed allow");

    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    assert!(engine.has_active_wfp_filter(exe_path, None, true));

    let proc_id = ProcessIdentity::new(5701, unix_ms_to_filetime(now_ms - 500));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: proc_id,
            parent_pid: 4,
            exe_path: exe_path.to_string(),
            command_line: exe_path.to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    let (deleted, _) = engine
        .delete_policy_rule("RULE-DL-ALLOW")
        .expect("delete allow rule");
    assert!(deleted);
    assert!(
        !engine.has_active_wfp_filter(exe_path, None, true),
        "Permit filter must be removed on delete"
    );
    assert!(
        engine.has_active_wfp_filter(exe_path, None, false),
        "Preemptive Block must be re-armed for active high-risk executable"
    );

    // Exiting the last active instance cleans up the Preemptive WFP filter (bounded BFE handles).
    engine
        .sender()
        .send(SensorEvent::ProcessStop {
            pid: proc_id.pid,
            exit_time_100ns: unix_ms_to_filetime(now_ms + 1_000),
            exit_code: 0,
        })
        .await
        .expect("send stop");
    assert!(
        wait_until(1_000, || !engine.has_active_wfp_filter(exe_path, None, false)).await,
        "Preemptive WFP block must be removed when the last running instance exits"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-10`: Materialized domain-scoped WFP filters (`DomainPolicy` Permit and Block)
/// survive unrelated `deploy_persisted_network_rules` reconciliations and are immediately removed
/// when their backing rule is deleted or overridden by a deny rule.
#[tokio::test]
async fn daemon_p3_10_domain_policy_filters_survive_unrelated_reconcile_and_purge_on_delete_or_deny()
{
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_sha = "4444444444444444444444444444444444444444444444444444444444444444";
    let app_exe = r"C:\Tools\domain_blocked_app.exe";
    inspector.register(ps_exe, Some(ps_sha), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-PS-DOMAIN-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ps_exe.to_string(),
            sha256: Some(ps_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("*.vendor.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed domain allow");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-APP-DOMAIN-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: app_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("*.evil-c2.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed domain block");

    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let sender = engine.sender();

    let ps_id = ProcessIdentity::new(6101, unix_ms_to_filetime(now_ms - 2_000));
    let app_id = ProcessIdentity::new(6102, unix_ms_to_filetime(now_ms - 1_000));
    for (id, exe) in [(ps_id, ps_exe), (app_id, app_exe)] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }

    let allow_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
    let block_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ps_id.pid,
            protocol: 6,
            dst_ip: allow_ip,
            dst_port: 443,
            domain_hint: Some("api.vendor.example".to_string()),
            timestamp_ms: now_ms,
        })
        .await
        .expect("send ps domain allow connect");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: app_id.pid,
            protocol: 6,
            dst_ip: block_ip,
            dst_port: 443,
            domain_hint: Some("gate.evil-c2.example".to_string()),
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("send app domain block connect");

    assert!(
        wait_until(2_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true)
                && engine.has_active_wfp_filter(app_exe, Some(block_ip), false)
        })
        .await,
        "both domain-scoped Permit and Block IP filters must materialize"
    );

    // Upserting and deleting an UNRELATED rule must NOT wipe either DomainPolicy filter!
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-UNRELATED-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Tools\unrelated.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms + 10,
            created_by: "user_policy".to_string(),
        })
        .expect("upsert unrelated");
    assert!(
        engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true),
        "DomainPolicy Permit must survive unrelated rule upsert/reconcile"
    );
    assert!(
        engine.has_active_wfp_filter(app_exe, Some(block_ip), false),
        "DomainPolicy Block must survive unrelated rule upsert/reconcile"
    );
    engine
        .delete_policy_rule("RULE-UNRELATED-BLOCK")
        .expect("delete unrelated");
    assert!(engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true));
    assert!(engine.has_active_wfp_filter(app_exe, Some(block_ip), false));

    // Deleting the backing domain allow & block rules must immediately purge both IP filters.
    engine
        .delete_policy_rule("RULE-PS-DOMAIN-ALLOW")
        .expect("delete domain allow");
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true),
        "deleting domain-scoped NetworkAllow must remove its materialized IP Permit"
    );
    engine
        .delete_policy_rule("RULE-APP-DOMAIN-BLOCK")
        .expect("delete domain block");
    assert!(
        !engine.has_active_wfp_filter(app_exe, Some(block_ip), false),
        "deleting domain-scoped NetworkBlock must remove its materialized IP Block"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-11`: Wildcard `NetworkBlock` rules are enforced immediately on `ProcessStart` for
/// general-path executables, and `NET_OUTBOUND` alert deduplication never bypasses an explicit
/// `NetworkBlock` (including over IPv4-mapped IPv6 `::ffff:a.b.c.d`).
#[tokio::test]
async fn daemon_p3_11_wildcard_block_on_process_start_and_dedup_never_bypasses_network_block() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // (a) Wildcard NetworkBlock saved before a general-path executable starts -> enforced at ProcessStart!
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-WILD-UNTRUSTED".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Untrusted\*.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("upsert wildcard block");

    let stealer_exe = r"C:\Untrusted\stealer.exe";
    let stealer_id = ProcessIdentity::new(6201, unix_ms_to_filetime(now_ms - 500));
    sender
        .send(SensorEvent::ProcessStart {
            identity: stealer_id,
            parent_pid: 4,
            exe_path: stealer_exe.to_string(),
            command_line: stealer_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("send wildcard-matched start");
    assert!(
        wait_until(2_000, || engine.has_active_wfp_filter(stealer_exe, None, false)).await,
        "wildcard NetworkBlock must be applied immediately on ProcessStart for general-path exe"
    );

    // (b) Process already emitted NET_OUTBOUND (e.g. when WFP failed), then operator adds an
    //     IP-scoped NetworkBlock -> connecting via IPv4-mapped IPv6 MUST NOT be dedup-bypassed!
    let multi_exe = r"C:\Tools\multi_dest.exe";
    let multi_id = ProcessIdentity::new(6202, unix_ms_to_filetime(now_ms - 400));
    sender
        .send(SensorEvent::ProcessStart {
            identity: multi_id,
            parent_pid: 4,
            exe_path: multi_exe.to_string(),
            command_line: multi_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("send multi start");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    defense.set_fail_wfp_add(true);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: multi_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("first connect sets NET_OUTBOUND dedup");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );

    defense.set_fail_wfp_add(false);
    let blocked_v4 = Ipv4Addr::new(198, 51, 100, 66);
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-MULTI-IP-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: multi_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some(blocked_v4.to_string()),
            created_at_ms: now_ms + 20,
            created_by: "user_policy".to_string(),
        })
        .expect("upsert IP block");

    // Connect over dual-stack IPv4-mapped IPv6 `::ffff:198.51.100.66`.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: multi_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V6(blocked_v4.to_ipv6_mapped()),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("second connect to blocked IP via mapped IPv6");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.iter().any(|a| a.rule_id == "LEDR-NET-POLICY-BLOCK"))
                .unwrap_or(false)
        })
        .await,
        "explicit NetworkBlock must still fire and enforce even after NET_OUTBOUND dedup"
    );
    assert!(engine.has_active_wfp_filter(multi_exe, Some(IpAddr::V4(blocked_v4)), false));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-12`: Sibling alert `record_alert` failure unbinds shared transient containment so
/// resolving the surviving alert cleanly lifts the block; sibling alerts sharing a `Preemptive`
/// block keep the block active until the last unresolved alert is resolved.
#[tokio::test]
async fn daemon_p3_12_sibling_alert_unbind_on_record_error_and_preemptive_sibling_guard() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // (a) Shared TransientContainment: P1 records A1, P2 shares H1 then record_alert(A2) fails ->
    //     A2 must be unbound so AllowOnce on A1 lifts H1 cleanly!
    let shared_exe = r"C:\Tools\shared_general.exe";
    let p1 = ProcessIdentity::new(6301, unix_ms_to_filetime(now_ms - 2_000));
    let p2 = ProcessIdentity::new(6302, unix_ms_to_filetime(now_ms - 1_500));
    for p in [p1, p2] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: shared_exe.to_string(),
                command_line: shared_exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("p1 connect");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let a1 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();

    engine.set_fail_record_alert_for_test(true);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p2.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("p2 connect failing record_alert");
    assert!(
        wait_until(2_000, || defense.resumes().contains(&p2)).await,
        "p2 suspension must be compensated on record_alert failure"
    );
    engine.set_fail_record_alert_for_test(false);

    engine
        .resolve_alert(&a1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on A1");
    assert!(
        !engine.has_active_wfp_filter(shared_exe, None, false),
        "failed sibling alert A2 must not leak a transient binding pinning the WFP block"
    );

    // (b) Shared Preemptive block: P3 & P4 both emit unresolved alerts -> resolving A3 alone must
    //     keep Preemptive block active while A4 is still unresolved; resolving A4 lifts it.
    let dl_exe = r"C:\Users\alice\Downloads\shared_dl.exe";
    let p3 = ProcessIdentity::new(6303, unix_ms_to_filetime(now_ms - 1_000));
    let p4 = ProcessIdentity::new(6304, unix_ms_to_filetime(now_ms - 900));
    for p in [p3, p4] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: dl_exe.to_string(),
                command_line: dl_exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send dl start");
        sender
            .send(SensorEvent::NetworkConnect {
                pid: p.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms + 20,
            })
            .await
            .expect("send dl connect");
    }
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    let pending_dl = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap();
    engine
        .resolve_alert(&pending_dl[0].alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce A3");
    assert!(
        engine.has_active_wfp_filter(dl_exe, None, false),
        "Preemptive block must remain active while sibling alert A4 is still unresolved"
    );
    engine
        .resolve_alert(&pending_dl[1].alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce A4");
    assert!(
        !engine.has_active_wfp_filter(dl_exe, None, false),
        "Preemptive block must lift once the last bound alert resolves"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-13`: Server-side IPC `UpsertRule` rejects invalid `L-04` and `AUTO-02` rules with
/// `INVALID_RULE` and stores zero invalid rows in SQLite.
#[tokio::test]
async fn daemon_p3_13_ipc_upsert_rule_enforces_server_side_l04_and_auto02_validation() {
    let store = LedrStore::open_in_memory().expect("open store");
    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            ..DaemonConfig::default()
        },
    );
    let ipc = start_ipc_server(Arc::clone(&engine)).expect("start IPC");
    let now_ms = current_unix_ms();

    let invalid_rules = vec![
        AllowlistRuleRecord {
            rule_id: "BAD-NO-IDENTITY".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\app.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        },
        AllowlistRuleRecord {
            rule_id: "BAD-ZERO-THUMBPRINT".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\app.exe".to_string(),
            sha256: None,
            signer_subject: Some("CN=Vendor".to_string()),
            root_thumbprint: Some("0".repeat(40)),
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        },
        AllowlistRuleRecord {
            rule_id: "BAD-SHORT-SHA".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\app.exe".to_string(),
            sha256: Some("deadbeef".to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        },
        AllowlistRuleRecord {
            rule_id: "BAD-BLOCK-LSASS".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Windows\System32\lsass.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        },
    ];

    let pipe_client = pipe_name.clone();
    let responses: Vec<IpcResponse> = tokio::task::spawn_blocking(move || {
        invalid_rules
            .into_iter()
            .map(|rule| send_pipe_request(&pipe_client, &IpcRequest::UpsertRule { rule }))
            .collect()
    })
    .await
    .expect("join IPC client");

    for resp in responses {
        match resp {
            IpcResponse::Error { code, .. } => assert_eq!(code, "INVALID_RULE"),
            other => panic!("expected INVALID_RULE error, got {other:?}"),
        }
    }
    assert!(
        store.list_rules(None).expect("list rules").is_empty(),
        "no invalid rules may be stored in SQLite"
    );

    ipc.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-14`: Local DNS history first-seen check (`L-14`, `has_seen_dns_domain`) is wired
/// into outbound network alert `context_json`.
#[tokio::test]
async fn daemon_p3_14_first_seen_dns_domain_wired_into_network_alert_context() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let p1 = ProcessIdentity::new(6401, unix_ms_to_filetime(now_ms - 2_000));
    let p2 = ProcessIdentity::new(6402, unix_ms_to_filetime(now_ms - 1_000));
    for (p, exe) in [
        (p1, r"C:\Tools\first_seen_probe.exe"),
        (p2, r"C:\Tools\known_domain_probe.exe"),
    ] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }

    // Seed historical DNS entry with trailing dot and flush it into SQLite.
    store
        .ingest_event(
            &SensorEvent::DnsQuery {
                pid: p2.pid,
                query_name: "Previously-Seen.Example.".to_string(),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                timestamp_ms: now_ms - 500,
            },
            Some(&p2.instance_id()),
            false,
            "OBSERVED",
        )
        .expect("seed dns");
    store.flush_batch().expect("flush dns");

    sender
        .send(SensorEvent::NetworkConnect {
            pid: p1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
            dst_port: 443,
            domain_hint: Some("never-seen-before.example".to_string()),
            timestamp_ms: now_ms,
        })
        .await
        .expect("send first-seen connect");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p2.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("previously-seen.example".to_string()),
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("send already-seen connect");

    engine.shutdown_and_flush().await.expect("shutdown");

    let alerts = store.list_alerts(Some(AlertStatus::Pending), 10).expect("list");
    let first_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p1.instance_id().as_str()))
        .expect("p1 alert");
    let second_alert = alerts
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p2.instance_id().as_str()))
        .expect("p2 alert");

    assert!(
        first_alert
            .context_json
            .contains("\"is_first_seen_domain\":true"),
        "unseen domain must set is_first_seen_domain=true: {}",
        first_alert.context_json
    );
    assert!(
        second_alert
            .context_json
            .contains("\"is_first_seen_domain\":false"),
        "historically seen domain must set is_first_seen_domain=false: {}",
        second_alert.context_json
    );
}

/// `DAEMON-P3-15`: After a failed `AllowPermanent` resume on a pre-emptively blocked process,
/// `maybe_apply_preemptive_wfp_block` restores the `Preemptive` block BEFORE `rollback_allow_once_wfp`
/// rebinds `alert_id` (and displaced sibling alerts), so a sibling `AllowOnce` cannot prematurely
/// drop the block while the failed alert remains unresolved.
#[tokio::test]
async fn daemon_p3_15_failed_allow_permanent_rollback_preserves_alert_binding_on_preemptive_block()
{
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Users\alice\Downloads\rollback_binding_test.exe";
    let sha = "5555555555555555555555555555555555555555555555555555555555555555";
    inspector.register(exe, Some(sha), None);

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // P1 uses the current live PID so `resume_process` failure is confirmed-live (not tolerated).
    let live_pid = std::process::id();
    let p1 = ProcessIdentity::new(live_pid, unix_ms_to_filetime(now_ms - 2_000));
    let p2 = ProcessIdentity::new(6502, unix_ms_to_filetime(now_ms - 1_500));

    for p in [p1, p2] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
        sender
            .send(SensorEvent::NetworkConnect {
                pid: p.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 40)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms,
            })
            .await
            .expect("send connect");
    }

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    let pending = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap();
    let a1 = pending
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p1.instance_id().as_str()))
        .expect("a1")
        .clone();
    let a2 = pending
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p2.instance_id().as_str()))
        .expect("a2")
        .clone();

    // Inject resume failure on P1 and try app-wide AllowPermanent on A1.
    defense.add_failing_resume_pid(live_pid);
    let err = engine
        .resolve_alert(
            &a1.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect_err("AllowPermanent must fail when live process P1 fails to resume");
    assert!(err.contains("still running") || err.contains("Access is denied"));

    // Preemptive block must be restored cleanly (exactly 1 active filter, no Permit).
    assert!(engine.has_active_wfp_filter(exe, None, false));
    assert!(!engine.has_active_wfp_filter(exe, None, true));
    assert_eq!(
        defense
            .active_wfp()
            .iter()
            .filter(|w| w.exe_path.eq_ignore_ascii_case(exe))
            .count(),
        1
    );

    // Resolving sibling A2 with AllowOnce MUST NOT drop the Preemptive block because A1
    // remained properly rebound during rollback!
    engine
        .resolve_alert(&a2.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on sibling A2");
    assert!(
        engine.has_active_wfp_filter(exe, None, false),
        "Preemptive block must remain active after sibling AllowOnce while failed alert A1 is still unresolved"
    );

    // Once P1's resume recovers and A1 also resolves AllowOnce, the block finally lifts.
    defense.clear_failing_resume_pid(live_pid);
    engine
        .resolve_alert(&a1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on A1 after resume recovers");
    assert!(
        !engine.has_active_wfp_filter(exe, None, false),
        "Preemptive block must lift once the last bound alert A1 resolves"
    );

    // Reverse order verification: on a second pre-emptively blocked binary, after A3 fails
    // AllowPermanent resume, resolving A3 FIRST (after recovery) must STILL keep the Preemptive
    // block active because displaced sibling A4's binding was also restored during rollback!
    let exe2 = r"C:\Users\alice\Downloads\rollback_sibling_preserved.exe";
    let sha2 = "5656565656565656565656565656565656565656565656565656565656565656";
    let p3 = ProcessIdentity::new(live_pid, unix_ms_to_filetime(now_ms + 1_000));
    let p4 = ProcessIdentity::new(6504, unix_ms_to_filetime(now_ms + 1_500));
    for p in [p3, p4] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: exe2.to_string(),
                command_line: exe2.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start2");
        sender
            .send(SensorEvent::NetworkConnect {
                pid: p.pid,
                protocol: 6,
                dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 41)),
                dst_port: 443,
                domain_hint: None,
                timestamp_ms: now_ms + 2_000,
            })
            .await
            .expect("send connect2");
    }
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    let pending2 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap();
    let a3 = pending2
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p3.instance_id().as_str()))
        .expect("a3")
        .clone();
    let a4 = pending2
        .iter()
        .find(|a| a.process_instance_id.as_deref() == Some(p4.instance_id().as_str()))
        .expect("a4")
        .clone();
    let _ = sha2;

    defense.add_failing_resume_pid(live_pid);
    assert!(engine
        .resolve_alert(
            &a3.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .is_err());
    defense.clear_failing_resume_pid(live_pid);
    engine
        .resolve_alert(&a3.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on A3");
    assert!(
        engine.has_active_wfp_filter(exe2, None, false),
        "displaced sibling A4 binding must keep Preemptive block active after A3 resolves"
    );
    engine
        .resolve_alert(&a4.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on A4");
    assert!(!engine.has_active_wfp_filter(exe2, None, false));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-16`: `AllowPermanent { use_signer_if_available: true }` ignores an all-zero
/// `root_thumbprint` (`L-04`) and falls back to persisting a valid SHA-256 allowlist rule.
#[tokio::test]
async fn daemon_p3_16_allow_permanent_falls_back_to_sha256_on_all_zero_root_thumbprint() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let exe = r"C:\Tools\zero_thumbprint_app.exe";
    let sha = "6666666666666666666666666666666666666666666666666666666666666666";
    inspector.register(
        exe,
        Some(sha),
        Some(("CN=Broken Cert Vendor", "0000000000000000000000000000000000000000")),
    );

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    let p = ProcessIdentity::new(6601, unix_ms_to_filetime(now_ms - 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: p,
            parent_pid: 4,
            exe_path: exe.to_string(),
            command_line: exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("send start");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("send connect");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let alert = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();

    let outcome = engine
        .resolve_alert_with_outcome(
            &alert.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: true,
                allow_dest: None,
            },
        )
        .expect("AllowPermanent falls back to SHA-256");
    let rule_id = outcome.saved_rule_id.expect("saved rule id");
    let saved = store.get_rule(&rule_id).unwrap().expect("rule exists");
    assert!(
        ledr_rules::validate_policy_rule(&saved).is_ok(),
        "saved fallback rule must satisfy L-04 policy validation"
    );
    assert_eq!(saved.sha256.as_deref(), Some(sha));
    assert!(saved.signer_subject.is_none());
    assert!(saved.root_thumbprint.is_none());
    assert!(
        engine.has_active_wfp_filter(exe, None, true),
        "fallback SHA-256 rule must deploy an active Permit WFP filter"
    );

    // Subsequent connection must be ALLOWED (not re-alerted).
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 12)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("send follow-up connect");

    engine.shutdown_and_flush().await.expect("shutdown");
    assert!(
        store
            .list_alerts(Some(AlertStatus::Pending), 10)
            .unwrap()
            .is_empty(),
        "SHA-256 fallback rule must permit follow-up connections without re-alerting"
    );
}

/// `DAEMON-P3-17`: `SensorEvent::DnsQuery` with `resolved_ips` pre-materializes `DomainPolicy`
/// IP Permit (over an active app-wide block) and `DomainPolicy` IP Block filters BEFORE any
/// `NetworkConnect` arrives, respects deny-overrides-allow, ignores non-external IPs, and skips
/// `ProtectedOs` binaries.
#[tokio::test]
async fn daemon_p3_17_dns_query_prematerializes_domain_policy_wfp_filters_before_connect() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_sha = "7777777777777777777777777777777777777777777777777777777777777777";
    let app_exe = r"C:\Tools\dns_blocked_app.exe";
    let svchost_exe = r"C:\Windows\System32\svchost.exe";
    inspector.register(ps_exe, Some(ps_sha), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-DNS-PS-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ps_exe.to_string(),
            sha256: Some(ps_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("*.packages.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed domain allow");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-DNS-PS-DENY-SUB".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: ps_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("bad.packages.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed overriding domain block");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-DNS-APP-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: app_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("*.c2-drop.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed app domain block");

    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );
    let sender = engine.sender();

    let ps_id = ProcessIdentity::new(6701, unix_ms_to_filetime(now_ms - 2_000));
    let app_id = ProcessIdentity::new(6702, unix_ms_to_filetime(now_ms - 1_500));
    let svc_id = ProcessIdentity::new(6703, unix_ms_to_filetime(now_ms - 1_000));
    for (id, exe) in [(ps_id, ps_exe), (app_id, app_exe), (svc_id, svchost_exe)] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }
    assert!(
        wait_until(2_000, || engine.has_active_wfp_filter(ps_exe, None, false)).await,
        "powershell.exe must have pre-emptive app-wide block on ProcessStart"
    );

    let allow_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 21));
    let loopback_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let deny_sub_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 22));
    let c2_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 88));

    // Send ONLY DnsQuery events (NO NetworkConnect yet!).
    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_id.pid,
            query_name: "cdn.packages.example.".to_string(),
            query_type: 1,
            resolved_ips: vec![allow_ip, loopback_ip],
            timestamp_ms: now_ms,
        })
        .await
        .expect("send ps allowed dns");
    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_id.pid,
            query_name: "bad.packages.example".to_string(),
            query_type: 1,
            resolved_ips: vec![deny_sub_ip],
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("send ps denied sub dns");
    sender
        .send(SensorEvent::DnsQuery {
            pid: app_id.pid,
            query_name: "stage1.c2-drop.example".to_string(),
            query_type: 1,
            resolved_ips: vec![c2_ip],
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("send app blocked dns");
    sender
        .send(SensorEvent::DnsQuery {
            pid: svc_id.pid,
            query_name: "stage1.c2-drop.example".to_string(),
            query_type: 1,
            resolved_ips: vec![c2_ip],
            timestamp_ms: now_ms + 3,
        })
        .await
        .expect("send svchost dns");

    assert!(
        wait_until(2_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true)
                && engine.has_active_wfp_filter(ps_exe, Some(deny_sub_ip), false)
                && engine.has_active_wfp_filter(app_exe, Some(c2_ip), false)
        })
        .await,
        "DnsQuery must pre-materialize DomainPolicy Permit & Block WFP filters before NetworkConnect"
    );
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(loopback_ip), true),
        "loopback IPs in DnsQuery must never create DomainPolicy WFP filters"
    );
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(deny_sub_ip), true),
        "deny-overrides-allow must materialize Block (not Permit) for bad.packages.example"
    );
    assert!(
        !engine.has_active_wfp_filter(svchost_exe, Some(c2_ip), false),
        "ProtectedOs process must never receive WFP Block filter on DnsQuery"
    );

    // Deleting the backing domain rules must immediately purge the pre-materialized IP filters.
    engine
        .delete_policy_rule("RULE-DNS-PS-ALLOW")
        .expect("delete ps allow");
    engine
        .delete_policy_rule("RULE-DNS-APP-BLOCK")
        .expect("delete app block");
    assert!(!engine.has_active_wfp_filter(ps_exe, Some(allow_ip), true));
    assert!(!engine.has_active_wfp_filter(app_exe, Some(c2_ip), false));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-18`: Startup pre-restriction (`DaemonConfig::preemptive_startup_executables`)
/// installs `Preemptive` WFP blocks BEFORE any `ProcessStart`, retains them across `ProcessStop`
/// (while transient `Downloads` filters still clean up on exit), honors `AUTO-02` protected OS
/// exclusions, and yields to app-wide `NetworkAllow` (re-arming immediately when deleted).
#[tokio::test]
async fn daemon_p3_18_startup_prerestriction_retention_across_stop_and_allow_override() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let node_exe = r"C:\Program Files\nodejs\node.exe";
    let lsass_exe = r"C:\Windows\System32\lsass.exe";
    let dl_exe = r"C:\Users\alice\Downloads\transient_tool.exe";

    let ps_sha = "8888888888888888888888888888888888888888888888888888888888888888";
    let node_sha = "9999999999999999999999999999999999999999999999999999999999999999";
    inspector.register(ps_exe, Some(ps_sha), None);
    inspector.register(node_exe, Some(node_sha), None);

    let now_ms = current_unix_ms();
    // Pre-seed app-wide NetworkAllow for node.exe BEFORE startup -> startup must install Permit,
    // NOT Preemptive Block, for node.exe, while powershell.exe receives Preemptive Block.
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-NODE-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: node_exe.to_string(),
            sha256: Some(node_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed node allow");

    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![
                ps_exe.to_string(),
                node_exe.to_string(),
                lsass_exe.to_string(), // Must be ignored per AUTO-02!
            ],
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );

    // BEFORE any ProcessStart:
    // - powershell.exe is pre-emptively blocked,
    // - node.exe is overridden by app-wide NetworkAllow (Permit, no Block),
    // - lsass.exe is never blocked (AUTO-02).
    assert!(
        engine.has_active_wfp_filter(ps_exe, None, false),
        "powershell.exe must be pre-emptively blocked at startup before any ProcessStart"
    );
    assert!(
        engine.has_active_wfp_filter(node_exe, None, true)
            && !engine.has_active_wfp_filter(node_exe, None, false),
        "app-wide NetworkAllow must override startup pre-restriction for node.exe"
    );
    assert!(
        !engine.has_active_wfp_filter(lsass_exe, None, false),
        "protected OS binary must never be startup pre-restricted"
    );

    // Start & stop BOTH powershell.exe (startup-pinned) and Downloads exe (transient).
    let sender = engine.sender();
    let ps_id = ProcessIdentity::new(6801, unix_ms_to_filetime(now_ms - 1_000));
    let dl_id = ProcessIdentity::new(6802, unix_ms_to_filetime(now_ms - 900));
    for (id, exe) in [(ps_id, ps_exe), (dl_id, dl_exe)] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: id,
                parent_pid: 4,
                exe_path: exe.to_string(),
                command_line: exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("send start");
    }
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(dl_exe, None, false)).await,
        "Downloads exe receives transient Preemptive block on ProcessStart"
    );

    for id in [ps_id, dl_id] {
        sender
            .send(SensorEvent::ProcessStop {
                pid: id.pid,
                exit_time_100ns: unix_ms_to_filetime(now_ms + 500),
                exit_code: 0,
            })
            .await
            .expect("send stop");
    }
    assert!(
        wait_until(1_000, || !engine.has_active_wfp_filter(dl_exe, None, false)).await,
        "transient Downloads Preemptive block must still clean up on ProcessStop"
    );
    assert!(
        engine.has_active_wfp_filter(ps_exe, None, false),
        "startup-pinned powershell.exe Preemptive block MUST stay intact across ProcessStop"
    );

    // Deleting node.exe's app-wide NetworkAllow must immediately arm its startup Preemptive block
    // even with zero running node.exe instances!
    engine
        .delete_policy_rule("RULE-NODE-ALLOW")
        .expect("delete node allow");
    assert!(
        !engine.has_active_wfp_filter(node_exe, None, true)
            && engine.has_active_wfp_filter(node_exe, None, false),
        "deleting app-wide NetworkAllow must immediately re-arm startup Preemptive block for node.exe"
    );

    // Granting AllowOnce to a running startup-pinned node.exe lifts the block for that instance,
    // survives an unrelated reconciliation, and automatically re-arms on ProcessStop.
    let node_id = ProcessIdentity::new(6803, unix_ms_to_filetime(now_ms + 600));
    sender
        .send(SensorEvent::ProcessStart {
            identity: node_id,
            parent_pid: 4,
            exe_path: node_exe.to_string(),
            command_line: node_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start node");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: node_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 700,
        })
        .await
        .expect("connect node");
    assert!(
        wait_until(2_000, || {
            engine
                .store()
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let node_alert = engine
        .store()
        .list_alerts(Some(AlertStatus::Pending), 10)
        .unwrap()[0]
        .clone();
    engine
        .resolve_alert(&node_alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce node");
    assert!(!engine.has_active_wfp_filter(node_exe, None, false));
    // Unrelated reconciliation must NOT clobber an active AllowOnce grant.
    let _ = engine.deploy_persisted_network_rules();
    assert!(!engine.has_active_wfp_filter(node_exe, None, false));
    // Once the AllowOnce node.exe instance exits, startup pre-restriction automatically re-arms!
    sender
        .send(SensorEvent::ProcessStop {
            pid: node_id.pid,
            exit_time_100ns: unix_ms_to_filetime(now_ms + 800),
            exit_code: 0,
        })
        .await
        .expect("stop node");
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(node_exe, None, false)).await,
        "startup-pinned node.exe Preemptive block must re-arm when AllowOnce instance exits"
    );

    // Upserting a wildcard app-wide NetworkAllow for powershell.exe overrides its startup Preemptive block.
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-PS-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Windows\System32\WindowsPowerShell\*\powershell.exe".to_string(),
            sha256: Some(ps_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms + 1_000,
            created_by: "user_policy".to_string(),
        })
        .expect("upsert ps wildcard allow");
    assert!(
        engine.has_active_wfp_filter(ps_exe, None, true)
            && !engine.has_active_wfp_filter(ps_exe, None, false),
        "app-wide NetworkAllow (including wildcard pattern) must replace startup Preemptive block with Permit"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}
