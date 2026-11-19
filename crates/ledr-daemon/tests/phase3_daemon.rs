//! Phase 3 integration tests for outbound firewall, coupled WFP + suspension containment,
//! deny-overrides-allow reconciliation, and live NRD domain cache (`L-03`, `L-04`, `L-07`,
//! `L-13`, `AUTO-02`, `AUTO-04`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ledr_daemon::{
    start_ipc_server, BinaryInspector, DaemonConfig, DaemonEngine, NotificationDispatcher,
    PolicyRuleError, WindowsBinaryInspector,
};
use ledr_proto::{
    read_ipc_frame, write_ipc_frame, ActiveDefenseController, AlertDecision, AlertRecord,
    AlertSeverity, AlertStatus, AllowlistRuleRecord, AuthenticodeInfo, IpcRequest, IpcResponse,
    ProcessIdentity, RuleScope, SensorEvent,
};
use ledr_rules::{BinaryIdentity, EarlyPruner, SigmaEngine};
use ledr_sensor_win::WfpDropEvent;
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
    fail_wfp_add_permits: Mutex<bool>,
    fail_wfp_add_exes: Mutex<Vec<String>>,
    fail_wfp_remove: Mutex<bool>,
    fail_wfp_remove_handles: Mutex<Vec<u64>>,
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

    fn set_fail_wfp_add_permits(&self, fail: bool) {
        *self
            .fail_wfp_add_permits
            .lock()
            .expect("lock fail_wfp_add_permits") = fail;
    }

    fn add_fail_wfp_exe(&self, exe_substr: &str) {
        self.fail_wfp_add_exes
            .lock()
            .expect("lock fail_wfp_add_exes")
            .push(exe_substr.to_ascii_lowercase());
    }

    fn set_fail_wfp_remove(&self, fail: bool) {
        *self.fail_wfp_remove.lock().expect("lock fail_wfp_remove") = fail;
    }

    fn add_fail_wfp_remove_handle(&self, filter_id: u64) {
        self.fail_wfp_remove_handles
            .lock()
            .expect("lock fail_wfp_remove_handles")
            .push(filter_id);
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
        let exe_lower = exe_path.to_string_lossy().to_ascii_lowercase();
        let exe_matched = self
            .fail_wfp_add_exes
            .lock()
            .expect("lock fail_wfp_add_exes")
            .iter()
            .any(|pat| exe_lower.contains(pat));
        if *self.fail_wfp_add.lock().expect("lock fail_wfp_add")
            || (allow && *self.fail_wfp_add_permits.lock().expect("lock fail_wfp_add_permits"))
            || exe_matched
        {
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
        if *self.fail_wfp_remove.lock().expect("lock fail_wfp_remove")
            || self
                .fail_wfp_remove_handles
                .lock()
                .expect("lock fail_wfp_remove_handles")
                .contains(&filter_id)
        {
            return Err(format!("mock WFP remove_wfp_rule failure for {filter_id}"));
        }
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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
        inspector.clone(),
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

/// `DAEMON-P3-19` (`#2`): Multi-instance `AllowOnce` preserves the exemption when sibling
/// instances start or connect externally (deferring shared app-wide WFP block while still
/// suspending the new instance and setting `"wfp_shared_allow_once_deferred": true`), and
/// restores the automatic `Preemptive` block when the last `AllowOnce` instance exits while
/// startup-pinned or another active instance remains.
#[tokio::test]
async fn daemon_p3_19_allow_once_multi_instance_preserves_sibling_and_restores_on_exit() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let dl_exe = r"C:\Users\alice\Downloads\multi_tool.exe";

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![ps_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let sender = engine.sender();
    let now_ms = current_unix_ms();

    // Part A: Startup-pinned powershell.exe (P1 gets AllowOnce, then P2 starts & connects)
    assert!(engine.has_active_wfp_filter(ps_exe, None, false));
    let ps1 = ProcessIdentity::new(7101, unix_ms_to_filetime(now_ms - 5_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps1,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps1");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ps1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms,
        })
        .await
        .expect("connect ps1");
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
    engine
        .resolve_alert(&a1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce ps1");
    assert!(
        !engine.has_active_wfp_filter(ps_exe, None, false),
        "AllowOnce on P1 lifts Preemptive WFP block"
    );

    // P2 starts -> MUST NOT re-apply Preemptive block while P1 holds AllowOnce.
    let ps2 = ProcessIdentity::new(7102, unix_ms_to_filetime(now_ms - 4_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps2,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps2");
    assert!(wait_until(1_000, || engine.active_process_table_len() >= 2).await);
    assert!(
        !engine.has_active_wfp_filter(ps_exe, None, false),
        "starting sibling P2 must NOT re-arm app-wide Preemptive block while P1 has AllowOnce"
    );

    // P1 follow-up connect remains ALLOWED.
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ps1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("follow-up connect ps1");

    // P2 external connect -> P2 MUST suspend and emit alert with deferred WFP flag,
    // without adding an app-wide WFP block that would sever P1!
    sender
        .send(SensorEvent::NetworkConnect {
            pid: ps2.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("connect ps2");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let a2 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    assert!(a2.process_suspended);
    assert!(defense.suspends().contains(&ps2));
    assert!(
        !engine.has_active_wfp_filter(ps_exe, None, false),
        "app-wide TransientContainment WFP block must be deferred while sibling P1 holds AllowOnce"
    );
    assert!(
        a2.context_json
            .contains("\"wfp_shared_allow_once_deferred\":true"),
        "alert context must record wfp_shared_allow_once_deferred=true: {}",
        a2.context_json
    );

    // P1 exits -> startup-pinned Preemptive block immediately restores!
    sender
        .send(SensorEvent::ProcessStop {
            pid: ps1.pid,
            exit_time_100ns: unix_ms_to_filetime(now_ms + 20),
            exit_code: 0,
        })
        .await
        .expect("stop ps1");
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(ps_exe, None, false)).await,
        "startup-pinned Preemptive block must restore when last AllowOnce instance P1 exits"
    );
    engine
        .resolve_alert(
            &a2.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: false,
            },
        )
        .expect("terminate ps2");

    // Part B: Non-startup high-risk Downloads executable with two active instances (P3, P4).
    let dl1 = ProcessIdentity::new(7103, unix_ms_to_filetime(now_ms - 3_000));
    let dl2 = ProcessIdentity::new(7104, unix_ms_to_filetime(now_ms - 2_000));
    let dl3 = ProcessIdentity::new(7105, unix_ms_to_filetime(now_ms - 1_000));
    for p in [dl1, dl2] {
        sender
            .send(SensorEvent::ProcessStart {
                identity: p,
                parent_pid: 4,
                exe_path: dl_exe.to_string(),
                command_line: dl_exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start dl");
    }
    assert!(wait_until(1_000, || engine.has_active_wfp_filter(dl_exe, None, false)).await);

    sender
        .send(SensorEvent::NetworkConnect {
            pid: dl1.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 30)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("connect dl1");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let a_dl1 = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(&a_dl1.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce dl1");
    assert!(!engine.has_active_wfp_filter(dl_exe, None, false));

    // dl3 starts while dl1 holds AllowOnce -> no Preemptive block added yet.
    sender
        .send(SensorEvent::ProcessStart {
            identity: dl3,
            parent_pid: 4,
            exe_path: dl_exe.to_string(),
            command_line: dl_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start dl3");
    assert!(wait_until(1_000, || engine.active_process_table_len() >= 5).await);
    assert!(!engine.has_active_wfp_filter(dl_exe, None, false));

    // dl1 (only AllowOnce instance) stops while dl2 and dl3 are STILL active -> Preemptive
    // block MUST restore automatically!
    sender
        .send(SensorEvent::ProcessStop {
            pid: dl1.pid,
            exit_time_100ns: unix_ms_to_filetime(now_ms + 40),
            exit_code: 0,
        })
        .await
        .expect("stop dl1");
    assert!(
        wait_until(1_000, || engine.has_active_wfp_filter(dl_exe, None, false)).await,
        "Preemptive block must restore when last AllowOnce exits and sibling instances remain active"
    );

    // When dl2 and dl3 also stop, the non-startup Preemptive block cleans up.
    for p in [dl2, dl3] {
        sender
            .send(SensorEvent::ProcessStop {
                pid: p.pid,
                exit_time_100ns: unix_ms_to_filetime(now_ms + 50),
                exit_code: 0,
            })
            .await
            .expect("stop remaining dl");
    }
    assert!(
        wait_until(1_000, || !engine.has_active_wfp_filter(dl_exe, None, false)).await,
        "Preemptive block must clean up once all non-startup instances exit"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-20` (`#3`): Shared-IP conflict visibility & deny-overrides-allow precedence when
/// a blocked domain and an allowed domain resolve to the same CDN/proxy IP address.
#[tokio::test]
async fn daemon_p3_20_shared_ip_block_precedence_for_domain_rules() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_sha = "1212121212121212121212121212121212121212121212121212121212121212";
    inspector.register(ps_exe, Some(ps_sha), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-SHARED-BLOCK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: ps_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("blocked.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed domain block");
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-SHARED-ALLOW".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ps_exe.to_string(),
            sha256: Some(ps_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("api.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed domain allow");

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
    let ps_id = ProcessIdentity::new(7201, unix_ms_to_filetime(now_ms - 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps_id,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps");

    let shared_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50));
    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_id.pid,
            query_name: "blocked.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: now_ms,
        })
        .await
        .expect("dns blocked");
    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_id.pid,
            query_name: "api.example".to_string(),
            query_type: 1,
            resolved_ips: vec![shared_ip],
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("dns allowed same IP");

    assert!(
        wait_until(2_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(shared_ip), false)
        })
        .await,
        "shared CDN IP must keep the IP-level Block filter"
    );
    assert!(
        !engine.has_active_wfp_filter(ps_exe, Some(shared_ip), true),
        "allowed domain sharing the same IP must not override the IP-level Block filter"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-21` (`#4`, `Analysis #7`): WFP synchronization failures compensate SQLite and surface
/// `WFP_SYNC_ERROR` over IPC (`UpsertRule` / `DeleteRule`) and fail alert resolution rollback
/// (`AllowPermanent` / `TerminateAndBlock`) without silently diverging SQLite vs BFE; startup
/// pre-emptive failures never fail unrelated user policy mutations; scope changes away from
/// network re-arm active pre-emptive blocks.
#[tokio::test]
async fn daemon_p3_21_wfp_sync_failure_compensation_ipc_error_and_scope_change() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let startup_ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let app_exe = r"C:\Tools\sync_test_app.exe";
    let dl_exe = r"C:\Users\alice\Downloads\scope_swap.exe";
    let dl_sha = "3434343434343434343434343434343434343434343434343434343434343434";
    let app_sha = "4545454545454545454545454545454545454545454545454545454545454545";
    inspector.register(dl_exe, Some(dl_sha), None);
    inspector.register(app_exe, Some(app_sha), None);

    // Startup-pinned interpreter fails WFP add — user policy mutations for other exes must STILL succeed!
    defense.add_fail_wfp_exe("powershell.exe");

    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            preemptive_startup_executables: vec![startup_ps.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let ipc = start_ipc_server(Arc::clone(&engine)).expect("start IPC");
    let now_ms = current_unix_ms();

    // 1. Upsert rule succeeds despite startup-pinned interpreter failing WFP!
    let valid_block = AllowlistRuleRecord {
        rule_id: "RULE-SYNC-TEST".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: app_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "user_policy".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let rule_clone = valid_block.clone();
    let ack = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: rule_clone })
    })
    .await
    .expect("join IPC");
    assert!(matches!(ack, IpcResponse::Ack { .. }));
    assert!(engine.has_active_wfp_filter(app_exe, None, false));

    // 2. Inject WFP add failure -> UpsertRule for a new NetworkBlock returns WFP_SYNC_ERROR and
    //    rolls back SQLite cleanly.
    defense.set_fail_wfp_add(true);
    let failing_new = AllowlistRuleRecord {
        rule_id: "RULE-FAIL-ADD".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: r"C:\Tools\never_persisted.exe".to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "user_policy".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let fail_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: failing_new })
    })
    .await
    .expect("join IPC");
    match fail_resp {
        IpcResponse::Error { code, .. } => assert_eq!(code, "WFP_SYNC_ERROR"),
        other => panic!("expected WFP_SYNC_ERROR, got {other:?}"),
    }
    assert!(
        store.get_rule("RULE-FAIL-ADD").unwrap().is_none(),
        "failed UpsertRule must be rolled back from SQLite"
    );

    // 3. Inject WFP remove failure -> DeleteRule returns WFP_SYNC_ERROR and restores rule in SQLite!
    defense.set_fail_wfp_add(false);
    defense.set_fail_wfp_remove(true);
    let pipe_c = pipe_name.clone();
    let del_err = tokio::task::spawn_blocking(move || {
        send_pipe_request(
            &pipe_c,
            &IpcRequest::DeleteRule {
                rule_id: "RULE-SYNC-TEST".to_string(),
            },
        )
    })
    .await
    .expect("join IPC");
    match del_err {
        IpcResponse::Error { code, .. } => assert_eq!(code, "WFP_SYNC_ERROR"),
        other => panic!("expected WFP_SYNC_ERROR, got {other:?}"),
    }
    assert!(
        store.get_rule("RULE-SYNC-TEST").unwrap().is_some(),
        "failed DeleteRule must restore rule in SQLite"
    );
    assert!(
        engine.has_active_wfp_filter(app_exe, None, false),
        "live WFP block must stay tracked after failed DeleteRule"
    );
    defense.set_fail_wfp_remove(false);

    // 4. Analysis #7: UpsertRule changing scope away from NetworkAllow -> FileCanaryAllow removes
    //    the Permit filter AND re-arms Preemptive Block for active high-risk binary!
    let dl_proc = ProcessIdentity::new(7301, unix_ms_to_filetime(now_ms - 500));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: dl_proc,
            parent_pid: 4,
            exe_path: dl_exe.to_string(),
            command_line: dl_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start dl_exe");
    assert!(wait_until(1_000, || engine.has_active_wfp_filter(dl_exe, None, false)).await);

    let swap_rule = AllowlistRuleRecord {
        rule_id: "RULE-SCOPE-SWAP".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: dl_exe.to_string(),
        sha256: Some(dl_sha.to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "user_policy".to_string(),
    };
    engine.upsert_policy_rule(&swap_rule).expect("allow dl_exe");
    assert!(engine.has_active_wfp_filter(dl_exe, None, true));
    assert!(!engine.has_active_wfp_filter(dl_exe, None, false));

    let non_net_rule = AllowlistRuleRecord {
        scope: RuleScope::FileCanaryAllow,
        ..swap_rule.clone()
    };
    engine
        .upsert_policy_rule(&non_net_rule)
        .expect("scope swap away from network");
    assert!(!engine.has_active_wfp_filter(dl_exe, None, true));
    assert!(
        engine.has_active_wfp_filter(dl_exe, None, false),
        "changing rule scope away from NetworkAllow must re-arm Preemptive block for active high-risk exe"
    );

    // Updating an existing rule from NetworkBlock -> NetworkAllow when Permit add fails restores
    // the previous NetworkBlock rule in SQLite.
    let err_upd = engine.upsert_policy_rule(&AllowlistRuleRecord {
        rule_id: "RULE-SYNC-TEST".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: app_exe.to_string(),
        sha256: Some(app_sha.to_string()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "user_policy".to_string(),
    });
    assert!(err_upd.is_ok(), "healthy add succeeds");
    defense.set_fail_wfp_add(true);
    let err_back = engine.upsert_policy_rule(&valid_block);
    assert!(matches!(err_back, Err(PolicyRuleError::FirewallSync(_))));
    assert_eq!(
        store.get_rule("RULE-SYNC-TEST").unwrap().unwrap().scope,
        RuleScope::NetworkAllow
    );
    defense.set_fail_wfp_add(false);

    // 5. resolve_alert_with_outcome: AllowPermanent Permit failure & TerminateAndBlock Block
    //    failure keep the alert unresolved, roll back saved rules, and allow clean retry!
    let dl_connect_proc = ProcessIdentity::new(7302, unix_ms_to_filetime(now_ms - 400));
    let dl_retry_exe = r"C:\Users\alice\Downloads\retry_triage.exe";
    let dl_retry_sha = "5656565656565656565656565656565656565656565656565656565656565656";
    inspector.register(dl_retry_exe, Some(dl_retry_sha), None);
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: dl_connect_proc,
            parent_pid: 4,
            exe_path: dl_retry_exe.to_string(),
            command_line: dl_retry_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start retry_triage");
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: dl_connect_proc.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("retry.example".to_string()),
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("connect retry_triage");
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

    // 5a: Domain-scoped AllowPermanent fails when IP Permit add fails
    defense.set_fail_wfp_add_permits(true);
    let domain_perm_err = engine.resolve_alert_with_outcome(
        &alert.alert_id,
        AlertDecision::AllowPermanent {
            use_signer_if_available: false,
            allow_dest: Some("retry.example".to_string()),
        },
    );
    assert!(domain_perm_err.is_err());
    assert!(
        store.list_rules(Some(RuleScope::NetworkAllow)).unwrap().into_iter().all(|r| r.exe_path_pattern != dl_retry_exe),
        "failed domain AllowPermanent must roll back saved rule"
    );
    assert_eq!(
        store.get_alert(&alert.alert_id).unwrap().unwrap().status,
        AlertStatus::Pending
    );
    assert!(engine.has_active_wfp_filter(dl_retry_exe, None, false));

    // 5b: Unscoped AllowPermanent fails when Permit add fails -> rolls back NetworkAllow,
    //     re-arms Preemptive Block, and keeps alert Pending.
    let app_perm_err = engine.resolve_alert_with_outcome(
        &alert.alert_id,
        AlertDecision::AllowPermanent {
            use_signer_if_available: false,
            allow_dest: None,
        },
    );
    assert!(app_perm_err.is_err());
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkAllow))
            .unwrap()
            .into_iter()
            .all(|r| r.exe_path_pattern != dl_retry_exe),
        "failed unscoped AllowPermanent must roll back saved rule"
    );
    assert!(
        engine.has_active_wfp_filter(dl_retry_exe, None, false),
        "Preemptive block must be re-armed after failed unscoped AllowPermanent"
    );
    assert!(!engine.has_active_wfp_filter(dl_retry_exe, None, true));
    assert_eq!(
        store.get_alert(&alert.alert_id).unwrap().unwrap().status,
        AlertStatus::Pending
    );
    defense.set_fail_wfp_add_permits(false);

    // 5c: TerminateAndBlock { add_block_rule: true } on an exe without an existing app-wide
    //     block fails when add_wfp_app_rule fails, rolling back the block rule and keeping alert Pending!
    let term_exe = r"C:\Tools\term_sync_fail.exe";
    let term_proc = ProcessIdentity::new(7303, unix_ms_to_filetime(now_ms - 300));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: term_proc,
            parent_pid: 4,
            exe_path: term_exe.to_string(),
            command_line: term_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start term_exe");
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: term_proc.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 90)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 6,
        })
        .await
        .expect("connect term_exe");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 2)
                .unwrap_or(false)
        })
        .await
    );
    let term_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .unwrap()
        .into_iter()
        .find(|a| a.process_instance_id.as_deref() == Some(term_proc.instance_id().as_str()))
        .expect("term_alert");

    // Simulate lifted/absent block (e.g., AllowOnce failed/absent or general process without
    // transient block when WFP previously failed, or clear transient by first AllowOnce? Wait:
    // if AllowOnce lifted it isn't Pending. Instead test a non-suspended alert or remove block via
    // transient fail on connect + retry on resolve!):
    // Create a second general exe whose connect WFP add fails initially (alert emitted, no WFP filter),
    // then TerminateAndBlock { add_block_rule: true } fails WFP add -> keeps alert Pending!
    let term2_exe = r"C:\Tools\term2_sync_fail.exe";
    let term2_proc = ProcessIdentity::new(7304, unix_ms_to_filetime(now_ms - 250));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: term2_proc,
            parent_pid: 4,
            exe_path: term2_exe.to_string(),
            command_line: term2_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start term2");
    assert!(wait_until(1_000, || engine.active_process_table_len() >= 3).await);
    defense.set_fail_wfp_add(true);
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: term2_proc.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 91)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 7,
        })
        .await
        .expect("connect term2 while WFP fails");
    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 3)
                .unwrap_or(false)
        })
        .await
    );
    let term2_alert = store
        .list_alerts(Some(AlertStatus::Pending), 10)
        .unwrap()
        .into_iter()
        .find(|a| a.process_instance_id.as_deref() == Some(term2_proc.instance_id().as_str()))
        .expect("term2_alert");

    let tb_err = engine.resolve_alert_with_outcome(
        &term2_alert.alert_id,
        AlertDecision::TerminateAndBlock {
            add_block_rule: true,
        },
    );
    assert!(tb_err.is_err());
    assert!(
        store
            .list_rules(Some(RuleScope::NetworkBlock))
            .unwrap()
            .into_iter()
            .all(|r| r.exe_path_pattern != term2_exe),
        "failed TerminateAndBlock must roll back saved NetworkBlock rule"
    );
    assert_eq!(
        store
            .get_alert(&term2_alert.alert_id)
            .unwrap()
            .unwrap()
            .status,
        AlertStatus::Pending
    );

    // Recover WFP -> retry TerminateAndBlock succeeds!
    defense.set_fail_wfp_add(false);
    let _ = term_alert;
    let tb_ok = engine
        .resolve_alert_with_outcome(
            &term2_alert.alert_id,
            AlertDecision::TerminateAndBlock {
                add_block_rule: true,
            },
        )
        .expect("retry TerminateAndBlock succeeds");
    assert_eq!(tb_ok.alert.status, AlertStatus::TerminatedBlocked);
    assert!(engine.has_active_wfp_filter(term2_exe, None, false));

    ipc.shutdown().await;
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-22` (`#6`, `L-10`): Unknown external `NetworkConnect` events submitted via
/// `ClassifiedEventSender` promote onto the high-priority lane and quarantine even when the
/// telemetry lane is heavily saturated (`telemetry_dropped > 0`). Steady PIDs stay on telemetry
/// and are invalidated on policy updates.
#[tokio::test]
async fn daemon_p3_22_high_priority_promotion_over_saturated_telemetry() {
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
            telemetry_capacity: 8,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let classified = engine.classified_sender();
    let now_ms = current_unix_ms();

    let unknown_id = ProcessIdentity::new(7401, unix_ms_to_filetime(now_ms - 1_000));
    let unknown_exe = r"C:\Tools\single_shot_beacon.exe";
    classified
        .send(SensorEvent::ProcessStart {
            identity: unknown_id,
            parent_pid: 4,
            exe_path: unknown_exe.to_string(),
            command_line: unknown_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start unknown");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    // Flood telemetry synchronously without yielding so the 8-slot telemetry ring overflows,
    // then immediately send a single external NetworkConnect from unknown_id via classified_sender.
    for i in 0..200 {
        classified
            .try_send(SensorEvent::DnsQuery {
                pid: 9999,
                query_name: format!("flood-{i}.example"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                timestamp_ms: now_ms + i,
            })
            .expect("telemetry flood");
    }
    let unknown_connect = SensorEvent::NetworkConnect {
        pid: unknown_id.pid,
        protocol: 6,
        dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)),
        dst_port: 443,
        domain_hint: Some("exfil.example".to_string()),
        timestamp_ms: now_ms + 300,
    };
    assert!(classified.should_promote(&unknown_connect));
    classified
        .send(unknown_connect)
        .await
        .expect("send unknown external connect");
    // Flood another 200 telemetry events right after.
    for i in 200..400 {
        classified
            .try_send(SensorEvent::DnsQuery {
                pid: 9999,
                query_name: format!("flood-{i}.example"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                timestamp_ms: now_ms + i + 301,
            })
            .expect("post telemetry flood");
    }

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "unknown external NetworkConnect must survive saturated telemetry via high-priority lane"
    );
    assert!(classified.telemetry_dropped() > 0);
    assert_eq!(engine.high_priority_dropped(), 0);
    assert!(defense.suspends().contains(&unknown_id));
    assert!(engine.has_active_wfp_filter(unknown_exe, None, false));

    // Steady PID tracking: after resolving AllowOnce and one follow-up connect, PID becomes steady
    // (routed to telemetry); upserting a policy rule invalidates non-protected steady PIDs.
    let alert = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(&alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce");
    classified
        .send(SensorEvent::NetworkConnect {
            pid: unknown_id.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 800,
        })
        .await
        .expect("connect while once allowed");
    assert!(
        wait_until(1_000, || classified.classifier().is_steady_pid(unknown_id.pid)).await,
        "AllowOnce PID must become steady after evaluation"
    );
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "RULE-INVALIDATE-STEADY".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: r"C:\Tools\unrelated_policy.exe".to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms + 900,
            created_by: "user_policy".to_string(),
        })
        .expect("upsert policy rule");
    assert!(
        !classified.classifier().is_steady_pid(unknown_id.pid),
        "policy mutation must invalidate non-protected steady PIDs"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-23` (`#8`): Replacing an allowlisted binary on disk revokes stale WFP Permit
/// filters on `ProcessStart` (re-arming `Preemptive` block for high-risk/script binaries) and
/// revokes leftover Permits before registering transient containment on `NetworkConnect`.
#[tokio::test]
async fn daemon_p3_23_binary_replacement_revokes_stale_wfp_permits() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let dl_exe = r"C:\Users\alice\Downloads\replaceable_tool.exe";
    let gen_exe = r"C:\Tools\replaceable_general.exe";
    let sha_good_dl = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let sha_evil_dl = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let sha_good_gen = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let sha_evil_gen = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    inspector.register(dl_exe, Some(sha_good_dl), None);
    inspector.register(gen_exe, Some(sha_good_gen), None);

    let now_ms = current_unix_ms();
    for (id, exe, sha) in [
        ("RULE-ALLOW-DL", dl_exe, sha_good_dl),
        ("RULE-ALLOW-GEN", gen_exe, sha_good_gen),
    ] {
        store
            .upsert_rule(&AllowlistRuleRecord {
                rule_id: id.to_string(),
                scope: RuleScope::NetworkAllow,
                exe_path_pattern: exe.to_string(),
                sha256: Some(sha.to_string()),
                signer_subject: None,
                root_thumbprint: None,
                allowed_target: None,
                created_at_ms: now_ms,
                created_by: "user_policy".to_string(),
            })
            .expect("seed allow");
    }

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
        inspector.clone(),
    );
    let sender = engine.sender();
    assert!(engine.has_active_wfp_filter(dl_exe, None, true));
    assert!(engine.has_active_wfp_filter(gen_exe, None, true));

    // Case A: Replace high-risk binary on disk BEFORE ProcessStart.
    inspector.register(dl_exe, Some(sha_evil_dl), None);
    let p_dl = ProcessIdentity::new(7501, unix_ms_to_filetime(now_ms));
    sender
        .send(SensorEvent::ProcessStart {
            identity: p_dl,
            parent_pid: 4,
            exe_path: dl_exe.to_string(),
            command_line: dl_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start replaced dl_exe");
    assert!(
        wait_until(2_000, || {
            !engine.has_active_wfp_filter(dl_exe, None, true)
                && engine.has_active_wfp_filter(dl_exe, None, false)
        })
        .await,
        "replaced high-risk binary must have stale Permit revoked and Preemptive Block armed on ProcessStart"
    );

    // Case B: General binary starts while still valid, then gets overwritten on disk BEFORE
    // its NetworkConnect -> handle_network_connect must revoke stale Permit, apply Transient
    // Block, suspend, and emit alert!
    let p_gen = ProcessIdentity::new(7502, unix_ms_to_filetime(now_ms + 10));
    sender
        .send(SensorEvent::ProcessStart {
            identity: p_gen,
            parent_pid: 4,
            exe_path: gen_exe.to_string(),
            command_line: gen_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start valid gen_exe");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);
    assert!(engine.has_active_wfp_filter(gen_exe, None, true));

    inspector.register(gen_exe, Some(sha_evil_gen), None);
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_gen.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            domain_hint: Some("c2.example".to_string()),
            timestamp_ms: now_ms + 20,
        })
        .await
        .expect("connect replaced gen_exe");
    assert!(
        wait_until(2_000, || {
            !engine.has_active_wfp_filter(gen_exe, None, true)
                && engine.has_active_wfp_filter(gen_exe, None, false)
                && defense.suspends().contains(&p_gen)
        })
        .await,
        "replaced general binary connecting externally must revoke stale Permit and enter coupled containment"
    );
    assert_eq!(store.list_alerts(Some(AlertStatus::Pending), 10).unwrap().len(), 1);

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-24` (`#9` Layer 2): Per-instance DNS history blocks cross-process `domain_hint`
/// contamination from bypassing domain-scoped `NetworkAllow` rules while preserving isolated
/// `NetworkConnect` tests where no conflicting process resolved that `(domain, ip)`.
#[tokio::test]
async fn daemon_p3_24_cross_process_dns_isolation_layer2() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let allow_sha = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let good_exe = r"C:\Tools\legit_browser.exe";
    let hijack_exe = r"C:\Tools\impostor_client.exe";
    let isolated_exe = r"C:\Tools\isolated_client.exe";
    for exe in [good_exe, hijack_exe, isolated_exe] {
        inspector.register(exe, Some(allow_sha), None);
    }

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "RULE-DOMAIN-TRUSTED".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: r"C:\Tools\*.exe".to_string(),
            sha256: Some(allow_sha.to_string()),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("trusted.example".to_string()),
            created_at_ms: now_ms,
            created_by: "user_policy".to_string(),
        })
        .expect("seed trusted domain rule");

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
        inspector.clone(),
    );
    let sender = engine.sender();

    let p_good = ProcessIdentity::new(7601, unix_ms_to_filetime(now_ms - 3_000));
    let p_hijack = ProcessIdentity::new(7602, unix_ms_to_filetime(now_ms - 2_000));
    let p_isolated = ProcessIdentity::new(7603, unix_ms_to_filetime(now_ms - 1_000));
    for (p, exe) in [
        (p_good, good_exe),
        (p_hijack, hijack_exe),
        (p_isolated, isolated_exe),
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
            .expect("start proc");
    }

    let trusted_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    // 1. Isolated connect with domain_hint and NO conflicting DnsQuery preserves domain_hint!
    let iso_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_isolated.pid,
            protocol: 6,
            dst_ip: iso_ip,
            dst_port: 443,
            domain_hint: Some("trusted.example".to_string()),
            timestamp_ms: now_ms,
        })
        .await
        .expect("isolated connect");

    // 2. Now p_good resolves trusted.example -> trusted_ip.
    sender
        .send(SensorEvent::DnsQuery {
            pid: p_good.pid,
            query_name: "trusted.example".to_string(),
            query_type: 1,
            resolved_ips: vec![trusted_ip],
            timestamp_ms: now_ms + 5,
        })
        .await
        .expect("good dns");
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_good.pid,
            protocol: 6,
            dst_ip: trusted_ip,
            dst_port: 443,
            domain_hint: Some("trusted.example".to_string()),
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("good connect");

    // 3. p_hijack NEVER queried trusted.example, yet receives poisoned domain_hint -> Layer 2
    //    MUST drop domain_hint and quarantine p_hijack!
    sender
        .send(SensorEvent::NetworkConnect {
            pid: p_hijack.pid,
            protocol: 6,
            dst_ip: trusted_ip,
            dst_port: 443,
            domain_hint: Some("trusted.example".to_string()),
            timestamp_ms: now_ms + 15,
        })
        .await
        .expect("hijack connect");

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "only p_hijack must trigger quarantine alert via cross-process DNS hint rejection"
    );
    let alerts = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap();
    assert_eq!(
        alerts[0].process_instance_id.as_deref(),
        Some(p_hijack.instance_id().as_str())
    );
    assert!(alerts[0].process_suspended);
    assert!(!defense.suspends().contains(&p_good));
    assert!(!defense.suspends().contains(&p_isolated));

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-25` (`#1`): `DaemonEngine::wfp_drop_sink` captures ONLY `Weak<DaemonEngine>`,
/// correlates `WfpDropEvent` against active/recent processes and per-instance DNS history,
/// deduplicates rapid retries within 250 ms, promotes to high-priority triage, and lifts the
/// pre-emptive WFP block on `AllowOnce`.
#[tokio::test]
async fn daemon_p3_25_wfp_drop_sink_correlation_dedup_and_weak_ref() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![ps_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector.clone(),
    );
    let strong_before = Arc::strong_count(&engine);
    let drop_sink = engine.wfp_drop_sink();
    assert_eq!(
        Arc::strong_count(&engine),
        strong_before,
        "wfp_drop_sink must capture Weak<DaemonEngine> only (no reference cycle)"
    );

    let sender = engine.sender();
    let now_ms = current_unix_ms();
    let ps_proc = ProcessIdentity::new(7701, unix_ms_to_filetime(now_ms - 1_000));
    sender
        .send(SensorEvent::ProcessStart {
            identity: ps_proc,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps");
    let drop_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
    sender
        .send(SensorEvent::DnsQuery {
            pid: ps_proc.pid,
            query_name: "blocked-drop.example".to_string(),
            query_type: 1,
            resolved_ips: vec![drop_ip],
            timestamp_ms: now_ms,
        })
        .await
        .expect("dns ps");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    // Emit pre-emptive WFP drop event -> correlated with ps_proc + DNS history -> triage alert!
    let ev1 = WfpDropEvent {
        os_filter_id: 99,
        rule_handle: 100,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: drop_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 10,
    };
    assert!(engine.ingest_wfp_drop_event(ev1.clone()));
    // Rapid retry within 250ms is deduplicated!
    let ev_dup = WfpDropEvent {
        timestamp_ms: now_ms + 60,
        ..ev1.clone()
    };
    assert!(!engine.ingest_wfp_drop_event(ev_dup));

    assert!(
        wait_until(2_000, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "correlated WFP drop event must emit high-priority triage alert"
    );
    let alert = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    assert_eq!(alert.rule_id, "LEDR-NET-SCRIPT-INTERPRETER");
    assert!(alert.process_suspended);
    assert!(defense.suspends().contains(&ps_proc));
    assert!(
        alert.context_json.contains("blocked-drop.example"),
        "alert context must retain DNS domain correlated from process_dns_history: {}",
        alert.context_json
    );

    // User chooses AllowOnce -> lifts pre-emptive WFP block and resumes ps_proc.
    engine
        .resolve_alert(&alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce from WFP drop alert");
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));
    assert!(defense.resumes().contains(&ps_proc));

    // After 250ms window passes, dedup allows re-ingestion for the same tuple.
    let ev_after_window = WfpDropEvent {
        timestamp_ms: now_ms + 300,
        ..ev1.clone()
    };
    assert!(engine.ingest_wfp_drop_event(ev_after_window));

    engine.shutdown_and_flush().await.expect("shutdown");
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(
        weak.upgrade().is_none(),
        "wfp_drop_sink must not keep DaemonEngine alive after drop"
    );
    // Calling drop_sink after engine drop is a safe no-op.
    drop_sink(ev1);
}

/// `DAEMON-P3-26` (`#5`): Background NRD refresh runs on an independent `std::thread` holding
/// zero `Arc<DaemonEngine>`, and `shutdown_and_flush` cancels an in-flight WinHTTP request
/// against a hanging HTTP server cleanly in well under 500 ms.
#[tokio::test]
async fn daemon_p3_26_nrd_hanging_http_shutdown_cancels_rapidly() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("local addr").port();
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking listener");

    let accepted = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::new(AtomicBool::new(false));
    let accepted_bg = Arc::clone(&accepted);
    let stop_bg = Arc::clone(&stop_server);

    let server_thread = std::thread::spawn(move || {
        let mut held_sockets = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop_bg.load(Ordering::Acquire) && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    accepted_bg.store(true, Ordering::Release);
                    held_sockets.push(stream);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let engine = DaemonEngine::start_with_dependencies(
        store,
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            nrd_refresh_enabled: true,
            nrd_refresh_interval_ms: 200,
            nrd_feed_urls: vec![format!("http://127.0.0.1:{port}/nrd.txt")],
            ..DaemonConfig::default()
        },
        defense,
        notifier,
        inspector,
    );

    assert!(
        wait_until(3_000, || accepted.load(Ordering::Acquire)).await,
        "WinHTTP NRD refresh thread must connect to hanging mock server"
    );

    let started = Instant::now();
    engine
        .shutdown_and_flush()
        .await
        .expect("shutdown_and_flush");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(500),
        "shutdown_and_flush must cancel hanging WinHTTP NRD refresh in < 500 ms (took {elapsed:?})"
    );
    assert!(
        !engine.is_nrd_refresh_in_flight(),
        "background NRD thread must be joined and exited before shutdown_and_flush returns"
    );
    assert_eq!(
        Arc::strong_count(&engine),
        1,
        "background NRD thread must hold zero Arc<DaemonEngine> references after shutdown"
    );
    drop(engine);

    stop_server.store(true, Ordering::Release);
    let _ = server_thread.join();
}

/// `DAEMON-P3-27` (`Thread 15`): With a domain-scoped `NetworkAllow` rule active,
/// `ClassifiedEventSender` promotes non-steady external `DnsQuery` events onto `HighPriority`
/// in order so telemetry overflow from steady noise never drops DNS correlation before
/// `NetworkConnect`.
#[tokio::test]
async fn daemon_p3_27_dns_query_promoted_above_telemetry_overflow_when_domain_rule_active() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_hash = "b".repeat(64);
    inspector.register(ps_exe, Some(&ps_hash), None);

    let now_ms = current_unix_ms();
    let allow_domain_rule = AllowlistRuleRecord {
        rule_id: "R-DNS-PROMOTE".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: ps_exe.to_string(),
        sha256: Some(ps_hash),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("api.allowed.example".to_string()),
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    store.upsert_rule(&allow_domain_rule).expect("seed rule");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            telemetry_capacity: 16,
            high_priority_capacity: 1024,
            preemptive_startup_executables: vec![ps_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let classified = engine.classified_sender();
    assert!(
        classified.classifier().has_domain_rules(),
        "domain-scoped NetworkAllow must enable DnsQuery promotion"
    );

    // Mark a steady PID to flood Telemetry past its tiny 16-slot capacity.
    classified.classifier().mark_steady(8888);

    let ps_proc = ProcessIdentity::new(7101, unix_ms_to_filetime(now_ms - 500));
    let target_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 44));
    classified
        .send(SensorEvent::ProcessStart {
            identity: ps_proc,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    let dns_ev = SensorEvent::DnsQuery {
        pid: ps_proc.pid,
        query_name: "api.allowed.example".to_string(),
        query_type: 1,
        resolved_ips: vec![target_ip],
        timestamp_ms: now_ms,
    };
    assert!(classified.should_promote(&dns_ev));
    classified.send(dns_ev).await.expect("send dns");

    // Overflow Telemetry lane with steady noise right after DnsQuery.
    for i in 0..80 {
        let _ = classified
            .send(SensorEvent::DnsQuery {
                pid: 8888,
                query_name: format!("noise-{i}.example"),
                query_type: 1,
                resolved_ips: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))],
                timestamp_ms: now_ms + i,
            })
            .await;
    }

    classified
        .send(SensorEvent::NetworkConnect {
            pid: ps_proc.pid,
            protocol: 6,
            dst_ip: target_ip,
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 90,
        })
        .await
        .expect("send connect without inline domain_hint");

    assert!(
        wait_until(2_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(target_ip), true)
        })
        .await,
        "promoted DnsQuery must materialize DomainPolicy Permit despite telemetry overflow"
    );
    assert!(classified.telemetry_dropped() > 0);
    assert!(defense.suspends().is_empty());
    assert!(store.list_alerts(None, 20).unwrap().is_empty());

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-28` (`Thread 13`): Pre-emptively blocked executable with a domain-scoped
/// `NetworkAllow` rule waits up to `wfp_drop_dns_grace_ms` for an out-of-band `DnsQuery` when
/// `WfpDropEvent` arrives early (never falsely suspending), while non-allowed drops suspend once
/// the grace window expires.
#[tokio::test]
async fn daemon_p3_28_wfp_drop_waits_for_delayed_dns_allow_and_suspends_on_timeout() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let ps_hash = "c".repeat(64);
    inspector.register(ps_exe, Some(&ps_hash), None);

    let now_ms = current_unix_ms();
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-ALLOW-DELAYED".to_string(),
            scope: RuleScope::NetworkAllow,
            exe_path_pattern: ps_exe.to_string(),
            sha256: Some(ps_hash),
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("api.delayed.example".to_string()),
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        })
        .expect("seed rule");

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![ps_exe.to_string()],
            wfp_drop_dns_grace_ms: 150,
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let ps_proc = ProcessIdentity::new(7201, unix_ms_to_filetime(now_ms - 500));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: ps_proc,
            parent_pid: 4,
            exe_path: ps_exe.to_string(),
            command_line: ps_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start ps");
    assert!(wait_until(1_000, || engine.active_process_table_len() == 1).await);

    // 1. Out-of-order: WfpDropEvent arrives BEFORE DnsQuery -> buffered, then allowed when DnsQuery lands.
    let allowed_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 55));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 1,
        rule_handle: 1,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: allowed_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 10,
    }));

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(defense.suspends().is_empty());

    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: ps_proc.pid,
            query_name: "api.delayed.example".to_string(),
            query_type: 1,
            resolved_ips: vec![allowed_ip],
            timestamp_ms: now_ms + 30,
        })
        .await
        .expect("delayed dns");

    assert!(
        wait_until(1_000, || {
            engine.has_active_wfp_filter(ps_exe, Some(allowed_ip), true)
        })
        .await,
        "delayed DnsQuery must authorize held WfpDropEvent and install DomainPolicy permit"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        defense.suspends().is_empty(),
        "allowed destination must never falsely suspend on delayed DNS"
    );
    assert!(store.list_alerts(None, 10).unwrap().is_empty());

    // 2. Non-allowed destination with no matching DnsQuery -> grace timer expires -> suspends + alerts.
    let raw_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 2,
        rule_handle: 2,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: raw_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 400,
    }));
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "unallowed drop must suspend and alert after grace window"
    );
    assert_eq!(defense.suspends(), vec![ps_proc]);

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-29` (`Thread 9`): Multiple active instances of the same executable must NEVER guess
/// `candidates[0]` or fabricate `network_events` when attributing `WfpDropEvent`:
/// - Ambiguous multi-instance drops emit a deduplicated app-level alert (`process_instance_id = None`,
///   `process_suspended = false`, `"attribution": "app_level_ambiguous"`) with zero suspensions.
/// - Unique recent PID-bearing `NetworkConnect` disambiguates the true connecting instance cleanly.
#[tokio::test]
async fn daemon_p3_29_wfp_drop_multi_instance_disambiguation_and_ambiguous_app_alert() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());
    let ps_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let tool_exe = r"C:\Tools\worker.exe";

    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: unique_test_pipe_name(),
            preemptive_startup_executables: vec![ps_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );

    let now_ms = current_unix_ms();
    let p1 = ProcessIdentity::new(8101, unix_ms_to_filetime(now_ms - 1_000));
    let p2 = ProcessIdentity::new(8102, unix_ms_to_filetime(now_ms - 900));
    for proc_id in [p1, p2] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: ps_exe.to_string(),
                command_line: ps_exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start ps");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 2).await);

    // 1. Ambiguous WfpDropEvent with two concurrent powershell instances -> app-level alert ONLY.
    let ambig_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 55));
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 10,
        rule_handle: 10,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: ambig_ip,
        dst_port: 443,
        timestamp_ms: now_ms + 10,
    }));

    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.len() == 1)
                .unwrap_or(false)
        })
        .await,
        "ambiguous multi-instance WFP drop must emit one app-level alert"
    );
    let ambig_alert = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    assert_eq!(ambig_alert.process_instance_id, None);
    assert!(!ambig_alert.process_suspended);
    assert!(
        defense.suspends().is_empty(),
        "ambiguous drop must suspend zero candidate processes"
    );
    let ctx_val: serde_json::Value = serde_json::from_str(&ambig_alert.context_json).unwrap();
    assert_eq!(ctx_val["attribution"], "app_level_ambiguous");
    assert!(ctx_val["pid"].is_null());
    let snap = store.query_flight_recorder(50, None).unwrap();
    assert!(
        snap.network_events.is_empty(),
        "WfpDropEvent must never fabricate synthetic network_events rows"
    );

    // Repeating same (exe, ip) after 250ms transport dedup is still app-deduped while unresolved.
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 10,
        rule_handle: 10,
        exe_path: ps_exe.to_string(),
        protocol: 6,
        dst_ip: ambig_ip,
        dst_port: 444,
        timestamp_ms: now_ms + 400,
    }));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        store.list_alerts(Some(AlertStatus::Pending), 10).unwrap().len(),
        1
    );

    // AllowOnce lifts WFP block and marks active candidate instances so pre-emptive block isn't re-armed.
    engine
        .resolve_alert(&ambig_alert.alert_id, AlertDecision::AllowOnce)
        .expect("AllowOnce on app-level ambiguous alert");
    assert!(!engine.has_active_wfp_filter(ps_exe, None, false));

    // 2. Two instances of `tool.exe` where ONLY `q2` recently had a NetworkConnect to (203.0.113.99, 8443)
    //    matching a NetworkBlock rule: WfpDropEvent disambiguates uniquely to `q2`, NOT `q1` and NOT
    //    `app_level_ambiguous`.
    let q1 = ProcessIdentity::new(8201, unix_ms_to_filetime(now_ms - 800));
    let q2 = ProcessIdentity::new(8202, unix_ms_to_filetime(now_ms - 700));
    engine
        .upsert_policy_rule(&AllowlistRuleRecord {
            rule_id: "R-TOOL-BLK".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: tool_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: Some("203.0.113.99".to_string()),
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        })
        .expect("upsert tool block");
    for proc_id in [q1, q2] {
        engine
            .sender()
            .send(SensorEvent::ProcessStart {
                identity: proc_id,
                parent_pid: 4,
                exe_path: tool_exe.to_string(),
                command_line: tool_exe.to_string(),
                user_sid: None,
            })
            .await
            .expect("start tool");
    }
    assert!(wait_until(1_000, || engine.active_process_table_len() == 4).await);

    let disambig_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: q2.pid,
            protocol: 6,
            dst_ip: disambig_ip,
            dst_port: 8443,
            domain_hint: None,
            timestamp_ms: now_ms + 500,
        })
        .await
        .expect("q2 network connect");

    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let q2_alert = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    assert_eq!(q2_alert.process_instance_id, Some(q2.instance_id()));

    // Now WfpDropEvent arrives: RecentConnectTracker matches `q2` uniquely -> `q2`'s dedup handles it
    // cleanly without creating a false `q1` alert OR an `app_level_ambiguous` alert!
    assert!(engine.ingest_wfp_drop_event(WfpDropEvent {
        os_filter_id: 20,
        rule_handle: 20,
        exe_path: tool_exe.to_string(),
        protocol: 6,
        dst_ip: disambig_ip,
        dst_port: 8443,
        timestamp_ms: now_ms + 520,
    }));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(
        store.list_alerts(Some(AlertStatus::Pending), 10).unwrap().len(),
        1,
        "unique RecentConnect attribution to q2 must neither blame q1 nor emit ambiguous alert"
    );

    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-30` (`Threads 10, 14, 18`): Unrelated pre-existing WFP reconcile failures do not
/// poison `UpsertRule` / `DeleteRule` / `AllowPermanent` / `TerminateAndBlock`; failed
/// `DeleteRule` on a domain block rule restores both SQLite and partially-removed `DomainPolicy`
/// WFP filters without breaking sibling containment bindings.
#[tokio::test]
async fn daemon_p3_30_wfp_scoping_ignores_unrelated_failure_and_restores_domain_block_on_rollback() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let broken_exe = r"C:\Tools\broken_preexisting.exe";
    let healthy_exe = r"C:\Tools\healthy_app.exe";
    let alert_exe = r"C:\Temp\resolve_target.exe";
    let dom_exe = r"C:\Tools\dom_rollback.exe";
    let dom_hash = "d".repeat(64);
    inspector.register(healthy_exe, Some(&"a".repeat(64)), None);
    inspector.register(alert_exe, Some(&"e".repeat(64)), None);
    inspector.register(dom_exe, Some(&dom_hash), None);

    let now_ms = current_unix_ms();
    // Seed a failing rule directly in SQLite before startup so startup reconcile records it.
    store
        .upsert_rule(&AllowlistRuleRecord {
            rule_id: "R-PRE-BROKEN".to_string(),
            scope: RuleScope::NetworkBlock,
            exe_path_pattern: broken_exe.to_string(),
            sha256: None,
            signer_subject: None,
            root_thumbprint: None,
            allowed_target: None,
            created_at_ms: now_ms,
            created_by: "test".to_string(),
        })
        .expect("seed broken rule");
    defense.add_fail_wfp_exe("broken_preexisting.exe");

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
    let server = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    // 1. Pre-existing failure on `broken_preexisting.exe` MUST NOT block UpsertRule / DeleteRule
    //    or AllowPermanent / TerminateAndBlock for unrelated executables.
    let healthy_rule = AllowlistRuleRecord {
        rule_id: "R-HEALTHY".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: healthy_exe.to_string(),
        sha256: Some("a".repeat(64)),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: None,
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let healthy_c = healthy_rule.clone();
    let ack1 = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: healthy_c })
    })
    .await
    .expect("join upsert");
    assert!(matches!(ack1, IpcResponse::Ack { .. }));
    let pipe_c = pipe_name.clone();
    let ack2 = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::DeleteRule { rule_id: "R-HEALTHY".to_string() })
    })
    .await
    .expect("join delete");
    assert!(matches!(ack2, IpcResponse::Ack { .. }));

    // AllowPermanent + TerminateAndBlock also succeed despite R-PRE-BROKEN still failing.
    let p_allow = ProcessIdentity::new(8301, unix_ms_to_filetime(now_ms - 500));
    let p_term = ProcessIdentity::new(8302, unix_ms_to_filetime(now_ms - 500));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: p_allow,
            parent_pid: 4,
            exe_path: alert_exe.to_string(),
            command_line: alert_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start p_allow");
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: p_allow.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 10)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("connect p_allow");
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let al_allow = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(
            &al_allow.alert_id,
            AlertDecision::AllowPermanent {
                use_signer_if_available: false,
                allow_dest: None,
            },
        )
        .expect("AllowPermanent succeeds even while unrelated broken rule fails");

    let term_exe = r"C:\Temp\term_target.exe";
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: p_term,
            parent_pid: 4,
            exe_path: term_exe.to_string(),
            command_line: term_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start p_term");
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: p_term.pid,
            protocol: 6,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 11)),
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("connect p_term");
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|v| v.len() == 1)
                .unwrap_or(false)
        })
        .await
    );
    let al_term = store.list_alerts(Some(AlertStatus::Pending), 10).unwrap()[0].clone();
    engine
        .resolve_alert(
            &al_term.alert_id,
            AlertDecision::TerminateAndBlock { add_block_rule: true },
        )
        .expect("TerminateAndBlock succeeds even while unrelated broken rule fails");

    // 2. Partial DomainPolicy delete failure rolls back SQLite AND restores deleted DomainPolicy IP.
    let dom_rule = AllowlistRuleRecord {
        rule_id: "R-DOM-ROLLBACK".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: dom_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("evil-rollback.example".to_string()),
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    engine.upsert_policy_rule(&dom_rule).expect("upsert dom block");

    let p_dom = ProcessIdentity::new(8303, unix_ms_to_filetime(now_ms - 300));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: p_dom,
            parent_pid: 4,
            exe_path: dom_exe.to_string(),
            command_line: dom_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start dom_exe");
    let ip1 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 101));
    let ip2 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 102));
    engine
        .sender()
        .send(SensorEvent::DnsQuery {
            pid: p_dom.pid,
            query_name: "evil-rollback.example".to_string(),
            query_type: 1,
            resolved_ips: vec![ip1, ip2],
            timestamp_ms: now_ms + 10,
        })
        .await
        .expect("dns dom_exe");
    assert!(
        wait_until(1_500, || {
            engine.has_active_wfp_filter(dom_exe, Some(ip1), false)
                && engine.has_active_wfp_filter(dom_exe, Some(ip2), false)
        })
        .await
    );

    // Fail removal on ip2's handle specifically while allowing ip1 to be removed during delete!
    let ip2_handle = defense
        .active_wfp()
        .into_iter()
        .find(|c| c.remote_ip == Some(ip2) && !c.allow)
        .expect("ip2 wfp handle")
        .handle;
    defense.add_fail_wfp_remove_handle(ip2_handle);

    let err = engine
        .delete_policy_rule("R-DOM-ROLLBACK")
        .expect_err("partial domain remove failure must fail delete_policy_rule");
    assert!(matches!(err, PolicyRuleError::FirewallSync(_)));
    assert!(
        store.get_rule("R-DOM-ROLLBACK").unwrap().is_some(),
        "SQLite rule must be restored on delete rollback"
    );
    assert!(
        engine.has_active_wfp_filter(dom_exe, Some(ip1), false),
        "ip1 DomainPolicy filter removed prior to ip2 failure must be restored in WFP"
    );
    assert!(
        engine.has_active_wfp_filter(dom_exe, Some(ip2), false),
        "ip2 DomainPolicy filter must remain active"
    );

    drop(server);
    engine.shutdown_and_flush().await.expect("shutdown");
}

/// `DAEMON-P3-31` (`Thread 16`): IPv4/IPv6 CIDR `NetworkAllow` and `NetworkBlock` rules are
/// validated via IPC, enforced with deny-overrides-allow precedence, and never wrongly trigger
/// domain-only `DnsQuery` lane promotion when no domain rules exist.
#[tokio::test]
async fn daemon_p3_31_cidr_network_allow_and_block_enforced_with_deny_precedence() {
    let store = LedrStore::open_in_memory().expect("open store");
    let defense = Arc::new(MockWfpDefense::new());
    let notifier = Arc::new(MockNotifier::default());
    let inspector = Arc::new(MapBinaryInspector::default());

    let app_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let app_hash = "f".repeat(64);
    inspector.register(app_exe, Some(&app_hash), None);

    let pipe_name = unique_test_pipe_name();
    let engine = DaemonEngine::start_with_dependencies(
        store.clone(),
        SigmaEngine::default(),
        EarlyPruner::default(),
        DaemonConfig {
            pipe_name: pipe_name.clone(),
            dev_mode_bypass_ui_auth: true,
            preemptive_startup_executables: vec![app_exe.to_string()],
            ..DaemonConfig::default()
        },
        defense.clone(),
        notifier,
        inspector,
    );
    let server = start_ipc_server(Arc::clone(&engine)).expect("start ipc");

    let now_ms = current_unix_ms();
    // Invalid CIDR rejected cleanly via IPC.
    let bad_rule = AllowlistRuleRecord {
        rule_id: "R-BAD-CIDR".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: app_exe.to_string(),
        sha256: Some(app_hash.clone()),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("198.51.100.0/33".to_string()),
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let bad_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: bad_rule })
    })
    .await
    .expect("join bad upsert");
    assert!(matches!(bad_resp, IpcResponse::Error { .. }));

    // Allow 198.51.100.0/24, Deny narrow subset 198.51.100.128/25 (deny overrides allow).
    let allow_rule = AllowlistRuleRecord {
        rule_id: "R-CIDR-ALLOW".to_string(),
        scope: RuleScope::NetworkAllow,
        exe_path_pattern: app_exe.to_string(),
        sha256: Some(app_hash),
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("198.51.100.0/24".to_string()),
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let allow_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: allow_rule })
    })
    .await
    .expect("join allow upsert");
    assert!(matches!(allow_resp, IpcResponse::Ack { .. }));

    let block_rule = AllowlistRuleRecord {
        rule_id: "R-CIDR-BLOCK".to_string(),
        scope: RuleScope::NetworkBlock,
        exe_path_pattern: app_exe.to_string(),
        sha256: None,
        signer_subject: None,
        root_thumbprint: None,
        allowed_target: Some("198.51.100.128/25".to_string()),
        created_at_ms: now_ms,
        created_by: "test".to_string(),
    };
    let pipe_c = pipe_name.clone();
    let block_resp = tokio::task::spawn_blocking(move || {
        send_pipe_request(&pipe_c, &IpcRequest::UpsertRule { rule: block_rule })
    })
    .await
    .expect("join block upsert");
    assert!(matches!(block_resp, IpcResponse::Ack { .. }));
    assert!(
        !engine.classified_sender().classifier().has_domain_rules(),
        "pure CIDR rules must NOT enable DnsQuery high-priority promotion"
    );

    let proc_id = ProcessIdentity::new(8401, unix_ms_to_filetime(now_ms - 500));
    engine
        .sender()
        .send(SensorEvent::ProcessStart {
            identity: proc_id,
            parent_pid: 4,
            exe_path: app_exe.to_string(),
            command_line: app_exe.to_string(),
            user_sid: None,
        })
        .await
        .expect("start app");

    let allowed_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: proc_id.pid,
            protocol: 6,
            dst_ip: allowed_ip,
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 1,
        })
        .await
        .expect("connect allowed cidr");
    assert!(
        wait_until(1_500, || engine.has_active_wfp_filter(app_exe, Some(allowed_ip), true)).await,
        "198.51.100.10 must be allowed via 198.51.100.0/24 CIDR and materialize WFP permit"
    );
    assert!(store.list_alerts(None, 10).unwrap().is_empty());

    let denied_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    engine
        .sender()
        .send(SensorEvent::NetworkConnect {
            pid: proc_id.pid,
            protocol: 6,
            dst_ip: denied_ip,
            dst_port: 443,
            domain_hint: None,
            timestamp_ms: now_ms + 2,
        })
        .await
        .expect("connect blocked cidr");
    assert!(
        wait_until(1_500, || {
            store
                .list_alerts(Some(AlertStatus::Pending), 10)
                .map(|a| a.iter().any(|r| r.rule_id == "LEDR-NET-POLICY-BLOCK"))
                .unwrap_or(false)
        })
        .await,
        "198.51.100.200 in 198.51.100.128/25 must be blocked with deny-overrides-allow"
    );
    assert!(engine.has_active_wfp_filter(app_exe, Some(denied_ip), false));

    drop(server);
    engine.shutdown_and_flush().await.expect("shutdown");
}
